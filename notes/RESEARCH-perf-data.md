# Performance Data Research — hasp backends

Date: 2026-04-26

## 1. OS Keyring Backend Latency

### macOS Keychain (`security find-generic-password` / `SecKeychainFindGenericPassword`)

**Cold call (first access):**
- `SecKeychainFindGenericPassword` can stall for up to **3.3 seconds** on a bad network
  day; the author confirmed this disappeared when internet was disabled, suggesting
  synchronous network validation on first access.
  Source: https://sigpipe.macromates.com/2020/macos-catalina-slow-by-design/
- No published millisecond-level "cold vs warm" microbenchmark found.
- Apple Tech Note TN3137 distinguishes two implementations: iOS (SQLite-backed) and
  macOS (legacy compatibility shim). The shim adds overhead not present on iOS.

**Warm call (cached unlock):**
- No published benchmark. Qualitatively described as "sub-second" in normal operation.
- `SecItemCopyMatching` (modern API) preferred over `SecKeychainFindGenericPassword`
  (legacy, undeprecated but problematic).

**Key caveat:** The 3.3 s figure is a worst-case anomaly tied to implicit network
I/O, not a steady-state cost. Normal same-process repeated reads are not benchmarked
publicly. Expect low single-digit milliseconds under normal conditions (unverified).

### Windows Credential Manager (`CredRead`)

Searched: "Windows Credential Manager CredRead latency performance milliseconds benchmark"
**No data.** No published benchmark found for CredRead latency. Microsoft does not
publish API-level latency specs for the Credential Manager APIs.

### Linux Secret Service via DBus

**Headless / container scenario:**
- The org.freedesktop.secrets protocol is **synchronous** — backends must reply
  immediately; requests that require user interaction will time out.
  Source: https://news.ycombinator.com/item?id=30694808
- Without a DBus session the keyring is simply unavailable. keyring-rs issue #477
  shows this manifests as "Operation not permitted" from gnome-keyring-daemon in
  containers even when dbus-run-session is used.
  Source: https://github.com/jaraco/keyring/issues/477
- Getting gnome-keyring working headless requires `--cap-add ipc_lock`, a dbus
  session, and `gnome-keyring-daemon --unlock` — non-trivial container setup.
  Source: https://alex-ber.medium.com/using-gnome-keyring-in-docker-container-2c8a56a894f7

**DBus roundtrip latency:** No published benchmark found. DBus IPC is local-socket
based; roundtrip on same host is typically sub-millisecond for simple requests, but
no keyring-specific measurement found.

**Auto-unlock prompt cost:** No published data. An interactive unlock prompt could
block for seconds to minutes depending on user response; the synchronous protocol
means the DBus request simply hangs until answered or times out.

---

## 2. Memory-Locking Overhead (`mlock` / `VirtualLock`)

### RLIMIT_MEMLOCK defaults
- Linux default for unprivileged processes: **64 KB** locked memory.
- Proposed increase to 8 MB (driven by io_uring registered-buffer use cases);
  Jens Axboe: "8MB is plenty for most casual use cases."
  Source: https://lwn.net/Articles/876288/
- No limit applies to privileged processes (CAP_IPC_LOCK).

### Per-page locking cost
No published nanosecond-per-page benchmark found for mlock() itself.
Linux manual: locking/unlocking occurs in whole-page units.
MLOCK_ONFAULT flag available for large mappings where only a subset of pages are touched.
Source: https://man7.org/linux/man-pages/man2/mlock.2.html

### Performance under memory pressure
- Real-time documentation: locking avoids page-fault jitter but does not eliminate
  all latency sources.
- io_uring context: buffer setup/teardown costs "can reach a point where they slow
  the application measurably" without persistent locked buffers.
  Source: https://lwn.net/Articles/876288/
- No general-purpose benchmark for secret-sized (32–4096 byte) mlock() overhead found.

### hasp-relevant implication
A single mlock() for a 32–256 byte secret value is below the 64 KB default limit and
is a one-time syscall cost, not a per-read cost. No evidence that this is measurably
expensive for typical secret payloads.

---

## 3. `zeroize` Performance Cost

### Compiler elision risk
- Without volatile semantics, compilers reliably eliminate zeroing of memory they
  judge to be dead — confirmed by assembly inspection (ARM64): identical output
  before/after naive zeroing.
  Source: https://cipherstash.com/blog/verifying-rust-zeroize-with-assembly-including-portable-simd

### How zeroize defeats elision
- Uses `core::ptr::write_volatile` (LLVM volatile semantics guarantee: operation
  not removed by optimizer).
- Adds `core::sync::atomic::compiler_fence(Ordering::SeqCst)` to prevent
  instruction reordering.
- Source code confirms the loop is `volatile_set`: one `write_volatile` call per
  element, not a bulk intrinsic.
  Source: https://docs.rs/zeroize/latest/zeroize/ and
  https://github.com/RustCrypto/utils/blob/master/zeroize/src/lib.rs

### `volatile_set_memory` vs current approach
- Crate TODO comment in source: "use `volatile_set_memory` when stabilized" —
  currently uses per-element write_volatile loop instead of a SIMD/memset intrinsic.
  This means zeroing a 32-byte secret is 32 individual volatile writes, not one
  call. Performance impact is negligible for secret-sized buffers.

### Performance cost per byte
- No Rust-specific ns/byte benchmark found. General hardware data from
  https://travisdowns.github.io/blog/2020/05/13/intel-zero-opt.html:
  - L1 cache zero-fill: ~100 GB/s (Intel Skylake client)
  - L2 cache: ~50 GB/s
  - At 100 GB/s, zeroing 32 bytes takes ~0.32 ns; 4 KB page ~40 ns.
  - Hardware store elimination for zero-writes: ~17–18% throughput improvement
    over non-zero writes at L3/RAM level.
  These numbers are for bulk memset, not write_volatile loops (which add per-element
  overhead). Per-element volatile write overhead is likely 2–5x slower than bulk,
  but still sub-microsecond for any realistic secret size.

### `volatile` vs `memset_explicit`
- C23 `memset_explicit` / POSIX `explicit_bzero` are the portable C equivalents.
  None of these are available to stable Rust; write_volatile is the equivalent.
- No Rust-specific comparison benchmark found.

### Key risk: copies before zeroize
- zeroize docs explicitly warn: Vec/String heap reallocation may have left copies
  that cannot be zeroed. Correct usage requires pre-sizing to capacity.
  Source: https://docs.rs/zeroize/latest/zeroize/

---

## 4. Cloud Secret-Store Roundtrip Latency

### AWS Secrets Manager `GetSecretValue`
- **In-region from Lambda / EC2:** Community-reported range **100–400 ms**, typical
  average ~200 ms. One user reported 700–800 ms (without VPC endpoint or caching).
  Source: https://repost.aws/questions/QUI0bQviZ3RHWKZMfL3heEAA/
  Source: http://community.zenduty.com/t/faster-ways-to-fetch-database-credentials-in-lambda/401
- AWS does not publish official p50/p99 latency SLAs for GetSecretValue.
- Caching library (client-side SDK) is recommended; no before/after numbers published.
  Source: https://aws.amazon.com/blogs/security/improve-availability-and-latency-of-applications-by-using-aws-secret-managers-python-client-side-caching-library/

**Cross-region:** AWS recommends replication rather than cross-region reads; no
latency benchmark found. Inter-region add-on latency is the underlying AWS network
path (typically 20–100+ ms depending on regions).

**Throttle limits (April 2025):** GetSecretValue now supports 10,000 RPS.
Source: https://aws.amazon.com/about-aws/whats-new/2025/03/aws-secrets-manager-increases-api-requests-seconds/

### AWS SSM `GetParameter` / `GetParametersByPath`
- **In-region from Lambda:** AWS X-Ray trace showed **~64 ms** average for a
  GetParameter call.
  Source (via search summary): search "SSM Parameter Store GetParameter latency 64ms"
- `GetParametersByPath` with the same query showed **~63.5 ms**.
- Default throughput quota: 40 RPS (low; caching is strongly recommended).
- Max results per GetParametersByPath page: 50 (pagination required for >50 params).

### HashiCorp Vault (KV read)
**Palark backend comparison benchmark (wrk, 4 threads, 16 connections, 1000 secrets):**
| Backend   | Avg read latency | Read RPS  |
|-----------|-----------------|-----------|
| Consul    | 2.25 ms         | 315,079/30s (~10,500 RPS) |
| PostgreSQL| 2.48 ms         | 251,861/30s (~8,400 RPS)  |
| GCS       | 4.40 ms         | 111,196/30s (~3,700 RPS)  |
Source: https://palark.com/blog/comparing-hashicorp-vault-backends-performance/

**HashiCorp engineering blog (single-node reference architecture):**
- Read: avg **8.76 ms** (4 threads, 16 connections, 55,589 requests)
- Write: avg **16.71 ms** (6 threads, 16 connections, 21,630 requests)
- Reads ~2.5x faster than writes in production cluster
- Single-thread local test: 224.89 ms avg write (different methodology)
Source: https://medium.com/hashicorp-engineering/hashicorp-vault-performance-benchmark-13d0ea7b703f

**Raft network requirement:** <8 ms between cluster nodes required.
**Vault benchmark tool:** `vault-benchmark` (open source from HashiCorp).

### GCP Secret Manager `AccessSecretVersion`
- No official p50/p99 latency published.
- User reports in community forum: typical calls appear fast (low hundreds ms in
  normal operation) but users have reported pathological cases of 10–31 seconds
  under load or with gRPC SDK issues.
  Source: https://www.googlecloudcommunity.com/gc/General-Misc-Q-A/GCP-Secrets-manager-too-slow/m-p/610155
- GCP SLA page for Secret Manager (cloud.google.com/secret-manager/sla) was
  unreachable during research (ECONNREFUSED).
- Best practice: use version-pinned references, not `latest` alias, and cache at startup.
  Source: https://docs.cloud.google.com/secret-manager/docs/best-practices

### Azure Key Vault `GetSecret`
- **First call (cold):** Reported **10–13 seconds** delay on Azure Functions
  Consumption Plan (cold start + auth overhead — not steady-state).
  Source: https://learn.microsoft.com/en-us/answers/questions/1322272/azure-key-vault-first-getsecret()-takes-more-than
- **Alert threshold:** Azure monitoring flags latency >1000 ms as concerning,
  implying normal warm operation is well under 1 s.
  Source: https://learn.microsoft.com/en-us/azure/key-vault/general/monitor-key-vault
- No official p50/p99 published. Throttle limits apply: GET secret = 2000 RPS per
  vault by default.
  Source: https://learn.microsoft.com/en-us/azure/key-vault/general/overview-throttling

---

## 5. TLS Handshake Cost

### Protocol round-trips
- TLS 1.2: 2 round trips before data flows (1 full RTT of latency added)
- TLS 1.3: 1 round trip (0.5 RTT added for new connections); 0-RTT for session resumption
- On a 100 ms RTT link: TLS 1.2 adds ~100 ms; TLS 1.3 adds ~50 ms
  Source: https://hosseinnejati.medium.com/the-tls-handshake-deep-dive-what-happens-before-a-single-byte-of-data-flows-ad8b7546b4dd

### rustls vs OpenSSL/BoringSSL
- Q1 2026 benchmark: rustls won 14/16 test scenarios vs BoringSSL (2 wins) and
  OpenSSL (0 wins). Numbers are chart-only; no text-extractable figures.
  Source: https://www.memorysafety.org/blog/26q1-rustls-performance/
- rustls multithreaded performance blog: tightest latency distribution of the three
  libraries at 80 concurrent threads.
  Source: https://rustls.dev/perf/2024-11-28-threading/
- Full vs resumed: "resumed connections are 5–10x quicker than full connections"
  Source: https://github.com/rustls/rustls/issues/2030

### HTTP/2 connection reuse
- HTTP/2 persistent connections reduced TLS-overhead-heavy requests by ~19% (requests
  with >20 ms TLS overhead) and ~50% for API-style requests in one study.
  Source: https://www.akamai.com/blog/performance/http2-persistent-connections
- HTTP/2 individual requests showed 56% of HTTP/1.1 individual request time (490 ms
  baseline → 276 ms) for 25-entity REST calls.
  Source: https://evertpot.com/h2-parallelism/
- HTTP/2 was 85% quicker than HTTP/1.1 in one benchmark; compound responses showed
  3.26x improvement for 500-item payloads in Chrome.

### DNS lookup amortization
- HTTP keep-alive eliminates second TCP handshake and DNS re-resolution per connection.
- Amortizing TLS+DNS over many requests is the primary justification for `Store`
  (connection-pool) reuse rather than throwaway clients.
  Source: https://cursa.app/en/page/keep-alive-and-connection-reuse-reducing-latency-across-requests

### hasp implication
Creating a new HTTP client per `get()` call would pay ~50–100 ms TLS overhead per
call (on realistic WAN paths). Connection reuse via a persistent client/store is
necessary to avoid this. Backends should expose connection pooling or accept an
injected client.

---

## 6. `url::Url` Parse Cost

Searched: "rust-url servo url parse benchmark nanoseconds criterion", "url::Url Rust
parse benchmark nanoseconds criterion site:github.com OR site:docs.rs"

**No published benchmark data found** for `url::Url` parse latency in the Rust
`url` crate (servo/rust-url).

**Inference from comparable parsers:**
- Ada (C++, used by Node.js/Deno): ~150–300 ns per URL, described as 7.1x faster
  than curl's parser.
  Source: https://www.yagiz.co/state-of-url-parsing-2025
- A magnet-URL Rust parser (different crate) was mentioned at ~500–600 ns per parse.
- The `url` crate implements the WHATWG URL Standard with IDNA processing. It is
  more complex than a bare parser and is likely in the low-microseconds range for
  typical `hasp`-style URLs (< 100 chars, no internationalized domains).

**hasp implication:** Re-parsing a URL on every `get()` call is not a measurable
overhead compared to any backend I/O. Caching the parsed URL is still good practice
to avoid allocation cost, but this is not a performance-critical decision.

---

## 7. `SecretString` Allocation Cost

### secrecy crate
- `SecretString` = `SecretBox<str>` = `Secret<Box<str>>`
- `SecretBox<T>` is `#[repr(transparent)]` over the inner value; no extra heap
  allocation beyond what `Box<str>` or `String` would require.
  Source: https://docs.rs/secrecy/latest/secrecy/struct.SecretBox.html

**Overhead beyond raw `String`:**
- Zero structural overhead: same heap layout as the inner type.
- `Drop` impl calls `zeroize()` — adds one pass of volatile writes over the buffer
  on drop. For a 32-byte secret this is ~0.32 ns of actual work (see §3 above);
  unmeasurable relative to I/O cost.
- No published Rust benchmark comparing `SecretString` allocation to `String`
  allocation found.

**`SecretBox<[u8]>` vs `Vec<u8>`:**
- Same layout question; `Box<[u8]>` is a fat pointer (ptr + len), same as a slice
  reference, no extra allocation.
- Overhead vs `Vec<u8>`: avoids capacity field (3-word vs 2-word stack struct),
  and `Box<[u8]>` cannot reallocate — this is a security feature (prevents copies
  from reallocation).

**hasp implication:** Using `secrecy::SecretString` or `SecretBox<[u8]>` has
negligible runtime overhead vs raw `String`/`Vec<u8>`. The wrapping is essentially
free; cost is only the zeroize-on-drop path which runs once and is nanosecond-scale.

---

## Gap summary

| Topic | Data quality |
|-------|-------------|
| macOS Keychain warm latency | No data — needs self-measurement |
| macOS Keychain cold latency | Anecdote only (3.3 s worst case) |
| Windows CredRead latency | No data |
| Linux DBus Secret Service roundtrip | No data |
| mlock() per-page overhead | No data (indirect inference available) |
| zeroize ns/byte | Derived from hardware fill throughput, not direct measurement |
| AWS SM in-region latency | Community reports 100–400 ms |
| AWS SSM in-region latency | X-Ray trace ~64 ms |
| Vault KV read (Raft) | 2.25 ms (Consul backend, lab conditions) |
| GCP Secret Manager latency | No reliable data |
| Azure Key Vault warm latency | No data (cold: 10–13 s) |
| rustls handshake ms | Charts only; no text figures |
| TLS 1.3 1-RTT vs resumption | 5–10x improvement (qualitative from rustls issue) |
| url::Url parse ns | No data; estimated < 10 µs |
| SecretString overhead | Zero structural; ~0.3 ns drop overhead |
