# hasp Standards & Formal-Spec Research
# D1 (zeroization / memory-locking) · D6 (file-on-disk format) · cross-cutting

Date: 2026-04-26
Researcher role: standards / formal-spec
Companion to: notes/RESEARCH-d1-d2-d3-d7.md (Rust crate ecosystem)

---

## Citations Table

| # | Source | Year | Body | Relevant claim (one sentence) | URL |
|---|--------|------|------|-------------------------------|-----|
| 1 | NIST SP 800-57 Part 1 Rev. 5 | 2020 | NIST | Key destruction function: "when a key is no longer needed, it must be destroyed beyond recovery through … zeroizing memory." | https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf |
| 2 | FIPS 140-2 (Section 4.7) | 2001 (upd 2002) | NIST | Defines zeroization as "a method of erasing … cryptographic keys … by altering or deleting the contents of the data storage to prevent recovery"; mandates that "all plaintext secret and private keys and unprotected CSPs shall be zeroized when entering or exiting the maintenance role." | https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.140-2.pdf |
| 3 | FIPS 140-3 / CMVP | 2019 | NIST / ISO | References ISO/IEC 19790:2012; requires zeroization of "all unprotected Sensitive Security Parameters (SSP)" and, at Level 3+, hardware-enforced zeroization on tamper detection. | https://csrc.nist.gov/pubs/fips/140-3/final |
| 4 | NIST SP 800-88 Rev. 2 | 2022 | NIST | Addresses volatile memory (DRAM) as a media type in sanitization scope; a "statement of volatility" is used to decide which components hold sensitive data and require clearing. | https://csrc.nist.gov/pubs/sp/800/88/r2/final |
| 5 | OWASP Secrets Management Cheat Sheet §2.5 | 2023 | OWASP | "After a secret has been used, the memory it occupied should be zeroed out to prevent lingering"; frames this as risk reduction, not an absolute control, and calls it potentially "overkill" when the threat actor cannot realistically gain memory access. | https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html |
| 6 | OWASP ASVS 4.0 §V6.4 | 2019 | OWASP | Control 6.4.2 (L2/L3): "Key material is not exposed to the application but instead uses an isolated security module like a vault for cryptographic operations" — mandates keeping cryptographic key material outside the application's address space when possible; 6.4.1 requires a dedicated secrets management solution (key vault). | https://github.com/OWASP/ASVS/blob/master/4.0/en/0x14-V6-Cryptography.md |
| 7 | CWE-591 (MITRE) | current | MITRE | "On POSIX systems the mlock() call ensures that a page will stay resident in memory but does not guarantee that the page will not appear in the swap … it is unsuitable for use as a protection mechanism for sensitive data"; Linux does make this guarantee but it is "non-standard and is not portable." | https://cwe.mitre.org/data/definitions/591.html |
| 8 | zeroize crate docs (RustCrypto) | 2024 | RustCrypto | Uses `core::ptr::write_volatile` + `core::sync::atomic::compiler_fence(Ordering::SeqCst)` to prevent compiler elision of zeroing; explicitly calls mlock "often overkill" and "explicitly out-of-scope for this crate." | https://docs.rs/zeroize/latest/zeroize/ |
| 9 | secrecy crate docs (iqlusioninc) | 2024 | iqlusioninc | "Does not provide more advanced memory protection mechanisms e.g. ones based on mlock(2)/mprotect(2)"; zeroize-on-drop is the only memory hygiene guarantee; recommends the `secrets` crate for mlock/mprotect consumers. | https://docs.rs/secrecy/latest/secrecy/ |
| 10 | CipherStash: "Verifying Rust Zeroize with Assembly" | 2023 | CipherStash | Confirms via disassembly that `write_volatile` zeroing is present in compiled output; found that naïve SIMD drop implementations are silently elided unless the pattern is correct. | https://cipherstash.com/blog/verifying-rust-zeroize-with-assembly-including-portable-simd |
| 11 | stouset/secrets crate (Rust) | 2022 | stouset | Provides mlock + mprotect + guard pages; marks protected memory inaccessible via mprotect except during active borrow — the alternative to secrecy when OS-level protection is required. | https://github.com/stouset/secrets |
| 12 | secrecy issue #480 (iqlusioninc) | 2022 | iqlusioninc | mlock feature request was closed as "not planned" — maintainers deliberately keep secrecy simple/safe/no_std; mlock deferred to external crates. | https://github.com/iqlusioninc/crates/issues/480 |
| 13 | Linux memfd_secret(2) | 2021 (Linux 5.14) | kernel.org | Creates anonymous memory regions removed from the kernel page tables so even the kernel cannot read them; also locks pages against swap (equivalent to mlock); before Linux 6.5, required opt-in kernel parameter. | https://man7.org/linux/man-pages/man2/memfd_secret.2.html |
| 14 | fork CoW + zeroization (search synthesis) | current | community | After fork(), child inherits parent's CoW pages verbatim; secret material must be zeroized *before* fork() to prevent the child from reading it through shared pages. | https://www.zeroize-python.com (representative; primary source is Linux fork(2) man page https://man7.org/linux/man-pages/man2/fork.2.html) |
| 15 | smallstep: "How to Handle Secrets on the Command Line" | 2020 | Smallstep | Secrets passed on argv are visible in /proc/<pid>/cmdline (globally readable); argv overwrite by the process is subject to a race; the safe pattern is file/stdin/env — never argv. | https://smallstep.com/blog/command-line-secrets/ |
| 16 | Docker secrets file format (GitHub aspnet/Configuration #706) | 2017 | Community / Docker | Docker writes secrets verbatim to /run/secrets/<name>; trailing `\n` is an artifact of `echo` (the tool that creates them), not of Docker; consuming applications should strip exactly one trailing newline for interop with the common creation idiom. | https://github.com/aspnet/Configuration/issues/706 |
| 17 | Docker secrets official docs | current | Docker | Mounts secrets as in-memory files at /run/secrets/<name>; content is the exact bytes of the secret as provided to `docker secret create`; the default creation idiom using `echo` appends a `\n`. | https://docs.docker.com/engine/swarm/secrets/ |
| 18 | Kubernetes secrets (docs + community) | current | kubernetes.io | Secrets mounted as volume files contain exactly the base64-decoded bytes; Kubernetes itself does not append a newline; newlines arise from encoding (`base64` with default behavior, or YAML multi-line strings). | https://kubernetes.io/docs/concepts/configuration/secret/ |
| 19 | systemd-creds / $CREDENTIALS_DIRECTORY | current | systemd.io | Credentials are binary-capable files; `--newline=auto` adds trailing newline only when writing to a TTY (not to files); the on-disk format in `$CREDENTIALS_DIRECTORY` is the raw decrypted bytes with no appended newline. | https://systemd.io/CREDENTIALS/ |
| 20 | RFC 7512: PKCS#11 URI Scheme | 2015 | IETF | Defines `pkcs11:` URI scheme for addressing PKCS#11 objects (cert, private, public, secret-key, data) inside tokens via token/slot/object/type/id attributes; query component carries pin-source and module-path. | https://www.rfc-editor.org/rfc/rfc7512.html |
| 21 | KMIP (OASIS) v2.0 | 2019 | OASIS | Uses server-assigned opaque Unique Identifiers (UIDs) per managed object, not URL-style human-readable paths; locate+retrieve model differs fundamentally from hasp's URL-per-secret grammar. | https://docs.oasis-open.org/kmip/kmip-spec/v2.0/os/kmip-spec-v2.0-os.html |
| 22 | CWE-591 mlock on Windows VirtualLock | current | MITRE | VirtualLock on older Windows (95/98/Me) is a stub; on current Windows it prevents paging only while a thread is executing in the process — does not provide persistent swap protection. | https://cwe.mitre.org/data/definitions/591.html |
| 23 | PostgreSQL libpq pgpass format | current | PostgreSQL | .pgpass uses `hostname:port:database:username:password` per line; docs say to escape `:` and `\` but are silent on trailing-whitespace / trailing-newline treatment for the password field. | https://www.postgresql.org/docs/current/libpq-pgpass.html |

---

## Detailed Findings by Decision Area

### D1 — Zeroization / Memory-Locking Posture

#### What the standards actually mandate

FIPS 140-2 §4.7 mandates zeroization for validated *cryptographic modules* (HSMs, software token libraries). The standard applies to the module boundary, not to general application code that calls the module. An unprivileged user-space library that *delegates* cryptographic operations to a validated module is not itself subject to FIPS 140-2. However the zeroization principle — "destroy plaintext key material when no longer needed" — is imported by NIST SP 800-57 as a key lifecycle requirement and by OWASP ASVS 6.4.2 as a verification control.

NIST SP 800-57 Part 1 Rev. 5 §8.3.4 states that key destruction must render key material "unrecoverable"; zeroization of volatile memory is listed as one valid mechanism. The standard is agnostic about implementation — it does not prescribe mlock, write_volatile, or any specific Rust crate.

NIST SP 800-88 Rev. 2 includes volatile memory (DRAM) in its scope via the "statement of volatility" concept, but its guidance is directed at system owners doing hardware disposal, not at software libraries. The applicability to in-process transient secret handling is indirect.

OWASP Secrets Management Cheat Sheet §2.5 explicitly calls memory zeroization a *risk reduction* measure that may be "overkill" depending on the threat model. It recommends it for "untrusted environments or situations where tight security is of utmost importance."

**Takeaway:** The standards mandate the *outcome* (key material not recoverable after use), not the mechanism. `zeroize`-on-drop satisfies this outcome for secrets that are heap-allocated in Rust.

#### mlock — meaningful or theatre?

The picture is nuanced and platform-specific:

- **CWE-591** (MITRE): "On POSIX systems, mlock() … does not guarantee that the page will not appear in the swap." Linux is a notable exception that *does* guarantee no-swap for mlocked pages, but this is "non-standard and non-portable."
- **Windows VirtualLock**: Only prevents paging while a thread is executing; does not provide persistent no-swap guarantee on older Windows versions (stub on 9x).
- **Linux memfd_secret(2)** (kernel 5.14+): Removes pages from the kernel's direct map so even the kernel cannot read them; also implies mlock semantics. Before kernel 6.5, required `secretmem.enable=y` boot parameter. Considered the strongest available protection on Linux, but has no portable equivalent.
- **zeroize crate authors**: Explicitly classify mlock as "often overkill" and "out-of-scope."
- **secrecy crate**: Deliberately does not call mlock; delegates to `secrets` crate (stouset) for mlock+mprotect+guard-pages use cases.

**Practical synthesis for hasp's scope:**

| Environment | mlock value | Reasoning |
|-------------|-------------|-----------|
| Short-lived CLI (most hasp invocations) | Low | Process exits before swap pressure materializes; swap leak window is negligible. |
| Long-lived daemon (Ferrule REPL, Spall server) | Moderate | Swap leaks become plausible if the daemon holds secrets across high-memory-pressure events. |
| Container (Docker/k8s) | Low-moderate | Container memory limits reduce swap risk; Linux mlock guarantee applies on most container hosts. |
| Desktop (laptop, suspend/hibernate) | High | Hibernate writes entire RAM to disk regardless of mlock. mlock does not help here; hibernation inhibition (via memfd_secret or equivalent) is the only mitigation. |

**Recommendation for hasp:** Zeroize-on-drop via `secrecy` + `zeroize` is the correct baseline. mlock is opt-in via a Cargo feature (`memory-lock`?) backed by `memsec` or `secrets`; it is not the default. Document the tradeoff: mlock costs a syscall per allocation, may fail under RLIMIT_MEMLOCK, and on most platforms does not protect against hibernation.

#### write_volatile + compiler_fence: is it sufficient?

Yes, for the compiler. The CipherStash assembly verification confirms that zeroize's `write_volatile` + `compiler_fence(SeqCst)` pattern is actually present in the output binary — the optimizer does not elide it. The fence prevents compiler-level reordering. However:

- It does *not* prevent CPU microarchitectural covert-channel leakage (Spectre, Meltdown) of already-read values.
- It does *not* guarantee that the OS page is not in swap *before* the zeroing occurs (only mlock/memfd_secret prevent that).
- It does *not* handle compiler-introduced copies during moves (Rust's move semantics physically copy bytes; use `Pin` + `Box` to avoid stack copies for large secrets).
- For `Vec`/`String`/`SecretString` with growth-triggered reallocations, old buffers are zeroed at deallocation (zeroize zeroes the full capacity), but they *were* in memory unzeroed between reallocation and deallocation.

`secrecy::SecretBox` with a pre-sized allocation (no reallocation) + zeroize-on-drop is the safe pattern. For password-style short strings this is fine. For long secrets requiring heap growth, callers should pre-allocate with capacity and avoid reallocation.

#### Fork / CoW threat

When a process forks, the child inherits CoW copies of the parent's pages. Any secret in the parent's heap at fork time is readable by the child *even if the parent subsequently zeroizes it* — the child already has its own CoW copy. The zeroize-before-fork rule is therefore:

> Zeroize all secrets (call drop or explicit Zeroize::zeroize) *before* calling fork()/std::process::Command::spawn() or any function that ultimately calls clone(2).

hasp as a library cannot enforce this — it cannot know when the caller will fork. hasp *can* document this requirement in public API docs for callers that embed it in long-lived daemons that may fork. For CLI invocations, the hasp process is typically the one forked *from* a shell; secrets acquired after the fork are not at risk from earlier CoW.

#### Process argv hygiene: library vs application responsibility

The consensus from the smallstep analysis and CWE literature is:

- **Never** pass secrets as command-line arguments. /proc/<pid>/cmdline is globally readable; secrets in argv appear in ps output, shell history, audit logs, and `/proc`.
- **argv sanitization is the CLI's responsibility**, not the library's. The library receives secrets through API calls (file paths, environment variables, named pipe content); the CLI layer controls how it acquires those values and must not accept them on argv.
- hasp CLI design: use `--secret-file` / stdin / env var for secret *input*; stdout for secret *output*. No `--password=<value>` flag.

---

### D6 — File-on-Disk Secrets Convention

#### Byte-level format: the consensus

There is no RFC or formal standard governing "password file format." The platforms have converged on a de facto convention through practice:

| Platform | Canonical format | Trailing newline? |
|----------|-----------------|-------------------|
| Docker Swarm secrets (`/run/secrets/<name>`) | Verbatim bytes as provided to `docker secret create` | **Not added by Docker.** Arises from `echo` in the common creation idiom. `echo -n` avoids it. |
| Kubernetes volume-mounted secrets | Base64-decoded verbatim bytes from the `data:` field | **Not added by Kubernetes.** Arises from `base64` encoding tools that append `\n` by default. |
| systemd-creds (`$CREDENTIALS_DIRECTORY/<name>`) | Raw decrypted bytes | **Not added by systemd.** `--newline=auto` adds it only when writing to TTY, never to files. |
| Podman secrets | Verbatim bytes as provided to `podman secret create` | **Not added by Podman.** Same echo-idiosyncrasy as Docker. |
| PostgreSQL .pgpass | `host:port:db:user:password` per line; newline terminates each *line* | The *line* ends in `\n`; the password *field* has no trailing newline of its own. |

**The consistent answer:** All platforms store the raw bytes; trailing `\n` is an artifact of the *creation tool* (echo, base64), not the secret store. The consumer (hasp `file://` backend) should:

1. Read the file verbatim by default.
2. Offer a `trim_trailing_newline` option (or make it the default) to strip exactly one trailing `\n` (or `\r\n`) — this is the dominant consumer expectation, as evidenced by Docker community workarounds (aspnet Configuration #706) and the Kubernetes "beware hidden newlines" lore.
3. Document the behavior explicitly. The trim should be configurable because some secrets (binary keys, private keys in PEM format which already end in `\n`) have meaningful trailing bytes.

#### Specific question: PEM files and `\n`

PEM-formatted private keys (RSA, EC, Ed25519) end with `-----END ... KEY-----\n` — the trailing newline is *part of the format*. Stripping it would corrupt the PEM. hasp's file backend must therefore distinguish:
- Text password secrets: trim `\n` by default.
- Binary / PEM secrets: read verbatim (perhaps indicated by a `type=raw` or `format=pem` URL query parameter).

---

### Cross-Cutting Findings

#### PKCS#11 URI (RFC 7512) relevance to hasp's URL grammar

RFC 7512 defines `pkcs11:token=<label>;object=<label>;type=<type>?pin-source=<uri>` — semicolon-delimited attributes, not slash-delimited hierarchy. This is a parallel design to hasp's `keyring://host/path` scheme. The PKCS#11 model addresses objects inside HSM tokens; hasp's `keyring://` scheme addresses the OS keyring. They do not conflict: hasp could in principle add a `pkcs11://` scheme that wraps RFC 7512 addressing, but this is out of scope for the initial design.

**Takeaway:** The PKCS#11 object model (token → slot → object type) is conceptually useful for understanding HSM-backed secret stores but does not impose constraints on hasp's URL grammar.

#### KMIP relevance

KMIP uses opaque server-assigned UIDs, not human-readable URLs. The design philosophy is opposite to hasp's URL-first approach. KMIP is authoritative for enterprise KMS integration but hasp need not map to KMIP identifiers at the library surface. If a future `kmip://` backend lands, it would internally translate hasp URLs to KMIP Locate+Get operations.

#### Platform credential storage (cross-platform)

| Platform | Storage mechanism | ACL model |
|----------|-------------------|-----------|
| Windows | DPAPI (CryptProtectData) | Per-user encryption; other processes in same session can read if no additional ACL |
| macOS | Keychain | ACL per item; other apps require user prompt unless explicitly trusted |
| Linux | libsecret / Secret Service (D-Bus) | Per-session or system keyring; application ACL via D-Bus policy |

hasp's `keyring://` backend abstracts these via the `keyring` crate. The threat model implication: on Windows and Linux, ambient-credential daemons can in principle read any secret in the same user's keyring without additional UI prompts; macOS provides stronger ACL isolation. hasp should document this.

---

## Synthesis: Design Implications for hasp

**On zeroization (secrecy + zeroize baseline):**
The standards literature (NIST 800-57, FIPS 140-2/3, OWASP Cheat Sheet, ASVS) universally endorses zeroization of secret material after use. `secrecy::SecretBox<str>` (= `SecretString`) with `zeroize`-on-drop satisfies this requirement for the vast majority of hasp's use cases. The `write_volatile` + `compiler_fence` approach in the `zeroize` crate is verified to survive compiler optimization.

**On mlock:**
mlock is not mandated by any standard for general-purpose user-space secrets libraries. CWE-591's own text calls POSIX mlock unreliable for swap protection across platforms. The hasp default should not call mlock. A `memory-lock` Cargo feature (off by default) can provide opt-in mlock via `memsec` for callers with daemon threat models where swap protection is meaningful. Document the hibernate caveat.

**On compiler fencing (volatile write ordering):**
`zeroize` already handles this correctly via `write_volatile` + `compiler_fence`. hasp does not need to add additional barriers. Use `secrecy::SecretBox` pre-allocated to the correct capacity and avoid grow-on-write patterns that trigger reallocation.

**On fork / CoW:**
Document in hasp's public API that callers embedding hasp in a daemon that forks must zeroize all live `SecretBox` values before calling fork or `Command::spawn`. hasp cannot enforce this; it can document it. The CLI case is self-contained (no fork after secret acquisition).

**On argv hygiene:**
hasp's CLI must never accept secret values on argv. The `file://` backend accepts a path on argv, which is fine — paths are not secrets. Secret values flow through file content, stdin, or environment variables.

**On file-on-disk format (D6):**
- Default behavior for `file://` backend: strip exactly one trailing `\n` (or `\r\n`) from the raw file content. This matches the dominant ecosystem expectation (Docker, Kubernetes, systemd-creds all produce this artifact via common tooling).
- Override: `file://path/to/secret?trim=false` or `type=binary` URL parameter for verbatim reading (binary keys, PEM, etc.).
- Explicitly document this in the `file://` scheme reference.

**On PKCS#11:**
RFC 7512's `pkcs11:` URI scheme does not conflict with hasp's URL grammar. hasp could eventually add a `pkcs11://` scheme translating to RFC 7512 internally. Not a near-term priority.

**On KMIP:**
Not a design constraint. Future `kmip://` backend would translate internally.

---

## Open Questions (for future research)

1. **Reallocation safety:** Is there a Rust pattern (e.g., custom allocator + `Pin<Box<[u8]>>`) that prevents reallocation of `SecretString` without forking to the `secrets` crate's mprotect approach?
2. **memfd_secret availability:** Should hasp detect Linux ≥ 5.14 + `secretmem.enable=y` and use memfd_secret pages as the backing store for daemon mode? This would be the strongest available protection without full HSM delegation.
3. **ASVS 6.4.2 applicability:** For Ferrule/Spall use cases that need to satisfy L2/L3 ASVS, the "key material not exposed to application" control ideally means hasp never decrypts inside the application process. This is at odds with hasp's design (hasp *is* the decryption + retrieval layer). Document this tension; the ASVS control targets *cryptographic* key material (signing keys, encryption keys), not general-purpose application secrets like API tokens.
