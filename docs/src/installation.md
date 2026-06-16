# Installation

Hasp ships as a single static binary. No runtime libraries are required
for the pure-Rust backends (`env://`, `file://`, `keyring://`). Cloud
SDKs are compiled in when their Cargo features are enabled.

## Pre-built binaries

The fastest path on any supported OS:

```bash
# Linux x86_64
curl -L https://github.com/rustpunk/hasp/releases/latest/download/hasp-linux-x64.tar.gz \
  | tar xz
sudo mv hasp /usr/local/bin/
```

Replace the asset name for other targets (`hasp-macos-arm64.tar.gz`,
`hasp-macos-x64.tar.gz`, `hasp-windows-x64.zip`). The full list is on
the [releases page](https://github.com/rustpunk/hasp/releases).

On macOS, if Gatekeeper blocks the binary the first time, allow it
under **System Settings → Privacy & Security**, or strip the
quarantine attribute:

```bash
xattr -d com.apple.quarantine /usr/local/bin/hasp
```

On Windows, drop `hasp.exe` somewhere on `%PATH%` (or run it from a
folder you've added to `PATH`).

## Verifying build provenance

Every release artifact is published with a [SLSA v1.0](https://slsa.dev/)
build attestation signed via GitHub OIDC and sigstore. The attestation
proves the artifact was produced from a specific commit of
`github.com/rustpunk/hasp` by the official release workflow — it
defends against the supply-chain class demonstrated by the Bitwarden CLI
npm compromise.

The simplest verification is with the GitHub CLI:

```bash
gh attestation verify hasp-linux-x64.tar.gz \
  --owner rustpunk
```

This queries the GitHub attestations API, fetches the signed bundle,
and verifies the artifact's digest. No additional flags are needed —
the workflow + commit + builder identity are all proven in one call.

For offline / air-gapped verification, the sigstore bundle is published
alongside each release artifact as `<asset>.intoto.jsonl`. Pass it to
any sigstore-compatible verifier — see GitHub's
[verifying attestations offline](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/verifying-attestations-offline)
guide for the current toolchain (`gh attestation verify --bundle` plus
`--no-api`, or [`cosign verify-blob-attestation`](https://docs.sigstore.dev/cosign/verifying/attestation/)).

The attestation establishes **Build L2** in the SLSA terminology: the
build identity is verifiable, but the build environment is not
isolated (hosted GitHub runners). It does **not** defend against a
maintainer account compromise pushing a malicious release tag — that
class requires SLSA L3 (isolation-of-build), which is deferred.

## From source

Requires a stable Rust toolchain (install via [rustup](https://rustup.rs/)).

```bash
git clone https://github.com/rustpunk/hasp.git
cd hasp

# Default build — env, file, keyring, op, vault, bw, aws-sm, aws-ssm,
# gcp-sm, azure-kv
cargo build --release --bin hasp

# Or install straight to ~/.cargo/bin
cargo install --path crates/hasp-cli
```

The release binary lands at `./target/release/hasp`.

## Feature flags

| Feature | Default | Notes |
|---|---|---|
| `env` | ✅ | Environment variables (`env://`) |
| `file` | ✅ | Local filesystem (`file://`) |
| `keyring` | ✅ | OS keyring (`keyring://`) |
| `op` | ✅ | 1Password (`op://`) — needs 1Password CLI |
| `vault` | ✅ | HashiCorp Vault (`vault://`) — needs `VAULT_ADDR` |
| `bw` | ✅ | Bitwarden (`bw://`) — needs `bw` CLI |
| `aws-sm` | ✅ | AWS Secrets Manager (`aws-sm://`) |
| `aws-ssm` | ✅ | AWS Systems Manager Parameter Store (`aws-ssm://`) |
| `gcp-sm` | ✅ | GCP Secret Manager (`gcp-sm://`) |
| `azure-kv` | ✅ | Azure Key Vault (`azure-kv://`) |

Build a minimal binary with only the backends you need:

```bash
# env + file only — tiny, no cloud deps
cargo build --release --bin hasp --no-default-features --features env,file

# Just the cloud providers you actually use
cargo build --release --bin hasp --no-default-features \
  --features env,file,aws-sm,aws-ssm
```

Cutting unused backends shrinks the binary and trims the dependency
graph; functionally there's no difference for the backends you keep.

## Hardened builds — `memory-lock` feature

The `memory-lock` feature instructs `hasp-core` to lock the physical
memory pages backing every fetched secret, preventing them from being
swapped to disk or included in crash dumps. Enable it at build time:

```bash
cargo build --release --bin hasp \
  --features hasp-core/memory-lock
```

### What it does

| Platform | Calls made |
|---|---|
| Linux | `mlock(addr, len)` + `madvise(MADV_DONTDUMP)` + `madvise(MADV_WIPEONFORK)` |
| macOS | `mlock(addr, len)` |
| Windows | `VirtualLock(addr, len)` |

`MADV_DONTDUMP` excludes the pages from `/proc/<pid>/coredump_filter`;
`MADV_WIPEONFORK` zeroes them in the child after `fork(2)`.

### Graceful degrade

All calls are best-effort. On Linux, `RLIMIT_MEMLOCK` defaults to
64 KiB for unprivileged users — once that budget is exhausted, `mlock`
returns `EAGAIN` and the secret remains usable but swappable. The
`MitigationOutcome` records whether each call succeeded; pass
`--verbose` to surface a summary in a future `hasp` release.

### What it does NOT promise

- Secrets already in the kernel's page cache (e.g., from `file://` read)
  before `mlock` was called may still be swappable until the call lands.
- Core dump exclusion does not prevent `/proc/<pid>/mem` reads by a
  same-uid process — that requires `PR_SET_DUMPABLE` (already applied by
  `hasp-core::hardening` regardless of this feature).
- SLSA / supply-chain guarantees are independent of runtime memory posture.

## Verify the install

```bash
hasp --version
# hasp 0.1.0-alpha

# Smoke test with no auth required
export HASP_SMOKE="ok"
hasp get env://HASP_SMOKE
```

If any of these fail, see [Troubleshooting](troubleshooting.md).

## Next steps

- [Quick Start](quickstart.md) — fetch, store, and delete a real secret.
- [How Hasp Thinks](concepts.md) — the mental model.
