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
