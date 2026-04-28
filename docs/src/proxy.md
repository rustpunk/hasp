# HTTP CONNECT Proxy

Corporate networks often force outbound traffic through an HTTP CONNECT
proxy (Squid, Blue Coat, Zscaler, etc.). `hasp` supports explicit proxy
configuration for HTTP-based backends (`vault://`, `gcp-sm://`,
`azure-kv://`). AWS SDK backends (`aws-sm://`, `aws-ssm://`) honour
`HTTPS_PROXY` / `HTTP_PROXY` environment variables.

## Quick start

```bash
hasp get --proxy-url http://proxy.corp.example.com:8080 \
  vault://secret/data/myapp/db-password
```

This routes every HTTP request through `proxy.corp.example.com:8080`.

## Proxy configuration layers

Three layers, first hit wins:

1. **`--proxy-url <URL>`** CLI flag.
2. **`proxy_url = "..."`** in the active profile (`profiles.toml`).
3. **`ALL_PROXY`**, **`HTTPS_PROXY`**, or **`HTTP_PROXY`** env vars.

`NO_PROXY` is honoured at layer 3. Layers 1 and 2 are explicit user
intent and therefore bypass `NO_PROXY`.

### Example profile

```toml
[profiles.corp]
proxy_url = "http://proxy.corp.example.com:8080"
db_password = "vault://secret/data/myapp/db-password"
```

When you run `hasp get @corp/db_password`, the proxy from the `corp`
profile is used automatically.

### Authenticated proxies

Include credentials in the URL:

```bash
hasp get --proxy-url http://user:pass@proxy.corp.example.com:8080 \
  vault://secret/data/myapp/db-password
```

The credentials are sent via `Proxy-Authorization: Basic <base64>` during
the CONNECT handshake. Internally, the password is wrapped in
`secrecy::SecretString` so it never appears in `Debug` output or error
messages.

## Backend support matrix

| Backend | Explicit proxy (`--proxy-url`, profile) | Env vars (`HTTP_PROXY`, `NO_PROXY`) |
|---|---|---|
| `vault://` | ✅ via `reqwest::Proxy` | ✅ reqwest default |
| `gcp-sm://` | ✅ via `reqwest::Proxy` | ✅ reqwest default |
| `azure-kv://` | ✅ via `reqwest::Proxy` | ✅ reqwest default |
| `aws-sm://` | ⚠️ not yet; use env vars | ✅ AWS SDK default chain |
| `aws-ssm://` | ⚠️ not yet; use env vars | ✅ AWS SDK default chain |
| `op://` | N/A (delegates to `op` CLI) | N/A |
| `bw://` | N/A (delegates to `bw` CLI) | N/A |
| `keyring://` | N/A (OS IPC) | N/A |
| `file://` / `env://` | N/A (no network) | N/A |

## `NO_PROXY` syntax

`NO_PROXY` supports the same rules as curl:

- `*` — disables proxy for every host.
- `localhost,127.0.0.1` — exact matches, comma-separated.
- `.example.com` — suffix match (`db.example.com` hits,
  `example.com` does not).
- Port numbers in patterns are ignored.

Example:

```bash
export HTTP_PROXY=http://proxy.corp.example.com:8080
export NO_PROXY="localhost,127.0.0.1,.internal.example.com"

hasp get vault://vault.internal.example.com/secret/data/db
# → NOT proxied (matches .internal.example.com)

hasp get vault://vault.external.example.com/secret/data/db
# → proxied through proxy.corp.example.com:8080
```

## SOCKS5

SOCKS5 is not implemented in this release. If your network requires it,
use a local SOCKS5-to-HTTP-CONNECT adapter (e.g. `proxychains-ng` or a
small `nc` wrapper) and point `hasp` at that.
