# hasp-backend-keyring

`keyring://` backend for the `hasp` secrets library.

## URL Grammar

```
keyring://<service>/<account>[?target=<target>]
```

- `service` (host): Required. Maps to the keyring service name.
- `account` (first path segment): Required. Maps to the keyring account name.
- `target` (query parameter, optional): Platform-specific modifier.

Only one path segment is allowed. Any query parameter other than `target`
is rejected with `Error::InvalidUrl`.

## Supported Operations

| Operation | Support | Notes |
|-----------|---------|-------|
| `get` | ✅ | Reads password from OS keyring |
| `put` | ✅ | Writes password to OS keyring |
| `exists` | ✅ | Returns true if a password is set |
| `delete` | ✅ | Removes the credential |
| `list` | ❌ | Unsupported |

## Platform-Specific Failure Modes

- **macOS**: Keychain ACL may reject access after binary re-sign or move.
  Returns `Backend { kind: Permanent }`.
- **Windows**: Credentials may roam across AD-joined machines.
  Returns `Backend { kind: Transient }` for sync failures.
- **Linux (Secret Service)**: Requires a DBus session bus; fails in
  headless containers without a secrets daemon.
  Returns `Backend { kind: Permanent, message: "keyring locked or unavailable" }`.
- **Linux (Keyutils)**: Alternative to Secret Service; not enabled by default.
  Enable by depending on `linux-keyutils-keyring-store` instead of
  `dbus-secret-service-keyring-store` in your build.

## Error Mapping

| `keyring_core::Error` | `hasp::Error` |
|-----------------------|---------------|
| `NoEntry` | `NotFound` |
| `NoStorageAccess` | `Backend { kind: Permanent }` |
| `PlatformFailure` | `Backend { kind: Transient }` |
| `Ambiguous` | `Backend { kind: Permanent }` |
| `NotSupportedByStore` | `UnsupportedOperation` |
| `TooLong` / `BadDataFormat` | `Backend { kind: Permanent }` |
