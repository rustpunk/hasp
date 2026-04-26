# hasp-backend-env

`env://` backend for the `hasp` secrets library.

## URL Grammar

```
env://VAR_NAME
```

- `VAR_NAME` (host): The name of the environment variable. Required.
- No path, query, or fragment components are allowed.

## Supported Operations

| Operation | Support | Notes |
|-----------|---------|-------|
| `get` | ✅ | Returns the value of the environment variable |
| `exists` | ✅ | Returns true if the variable is set |
| `put` | ❌ | Unsupported — child processes cannot set parent environment variables |
| `list` | ❌ | Unsupported |
| `delete` | ❌ | Unsupported |

## Platform-Specific Failure Modes

- **Variable not set**: Returns `Error::NotFound`
- **Variable not valid Unicode**: Returns `Error::Backend { kind: Permanent }`
