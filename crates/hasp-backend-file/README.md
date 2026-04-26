# hasp-backend-file

`file://` backend for the [`hasp`](https://github.com/rustpunk/hasp) secrets library.

## URL grammar

```
file:///absolute/path/to/secret
file://localhost/absolute/path/to/secret
file://./relative/path/to/secret
file:///absolute/path/to/secret?raw=true
```

- **Absolute paths** use an empty host or `localhost`: `file:///etc/secrets/db.txt`.
- **Relative paths** use `.` as the host: `file://./config/secrets.txt`
  (resolved relative to the current working directory).
- **`?raw=true`** disables the default newline trimming. No other query
  parameters are accepted.

## Supported operations

| Operation | Support |
|-----------|---------|
| `get`     | Read file contents as `SecretString`. Default strips one trailing `\n` or `\r\n`. |
| `put`     | Write secret to file; creates parent directories if missing. |
| `exists`  | `true` if the path exists. |
| `delete`  | Remove the file. |
| `list`    | `UnsupportedOperation` — directory enumeration is not implemented. |

## Default newline trimming

Most secret files are created with `echo "secret" > file`, which appends an
unwanted newline. By default `file://` strips exactly one trailing `\r\n` or
`\n`. Binary secrets or passphrase files where trailing whitespace is
intentional should use `?raw=true`.

## Error mapping

| `std::io::Error`        | `hasp::Error`            |
|-------------------------|--------------------------|
| `NotFound`              | `NotFound`               |
| `PermissionDenied`      | `PermissionDenied`       |
| `WouldBlock`            | `Backend { Transient }`  |
| `TimedOut`              | `Backend { Transient }`  |
| `Interrupted`           | `Backend { Transient }`  |
| All other I/O errors    | `Backend { Permanent }`  |

## License

MIT OR Apache-2.0
