# hasp-cli

Unified secrets CLI — a thin shell over the `hasp` library.

Full documentation lives in the mdbook at `../../docs/`:

```bash
cd ../../docs
mdbook serve --open
```

Or read it online at `https://rustpunk.github.io/hasp/`.

## Quick preview

```bash
hasp get env://HOME
hasp put file:///tmp/secret "my-value"
hasp exists env://VAR || echo "missing"
hasp get @prod/db_password
```

## Quick links

- [Installation](https://rustpunk.github.io/hasp/installation.html)
- [Quick Start](https://rustpunk.github.io/hasp/quickstart.html)
- [Shell Completions](https://rustpunk.github.io/hasp/shell-completions.html)
- [CLI Reference](https://rustpunk.github.io/hasp/cli-reference.html)
- [Troubleshooting](https://rustpunk.github.io/hasp/troubleshooting.html)
