# Quick Start

This walkthrough takes you from a fresh hasp install to managing
secrets across two backends in under five minutes. Everything here uses
only `env://` and `file://` — no cloud accounts, no tokens, no setup.

## Step 1 — your first get

Create a secret using the environment, then read it back:

```bash
export DEMO_SECRET="hello-from-hasp"
hasp get env://DEMO_SECRET
```

Output:

```text
hello-from-hasp
```

The value goes to stdout; that's the contract. Everything else goes to
stderr, so piping works cleanly.

## Step 2 — check and delete

See whether a secret exists before you use it:

```bash
hasp exists env://DEMO_SECRET && echo "present" || echo "missing"
```

Delete it and confirm it's gone:

```bash
hasp delete env://DEMO_SECRET
hasp exists env://DEMO_SECRET || echo "confirmed deleted"
```

`delete` exits 0 on success. `exists` exits 0 when the secret is
present and 1 when it is absent, making it natural for shell
conditionals.

## Step 3 — write to a file

Put a value directly, or omit it to be prompted securely:

```bash
hasp put file:///tmp/hasp-demo "shh"
hasp get file:///tmp/hasp-demo
# shh

# Prompt mode (no echo in TTY)
hasp put file:///tmp/hasp-demo
# Value: ·····
```

The file backend creates parent directories automatically.

## Step 4 — profile aliases

Typing `env://` every time gets old. Define shortcuts in
`~/.config/hasp/profiles.toml`:

```bash
mkdir -p ~/.config/hasp
cat > ~/.config/hasp/profiles.toml <<'EOF'
[profiles.demo]
secret = "env://DEMO_SECRET"
token = "file:///tmp/hasp-demo"

[profiles.local]
db_password = "env://DB_PASSWORD"
EOF
```

Now use the alias:

```bash
export DEMO_SECRET="aliased-value"
hasp get "@demo/secret"
# aliased-value
```

If a profile contains a key with the same name as the profile itself
(e.g. `[profiles.foo]` with `foo = "file:///etc/foo"`), the bare alias
`@foo` resolves to that URL. Otherwise you must write `@foo/key`.

## Step 5 — pipe-friendly output

The default output is plaintext to stdout. No JSON wrappers, no quotes,
no trailing newline tricks:

```bash
hasp get "@demo/secret" | wc -c
# 13

# Use in a command substitution
MY_TOKEN=$(hasp get "@demo/token")
# MY_TOKEN is exactly the bytes stored, no extra whitespace
```

For `file://` values that were written with a trailing newline, hasp
strips it automatically on read. This means:

```bash
echo -n "no-newline" | hasp put file:///tmp/clean -
hasp get file:///tmp/clean | xxd | tail -1
# no trailing 0a
```

## Where to next

- [How Hasp Thinks](concepts.md) — the abstractions everything is built
  on.
- [Profile Aliases](profiles.md) — deeper alias resolution, env
  overrides, and config layout.
- [Supported Backends](backends.md) — what operations work where, and
  what each URL looks like.
