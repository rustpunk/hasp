# Shell Completions

Hasp supports two completion modes: a **static AOT subcommand** for
packaging and a **dynamic runtime system** powered by
`clap_complete` that completes profile aliases, URL schemes, and
file paths at tab-press time.

## Static completion scripts

Generate a completion script once and install it in your shell's
completion directory:

### Bash

```bash
hasp complete bash > /usr/share/bash-completion/completions/hasp
# or user-local:
hasp complete bash > ~/.local/share/bash-completion/completions/hasp
```

### Zsh

```bash
hasp complete zsh > "${fpath[1]}/_hasp"
```

### Fish

```bash
hasp complete fish > ~/.config/fish/completions/hasp.fish
```

### PowerShell

```powershell
hasp complete powershell | Out-String | Invoke-Expression
# Or save to your profile
```

The `complete` subcommand is hidden from `--help` because it is a
packaging concern, not a daily user workflow.

## Dynamic completions (recommended)

Dynamic completions use `clap_complete::CompleteEnv` to call back into
`hasp` on every tab press. This lets hasp suggest:

- **URL schemes** — `hasp get en<TAB>` → `env://`
- **Profile aliases** — `hasp get @prod/<TAB>` → keys in the prod
  profile from `profiles.toml`
- **File paths** — `hasp get file:///tmp/<TAB>` → native filesystem
  completion

To enable them, source the registration snippet for your shell:

### Bash

```bash
echo 'source <(COMPLETE=bash hasp)' >> ~/.bashrc
```

### Zsh

```zsh
echo 'source <(COMPLETE=zsh hasp)' >> ~/.zshrc
```

### Fish

```fish
echo 'COMPLETE=fish hasp | source' >> ~/.config/fish/completions/hasp.fish
```

### PowerShell

```powershell
echo '$env:COMPLETE = "powershell"; hasp | Out-String | Invoke-Expression; Remove-Item Env:\COMPLETE' >> $PROFILE
```

### How it works

The registration script emitted by `COMPLETE=<shell> hasp` is a thin
wrapper that calls back into `hasp` with the current command-line words.
Hasp parses the partial command, identifies which argument is being
completed, and returns candidates:

```text
$ hasp get en<TAB>
env://

$ hasp get @prod/<TAB>
@prod/db_password
@prod/api_key
```

Because the completion logic lives in the same binary as the CLI, it
is always in sync — no mismatched completion scripts after upgrades.

### Disabling dynamic completions

Set `COMPLETE=` or `COMPLETE=0`:

```bash
COMPLETE= hasp get env://HOME
```

## Completion internals

The `complete` subcommand uses
[`clap_complete`](https://github.com/clap-rs/clap/tree/main/clap_complete)
to generate shell-specific completion scripts. The dynamic path uses
`clap_complete::engine::ArgValueCompleter` attached to every `address`
argument in the derive macro, so custom completion logic is co-located
with the argument definition.

## Next steps

- [CLI Reference](cli-reference.md) — all flags and subcommands.
- [Troubleshooting](troubleshooting.md) — if completions aren't
  appearing.
