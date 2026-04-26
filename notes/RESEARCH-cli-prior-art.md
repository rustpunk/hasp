# hasp Prior-Art Research: Secrets CLI Ecosystem

Date: 2026-04-26  
Scope: User-facing CLI design patterns across 19 tools.  
Researcher: primary prior-art sweep (parallel web + firecrawl + WebFetch).  
Sources cited inline. No hasp design proposals in this file.

---

## Tool-by-Tool Survey

### chamber (Segment, AWS SSM frontend)
Source: https://github.com/segmentio/chamber/blob/master/README.md

**Addressing:** `<service>/<key>` positional args. Service maps to an SSM path prefix (`/<service>/KEY_NAME`). Keys are auto-normalized: hyphens → underscores, lowercased → UPPERCASED. Reserved name `_chamber` is internal.

**Profile/alias:** No formal profile system. Shell aliases are the documented pattern: `alias chamberprod='aws-vault exec production -- chamber'`. AWS KMS key aliases exist at infra level only.

**Output formats:** json (default), yaml, java-properties, csv, tsv, dotenv, tfvars. `env` subcommand has `--preserve-case` and `--escape-strings`.

**Exit codes:** Not documented.

**Redaction:** Selective: the `read` command shows one secret with metadata; bulk listing is deliberately limited. No explicit log-redaction posture documented.

**TTY interaction:** Not documented; defers to AWS CLI credential chain.

**Library vs CLI:** v3.0 added `context.Context` requirement on `Store` methods, indicating library consumers exist and are considered, but library API is secondary.

**Auth bootstrap:** AWS credential chain (env vars, instance profile, `~/.aws/credentials`).

---

### aws-vault (99designs)
Source: https://github.com/99designs/aws-vault/blob/master/USAGE.md

**Addressing:** Profile names from `~/.aws/config`. No URL scheme. Profiles reference credentials by name; role-assumption chains are declared with `role_arn + source_profile`.

**Profile/alias:** Full `~/.aws/config` profile system. Profiles can chain via `source_profile`, include via `include_profile` to reduce duplication. MFA serial is per-profile. AWS Vault caches session tokens across profiles sharing `mfa_serial`.

**Output formats:** `aws-vault export --format=json <profile>` for credential_process use. Binary returns short-lived temp creds to subprocess env.

**Exit codes:** Not documented explicitly. CLI binary propagates subprocess exit code via `os.Exit(exitcode)`.

**Redaction:** Long-lived keys stored in OS keystore only; never in env. Short-lived STS credentials are in subprocess env (visible in `/proc/<pid>/environ` to the subprocess's user).

**Library vs CLI:** Primarily a CLI tool. `credential_process` mechanism is the integration boundary for SDK consumers; no documented Go library API.

**Auth bootstrap:** OS keystore (keychain / pass / file backend) → STS GetSessionToken / AssumeRole. Disk cache of STS tokens in same backend.

**Known issues:** AWS CLI stores credentials unencrypted in `~/.aws/credentials`; aws-vault solves this by keeping master credentials in OS keystore. `.aws/cli/cache/` still writes short-lived tokens in plaintext to disk — a documented concern for high-security environments.

---

### vault CLI (HashiCorp)
Source: https://developer.hashicorp.com/vault/docs/commands

**Addressing:** Path-based Unix-style hierarchy: `vault kv get secret/myapp/db-pass`. No URI scheme; paths are just HTTP paths to the Vault API. `-field=password` extracts a single field.

**Profile/alias:** No profile system in CLI. `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE` are the knobs.

**Output formats:** `-format` flag or `VAULT_FORMAT` env: `table` (default), `json`, `yaml`, `jsonx` (XML). `-field=NAME` for single-value extraction.

**Newline trimming:** `-field` output explicitly does NOT include a trailing newline, documented as "ideal for piping to other processes." Raw `vault kv get` table output has newlines. Issue #3590 (2017, unresolved) documents that writing secrets from files via `value=@file` preserves trailing newlines in the stored value.

**Exit codes:** 0 = success; 1 = local/terminal error (bad flags, wrong arg count, validation failure); 2 = remote/server error (API failures, bad TLS, wrong API params). `vault status` has a third code: 2 = sealed. **Notable: does NOT distinguish not-found from permission-denied in exit code.**

**Redaction:** `-output-curl-string` and `-output-policy` are debug flags that don't emit secrets. Token cached at `~/.vault-token` in plaintext — a well-known disk-exposure risk.

**TTY interaction:** `vault login` prompts for tokens interactively. Uses terminal directly.

**Library vs CLI:** Separate `api` package for programmatic access. CLI is a consumer of the API library.

**Auth bootstrap:** Ambient `VAULT_TOKEN` or `~/.vault-token` file. Multiple auth backends via `vault login -method=...`.

---

### pass (passwordstore.org, GPG-backed)
Source: https://www.passwordstore.org/

**Addressing:** Filesystem hierarchy under `~/.password-store`. Paths use forward slashes: `Email/zx2c4.com`, `Business/cheese-whiz-factory`. No formal URI scheme. Keys are GPG-encrypted `.gpg` files; the filename IS the identifier.

**Profile/alias:** None. Single root store. Extensions and `PASSWORD_STORE_DIR` env var allow multi-root patterns.

**Output formats:** Full secret text to stdout (all lines). `--clip / -c` copies only the first line to clipboard with auto-clear (45 seconds). No `--format` flag.

**Multiline handling:** First line is the password by convention. Everything else is metadata. Clipboard only gets first line.

**Exit codes:** Not documented; standard Unix conventions inferred from shell script.

**Redaction:** GPG prompts via `gpg-agent` dialog. Secret contents go only to stdout or clipboard.

**TTY interaction:** gpg-agent handles the passphrase dialog (native OS dialog or terminal).

**Library vs CLI:** Shell script; no library surface.

---

### op (1Password vendor CLI)
Sources: https://developer.1password.com/docs/cli/secret-reference-syntax/ and https://developer.1password.com/docs/cli/reference/commands/run/

**Addressing:** `op://vault/item[/section]/field` — a formal 3- (or 4-) component URI scheme. Optional query parameters: `?attr=otp`, `?attr=id`, `?ssh-format=openssh`. Both names and UUIDs work; UUIDs are preferred for automation. Case-insensitive. Spaces require quoting. Field-only form: `op://vault/item/field`. Section form: `op://vault/item/section/field`.

**Profile/alias:** No config-file alias layer; users reference vaults and items by name or UUID directly.

**Output formats:** `--format json` for structured data. Single-value `op read op://vault/item/field` emits raw bytes to stdout.

**TTY interaction:** `op run` creates a PTY pair to redact secrets printed to stdout/stderr. `--no-masking` disables this. PTY can interfere with some terminal apps (dev containers, VS Code).

**Exit codes:** Now exits 1 (not 0) on server errors (changelog note, 2024). Not documented in detail; binary success/failure.

**Redaction:** op run PTY masking conceals secrets in stdout output (shows `<concealed by 1Password>`). Auth via biometric / service account.

**Library vs CLI:** CLI-only. Service account tokens are the integration boundary.

**Auth bootstrap:** Interactive biometric unlock or service account token (`OP_SERVICE_ACCOUNT_TOKEN`). No disk-cached plaintext token.

**3-component addressing:** Yes, explicitly: `op://vault/item/field` is the minimum; `op://vault/item/section/field` adds a 4th. This is the clearest prior art for multi-level addressing needing more than a 2-tuple.

---

### bw / bws (Bitwarden CLI — Password Manager and Secrets Manager)
Source: https://bitwarden.com/help/secrets-manager-cli/

**Addressing:** UUID-based for secrets (`bws secret get <UUID>`). `--uuids-as-keynames` maps UUIDs to env-var names. Name-based lookup in password manager CLI, UUID-based in Secrets Manager CLI (bws).

**Profile/alias:** Named profiles in `~/.config/bws/config` TOML. `--profile <name>` to select. State files store encrypted session tokens to reduce rate-limit round-trips.

**Output formats:** `-o / --output`: `json` (default), `yaml`, `table`, `tsv`, `none`, `env` (KEY=VALUE). Non-POSIX keys in `env` format are commented out.

**Exit codes:** `run` command propagates child process exit code. Bulk delete exits 1 if any operation fails (partial success reporting).

**Redaction:** Not explicitly documented.

**Auth bootstrap:** `BWS_ACCESS_TOKEN` env var or `--access-token` flag.

**Library vs CLI:** CLI-only; SDK library exists separately in Go/Python/JS/Java.

---

### sops (Mozilla / CNCF)
Sources: https://getsops.io/docs/ and https://github.com/getsops/sops

**Addressing:** File-based (yaml/json/env/ini/binary). Specific value extraction via tree path syntax: `sops decrypt --extract '["app2"]["key"]'`. No URL scheme.

**Output formats:** Preserves file format. Supports `exec-env` (inject all vars into child process env), `exec-file` (decrypt to tmpfile/FIFO). `--input-type` and `--output-type` override format detection.

**Exit codes:** Not documented.

**Redaction:** No explicit log-redaction posture documented.

**Library vs CLI:** Go `decrypt` package for library use.

**Auth bootstrap:** Ambient KMS credentials (env vars, IAM role, `~/.config/gcloud/`, `~/.aws/`, Azure CLI). PGP via gpg-agent.

**Shell-eval safety:** Not addressed. `exec-env` is safer than `eval $(sops decrypt ...)` because it uses process environment rather than shell eval.

---

### summon (CyberArk / Conjur)
Sources: https://cyberark.github.io/summon/ and https://github.com/cyberark/summon

**Addressing:** String identifiers in `secrets.yml` YAML config. Values are passed verbatim to the provider binary. Convention: `aws/iam/user/robot/access_key_id` style paths — provider-specific, no universal scheme. Tags: `!var` (provider-resolved), `!file` (write to tmpfile), `!var:file` (fetch+tmpfile), no tag (literal).

**Profile/alias:** No profile layer. `--provider` flag or `SUMMON_PROVIDER` env var selects provider. Default: `/usr/local/lib/summon/` directory.

**Plugin architecture:** External subprocess model. Provider contract: takes one argument (secret ID), returns value on stdout + exit 0 or error on stderr + non-zero. Stream mode: provider reads IDs from stdin (one per line), returns Base64-encoded values on stdout. Summon tries stream mode first, falls back to legacy (one-process-per-secret). Multi-provider within a single `secrets.yml` was requested (issue #25) but declined as "not planned."

**Output formats:** ENV injection into child process. `--push-to-file` with formats: yaml, json, dotenv, properties, bash, template.

**Exit codes:** Provider contract uses non-zero = error. CLI exit code propagation not explicitly documented.

**Redaction:** Secrets go into subprocess environment (visible in `/proc/<pid>/environ` to child). No stdout log redaction.

**TTY interaction:** Not documented.

**Library vs CLI:** CLI-only; providers are external binaries.

---

### direnv
Source: https://direnv.net/

**Addressing:** No secret addressing scheme. Loads `.envrc` shell script in project directory; secrets come from whatever shell commands the `.envrc` runs (e.g., `$(op read op://vault/item/field)`).

**Profile/alias:** Directory-scoping IS the profile mechanism. Each directory has its own `.envrc`.

**Security posture:** Requires explicit `direnv allow` before executing `.envrc`. Changes trigger re-approval requirement. Warning: `.envrc` is arbitrary shell; approved code can do anything.

**Library vs CLI:** Shell hook only. No library.

**Auth bootstrap:** Defers to whatever commands `.envrc` calls.

---

### envchain (sorah)
Source: https://github.com/sorah/envchain/blob/master/README.md

**Addressing:** Namespace + variable name 2-tuple. Stored as `envchain-NAMESPACE` in system keyring (macOS Keychain or D-Bus/gnome-keyring). Variables within a namespace are individual keyring entries under that service name. Usage: `envchain aws command` loads all variables in namespace `aws`.

**Keyring naming:** macOS: `envchain-NAMESPACE` as the keychain service name. Linux: same via libsecret.

**Profile/alias:** Namespace IS the profile. Multiple namespaces via comma: `envchain aws,hubot command`.

**Output formats:** Env injection into subprocess only.

**Exit codes:** Not documented.

**Library vs CLI:** C binary; no library.

**3-component addressing insight:** envchain maps `(namespace, varname)` to `(service="envchain-NAMESPACE", account=varname)` in the keyring — exactly a 2-tuple with namespace embedded in the service name. This is the standard workaround for the keyring 2-tuple limitation.

---

### gopass
Sources: https://github.com/gopasspw/gopass/blob/master/ARCHITECTURE.md and https://www.gopass.pw/

**Addressing:** Path-based like `pass`. Multi-store: mount points via `gopass mounts add test /tmp/store`. Secrets in mounted stores: prefix with mount name, e.g., `test/secret`. No formal URI scheme (no `gopass://`). `--store=mountname` flag for recipients/admin commands.

**Profile/alias:** Mount points act as named sub-stores. No "profile" concept explicitly.

**Output formats:** Plain text to stdout. `-c` flag for clipboard. `-o` for password-only. `safecontent: true` config obstructs sensitive fields by default; `--unsafe` flag to reveal.

**Exit codes:** Not documented.

**Plugin architecture:** Backend registry with `loader.go` + priority values for auto-detection. Crypto backends (GPG, age) and storage backends (filesystem, fossil) registered via blank imports. Compile-time, not dynamic-loading.

**Library vs CLI:** `pkg/gopass` is the public API for integrations (with mock implementations for testing). Versioning mismatch: semver applies to CLI only, not the module.

**Redaction:** `safecontent` config option and `unsafe-keys` list. Per-field redaction in terminal output.

---

### doppler CLI
Sources: https://docs.doppler.com/docs/cli and https://docs.doppler.com/docs/accessing-secrets

**Addressing:** `project/config/secret-name` hierarchy. `doppler setup` scopes a directory to a project+config. `--project` and `--config` flags override. `doppler secrets get SECRET_NAME`.

**Profile/alias:** `doppler setup` with `--scope` acts as a profile system (project-local config file). No explicit "profile name" concept.

**Output formats:** `--plain` for raw value, `--json` for structured, `--format dotenv/json/yaml/docker/env-no-quotes`. `doppler run` injects into subprocess env. `--mount` for file mounts.

**Exit codes:** Binary (0/non-zero). Non-existent command returns non-zero. Windows Ctrl+C non-zero. No documented granular codes.

**Redaction:** Cloud service; secrets never logged in the CLI. Doppler console shows secret history.

**Auth bootstrap:** `doppler login` for interactive. Service tokens (`DOPPLER_TOKEN`) for CI. Ephemeral tokens with `--max-age`.

**Library vs CLI:** SaaS vendor CLI; library SDKs are separate per-language packages.

---

### teller (SpectralOps / tellerops)
Sources: https://github.com/tellerops/teller and https://www.cncf.io/projects/teller/

**Addressing:** `.teller.yml` config maps provider instances to key maps. No URL scheme. Each map has an `id` and a `path`. Keys are optionally renamed via `keys: {SOURCE: TARGET}`. Reference syntax for operations: `provider_name/map_id` (e.g., `source/dev`).

**Provider architecture:** **Built-in only** in the current Rust rewrite. All providers (`hashicorp`, `aws_secretsmanager`, `aws_ssm`, `dotenv`, `consul`, `gcp_secretmanager`, etc.) are compiled-in. No external plugin / subprocess model.

**Output formats:** `teller sh` → `eval`-compatible shell output. `teller export yaml|json` → structured. `--env-file` → Docker env-file. `teller show` → table with partial redaction (first 2 chars shown).

**Shell-eval safety:** `teller sh` emits `export KEY=VALUE` lines for `eval`; no injection protection documented.

**Exit codes:** `teller scan --error-if-found` returns 1 when secrets found. No other documented codes.

**Redaction:** `teller redact` pipes process output through secret-scrubbing. `teller show` shows first 2 chars only.

**Config file location:** `.teller.yml` in working directory. Templating via `{{ get_env(name="VAR", default="val") }}`.

**Profile/alias:** None documented.

**Auth bootstrap:** Per-provider (ambient AWS creds, VAULT_TOKEN, etc.).

---

### infisical CLI (vendor)
Sources: https://infisical.com/docs/cli/commands/secrets and https://github.com/Infisical/infisical/issues/2967

**Addressing:** `--path /my-secret-path` hierarchy; `--env dev|staging|prod`; `--projectId`. Paths are slash-delimited folder hierarchy. Single secret: `infisical secrets get SECRET_NAME --path /path --env dev`.

**Profile/alias:** `.infisical.json` project-local config. Machine identity tokens via `INFISICAL_TOKEN`.

**Output formats:** Table (default), `--plain` (value only, one per line), `--silent` suppresses CLI info. `infisical export --format=dotenv-export` → `export KEY=VALUE`.

**Multiline handling:** Known pain point (issue #2967): `set foo=$(cat cert.pem)` panics. Proposed fix: `set foo < cert.pem` (stdin without `=`).

**Exit codes:** Not documented. Auth failures print "must be logged in" message; exit code unspecified.

**Redaction:** Not documented explicitly.

**Auth bootstrap:** `infisical login` interactive, or `INFISICAL_TOKEN` machine identity env var.

---

### akeyless CLI
Sources: https://docs.akeyless.io/docs/cli and https://docs.akeyless.io/docs/cli-reference-static-secrets

**Addressing:** Path-based: `/folder/subfolder/SecretName`. `default_location_prefix` config auto-prepends. `akeyless get-secret-value --name /non-production/MySecret`.

**Profile/alias:** Profiles in `~/.akeyless/profiles/*.toml`. `--profile <name>` to switch. Supports `gateway_url`, `cert_issuer_name`, etc. per profile.

**Output formats:** `--json` for JSON output. `--jq-expression` for inline filtering. Default is plain text.

**Version access:** `--version=-N` for Nth-most-recent (max 20).

**Exit codes:** Not documented.

**Auth bootstrap:** Interactive (`akeyless --init`) or `--profile` / `--token` / `--uid-token` flags.

---

### berglas (Google, GCS-backed)
Source: https://github.com/GoogleCloudPlatform/berglas/blob/main/README.md

**Addressing:** Two URL schemes:
- `berglas://bucket/secret-name[#version]` — Cloud Storage backend
- `sm://project-id/secret-name[#version]` — Secret Manager backend

Version pinning via `#` fragment: `sm://myproject/foo#3` or `berglas://bucket/foo#1563925940580201`.

**Exit codes:** Custom exit codes: 60 = API error (upstream communication failure); 61 = misuse error (unexpected input). `berglas exec` propagates child exit code. Standard Unix 0/1 otherwise.

**Library vs CLI:** Dual: `berglas exec` as CLI wrapper; `berglas/pkg/berglas` and `berglas/pkg/auto` as library APIs. `auto` package auto-resolves references at import time in App Engine, Cloud Run, Cloud Functions.

**Output formats:** Text logging (CLI), JSON structured logging (library for Cloud Logging).

**Auth bootstrap:** Ambient GCP credentials (Application Default Credentials, Workload Identity).

**Notable:** berglas is the clearest prior art for a URL-based multi-backend secret reference system (predating hasp's design). Two distinct schemes for two backends.

---

### credstash (Fugue, AWS DDB+KMS)
Source: https://github.com/fugue/credstash and https://deepwiki.com/fugue/credstash/3.1-command-line-interface

**Addressing:** `<name>[#version]` flat keys in DynamoDB table. Table is per-account/region. No path hierarchy. Versioned: always fetches highest version by default. `credstash get mykey` or `credstash get mykey@3`.

**Profile/alias:** None. AWS profile via standard AWS CLI config.

**Output formats:** Plain text to stdout. JSON with `--format json`. Table with `-t`.

**Exit codes:** Not documented.

**Auth bootstrap:** AWS credential chain + KMS key ID.

---

### ejson (Shopify)
Source: https://shopify.engineering/secrets-at-shopify-introducing-ejson

**Addressing:** JSON file with `_public_key` field; all string values are encrypted. Keys are plain JSON object keys (no path hierarchy). Decryption via `ejson decrypt secrets.ejson`.

**Profile/alias:** None. Per-file key management via `EJSON_KEYDIR` or `--keydir`.

**Output formats:** Decrypted JSON to stdout or in-place.

**Design rationale:** Asymmetric encryption (NaCl Box / Curve25519) so developers can add/rotate secrets without needing the private key. Private key lives on CI/deploy servers. Enables line-by-line git diff of encrypted secrets. Out-of-scope: per-secret rotation, env injection.

**Exit codes:** Not documented.

---

### git-secret / blackbox (StackExchange)
Source: https://github.com/StackExchange/blackbox/blob/master/README.md

**Addressing:** Filesystem paths (specific files in the repository). `blackbox_encrypt_file secrets.yml`. GPG recipients list controls who can decrypt.

**Profile/alias:** GPG keyring IS the profile. Admins listed by email.

**Output formats:** Decrypts in-place or to stdout. No structured output.

**Exit codes:** Not documented.

**Key insight:** Addresses the "commit secrets to git" use case; orthogonal to hasp's get/put model.

---

### direnv (revisited)
Already covered above. Key design note: `.envrc` can call any secrets tool, so direnv is really a composition layer, not a secrets store.

---

## Cross-Cutting Patterns

### Q1: URL / Addressing Scheme

**Who uses a URI/URL scheme:**
- 1Password: `op://vault/item[/section]/field` — formal 4-component URI with optional query params
- Berglas: `berglas://bucket/name[#version]` and `sm://project/name[#version]` — two schemes, one per backend
- Summon: string identifiers with no fixed format (provider-specific)
- SOPS: file paths only, tree path for extract

**Who uses positional path hierarchy (no scheme):**
- Vault: Unix-style path (`secret/myapp/db-pass`)
- pass / gopass: filesystem path (`Email/jason@example.com`)
- Chamber: `service/KEY` 2-level
- Infisical: `--path /folder/secret` with env+project as separate flags
- Akeyless: `/folder/SecretName`
- Credstash: flat key + optional `@version`

**Who uses project/config hierarchy:**
- Doppler: project / config / secret-name (3 levels, separate flags)
- Teller: provider-name / map-id / path (encoded in YAML)

**Hasp's proposed `aws-sm://name?region=us-west-2` form is unprecedented in this ecosystem.** No existing tool uses URI schemes to unify multiple backends. Berglas comes closest (two schemes, one per backend). The 1Password `op://` scheme is within a single vendor's namespace.

### Q2: Profile / Alias Config File

| Tool | Config file | Location | CLI-only or Library? |
|------|------------|----------|---------------------|
| chamber | No formal profiles | – | CLI-only (shell aliases recommended) |
| aws-vault | `~/.aws/config` | XDG-adjacent | CLI-only |
| doppler | `.doppler.yaml` (scoped by dir) | project-local | CLI-only |
| teller | `.teller.yml` | project-local (CWD) | CLI-only |
| akeyless | `~/.akeyless/profiles/*.toml` | $HOME | CLI-only (--profile flag) |
| bws (Bitwarden) | `~/.config/bws/config` | XDG | CLI-only |
| infisical | `.infisical.json` | project-local | CLI-only |
| pass/gopass | GPG trust / mount names | `~/.password-store` | CLI-only |
| vault | None (uses env vars) | – | CLI delegates to library |

**Consistent finding:** alias/profile expansion is ALWAYS CLI-only; the underlying library never sees alias names. Libraries operate on fully-resolved identifiers. This strongly supports hasp's planned `@profile/key` → URL expansion happening in the CLI binary only, never in the library.

### Q3: TTY Interaction

- **pass:** gpg-agent handles passphrase (native OS dialog or terminal)
- **1Password op run:** PTY pair masking — conceals secret values printed to stdout/stderr
- **vault login:** reads token from terminal directly
- **getpass() / /dev/tty:** Standard Unix pattern — opens `/dev/tty` directly (bypasses redirected stdin), disables echo, restores terminal state. Falls back to stderr+stdin with warning if `/dev/tty` unavailable.
- **No tool's library surface handles prompting.** Prompting is universally CLI-only.
- **hasp implication:** If hasp ever needs to prompt (e.g., for keyring unlock passphrase), it must open `/dev/tty` directly, not read from stdin, and must never do it in the library.

### Q4: Output Formats

Near-universal support for:
- Raw value to stdout (the primary pipe-safe format)
- JSON (structured, for scripting with jq)
- dotenv (`KEY=VALUE` lines)
- `export KEY=VALUE` (for shell sourcing)
- Table (human-readable)

**Shell-eval injection risk:** `eval "$(teller sh)"` and `eval "$(chamber export --format=dotenv)"` are unsafe if a secret value contains shell metacharacters (`;`, `$()`, backticks). Only 1Password's `op run` mitigates this by using subprocess env injection instead of eval. **No tool documents injection safety in their shell-eval output modes.**

**hasp implication:** The CLI's `get` command should emit raw bytes to stdout (no trailing newline by default, or explicit `--newline` flag). A `run` subcommand (like `summon`) is safer than shell-eval for env injection.

### Q5: Exit Codes

**The ecosystem is strikingly bad at granular exit codes:**

| Tool | 0 | 1 | 2 | Other |
|------|---|---|---|-------|
| vault | success | local/terminal error | remote/server error | – |
| berglas | success | generic error | – | 60=API, 61=misuse |
| bws | success | partial failure | – | child propagated |
| op | success | server error | – | – |
| summon provider | success (by contract) | error | – | – |
| Most others | success | error | – | – |

**No tool uses distinct exit codes for not-found vs. permission-denied vs. transport-failure vs. auth-failure.** Vault's 1/2 split (local vs remote) is the best seen. Berglas's 60/61 is the most inventive but non-standard. **hasp has a greenfield opportunity to define a principled exit-code convention.**

Proposed convention based on gaps observed:
- 0: success
- 1: usage/local error (bad flags, wrong number of args)
- 2: not found (the secret does not exist at this URL)
- 3: permission denied (secret exists, caller lacks access)
- 4: transport/network failure (could not reach backend)
- 5: auth failure (credentials to reach the backend are invalid/missing)

### Q6: Redaction Posture

**1Password op run:** PTY pair masking — active concealment in stdout/stderr. Opt-out via `--no-masking`. Clearest documented redaction posture.

**Teller:** `teller redact` pipe-through filter; `teller show` partial visibility (first 2 chars).

**AWS CLI / GCloud CLI (LeakyCLI, 2024):** CVE-2023-36052 (Azure; CVSS 8.6) and analogous AWS/GCloud behavior — certain `aws lambda get-function-configuration` and `gcloud functions deploy --set-env-vars` commands echo environment variables (including secrets) to stdout in CI/CD logs. AWS and Google consider it "expected behavior." Microsoft patched Azure CLI 2.54.

**No tool documents that verbose/debug/trace mode suppresses secret values.** This is a gap — hasp should explicitly document that `RUST_LOG=trace` never emits secret bytes.

**Subprocess env visibility:** Tools that inject secrets via subprocess env (summon, doppler run, op run) leave secrets readable in `/proc/<pid>/environ` to the child process owner. This is unavoidable with the env-injection model.

### Q7: `file://` Style Sources, Newline Trimming

**The trailing newline problem is endemic and underdocumented:**

- **Vault `-field` flag:** Explicitly NO trailing newline — "ideal for piping." But raw `vault kv get` output has newlines. Writing a secret from a file with `value=@/path/to/file` preserves the file's trailing newline in the stored value (issue #3590, 2017, unresolved).
- **Kubernetes secrets as env vars:** Issue #23404 (open, ~2015–2026+). `echo -n` workaround documented everywhere. `kubectl create secret` from `echo myval` encodes the trailing newline into base64, causing decoded value to have `\n` appended.
- **Docker / Podman secrets (`/run/secrets/name`):** Stored on tmpfs. Trailing newline from `echo secret > /run/secrets/name` is preserved in the mount. `echo -n` or `printf` is the documented mitigation.
- **systemd credentials (`$CREDENTIALS_DIRECTORY/name`):** Binary format supported. `systemd-creds cat` has an "auto" mode for trailing newline: adds `\n` only when outputting to a TTY.
- **gopass:** "leaves your secret as is whenever possible."
- **pass clipboard:** `-c` copies first line only (no newline in clipboard).

**No tool offers a `--trim` flag. No tool documents a universal "trim trailing newline" behavior by default on read.**

**hasp implication for `file://` backend:** Reading a file secret should trim exactly one trailing `\n` by default (matching the `vault -field` behavior and `echo -n` convention), with `--raw` to suppress trimming. Storing a secret to a file should NOT add a trailing newline. This should be explicitly documented.

### D3: Keyring URL Grammar — 3-Component Addressing

**Question:** Does any tool need more than the keyring crate's `(service, user)` 2-tuple?

**Findings:**

- **1Password `op://vault/item[/section]/field`:** 3–4 components (vault, item, optional section, field). Explicitly models hierarchical named fields within an item. This IS more than a 2-tuple.
- **envchain:** Encodes namespace into the service name as `envchain-NAMESPACE`; variable name as `account`. Effective 2-tuple but with embedding trick.
- **go-keyring (zalando):** Pure 2-tuple `(service, user)` on all platforms. Windows combines them as `service:user`.
- **Bitwarden bws:** UUID-based; no keyring notion.

**Conclusion:** The keyring crate's `(service, account)` 2-tuple is sufficient IF the URL grammar maps `keyring://service/account` as 2 components. But `keyring://service/account/key` as a 3-tuple requires either embedding `account/key` into the service or user string, or maintaining a local index file, or constraining keyring URLs to 2 components. The 1Password model (where `item` is a named container with multiple named fields) is the strongest prior art for why 3-component addressing is useful; the keyring backend cannot replicate this without a compound key strategy.

**Recommendation signal:** `keyring://service/account` (2-tuple only) with documentation that the keyring backend cannot address sub-fields natively. Use `aws-sm://` or `vault://` for multi-field items.

### D5: ProfileResolver — CLI vs Library Location

**Universal finding across all 19 tools: alias/profile expansion lives entirely in the CLI binary.** Libraries consume fully-qualified identifiers (paths, UUIDs, service+key pairs). Zero tools expose an alias-resolution API at the library layer. This is architecturally consistent and deliberate.

**chamber:** `service/key` parsing in CLI; SSM path construction in library.  
**aws-vault:** Profile parsing in CLI; credential chain in library.  
**doppler:** `--project --config` resolution in CLI; API calls use project/config directly.  
**teller:** `.teller.yml` provider/map resolution in CLI only.

**hasp implication:** `@profile/key` → URL expansion belongs in `src/bin/hasp.rs` only, never in `hasp::` library. The library receives a URL and resolves it.

### D8: Auth Bootstrap Chain

Universal pattern: **ambient credentials first, explicit override second.**

1. Environment variables (AWS_ACCESS_KEY_ID, VAULT_TOKEN, GOOGLE_APPLICATION_CREDENTIALS)
2. Config files (~/.aws/credentials, ~/.vault-token, ~/.config/gcloud/)
3. Instance metadata / IAM role / Workload Identity
4. OS keystore (aws-vault, envchain)
5. Explicit flag (--token, --access-key-id)

Libraries assume ambient. CLIs may accept explicit flags. No tool bootstraps credentials interactively at the library layer.

### D9: Plugin / Extension Model

| Tool | Plugin model |
|------|-------------|
| summon | External subprocess (any language, /usr/local/lib/summon/) |
| teller (current Rust rewrite) | Built-in only; compiled-in providers |
| gopass | Backend registry via blank imports; compile-time only |
| vault | Auth backend plugins (Go plugin framework with RPC) |
| All others | No plugin model; monolithic binary |

**summon's external subprocess model is unique:** any executable at the right path becomes a provider. Zero compilation required. The stream mode protocol (stdin/stdout, Base64-encoded) is a clean IPC interface. Multi-provider within one `secrets.yml` was rejected by maintainers.

**hasp implication:** Cargo features (compile-time) for backends aligns with gopass/teller. The summon subprocess model has elegance but introduces a security surface (untrusted executables in a PATH directory). Cargo features are safer and more idiomatic Rust.

### D10: Known Incidents / CVEs

| Incident | Tool | Year | Mechanism |
|----------|------|------|-----------|
| LeakyCLI / CVE-2023-36052 | Azure CLI (patched 2.54), AWS CLI, GCloud CLI | 2023–2024 | Commands output cloud function environment variables (including secrets) to stdout in CI logs |
| `.vault-token` disk exposure | HashiCorp Vault | Ongoing | Plaintext token cached in `~/.vault-token`; world-readable if file perms wrong |
| `.aws/cli/cache/` disk exposure | AWS CLI | Ongoing | Short-lived STS tokens cached plaintext in `~/.aws/cli/cache/` |
| Kubernetes env var newline | Kubernetes | 2015–present | Base64-encoded secrets with trailing newline inject extra `\n` into env vars |
| 1Password op run PTY interference | 1Password CLI | 2023–present | PTY masking breaks some terminal apps and VS Code dev containers |
| gopass URI breaking change 1.7.0 | gopass | ~2019 | Storage backend URI scheme change broke all integrations |
| argv leakage via /proc/cmdline | Universal | Ongoing | Any secret passed as command-line argument is globally readable in /proc |

**No CVE found for:** teller, chamber, summon, credstash, ejson, berglas, envchain, direnv, pass.

---

## Synthesis: What the Ecosystem Agrees On

1. **Env injection via subprocess (not eval) is safer.** `op run`, `summon`, `doppler run` all exec a child process. `teller sh` + `eval` is the risky outlier.

2. **Trailing newline behavior is inconsistent and causes real user pain.** Only Vault's `-field` explicitly strips it. The rest preserve or don't document.

3. **Profile/alias expansion is universally CLI-only.** Libraries operate on resolved identifiers.

4. **Exit codes are almost universally binary (0/non-zero).** The ecosystem leaves granular codes as a greenfield opportunity.

5. **Shell-eval injection from secrets values is a known risk, universally underdocumented.**

6. **Auth bootstrap is ambient-first everywhere.** Libraries never prompt or bootstrap; CLIs may accept explicit credentials as flags.

7. **No URL scheme unifies multiple backends in a single tool.** hasp's proposed scheme is novel; berglas's dual-scheme is the closest precedent.

8. **3-component secret addressing (beyond service/account 2-tuple) exists in practice** (1Password, Vault kv with `path + field`, berglas `bucket/name#version`). The keyring crate's 2-tuple is insufficient for this use case without embedding tricks.

9. **PTY masking for secret redaction in subprocess output** is 1Password's innovation; no other tool replicates it. Teller's pipe-through redact is the closest analog.

10. **Plugin models tend toward compile-time (Cargo features / blank imports) or external subprocess.** Dynamic loading (dlopen/shared objects) is absent from this ecosystem.

---

*All URLs fetched during this research are cited inline above or in the tool sections. See also `notes/RESEARCH-d1-d2-d3-d7.md` for complementary crate-level research.*
