# Project Context

Paste this block into every research sub-agent prompt, above the research
brief. These constraints are non-negotiable.

---

## Project Context — hasp

**What this project is:**
`hasp` is a **unified secrets CLI** for the rustpunk portfolio. One static
binary, many backends, one URL-style addressing scheme. Verbs are `get`,
`put`, `list`, `delete`, `exists`. Backends include OS keyring (Secret
Service / macOS Keychain / Windows Credential Manager), AWS Secrets
Manager, AWS SSM Parameter Store, HashiCorp Vault, GCP Secret Manager,
Azure Key Vault, 1Password CLI, Bitwarden CLI, dotenv files, and plain
files on disk. URL form parallels its sibling `ferrule`:

```
keyring://service/account/key
aws-sm://name?region=us-west-2&version=AWSCURRENT
aws-ssm:///path/to/parameter?with-decryption=true
vault://kv/data/myapp/db-password
gcp-sm://projects/<project>/secrets/<name>/versions/latest
azure-kv://<vault>.vault.azure.net/secrets/<name>
op://Vault/Item/field
bw://item-uuid/login.password
file:///etc/secrets/db.txt
env://DATABASE_PASSWORD
```

**What this project is NOT:**
- Not a secret rotation tool — operational concern, separate domain
- Not a key generator — separate `keygen`-style tool
- Not an auth bootstrapper — `hasp` assumes ambient credentials (env,
  IAM role, `~/.vault-token`) or delegates to a backend plugin
- Not a bulk file encryption tool — see `age` / `sops` / `cocoon`
- Not a TLS / certificate lifecycle tool — separate problem space

**Closest prior art (PRIMARY):**
- chamber (Segment) — AWS SSM Parameter Store CLI
- aws-vault — credential-helper / session-cache for AWS
- vault CLI (HashiCorp) — itself, the canonical Vault frontend
- pass — GPG-based unix password manager
- 1Password CLI (`op`) — vendor CLI for 1Password
- Bitwarden CLI (`bw`) — vendor CLI for Bitwarden
- sops (Mozilla / CNCF) — file encryption with cloud KMS keys
- summon (CyberArk / Conjur) — secret-injection wrapper
- direnv — env-var scoping per directory
- envchain — keychain-backed env vars (macOS / Linux)
- gopass — pass alternative with team features
- doppler CLI, teller (SpectralOps), infisical CLI, akeyless CLI,
  berglas (Google) — vendor / open-source alternatives

**Closest prior art (SUPPLEMENTARY — protocol level):**
- AWS Secrets Manager API and AWS SSM Parameter Store API
- HashiCorp Vault HTTP API (KV v1, KV v2, AppRole, kubernetes auth,
  approle, token renewal)
- GCP Secret Manager gRPC API
- Azure Key Vault REST API
- KMIP, KMS protocols, PKCS#11 (peripheral but informs HSM-backed paths)

**Greenfield status:**
This project has **zero users and zero deployments**. There are no
consumers, no backwards-compatibility obligations, and no migration
concerns. Breaking changes are not just acceptable — they are
**encouraged** when they produce a more correct architecture or a more
defensible threat model.

**Decision criteria:**
When evaluating approaches, the following are **NOT valid factors**:

- Implementation complexity or estimated effort
- Number of files touched or scope of change
- Breaking change risk (there is nothing to break)
- "Pragmatic" or "incremental" alternatives that compromise architecture
  or weaken security
- Difficulty of the refactor

The **ONLY valid criteria** are:

- **Architectural correctness** — does the design serve the unified-CLI
  abstraction, or leak backend specifics into the user surface?
- **Threat-model soundness** — does the design respect secret lifetime,
  redaction, zeroize-on-drop, no-debug-leak, no-log-leak, no-error-leak
  invariants?
- **Long-term maintainability** of the correct design
- **Alignment with rustpunk identity** — pure-Rust default backends, zero
  runtime deps for the default feature set, rustls (no native-tls /
  OpenSSL host dependency), feature-gated optional backends

**Security invariants (non-negotiable):**

1. Every secret value lives in `secrecy::SecretString` (or
   `SecretBox<[u8]>`) from the moment it leaves the backend until it is
   intentionally exposed. Bare `String` for a secret is a defect.
2. `Drop` zeroizes (via `zeroize`). Stack-allocated buffers used in
   transit are explicitly zeroized.
3. `Debug` never prints a secret value — `SecretString`'s default
   redaction is the floor, not the ceiling.
4. URLs in logs / errors / diagnostics have their userinfo redacted.
   Backend addresses (vault path, AWS SM ARN) may be logged; embedded
   tokens may not.
5. `--insecure` flags require explicit opt-in and warn loudly on stderr.
   Default TLS is rustls + WebPKI roots — no fallback to native-tls.
6. Process-boundary leaks (env vars in `ps`, command-line in `/proc`)
   are documented. Prefer stdin / file descriptors for long-form secret
   ingest; never pass secrets on argv.

**No shortcuts:**
If your research surfaces a correct-but-harder option alongside an
expedient shortcut, report both but be explicit that the correct option
is the one this project will adopt. Do not recommend shortcuts, shims,
compatibility layers, or deferred cleanups. Security-sensitive code is
particularly hostile to "fix it later" — the right time to get the
threat model right is now.
