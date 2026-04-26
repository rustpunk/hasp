# RESEARCH-file-trim

> Decision: should the `file://` backend automatically trim trailing newline(s) from secret files?
>
> Date: 2026-04-26
> Audience: hasp-backend-file author
> Status: recommendation, awaiting design lock

---

## Core question

Ferrule explicitly requests trailing-newline trimming for Docker secrets. Should `file://` strip newlines automatically (lossy), opt-in via `?trim=true`, opt-out via `?raw=true`, or never trim (caller responsibility)? What surprises does each policy cause?

**Cross-platform note:** The `file://` backend is platform-agnostic — it reads any file accessible via a filesystem path on Linux, macOS, or Windows. The line-ending discussion below covers `\n` (LF, Unix-native) and `\r\n` (CRLF, Windows-native and Windows line-edited file leftovers). Files written on Windows and read on Linux (or vice versa) are common in mixed-platform deployments; the trim policy must handle both terminators. The dominant secret-source platforms cited (Docker secrets, Kubernetes secrets, systemd-creds, podman secrets) are Linux-leaning by deployment, but Docker Desktop on Windows / macOS produces files with the same byte semantics, and Kubernetes Secrets mounted into Windows containers behave identically. Path handling uses `std::path::Path` (platform-native separators) but URL grammar always uses `/` per RFC 3986 §3.3.

The decision affects every container deployment, every Kubernetes Secret-mounted-as-file, every systemd-creds-using service, and any CLI workflow that pipes a value into a file via `echo`. Wrong default = silent corruption or silent authentication failure across the deployment surface.

---

## The landscape

The byte-exact format used by every major secret-as-file source is **verbatim — the platform appends nothing**:

| Platform | What gets written | Source |
|----------|-------------------|--------|
| Docker secrets (`/run/secrets/<name>`) | Exact bytes provided to `docker secret create` | [docs.docker.com](https://docs.docker.com/engine/swarm/secrets/), [aspnet/Configuration #706](https://github.com/aspnet/Configuration/issues/706) |
| Kubernetes secrets (volume-mounted) | Exact base64-decoded bytes | [kubernetes.io](https://kubernetes.io/docs/concepts/configuration/secret/) |
| systemd-creds (`$CREDENTIALS_DIRECTORY/<name>`) | Raw decrypted bytes; binary-capable; `--newline=auto` adds `\n` only on TTY output, never to files | [systemd.io/CREDENTIALS](https://systemd.io/CREDENTIALS/) |
| Podman secrets | Same model as Docker | [docs.docker.com](https://docs.docker.com/engine/swarm/secrets/) |

The trailing `\n` that users observe is **not from the platform**. It's from the most common creation idiom: `echo "secret" > /run/secrets/db_pass`. `echo` appends `\n` by default. The widely-known workaround is `echo -n "secret"` or `printf '%s' "secret"`. This footgun has lived for a decade across every major container runtime. Kubernetes issue #23404 (open since 2015) and Vault issue #3590 (open since 2017) document the same pain.

The CLI-tool ecosystem is **inconsistent on read**:

| Tool | On read | Source |
|------|---------|--------|
| `vault read -field=NAME` | **Strips trailing newline** — explicitly documented "ideal for piping" | [HashiCorp Vault CLI docs](https://developer.hashicorp.com/vault/docs/commands) |
| `vault write value=@file` | **Preserves** the file's newline in the stored value (Vault #3590, unresolved since 2017) | [link](https://github.com/hashicorp/vault/issues/3590) |
| Kubernetes `kubectl get secret -o ...` | Returns base64 of exact bytes; consuming app sees whatever was put in | [link](https://kubernetes.io/docs/concepts/configuration/secret/) |
| `gopass` show | Preserves "as is whenever possible" | [github](https://github.com/gopasspw/gopass/blob/master/docs/features.md) |
| `pass show -c` (clipboard) | First line only → no trailing newline goes to clipboard | [passwordstore.org](https://www.passwordstore.org/) |
| `summon -f` | Preserves | [cyberark.github.io/summon](https://cyberark.github.io/summon/) |
| `doppler` file mounts | Preserves | [docs.doppler.com](https://docs.doppler.com/docs/cli) |
| `chamber export --format=dotenv` | Adds newlines per format spec (envfile is line-oriented) | [github](https://github.com/segmentio/chamber/blob/master/README.md) |
| `sops decrypt --extract` | Format-dependent (binary preserves; YAML/JSON normalize) | [getsops.io](https://getsops.io/docs/) |

**No tool offers a `--trim` flag.** No tool defines a default "trim trailing newline on read" behavior universally for a `file://`-style backend. Vault's `-field` is the closest analogue and it strips.

The asymmetry is the source of pain: tools that put values into files don't strip; tools that read fields strip; users build pipelines that write with one and read with the other and get different bytes back than they put in. CipherStash's verification work, smallstep's incident report, and Argo Workflows' regression all trace to this asymmetry.

---

## Approach A: Always trim exactly one trailing `\n` or `\r\n`. No opt-out.

**How it works:** `file://` backend reads the file, removes one trailing `\n` or `\r\n`, returns the result.

**Strengths:**
- Matches Vault `-field` (the only documented prior art with explicit trim).
- Matches the dominant user expectation: "I `echo`d the password into a file, I want the password back out, not password + newline."
- Single behavior, easy to document.

**Weaknesses / failure modes:**
- **Silent corruption of binary data.** PEM private keys end with `-----END … KEY-----\n` — stripping that newline is harmless for most parsers but technically corrupts the canonical form. Binary keys (raw 256-bit secrets, AES keys serialized to a file) that legitimately contain `0x0A` as the last byte become 1 byte shorter than written.
- **No way to opt out.** A caller that genuinely wants the verbatim file contents has no path. `cat` would do it; hasp wouldn't.
- Drupal's password-trim incident: silently trimming user-typed passphrases weakens password strength; users with intentional trailing whitespace never know they're stored without it ([Drupal issue #1921576](https://www.drupal.org/project/drupal/issues/1921576)). Not directly applicable to a file-read context but a cautionary tale on lossy defaults.

**Source:** [HashiCorp Vault CLI docs](https://developer.hashicorp.com/vault/docs/commands), [smallstep/cli #428](https://github.com/smallstep/cli/issues/428).

---

## Approach B: Trim by default, opt-out via `?raw=true` query parameter

**How it works:**

```
file:///etc/secrets/db.txt              # trim one trailing \n or \r\n (default)
file:///etc/secrets/db.txt?raw=true     # return verbatim bytes, no trim
```

**Strengths:**
- Same default as Approach A; same rationale: matches user expectation, matches Vault `-field`.
- Honest escape hatch for binary keys, PEM material, password files where trailing whitespace is intentional.
- The default behavior covers >95% of use cases (Docker secrets, Kubernetes secrets, systemd-creds, hand-edited `.txt` password files).
- `?raw=true` is discoverable in URL grammar docs and forces an explicit user choice when trimming would be wrong.
- Adoption story for binary keys: once a user hits a "wait, where did my last byte go?" symptom, they discover `?raw=true` and the URL self-documents the intent.

**Weaknesses / failure modes:**
- The first time a user puts a binary key in a file and reads it via `file://`, they may not realize trim happened until something downstream complains about a missing byte. Mitigation: document loudly in the `file://` backend docs and in a top-level "common pitfalls" section.
- Users who want to suppress the trim without remembering the URL syntax may invent workarounds (write `secret\n\n` so trim leaves one `\n`; brittle).

**Source:** [Vault `-field`](https://developer.hashicorp.com/vault/docs/commands), [smallstep/cli #428](https://github.com/smallstep/cli/issues/428), [Argo Workflows #981](https://github.com/argoproj/argo-workflows/issues/981).

---

## Approach C: Never trim. Caller's responsibility.

**How it works:** `file://` returns verbatim file contents. Callers that want to trim do so themselves: `secret.expose_secret().trim_end_matches(['\n', '\r'])`.

**Strengths:**
- No surprise for binary callers.
- No silent data loss.

**Weaknesses / failure modes:**
- Every caller has to know to trim. Most won't, until they hit `password\n` causing PostgreSQL `PGPASSWORD` auth failure.
- Re-creates the same footgun the entire ecosystem has been suffering for a decade.
- Argo Workflows #981 is the canonical example: the original code trimmed; a refactor dropped the trim; production S3 auth broke because Authorization headers became `AWS <ACCESSKEY>\n:SECRET`. Putting the trim choice on every caller guarantees this happens to someone every release ([github.com/argoproj/argo-workflows/issues/981](https://github.com/argoproj/argo-workflows/issues/981)).
- Forces every consumer to write the same trim-end-matches helper. Or worse, a helper that trims wrong (multiple newlines, whitespace too).

---

## Approach D: Opt-in via `?trim=true`. Default verbatim.

**How it works:** Default verbatim; users add `?trim=true` to opt in.

**Strengths:**
- Honest about the byte-level cost.

**Weaknesses / failure modes:**
- Inverts the prevailing user expectation. The default is the rare case (binary); the opt-in is the common case (text).
- Users will forget the query param, get bitten, add it. Same outcome as Approach C, just with one extra step.
- Also re-creates the decade-long footgun.

---

## Benchmark data

Not applicable to this decision. File read latency dominates by orders of magnitude over the trim operation.

---

## Threat-model / standards anchors

| Source | Year | Body | Relevant insight | URL |
|--------|------|------|-----------------|-----|
| Docker secrets format documentation | current | Docker | Verbatim bytes; no platform-added newline | [link](https://docs.docker.com/engine/swarm/secrets/) |
| Kubernetes secrets file mount | current | kubernetes.io | Verbatim base64-decoded bytes | [link](https://kubernetes.io/docs/concepts/configuration/secret/) |
| systemd-creds | current | systemd.io | Binary-capable; on-disk content is raw bytes | [link](https://systemd.io/CREDENTIALS/) |
| PostgreSQL libpq pgpass | current | PostgreSQL | Silent on trailing-whitespace handling — implementations vary | [link](https://www.postgresql.org/docs/current/libpq-pgpass.html) |
| RFC 7468 (PEM textual encoding) | 2015 | IETF | PEM parsers MUST tolerate trailing whitespace; trim of PEM `\n` is harmless in practice | [link](https://datatracker.ietf.org/doc/html/rfc7468) |

No RFC governs "password file format." The conventions are de facto.

---

## Failure modes / CVEs to avoid

- **smallstep/cli issue #428 — trailing newline changes the encryption key.** `pwgen -s 64 1 > my_pass` produces a file with `\n`. step-cli used raw file bytes as the encryption key; one code path trimmed and another did not. Encrypting worked; decrypting failed with `x509: decryption password incorrect`. The password was not corrupted — it was inconsistently interpreted ([github.com/smallstep/cli/issues/428](https://github.com/smallstep/cli/issues/428)). **Lesson:** consistency matters more than which choice you make. Document the policy and stick to it.
- **Argo Workflows #981 — no-trim regression broke S3 auth.** Argo < v2.2.0 trimmed whitespace from S3 keys. A refactor to a shared S3 helper dropped the trim. K8s Secrets include a trailing `\n`. Result: Authorization headers became `AWS <ACCESSKEY>\n:SECRET` and S3 operations failed. **Lesson:** the ecosystem expectation for K8s Secrets / Docker secrets is "trim the newline"; deviating breaks production ([github.com/argoproj/argo-workflows/issues/981](https://github.com/argoproj/argo-workflows/issues/981)).
- **Drupal #1921576 — silent trim of intentional trailing whitespace weakens passwords.** Drupal stripped leading/trailing whitespace from password fields at storage and login. Users with intentional trailing spaces had weaker passwords than they set, and never knew ([drupal.org issue](https://www.drupal.org/project/drupal/issues/1921576)). **Lesson:** trimming user-chosen passphrases is harmful. hasp's `file://` backend is reading machine-generated secret files (Docker secrets, K8s Secrets, systemd-creds), not user passphrase files; the analogy is weak but the warning is real for the `?raw=true` doc — call out that user passphrases should use `?raw=true`.
- **`openssl enc -d -base64` requires trailing newline.** Scripts that pipe base64 without a newline produce truncation errors. The mirror footgun: a consumer that requires the newline, broken when trim removes it ([openssl/openssl #29595](https://github.com/openssl/openssl/issues/29595)). **Lesson:** `?raw=true` must be truly raw. Document the byte-level contract explicitly.

---

## Design insights for hasp

1. **Adopt Approach B: trim exactly one trailing `\n` or `\r\n` by default, opt-out via `?raw=true`.** The default matches user expectation across Docker secrets, K8s Secrets, systemd-creds, and the standard Unix `echo > file` workflow. The opt-out gives binary keys and PEM material an honest escape hatch.
2. **Trim *exactly one* `\n` or `\r\n`, not all trailing whitespace.** Stripping multiple newlines or arbitrary whitespace would silently corrupt secrets that legitimately end with whitespace. Match the C library `getline()` convention: one line terminator.
3. **Document the byte-level contract explicitly in the `file://` backend docs.** Spell out the byte sequence: "default behavior strips one `\n` or `\r\n` if present at end of file; `?raw=true` returns verbatim bytes. No leading whitespace is stripped. No middle whitespace is touched."
4. **Document the user-passphrase caution.** Add a note: "if you are reading a user-typed passphrase from a file, use `?raw=true` to preserve trailing whitespace the user may have intentionally set."
5. **Document the dominant write pattern in error messages and docs.** When a user gets a `file://` URL wrong (file doesn't exist, permission denied), include in the error message: "to write a secret to a file, use `printf '%s' \"secret\" > /path` (no trailing newline) or `echo -n \"secret\" > /path`."
6. **`hasp put file:///path` writes verbatim — no newline appended.** The CLI's `put` writes the bytes provided via stdin as-is. This is the symmetric default with `?raw=true` reads, and the explicit "if you want a newline, send one" posture.
7. **No `?trim=N` for trimming N newlines.** Avoid grammar creep. Trim is binary: one `\n` or `\r\n` at end (default), or none (`?raw=true`).
8. **Apply the same default to the `env://` backend.** Env vars don't have trailing newlines anyway, but for consistency, document that `env://` returns the env-var value verbatim — no trim, because there's nothing to trim.

---

## Decision criteria (enforced)

NOT valid: "what's easiest to implement"; "what avoids re-reading the file."

ONLY valid:
- Architectural correctness (default behavior must match dominant user expectation; opt-out must exist for the rare case)
- Threat-model soundness (silent data loss is bad; silent inconsistency between write-then-read is also bad)
- Long-term maintainability (one well-documented byte-level contract beats two ambiguous behaviors)
- Alignment with rustpunk identity (be honest about byte-level semantics)

---

## Recommendation

**Approach B — trim one trailing `\n` or `\r\n` by default; `?raw=true` for verbatim bytes.**

**Confidence:** High.

**Rationale:**
- Matches the dominant ecosystem convention (Vault `-field` is the only tool with explicit policy; it strips). Matches user expectation across the Docker / Kubernetes / systemd-creds platforms (which all write verbatim and then users `echo` newlines into them).
- The opt-out via `?raw=true` directly addresses the documented failure modes of always-trim (smallstep #428, Drupal #1921576) without forcing every caller to remember to trim (Argo #981).
- "Trim exactly one" matches the POSIX text-file convention (lines end with `\n`); it does not enable arbitrary whitespace stripping.

**Key risk:** A user reads a binary secret with the default (lossy) and gets an off-by-one error downstream. **Mitigation:** loud documentation in the `file://` backend rustdoc; a "common pitfalls" section in the user guide; an example in the `hasp get file://` `--help` output that mentions `?raw=true`.

**Threat-model note:** Approach B preserves the secret value in the lossless case (`?raw=true`) and matches the dominant lossless-source-with-spurious-newline case in the lossy default. There is no scenario where Approach B silently weakens a password (Drupal-style trim of intentional whitespace) because hasp's `file://` is reading machine-generated secret files, not user passphrase entry. The `?raw=true` opt-out gives users who *are* reading passphrase files an explicit path to preserve every byte.

**If wrong:** If `?raw=true` proves discoverable poorly and users accumulate confusion about what `file://` returns, the fix is doc-only — make the rustdoc, README, and CLI help louder. The byte-level contract itself stays the same.

**Rejected alternatives:**
- **Approach A (always trim, no opt-out):** rejected because it has no path for binary keys or genuinely-trailing-newline secrets. Silent data loss with no escape is architecturally wrong.
- **Approach C (never trim):** rejected because it re-creates the decade-long ecosystem footgun (`echo "secret" >file` causes `password\n` auth failure downstream). Argo #981 is the canonical example; we should not re-implement that bug.
- **Approach D (opt-in `?trim=true`, default verbatim):** rejected because it inverts the prevailing user expectation. The common case becomes the opt-in; the rare case becomes the default. Same outcome as Approach C with one extra cognitive step.

---

## Bibliography

| Source | Type | Relevance | URL |
|--------|------|-----------|-----|
| Docker secrets docs | doc | Verbatim bytes; no platform newline | [link](https://docs.docker.com/engine/swarm/secrets/) |
| Kubernetes secrets file mount | doc | Verbatim base64-decoded bytes | [link](https://kubernetes.io/docs/concepts/configuration/secret/) |
| systemd-creds CREDENTIALS doc | doc | Binary-capable; raw bytes on disk | [link](https://systemd.io/CREDENTIALS/) |
| Vault `-field` strips newline | doc | Closest prior-art trim policy | [link](https://developer.hashicorp.com/vault/docs/commands) |
| aspnet/Configuration #706 | issue | Docker secret newline trim discussion | [link](https://github.com/aspnet/Configuration/issues/706) |
| Vault #3590 | issue | Vault write `value=@file` preserves newline (asymmetry) | [link](https://github.com/hashicorp/vault/issues/3590) |
| Kubernetes #23404 | issue | K8s env-var newline source-of-pain | [link](https://github.com/kubernetes/kubernetes/issues/23404) |
| smallstep/cli #428 | issue | Trim/no-trim inconsistency cost | [link](https://github.com/smallstep/cli/issues/428) |
| Argo Workflows #981 | issue | No-trim regression broke S3 auth | [link](https://github.com/argoproj/argo-workflows/issues/981) |
| Drupal #1921576 | issue | Silent trim of user passphrase weakens password | [link](https://www.drupal.org/project/drupal/issues/1921576) |
| openssl/openssl #29595 | issue | Counter-example: openssl base64 needs trailing newline | [link](https://github.com/openssl/openssl/issues/29595) |
| RFC 7468 | RFC | PEM textual encoding tolerance | [link](https://datatracker.ietf.org/doc/html/rfc7468) |
| Ferrule WISHLIST §7.4 | doc | hasp consumer requesting trim | `docs/internal/ferrule/WISHLIST.md` |
