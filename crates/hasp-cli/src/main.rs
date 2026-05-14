use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueEnum, ValueHint};
use clap_complete::engine::ArgValueCompleter;
use secrecy::ExposeSecret;
use std::io::{self, IsTerminal, Read, Write};
use std::sync::Arc;

mod audit_config;
mod completions;
mod config_init;
mod list_format;
mod profile_allow;
mod profiles;
mod run;
use list_format::{format_list, Format};

/// Unified secrets CLI.
///
/// `hasp` dispatches `get` / `put` / `list` / `delete` / `exists` to
/// multiple backends addressed by URL or alias.
#[derive(Parser)]
#[command(name = "hasp", about = "Unified secrets CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Suppress non-error informational output.
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Increase output verbosity (can be used multiple times).
    #[arg(short, long, global = true, action = ArgAction::Count)]
    verbose: u8,

    /// Print what would happen without mutating anything.
    #[arg(long, global = true)]
    explain: bool,

    /// HTTP CONNECT proxy URL.
    #[arg(long, global = true)]
    proxy_url: Option<String>,

    /// Skip the `HASP_REQUIRE_PROFILE_ALLOW` enforcement check for this
    /// invocation. Useful in CI environments that cannot run
    /// `hasp profile allow` before each command.
    #[arg(long, global = true)]
    no_profile_allow: bool,

    /// Disable the per-invocation in-process secret cache.
    ///
    /// By default `hasp` memoizes fetched secrets for the lifetime of
    /// a single invocation (process lifetime), which eliminates the
    /// duplicate-URL footgun across batched fetches. Also honored:
    /// `HASP_NO_CACHE=1` env var, or presence of `CI` (auto-disabled
    /// in CI environments to defend against credential-cache-targeting
    /// supply-chain worms — see cli-reference.md#caching).
    #[arg(long, global = true)]
    no_cache: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch a secret.
    Get {
        /// URL or alias (`@profile/key`) of the secret.
        #[arg(value_hint = ValueHint::AnyPath, add = ArgValueCompleter::new(completions::complete_address))]
        address: String,
        /// Extract a single field from a JSON-encoded secret payload.
        /// Sugar for `?field=<path>` on the URL; refused if the URL
        /// already carries `?field=`.
        #[arg(short = 'F', long)]
        field: Option<String>,
    },
    /// Store a secret.
    Put {
        /// URL or alias (`@profile/key`) of the secret.
        #[arg(value_hint = ValueHint::AnyPath, add = ArgValueCompleter::new(completions::complete_address))]
        address: String,
        /// Value to store. Use `-` to read from stdin.
        /// If omitted in a TTY, you will be prompted securely.
        value: Option<String>,
    },
    /// List entries matching a URL prefix or alias.
    List {
        /// URL or alias (`@profile`) to list.
        #[arg(value_hint = ValueHint::AnyPath, add = ArgValueCompleter::new(completions::complete_address))]
        address: String,
        /// Output format for list entries.
        #[arg(short, long, value_enum, default_value = "plain")]
        format: Format,
    },
    /// Delete a secret.
    Delete {
        /// URL or alias (`@profile/key`) of the secret.
        #[arg(value_hint = ValueHint::AnyPath, add = ArgValueCompleter::new(completions::complete_address))]
        address: String,
    },
    /// Check whether a secret exists.
    Exists {
        /// URL or alias (`@profile/key`) of the secret.
        #[arg(value_hint = ValueHint::AnyPath, add = ArgValueCompleter::new(completions::complete_address))]
        address: String,
    },
    /// Copy a secret from one URL or alias to another.
    ///
    /// `cp` reads from `src` and writes to `dst`. It is the only verb
    /// that holds plaintext in memory across two backends in one
    /// invocation, so the security model is documented at
    /// `docs/src/cli-reference.md#cp` — read it before scripting
    /// production migrations.
    Cp {
        /// Source URL or alias (`@profile/key`).
        #[arg(value_hint = ValueHint::AnyPath, add = ArgValueCompleter::new(completions::complete_address))]
        src: String,
        /// Destination URL or alias (`@profile/key`).
        #[arg(value_hint = ValueHint::AnyPath, add = ArgValueCompleter::new(completions::complete_address))]
        dst: String,
        /// Behavior when destination already holds a value.
        #[arg(long, value_enum, default_value = "fail")]
        if_exists: CliIfExists,
        /// Shorthand for `--if-exists=overwrite`.
        #[arg(short, long)]
        force: bool,
        /// Re-read destination after writing and constant-time compare.
        #[arg(long)]
        verify: bool,
        /// Confirm cross-environment writes (e.g., prod → stage).
        #[arg(short, long)]
        yes: bool,
    },
    /// Compare two secrets across (possibly different) backends.
    ///
    /// `diff` is the read-only sibling of `cp`: both URLs are fetched
    /// and the values are compared in constant time. The mismatch
    /// reveals nothing beyond the boolean — no byte counts, no common
    /// prefix, no diff position.
    ///
    /// Exit codes: 0 = match, 1 = differ. Backend errors propagate
    /// through the standard exit-code table (auth=5, transport=4,
    /// not-found=2, etc.). The 0/1 boolean parallels `hasp exists`.
    Diff {
        /// First URL or alias (`@profile/key`).
        #[arg(value_hint = ValueHint::AnyPath, add = ArgValueCompleter::new(completions::complete_address))]
        a: String,
        /// Second URL or alias (`@profile/key`).
        #[arg(value_hint = ValueHint::AnyPath, add = ArgValueCompleter::new(completions::complete_address))]
        b: String,
        /// Confirm cross-environment comparison (e.g., prod vs stage).
        #[arg(short, long)]
        yes: bool,
    },
    /// Run a command with secrets injected as environment variables.
    ///
    /// `hasp run -e KEY=URL [...] -- <cmd> [args...]` resolves each
    /// secret through the configured `Store` and execs the command
    /// with those variables added to its environment. The child
    /// inherits hasp's exit code (preserved verbatim).
    ///
    /// Security: env injection is same-uid readable via
    /// `/proc/<pid>/environ` on Linux. PTY masking is deferred.
    Run {
        /// `KEY=URL` (or `KEY=@profile/key`) pair. Repeatable.
        #[arg(short = 'e', long = "env", value_name = "KEY=URL")]
        env: Vec<String>,
        /// Bypass the stdout-is-TTY refusal.
        #[arg(long)]
        allow_tty: bool,
        /// Command and arguments (everything after `--`).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Initialize a default `profiles.toml` in the platform config dir.
    Init {
        /// Overwrite existing config file.
        #[arg(long)]
        force: bool,
    },
    /// Manage profile-file trust (direnv-style allow / show).
    ///
    /// Before `hasp` will use profile aliases in an environment where
    /// `HASP_REQUIRE_PROFILE_ALLOW=1` is set, the operator must run
    /// `hasp profile allow` to record a trusted baseline. Any subsequent
    /// modification to `profiles.toml` is detected and rejected until
    /// `allow` is re-run.
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Manage the in-process and (when enabled) on-disk secret cache.
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Generate a man page for the `hasp` binary.
    ///
    /// Hidden from help to keep the CLI surface minimal.
    #[command(hide = true)]
    Man,
    /// Generate shell completions for the `hasp` binary.
    ///
    /// Hidden from help to keep the CLI surface minimal — completions
    /// are a packaging concern, not a daily user workflow.
    #[command(hide = true)]
    Complete {
        /// Target shell.
        shell: clap_complete::aot::Shell,
    },
}

/// Sub-actions for `hasp cache`.
#[derive(Subcommand)]
enum CacheAction {
    /// Drop every cached entry.
    ///
    /// Today the cache is in-process: clearing it has effect only
    /// within the current invocation (which exits right after this
    /// command, so the gesture is a no-op against future invocations).
    /// When the `cache-persistent` feature is enabled and the
    /// on-disk cache implementation lands, this also removes the
    /// encrypted cache file and the OS-keyring entry holding its key.
    Clear,
}

/// Sub-actions for `hasp profile`.
#[derive(Subcommand)]
enum ProfileAction {
    /// Mark the current `profiles.toml` as trusted.
    ///
    /// Records the file's mtime and SHA-256 to `profiles.allowed` with
    /// mode 0600 on Unix. Any future modification to `profiles.toml`
    /// invalidates the trust; re-run `allow` after reviewing the change.
    Allow,
    /// Print the resolved path, mtime, and allowed status.
    Show,
}

/// CLI mirror of `hasp::IfExists`.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliIfExists {
    /// Refuse to clobber an existing destination (default).
    Fail,
    /// Write over the destination unconditionally.
    Overwrite,
    /// No-op when the destination already has a value.
    Skip,
}

impl CliIfExists {
    fn into_lib(self) -> hasp::IfExists {
        match self {
            CliIfExists::Fail => hasp::IfExists::Fail,
            CliIfExists::Overwrite => hasp::IfExists::Overwrite,
            CliIfExists::Skip => hasp::IfExists::Skip,
        }
    }
}

fn main() {
    clap_complete::CompleteEnv::with_factory(Cli::command).complete();

    // Process-hardening runs before any secret-handling code. Refuses
    // on injection-style env vars (LD_PRELOAD, DYLD_INSERT_LIBRARIES,
    // …) and setuid configurations; applies best-effort platform
    // mitigations (PR_SET_DUMPABLE, WER suppression, mitigation
    // policies, dll search-order). The returned token is the witness
    // that hardening succeeded; it's required to construct the
    // in-process cache later in `run`.
    let token = match hasp::install_hardening() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("hasp: {e}");
            std::process::exit(EXIT_USAGE);
        }
    };

    let cli = Cli::parse();

    if let Err((code, msg)) = run(cli, token) {
        eprintln!("{msg}");
        std::process::exit(code);
    }
}

// Exit-code convention. Documented in `docs/src/cli-reference.md`.
// Mapped from `hasp::Error` variants by `exit_code()`. Soft breaking
// change from the prior 0/1-only behavior; scripts that grep on a
// specific non-zero must migrate.
pub(crate) const EXIT_SUCCESS: i32 = 0;
pub(crate) const EXIT_USAGE: i32 = 1;
pub(crate) const EXIT_NOT_FOUND: i32 = 2;
pub(crate) const EXIT_PERMISSION_DENIED: i32 = 3;
pub(crate) const EXIT_TRANSPORT: i32 = 4;
pub(crate) const EXIT_AUTH_FAILED: i32 = 5;
pub(crate) const EXIT_PRECONDITION: i32 = 6;
// Permanent backend failure that doesn't fit a more-specific code
// (e.g. unexpected 4xx, malformed response). Distinct from EXIT_USAGE
// so scripted callers can distinguish a flag mistake from a backend
// returning something unexpected.
pub(crate) const EXIT_BACKEND: i32 = 7;

fn run(cli: Cli, hardening_token: hasp::HardeningToken) -> Result<(), (i32, String)> {
    // Init and Profile don't need a store; Profile::Allow also doesn't
    // need profiles loaded (it writes the allow record, it doesn't read
    // aliases).
    if let Command::Init { force } = &cli.command {
        return config_init::init(*force).map_err(usage_err);
    }

    let profiles = profiles::load_profiles()
        .map_err(|e| usage_err(format!("failed to load profiles: {e}")))?;

    // Profile allow-list enforcement. Active when
    // `HASP_REQUIRE_PROFILE_ALLOW` is set to a truthy value (`1` or
    // `true`) AND `--no-profile-allow` is not given. Refuse unless the
    // current `profiles.toml` has been explicitly marked trusted via
    // `hasp profile allow`. Truthy-only semantics match the
    // documented `=1` contract; `=0`, empty, or unset all disable.
    if is_truthy_env("HASP_REQUIRE_PROFILE_ALLOW")
        && !matches!(&cli.command, Command::Profile { .. })
    {
        if let Some(profiles_path) = profile_allow::profiles_toml_path() {
            profile_allow::check_profile_allowed(&profiles_path, cli.no_profile_allow)
                .map_err(|e| usage_err(e.to_string()))?;
        }
    }

    let proxy = resolve_proxy(&cli, &profiles)?;
    let audit_sink = resolve_audit_sink();
    let cache_policy = resolve_cache_policy(&cli);
    let store = hasp::StoreBuilder::with_defaults()
        .proxy(proxy)
        .with_audit_sink(audit_sink.clone())
        .with_cache_policy(cache_policy, hardening_token)
        .build();

    // `cp` and `diff` handle `--explain` in their own arms because
    // both have two addresses to resolve. Every other verb's dry-run
    // path lives in this shared branch.
    if cli.explain && !matches!(cli.command, Command::Cp { .. } | Command::Diff { .. }) {
        let address = command_address(&cli);
        if let Some(addr) = address {
            let mut url = resolve(addr, &profiles)?;
            if let Some(path) = command_field(&cli) {
                url = compose_field(&url, path)?;
            }
            let (_scheme, backend_scheme, cached) = store.resolve(&url).map_err(cli_error)?;
            eprintln!("URL:         {url}");
            eprintln!("Backend:     {backend_scheme}");
            eprintln!("Cache:       {}", if cached { "hit" } else { "miss" });
            eprintln!("Operation:   {}", command_verb(&cli));
            return Ok(());
        }
    }

    match cli.command {
        Command::Get { address, field } => {
            if cli.verbose > 0 && !cli.quiet {
                eprintln!("hasp: get {address}");
            }
            let mut url = resolve(&address, &profiles)?;
            if let Some(path) = field.as_deref() {
                url = compose_field(&url, path)?;
            }
            let secret = store.get(&url).map_err(cli_error)?;
            println!("{}", secret.expose_secret());
        }
        Command::Put { address, value } => {
            if cli.verbose > 0 && !cli.quiet {
                eprintln!("hasp: put {address}");
            }
            let url = resolve(&address, &profiles)?;
            let value = read_value(value).map_err(usage_err)?;
            let secret = secrecy::SecretString::new(value.into());
            store.put(&url, &secret).map_err(cli_error)?;
        }
        Command::List { address, format } => {
            if cli.verbose > 0 && !cli.quiet {
                eprintln!("hasp: list {address}");
            }
            let url = resolve(&address, &profiles)?;
            let entries = store.list(&url).map_err(cli_error)?;
            let output = format_list(&entries, format).map_err(usage_err)?;
            if !output.is_empty() {
                println!("{output}");
            }
        }
        Command::Delete { address } => {
            if cli.verbose > 0 && !cli.quiet {
                eprintln!("hasp: delete {address}");
            }
            let url = resolve(&address, &profiles)?;
            store.delete(&url).map_err(cli_error)?;
        }
        Command::Exists { address } => {
            if cli.verbose > 0 && !cli.quiet {
                eprintln!("hasp: exists {address}");
            }
            let url = resolve(&address, &profiles)?;
            // `exists` preserves 0/1 boolean semantics: 0 = present,
            // 1 = absent. Backend errors flow through the standard
            // mapping (auth=5, transport=4, etc.) so callers can still
            // distinguish "key missing" from "could not check".
            let exists = store.exists(&url).map_err(cli_error)?;
            std::process::exit(if exists { EXIT_SUCCESS } else { EXIT_USAGE });
        }
        Command::Cp {
            src,
            dst,
            if_exists,
            force,
            verify,
            yes,
        } => {
            let src_url = resolve(&src, &profiles)?;
            let dst_url = resolve(&dst, &profiles)?;

            // Proxy hygiene: a plain-http proxy in front of a secret
            // copy is a credible MITM vector. cp doubles the exposure
            // window relative to a back-to-back get+put, so refuse
            // unless the caller has explicitly opted in.
            refuse_plain_http_proxy(cli.proxy_url.as_deref(), "cp")?;

            // Cross-environment refusal: when both src and dst are
            // alias-prefixed and their profiles carry an `environment`
            // label, refuse a mismatch without --yes. Absent labels
            // mean no extra check — backwards-compatible for users
            // who haven't adopted the labeling convention.
            if !yes {
                if let (Some(s_env), Some(d_env)) = (
                    profile_environment(&src, &profiles),
                    profile_environment(&dst, &profiles),
                ) {
                    if s_env != d_env {
                        return Err(precondition_err(format!(
                            "refusing cross-environment copy: src='{s_env}' dst='{d_env}'; \
                             pass --yes to confirm"
                        )));
                    }
                }
            }

            let resolved_if_exists = if force {
                hasp::IfExists::Overwrite
            } else {
                if_exists.into_lib()
            };
            let dry_run = cli.explain;
            let opts = hasp::CopyOptions {
                if_exists: resolved_if_exists,
                dry_run,
                verify,
            };

            // Audit emission (cp.start / cp.done) is now produced
            // inside `Store::copy` so library consumers get the same
            // event stream the CLI does. The wire format is unchanged;
            // see `hasp_core::audit`.
            if dry_run && !cli.quiet {
                let src_scheme = scheme_of(&src_url);
                let dst_scheme = scheme_of(&dst_url);
                eprintln!("URL (src):   {src_url}");
                eprintln!("URL (dst):   {dst_url}");
                eprintln!("Backend src: {src_scheme}");
                eprintln!("Backend dst: {dst_scheme}");
                eprintln!(
                    "Operation:   cp (dry-run; no read, no write){}",
                    if verify { " verify=true" } else { "" }
                );
            }

            let outcome_result = store.copy(&src_url, &dst_url, opts);
            if let Ok(o) = &outcome_result {
                if cli.verbose > 0 && !cli.quiet {
                    eprintln!(
                        "hasp: cp {} -> {} (copied={}, verified={})",
                        src, dst, o.copied, o.verified
                    );
                }
            }
            outcome_result.map_err(cli_error)?;
        }
        Command::Diff { a, b, yes } => {
            let a_url = resolve(&a, &profiles)?;
            let b_url = resolve(&b, &profiles)?;

            // diff fetches both secrets, so a MITM on a plain-http
            // proxy can still observe them. Apply the same refusal as
            // cp.
            refuse_plain_http_proxy(cli.proxy_url.as_deref(), "diff")?;

            // Cross-environment refusal: aliases carrying mismatched
            // `environment` labels require explicit --yes confirmation,
            // mirroring `cp`. A diff itself is read-only, but the act
            // of pulling a prod secret into the same process as a stage
            // secret is the surprise we want to gate.
            if !yes {
                if let (Some(a_env), Some(b_env)) = (
                    profile_environment(&a, &profiles),
                    profile_environment(&b, &profiles),
                ) {
                    if a_env != b_env {
                        return Err(precondition_err(format!(
                            "refusing cross-environment diff: a='{a_env}' b='{b_env}'; \
                             pass --yes to confirm"
                        )));
                    }
                }
            }

            if cli.explain && !cli.quiet {
                eprintln!("URL (a):     {a_url}");
                eprintln!("URL (b):     {b_url}");
                eprintln!("Backend a:   {}", scheme_of(&a_url));
                eprintln!("Backend b:   {}", scheme_of(&b_url));
                eprintln!("Operation:   diff (dry-run; no read)");
                return Ok(());
            }

            let outcome = store.compare(&a_url, &b_url).map_err(cli_error)?;
            if cli.verbose > 0 && !cli.quiet {
                eprintln!("hasp: diff {a} vs {b} -> {outcome:?}");
            }
            // 0 = match, 1 = differ. Parallels `hasp exists`.
            std::process::exit(match outcome {
                hasp::DiffOutcome::Match => EXIT_SUCCESS,
                hasp::DiffOutcome::Differ => EXIT_USAGE,
            });
        }
        Command::Run {
            env,
            allow_tty,
            cmd,
        } => {
            let exit = run::run(
                &store,
                &profiles,
                audit_sink.clone(),
                env,
                cmd,
                allow_tty,
                cli.quiet,
                cli.verbose,
            )?;
            std::process::exit(exit);
        }
        Command::Profile { action } => {
            let profiles_path = profile_allow::profiles_toml_path()
                .ok_or_else(|| usage_err("could not determine config directory".into()))?;
            match action {
                ProfileAction::Allow => {
                    profile_allow::profile_allow(&profiles_path)
                        .map_err(|e| usage_err(e.to_string()))?;
                    if !cli.quiet {
                        eprintln!(
                            "profiles.toml at {} marked as trusted.",
                            profiles_path.display()
                        );
                    }
                }
                ProfileAction::Show => {
                    profile_allow::profile_show(&profiles_path)
                        .map_err(|e| usage_err(e.to_string()))?;
                }
            }
        }
        Command::Init { force } => {
            config_init::init(force).map_err(usage_err)?;
        }
        Command::Cache { action } => match action {
            CacheAction::Clear => {
                store.clear_cache();
                if !cli.quiet {
                    eprintln!("hasp cache cleared.");
                }
            }
        },
        Command::Complete { shell } => {
            let mut app = Cli::command();
            let bin_name = app.get_name().to_string();
            clap_complete::aot::generate(shell, &mut app, bin_name, &mut io::stdout());
        }
        Command::Man => {
            let app = Cli::command();
            let man = clap_mangen::Man::new(app);
            let mut buf = Vec::new();
            man.render(&mut buf)
                .map_err(|e| usage_err(format!("failed to render man page: {e}")))?;
            if !cli.quiet {
                io::stdout()
                    .write_all(&buf)
                    .map_err(|e| usage_err(format!("failed to write man page: {e}")))?;
            }
        }
    }
    Ok(())
}

/// Resolve an address to a canonical URL.
///
/// If the address starts with `@`, look it up in the profile resolver.
/// Otherwise return it unchanged, validating that it looks like a URL.
pub(crate) fn resolve(
    address: &str,
    profiles: &profiles::Profiles,
) -> Result<String, (i32, String)> {
    if let Some(rest) = address.strip_prefix('@') {
        let url = profiles
            .resolve(rest)
            .ok_or_else(|| usage_err(format!("unknown profile alias: @{rest}")))?;
        Ok(url)
    } else {
        Ok(address.to_owned())
    }
}

/// Resolve proxy configuration from CLI flag and profile settings.
///
/// 1. `--proxy-url <URL>` CLI flag.
/// 2. `proxy_url = "..."` in the active profile.
/// 3. No explicit proxy — backends fall back to `HTTP_PROXY` / `HTTPS_PROXY`
///    / `ALL_PROXY` environment variables.
fn resolve_proxy(
    cli: &Cli,
    profiles: &profiles::Profiles,
) -> Result<Option<hasp::ProxyConfig>, (i32, String)> {
    // Layer 1: CLI flag.
    if let Some(raw) = &cli.proxy_url {
        return hasp::ProxyConfig::parse(raw)
            .map(Some)
            .map_err(|e| usage_err(format!("invalid --proxy-url: {e}")));
    }

    // Layer 2: profile `proxy_url`.
    // We need the active profile name; look at the command's address.
    for address in command_addresses(cli) {
        if let Some(rest) = address.strip_prefix('@') {
            let profile_name = rest.split_once('/').map(|(p, _)| p).unwrap_or(rest);
            if let Some(raw) = profiles.proxy_url(profile_name) {
                return hasp::ProxyConfig::parse(&raw).map(Some).map_err(|e| {
                    usage_err(format!(
                        "invalid proxy_url in profile '{profile_name}': {e}"
                    ))
                });
            }
        }
    }

    // Layer 3: fall back to env vars handled by reqwest / AWS SDK natively.
    Ok(None)
}

/// Extract the `--field` flag value for verbs that support it.
fn command_field(cli: &Cli) -> Option<&str> {
    match &cli.command {
        Command::Get { field, .. } => field.as_deref(),
        _ => None,
    }
}

/// Extract the primary address argument from the current CLI command.
///
/// Returns `None` for `cp` because `cp` has two addresses and handles
/// `--explain` inside its own arm rather than the shared early branch.
fn command_address(cli: &Cli) -> Option<&str> {
    match &cli.command {
        Command::Get { address, .. }
        | Command::Put { address, .. }
        | Command::List { address, .. }
        | Command::Delete { address }
        | Command::Exists { address } => Some(address.as_str()),
        Command::Cp { .. }
        | Command::Diff { .. }
        | Command::Run { .. }
        | Command::Init { .. }
        | Command::Profile { .. }
        | Command::Cache { .. }
        | Command::Man
        | Command::Complete { .. } => None,
    }
}

/// Extract a human-readable verb from the current CLI command.
fn command_verb(cli: &Cli) -> &'static str {
    match &cli.command {
        Command::Get { .. } => "get",
        Command::Put { .. } => "put",
        Command::List { .. } => "list",
        Command::Delete { .. } => "delete",
        Command::Exists { .. } => "exists",
        Command::Cp { .. } => "cp",
        Command::Diff { .. } => "diff",
        Command::Run { .. } => "run",
        Command::Init { .. } => "init",
        Command::Profile { .. } => "profile",
        Command::Cache { .. } => "cache",
        Command::Man => "man",
        Command::Complete { .. } => "complete",
    }
}

/// Extract all address arguments from the current CLI command for proxy
/// resolution.
fn command_addresses(cli: &Cli) -> Vec<&str> {
    match &cli.command {
        Command::Get { address, .. } => vec![address.as_str()],
        Command::Put { address, .. } => vec![address.as_str()],
        Command::List { address, .. } => vec![address.as_str()],
        Command::Delete { address } => vec![address.as_str()],
        Command::Exists { address } => vec![address.as_str()],
        Command::Cp { src, dst, .. } => vec![src.as_str(), dst.as_str()],
        Command::Diff { a, b, .. } => vec![a.as_str(), b.as_str()],
        Command::Run { env, .. } => env
            .iter()
            .filter_map(|s| s.split_once('=').map(|(_, v)| v))
            .collect(),
        Command::Init { .. }
        | Command::Profile { .. }
        | Command::Cache { .. }
        | Command::Man
        | Command::Complete { .. } => {
            vec![]
        }
    }
}

/// Extract the URL scheme of a resolved URL string.
pub(crate) fn scheme_of(url: &str) -> String {
    url.split_once("://")
        .map(|(s, _)| s.to_owned())
        .unwrap_or_else(|| url.to_owned())
}

/// Look up the `environment` label for the profile referenced by an
/// alias of the form `@<profile>[/key]`. Plain URLs return `None`.
fn profile_environment(address: &str, profiles: &profiles::Profiles) -> Option<String> {
    let rest = address.strip_prefix('@')?;
    let profile_name = rest.split_once('/').map(|(p, _)| p).unwrap_or(rest);
    profiles.environment(profile_name)
}

/// Truthy-env predicate. `1` / `true` / `yes` / `on` (case-insensitive)
/// return true; everything else (including `0`, empty string, unset)
/// returns false. Avoids the `is_some()` footgun where
/// `HASP_REQUIRE_PROFILE_ALLOW=0` would enable enforcement.
fn is_truthy_env(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

/// Resolve the cache policy for this invocation.
///
/// Default is the per-invocation in-process cache
/// (`CachePolicy::process_default`, 5-minute TTL). Disabled by:
///
/// 1. `--no-cache` flag (explicit user opt-out).
/// 2. `HASP_NO_CACHE=1` truthy env var (per-environment opt-out).
/// 3. `HASP_CACHE_TTL=0` env var. AWS Secrets Manager Agent's
///    `TTL=0 disables` convention.
/// 4. Presence of `CI` env var. CI environments are the documented
///    target surface for credential-cache-targeting supply-chain
///    worms (Bitwarden 2026.4.0 / Mini Shai-Hulud / CanisterWorm);
///    auto-disabling there defends against the warm-cache class of
///    exfil without forcing every CI pipeline to remember the flag.
///
/// `HASP_CACHE_TTL=<seconds>` (1..=3600) overrides the default TTL
/// envelope. Above 3600 the value is clamped to 3600 (AWS Agent's
/// published 1-hour ceiling). Below 1 is treated as disabled.
fn resolve_cache_policy(cli: &Cli) -> hasp::CachePolicy {
    if cli.no_cache || is_truthy_env("HASP_NO_CACHE") || std::env::var_os("CI").is_some() {
        return hasp::CachePolicy::Disabled;
    }

    match std::env::var("HASP_CACHE_TTL")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(0) => hasp::CachePolicy::Disabled,
        Some(secs) => {
            let clamped = secs.min(3600);
            hasp::CachePolicy::Process {
                ttl: std::time::Duration::from_secs(clamped),
                capacity: 1024,
            }
        }
        None => hasp::CachePolicy::process_default(),
    }
}

/// Refuse if any well-known proxy env var (or the `--proxy-url` flag)
/// points at a plain-http endpoint. Used by `cp` and `diff`: a MITM on
/// the proxy can observe values fetched through it.
///
/// `verb` appears in the user-facing refusal so the message names the
/// operation that's being blocked. The flag is passed in by reference
/// rather than reading from `&Cli` because callers have typically
/// partially-moved out of the Cli enum's command field via match
/// destructuring.
fn refuse_plain_http_proxy(flag_proxy_url: Option<&str>, verb: &str) -> Result<(), (i32, String)> {
    // Mirror the reqwest / AWS-SDK fallback set: HTTPS_PROXY, HTTP_PROXY,
    // and ALL_PROXY (each in both case-conventions). Missing any one of
    // these would let a user with the alternate variable set bypass the
    // refusal.
    const PROXY_ENV_VARS: &[&str] = &[
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ];
    for var in PROXY_ENV_VARS {
        if let Ok(p) = std::env::var(var) {
            if p.starts_with("http://") && std::env::var_os("HASP_ALLOW_HTTP_PROXY").is_none() {
                return Err(precondition_err(format!(
                    "refusing hasp {verb} through a plain-http proxy ({p} via {var}); \
                     set HASP_ALLOW_HTTP_PROXY=1 to override"
                )));
            }
        }
    }
    if let Some(p) = flag_proxy_url {
        if p.starts_with("http://") && std::env::var_os("HASP_ALLOW_HTTP_PROXY").is_none() {
            return Err(precondition_err(format!(
                "refusing hasp {verb} through a plain-http proxy ({p}); \
                 set HASP_ALLOW_HTTP_PROXY=1 to override"
            )));
        }
    }
    Ok(())
}

/// Build the [`hasp::AuditSink`] for this CLI invocation.
///
/// Resolution layers (highest precedence first):
/// 1. `HASP_AUDIT` env var (`off` / `file` / `syslog` / `stderr`),
///    refined by `HASP_AUDIT_PATH` (file mode) and `HASP_AUDIT_IDENT`
///    (syslog mode).
/// 2. `audit.toml` `[audit]` section, located via
///    `HASP_AUDIT_CONFIG_PATH` or `~/.config/hasp/audit.toml`.
/// 3. Default: [`hasp::StderrSink`].
///
/// File-open failures, syslog-open failures, and unknown sink labels
/// degrade to safe defaults — audit must never poison a verb's
/// result. See [`audit_config`] for the full table.
fn resolve_audit_sink() -> Arc<dyn hasp::AuditSink> {
    audit_config::AuditConfig::resolve().into_sink()
}

/// CLI exit-code mapping for library errors. Exit codes are CLI policy,
/// not library policy — `hasp_core::Error` carries variant info only.
fn exit_code(err: &hasp::Error) -> i32 {
    use hasp::BackendFailureKind;
    match err {
        hasp::Error::UrlParse(_)
        | hasp::Error::InvalidUrl(_)
        | hasp::Error::UnknownScheme(_)
        | hasp::Error::UnsupportedOperation { .. } => EXIT_USAGE,
        hasp::Error::NotFound(_) => EXIT_NOT_FOUND,
        hasp::Error::PermissionDenied(_) => EXIT_PERMISSION_DENIED,
        hasp::Error::AuthenticationFailed(_) => EXIT_AUTH_FAILED,
        hasp::Error::PreconditionFailed(_) => EXIT_PRECONDITION,
        hasp::Error::Backend {
            kind: BackendFailureKind::Transient | BackendFailureKind::Throttled,
            ..
        } => EXIT_TRANSPORT,
        hasp::Error::Backend {
            kind: BackendFailureKind::Permanent,
            ..
        } => EXIT_BACKEND,
        // Future-added variants (Error is #[non_exhaustive]) fall through
        // to usage rather than be misclassified.
        _ => EXIT_USAGE,
    }
}

/// Combine `exit_code` and `fmt_error` into the pair propagated by `run`.
pub(crate) fn cli_error(err: hasp::Error) -> (i32, String) {
    let code = exit_code(&err);
    let message = fmt_error(err);
    (code, message)
}

/// Wrap a `String` CLI-policy error (usage, IO, config parse) as code 1.
pub(crate) fn usage_err(message: String) -> (i32, String) {
    (EXIT_USAGE, message)
}

/// Wrap a CLI-policy refusal (cross-env, plain-http proxy, self-copy)
/// as code 6 (precondition). The refusal originates in the CLI rather
/// than the library, but maps onto the same semantic — "preconditions
/// for this operation are not met."
pub(crate) fn precondition_err(message: String) -> (i32, String) {
    (EXIT_PRECONDITION, message)
}

/// Append `?field=<path>` (URL-encoded) to an address.
///
/// Refuses if the URL already carries `?field=` to keep `-F` and the
/// query-param form unambiguous — silently overriding either direction
/// would surprise users scripting on top of the URL.
fn compose_field(url: &str, path: &str) -> Result<String, (i32, String)> {
    let mut parsed = url::Url::parse(url).map_err(|e| usage_err(format!("invalid URL: {e}")))?;
    if parsed.query_pairs().any(|(k, _)| k == "field") {
        return Err(usage_err(
            "URL already specifies ?field=; -F/--field would conflict".into(),
        ));
    }
    parsed.query_pairs_mut().append_pair("field", path);
    Ok(parsed.into())
}

/// Read a secret value from argument, stdin, or TTY prompt.
///
/// If the argument is `-`, reads from stdin until EOF.
/// If no argument is given and stdin is a TTY, prompts securely via
/// `rpassword` so the value is not echoed.
/// If no argument and stdin is not a TTY, reads stdin to EOF.
fn read_value(value: Option<String>) -> Result<String, String> {
    match value.as_deref() {
        Some("-") | None if !io::stdin().is_terminal() => {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("failed to read stdin: {e}"))?;
            Ok(buf)
        }
        None => {
            let prompt = "Value: ";
            rpassword::prompt_password(prompt).map_err(|e| format!("failed to read password: {e}"))
        }
        Some(v) => Ok(v.to_owned()),
    }
}

/// Format a `hasp::Error` into a human-readable string for the CLI.
///
/// Never includes secret values. Adds actionable hints for common
/// error variants so users know what to check next.
fn fmt_error(err: hasp::Error) -> String {
    use hasp::BackendFailureKind;
    match err {
        hasp::Error::UrlParse(ref e) => {
            format!("invalid URL: {e}\nHint: ensure the address is a valid URL")
        }
        hasp::Error::InvalidUrl(ref msg) => {
            format!("invalid URL for backend: {msg}\nHint: check the URL grammar for the scheme")
        }
        hasp::Error::UnknownScheme(ref scheme) => {
            format!(
                "unsupported scheme: {scheme}\nHint: register the backend or enable the Cargo feature"
            )
        }
        hasp::Error::UnsupportedOperation { scheme, operation } => {
            format!("{scheme} does not support {operation}")
        }
        hasp::Error::NotFound(ref msg) => {
            format!(
                "not found: {msg}\nHint: verify the secret name and that backend credentials have access"
            )
        }
        hasp::Error::PermissionDenied(ref msg) => {
            format!(
                "permission denied: {msg}\nHint: check IAM / RBAC policies for this resource"
            )
        }
        hasp::Error::AuthenticationFailed(ref msg) => {
            format!(
                "authentication failed: {msg}\nHint: ensure ambient credentials are configured for this backend"
            )
        }
        hasp::Error::PreconditionFailed(ref msg) => {
            format!(
                "precondition failed: {msg}\nHint: the resource may be in an incompatible state (e.g., soft-deleted)"
            )
        }
        hasp::Error::Backend {
            ref scheme,
            kind,
            ref message,
        } => match kind {
            BackendFailureKind::Throttled => format!(
                "backend '{scheme}' throttled: {message}\nHint: wait and retry"
            ),
            BackendFailureKind::Transient => format!(
                "backend '{scheme}' failed: {message}\nHint: this is a transient error; retrying may help"
            ),
            BackendFailureKind::Permanent => {
                format!("backend '{scheme}' failed: {message}")
            }
            _ => format!("backend '{scheme}' failed: {message}"),
        },
        _ => err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hasp::BackendFailureKind;

    #[test]
    fn exit_code_url_parse() {
        let err = url::Url::parse("not a url").unwrap_err();
        assert_eq!(exit_code(&hasp::Error::UrlParse(err)), EXIT_USAGE);
    }

    #[test]
    fn exit_code_invalid_url() {
        assert_eq!(
            exit_code(&hasp::Error::InvalidUrl("bad".into())),
            EXIT_USAGE
        );
    }

    #[test]
    fn exit_code_unknown_scheme() {
        assert_eq!(
            exit_code(&hasp::Error::UnknownScheme("foo".into())),
            EXIT_USAGE
        );
    }

    #[test]
    fn exit_code_unsupported_operation() {
        assert_eq!(
            exit_code(&hasp::Error::UnsupportedOperation {
                scheme: "env",
                operation: "put"
            }),
            EXIT_USAGE
        );
    }

    #[test]
    fn exit_code_not_found() {
        assert_eq!(
            exit_code(&hasp::Error::NotFound("x".into())),
            EXIT_NOT_FOUND
        );
    }

    #[test]
    fn exit_code_permission_denied() {
        assert_eq!(
            exit_code(&hasp::Error::PermissionDenied("x".into())),
            EXIT_PERMISSION_DENIED
        );
    }

    #[test]
    fn exit_code_auth_failed() {
        assert_eq!(
            exit_code(&hasp::Error::AuthenticationFailed("x".into())),
            EXIT_AUTH_FAILED
        );
    }

    #[test]
    fn exit_code_precondition_failed() {
        assert_eq!(
            exit_code(&hasp::Error::PreconditionFailed("x".into())),
            EXIT_PRECONDITION
        );
    }

    #[test]
    fn exit_code_backend_transient() {
        assert_eq!(
            exit_code(&hasp::Error::Backend {
                scheme: "vault",
                kind: BackendFailureKind::Transient,
                message: "timeout".into(),
            }),
            EXIT_TRANSPORT
        );
    }

    #[test]
    fn exit_code_backend_throttled() {
        assert_eq!(
            exit_code(&hasp::Error::Backend {
                scheme: "aws-sm",
                kind: BackendFailureKind::Throttled,
                message: "429".into(),
            }),
            EXIT_TRANSPORT
        );
    }

    #[test]
    fn exit_code_backend_permanent() {
        assert_eq!(
            exit_code(&hasp::Error::Backend {
                scheme: "gcp-sm",
                kind: BackendFailureKind::Permanent,
                message: "418".into(),
            }),
            EXIT_BACKEND
        );
    }

    #[test]
    fn compose_field_appends_query() {
        let out = compose_field("vault://kv/data/app", "password").unwrap();
        // url crate normalizes the trailing slash; check the suffix.
        assert!(out.ends_with("?field=password"), "got: {out}");
    }

    #[test]
    fn compose_field_appends_to_existing_query() {
        let out = compose_field("vault://kv/data/app?version=2", "password").unwrap();
        assert!(
            out.contains("version=2") && out.contains("field=password"),
            "got: {out}"
        );
    }

    #[test]
    fn compose_field_encodes_special_chars() {
        // url::Url::query_pairs_mut percent-encodes spaces as `+`.
        let out = compose_field("vault://kv/data/app", "with space").unwrap();
        assert!(out.contains("field=with+space"), "got: {out}");
    }

    #[test]
    fn compose_field_refuses_double_spec() {
        let err = compose_field("vault://kv/data/app?field=already", "password").unwrap_err();
        assert_eq!(err.0, EXIT_USAGE);
        assert!(err.1.contains("already specifies ?field="));
    }
}
