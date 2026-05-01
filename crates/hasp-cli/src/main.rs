use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueHint};
use clap_complete::engine::ArgValueCompleter;
use secrecy::ExposeSecret;
use std::io::{self, IsTerminal, Read, Write};

mod completions;
mod list_format;
mod profiles;
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
}

#[derive(Subcommand)]
enum Command {
    /// Fetch a secret.
    Get {
        /// URL or alias (`@profile/key`) of the secret.
        #[arg(value_hint = ValueHint::AnyPath, add = ArgValueCompleter::new(completions::complete_address))]
        address: String,
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

fn main() {
    clap_complete::CompleteEnv::with_factory(Cli::command).complete();

    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let profiles =
        profiles::load_profiles().map_err(|e| format!("failed to load profiles: {e}"))?;

    let proxy = resolve_proxy(&cli, &profiles)?;
    let store = hasp::StoreBuilder::with_defaults().proxy(proxy).build();

    if cli.explain {
        let address = command_address(&cli);
        if let Some(addr) = address {
            let url = resolve(addr, &profiles)?;
            let (_scheme, backend_scheme, cached) = store.resolve(&url).map_err(fmt_error)?;
            eprintln!("URL:         {url}");
            eprintln!("Backend:     {backend_scheme}");
            eprintln!("Cache:       {}", if cached { "hit" } else { "miss" });
            eprintln!("Operation:   {}", command_verb(&cli));
            return Ok(());
        }
    }

    match cli.command {
        Command::Get { address } => {
            if cli.verbose > 0 && !cli.quiet {
                eprintln!("hasp: get {address}");
            }
            let url = resolve(&address, &profiles)?;
            let secret = store.get(&url).map_err(fmt_error)?;
            println!("{}", secret.expose_secret());
        }
        Command::Put { address, value } => {
            if cli.verbose > 0 && !cli.quiet {
                eprintln!("hasp: put {address}");
            }
            let url = resolve(&address, &profiles)?;
            let value = read_value(value)?;
            let secret = secrecy::SecretString::new(value.into());
            store.put(&url, &secret).map_err(fmt_error)?;
        }
        Command::List { address, format } => {
            if cli.verbose > 0 && !cli.quiet {
                eprintln!("hasp: list {address}");
            }
            let url = resolve(&address, &profiles)?;
            let entries = store.list(&url).map_err(fmt_error)?;
            let output = format_list(&entries, format)?;
            if !output.is_empty() {
                println!("{output}");
            }
        }
        Command::Delete { address } => {
            if cli.verbose > 0 && !cli.quiet {
                eprintln!("hasp: delete {address}");
            }
            let url = resolve(&address, &profiles)?;
            store.delete(&url).map_err(fmt_error)?;
        }
        Command::Exists { address } => {
            if cli.verbose > 0 && !cli.quiet {
                eprintln!("hasp: exists {address}");
            }
            let url = resolve(&address, &profiles)?;
            let exists = store.exists(&url).map_err(fmt_error)?;
            std::process::exit(if exists { 0 } else { 1 });
        }
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
                .map_err(|e| format!("failed to render man page: {e}"))?;
            if !cli.quiet {
                io::stdout()
                    .write_all(&buf)
                    .map_err(|e| format!("failed to write man page: {e}"))?;
            }
        }
    }
    Ok(())
}

/// Resolve an address to a canonical URL.
///
/// If the address starts with `@`, look it up in the profile resolver.
/// Otherwise return it unchanged, validating that it looks like a URL.
fn resolve(address: &str, profiles: &profiles::Profiles) -> Result<String, String> {
    if let Some(rest) = address.strip_prefix('@') {
        let url = profiles
            .resolve(rest)
            .ok_or_else(|| format!("unknown profile alias: @{rest}"))?;
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
) -> Result<Option<hasp::ProxyConfig>, String> {
    // Layer 1: CLI flag.
    if let Some(raw) = &cli.proxy_url {
        return hasp::ProxyConfig::parse(raw)
            .map(Some)
            .map_err(|e| format!("invalid --proxy-url: {e}"));
    }

    // Layer 2: profile `proxy_url`.
    // We need the active profile name; look at the command's address.
    for address in command_addresses(cli) {
        if let Some(rest) = address.strip_prefix('@') {
            let profile_name = rest.split_once('/').map(|(p, _)| p).unwrap_or(rest);
            if let Some(raw) = profiles.proxy_url(profile_name) {
                return hasp::ProxyConfig::parse(&raw)
                    .map(Some)
                    .map_err(|e| format!("invalid proxy_url in profile '{profile_name}': {e}"));
            }
        }
    }

    // Layer 3: fall back to env vars handled by reqwest / AWS SDK natively.
    Ok(None)
}

/// Extract the primary address argument from the current CLI command.
fn command_address(cli: &Cli) -> Option<&str> {
    match &cli.command {
        Command::Get { address }
        | Command::Put { address, .. }
        | Command::List { address, .. }
        | Command::Delete { address }
        | Command::Exists { address } => Some(address.as_str()),
        Command::Man | Command::Complete { .. } => None,
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
        Command::Man => "man",
        Command::Complete { .. } => "complete",
    }
}

/// Extract all address arguments from the current CLI command for proxy
/// resolution.
fn command_addresses(cli: &Cli) -> Vec<&str> {
    match &cli.command {
        Command::Get { address } => vec![address.as_str()],
        Command::Put { address, .. } => vec![address.as_str()],
        Command::List { address, .. } => vec![address.as_str()],
        Command::Delete { address } => vec![address.as_str()],
        Command::Exists { address } => vec![address.as_str()],
        Command::Man | Command::Complete { .. } => vec![],
    }
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
