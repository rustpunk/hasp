//! `hasp run -- <cmd>` subprocess env injection.
//!
//! Reads `KEY=URL` pairs, fetches each secret through the shared
//! `Store`, exports the resolved value as `KEY` in the child's
//! environment, and execs the command. The child inherits hasp's
//! redirected stdio and its exit code.
//!
//! Threat model: env injection has fundamental same-uid
//! `/proc/<pid>/environ` visibility on Linux. This is the unavoidable
//! cost of subprocess env injection; documented in
//! `docs/src/cli-reference.md#run`. PTY masking (1Password's `op run`
//! trick) is deferred.

use crate::profiles::Profiles;
use crate::{
    cli_error, precondition_err, resolve, scheme_of, usage_err, EXIT_BACKEND, EXIT_SUCCESS,
};
use hasp::{AuditEvent, AuditSink, Verb};
use secrecy::ExposeSecret;
use std::collections::{BTreeSet, HashMap};
use std::io::IsTerminal;
use std::process::Command;
use std::sync::Arc;

/// Parsed `-e KEY=URL` entry.
struct EnvSpec {
    key: String,
    address: String,
}

impl EnvSpec {
    fn parse(raw: &str) -> Result<Self, (i32, String)> {
        let (key, address) = raw
            .split_once('=')
            .ok_or_else(|| usage_err(format!("-e expects KEY=URL, got '{raw}'")))?;
        if key.is_empty() {
            return Err(usage_err(format!("-e KEY=URL: empty key in '{raw}'")));
        }
        // POSIX env names: letters, digits, underscore; not starting
        // with a digit. We don't enforce strict POSIX (some shells
        // accept laxer names) but we do refuse keys containing `=` or
        // NUL, which would corrupt the child's environment.
        if key.contains('\0') || address.contains('\0') {
            return Err(usage_err(
                "-e KEY=URL: NUL byte in key or value not allowed".into(),
            ));
        }
        Ok(EnvSpec {
            key: key.to_owned(),
            address: address.to_owned(),
        })
    }
}

/// Entry point for the `Run` arm.
///
/// `entries` are the raw `KEY=URL` strings from `-e`; `cmd_and_args`
/// is the trailing positional argv (everything after `--`).
#[allow(clippy::too_many_arguments)]
pub fn run(
    store: &hasp::Store,
    profiles: &Profiles,
    audit_sink: Arc<dyn AuditSink>,
    entries: Vec<String>,
    cmd_and_args: Vec<String>,
    allow_tty: bool,
    quiet: bool,
    verbose: u8,
) -> Result<i32, (i32, String)> {
    if cmd_and_args.is_empty() {
        return Err(usage_err(
            "hasp run requires a command after `--`, e.g. `hasp run -e K=env://V -- ./app`".into(),
        ));
    }

    // Refuse to run on an interactive terminal unless the caller
    // explicitly opts in. The default exists because the common
    // accidental pattern `hasp run -- echo $DB_PASS` echoes the secret
    // to the user's terminal (and scroll buffer / tmux capture / SSH
    // recording). Scripted callers piping stdio already pass this
    // check; only interactive misuse is blocked. Both stdout and
    // stderr are checked — a child writing the value to stderr in an
    // interactive shell is just as exposed as one writing to stdout.
    if !allow_tty && (std::io::stdout().is_terminal() || std::io::stderr().is_terminal()) {
        return Err(precondition_err(
            "refusing to run with stdout or stderr attached to a TTY; pass --allow-tty to \
             override (printed values may end up in your terminal scroll buffer or recording)"
                .into(),
        ));
    }

    let specs: Vec<EnvSpec> = entries
        .iter()
        .map(|raw| EnvSpec::parse(raw))
        .collect::<Result<_, _>>()?;

    // Refuse duplicate KEYs: silent override would surprise users
    // scripting on top of `-e`.
    let mut seen = HashMap::new();
    for s in &specs {
        if seen.insert(s.key.clone(), ()).is_some() {
            return Err(usage_err(format!("-e KEY=URL: duplicate key '{}'", s.key)));
        }
    }

    // Pre-compute the umbrella scheme for `run.start` / `run.done`.
    // Single scheme: report it. Mixed: "multi". Empty: "none".
    let mut schemes: BTreeSet<String> = BTreeSet::new();
    for s in &specs {
        let url = resolve(&s.address, profiles)?;
        schemes.insert(scheme_of(&url));
    }
    let umbrella = match schemes.len() {
        0 => "none".to_owned(),
        1 => schemes.iter().next().cloned().unwrap(),
        _ => "multi".to_owned(),
    };

    audit_sink.emit(&AuditEvent::start(Verb::Run, umbrella.clone()));

    // Resolve every URL up front. If any fetch fails, the child is
    // never spawned — hasp run is all-or-nothing. The per-URL
    // `get.start` / `get.done` events come from `Store::get` for free.
    let mut resolved: Vec<(String, secrecy::SecretString)> = Vec::with_capacity(specs.len());
    for s in &specs {
        let url = resolve(&s.address, profiles)?;
        match store.get(&url) {
            Ok(secret) => resolved.push((s.key.clone(), secret)),
            Err(e) => {
                let kind = e.kind();
                audit_sink.emit(
                    &AuditEvent::done(Verb::Run, umbrella.clone(), "error").with_error_kind(kind),
                );
                return Err(cli_error(e));
            }
        }
    }

    if verbose > 0 && !quiet {
        eprintln!(
            "hasp: run {} (env keys: {})",
            cmd_and_args.join(" "),
            specs
                .iter()
                .map(|s| s.key.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
    }

    let (program, args) = cmd_and_args.split_first().expect("non-empty checked above");
    let mut command = Command::new(program);
    command.args(args);
    for (key, secret) in &resolved {
        command.env(key, secret.expose_secret());
    }

    // Inherits stdin/stdout/stderr from the parent by default —
    // subprocess output flows through to the user's terminal, which is
    // the entire point of `hasp run`.
    let status = match command.status() {
        Ok(s) => s,
        Err(e) => {
            audit_sink.emit(
                &AuditEvent::done(Verb::Run, umbrella.clone(), "error").with_error_kind("backend"),
            );
            return Err((EXIT_BACKEND, format!("failed to exec '{program}': {e}")));
        }
    };

    let code = if let Some(c) = status.code() {
        c
    } else {
        // Killed by signal on Unix: surface as 128+signo per shell
        // convention. On Windows, status.code() is always Some.
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(sig) = status.signal() {
                128 + sig
            } else {
                EXIT_SUCCESS
            }
        }
        #[cfg(not(unix))]
        {
            EXIT_SUCCESS
        }
    };

    let outcome = if code == 0 { "ok" } else { "child_nonzero" };
    audit_sink.emit(&AuditEvent::done(Verb::Run, umbrella, outcome));

    Ok(code)
}
