//! anago CLI (DESIGN.md §8).
//!
//! `main` does three things: read argv, ask [`cli::parse`] what it
//! means, and run it. Routing has no side effects and lives in `cli`,
//! so this file stays small enough to read in one screen.
//!
//! The M0 commands route and validate but have no implementation
//! behind them yet — the server, join, and state-file slices land
//! next. They exit non-zero rather than pretending to have worked.

mod activate;
#[allow(dead_code)]
mod api;
mod args;
mod cli;
#[allow(dead_code)]
mod client;
mod code;
mod init;
mod join;
mod ls;
// Path rules and file handling are complete and unit-tested; the
// slices that read and write those files (server init, join) land next,
// so both modules are briefly ahead of their callers.
#[allow(dead_code)]
mod fsutil;
// Client-side path resolution and a few server paths are used by the
// join and serving slices that land next.
#[allow(dead_code)]
mod paths;
#[allow(dead_code)]
mod secret;
mod serve;
#[allow(dead_code)]
mod store;
#[allow(dead_code)]
mod systemd;
#[allow(dead_code)]
mod tls;
#[allow(dead_code)]
mod wg;
#[allow(dead_code)]
mod wgapply;

use cli::Command;

/// Exit codes: 1 for "understood, could not do it", 2 for "did not
/// understand". A script can tell a typo from a failure; which error
/// falls where is decided by [`cli::exit_code`].
const EXIT_FAILED: i32 = 1;
const EXIT_USAGE: i32 = 2;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    let command = match cli::parse(&argv) {
        Ok(command) => command,
        Err(e) => {
            eprintln!("anago: {e}");
            // A command that exists but belongs to a later milestone
            // was understood; only a typo earns the usage code.
            if cli::exit_code(&e) == EXIT_USAGE {
                eprintln!("try `anago --help`");
            }
            std::process::exit(cli::exit_code(&e));
        }
    };

    match command {
        Command::Version => println!("anago {}", env!("CARGO_PKG_VERSION")),
        Command::Help(topic) => print!("{}", cli::help(topic.as_deref())),
        Command::ServerInit(args) => server_init(&args),
        Command::ServerRun => server_run(),
        Command::Code => match code::run(std::path::Path::new(paths::DEFAULT_SERVER_ROOT), now()) {
            Ok(text) => print!("{text}"),
            Err(e) => {
                eprintln!("anago: {e}");
                std::process::exit(EXIT_FAILED);
            }
        },
        Command::Join(args) => join_device(&args),
        Command::Ls => list_devices(),
        Command::Rm(_) => not_yet_built("anago rm"),
    }
}

/// `anago server init` — the only M0 command wired up so far.
fn server_init(args: &cli::ServerInit) -> ! {
    match init::run(
        args,
        std::path::Path::new(paths::DEFAULT_SERVER_ROOT),
        std::path::Path::new(paths::DEFAULT_WG_DIR),
        now(),
    ) {
        Ok(done) => {
            for warning in &done.warnings {
                eprintln!("anago: warning: {warning}");
            }
            // `init::run` already ends with how this hub starts —
            // under systemd, or by hand. Nothing to add here.
            print!("{}", done.instructions);
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("anago: {e}");
            std::process::exit(EXIT_FAILED);
        }
    }
}

/// `anago server run` — the process systemd starts.
fn server_run() -> ! {
    match serve::run(
        std::path::Path::new(paths::DEFAULT_SERVER_ROOT),
        std::path::Path::new(paths::DEFAULT_WG_DIR),
    ) {
        // `serve::run` only returns when the listener stops.
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("anago: {e}");
            std::process::exit(EXIT_FAILED);
        }
    }
}

/// `anago join <domain> <code>`.
fn join_device(args: &cli::Join) -> ! {
    let client_paths = match paths::client_config_dir_from_env() {
        Ok(paths) => paths,
        Err(e) => {
            eprintln!("anago: {e}");
            std::process::exit(EXIT_FAILED);
        }
    };
    let wg_config = paths::wg_config(paths::DEFAULT_WG_DIR);

    match join::run(
        &args.domain,
        &args.code,
        args.name.clone(),
        args.api_port,
        &client_paths,
        &wg_config,
    ) {
        Ok(joined) => {
            println!(
                "Registered as {name} — this device is {address} on {subnet}.",
                name = joined.config.name,
                address = joined.config.address,
                subnet = joined.config.subnet
            );
            println!(
                "  device file   {}\n  wg config     {}",
                client_paths.device_file().display(),
                wg_config.display()
            );

            // Bring the tunnel up and see whether it carries traffic.
            // The registration stands either way, so a failure here is
            // a diagnosis rather than a rollback.
            let Some(server_address) = joined.config.server_ip() else {
                // validate() accepted it, so this is a file edited by
                // hand between then and now.
                eprintln!("anago: the saved hub address is unreadable — bring the tunnel up with");
                eprintln!("       sudo wg-quick up {}", wg_config.display());
                std::process::exit(EXIT_FAILED);
            };
            let path_var = std::env::var("PATH").unwrap_or_default();
            let outcome = activate::run(&wg_config, server_address, &path_var);
            let report = activate::report(
                &outcome,
                server_address,
                &joined.config.server_endpoint,
                &wg_config,
            );
            if outcome.is_working() {
                print!("{report}");
                std::process::exit(0);
            }
            eprint!("{report}");
            std::process::exit(EXIT_FAILED);
        }
        Err(e) => {
            eprintln!("anago: {e}");
            std::process::exit(EXIT_FAILED);
        }
    }
}

/// `anago ls` — from the state file on the hub, from the API on a
/// device.
fn list_devices() -> ! {
    // The config directory is resolved lazily: a hub reads its own
    // state file, and asking for HOME first would break `anago ls` in
    // cron or a bare service environment.
    match ls::run(
        std::path::Path::new(paths::DEFAULT_SERVER_ROOT),
        std::path::Path::new(paths::DEFAULT_WG_DIR),
        paths::client_config_dir_from_env,
        now(),
    ) {
        Ok(table) => {
            print!("{table}");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("anago: {e}");
            std::process::exit(EXIT_FAILED);
        }
    }
}

/// Unix epoch seconds.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// An M0 command that routes and validates but has no implementation
/// behind it yet. Distinct from `CliError::NotYet`, which is a settled
/// answer about a later milestone.
fn not_yet_built(command: &str) -> ! {
    eprintln!("anago: {command} is not implemented yet — M0 is still being built");
    eprintln!("the command line was accepted; docs/DESIGN.md §11 has what lands when");
    std::process::exit(EXIT_FAILED);
}
