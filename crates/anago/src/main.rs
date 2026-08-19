//! anago CLI (DESIGN.md §8).
//!
//! `main` does three things: read argv, ask [`cli::parse`] what it
//! means, and run it. Routing has no side effects and lives in `cli`,
//! so this file stays small enough to read in one screen.
//!
//! Every M0 command (§8) is wired up: `server init`, `server run`,
//! `code`, `join`, `ls`, `rm`.

mod activate;
// Which way the hub gets its certificate: `server init` orders the
// first one and `serve` renews it. A few pieces wait for
// `server renew`, which lands next.
#[allow(dead_code)]
mod acme;
mod api;
mod args;
// Cloudflare: where the token comes from, which zone the domain lives
// in, and the hub's A record. `server init` uses all of it; token
// verification waits for the command that rotates one.
#[allow(dead_code)]
mod cfapi;
mod cli;
mod client;
mod code;
mod diagnostics;
// Watching for a DNS-01 record to be served, alongside `cfapi`'s
// challenge record.
mod dnsprobe;
mod fsutil;
mod init;
mod join;
mod launchd;
mod ls;
mod paths;
mod qrcode;
mod renew;
mod rm;
mod secret;
mod serve;
mod store;
mod sync;
mod systemd;
mod timer;
mod tls;
mod wg;
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
        Command::ServerRenew(args) => server_renew(&args),
        Command::ServerRun => server_run(),
        Command::Sync(args) => sync_device(&args),
        Command::Code => match code::run(std::path::Path::new(paths::DEFAULT_SERVER_ROOT), now()) {
            Ok(text) => print!("{text}"),
            Err(e) => {
                eprintln!("anago: {e}");
                std::process::exit(EXIT_FAILED);
            }
        },
        Command::Join(args) => join_device(&args),
        Command::Ls => list_devices(),
        Command::Rm(args) => remove_device(&args),
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

/// `anago server renew` — a certificate again, a setting changed, or
/// the A record pushed. Never touches `wg` (§8).
fn server_renew(args: &cli::ServerRenew) -> ! {
    let root = std::path::Path::new(paths::DEFAULT_SERVER_ROOT);
    let store = store::Store::new(root);
    let server_paths = paths::ServerPaths::new(root);
    let env = std::env::var(cfapi::TOKEN_ENV).ok();
    match renew::run(&store, &server_paths, args, env.as_deref(), now()) {
        Ok(done) => {
            for warning in &done.warnings {
                eprintln!("anago: warning: {warning}");
            }
            print!("{}", done.output);
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

/// `anago sync` — on a device, pull the peer list (§6.3).
fn sync_device(args: &cli::Sync) -> ! {
    let wg_config = paths::wg_config(paths::DEFAULT_WG_DIR);
    if let Some(timer) = args.timer {
        manage_timer(timer, args.config.as_deref(), &wg_config);
    }

    let synced = sync::run(args.config.as_deref(), &wg_config, args.quiet);
    if !synced.report.is_empty() {
        // stdout is what the run found; stderr is what it could not
        // do. `Passed` is the second kind — the hub was not reachable,
        // or another run had the lock — so it goes there even though
        // it exits zero (§6.3). Under `--quiet` the report is empty
        // for both and nothing is printed at all.
        match synced.ending {
            sync::Ending::Fine => print!("{}", synced.report),
            sync::Ending::Passed | sync::Ending::Stop => eprint!("{}", synced.report),
        }
    }
    std::process::exit(synced.ending.exit_code());
}

/// `anago sync --install-timer` / `--uninstall-timer` (§8).
///
/// The device file is resolved here, while `sudo` still says who ran
/// the command — the unit itself will run with none of that (§8).
fn manage_timer(
    timer: cli::Timer,
    config: Option<&std::path::Path>,
    wg_config: &std::path::Path,
) -> ! {
    let machine = timer::scheduler_here();
    let unit_dir = std::path::Path::new(systemd::UNIT_DIR);
    let daemon_dir = std::path::Path::new(launchd::DAEMON_DIR);

    let result = match timer {
        cli::Timer::Install { interval } => {
            let device_file = match sync::device_file(config) {
                Ok(path) => path,
                Err(e) => {
                    eprintln!("anago: {e}");
                    std::process::exit(EXIT_FAILED);
                }
            };
            // A unit needs an absolute program path, and a guess would
            // be baked into a file that runs as root.
            let exec = match std::env::current_exe() {
                Ok(exec) => exec,
                Err(e) => {
                    eprintln!(
                        "anago: could not find this binary's own path ({e}), and a schedule \n       \
                         has to name it in full — run `anago sync` by hand instead"
                    );
                    std::process::exit(EXIT_FAILED);
                }
            };
            timer::install(
                machine,
                &timer::Setup {
                    exec: &exec,
                    device_file: &device_file,
                    wg_config,
                    interval,
                    unit_dir,
                    daemon_dir,
                },
            )
        }
        cli::Timer::Uninstall => timer::uninstall(&timer::removal(machine, unit_dir, daemon_dir)),
    };

    match result {
        Ok(report) => {
            print!("{report}");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("anago: {e}");
            std::process::exit(EXIT_FAILED);
        }
    }
}

/// `anago join <domain> <code>`.
fn join_device(args: &cli::Join) -> ! {
    // Before anything local. `--export` registers a *phone* and writes
    // nothing here (§8), so it must not go past this point — not even
    // to resolve a config directory it will never use.
    if let Some(export) = args.export.clone() {
        export_phone(args, export);
    }

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
        paths::invoking_user_from_env().as_ref(),
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
                // Advice, not an install: the periodic sync is a
                // convenience rather than a correctness requirement
                // (§6.3), so joining does not quietly leave a
                // recurring root job behind. An unreadable answer
                // about what is already installed is not join's
                // problem — the advice is advice.
                let machine = timer::scheduler_here();
                let present = timer::present_here(
                    machine,
                    std::path::Path::new(systemd::UNIT_DIR),
                    std::path::Path::new(launchd::DAEMON_DIR),
                );
                print!("\n{}", timer::advice(machine, present));
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

/// `anago join --export` — registers a phone and hands over its config
/// (§8, §7.3).
///
/// Nothing on this machine changes, so nothing here resolves a path
/// under §9 or asks for root.
fn export_phone(args: &cli::Join, export: cli::Export) -> ! {
    let Some(name) = args.name.clone() else {
        // The parser refuses `--export` without `--name`, because the
        // hostname default names this machine (§8). Only reachable if
        // that rule is ever taken out.
        eprintln!("anago: --export needs --name");
        std::process::exit(EXIT_USAGE);
    };
    // The width is asked for before the hub is, so a window too narrow
    // to draw in costs nothing: the join code is still unspent when it
    // refuses.
    let to = match &export {
        cli::Export::Conf { out: Some(path) } => join::Handover::File(path),
        cli::Export::Conf { out: None } => join::Handover::Text,
        cli::Export::Qr => join::Handover::Qr {
            columns: qrcode::columns(),
        },
    };

    match join::export_conf(&args.domain, &args.code, &name, args.api_port, to) {
        Ok(exported) => {
            // The config itself has already gone to stdout or to the
            // file; everything else goes to stderr, so a pipe carries
            // the config alone (§7.3). The blank line first is for the
            // QR, which ends flush against whatever comes next.
            eprintln!(
                "\nRegistered {name} — the phone is {address} on {subnet}.\n",
                address = exported.config.address,
                subnet = exported.config.subnet
            );
            eprint!("{}", join::export_note(&name, &exported.handed));
            std::process::exit(0);
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

/// `anago rm <name>` — locally on the hub, over the API on a device.
fn remove_device(args: &cli::Rm) -> ! {
    let wg_config = paths::wg_config(paths::DEFAULT_WG_DIR);
    match rm::run(
        &args.name,
        std::path::Path::new(paths::DEFAULT_SERVER_ROOT),
        std::path::Path::new(paths::DEFAULT_WG_DIR),
        paths::client_config_dir_from_env,
    ) {
        Ok(removed) => {
            let device_file = paths::client_config_dir_from_env()
                .map(|paths| paths.device_file())
                .unwrap_or_else(|_| std::path::PathBuf::from("~/.config/anago/device.json"));
            print!("{}", rm::report(&removed, &device_file, &wg_config));
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
