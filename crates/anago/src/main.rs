//! anago CLI (DESIGN.md §8).
//!
//! `main` does three things: read argv, ask [`cli::parse`] what it
//! means, and run it. Routing has no side effects and lives in `cli`,
//! so this file stays small enough to read in one screen.
//!
//! The M0 commands route and validate but have no implementation
//! behind them yet — the server, join, and state-file slices land
//! next. They exit non-zero rather than pretending to have worked.

mod args;
mod cli;

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
        Command::ServerInit(_) => not_yet_built("anago server init"),
        Command::Code => not_yet_built("anago code"),
        Command::Join(_) => not_yet_built("anago join"),
        Command::Ls => not_yet_built("anago ls"),
        Command::Rm(_) => not_yet_built("anago rm"),
    }
}

/// An M0 command that routes and validates but has no implementation
/// behind it yet. Distinct from `CliError::NotYet`, which is a settled
/// answer about a later milestone.
fn not_yet_built(command: &str) -> ! {
    eprintln!("anago: {command} is not implemented yet — M0 is still being built");
    eprintln!("the command line was accepted; docs/DESIGN.md §11 has what lands when");
    std::process::exit(EXIT_FAILED);
}
