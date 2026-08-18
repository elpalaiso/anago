//! anago CLI — dispatch skeleton. The M0 subcommands (DESIGN.md §8)
//! land in the next slice; this proves the flag parser on the two
//! global flags and keeps the usage line honest.

// Value flags and `require` are exercised by the parser's own tests;
// the subcommands that use them land in the next slice, so the module
// is allowed to be ahead of its callers until then.
#[allow(dead_code)]
mod args;

use args::{Flag, ParsedArgs};

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let spec = [
        Flag::boolean("help").short('h'),
        Flag::boolean("version").short('V'),
    ];

    match ParsedArgs::parse(&argv, &spec) {
        Ok(parsed) if parsed.is_set("version") => {
            println!("anago {}", env!("CARGO_PKG_VERSION"));
        }
        Ok(parsed) if parsed.is_set("help") || parsed.positionals().is_empty() => {
            print_usage();
        }
        Ok(_) => {
            eprintln!("anago: subcommands are not wired up yet — see docs/DESIGN.md §8");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("anago: {e}");
            print_usage();
            std::process::exit(2);
        }
    }
}

/// The M0 surface (§8). Flags a subcommand takes are declared with the
/// subcommand, so they show up here as the next slice adds them.
fn print_usage() {
    eprintln!(
        "\
anago {version} — self-hosted WireGuard private network

usage:
  anago server init --domain <d> --tls-cert <p> --tls-key <p>
  anago code
  anago join <domain> <code> [--name <name>]
  anago ls
  anago rm <name>

  -h, --help       show this
  -V, --version    show the version",
        version = env!("CARGO_PKG_VERSION")
    );
}
