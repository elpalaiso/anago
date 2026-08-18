//! Command routing (DESIGN.md §8) — argv in, a typed [`Command`] out.
//!
//! Pure: this module resolves what the user asked for and turns the
//! strings into core types, but runs nothing. `main` executes what it
//! gets back, which is what lets every routing rule below be a unit
//! test.
//!
//! Commands that belong to a later milestone are routed too, into
//! [`CliError::NotYet`]. A person who read the design doc and typed
//! `anago sync` deserves "M1, and here is why you do not need it yet"
//! rather than "unknown command".

use anago_core::code::JoinCode;
use anago_core::name::DeviceName;
use anago_core::subnet::Subnet;
use std::fmt;

use crate::args::{ArgError, Flag, ParsedArgs};

/// Defaults from §5 and §8, applied when the flag is absent.
pub const DEFAULT_SUBNET: &str = "10.100.0.0/24";
pub const DEFAULT_LISTEN_PORT: u16 = 51820;
pub const DEFAULT_API_PORT: u16 = 443;

/// What the user asked anago to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    ServerInit(ServerInit),
    /// The resident process (§8). systemd runs this; a person only
    /// types it after `server init --no-systemd`.
    ServerRun,
    Code,
    Join(Join),
    Ls,
    Rm(Rm),
    /// `--help`, or no arguments at all. Carries the topic when one was
    /// named: `anago help join`.
    Help(Option<String>),
    Version,
}

/// `anago server init` (§8, M0: manual DNS, existing certificate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInit {
    pub domain: String,
    pub tls_cert: String,
    pub tls_key: String,
    pub subnet: Subnet,
    pub listen_port: u16,
    pub api_port: u16,
    /// False when `--no-systemd` asked for a foreground run.
    pub systemd: bool,
}

/// `anago join <domain> <code>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Join {
    pub domain: String,
    pub code: JoinCode,
    /// `None` means the client fills in this machine's hostname.
    pub name: Option<DeviceName>,
}

/// `anago rm <name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rm {
    pub name: DeviceName,
}

/// Routes a command line. `argv` excludes the program name.
pub fn parse(argv: &[String]) -> Result<Command, CliError> {
    if let Some(command) = help_or_version(argv) {
        return Ok(command);
    }

    let (head, rest) = argv.split_first().expect("argv is not empty");
    match head.as_str() {
        "server" => server(rest),
        "code" => no_args("code", rest),
        "join" => join(rest),
        "ls" => no_args("ls", rest),
        "rm" => rm(rest),
        "help" => Ok(Command::Help(rest.first().cloned())),
        "sync" => Err(CliError::NotYet {
            what: "anago sync",
            milestone: "M1",
            because: "the hub already knows every peer, so M0 devices stay reachable without it",
        }),
        "ping" => Err(CliError::NotYet {
            what: "anago ping",
            milestone: "M3",
            because: "name resolution lands with it — use the private address from `anago ls`",
        }),
        other => Err(CliError::UnknownCommand(other.to_string())),
    }
}

/// `--help`/`--version` anywhere on the line, and an empty line, are
/// answered before any command-specific parsing.
///
/// This scans the raw arguments rather than parsing them, because
/// parsing needs to know the command first: `anago server init --domain
/// net.example.com --help` must reach the help text, not fail on a
/// `--help` the init parser was never told about.
///
/// Scanning stops at `--`, so `anago rm -- --help` still means a device
/// literally called `--help`.
fn help_or_version(argv: &[String]) -> Option<Command> {
    let mut topic = None;
    let mut wants_help = argv.is_empty();

    for arg in argv {
        let arg = arg.as_str();
        if arg == "--" {
            break;
        }
        match arg {
            "--version" | "-V" => return Some(Command::Version),
            "--help" | "-h" => wants_help = true,
            _ => {
                if topic.is_none() && !arg.starts_with('-') {
                    topic = Some(arg.to_string());
                }
            }
        }
    }

    wants_help.then(|| {
        // `anago help join` names its topic; `anago help` alone does not.
        let topic = match topic.as_deref() {
            Some("help") => argv.iter().map(String::as_str).find(|arg| *arg != "help"),
            other => other,
        };
        Command::Help(topic.map(str::to_string))
    })
}

fn server(argv: &[String]) -> Result<Command, CliError> {
    match argv.split_first() {
        None => Err(CliError::MissingSubcommand("server")),
        Some((head, rest)) => match head.as_str() {
            "init" => server_init(rest),
            "run" => no_args("server run", rest).map(|_| Command::ServerRun),
            "status" => Err(CliError::NotYet {
                what: "anago server status",
                milestone: "M3",
                because: "`anago ls` on the server already shows peers and handshakes",
            }),
            other => Err(CliError::UnknownCommand(format!("server {other}"))),
        },
    }
}

fn server_init(argv: &[String]) -> Result<Command, CliError> {
    let spec = [
        Flag::value("domain"),
        Flag::value("tls-cert"),
        Flag::value("tls-key"),
        Flag::value("subnet"),
        Flag::value("port"),
        Flag::value("api-port"),
        Flag::boolean("no-systemd"),
        // Routed so the M1 answer is specific; §8 keeps it out of M0.
        Flag::value("cf-token"),
    ];
    let parsed = ParsedArgs::parse(argv, &spec)?;
    reject_extra_positionals(&parsed, "server init")?;

    if parsed.is_set("cf-token") {
        return Err(CliError::NotYet {
            what: "--cf-token",
            milestone: "M1",
            because: "M0 asks you to add the DNS record and pass --tls-cert/--tls-key yourself",
        });
    }

    let domain = domain(parsed.require("domain")?)?;
    let subnet = match parsed.value("subnet") {
        Some(text) => text,
        None => DEFAULT_SUBNET,
    };
    let subnet = Subnet::parse(subnet).map_err(|e| CliError::BadValue {
        flag: "subnet",
        message: e.to_string(),
    })?;

    Ok(Command::ServerInit(ServerInit {
        domain,
        tls_cert: parsed.require("tls-cert")?.to_string(),
        tls_key: parsed.require("tls-key")?.to_string(),
        subnet,
        listen_port: port(&parsed, "port", DEFAULT_LISTEN_PORT)?,
        api_port: port(&parsed, "api-port", DEFAULT_API_PORT)?,
        systemd: !parsed.is_set("no-systemd"),
    }))
}

fn join(argv: &[String]) -> Result<Command, CliError> {
    let spec = [Flag::value("name"), Flag::value("export")];
    let parsed = ParsedArgs::parse(argv, &spec)?;

    if parsed.is_set("export") {
        return Err(CliError::NotYet {
            what: "--export",
            milestone: "M1",
            because: "phones join through the official WireGuard app once it can emit a config",
        });
    }

    let positionals = parsed.positionals();
    let (host, code) = match positionals {
        [host, code] => (host, code),
        [] => return Err(CliError::MissingArgument("join", "<domain> <code>")),
        [_] => return Err(CliError::MissingArgument("join", "<code>")),
        _ => return Err(CliError::TooManyArguments("join")),
    };

    let name = match parsed.value("name") {
        Some(text) => Some(DeviceName::parse(text).map_err(|e| CliError::BadValue {
            flag: "name",
            message: e.to_string(),
        })?),
        None => None,
    };

    Ok(Command::Join(Join {
        domain: domain(host)?,
        code: JoinCode::parse(code).map_err(|e| CliError::BadArgument {
            what: "join code",
            message: e.to_string(),
        })?,
        name,
    }))
}

fn rm(argv: &[String]) -> Result<Command, CliError> {
    let parsed = ParsedArgs::parse(argv, &[])?;
    let name = match parsed.positionals() {
        [name] => name,
        [] => return Err(CliError::MissingArgument("rm", "<name>")),
        _ => return Err(CliError::TooManyArguments("rm")),
    };
    Ok(Command::Rm(Rm {
        name: DeviceName::parse(name).map_err(|e| CliError::BadArgument {
            what: "device name",
            message: e.to_string(),
        })?,
    }))
}

fn no_args(name: &'static str, argv: &[String]) -> Result<Command, CliError> {
    let parsed = ParsedArgs::parse(argv, &[])?;
    if !parsed.positionals().is_empty() {
        return Err(CliError::TooManyArguments(name));
    }
    Ok(match name {
        "code" => Command::Code,
        "ls" => Command::Ls,
        // `server run` maps itself; this arm only reports the shape.
        "server run" => Command::ServerRun,
        other => unreachable!("no_args called for {other}"),
    })
}

fn reject_extra_positionals(parsed: &ParsedArgs, command: &'static str) -> Result<(), CliError> {
    if parsed.positionals().is_empty() {
        Ok(())
    } else {
        Err(CliError::TooManyArguments(command))
    }
}

fn port(parsed: &ParsedArgs, flag: &'static str, default: u16) -> Result<u16, CliError> {
    match parsed.value(flag) {
        None => Ok(default),
        Some(text) => match text.parse::<u16>() {
            // 0 parses but means "any free port" to the OS, which is
            // the one thing a hub cannot be: nothing could dial it.
            Ok(0) | Err(_) => Err(CliError::BadValue {
                flag,
                message: format!("{text:?} is not a port number (1-65535)"),
            }),
            Ok(port) => Ok(port),
        },
    }
}

/// A bare hostname, which is what both the DNS record and the TLS
/// certificate are about. A pasted URL is the likely mistake, so it is
/// named rather than passed through to fail later at connect time.
fn domain(text: &str) -> Result<String, CliError> {
    let bad = |message: &str| CliError::BadArgument {
        what: "domain",
        message: message.to_string(),
    };
    if text.contains("://") {
        return Err(bad("give the hostname only, without https://"));
    }
    if text.contains('/') {
        return Err(bad("give the hostname only, without a path"));
    }
    if text.contains(':') {
        return Err(bad("give the hostname only, without a port"));
    }
    if text.chars().any(char::is_whitespace) {
        return Err(bad("a domain cannot contain spaces"));
    }
    if !text.contains('.') {
        return Err(bad("expected a full domain, e.g. net.example.com"));
    }
    Ok(text.to_string())
}

/// Why a command line did not resolve to something anago can run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// Flag-level problem, from the parser.
    Arg(ArgError),
    UnknownCommand(String),
    /// `anago server` with nothing after it.
    MissingSubcommand(&'static str),
    /// A positional the command cannot run without.
    MissingArgument(&'static str, &'static str),
    TooManyArguments(&'static str),
    /// A flag's value did not pass the rules of its type.
    BadValue {
        flag: &'static str,
        message: String,
    },
    /// A positional's value did not.
    BadArgument {
        what: &'static str,
        message: String,
    },
    /// Real, designed, and not in this milestone.
    NotYet {
        what: &'static str,
        milestone: &'static str,
        because: &'static str,
    },
}

impl From<ArgError> for CliError {
    fn from(e: ArgError) -> CliError {
        CliError::Arg(e)
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Arg(e) => write!(f, "{e}"),
            CliError::UnknownCommand(name) => write!(f, "unknown command {name:?}"),
            CliError::MissingSubcommand(command) => {
                write!(f, "`anago {command}` needs a subcommand")
            }
            CliError::MissingArgument(command, what) => {
                write!(f, "`anago {command}` needs {what}")
            }
            CliError::TooManyArguments(command) => {
                write!(f, "`anago {command}` got more arguments than it takes")
            }
            CliError::BadValue { flag, message } => write!(f, "--{flag}: {message}"),
            CliError::BadArgument { what, message } => write!(f, "{what}: {message}"),
            CliError::NotYet {
                what,
                milestone,
                because,
            } => write!(f, "{what} arrives in {milestone} — {because}"),
        }
    }
}

impl std::error::Error for CliError {}

/// Exit code for a routing failure: 1 for "understood, cannot do it",
/// 2 for "did not understand". `anago sync` is recognized and refused
/// on purpose, so it is a failure, not a usage error.
pub fn exit_code(error: &CliError) -> i32 {
    match error {
        CliError::NotYet { .. } => 1,
        _ => 2,
    }
}

/// Usage text. With a topic, the one command; without, the M0 surface.
pub fn help(topic: Option<&str>) -> String {
    let version = env!("CARGO_PKG_VERSION");
    match topic {
        Some("server") | Some("init") => format!(
            "\
usage: anago server init --domain <d> --tls-cert <path> --tls-key <path>
                        [--subnet {DEFAULT_SUBNET}] [--port {DEFAULT_LISTEN_PORT}]
                        [--api-port {DEFAULT_API_PORT}] [--no-systemd]

Sets up the hub on this machine: generates its wg keypair, writes the
state file, prints the DNS record to add and the ports to open, then
issues the first join code.

M0 takes an existing certificate; ACME and Cloudflare DNS arrive in M1.
"
        ),
        Some("join") => format!(
            "\
usage: anago join <domain> <code> [--name <name>]

Registers this device with the hub at <domain>. The wg keypair is made
here and the private key never leaves — the server sees the public half
only. Without --name the machine's hostname is used.

Join codes are single use and expire; ask the server for another with
`anago code`. Format: {code}
",
            code = "XXXX-XXXX"
        ),
        Some("code") => "\
usage: anago code

Run on the server. Issues a join code, prints the exact `anago join`
line to run on the new device, and stores the code in the state file.
"
        .to_string(),
        Some("ls") => "\
usage: anago ls

Lists registered devices. On the server it also shows when each device
last completed a handshake; over the API that column reads as unknown.
"
        .to_string(),
        Some("rm") => "\
usage: anago rm <name>

Removes a device. Its address returns to the pool and its token stops
working immediately.
"
        .to_string(),
        _ => format!(
            "\
anago {version} — self-hosted WireGuard private network

usage:
  anago server init --domain <d> --tls-cert <path> --tls-key <path>
  anago server run                  run the hub (systemd does this for you)
  anago code                        issue a join code (on the server)
  anago join <domain> <code>        register this device
  anago ls                          list devices
  anago rm <name>                   remove a device

  -h, --help                        show this, or `anago help <command>`
  -V, --version                     show the version

Later milestones: `anago sync` (M1), `--export qr|conf` (M1),
`anago ping` and `anago server status` (M3).
"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str]) -> Result<Command, CliError> {
        let argv: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
        parse(&argv)
    }

    fn init(args: &[&str]) -> Result<ServerInit, CliError> {
        match parse_args(args)? {
            Command::ServerInit(init) => Ok(init),
            other => panic!("expected server init, got {other:?}"),
        }
    }

    const REQUIRED: [&str; 7] = [
        "server",
        "init",
        "--domain",
        "net.example.com",
        "--tls-cert",
        "/etc/ssl/anago/fullchain.pem",
        "--tls-key",
        // one more below so the array length is a compile-time check
    ];

    fn required_init() -> Vec<&'static str> {
        let mut args = REQUIRED.to_vec();
        args.push("/etc/ssl/anago/privkey.pem");
        args
    }

    #[test]
    fn server_init_fills_in_the_documented_defaults() {
        let init = init(&required_init()).unwrap();
        assert_eq!(init.domain, "net.example.com");
        assert_eq!(init.tls_cert, "/etc/ssl/anago/fullchain.pem");
        assert_eq!(init.tls_key, "/etc/ssl/anago/privkey.pem");
        assert_eq!(init.subnet, Subnet::parse(DEFAULT_SUBNET).unwrap());
        assert_eq!(init.listen_port, 51820);
        assert_eq!(init.api_port, 443);
        assert!(init.systemd);
    }

    #[test]
    fn server_init_takes_the_overrides() {
        let mut args = required_init();
        args.extend([
            "--subnet",
            "192.168.7.0/24",
            "--port",
            "51999",
            "--api-port",
            "8443",
            "--no-systemd",
        ]);
        let init = init(&args).unwrap();
        assert_eq!(init.subnet, Subnet::parse("192.168.7.0/24").unwrap());
        assert_eq!(init.listen_port, 51999);
        assert_eq!(init.api_port, 8443);
        assert!(!init.systemd);
    }

    #[test]
    fn server_init_insists_on_what_m0_cannot_invent() {
        // No ACME yet, so the certificate paths are not optional.
        assert_eq!(
            parse_args(&["server", "init"]),
            Err(CliError::Arg(ArgError::Required("domain")))
        );
        assert_eq!(
            parse_args(&["server", "init", "--domain", "net.example.com"]),
            Err(CliError::Arg(ArgError::Required("tls-cert")))
        );
        assert_eq!(
            parse_args(&[
                "server",
                "init",
                "--domain",
                "net.example.com",
                "--tls-cert",
                "/c.pem"
            ]),
            Err(CliError::Arg(ArgError::Required("tls-key")))
        );
    }

    #[test]
    fn bad_values_are_caught_before_anything_runs() {
        let mut args = required_init();
        args.extend(["--subnet", "10.100.0.0/16"]);
        assert_eq!(
            init(&args),
            Err(CliError::BadValue {
                flag: "subnet",
                message: "anago supports /24 only, got /16".to_string(),
            })
        );

        let mut args = required_init();
        args.extend(["--port", "70000"]);
        assert!(matches!(
            init(&args),
            Err(CliError::BadValue { flag: "port", .. })
        ));

        let mut args = required_init();
        args.extend(["--api-port", "https"]);
        assert!(matches!(
            init(&args),
            Err(CliError::BadValue {
                flag: "api-port",
                ..
            })
        ));
    }

    #[test]
    fn a_pasted_url_is_named_as_the_mistake() {
        for (domain, expected) in [
            ("https://net.example.com", "without https://"),
            ("net.example.com/api", "without a path"),
            ("net.example.com:443", "without a port"),
            ("net example com", "cannot contain spaces"),
            ("localhost", "e.g. net.example.com"),
        ] {
            let args = vec![
                "server",
                "init",
                "--domain",
                domain,
                "--tls-cert",
                "/c.pem",
                "--tls-key",
                "/k.pem",
            ];
            let e = parse_args(&args).unwrap_err();
            assert!(e.to_string().contains(expected), "{domain}: {e}");
        }
    }

    #[test]
    fn join_takes_a_domain_and_a_code() {
        let command = parse_args(&["join", "net.example.com", "7qx4-m2kd"]).unwrap();
        assert_eq!(
            command,
            Command::Join(Join {
                domain: "net.example.com".to_string(),
                // Normalized on the way in, so the server sees one form.
                code: JoinCode::parse("7QX4-M2KD").unwrap(),
                name: None,
            })
        );

        let command = parse_args(&["join", "net.example.com", "7QX4-M2KD", "--name", "맥북"]);
        assert_eq!(
            command.unwrap(),
            Command::Join(Join {
                domain: "net.example.com".to_string(),
                code: JoinCode::parse("7QX4-M2KD").unwrap(),
                name: Some(DeviceName::parse("맥북").unwrap()),
            })
        );
    }

    #[test]
    fn join_reports_what_is_missing_or_malformed() {
        assert_eq!(
            parse_args(&["join"]),
            Err(CliError::MissingArgument("join", "<domain> <code>"))
        );
        assert_eq!(
            parse_args(&["join", "net.example.com"]),
            Err(CliError::MissingArgument("join", "<code>"))
        );
        assert_eq!(
            parse_args(&["join", "net.example.com", "7QX4-M2KD", "extra"]),
            Err(CliError::TooManyArguments("join"))
        );
        assert!(matches!(
            parse_args(&["join", "net.example.com", "OOOO-OOOO"]),
            Err(CliError::BadArgument {
                what: "join code",
                ..
            })
        ));
        assert!(matches!(
            parse_args(&["join", "net.example.com", "7QX4-M2KD", "--name", "my mac"]),
            Err(CliError::BadValue { flag: "name", .. })
        ));
    }

    #[test]
    fn the_argument_free_commands_take_no_arguments() {
        assert_eq!(parse_args(&["code"]), Ok(Command::Code));
        assert_eq!(parse_args(&["ls"]), Ok(Command::Ls));
        assert_eq!(
            parse_args(&["code", "now"]),
            Err(CliError::TooManyArguments("code"))
        );
        assert_eq!(
            parse_args(&["ls", "all"]),
            Err(CliError::TooManyArguments("ls"))
        );
    }

    #[test]
    fn rm_takes_exactly_one_name() {
        assert_eq!(
            parse_args(&["rm", "MacBook"]),
            Ok(Command::Rm(Rm {
                name: DeviceName::parse("macbook").unwrap()
            }))
        );
        assert_eq!(
            parse_args(&["rm"]),
            Err(CliError::MissingArgument("rm", "<name>"))
        );
        assert_eq!(
            parse_args(&["rm", "macbook", "desktop"]),
            Err(CliError::TooManyArguments("rm"))
        );
        assert!(matches!(
            parse_args(&["rm", "server"]),
            Err(CliError::BadArgument {
                what: "device name",
                ..
            })
        ));
        // `--` keeps a device whose name starts with a dash reachable.
        assert!(parse_args(&["rm", "--", "x-1"]).is_ok());
    }

    #[test]
    fn server_run_is_routed_for_systemd_and_for_no_systemd_users() {
        assert_eq!(parse_args(&["server", "run"]), Ok(Command::ServerRun));
        assert_eq!(
            parse_args(&["server", "run", "now"]),
            Err(CliError::TooManyArguments("server run"))
        );
        assert!(cli_help_mentions("anago server run"));
    }

    fn cli_help_mentions(text: &str) -> bool {
        help(None).contains(text)
    }

    #[test]
    fn later_milestones_answer_with_their_milestone() {
        for (args, what, milestone) in [
            (vec!["sync"], "anago sync", "M1"),
            (vec!["ping", "macbook"], "anago ping", "M3"),
            (vec!["server", "status"], "anago server status", "M3"),
        ] {
            match parse_args(&args) {
                Err(CliError::NotYet {
                    what: got,
                    milestone: got_milestone,
                    ..
                }) => {
                    assert_eq!(got, what);
                    assert_eq!(got_milestone, milestone);
                }
                other => panic!("{args:?} routed to {other:?}"),
            }
        }
    }

    #[test]
    fn later_flags_answer_the_same_way() {
        let mut args = required_init();
        args.extend(["--cf-token", "secret"]);
        let e = parse_args(&args).unwrap_err();
        assert!(e.to_string().starts_with("--cf-token arrives in M1"), "{e}");

        let e =
            parse_args(&["join", "net.example.com", "7QX4-M2KD", "--export", "qr"]).unwrap_err();
        assert!(e.to_string().starts_with("--export arrives in M1"), "{e}");
    }

    #[test]
    fn unknown_commands_are_named_not_guessed() {
        assert_eq!(
            parse_args(&["status"]),
            Err(CliError::UnknownCommand("status".to_string()))
        );
        assert_eq!(
            parse_args(&["server", "start"]),
            Err(CliError::UnknownCommand("server start".to_string()))
        );
        assert_eq!(
            parse_args(&["server"]),
            Err(CliError::MissingSubcommand("server"))
        );
    }

    #[test]
    fn help_and_version_win_wherever_they_appear() {
        assert_eq!(parse_args(&["--version"]), Ok(Command::Version));
        assert_eq!(parse_args(&["-V"]), Ok(Command::Version));
        assert_eq!(parse_args(&[]), Ok(Command::Help(None)));
        assert_eq!(parse_args(&["--help"]), Ok(Command::Help(None)));
        assert_eq!(
            parse_args(&["join", "--help"]),
            Ok(Command::Help(Some("join".to_string())))
        );
        assert_eq!(
            parse_args(&["help", "rm"]),
            Ok(Command::Help(Some("rm".to_string())))
        );
        // Even when the rest of the line is nonsense.
        assert_eq!(
            parse_args(&["server", "init", "--help"]),
            Ok(Command::Help(Some("server".to_string())))
        );
    }

    #[test]
    fn help_wins_after_command_flags_too() {
        // Regression: the help scan runs before command parsing, so a
        // line that is otherwise valid still reaches the help text.
        assert_eq!(
            parse_args(&["server", "init", "--domain", "net.example.com", "--help"]),
            Ok(Command::Help(Some("server".to_string())))
        );
        assert_eq!(
            parse_args(&[
                "join",
                "net.example.com",
                "7QX4-M2KD",
                "--name",
                "맥북",
                "-h"
            ]),
            Ok(Command::Help(Some("join".to_string())))
        );
        // Even when the line would otherwise be an error.
        assert_eq!(
            parse_args(&["server", "init", "--domain", "--help"]),
            Ok(Command::Help(Some("server".to_string())))
        );
        assert_eq!(
            parse_args(&["rm", "--nope", "--help"]),
            Ok(Command::Help(Some("rm".to_string())))
        );
        // Version wins over help, wherever both appear.
        assert_eq!(
            parse_args(&["server", "init", "--help", "-V"]),
            Ok(Command::Version)
        );
    }

    #[test]
    fn a_device_named_like_a_flag_is_still_removable() {
        // After `--`, `--help` is a name, not a request for help.
        assert!(matches!(
            parse_args(&["rm", "--", "--help"]),
            Err(CliError::BadArgument { .. })
        ));
        assert_eq!(
            parse_args(&["rm", "--", "x-1"]),
            Ok(Command::Rm(Rm {
                name: DeviceName::parse("x-1").unwrap()
            }))
        );
    }

    #[test]
    fn port_zero_is_not_a_port() {
        // It parses as u16 but means "any free port" to the OS, which
        // is the one thing a hub cannot be.
        for flag in ["--port", "--api-port"] {
            let mut args = required_init();
            args.extend([flag, "0"]);
            let e = parse_args(&args).unwrap_err();
            assert!(e.to_string().contains("1-65535"), "{flag}: {e}");
        }
        // The rest of the range still works.
        let mut args = required_init();
        args.extend(["--port", "1", "--api-port", "65535"]);
        let init = init(&args).unwrap();
        assert_eq!((init.listen_port, init.api_port), (1, 65535));
    }

    #[test]
    fn recognized_but_unbuilt_commands_are_not_usage_errors() {
        // `anago sync` was understood and refused on purpose; a typo
        // was not understood at all.
        assert_eq!(exit_code(&parse_args(&["sync"]).unwrap_err()), 1);
        assert_eq!(exit_code(&parse_args(&["ping", "macbook"]).unwrap_err()), 1);
        assert_eq!(
            exit_code(&parse_args(&["server", "status"]).unwrap_err()),
            1
        );
        assert_eq!(exit_code(&parse_args(&["snyc"]).unwrap_err()), 2);
        assert_eq!(exit_code(&parse_args(&["rm"]).unwrap_err()), 2);
        assert_eq!(
            exit_code(&parse_args(&["rm", "--force", "x"]).unwrap_err()),
            2
        );
    }

    #[test]
    fn help_text_covers_every_m0_command() {
        let general = help(None);
        for command in ["server init", "code", "join", "ls", "rm"] {
            assert!(general.contains(command), "general help omits {command}");
        }
        // And says where the rest went.
        assert!(general.contains("M1"), "{general}");
        assert!(general.contains("M3"), "{general}");

        for topic in ["server", "join", "code", "ls", "rm"] {
            let text = help(Some(topic));
            assert!(text.starts_with("usage: anago "), "{topic}: {text}");
        }
        // An unknown topic falls back to the overview rather than
        // printing nothing.
        assert_eq!(help(Some("nope")), general);
    }

    #[test]
    fn flag_errors_pass_through_with_their_own_wording() {
        assert_eq!(
            parse_args(&["rm", "--force", "macbook"]),
            Err(CliError::Arg(ArgError::Unknown("--force".to_string())))
        );
        let mut args = required_init();
        args.extend(["--subnet", "10.100.0.0/24", "--subnet", "10.0.0.0/24"]);
        assert_eq!(
            parse_args(&args),
            Err(CliError::Arg(ArgError::Duplicate("subnet")))
        );
    }
}
