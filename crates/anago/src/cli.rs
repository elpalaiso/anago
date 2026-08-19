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

use std::path::{Path, PathBuf};
use std::time::Duration;

use anago_core::code::JoinCode;
use anago_core::name::DeviceName;
use anago_core::state::Challenge;
use anago_core::subnet::Subnet;
use std::fmt;

use crate::acme::{self, PlanError};
use crate::args::{ArgError, Flag, ParsedArgs};
use crate::cfapi::{self, CfError, Source, Token};

/// Defaults from §5 and §8, applied when the flag is absent.
pub const DEFAULT_SUBNET: &str = "10.100.0.0/24";
pub const DEFAULT_LISTEN_PORT: u16 = 51820;
pub const DEFAULT_API_PORT: u16 = 443;

/// What the user asked anago to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    ServerInit(ServerInit),
    /// `anago server renew` (§8): a certificate again, settings
    /// changed, or just the A record.
    ServerRenew(ServerRenew),
    /// The resident process (§8). systemd runs this; a person only
    /// types it after `server init --no-systemd`.
    ServerRun,
    /// `anago sync` (§8): on a device, pull the peer list — or install
    /// the timer that does.
    Sync(Sync),
    Code,
    Join(Join),
    Ls,
    Rm(Rm),
    /// `--help`, or no arguments at all. Carries the topic when one was
    /// named: `anago help join`.
    Help(Option<String>),
    Version,
}

/// `anago server init` (§8).
///
/// The certificate flags are optional in M1 and that is the whole
/// fork: given, this is M0's manual path and ACME never runs; left out,
/// anago orders and renews the certificate itself. Routing keeps them
/// as they were typed rather than resolving the fork, because the
/// answer also depends on the environment — see [`check_combination`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInit {
    pub domain: String,
    /// `--tls-cert`/`--tls-key`. Both or neither.
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    /// `--acme-email` — the address the CA warns before an expiry, and
    /// the only alarm that reaches a person when renewal has quietly
    /// stopped working (§8).
    pub acme_email: Option<String>,
    /// `--acme-staging`: order from Let's Encrypt's staging CA, whose
    /// certificates are not publicly trusted.
    pub acme_staging: bool,
    /// `--acme-challenge`. `None` means "decide from whether there is
    /// a token", which routing cannot know.
    pub acme_challenge: Option<Challenge>,
    /// `--cf-token`. Parsed here so a truncated paste is caught before
    /// anything is generated, and redacted in `Debug` (§13).
    pub cf_token: Option<Token>,
    /// `--cf-token-file`, the form that keeps the secret out of argv.
    pub cf_token_file: Option<String>,
    pub subnet: Subnet,
    pub listen_port: u16,
    pub api_port: u16,
    /// False when `--no-systemd` asked for a foreground run.
    pub systemd: bool,
}

/// `anago server renew` (§8).
///
/// Every field is "what was asked for", never "what the hub should end
/// up with": a flag left out means *leave that alone*, which is why
/// they are all optional and why the CA is a tri-state rather than a
/// `bool`. Reading an absent `--acme-staging` as "production" would
/// move a hub to a different CA on an ordinary renewal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerRenew {
    /// Re-issue even though the certificate is not due.
    pub force: bool,
    /// Push the A record and stop.
    pub dns_only: bool,
    /// `--acme-staging` / `--acme-production`, or neither.
    pub ca: Option<Ca>,
    pub acme_email: Option<String>,
    pub acme_challenge: Option<Challenge>,
    pub cf_token: Option<Token>,
    pub cf_token_file: Option<String>,
}

/// Which CA the hub should order from after this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ca {
    Staging,
    Production,
}

/// `anago sync` (§8, §6.3).
///
/// Three shapes in one command: sync now, install the timer that syncs,
/// or take that timer away. `timer` is what tells them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sync {
    /// `--quiet` — for the timer, which is why it is on the unit's
    /// command line rather than sniffed from a tty (§8). Reading a
    /// unit file should say why it is quiet.
    pub quiet: bool,
    /// `--config <path>`, the escape hatch from §9's XDG/`SUDO_UID`
    /// rules — and the reason a timer can exist at all, since a unit
    /// runs as root outside any user session.
    pub config: Option<PathBuf>,
    pub timer: Option<Timer>,
}

/// What to do about periodic runs (§8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timer {
    Install { interval: Duration },
    Uninstall,
}

/// The default period (§6.3): most changes ask nothing of a client,
/// and a removed device stops being routed the moment the hub drops the
/// peer — so a late sync is late *news*, not late traffic.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Below this a timer costs more than it delivers and hammers the hub's
/// API for nothing.
pub const MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Above this the timer stops being a timer. A device that syncs once a
/// day is one whose peer list is a day stale, and §6.3's promise is
/// that the list is roughly current.
pub const MAX_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// `anago join <domain> <code>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Join {
    pub domain: String,
    pub code: JoinCode,
    /// `None` means the client fills in this machine's hostname.
    pub name: Option<DeviceName>,
    /// Control-API port. Must match the hub's `--api-port`, which is
    /// why it is a flag and not a guess.
    pub api_port: u16,
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
        "sync" => sync(rest),
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
            "renew" => server_renew(rest),
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
        Flag::value("acme-email"),
        Flag::boolean("acme-staging"),
        Flag::value("acme-challenge"),
        Flag::value("cf-token"),
        Flag::value("cf-token-file"),
    ];
    let parsed = ParsedArgs::parse(argv, &spec)?;
    reject_extra_positionals(&parsed, "server init")?;

    let subnet = match parsed.value("subnet") {
        Some(text) => text,
        None => DEFAULT_SUBNET,
    };
    let subnet = Subnet::parse(subnet).map_err(|e| CliError::BadValue {
        flag: "subnet",
        message: e.to_string(),
    })?;

    let init = ServerInit {
        domain: domain(parsed.require("domain")?)?,
        tls_cert: parsed.value("tls-cert").map(str::to_string),
        tls_key: parsed.value("tls-key").map(str::to_string),
        acme_email: parsed.value("acme-email").map(str::to_string),
        acme_staging: parsed.is_set("acme-staging"),
        acme_challenge: challenge(&parsed)?,
        cf_token: token(&parsed)?,
        cf_token_file: parsed.value("cf-token-file").map(str::to_string),
        subnet,
        listen_port: port(&parsed, "port", DEFAULT_LISTEN_PORT)?,
        api_port: port(&parsed, "api-port", DEFAULT_API_PORT)?,
        systemd: !parsed.is_set("no-systemd"),
    };
    check_combination(&init)?;
    Ok(Command::ServerInit(init))
}

/// `--acme-challenge http-01|dns-01`.
///
/// The spelling is the one the state file uses, so what a person types
/// and what `anago server status` will print are the same string.
fn challenge(parsed: &ParsedArgs) -> Result<Option<Challenge>, CliError> {
    match parsed.value("acme-challenge") {
        None => Ok(None),
        Some(text) => match Challenge::parse(text) {
            Some(challenge) => Ok(Some(challenge)),
            None => Err(CliError::BadValue {
                flag: "acme-challenge",
                message: format!(
                    "{text:?} is not a challenge — expected {} or {}",
                    Challenge::Http01.as_str(),
                    Challenge::Dns01.as_str()
                ),
            }),
        },
    }
}

/// `--cf-token <t>`, checked here rather than at first use.
///
/// A token truncated by a copy-paste is a command line that is wrong
/// the moment it is typed, and the alternative is finding out from a
/// 401 halfway through a setup — which reads as a permissions problem
/// rather than a typo.
fn token(parsed: &ParsedArgs) -> Result<Option<Token>, CliError> {
    match parsed.value("cf-token") {
        None => Ok(None),
        Some(text) => Token::parse(text, Source::Flag)
            .map(Some)
            .map_err(CliError::Token),
    }
}

/// The combination rules for `server init` (§8) that argv can settle.
///
/// **Not one of them is written out here.** They belong to the two pure
/// functions that already own them and are already tested against the
/// design — [`cfapi::choose`] for the two token flags, [`acme::plan`]
/// for the fork between a certificate you have and one anago orders.
/// Routing calls those so that a combination which cannot work is
/// refused before anything is generated, and so that the sentence a
/// person reads is the same wherever the check happens to run.
///
/// The plan itself is thrown away: `init` makes it again with the
/// environment in hand, and that is the copy that decides anything.
/// This call is here for the refusals.
///
/// One rule is deliberately **not** settled here. `--acme-challenge
/// dns-01` needs a Cloudflare token, and a token can still arrive from
/// `CLOUDFLARE_API_TOKEN` — which routing does not read, because not
/// reading it is what keeps every rule in this module a unit test. So
/// that verdict is left to `init`, which has the environment and runs
/// the same function.
fn check_combination(init: &ServerInit) -> Result<(), CliError> {
    let token = cfapi::choose(
        init.cf_token_file.as_deref(),
        init.cf_token.as_ref().map(Token::expose),
        None,
    )
    .map_err(CliError::Token)?;

    match acme::plan(&acme::Request {
        tls_cert: init.tls_cert.as_deref(),
        tls_key: init.tls_key.as_deref(),
        acme_email: init.acme_email.as_deref(),
        staging: init.acme_staging,
        challenge: init.acme_challenge,
        token: token.as_ref(),
    }) {
        Ok(_) => Ok(()),
        Err(PlanError::Dns01WithoutToken) => Ok(()),
        Err(e) => Err(CliError::Plan(e)),
    }
}

fn server_renew(argv: &[String]) -> Result<Command, CliError> {
    let spec = [
        Flag::boolean("force"),
        Flag::boolean("dns"),
        Flag::boolean("acme-staging"),
        Flag::boolean("acme-production"),
        Flag::value("acme-email"),
        Flag::value("acme-challenge"),
        Flag::value("cf-token"),
        Flag::value("cf-token-file"),
    ];
    let parsed = ParsedArgs::parse(argv, &spec)?;
    reject_extra_positionals(&parsed, "server renew")?;

    // Both, or neither. `init` has no pair because production is the
    // default there and `--acme-staging` is a plain opt-in; here the
    // flag has to overwrite a value the hub already has, so the other
    // direction needs a way to be said (§8).
    let ca = match (
        parsed.is_set("acme-staging"),
        parsed.is_set("acme-production"),
    ) {
        (true, true) => {
            return Err(CliError::Contradiction(
                "--acme-staging",
                "--acme-production",
            ))
        }
        (true, false) => Some(Ca::Staging),
        (false, true) => Some(Ca::Production),
        (false, false) => None,
    };

    let renew = ServerRenew {
        force: parsed.is_set("force"),
        dns_only: parsed.is_set("dns"),
        ca,
        acme_email: parsed.value("acme-email").map(str::to_string),
        acme_challenge: challenge(&parsed)?,
        cf_token: token(&parsed)?,
        cf_token_file: parsed.value("cf-token-file").map(str::to_string),
    };

    // The token flags are one question asked twice, wherever they
    // appear — the rule and its wording belong to `cfapi::choose`.
    cfapi::choose(
        renew.cf_token_file.as_deref(),
        renew.cf_token.as_ref().map(Token::expose),
        None,
    )
    .map_err(CliError::Token)?;

    // `--dns` means *only* DNS. Mixed with a re-issue or a settings
    // change, a failure leaves it unclear which half took (§8). The
    // token flags are the exception: pushing a record needs a token,
    // and the hub may not have one recorded.
    if renew.dns_only {
        let mixed: Vec<&'static str> = [
            (renew.force, "--force"),
            (renew.ca.is_some(), "--acme-staging/--acme-production"),
            (renew.acme_email.is_some(), "--acme-email"),
            (renew.acme_challenge.is_some(), "--acme-challenge"),
        ]
        .into_iter()
        .filter_map(|(given, flag)| given.then_some(flag))
        .collect();
        if let Some(other) = mixed.first() {
            return Err(CliError::Contradiction("--dns", other));
        }
    }

    Ok(Command::ServerRenew(renew))
}

fn join(argv: &[String]) -> Result<Command, CliError> {
    let spec = [
        Flag::value("name"),
        Flag::value("api-port"),
        Flag::value("export"),
    ];
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

    let api_port = port(&parsed, "api-port", DEFAULT_API_PORT)?;
    Ok(Command::Join(Join {
        domain: domain(host)?,
        api_port,
        code: JoinCode::parse(code).map_err(|e| CliError::BadArgument {
            what: "join code",
            message: e.to_string(),
        })?,
        name,
    }))
}

fn sync(argv: &[String]) -> Result<Command, CliError> {
    let spec = [
        Flag::boolean("quiet"),
        Flag::value("config"),
        Flag::boolean("install-timer"),
        Flag::boolean("uninstall-timer"),
        Flag::value("interval"),
    ];
    let parsed = ParsedArgs::parse(argv, &spec)?;
    reject_extra_positionals(&parsed, "sync")?;

    let timer = match (
        parsed.is_set("install-timer"),
        parsed.is_set("uninstall-timer"),
    ) {
        (true, true) => {
            return Err(CliError::Contradiction(
                "--install-timer",
                "--uninstall-timer",
            ))
        }
        (true, false) => Some(Timer::Install {
            interval: interval(&parsed)?,
        }),
        (false, true) => Some(Timer::Uninstall),
        (false, false) => None,
    };

    // `--interval` belongs to installing a timer and to nothing else.
    // Beside a run it looks like it changed a schedule and changed
    // nothing; beside `--uninstall-timer` it is a period for a timer
    // that is about to stop existing (§8).
    if parsed.is_set("interval") && !matches!(timer, Some(Timer::Install { .. })) {
        return Err(CliError::Orphan {
            flag: "--interval",
            needs: "--install-timer",
        });
    }

    // The two flags that belong to a run, not to managing the timer.
    // A quiet install would swallow the lines that say how to check
    // the timer, which are the point of installing one.
    if timer.is_some() && parsed.is_set("quiet") {
        return Err(CliError::Orphan {
            flag: "--quiet",
            needs: "a sync run — the installed timer is quiet already",
        });
    }
    if timer == Some(Timer::Uninstall) && parsed.is_set("config") {
        return Err(CliError::Orphan {
            flag: "--config",
            needs: "a sync run or --install-timer — removing the timer reads no device file",
        });
    }

    Ok(Command::Sync(Sync {
        quiet: parsed.is_set("quiet"),
        config: config(&parsed)?,
        timer,
    }))
}

/// `--config <path>`, which has to be absolute.
///
/// A relative path is resolved against the working directory, and the
/// whole reason this flag exists is that a timer unit has no working
/// directory a person would recognise — it runs as root, outside the
/// session, from `/`. Baking `device.json` into a unit is only useful
/// if it names the file from the root down (§8).
fn config(parsed: &ParsedArgs) -> Result<Option<PathBuf>, CliError> {
    let Some(text) = parsed.value("config") else {
        return Ok(None);
    };
    let path = Path::new(text);
    if !path.is_absolute() {
        return Err(CliError::BadValue {
            flag: "config",
            message: format!(
                "{text:?} is a relative path — give the full path from /, because the \
                 timer that reads it runs from somewhere else entirely"
            ),
        });
    }
    Ok(Some(path.to_path_buf()))
}

/// `--interval 5m`.
///
/// A unit is required. A bare number would have to mean seconds by
/// convention, and `--interval 5` meaning five *seconds* on a command
/// whose default is five minutes is a mistake nobody would catch until
/// the hub's API was being polled twelve times a minute.
fn interval(parsed: &ParsedArgs) -> Result<Duration, CliError> {
    let Some(text) = parsed.value("interval") else {
        return Ok(DEFAULT_INTERVAL);
    };
    let bad = |message: String| CliError::BadValue {
        flag: "interval",
        message,
    };

    // `strip_suffix` takes a character, so a value that is not ASCII
    // — `5분`, say — falls out here as "no unit" rather than splitting
    // a byte index inside a character and panicking.
    let Some((digits, seconds)) = [("s", 1), ("m", 60), ("h", 60 * 60)]
        .into_iter()
        .find_map(|(unit, seconds)| text.strip_suffix(unit).map(|digits| (digits, seconds)))
    else {
        return Err(bad(format!(
            "{text:?} has no unit — write it as 90s, 5m or 1h"
        )));
    };
    let count: u64 = digits
        .parse()
        .map_err(|_| bad(format!("{text:?} is not a length of time — try 5m")))?;
    let interval = Duration::from_secs(count.saturating_mul(seconds));

    if interval < MIN_INTERVAL {
        return Err(bad(format!(
            "{text:?} is shorter than a minute. Most changes ask nothing of a device, \
             so syncing that often only polls the hub"
        )));
    }
    if interval > MAX_INTERVAL {
        return Err(bad(format!(
            "{text:?} is longer than a day, which is not a timer any more — the peer \
             list would be a day stale"
        )));
    }
    Ok(interval)
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
    /// Two flags that cannot both be meant.
    Contradiction(&'static str, &'static str),
    /// A flag that only means something beside another one.
    Orphan {
        flag: &'static str,
        needs: &'static str,
    },
    /// Flags that do not together describe a hub anago can set up
    /// ([`acme::plan`]).
    Plan(PlanError),
    /// A Cloudflare token flag that anago cannot use ([`cfapi`]).
    Token(CfError),
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
            // Both already name the flags they are about, so adding a
            // prefix here would say one of them twice.
            CliError::Contradiction(one, other) => write!(
                f,
                "{one} and {other} cannot both be given; pass one and run it again"
            ),
            CliError::Orphan { flag, needs } => {
                write!(f, "{flag} only means something with {needs}")
            }
            CliError::Plan(e) => write!(f, "{e}"),
            CliError::Token(e) => write!(f, "{e}"),
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
usage: anago server init --domain <d>
                        [--tls-cert <path> --tls-key <path>]
                        [--acme-email <address>] [--acme-staging]
                        [--acme-challenge http-01|dns-01]
                        [--cf-token <token> | --cf-token-file <path>]
                        [--subnet {DEFAULT_SUBNET}] [--port {DEFAULT_LISTEN_PORT}]
                        [--api-port {DEFAULT_API_PORT}] [--no-systemd]

Sets up the hub on this machine: generates its wg keypair, writes the
state file, prints the DNS record to add and the ports to open, then
issues the first join code.

The certificate pair decides everything else. Give both and anago
serves the certificate you already have and never renews it. Leave both
out and anago orders one from Let's Encrypt and renews it — which needs
--acme-email, the address the CA writes to before an expiry.

--acme-challenge defaults to dns-01 when there is a Cloudflare token
and http-01 when there is not. http-01 needs port 80 reachable; dns-01
needs the token, which is also what lets anago add the A record for
you. The token can come from --cf-token-file (safest), --cf-token
(visible to `ps` and in shell history), or {env}.

--acme-staging orders from Let's Encrypt's staging CA. Nothing trusts
those certificates, so `anago join` will refuse them — it is for
checking the wiring without spending a rate limit.
",
            env = cfapi::TOKEN_ENV
        ),
        Some("renew") => format!(
            "\
usage: anago server renew [--force] [--dns]
                         [--acme-staging | --acme-production]
                         [--acme-email <address>]
                         [--acme-challenge http-01|dns-01]
                         [--cf-token <token> | --cf-token-file <path>]

Run on the hub. Orders the certificate again, changes how it will be
ordered next time, or pushes the A record — never all three, and never
anything to do with WireGuard: no tunnel drops for any of this.

With no flags it decides for itself. If the certificate is not due yet
it says when it will be and does nothing, so it is safe in cron.
--force orders one anyway, which spends one of the CA's few per week
for this name.

A flag that changes *which* certificate you would get — moving between
{staging} and the real CA, or taking over a hub set up with
--tls-cert/--tls-key — orders one straight away; --force is not needed
and would not mean anything. A flag that does not (--acme-email,
--acme-challenge, the token) is written down and applies from the next
renewal.

--dns pushes the A record at this machine's current address and stops.
That is for a server whose public IP changed; nothing else here does
it, and `server init` refuses to run twice.
",
            staging = "staging"
        ),
        Some("join") => format!(
            "\
usage: anago join <domain> <code> [--name <name>] [--api-port <port>]

Registers this device with the hub at <domain>. The wg keypair is made
here and the private key never leaves — the server sees the public half
only. Without --name the machine's hostname is used.

--api-port has to match the hub's; pass it when the server was set up
with a non-default one.

Join codes are single use and expire; ask the server for another with
`anago code`. Format: {code}
",
            code = "XXXX-XXXX"
        ),
        Some("sync") => format!(
            "\
usage: anago sync [--quiet] [--config <path>]
       anago sync --install-timer [--interval {default}] [--config <path>]
       anago sync --uninstall-timer

Run on a device, as root. Asks the hub for the peer list and rewrites
the WireGuard config only if something changed.

Nothing here is needed to reach the hub — it already knows every
device. Syncing is how *this* device hears about the others.

--config gives the full path to device.json, from / down. Without it
anago works the path out the way `ls` and `rm` do, which needs your
user session; a timer has none, so the installed unit carries the path
on its command line. --quiet goes on that command line too, so opening
the unit file says why it is silent.

--install-timer writes the unit and starts it: a systemd timer on
Linux, a LaunchDaemon on macOS. Where neither exists, it prints a cron
line instead of pretending. --interval takes 90s, 5m or 1h — between
{min} and {max}.
",
            default = "5m",
            min = "1m",
            max = "24h"
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
  anago server init --domain <d>    set this machine up as the hub
  anago server renew                order the certificate again, or change how
  anago server run                  run the hub (systemd does this for you)
  anago code                        issue a join code (on the server)
  anago join <domain> <code>        register this device
  anago sync                        pull the peer list (on a device)
  anago ls                          list devices
  anago rm <name>                   remove a device

  -h, --help                        show this, or `anago help <command>`
  -V, --version                     show the version

Later milestones: `--export qr|conf` (M1), `anago ping` and
`anago server status` (M3).
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
        assert_eq!(
            init.tls_cert.as_deref(),
            Some("/etc/ssl/anago/fullchain.pem")
        );
        assert_eq!(init.tls_key.as_deref(), Some("/etc/ssl/anago/privkey.pem"));
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
    fn server_init_insists_on_what_it_cannot_invent() {
        // The domain is the one thing with no default and no other
        // way in: it is the DNS name, the certificate's subject, and
        // what `anago join` is typed against.
        assert_eq!(
            parse_args(&["server", "init"]),
            Err(CliError::Arg(ArgError::Required("domain")))
        );

        // The certificate pair is not required any more — leaving it
        // out is how a person asks anago to get one (§8).
        let init = init(&[
            "server",
            "init",
            "--domain",
            "net.example.com",
            "--acme-email",
            "jo@example.com",
        ])
        .unwrap();
        assert_eq!(init.tls_cert, None);
        assert_eq!(init.tls_key, None);
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
                api_port: DEFAULT_API_PORT,
            })
        );

        let command = parse_args(&["join", "net.example.com", "7QX4-M2KD", "--name", "맥북"]);
        assert_eq!(
            command.unwrap(),
            Command::Join(Join {
                domain: "net.example.com".to_string(),
                code: JoinCode::parse("7QX4-M2KD").unwrap(),
                name: Some(DeviceName::parse("맥북").unwrap()),
                api_port: DEFAULT_API_PORT,
            })
        );
    }

    #[test]
    fn join_can_reach_a_hub_on_a_non_default_port() {
        // `server init --api-port 8443` is a supported setup, so the
        // device has to be able to say the same number.
        match parse_args(&["join", "net.example.com", "7QX4-M2KD", "--api-port", "8443"]).unwrap() {
            Command::Join(join) => assert_eq!(join.api_port, 8443),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse_args(&["join", "net.example.com", "7QX4-M2KD", "--api-port", "0"]),
            Err(CliError::BadValue {
                flag: "api-port",
                ..
            })
        ));
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
        let e =
            parse_args(&["join", "net.example.com", "7QX4-M2KD", "--export", "qr"]).unwrap_err();
        assert!(e.to_string().starts_with("--export arrives in M1"), "{e}");
    }

    #[test]
    fn leaving_the_certificate_out_is_how_acme_is_asked_for() {
        let asked = init(&[
            "server",
            "init",
            "--domain",
            "net.example.com",
            "--acme-email",
            "jo@example.com",
            "--acme-staging",
            "--acme-challenge",
            "dns-01",
            "--cf-token",
            "cf-secret-value",
        ])
        .unwrap();
        assert_eq!(asked.tls_cert, None);
        assert_eq!(asked.acme_email.as_deref(), Some("jo@example.com"));
        assert!(asked.acme_staging);
        assert_eq!(asked.acme_challenge, Some(Challenge::Dns01));
        assert_eq!(
            asked.cf_token.map(|t| t.expose().to_string()).as_deref(),
            Some("cf-secret-value")
        );
        assert_eq!(asked.cf_token_file, None);

        // Nothing but the domain: the challenge is left undecided,
        // because whether there is a token is not argv's to know.
        let bare = init(&[
            "server",
            "init",
            "--domain",
            "net.example.com",
            "--acme-email",
            "jo@example.com",
        ])
        .unwrap();
        assert_eq!(bare.acme_challenge, None);
        assert!(!bare.acme_staging);
        assert_eq!(bare.cf_token, None);
    }

    #[test]
    fn the_certificate_flags_come_as_a_pair() {
        // Half a pair is a person meaning one of two different things,
        // and neither is safe to pick: with the pair anago serves what
        // it is given and never renews, without it anago orders one.
        let e = init(&[
            "server",
            "init",
            "--domain",
            "net.example.com",
            "--tls-cert",
            "/c.pem",
        ])
        .unwrap_err();
        assert_eq!(
            e,
            CliError::Plan(PlanError::HalfAPair {
                given: "--tls-cert",
                missing: "--tls-key",
            })
        );
        assert!(e.to_string().contains("--tls-key"), "{e}");

        let e = init(&[
            "server",
            "init",
            "--domain",
            "net.example.com",
            "--tls-key",
            "/k.pem",
        ])
        .unwrap_err();
        assert_eq!(
            e,
            CliError::Plan(PlanError::HalfAPair {
                given: "--tls-key",
                missing: "--tls-cert",
            })
        );
    }

    #[test]
    fn acme_flags_beside_a_certificate_are_refused_not_ignored() {
        // The failure this prevents is silent: the pair means anago
        // never orders anything, so an --acme-* flag that was quietly
        // dropped leaves a person believing renewal is automatic, and
        // they find out when the certificate expires.
        let mut args = required_init();
        args.extend(["--acme-email", "jo@example.com"]);
        let e = parse_args(&args).unwrap_err();
        assert_eq!(
            e,
            CliError::Plan(PlanError::AcmeFlagsWithCertificate(vec!["--acme-email"]))
        );
        assert!(e.to_string().contains("nothing here would renew"), "{e}");

        // Every one of them is named, so the fix does not have to be
        // guessed at one flag per attempt.
        let mut args = required_init();
        args.extend([
            "--acme-email",
            "jo@example.com",
            "--acme-staging",
            "--acme-challenge",
            "http-01",
        ]);
        let e = parse_args(&args).unwrap_err();
        let message = e.to_string();
        for flag in ["--acme-email", "--acme-staging", "--acme-challenge"] {
            assert!(message.contains(flag), "{flag} is missing from {message}");
        }

        // A Cloudflare token is the exception (§8): what it does — the
        // A record — has nothing to do with where the certificate came
        // from, and refusing it would tie two unrelated features
        // together.
        let mut args = required_init();
        args.extend(["--cf-token", "cf-secret-value"]);
        let init = match parse_args(&args).unwrap() {
            Command::ServerInit(init) => init,
            other => panic!("{other:?}"),
        };
        assert!(init.cf_token.is_some());
        assert!(init.tls_cert.is_some());
    }

    #[test]
    fn ordering_a_certificate_needs_an_address_to_warn() {
        // Let's Encrypt will make an account without one. The expiry
        // mail is the only alarm that reaches a person when automatic
        // renewal has quietly stopped, and "set it up and forget it"
        // is not worth trading for one flag (§8).
        let e = init(&["server", "init", "--domain", "net.example.com"]).unwrap_err();
        assert_eq!(e, CliError::Plan(PlanError::NoContact));
        assert!(e.to_string().contains("about to expire"), "{e}");
    }

    #[test]
    fn the_two_token_flags_are_one_question_asked_twice() {
        let mut args = required_init();
        args.extend([
            "--cf-token",
            "cf-secret-value",
            "--cf-token-file",
            "/root/cf",
        ]);
        let e = parse_args(&args).unwrap_err();
        assert_eq!(e, CliError::Token(CfError::BothFlags));
        // And it says which one to keep rather than just refusing.
        assert!(e.to_string().contains("the safer of the two"), "{e}");
    }

    #[test]
    fn a_truncated_token_is_caught_where_it_was_typed() {
        // A token with whitespace in it is a copy-paste that lost its
        // tail. Sending it produces a 401, which reads as a
        // permissions problem rather than a typo — so it is refused
        // here, before anything is generated.
        let mut args = required_init();
        args.extend(["--cf-token", "half a token"]);
        let e = parse_args(&args).unwrap_err();
        assert_eq!(e, CliError::Token(CfError::Malformed(Source::Flag)));
        assert!(e.to_string().contains("--cf-token"), "{e}");

        // Empty is the parser's own complaint, and comes first.
        let mut args = required_init();
        args.extend(["--cf-token="]);
        assert_eq!(
            parse_args(&args),
            Err(CliError::Arg(ArgError::EmptyValue("cf-token")))
        );
    }

    #[test]
    fn the_challenge_is_spelled_the_way_the_state_file_spells_it() {
        let mut args = required_init();
        args.extend(["--acme-challenge", "dns"]);
        let e = parse_args(&args).unwrap_err();
        assert_eq!(
            e,
            CliError::BadValue {
                flag: "acme-challenge",
                message: "\"dns\" is not a challenge — expected http-01 or dns-01".to_string(),
            }
        );

        for (text, expected) in [("http-01", Challenge::Http01), ("dns-01", Challenge::Dns01)] {
            let init = init(&[
                "server",
                "init",
                "--domain",
                "net.example.com",
                "--acme-email",
                "jo@example.com",
                "--acme-challenge",
                text,
                "--cf-token",
                "cf-secret-value",
            ])
            .unwrap();
            assert_eq!(init.acme_challenge, Some(expected));
        }
    }

    #[test]
    fn dns01_without_a_token_is_left_for_init_to_answer() {
        // Routing does not read CLOUDFLARE_API_TOKEN — not reading it
        // is what keeps every rule in this module a unit test — so it
        // cannot know there is no token. Refusing here would break the
        // documented third way of passing one; `init` runs the same
        // check with the environment in hand.
        let init = init(&[
            "server",
            "init",
            "--domain",
            "net.example.com",
            "--acme-email",
            "jo@example.com",
            "--acme-challenge",
            "dns-01",
        ])
        .unwrap();
        assert_eq!(init.acme_challenge, Some(Challenge::Dns01));
        assert_eq!(init.cf_token, None);
        assert_eq!(init.cf_token_file, None);

        // With a token flag the same line is settled here, and passes.
        let mut with_file = vec![
            "server",
            "init",
            "--domain",
            "net.example.com",
            "--acme-email",
            "jo@example.com",
            "--acme-challenge",
            "dns-01",
        ];
        with_file.extend(["--cf-token-file", "/root/cf-token"]);
        assert!(parse_args(&with_file).is_ok());
    }

    #[test]
    fn a_token_never_prints_itself() {
        // §13: `Debug` on a command is the sort of thing that ends up
        // in a log, and argv being visible to `ps` already is no
        // reason for anago to repeat it.
        let mut args = required_init();
        args.extend(["--cf-token", "cf-secret-value"]);
        let printed = format!("{:?}", parse_args(&args).unwrap());
        assert!(!printed.contains("cf-secret-value"), "{printed}");
        assert!(printed.contains("redacted"), "{printed}");
    }

    #[test]
    fn a_bad_combination_is_a_usage_error() {
        // Exit 2 is "did not understand"; 1 is "understood, cannot do
        // it". Flags that contradict each other are the former, and a
        // script can tell them apart.
        let e = init(&["server", "init", "--domain", "net.example.com"]).unwrap_err();
        assert_eq!(exit_code(&e), 2);
        let mut args = required_init();
        args.extend(["--cf-token", "a", "--cf-token-file", "/b"]);
        assert_eq!(exit_code(&parse_args(&args).unwrap_err()), 2);
    }

    fn renew(args: &[&str]) -> Result<ServerRenew, CliError> {
        let mut argv = vec!["server", "renew"];
        argv.extend_from_slice(args);
        match parse_args(&argv)? {
            Command::ServerRenew(renew) => Ok(renew),
            other => panic!("expected server renew, got {other:?}"),
        }
    }

    #[test]
    fn server_renew_takes_nothing_at_all() {
        // The command's whole point as a cron job: with no flags it is
        // a check that decides for itself (§8).
        let asked = renew(&[]).unwrap();
        assert!(!asked.force);
        assert!(!asked.dns_only);
        assert_eq!(asked.ca, None);
    }

    #[test]
    fn the_ca_is_three_states_and_not_a_flag() {
        // An absent `--acme-staging` must not read as "production":
        // that would move a staging hub to another CA on an ordinary
        // renewal. Hence the pair, which `server init` does not need
        // because production is the default there (§8).
        assert_eq!(renew(&[]).unwrap().ca, None);
        assert_eq!(renew(&["--acme-staging"]).unwrap().ca, Some(Ca::Staging));
        assert_eq!(
            renew(&["--acme-production"]).unwrap().ca,
            Some(Ca::Production)
        );

        let e = renew(&["--acme-staging", "--acme-production"]).unwrap_err();
        assert_eq!(
            e,
            CliError::Contradiction("--acme-staging", "--acme-production")
        );
        assert!(e.to_string().contains("cannot both be given"), "{e}");
    }

    #[test]
    fn dns_means_only_dns() {
        // Mixed with a re-issue or a settings change, a failure leaves
        // it unclear which half took (§8).
        assert!(renew(&["--dns"]).unwrap().dns_only);
        for other in [
            "--force",
            "--acme-staging",
            "--acme-production",
            "--acme-email=jo@example.com",
            "--acme-challenge=dns-01",
        ] {
            let e = renew(&["--dns", other]).unwrap_err();
            assert!(
                matches!(e, CliError::Contradiction("--dns", _)),
                "{other}: {e:?}"
            );
        }

        // The token flags are the exception: pushing a record needs a
        // token, and the hub may have none recorded.
        let asked = renew(&["--dns", "--cf-token-file", "/root/cf-token"]).unwrap();
        assert!(asked.dns_only);
        assert_eq!(asked.cf_token_file.as_deref(), Some("/root/cf-token"));
    }

    #[test]
    fn server_renew_settles_the_token_flags_the_same_way_everywhere() {
        let e = renew(&[
            "--cf-token",
            "cf-secret-value",
            "--cf-token-file",
            "/root/cf",
        ])
        .unwrap_err();
        assert_eq!(e, CliError::Token(CfError::BothFlags));
        assert!(e.to_string().contains("the safer of the two"), "{e}");

        // And a truncated paste is caught where it was typed.
        assert_eq!(
            renew(&["--cf-token", "half a token"]),
            Err(CliError::Token(CfError::Malformed(Source::Flag)))
        );
    }

    #[test]
    fn every_setting_flag_reaches_the_field_it_belongs_to() {
        // `renew::plan` decides what to do by comparing these against
        // the hub's recorded values (§8), so a flag that lands in the
        // wrong field is a certificate ordered — or not — for the
        // wrong reason.
        let asked = renew(&[
            "--acme-email",
            "jo@example.com",
            "--acme-challenge",
            "dns-01",
            "--cf-token-file",
            "/root/cf-token",
            "--acme-staging",
            "--force",
        ])
        .unwrap();
        assert_eq!(asked.acme_email.as_deref(), Some("jo@example.com"));
        assert_eq!(asked.acme_challenge, Some(Challenge::Dns01));
        assert_eq!(asked.cf_token_file.as_deref(), Some("/root/cf-token"));
        assert_eq!(asked.ca, Some(Ca::Staging));
        assert!(asked.force);
        assert!(!asked.dns_only);

        // And an empty command line leaves every one of them alone —
        // which is what makes a bare `server renew` a check rather
        // than an edit.
        let bare = renew(&[]).unwrap();
        assert_eq!(bare.acme_email, None);
        assert_eq!(bare.acme_challenge, None);
        assert_eq!(bare.cf_token, None);
        assert_eq!(bare.cf_token_file, None);
        assert_eq!(bare.ca, None);
        assert!(!bare.force);
    }

    #[test]
    fn server_renew_refuses_what_it_does_not_take() {
        assert_eq!(
            parse_args(&["server", "renew", "--domain", "net.example.com"]),
            Err(CliError::Arg(ArgError::Unknown("--domain".to_string())))
        );
        assert_eq!(
            parse_args(&["server", "renew", "net.example.com"]),
            Err(CliError::TooManyArguments("server renew"))
        );
        // The same challenge spelling as everywhere else.
        assert!(matches!(
            renew(&["--acme-challenge", "dns"]),
            Err(CliError::BadValue {
                flag: "acme-challenge",
                ..
            })
        ));
    }

    #[test]
    fn the_help_for_server_renew_names_every_flag_it_accepts() {
        let text = help(Some("renew"));
        for flag in [
            "--force",
            "--dns",
            "--acme-staging",
            "--acme-production",
            "--acme-email",
            "--acme-challenge",
            "--cf-token",
            "--cf-token-file",
        ] {
            assert!(
                text.contains(flag),
                "the help for server renew omits {flag}"
            );
            assert_ne!(
                parse_args(&["server", "renew", flag]),
                Err(CliError::Arg(ArgError::Unknown(flag.to_string()))),
                "{flag} is in the help but not in the spec"
            );
        }
        // And the two things a person has to be told rather than find
        // out: it is safe in cron, and it never touches the tunnel.
        assert!(text.contains("safe in cron"), "{text}");
        assert!(text.contains("no tunnel drops"), "{text}");
    }

    fn sync(args: &[&str]) -> Result<Sync, CliError> {
        let mut argv = vec!["sync"];
        argv.extend_from_slice(args);
        match parse_args(&argv)? {
            Command::Sync(sync) => Ok(sync),
            other => panic!("expected sync, got {other:?}"),
        }
    }

    #[test]
    fn sync_is_a_command_now_and_not_a_promise() {
        // M0 answered `anago sync` with "arrives in M1". It has.
        let asked = sync(&[]).unwrap();
        assert!(!asked.quiet);
        assert_eq!(asked.config, None);
        assert_eq!(asked.timer, None);
    }

    #[test]
    fn the_timer_form_is_the_one_the_unit_file_carries() {
        // §8 fixes the installed command line as
        // `anago sync --quiet --config <absolute path>`, so both have
        // to parse exactly as the unit writes them.
        let asked = sync(&["--quiet", "--config", "/home/jo/.config/anago/device.json"]).unwrap();
        assert!(asked.quiet);
        assert_eq!(
            asked.config,
            Some(PathBuf::from("/home/jo/.config/anago/device.json"))
        );
        assert_eq!(asked.timer, None);
    }

    #[test]
    fn a_relative_config_path_is_refused() {
        // The flag exists because a timer has no working directory a
        // person would recognise: it runs as root, outside the
        // session, from `/`. A relative path in a unit file is the
        // failure this flag was added to avoid.
        for path in ["device.json", "./device.json", "../anago/device.json"] {
            let e = sync(&["--config", path]).unwrap_err();
            assert!(
                matches!(e, CliError::BadValue { flag: "config", .. }),
                "{path}: {e:?}"
            );
            assert!(e.to_string().contains("full path from /"), "{e}");
        }
        assert!(sync(&["--config", "/root/device.json"]).is_ok());
    }

    #[test]
    fn installing_and_uninstalling_are_not_both_meant() {
        assert_eq!(
            sync(&["--install-timer"]).unwrap().timer,
            Some(Timer::Install {
                interval: DEFAULT_INTERVAL
            })
        );
        assert_eq!(
            sync(&["--uninstall-timer"]).unwrap().timer,
            Some(Timer::Uninstall)
        );
        assert_eq!(
            sync(&["--install-timer", "--uninstall-timer"]),
            Err(CliError::Contradiction(
                "--install-timer",
                "--uninstall-timer"
            ))
        );
    }

    #[test]
    fn the_interval_needs_a_unit_and_stays_in_range() {
        let interval =
            |text: &str| sync(&["--install-timer", "--interval", text]).map(|asked| asked.timer);
        let every = |seconds| {
            Some(Timer::Install {
                interval: Duration::from_secs(seconds),
            })
        };
        assert_eq!(interval("90s").unwrap(), every(90));
        assert_eq!(interval("5m").unwrap(), every(5 * 60));
        assert_eq!(interval("1h").unwrap(), every(60 * 60));
        // And left out, the default §6.3 argues for.
        assert_eq!(
            sync(&["--install-timer"]).unwrap().timer,
            every(DEFAULT_INTERVAL.as_secs())
        );

        // A bare number would have to mean seconds by convention, and
        // `--interval 5` meaning five *seconds* on a command whose
        // default is five minutes is a mistake nobody catches until
        // the hub is being polled twelve times a minute.
        let e = interval("5").unwrap_err();
        assert!(e.to_string().contains("no unit"), "{e}");
        assert!(e.to_string().contains("5m"), "{e}");
        assert!(interval("5min")
            .unwrap_err()
            .to_string()
            .contains("no unit"));

        // Regression: the unit used to be taken off by byte, so a
        // value whose last character is not ASCII split inside that
        // character and panicked the process instead of returning an
        // error a person can read.
        for text in ["5분", "5초", "５m", "5м", "5\u{301}"] {
            let e = interval(text).unwrap_err();
            assert!(
                matches!(
                    e,
                    CliError::BadValue {
                        flag: "interval",
                        ..
                    }
                ),
                "{text:?}: {e:?}"
            );
            // A usage error, which is what exit 2 means — not a crash.
            assert_eq!(exit_code(&e), 2, "{text:?}");
        }
        assert!(interval("mm")
            .unwrap_err()
            .to_string()
            .contains("not a length of time"));

        // The floor: below a minute the timer only polls (§6.3).
        assert!(interval("0m").is_err());
        assert!(interval("59s")
            .unwrap_err()
            .to_string()
            .contains("shorter than a minute"));
        assert!(interval("1m").is_ok());
        // And the ceiling, past which it is not a timer any more.
        assert!(interval("24h").is_ok());
        assert!(interval("25h")
            .unwrap_err()
            .to_string()
            .contains("longer than a day"));
    }

    #[test]
    fn a_flag_that_would_be_ignored_is_refused_instead() {
        // The failure this prevents is silent: a flag accepted and
        // dropped looks exactly like a flag that worked.
        //
        // `--interval` alone changes no schedule, because there is no
        // timer to change (§8).
        let e = sync(&["--interval", "5m"]).unwrap_err();
        assert_eq!(
            e,
            CliError::Orphan {
                flag: "--interval",
                needs: "--install-timer"
            }
        );
        assert!(e.to_string().contains("only means something with"), "{e}");

        // `--quiet` belongs to a run. A quiet install would swallow
        // the lines that say how to check the timer, which are why
        // installing prints anything at all.
        for timer in ["--install-timer", "--uninstall-timer"] {
            assert!(
                matches!(
                    sync(&[timer, "--quiet"]),
                    Err(CliError::Orphan {
                        flag: "--quiet",
                        ..
                    })
                ),
                "{timer}"
            );
        }

        // And removing the timer reads no device file.
        assert!(matches!(
            sync(&["--uninstall-timer", "--config", "/root/device.json"]),
            Err(CliError::Orphan {
                flag: "--config",
                ..
            })
        ));
        // Installing one does — that is the path it bakes in.
        assert!(sync(&["--install-timer", "--config", "/root/device.json"]).is_ok());
    }

    #[test]
    fn sync_refuses_what_it_does_not_take() {
        assert_eq!(
            parse_args(&["sync", "--domain", "net.example.com"]),
            Err(CliError::Arg(ArgError::Unknown("--domain".to_string())))
        );
        assert_eq!(
            parse_args(&["sync", "macbook"]),
            Err(CliError::TooManyArguments("sync"))
        );
        assert_eq!(
            parse_args(&["sync", "--config"]),
            Err(CliError::Arg(ArgError::MissingValue("config")))
        );
    }

    #[test]
    fn the_help_for_sync_names_every_flag_it_accepts() {
        let text = help(Some("sync"));
        for flag in [
            "--quiet",
            "--config",
            "--install-timer",
            "--uninstall-timer",
            "--interval",
        ] {
            assert!(text.contains(flag), "the help for sync omits {flag}");
            assert_ne!(
                parse_args(&["sync", flag]),
                Err(CliError::Arg(ArgError::Unknown(flag.to_string()))),
                "{flag} is in the help but not in the spec"
            );
        }
        // The two things a person has to be told rather than discover:
        // syncing is not what makes the hub reachable, and the path
        // has to be absolute because a timer has no session.
        assert!(text.contains("already knows every"), "{text}");
        assert!(text.contains("full path to device.json"), "{text}");
        assert!(text.contains("cron"), "{text}");
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
        // `anago ping` was understood and refused on purpose; a typo
        // was not understood at all.
        assert_eq!(exit_code(&parse_args(&["ping", "macbook"]).unwrap_err()), 1);
        assert_eq!(
            exit_code(&parse_args(&["server", "status"]).unwrap_err()),
            1
        );
        assert_eq!(exit_code(&parse_args(&["snyc"]).unwrap_err()), 2);
        // And a flag `sync` does take, given wrongly, is a usage error
        // like any other.
        assert_eq!(
            exit_code(&parse_args(&["sync", "--interval", "5m"]).unwrap_err()),
            2
        );
        assert_eq!(exit_code(&parse_args(&["rm"]).unwrap_err()), 2);
        assert_eq!(
            exit_code(&parse_args(&["rm", "--force", "x"]).unwrap_err()),
            2
        );
    }

    #[test]
    fn help_text_covers_every_m0_command() {
        let general = help(None);
        for command in [
            "server init",
            "server renew",
            "sync",
            "code",
            "join",
            "ls",
            "rm",
        ] {
            assert!(general.contains(command), "general help omits {command}");
        }
        // And says where the rest went.
        assert!(general.contains("M1"), "{general}");
        assert!(general.contains("M3"), "{general}");

        for topic in ["server", "renew", "sync", "join", "code", "ls", "rm"] {
            let text = help(Some(topic));
            assert!(text.starts_with("usage: anago "), "{topic}: {text}");
        }
        // An unknown topic falls back to the overview rather than
        // printing nothing.
        assert_eq!(help(Some("nope")), general);
    }

    #[test]
    fn the_help_for_server_init_names_every_flag_it_accepts() {
        // Help that has drifted from the parser is worse than none:
        // the flag a person copies out of it fails as unknown. This
        // pins the two together.
        let text = help(Some("init"));
        for flag in [
            "--domain",
            "--tls-cert",
            "--tls-key",
            "--acme-email",
            "--acme-staging",
            "--acme-challenge",
            "--cf-token",
            "--cf-token-file",
            "--subnet",
            "--port",
            "--api-port",
            "--no-systemd",
        ] {
            assert!(text.contains(flag), "the help for server init omits {flag}");
            // And every one of them parses, so the help is not
            // advertising something the parser would refuse.
            let e = parse_args(&["server", "init", flag]);
            assert_ne!(
                e,
                Err(CliError::Arg(ArgError::Unknown(flag.to_string()))),
                "{flag} is in the help but not in the spec"
            );
        }

        // The two things a person has to be told rather than discover:
        // staging certificates are not trusted, and a token in argv is
        // visible to other users.
        assert!(text.contains("Nothing trusts"), "{text}");
        assert!(text.contains("`ps`"), "{text}");
        assert!(text.contains(cfapi::TOKEN_ENV), "{text}");
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
