//! Flag parsing — hand rolled, no dependency (DESIGN.md §10).
//!
//! Parsing is a pure function of the argument slice: nothing here reads
//! or writes the environment, so the tests below are the whole story.
//! `main` passes `std::env::args()` in and that is the only place the
//! process's real arguments appear.
//!
//! Flags are declared, not guessed. A caller hands in the [`Flag`]s a
//! command accepts, which is what lets `--domian` fail as an unknown
//! flag instead of being silently ignored, and lets `--no-systemd ls`
//! keep `ls` as a positional rather than eating it as a value.

use std::fmt;

/// Whether a flag carries a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagKind {
    /// `--no-systemd` — present or absent.
    Boolean,
    /// `--domain net.example.com` or `--domain=net.example.com`.
    Value,
}

/// One flag a command accepts.
///
/// Long names only. The two single-letter forms anago has, `-h` and
/// `-V`, are answered before parsing (see `cli::parse`), so there is no
/// alias machinery here to keep in sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flag {
    pub name: &'static str,
    pub kind: FlagKind,
}

impl Flag {
    pub fn boolean(name: &'static str) -> Flag {
        Flag {
            name,
            kind: FlagKind::Boolean,
        }
    }

    pub fn value(name: &'static str) -> Flag {
        Flag {
            name,
            kind: FlagKind::Value,
        }
    }
}

/// The result of parsing: positionals in order, flags by name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedArgs {
    positionals: Vec<String>,
    /// Long name and, for value flags, what was given.
    flags: Vec<(&'static str, Option<String>)>,
}

impl ParsedArgs {
    /// Splits `argv` (without the program name) into positionals and
    /// flags, against the flags this command declares.
    ///
    /// `--` ends flag parsing: everything after it is positional, so a
    /// device named `-x` is still reachable.
    pub fn parse(argv: &[String], spec: &[Flag]) -> Result<ParsedArgs, ArgError> {
        let mut parsed = ParsedArgs::default();
        let mut rest_are_positional = false;
        let mut i = 0;

        while i < argv.len() {
            let arg = argv[i].as_str();
            i += 1;

            if rest_are_positional {
                parsed.positionals.push(arg.to_string());
                continue;
            }
            if arg == "--" {
                rest_are_positional = true;
                continue;
            }
            // A lone "-" is a positional by convention (stdin), and
            // anything not starting with "-" obviously is.
            if arg == "-" || !arg.starts_with('-') {
                parsed.positionals.push(arg.to_string());
                continue;
            }

            let (token, inline) = match arg.split_once('=') {
                Some((token, value)) => (token, Some(value.to_string())),
                None => (arg, None),
            };
            let flag =
                find_flag(spec, token).ok_or_else(|| ArgError::Unknown(token.to_string()))?;

            let value = match flag.kind {
                FlagKind::Boolean => {
                    if inline.is_some() {
                        return Err(ArgError::UnexpectedValue(flag.name));
                    }
                    None
                }
                FlagKind::Value => {
                    let value = match inline {
                        Some(value) => value,
                        None => {
                            // The next token is the value — but only if
                            // there is one and it is not another flag.
                            match argv.get(i) {
                                Some(next) if !is_flag_like(next) => {
                                    i += 1;
                                    next.clone()
                                }
                                _ => return Err(ArgError::MissingValue(flag.name)),
                            }
                        }
                    };
                    if value.is_empty() {
                        return Err(ArgError::EmptyValue(flag.name));
                    }
                    Some(value)
                }
            };

            // Repeats are an error, not last-wins: `--subnet a --subnet
            // b` is a mistake, and quietly picking one would configure a
            // network the person did not ask for.
            if parsed.flags.iter().any(|(name, _)| *name == flag.name) {
                return Err(ArgError::Duplicate(flag.name));
            }
            parsed.flags.push((flag.name, value));
        }
        Ok(parsed)
    }

    /// Positional arguments, in the order given.
    pub fn positionals(&self) -> &[String] {
        &self.positionals
    }

    /// Whether a flag was given at all — the question a boolean flag
    /// answers.
    pub fn is_set(&self, name: &str) -> bool {
        self.flags.iter().any(|(flag, _)| *flag == name)
    }

    /// The value of a value flag, or `None` if it was not given.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .find(|(flag, _)| *flag == name)
            .and_then(|(_, value)| value.as_deref())
    }

    /// The value of a flag the command cannot run without.
    pub fn require(&self, name: &'static str) -> Result<&str, ArgError> {
        self.value(name).ok_or(ArgError::Required(name))
    }
}

/// A flag-shaped token: `--domain`, `-h`. A bare `-` is not one, and
/// neither is a negative number, so `--port -1` reports a missing value
/// rather than swallowing the next argument.
fn is_flag_like(arg: &str) -> bool {
    arg.starts_with('-') && arg != "-"
}

fn find_flag<'a>(spec: &'a [Flag], token: &str) -> Option<&'a Flag> {
    let name = token.strip_prefix("--")?;
    spec.iter().find(|flag| flag.name == name)
}

/// Why the command line could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgError {
    /// A flag this command does not accept.
    Unknown(String),
    /// A value flag with nothing after it.
    MissingValue(&'static str),
    /// `--domain=` — present but empty.
    EmptyValue(&'static str),
    /// A value given to a boolean flag.
    UnexpectedValue(&'static str),
    /// The same flag twice.
    Duplicate(&'static str),
    /// A required flag that was not given at all.
    Required(&'static str),
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArgError::Unknown(token) => write!(f, "unknown flag {token}"),
            ArgError::MissingValue(name) => write!(f, "--{name} needs a value"),
            ArgError::EmptyValue(name) => write!(f, "--{name} needs a non-empty value"),
            ArgError::UnexpectedValue(name) => write!(f, "--{name} does not take a value"),
            ArgError::Duplicate(name) => write!(f, "--{name} was given more than once"),
            ArgError::Required(name) => write!(f, "--{name} is required"),
        }
    }
}

impl std::error::Error for ArgError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    fn spec() -> Vec<Flag> {
        vec![
            Flag::value("domain"),
            Flag::value("subnet"),
            Flag::value("port"),
            Flag::boolean("no-systemd"),
        ]
    }

    fn parse(args: &[&str]) -> Result<ParsedArgs, ArgError> {
        ParsedArgs::parse(&argv(args), &spec())
    }

    #[test]
    fn an_empty_command_line_parses_to_nothing() {
        let parsed = parse(&[]).unwrap();
        assert!(parsed.positionals().is_empty());
        assert!(!parsed.is_set("help"));
        assert_eq!(parsed.value("domain"), None);
    }

    #[test]
    fn collects_positionals_in_order() {
        let parsed = parse(&["server", "init"]).unwrap();
        assert_eq!(parsed.positionals(), ["server", "init"]);
    }

    #[test]
    fn reads_a_value_written_either_way() {
        for args in [
            vec!["--domain", "net.example.com"],
            vec!["--domain=net.example.com"],
        ] {
            let parsed = ParsedArgs::parse(&argv(&args), &spec()).unwrap();
            assert_eq!(parsed.value("domain"), Some("net.example.com"), "{args:?}");
            assert!(parsed.is_set("domain"));
        }
    }

    #[test]
    fn boolean_flags_are_presence_only() {
        let parsed = parse(&["--no-systemd"]).unwrap();
        assert!(parsed.is_set("no-systemd"));
        assert_eq!(parsed.value("no-systemd"), None);
        assert!(!parsed.is_set("help"));
    }

    #[test]
    fn single_dash_tokens_are_unknown_flags() {
        // `-h`/`-V` never reach the parser; anything else short is a
        // typo rather than an alias this module should invent.
        assert_eq!(parse(&["-x"]), Err(ArgError::Unknown("-x".to_string())));
        assert_eq!(parse(&["-hV"]), Err(ArgError::Unknown("-hV".to_string())));
        assert_eq!(
            parse(&["-domain"]),
            Err(ArgError::Unknown("-domain".to_string()))
        );
    }

    #[test]
    fn a_boolean_flag_does_not_eat_the_next_argument() {
        // The reason flags are declared rather than guessed.
        let parsed = parse(&["--no-systemd", "ls"]).unwrap();
        assert!(parsed.is_set("no-systemd"));
        assert_eq!(parsed.positionals(), ["ls"]);
    }

    #[test]
    fn flags_and_positionals_mix_in_any_order() {
        let parsed = parse(&[
            "server",
            "--domain",
            "net.example.com",
            "init",
            "--no-systemd",
        ])
        .unwrap();
        assert_eq!(parsed.positionals(), ["server", "init"]);
        assert_eq!(parsed.value("domain"), Some("net.example.com"));
        assert!(parsed.is_set("no-systemd"));
    }

    #[test]
    fn a_double_dash_ends_flag_parsing() {
        // How a device named `-x` stays reachable.
        let parsed = parse(&["rm", "--", "-x", "--domain"]).unwrap();
        assert_eq!(parsed.positionals(), ["rm", "-x", "--domain"]);
        assert_eq!(parsed.value("domain"), None);
    }

    #[test]
    fn a_lone_dash_is_a_positional() {
        let parsed = parse(&["-"]).unwrap();
        assert_eq!(parsed.positionals(), ["-"]);
    }

    #[test]
    fn a_value_that_looks_like_a_flag_is_refused() {
        // `--port -1` is a typo, not a port; taking `-1` as the value
        // would configure something absurd.
        assert_eq!(
            parse(&["--port", "-1"]),
            Err(ArgError::MissingValue("port"))
        );
        assert_eq!(
            parse(&["--domain", "--no-systemd"]),
            Err(ArgError::MissingValue("domain"))
        );
        // Spelled with `=`, the same text is a deliberate value.
        assert_eq!(parse(&["--port=-1"]).unwrap().value("port"), Some("-1"));
    }

    #[test]
    fn a_value_flag_at_the_end_needs_its_value() {
        assert_eq!(parse(&["--domain"]), Err(ArgError::MissingValue("domain")));
        assert_eq!(parse(&["--domain="]), Err(ArgError::EmptyValue("domain")));
    }

    #[test]
    fn a_boolean_flag_takes_no_value() {
        assert_eq!(
            parse(&["--no-systemd=true"]),
            Err(ArgError::UnexpectedValue("no-systemd"))
        );
    }

    #[test]
    fn repeating_a_flag_is_an_error_not_last_wins() {
        // Quietly picking one would build a network nobody asked for.
        assert_eq!(
            parse(&["--subnet", "10.100.0.0/24", "--subnet", "192.168.7.0/24"]),
            Err(ArgError::Duplicate("subnet"))
        );
        assert_eq!(
            parse(&["--no-systemd", "--no-systemd"]),
            Err(ArgError::Duplicate("no-systemd"))
        );
    }

    #[test]
    fn unknown_flags_are_reported_as_typed() {
        assert_eq!(
            parse(&["--domian", "net.example.com"]),
            Err(ArgError::Unknown("--domian".to_string()))
        );
        assert_eq!(
            parse(&["--domian=x"]),
            Err(ArgError::Unknown("--domian".to_string()))
        );
    }

    #[test]
    fn required_flags_report_themselves() {
        let parsed = parse(&["--domain", "net.example.com"]).unwrap();
        assert_eq!(parsed.require("domain"), Ok("net.example.com"));
        assert_eq!(parsed.require("subnet"), Err(ArgError::Required("subnet")));
    }

    #[test]
    fn values_keep_whatever_they_contain() {
        // Korean device names, paths with spaces, `=` inside a value.
        let spec = [Flag::value("name")];
        let parsed = ParsedArgs::parse(&argv(&["--name", "맥북"]), &spec).unwrap();
        assert_eq!(parsed.value("name"), Some("맥북"));

        let parsed = ParsedArgs::parse(&argv(&["--name=a=b"]), &spec).unwrap();
        assert_eq!(parsed.value("name"), Some("a=b"));

        let parsed = ParsedArgs::parse(&argv(&["--name", "my mac"]), &spec).unwrap();
        assert_eq!(parsed.value("name"), Some("my mac"));
    }

    #[test]
    fn errors_say_what_to_fix() {
        assert_eq!(
            ArgError::Unknown("--domian".to_string()).to_string(),
            "unknown flag --domian"
        );
        assert_eq!(
            ArgError::MissingValue("domain").to_string(),
            "--domain needs a value"
        );
        assert_eq!(
            ArgError::EmptyValue("domain").to_string(),
            "--domain needs a non-empty value"
        );
        assert_eq!(
            ArgError::UnexpectedValue("no-systemd").to_string(),
            "--no-systemd does not take a value"
        );
        assert_eq!(
            ArgError::Duplicate("subnet").to_string(),
            "--subnet was given more than once"
        );
        assert_eq!(
            ArgError::Required("domain").to_string(),
            "--domain is required"
        );
    }
}
