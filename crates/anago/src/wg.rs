//! Talking to WireGuard's own tools (DESIGN.md §4 principle 1, §13).
//!
//! anago never touches crypto or netlink: it builds `wg`/`wg-quick`
//! command lines, runs them, and reads what they print. So everything
//! that can be decided without a running system — how each command line
//! is assembled, whether a key looks like a key, where a binary sits on
//! `PATH`, what to tell someone who has not installed the tools — is a
//! pure function tested below.
//!
//! What is left unavoidably impure is spawning the processes. Those
//! functions need a machine with wireguard-tools installed, so they are
//! marked for human verification rather than mocked into a test that
//! would only assert that the mock was called.

use std::ffi::OsStr;
use std::fmt;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anago_core::state::PrivateKey;

/// The tools anago drives.
pub const WG: &str = "wg";
pub const WG_QUICK: &str = "wg-quick";

/// A command line, assembled but not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
}

impl Cmd {
    fn new(program: &str, args: &[&str]) -> Cmd {
        Cmd {
            program: program.to_string(),
            args: args.iter().map(|arg| arg.to_string()).collect(),
        }
    }

    fn with_path(program: &str, args: &[&str], path: &Path) -> Cmd {
        let mut cmd = Cmd::new(program, args);
        cmd.args.push(path.to_string_lossy().into_owned());
        cmd
    }

    /// The line as a person would type it — for error messages that ask
    /// someone to run it themselves.
    pub fn display(&self) -> String {
        let mut line = self.program.clone();
        for arg in &self.args {
            line.push(' ');
            line.push_str(arg);
        }
        line
    }

    fn to_command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(self.args.iter().map(OsStr::new));
        command
    }
}

/// `wg genkey` — prints a new private key.
pub fn genkey() -> Cmd {
    Cmd::new(WG, &["genkey"])
}

/// `wg pubkey` — reads a private key on stdin, prints its public half.
pub fn pubkey() -> Cmd {
    Cmd::new(WG, &["pubkey"])
}

/// `wg-quick up <config>`. Given the config path rather than an
/// interface name so a test — or a second network — is not forced
/// through `/etc/wireguard`.
pub fn quick_up(config: &Path) -> Cmd {
    Cmd::with_path(WG_QUICK, &["up"], config)
}

/// `wg-quick down <config>`.
pub fn quick_down(config: &Path) -> Cmd {
    Cmd::with_path(WG_QUICK, &["down"], config)
}

/// `wg-quick strip <config>` — the same file with the keys plain `wg`
/// does not understand (`Address`, `DNS`, `PostUp`) removed, which is
/// what [`syncconf`] must be fed.
pub fn quick_strip(config: &Path) -> Cmd {
    Cmd::with_path(WG_QUICK, &["strip"], config)
}

/// `wg syncconf <interface> <stripped>` — applies a changed peer list
/// to a running interface without dropping existing tunnels, which
/// `wg-quick down`/`up` would.
pub fn syncconf(interface: &str, stripped: &Path) -> Cmd {
    let mut cmd = Cmd::new(WG, &["syncconf"]);
    cmd.args.push(interface.to_string());
    cmd.args.push(stripped.to_string_lossy().into_owned());
    cmd
}

/// `wg show <interface> dump` — machine-readable peer state, including
/// the last handshake `anago ls` shows on the server.
pub fn show_dump(interface: &str) -> Cmd {
    let mut cmd = Cmd::new(WG, &["show"]);
    cmd.args.push(interface.to_string());
    cmd.args.push("dump".to_string());
    cmd
}

/// A WireGuard key as the tools print it: 32 bytes, base64, 44
/// characters ending in `=`.
///
/// Checked here so a mistyped path or an error message on stdout cannot
/// end up in a config file as if it were a key.
///
/// A rejection reports the length and nothing else. The input on this
/// path is `wg genkey` output — a private key — and a malformed one is
/// still secret material, so no part of it may reach an error message
/// or a log line (§7.1).
pub fn parse_key(output: &str) -> Result<String, WgError> {
    let key = output.trim();
    let valid = key.len() == 44
        && key.ends_with('=')
        && key[..43]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/');
    if valid {
        Ok(key.to_string())
    } else {
        Err(WgError::BadKey {
            length: key.chars().count(),
        })
    }
}

/// Which install instructions to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Linux,
    Other,
}

/// Maps `std::env::consts::OS` — passed in, so the mapping is testable
/// without pretending to be another machine.
pub fn platform_from(os: &str) -> Platform {
    match os {
        "macos" => Platform::MacOs,
        "linux" => Platform::Linux,
        _ => Platform::Other,
    }
}

/// What to tell someone whose machine has no `wg` yet (§13: the tools
/// come from brew on macOS and the distro package elsewhere).
pub fn install_hint(platform: Platform) -> &'static str {
    match platform {
        Platform::MacOs => "install it with: brew install wireguard-tools",
        Platform::Linux => {
            "install the wireguard-tools package: apt install wireguard-tools \
             (Debian/Ubuntu), dnf install wireguard-tools (Fedora), \
             pacman -S wireguard-tools (Arch)"
        }
        Platform::Other => {
            "anago needs WireGuard's userspace tools (wg, wg-quick); \
             Windows is not supported in v1 — use WSL2"
        }
    }
}

/// Finds an executable on a `PATH`-shaped string.
///
/// Empty entries are skipped rather than treated as the current
/// directory: a tool found there would depend on where the user
/// happened to `cd`, which is not something to run as root.
pub fn find_in_path(path_var: &str, program: &str) -> Option<PathBuf> {
    path_var
        .split(':')
        .filter(|dir| !dir.is_empty())
        .map(|dir| Path::new(dir).join(program))
        .find(|candidate| is_executable_file(candidate))
}

fn is_executable_file(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// Checks that both tools are present, naming the missing one and how
/// to get it.
pub fn check_tools(path_var: &str, platform: Platform) -> Result<(), WgError> {
    for tool in [WG, WG_QUICK] {
        if find_in_path(path_var, tool).is_none() {
            return Err(WgError::NotFound {
                tool,
                hint: install_hint(platform),
            });
        }
    }
    Ok(())
}

/// [`check_tools`] against this process's real environment.
pub fn check_tools_from_env() -> Result<(), WgError> {
    let path = std::env::var("PATH").unwrap_or_default();
    check_tools(&path, platform_from(std::env::consts::OS))
}

/// Generates a keypair by running the tools — the private key is made
/// on this machine and, for a device, never leaves it (§6.2).
///
/// **Human verification needed**: this spawns real processes, so it is
/// exercised on a machine with wireguard-tools rather than in a unit
/// test.
pub fn generate_keypair() -> Result<(PrivateKey, String), WgError> {
    let private = run(&genkey(), None)?;
    let private = parse_key(&private)?;
    let public = run(&pubkey(), Some(&private))?;
    let public = parse_key(&public)?;
    Ok((PrivateKey::new(private), public))
}

/// Runs a command, optionally writing `stdin`, and returns its stdout.
///
/// **Human verification needed** — see [`generate_keypair`].
pub fn run(cmd: &Cmd, stdin: Option<&str>) -> Result<String, WgError> {
    let mut command = cmd.to_command();
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });

    let mut child = command.spawn().map_err(|e| WgError::Spawn {
        line: cmd.display(),
        source: e.to_string(),
    })?;
    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().expect("stdin was piped");
        pipe.write_all(input.as_bytes())
            .map_err(|e| WgError::Spawn {
                line: cmd.display(),
                source: e.to_string(),
            })?;
        // Dropped here so the child sees EOF instead of waiting.
    }

    let output = child.wait_with_output().map_err(|e| WgError::Spawn {
        line: cmd.display(),
        source: e.to_string(),
    })?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(WgError::Failed {
            line: cmd.display(),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

/// What can go wrong between anago and the WireGuard tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WgError {
    /// A tool is not on `PATH`.
    NotFound {
        tool: &'static str,
        hint: &'static str,
    },
    /// The process could not be started at all.
    Spawn { line: String, source: String },
    /// It ran and refused.
    Failed {
        line: String,
        status: Option<i32>,
        stderr: String,
    },
    /// Output that should have been a key was not one. Carries the
    /// length only — the output itself may be a private key.
    BadKey { length: usize },
}

impl fmt::Display for WgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WgError::NotFound { tool, hint } => {
                write!(f, "`{tool}` is not installed or not on PATH — {hint}")
            }
            WgError::Spawn { line, source } => write!(f, "could not run `{line}`: {source}"),
            WgError::Failed {
                line,
                status,
                stderr,
            } => {
                write!(f, "`{line}` failed")?;
                if let Some(code) = status {
                    write!(f, " (exit {code})")?;
                }
                if !stderr.is_empty() {
                    write!(f, ": {stderr}")?;
                }
                Ok(())
            }
            WgError::BadKey { length } => write!(
                f,
                "expected a WireGuard key (44 base64 characters), got {length} characters"
            ),
        }
    }
}

impl std::error::Error for WgError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> TempDir {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("anago-wg-{}-{unique}", std::process::id()));
            fs::create_dir_all(&path).expect("temp dir");
            TempDir { path }
        }

        /// Writes a file with the given mode and returns its directory.
        fn tool(&self, name: &str, mode: u32) -> &Path {
            let path = self.path.join(name);
            fs::write(&path, "#!/bin/sh\n").expect("write");
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn key(fill: &str) -> String {
        let mut key = fill.repeat(44);
        key.truncate(43);
        key.push('=');
        key
    }

    #[test]
    fn command_lines_are_what_the_docs_say_to_run() {
        assert_eq!(genkey().display(), "wg genkey");
        assert_eq!(pubkey().display(), "wg pubkey");
        assert_eq!(
            quick_up(Path::new("/etc/wireguard/anago.conf")).display(),
            "wg-quick up /etc/wireguard/anago.conf"
        );
        assert_eq!(
            quick_down(Path::new("/etc/wireguard/anago.conf")).display(),
            "wg-quick down /etc/wireguard/anago.conf"
        );
        assert_eq!(
            quick_strip(Path::new("/etc/wireguard/anago.conf")).display(),
            "wg-quick strip /etc/wireguard/anago.conf"
        );
        assert_eq!(
            syncconf("anago", Path::new("/tmp/stripped.conf")).display(),
            "wg syncconf anago /tmp/stripped.conf"
        );
        assert_eq!(show_dump("anago").display(), "wg show anago dump");
    }

    #[test]
    fn commands_carry_their_arguments_separately() {
        // Not a shell string: a path with a space must stay one argument.
        let cmd = quick_up(Path::new("/tmp/my configs/anago.conf"));
        assert_eq!(cmd.program, "wg-quick");
        assert_eq!(cmd.args, ["up", "/tmp/my configs/anago.conf"]);
    }

    #[test]
    fn syncconf_is_preferred_over_a_restart() {
        // `wg-quick down`/`up` would drop every live tunnel; syncconf
        // applies a new peer list in place.
        let cmd = syncconf("anago", Path::new("/tmp/s.conf"));
        assert_eq!(cmd.args[0], "syncconf");
        assert_eq!(cmd.args[1], "anago");
    }

    #[test]
    fn a_key_is_accepted_with_or_without_its_newline() {
        let expected = key("A");
        assert_eq!(parse_key(&expected).unwrap(), expected);
        assert_eq!(parse_key(&format!("{expected}\n")).unwrap(), expected);
        assert_eq!(parse_key(&format!("  {expected}  \n")).unwrap(), expected);
        // The whole base64 alphabet.
        let mixed = format!(
            "{}=",
            "aZ09+/".repeat(8).chars().take(43).collect::<String>()
        );
        assert_eq!(parse_key(&mixed).unwrap(), mixed);
    }

    #[test]
    fn output_that_is_not_a_key_is_refused() {
        // Otherwise an error message on stdout lands in a config file
        // as if it were a key.
        for output in [
            "",
            "\n",
            "wg: command not found",
            "short=",
            &key("A")[..43],
            &format!("{}x", &key("A")[..43]),
            &format!("{}!", &key("A")[..43]),
        ] {
            assert!(parse_key(output).is_err(), "accepted {output:?}");
        }
    }

    #[test]
    fn a_rejected_key_never_reaches_the_error_message() {
        // The input here is `wg genkey` output: even malformed, it is
        // secret material, so not one fragment may be echoed.
        let secret = key("S9x+/Az");
        let e = parse_key(&format!("{secret} trailing")).unwrap_err();
        let message = e.to_string();
        assert_eq!(
            e,
            WgError::BadKey {
                length: secret.chars().count() + 9
            }
        );
        let chars: Vec<char> = secret.chars().collect();
        for window in chars.windows(4) {
            let fragment: String = window.iter().collect();
            assert!(
                !message.contains(&fragment),
                "leaked {fragment:?} in {message}"
            );
        }
        assert_eq!(
            message,
            "expected a WireGuard key (44 base64 characters), got 53 characters"
        );
    }

    #[test]
    fn install_hints_match_the_platform() {
        assert_eq!(platform_from("macos"), Platform::MacOs);
        assert_eq!(platform_from("linux"), Platform::Linux);
        assert_eq!(platform_from("windows"), Platform::Other);
        assert_eq!(platform_from("freebsd"), Platform::Other);

        assert!(install_hint(Platform::MacOs).contains("brew install wireguard-tools"));
        assert!(install_hint(Platform::Linux).contains("apt install wireguard-tools"));
        assert!(install_hint(Platform::Linux).contains("dnf"));
        assert!(install_hint(Platform::Other).contains("WSL2"));
    }

    #[test]
    fn finds_a_tool_on_path() {
        let dir = TempDir::new();
        let bin = dir.tool("wg", 0o755).to_string_lossy().into_owned();

        assert_eq!(find_in_path(&bin, "wg"), Some(Path::new(&bin).join("wg")));
        assert_eq!(find_in_path(&bin, "wg-quick"), None);
        // Earlier entries win.
        let path = format!("/nonexistent-anago:{bin}");
        assert_eq!(find_in_path(&path, "wg"), Some(Path::new(&bin).join("wg")));
    }

    #[test]
    fn a_non_executable_file_does_not_count() {
        let dir = TempDir::new();
        let bin = dir.tool("wg", 0o644).to_string_lossy().into_owned();
        assert_eq!(find_in_path(&bin, "wg"), None);
    }

    #[test]
    fn empty_path_entries_are_skipped_not_read_as_the_cwd() {
        // A tool picked up from "." would depend on where the user
        // stood — not something to run as root.
        let dir = TempDir::new();
        let bin = dir.tool("wg", 0o755).to_string_lossy().into_owned();
        assert_eq!(find_in_path("", "wg"), None);
        assert_eq!(find_in_path("::", "wg"), None);
        assert_eq!(
            find_in_path(&format!(":{bin}:"), "wg"),
            Some(Path::new(&bin).join("wg"))
        );
    }

    #[test]
    fn a_missing_tool_is_named_with_how_to_get_it() {
        let dir = TempDir::new();
        let bin = dir.tool("wg", 0o755).to_string_lossy().into_owned();

        // wg is there, wg-quick is not.
        let e = check_tools(&bin, Platform::MacOs).unwrap_err();
        assert_eq!(
            e,
            WgError::NotFound {
                tool: WG_QUICK,
                hint: install_hint(Platform::MacOs),
            }
        );
        assert!(
            e.to_string().starts_with("`wg-quick` is not installed"),
            "{e}"
        );
        assert!(e.to_string().contains("brew install"), "{e}");

        // Neither: the first missing one is reported.
        let e = check_tools("/nonexistent-anago", Platform::Linux).unwrap_err();
        assert!(matches!(e, WgError::NotFound { tool: WG, .. }), "{e:?}");

        dir.tool("wg-quick", 0o755);
        assert_eq!(check_tools(&bin, Platform::MacOs), Ok(()));
    }

    #[test]
    fn failures_quote_the_line_a_person_can_retry() {
        let e = WgError::Failed {
            line: "wg-quick up /etc/wireguard/anago.conf".to_string(),
            status: Some(1),
            stderr: "RTNETLINK answers: Operation not permitted".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "`wg-quick up /etc/wireguard/anago.conf` failed (exit 1): \
             RTNETLINK answers: Operation not permitted"
        );

        let e = WgError::Spawn {
            line: "wg genkey".to_string(),
            source: "No such file or directory".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "could not run `wg genkey`: No such file or directory"
        );
    }
}
