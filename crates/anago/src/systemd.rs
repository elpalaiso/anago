//! The systemd unit (DESIGN.md §6.1 step 4).
//!
//! The unit text is a pure function of the paths it refers to, so what
//! ends up in `/etc/systemd/system/anago.service` is a unit test rather
//! than something discovered on a VPS. Installing it and asking
//! `systemctl` to start it are the impure half, and need a real
//! machine.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the unit goes, and what `systemctl` calls it.
pub const UNIT_NAME: &str = "anago.service";
pub const UNIT_DIR: &str = "/etc/systemd/system";

/// Full path of the installed unit.
pub fn unit_path(dir: &Path) -> PathBuf {
    dir.join(UNIT_NAME)
}

/// The unit text.
///
/// Runs as root: the process configures a WireGuard interface and binds
/// :443, and dropping to a user would mean handing that user
/// `CAP_NET_ADMIN` anyway. What it gives up instead is everything it
/// does not need — the filesystem is read-only apart from the two
/// directories anago owns.
///
/// The binary, the certificate, and the key are bind-mounted in
/// read-only, and `ProtectHome=` is `tmpfs` rather than `yes`.
///
/// That combination is deliberate. `server init` runs as root and
/// accepts any path, so `--tls-cert /root/fullchain.pem` is a normal
/// thing to type — but `ProtectHome=yes` makes `/root` *inaccessible*,
/// and systemd will not put a bind destination underneath an
/// inaccessible directory. `tmpfs` instead gives the service an empty
/// `/root` and `/home` that binds can be mounted into, which is the
/// documented way to expose exactly one file from a home directory
/// (systemd.exec(5), "Sandboxing"). `PrivateTmp=yes` hides a
/// `/tmp/key.pem` the same way, and the same bind brings it back.
///
/// The executable gets the same treatment: `anago` installed under a
/// home directory would otherwise be hidden from its own unit.
///
/// A successful init has to mean a hub that can actually start.
pub fn unit_text(
    exec: &Path,
    state_dir: &Path,
    wg_dir: &Path,
    tls_cert: &Path,
    tls_key: &Path,
) -> String {
    format!(
        "\
[Unit]
Description=anago — self-hosted WireGuard private network
Documentation=https://github.com/elpalaiso/anago
# The hub is useless before the network is up, and it dials nothing at
# start, so `network-online` is the honest dependency.
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
ExecStart={exec} server run
Restart=on-failure
RestartSec=5s
# A control plane that cannot answer is worse than one that restarts.
NoNewPrivileges=yes
# tmpfs, not yes: an empty home the binds below can mount into.
ProtectHome=tmpfs
ProtectSystem=strict
ReadWritePaths={state_dir} {wg_dir}
# Reachable even though the sandbox hides where they live.
BindReadOnlyPaths={exec} {tls_cert} {tls_key}
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
",
        exec = escape(exec),
        state_dir = escape(state_dir),
        wg_dir = escape(wg_dir),
        tls_cert = escape(tls_cert),
        tls_key = escape(tls_key)
    )
}

/// Renders a path the way systemd reads one.
///
/// Two rules, both easy to miss and both silent when missed: `%` starts
/// a specifier expansion, so it has to be doubled; and a path with
/// whitespace would otherwise split into separate arguments — in
/// `ExecStart` that means running the wrong program, in a path list it
/// means guarding the wrong directory.
pub fn escape(path: &Path) -> String {
    let text = path.to_string_lossy().replace('%', "%%");
    let needs_quotes = text
        .chars()
        .any(|c| c.is_whitespace() || c == '"' || c == '\\');
    if !needs_quotes {
        return text;
    }
    let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Writes the unit, reloads systemd, and enables it for boot.
///
/// **Human verification needed**: needs systemd and root.
pub fn install(
    exec: &Path,
    state_dir: &Path,
    wg_dir: &Path,
    tls_cert: &Path,
    tls_key: &Path,
    unit_dir: &Path,
) -> Result<PathBuf, SystemdError> {
    let path = unit_path(unit_dir);
    let text = unit_text(exec, state_dir, wg_dir, tls_cert, tls_key);
    // Not `create_new`: reinstalling over an older unit is the point of
    // an upgrade, and the file holds no secret.
    std::fs::write(&path, text).map_err(|e| SystemdError::Write {
        path: path.clone(),
        source: e.to_string(),
    })?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", "--now", UNIT_NAME])?;
    Ok(path)
}

/// Whether this machine even has systemd — checked before offering to
/// install a unit that nothing would read.
pub fn is_available() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

/// **Human verification needed**: runs `systemctl`.
fn systemctl(args: &[&str]) -> Result<(), SystemdError> {
    let output = Command::new("systemctl")
        .args(args)
        .output()
        .map_err(|e| SystemdError::Run {
            line: format!("systemctl {}", args.join(" ")),
            source: e.to_string(),
        })?;
    if output.status.success() {
        return Ok(());
    }
    Err(SystemdError::Failed {
        line: format!("systemctl {}", args.join(" ")),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

/// Why the unit could not be installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemdError {
    Write { path: PathBuf, source: String },
    Run { line: String, source: String },
    Failed { line: String, stderr: String },
}

impl fmt::Display for SystemdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SystemdError::Write { path, source } => {
                write!(f, "could not write {}: {source}", path.display())
            }
            SystemdError::Run { line, source } => write!(f, "could not run `{line}`: {source}"),
            SystemdError::Failed { line, stderr } => {
                write!(f, "`{line}` failed")?;
                if !stderr.is_empty() {
                    write!(f, ": {stderr}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for SystemdError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn text() -> String {
        unit_text(
            Path::new("/usr/local/bin/anago"),
            Path::new("/var/lib/anago"),
            Path::new("/etc/wireguard"),
            Path::new("/etc/ssl/anago/fullchain.pem"),
            Path::new("/etc/ssl/anago/privkey.pem"),
        )
    }

    #[test]
    fn the_unit_starts_the_serving_command() {
        assert!(
            text().contains("ExecStart=/usr/local/bin/anago server run"),
            "{}",
            text()
        );
        // The binary's own path, not a guess about where it was
        // installed.
        let other = unit_text(
            Path::new("/opt/anago/bin/anago"),
            Path::new("/var/lib/anago"),
            Path::new("/etc/wireguard"),
            Path::new("/etc/ssl/anago/fullchain.pem"),
            Path::new("/etc/ssl/anago/privkey.pem"),
        );
        assert!(
            other.contains("ExecStart=/opt/anago/bin/anago server run"),
            "{other}"
        );
    }

    #[test]
    fn the_unit_waits_for_the_network_and_comes_back_after_a_crash() {
        let text = text();
        assert!(text.contains("After=network-online.target"), "{text}");
        assert!(text.contains("Wants=network-online.target"), "{text}");
        assert!(text.contains("Restart=on-failure"), "{text}");
        assert!(text.contains("RestartSec=5s"), "{text}");
        assert!(
            text.contains("WantedBy=multi-user.target"),
            "start at boot: {text}"
        );
    }

    #[test]
    fn the_unit_can_write_exactly_the_two_directories_anago_owns() {
        // ProtectSystem=strict without ReadWritePaths would leave the
        // hub unable to save a join.
        let text = text();
        assert!(text.contains("ProtectSystem=strict"), "{text}");
        assert!(
            text.contains("ReadWritePaths=/var/lib/anago /etc/wireguard"),
            "{text}"
        );
        assert!(text.contains("NoNewPrivileges=yes"), "{text}");
        assert!(text.contains("ProtectHome=tmpfs"), "{text}");
    }

    #[test]
    fn the_writable_paths_follow_the_arguments() {
        let text = unit_text(
            Path::new("/usr/local/bin/anago"),
            Path::new("/srv/anago"),
            Path::new("/usr/local/etc/wireguard"),
            Path::new("/etc/ssl/anago/fullchain.pem"),
            Path::new("/etc/ssl/anago/privkey.pem"),
        );
        assert!(
            text.contains("ReadWritePaths=/srv/anago /usr/local/etc/wireguard"),
            "{text}"
        );
    }

    #[test]
    fn a_certificate_in_a_home_directory_is_still_reachable() {
        // `ProtectHome=yes` hides /root outright, and systemd refuses
        // to place a bind destination under an inaccessible directory —
        // so the bind alone would not have helped. `tmpfs` gives an
        // empty /root the bind can mount into.
        let text = unit_text(
            Path::new("/root/bin/anago"),
            Path::new("/var/lib/anago"),
            Path::new("/etc/wireguard"),
            Path::new("/root/fullchain.pem"),
            Path::new("/tmp/privkey.pem"),
        );
        assert!(text.contains("ProtectHome=tmpfs"), "{text}");
        assert!(!text.contains("ProtectHome=yes"), "{text}");
        assert!(
            text.contains("BindReadOnlyPaths=/root/bin/anago /root/fullchain.pem /tmp/privkey.pem"),
            "the binary and both files have to come in: {text}"
        );
        assert!(text.contains("PrivateTmp=yes"), "{text}");
    }

    #[test]
    fn paths_are_escaped_the_way_systemd_reads_them() {
        // `%` starts a specifier, and whitespace splits arguments —
        // both silent failures that would run the wrong program.
        assert_eq!(
            escape(Path::new("/usr/local/bin/anago")),
            "/usr/local/bin/anago"
        );
        assert_eq!(escape(Path::new("/opt/100%/anago")), "/opt/100%%/anago");
        assert_eq!(
            escape(Path::new("/opt/my anago/bin/anago")),
            "\"/opt/my anago/bin/anago\""
        );
        assert_eq!(
            escape(Path::new("/opt/a\"b/anago")),
            "\"/opt/a\\\"b/anago\""
        );
        assert_eq!(escape(Path::new("/opt/a\\b")), "\"/opt/a\\\\b\"");
    }

    #[test]
    fn an_awkward_install_path_still_starts_the_right_binary() {
        let text = unit_text(
            Path::new("/opt/my anago/anago"),
            Path::new("/var/lib/my anago"),
            Path::new("/etc/wireguard"),
            Path::new("/etc/ssl/100% sure/cert.pem"),
            Path::new("/etc/ssl/key.pem"),
        );
        assert!(
            text.contains("ExecStart=\"/opt/my anago/anago\" server run"),
            "{text}"
        );
        assert!(
            text.contains("ReadWritePaths=\"/var/lib/my anago\" /etc/wireguard"),
            "{text}"
        );
        assert!(
            text.contains(
                "BindReadOnlyPaths=\"/opt/my anago/anago\" \"/etc/ssl/100%% sure/cert.pem\" /etc/ssl/key.pem"
            ),
            "{text}"
        );
    }

    #[test]
    fn the_unit_is_a_complete_ini_file() {
        let text = text();
        for section in ["[Unit]", "[Service]", "[Install]"] {
            assert_eq!(text.matches(section).count(), 1, "{section} in {text}");
        }
        assert!(text.ends_with("WantedBy=multi-user.target\n"), "{text}");
        for line in text.lines().filter(|line| !line.is_empty()) {
            assert!(
                line.starts_with('[') || line.starts_with('#') || line.contains('='),
                "unexpected line {line:?}"
            );
        }
    }

    #[test]
    fn the_unit_lands_where_systemd_looks() {
        assert_eq!(
            unit_path(Path::new(UNIT_DIR)),
            Path::new("/etc/systemd/system/anago.service")
        );
    }

    #[test]
    fn failures_quote_the_line_a_person_can_retry() {
        let e = SystemdError::Failed {
            line: "systemctl enable --now anago.service".to_string(),
            stderr: "Failed to enable unit: Unit file does not exist.".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "`systemctl enable --now anago.service` failed: \
             Failed to enable unit: Unit file does not exist."
        );
    }
}
