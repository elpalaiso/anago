//! The systemd units: the hub's (DESIGN.md §6.1 step 4) and the sync
//! timer's pair (§8).
//!
//! Every unit's text is a pure function of the paths it refers to, so
//! what ends up in `/etc/systemd/system` is a unit test rather than
//! something discovered on a VPS. Installing them and asking
//! `systemctl` to start them are the impure half, and need a real
//! machine.
//!
//! All three are system units. The hub binds :443 and configures a
//! WireGuard interface; sync reconfigures one and reads a device file
//! that is 0600 to whoever joined. Nothing here would work as a
//! `--user` unit, which is the same reason the mac side installs a
//! `LaunchDaemon` rather than a `LaunchAgent` (§8).
//!
//! **Human verification needed**: the `:` prefix on every `ExecStart=`
//! needs systemd 231 (2016) or newer. Older systemd does not know the
//! prefix and reads it as part of the executable path, which it then
//! refuses for not being absolute — a loud failure at install time
//! rather than a quiet one later, but still one only a real machine
//! reports.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Where the units go, and what `systemctl` calls them.
pub const UNIT_NAME: &str = "anago.service";
pub const UNIT_DIR: &str = "/etc/systemd/system";

/// The sync timer's pair (§8).
///
/// **System units, not `--user` ones.** `sync` rewrites
/// `/etc/wireguard/anago.conf` and hands it to `wg syncconf`, which
/// needs `CAP_NET_ADMIN`; a user unit would have neither that nor the
/// right to read a device file that is 0600 to its owner. This is the
/// same reason the mac side installs a `LaunchDaemon` rather than a
/// `LaunchAgent` (§8), so both platforms answer the question the same
/// way, and `UNIT_DIR` is the system directory for these two as well.
///
/// The names share the `anago-sync` stem on purpose: it is what
/// `systemctl list-timers 'anago-sync*'` matches, and it is what lets
/// the timer name the service it starts (§8).
// The four pieces below are the whole text of the sync timer, and
// they are pure: what `--install-timer` writes is decided and tested
// here, and the slice that installs them adds only the writing.
#[allow(dead_code)]
pub const SYNC_SERVICE: &str = "anago-sync.service";
#[allow(dead_code)]
pub const SYNC_TIMER: &str = "anago-sync.timer";

/// Full path of an installed unit.
pub fn unit_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(name)
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
) -> Result<String, Unusable> {
    Ok(format!(
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
# The leading `:` turns off $-expansion for this command line. A path
# may legally hold a dollar sign, and without the prefix `${{X}}` would
# be replaced — with nothing at all, if X is unset — so the unit would
# start a different binary or read a different certificate than the one
# `server init` was given.
ExecStart=:{exec} server run
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
        exec = bind(exec)?,
        state_dir = escape(state_dir)?,
        wg_dir = escape(wg_dir)?,
        tls_cert = bind(tls_cert)?,
        tls_key = bind(tls_key)?
    ))
}

/// Renders a path the way systemd reads one.
///
/// Two rules, both easy to miss and both silent when missed: `%` starts
/// a specifier expansion, so it has to be doubled; and a path with
/// whitespace would otherwise split into separate arguments — in
/// `ExecStart` that means running the wrong program, in a path list it
/// means guarding the wrong directory.
///
/// `$` is deliberately left as it is. It means nothing in a path list
/// or any other setting — only a command line expands variables — so
/// doubling it here would put a literal `$$` in `BindPaths=`. The two
/// `ExecStart=` lines turn expansion off with a `:` prefix instead,
/// which keeps them spelling the path exactly the way the settings
/// around them do.
///
/// And two paths it will not render at all — see [`Unusable`]. Both
/// arrive the same way: `server init` and `sync --install-timer` take
/// paths from the command line, and a Unix filename may hold anything
/// but a slash and a NUL.
pub fn escape(path: &Path) -> Result<String, Unusable> {
    let Some(text) = path.to_str() else {
        return Err(Unusable::NotText(path.to_path_buf()));
    };
    if text.chars().any(char::is_control) {
        return Err(Unusable::NotPrintable(path.to_path_buf()));
    }
    let text = text.replace('%', "%%");
    let needs_quotes = text
        .chars()
        .any(|c| c.is_whitespace() || c == '"' || c == '\\');
    if !needs_quotes {
        return Ok(text);
    }
    let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("\"{escaped}\""))
}

/// Renders a path for `BindPaths=` or `BindReadOnlyPaths=`.
///
/// Everything [`escape`] does, and one more refusal. A bind entry is
/// `source:destination:options`, so `/home/jo/a:b` is read as a bind of
/// `/home/jo/a` onto a destination `b` — and systemd then **drops the
/// entry**, because a destination has to be absolute.
///
/// Dropping it is the bad part. The unit still installs, still starts,
/// and still has `ProtectHome=tmpfs` hiding the very directory the bind
/// was there to bring back — so the timer fails every time it fires,
/// and the file a person opens to find out why looks correct.
///
/// Refused rather than escaped or quoted. A backslash or a pair of
/// quotes may well carry a colon past that parser, but "may well" is
/// not something to bake into a unit that runs as root on a machine
/// this code cannot try. A colon in a directory name is rare; a timer
/// that fails silently forever is not worth the trade.
fn bind(path: &Path) -> Result<String, Unusable> {
    let text = escape(path)?;
    if text.contains(':') {
        return Err(Unusable::NotBindable(path.to_path_buf()));
    }
    Ok(text)
}

/// A path no unit file can name.
///
/// Refusing beats rendering something close: a unit is a file a person
/// opens to find out what runs as root on their machine, and each of
/// these turns it into a file that says one thing and means another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unusable {
    /// No directory to open for it — see [`writable_dir`].
    NoDirectory(PathBuf),
    /// A colon, in a path that has to go into a bind list — see
    /// [`bind`]. Only there: a colon means nothing in `ExecStart=` or
    /// in `ReadWritePaths=`, and a path that never reaches a bind is
    /// rendered with it intact.
    NotBindable(PathBuf),
    /// A control character. A newline is the one that bites: systemd
    /// reads a unit **one line at a time**, so no quoting survives one
    /// — the rest of the path becomes a directive of its own, and a
    /// `BindPaths=` half-line either breaks the unit or guards
    /// something nobody named. The others are refused with it because a
    /// unit is meant to be readable, and an invisible character in a
    /// path is not.
    NotPrintable(PathBuf),
    /// Not UTF-8. There is no faithful way to write it down, and
    /// `to_string_lossy` would put a *different* path in the file —
    /// one whose sandbox guards a directory that does not exist and
    /// whose `ExecStart` names a binary that is not there.
    NotText(PathBuf),
}

impl fmt::Display for Unusable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unusable::NoDirectory(path) => write!(
                f,
                "{} is not inside a directory a unit could open — a file \
                 directly in / would mean handing the run the whole filesystem",
                shown(path)
            ),
            Unusable::NotBindable(path) => write!(
                f,
                "{} has a colon in it, and a bind mount reads a colon as \
                 source:destination — systemd would drop the line and the \
                 sandbox would hide the path instead of bringing it in",
                shown(path)
            ),
            Unusable::NotPrintable(path) => write!(
                f,
                "{} has a control character in it, and a unit file is read \
                 one line at a time — no quoting survives that",
                shown(path)
            ),
            Unusable::NotText(path) => write!(
                f,
                "{} is not valid UTF-8, so a unit file could only name a \
                 different path than the one you meant",
                shown(path)
            ),
        }
    }
}

impl std::error::Error for Unusable {}

/// The offending path, written so the complaint about it stays one
/// line. A message that says "this path has a newline in it" and then
/// prints the newline is the same bug one layer up.
fn shown(path: &Path) -> String {
    path.to_string_lossy().escape_debug().to_string()
}

/// The directory a unit has to be able to write, given a file inside it.
///
/// Refused when there is no such directory to name: a relative path (a
/// unit runs from `/`, so it would resolve somewhere nobody chose), or
/// a file sitting directly in `/`. The second is the interesting one —
/// the sandbox below opens exactly the directories the run writes, and
/// a device file at `/device.json` would make that directory `/`. Then
/// `ProtectSystem=strict` still appears in the unit while granting the
/// run the whole filesystem, which is worse than no sandbox at all:
/// it reads as one.
#[allow(dead_code)]
pub fn writable_dir(file: &Path) -> Result<&Path, Unusable> {
    let dir = file
        .parent()
        .filter(|dir| dir.is_absolute() && *dir != Path::new("/"))
        .ok_or_else(|| Unusable::NoDirectory(file.to_path_buf()))?;
    Ok(dir)
}

/// The service the sync timer starts.
///
/// Refused when either file has no directory to open, or when any of
/// the three paths is one a unit file cannot name — see [`Unusable`].
/// Nothing is written before that is settled, so a `--config` nobody
/// could put in a unit leaves no half-installed timer behind.
///
/// The command line is the whole point of the file: `--quiet` and
/// `--config <absolute path>` are written out rather than inferred, so
/// opening the unit says which device this machine syncs and why the
/// run says nothing when nothing changed (§8).
///
/// Root again, and for the same reasons as the hub's unit: `wg
/// syncconf` needs `CAP_NET_ADMIN`, and the device file is 0600 to
/// whoever joined. Capabilities are left alone rather than trimmed to
/// a bounding set — the run reconfigures a kernel network interface
/// through `wg-quick`, so guessing at which of `CAP_NET_ADMIN`,
/// `CAP_CHOWN` and `CAP_DAC_OVERRIDE` it still needs is how a timer
/// starts failing on a machine nobody is watching. What it does give
/// up is the filesystem, which is where the sandbox is honest: two
/// writable directories and one read-only binary.
///
/// **Human verification needed**: that these lines still let the run do
/// its work. The text is decided here, but only a real machine says
/// whether `BindPaths=` reaches a device file under `/home` through
/// `ProtectHome=tmpfs` — `systemd-analyze security anago-sync.service`
/// lists what is on, and one actual sync proves nothing else was shut.
#[allow(dead_code)]
pub fn sync_service_text(
    exec: &Path,
    device_file: &Path,
    wg_config: &Path,
) -> Result<String, Unusable> {
    let config_dir = writable_dir(device_file)?;
    let wg_dir = writable_dir(wg_config)?;
    Ok(format!(
        "\
[Unit]
Description=anago — pull the peer list from the hub
Documentation=https://github.com/elpalaiso/anago
# No network dependency on purpose. A hub this device cannot reach is
# an ordinary silent exit 0 (§6.3) — the laptop is out of the house and
# that is fine — so ordering after `network-online.target` would buy
# nothing that the next tick does not already carry.

[Service]
Type=oneshot
# The leading `:` turns off $-expansion for this command line. A path
# may legally hold a dollar sign, and `${{X}}` in a command line would be
# replaced — with nothing at all, if X is unset. The path lists below
# expand no such thing, so without the prefix this line and BindPaths=
# could name two different directories from the same `--config`: the
# sandbox would open one and the run would read the other.
ExecStart=:{exec} sync --quiet --config {device_file}
# No Restart=. The timer is the retry policy, and it already knows how
# often. A run that ended in 401 restarted on failure would hammer the
# hub for a device it has removed.
#
# TimeoutStartSec= is not optional here: systemd disables the start
# timeout entirely for Type=oneshot. A wedged run holds the sync lock,
# and §6.3 has every later run exit quietly on that lock — so without a
# bound the timer would go silent and look healthy. The client's own
# limits are 10s to connect and 30s to read; this sits above them.
TimeoutStartSec=2min
NoNewPrivileges=yes
ProtectSystem=strict
# tmpfs, not yes: the device file usually lives under a home directory,
# which `yes` would make inaccessible — and systemd will not mount a
# bind underneath an inaccessible directory.
ProtectHome=tmpfs
# Read-write, and a bind rather than an exception, because this run
# rewrites `device.json` and takes the sync lock beside it. A bind also
# works when that directory is not under a home at all, so there is one
# rule here instead of two.
BindPaths={config_dir}
# /etc is not hidden, so an exception is enough for the WireGuard
# directory — the config, and the stripped copy written next to it.
ReadWritePaths={wg_dir}
BindReadOnlyPaths={exec}
PrivateTmp=yes
# No [Install] section. This unit is what the timer starts; enabling it
# would run one sync at boot and never another.
",
        exec = bind(exec)?,
        device_file = escape(device_file)?,
        config_dir = bind(config_dir)?,
        wg_dir = escape(wg_dir)?,
    ))
}

/// The timer that starts it.
///
/// One period governs both lines. `OnUnitActiveSec=` alone never fires
/// a first time — it measures from the last run, and there has not been
/// one — so `OnBootSec=` seeds it. On a machine that has been up longer
/// than the period, which is every machine where somebody is typing
/// `--install-timer`, that seed has already elapsed and the first sync
/// runs at once.
#[allow(dead_code)]
pub fn sync_timer_text(interval: Duration) -> String {
    let every = span(interval);
    format!(
        "\
[Unit]
Description=anago — sync the peer list every {every}
Documentation=https://github.com/elpalaiso/anago

[Timer]
OnBootSec={every}
OnUnitActiveSec={every}
Unit={SYNC_SERVICE}
# No Persistent=. It applies to calendar timers, not to this kind, and
# a laptop that was asleep has nothing to catch up on anyway: the next
# run carries everything the missed one would have (§6.3).

[Install]
WantedBy=timers.target
"
    )
}

/// A period, spelled so systemd cannot read it as something else.
///
/// A bare number is seconds to systemd, and `m` is minutes — the same
/// two readings `--interval` refuses to guess between (§8). `min`
/// leaves nothing to read twice. Whole seconds only; the parser only
/// ever produces those.
#[allow(dead_code)]
pub fn span(interval: Duration) -> String {
    let seconds = interval.as_secs();
    if seconds == 0 {
        return "0s".to_string();
    }
    if seconds.is_multiple_of(3600) {
        return format!("{}h", seconds / 3600);
    }
    if seconds.is_multiple_of(60) {
        return format!("{}min", seconds / 60);
    }
    format!("{seconds}s")
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
    let path = unit_path(unit_dir, UNIT_NAME);
    // Before the write, so a path no unit can name leaves no file.
    let text = unit_text(exec, state_dir, wg_dir, tls_cert, tls_key).map_err(SystemdError::Path)?;
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
    Path(Unusable),
    Write { path: PathBuf, source: String },
    Run { line: String, source: String },
    Failed { line: String, stderr: String },
}

impl fmt::Display for SystemdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SystemdError::Path(unusable) => write!(f, "{unusable}"),
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
        .expect("every path here is one a unit can name")
    }

    #[test]
    fn the_unit_starts_the_serving_command() {
        assert!(
            text().contains("ExecStart=:/usr/local/bin/anago server run"),
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
        )
        .unwrap();
        assert!(
            other.contains("ExecStart=:/opt/anago/bin/anago server run"),
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
        )
        .unwrap();
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
        )
        .unwrap();
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
        let rendered = |text: &str| escape(Path::new(text)).unwrap();
        assert_eq!(rendered("/usr/local/bin/anago"), "/usr/local/bin/anago");
        assert_eq!(rendered("/opt/100%/anago"), "/opt/100%%/anago");
        assert_eq!(
            rendered("/opt/my anago/bin/anago"),
            "\"/opt/my anago/bin/anago\""
        );
        assert_eq!(rendered("/opt/a\"b/anago"), "\"/opt/a\\\"b/anago\"");
        // A path ending in a backslash would continue the line if the
        // quote did not come after it.
        assert_eq!(rendered("/opt/a\\b"), "\"/opt/a\\\\b\"");
        assert_eq!(rendered("/opt/b\\"), "\"/opt/b\\\\\"");
    }

    #[test]
    fn an_awkward_install_path_still_starts_the_right_binary() {
        let text = unit_text(
            Path::new("/opt/my anago/anago"),
            Path::new("/var/lib/my anago"),
            Path::new("/etc/wireguard"),
            Path::new("/etc/ssl/100% sure/cert.pem"),
            Path::new("/etc/ssl/key.pem"),
        )
        .unwrap();
        assert!(
            text.contains("ExecStart=:\"/opt/my anago/anago\" server run"),
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
            unit_path(Path::new(UNIT_DIR), UNIT_NAME),
            Path::new("/etc/systemd/system/anago.service")
        );
    }

    /// The lines systemd acts on.
    ///
    /// Both units carry comments that name the directives they leave
    /// out — that is the point of them — so a plain `contains` cannot
    /// tell "we deliberately set no `Restart=`" from setting one.
    fn directives(text: &str) -> Vec<&str> {
        text.lines()
            .filter(|line| !line.starts_with('#') && line.contains('='))
            .collect()
    }

    fn has_directive(text: &str, key: &str) -> bool {
        directives(text).iter().any(|line| line.starts_with(key))
    }

    fn service() -> String {
        sync_service_text(
            Path::new("/usr/local/bin/anago"),
            Path::new("/home/jo/.config/anago/device.json"),
            Path::new("/etc/wireguard/anago.conf"),
        )
        .expect("every path here is one a unit can name")
    }

    #[test]
    fn the_sync_units_are_named_so_a_person_can_find_them() {
        // §8 tells people to type `systemctl list-timers 'anago-sync*'`
        // and `systemctl cat anago-sync.service`. Those are only true
        // sentences while the names below are.
        assert_eq!(SYNC_SERVICE, "anago-sync.service");
        assert_eq!(SYNC_TIMER, "anago-sync.timer");
        assert_eq!(
            SYNC_SERVICE.trim_end_matches(".service"),
            SYNC_TIMER.trim_end_matches(".timer"),
            "the glob in §8 matches one stem"
        );
        for name in [UNIT_NAME, SYNC_SERVICE, SYNC_TIMER] {
            assert!(!name.contains('/'), "{name} is a name, not a path");
        }
        assert_eq!(
            unit_path(Path::new(UNIT_DIR), SYNC_TIMER),
            Path::new("/etc/systemd/system/anago-sync.timer")
        );
    }

    #[test]
    fn these_are_system_units_because_sync_needs_root() {
        // A `--user` unit could not hand a configuration to
        // `wg syncconf`, nor read a device file that is 0600 to its
        // owner. `timers.target` is the system target; `default.target`
        // is the one a user unit would want.
        let timer = sync_timer_text(crate::cli::DEFAULT_INTERVAL);
        assert!(timer.contains("WantedBy=timers.target"), "{timer}");
        assert!(!timer.contains("default.target"), "{timer}");
        assert!(!has_directive(&timer, "WantedBy=default"), "{timer}");
        assert!(UNIT_DIR.starts_with("/etc/systemd/system"), "{UNIT_DIR}");
        // Nothing drops privileges, so nothing has to be handed back.
        let service = service();
        for line in service.lines() {
            assert!(!line.starts_with("User="), "{service}");
            assert!(!line.starts_with("Group="), "{service}");
            assert!(!line.starts_with("DynamicUser="), "{service}");
        }
    }

    #[test]
    fn the_timer_starts_the_service_and_seeds_its_own_first_run() {
        let timer = sync_timer_text(Duration::from_secs(5 * 60));
        assert!(timer.contains(&format!("Unit={SYNC_SERVICE}")), "{timer}");
        // Without OnBootSec= the timer measures from a run that has
        // never happened, and so never fires at all.
        assert!(timer.contains("OnBootSec=5min"), "{timer}");
        assert!(timer.contains("OnUnitActiveSec=5min"), "{timer}");
        // Persistent= is for calendar timers; here it would be a line
        // that reads as if it did something.
        assert!(!has_directive(&timer, "Persistent="), "{timer}");
    }

    #[test]
    fn the_default_period_is_the_one_the_command_documents() {
        // §6.3 fixes five minutes and §8 prints it in the usage text;
        // the unit must not disagree with either.
        let timer = sync_timer_text(crate::cli::DEFAULT_INTERVAL);
        assert!(timer.contains("OnUnitActiveSec=5min"), "{timer}");
        // And the ends of the accepted range land somewhere sensible.
        assert!(
            sync_timer_text(crate::cli::MIN_INTERVAL).contains("OnUnitActiveSec=1min"),
            "1m"
        );
        assert!(
            sync_timer_text(crate::cli::MAX_INTERVAL).contains("OnUnitActiveSec=24h"),
            "24h"
        );
    }

    #[test]
    fn a_period_cannot_be_read_as_seconds_by_mistake() {
        // Same trap `--interval` refuses to guess through: a bare
        // number is seconds, and `m` is minutes only if you know that.
        assert_eq!(span(Duration::from_secs(90)), "90s");
        assert_eq!(span(Duration::from_secs(5 * 60)), "5min");
        assert_eq!(span(Duration::from_secs(61)), "61s");
        assert_eq!(span(Duration::from_secs(60 * 60)), "1h");
        assert_eq!(span(Duration::from_secs(24 * 60 * 60)), "24h");
        assert_eq!(span(Duration::from_secs(90 * 60)), "90min");
        assert_eq!(span(Duration::ZERO), "0s");
        for seconds in [60u64, 61, 300, 3600, 86400] {
            let text = span(Duration::from_secs(seconds));
            assert!(
                text.ends_with('s') || text.ends_with("min") || text.ends_with('h'),
                "{text} needs a unit"
            );
        }
    }

    #[test]
    fn the_service_names_the_device_it_syncs() {
        // The reason `--quiet` and `--config` are on the command line
        // rather than sniffed from the environment (§8): opening the
        // unit answers "which device, and why is it silent?".
        assert!(
            service().contains(
                "ExecStart=:/usr/local/bin/anago sync --quiet \
                 --config /home/jo/.config/anago/device.json"
            ),
            "{}",
            service()
        );
    }

    #[test]
    fn the_service_is_started_by_the_timer_and_by_nothing_else() {
        let service = service();
        assert!(service.contains("Type=oneshot"), "{service}");
        // Enabling it would run one sync at boot and never another.
        assert!(
            !service.lines().any(|line| line == "[Install]"),
            "{service}"
        );
        assert!(!has_directive(&service, "WantedBy="), "{service}");
        // The timer is the retry policy — a 401 restarted on failure
        // would hammer the hub for a device it has already removed.
        assert!(!has_directive(&service, "Restart"), "{service}");
        // systemd disables the start timeout for oneshot units, and a
        // wedged run holds the sync lock that silences every run after
        // it (§6.3).
        assert!(service.contains("TimeoutStartSec=2min"), "{service}");
    }

    #[test]
    fn an_unreachable_hub_is_not_worth_waiting_for_the_network() {
        // §6.3 makes it an ordinary exit 0, so the sync service says
        // nothing about the network — unlike the hub's own unit, which
        // cannot serve without one.
        let service = service();
        assert!(
            !directives(&service)
                .iter()
                .any(|line| line.contains("network-online.target")),
            "{service}"
        );
        assert!(
            !has_directive(&service, "After=") && !has_directive(&service, "Wants="),
            "{service}"
        );
        assert!(
            text().contains("Wants=network-online.target"),
            "the hub still waits for one"
        );
    }

    #[test]
    fn the_sandbox_opens_the_two_directories_the_run_writes() {
        let service = service();
        assert!(service.contains("ProtectSystem=strict"), "{service}");
        assert!(service.contains("NoNewPrivileges=yes"), "{service}");
        assert!(service.contains("PrivateTmp=yes"), "{service}");
        // device.json is rewritten and the sync lock is taken beside
        // it, so the config directory is read-write.
        assert!(
            service.contains("BindPaths=/home/jo/.config/anago\n"),
            "{service}"
        );
        // The config and the stripped copy written next to it.
        assert!(
            service.contains("ReadWritePaths=/etc/wireguard\n"),
            "{service}"
        );
        assert!(
            service.contains("BindReadOnlyPaths=/usr/local/bin/anago\n"),
            "{service}"
        );
        // The directories, not the files: a rename needs the directory.
        assert!(
            !service.contains("BindPaths=/home/jo/.config/anago/device.json"),
            "{service}"
        );
    }

    #[test]
    fn a_device_file_under_a_home_directory_is_still_writable() {
        // `ProtectHome=yes` would hide it outright, and systemd refuses
        // to mount a bind under an inaccessible directory — so the bind
        // alone would not have been enough.
        let service = service();
        assert!(service.contains("ProtectHome=tmpfs"), "{service}");
        assert!(!service.contains("ProtectHome=yes"), "{service}");
    }

    #[test]
    fn a_device_file_outside_a_home_directory_gets_the_same_treatment() {
        // One rule, not two: the bind is a no-op for a directory that
        // was never hidden, and it still makes it writable.
        let service = sync_service_text(
            Path::new("/usr/local/bin/anago"),
            Path::new("/etc/anago/device.json"),
            Path::new("/etc/wireguard/anago.conf"),
        )
        .unwrap();
        assert!(service.contains("BindPaths=/etc/anago\n"), "{service}");
        assert!(service.contains("ProtectHome=tmpfs"), "{service}");
    }

    #[test]
    fn a_file_with_no_directory_to_open_is_refused() {
        // Granting the run `/` would leave `ProtectSystem=strict` in
        // the file describing a sandbox that is not there.
        for text in ["/device.json", "/", "device.json", "anago/device.json"] {
            assert_eq!(
                writable_dir(Path::new(text)),
                Err(Unusable::NoDirectory(PathBuf::from(text))),
                "{text}"
            );
        }
        assert_eq!(
            writable_dir(Path::new("/home/jo/.config/anago/device.json")),
            Ok(Path::new("/home/jo/.config/anago"))
        );
        assert_eq!(
            sync_service_text(
                Path::new("/usr/local/bin/anago"),
                Path::new("/device.json"),
                Path::new("/etc/wireguard/anago.conf"),
            ),
            Err(Unusable::NoDirectory(PathBuf::from("/device.json"))),
            "a device file in / has no directory to bind"
        );
        assert_eq!(
            sync_service_text(
                Path::new("/usr/local/bin/anago"),
                Path::new("/home/jo/.config/anago/device.json"),
                Path::new("/anago.conf"),
            ),
            Err(Unusable::NoDirectory(PathBuf::from("/anago.conf"))),
            "and neither has a wg config in /"
        );
    }

    #[test]
    fn an_awkward_device_path_still_syncs_the_right_file() {
        let service = sync_service_text(
            Path::new("/opt/my anago/anago"),
            Path::new("/home/jo/100% mine/device.json"),
            Path::new("/etc/wireguard/anago.conf"),
        )
        .unwrap();
        assert!(
            service.contains(
                "ExecStart=:\"/opt/my anago/anago\" sync --quiet \
                 --config \"/home/jo/100%% mine/device.json\""
            ),
            "{service}"
        );
        assert!(
            service.contains("BindPaths=\"/home/jo/100%% mine\"\n"),
            "{service}"
        );
        assert!(
            service.contains("BindReadOnlyPaths=\"/opt/my anago/anago\"\n"),
            "{service}"
        );
    }

    #[test]
    fn a_colon_in_a_path_that_has_to_be_bound_is_refused() {
        // `/home/jo/a:b` is a legal directory, and it renders — into a
        // bind of `/home/jo/a` onto a destination `b`, which systemd
        // drops for not being absolute. The unit then installs and
        // starts with ProtectHome=tmpfs hiding the directory the bind
        // was there to bring back: the timer fails every five minutes
        // and the file that says why reads correctly.
        assert_eq!(
            sync_service_text(
                Path::new("/usr/local/bin/anago"),
                Path::new("/home/jo/a:b/device.json"),
                Path::new("/etc/wireguard/anago.conf"),
            ),
            Err(Unusable::NotBindable(PathBuf::from("/home/jo/a:b")))
        );
        // The binary goes into a bind list too, in both units.
        for text in [
            sync_service_text(
                Path::new("/opt/a:b/anago"),
                Path::new("/home/jo/.config/anago/device.json"),
                Path::new("/etc/wireguard/anago.conf"),
            ),
            unit_text(
                Path::new("/opt/a:b/anago"),
                Path::new("/var/lib/anago"),
                Path::new("/etc/wireguard"),
                Path::new("/etc/ssl/anago/fullchain.pem"),
                Path::new("/etc/ssl/anago/privkey.pem"),
            ),
        ] {
            assert_eq!(
                text,
                Err(Unusable::NotBindable(PathBuf::from("/opt/a:b/anago")))
            );
        }
        // And the hub's certificate and key.
        assert_eq!(
            unit_text(
                Path::new("/usr/local/bin/anago"),
                Path::new("/var/lib/anago"),
                Path::new("/etc/wireguard"),
                Path::new("/etc/ssl/anago/fullchain.pem"),
                Path::new("/etc/ssl/a:b/privkey.pem"),
            ),
            Err(Unusable::NotBindable(PathBuf::from(
                "/etc/ssl/a:b/privkey.pem"
            )))
        );
        let message = Unusable::NotBindable(PathBuf::from("/home/jo/a:b")).to_string();
        assert_eq!(message.lines().count(), 1, "{message}");
        assert!(message.contains("source:destination"), "{message}");
    }

    #[test]
    fn a_colon_is_refused_only_where_it_would_split_something() {
        // A colon means nothing in an ExecStart argument or in
        // ReadWritePaths=, so refusing it there would be turning away a
        // legal path for a reason that is not true at that line.
        let service = sync_service_text(
            Path::new("/usr/local/bin/anago"),
            Path::new("/home/jo/.config/anago/de:vice.json"),
            Path::new("/etc/wire:guard/anago.conf"),
        )
        .expect("neither colon reaches a bind list");
        assert!(
            service.contains("--config /home/jo/.config/anago/de:vice.json"),
            "{service}"
        );
        assert!(
            service.contains("ReadWritePaths=/etc/wire:guard\n"),
            "{service}"
        );
        let hub = unit_text(
            Path::new("/usr/local/bin/anago"),
            Path::new("/var/lib/an:ago"),
            Path::new("/etc/wire:guard"),
            Path::new("/etc/ssl/anago/fullchain.pem"),
            Path::new("/etc/ssl/anago/privkey.pem"),
        )
        .expect("both directories only reach ReadWritePaths=");
        assert!(
            hub.contains("ReadWritePaths=/var/lib/an:ago /etc/wire:guard\n"),
            "{hub}"
        );
    }

    #[test]
    fn a_dollar_sign_in_a_path_stays_a_dollar_sign() {
        // `/home/jo/${USER}/device.json` is an ordinary legal path, and
        // it renders — but a command line expands variables, so without
        // the `:` prefix systemd would read `/home/jo/root/device.json`
        // on a system unit, or `/home/jo//device.json` when the
        // variable is unset. Neither is the file the person joined
        // with, and neither is what `BindPaths=` opened.
        let device = Path::new("/home/jo/${USER}/$HOME.d/device.json");
        let service = sync_service_text(
            Path::new("/usr/local/bin/anago"),
            device,
            Path::new("/etc/wireguard/anago.conf"),
        )
        .expect("a dollar sign is not a reason to refuse a path");
        assert!(
            service.contains(
                "ExecStart=:/usr/local/bin/anago sync --quiet \
                 --config /home/jo/${USER}/$HOME.d/device.json"
            ),
            "{service}"
        );
        // The whole point of the prefix: the argument and the directory
        // the sandbox opens are the same text, character for character.
        assert!(
            service.contains("BindPaths=/home/jo/${USER}/$HOME.d\n"),
            "{service}"
        );
        // A path list expands no variables, so a doubled `$` there
        // would be two literal dollars — `escape` leaves it alone.
        assert!(!service.contains("$$"), "{service}");
        assert_eq!(
            escape(device).unwrap(),
            "/home/jo/${USER}/$HOME.d/device.json"
        );

        // The hub's command line carries the same prefix: `--tls-cert`
        // reaches it the same way `--config` reaches this one.
        let hub = unit_text(
            Path::new("/usr/local/bin/anago"),
            Path::new("/var/lib/anago"),
            Path::new("/etc/wireguard"),
            Path::new("/etc/ssl/${x}/fullchain.pem"),
            Path::new("/etc/ssl/anago/privkey.pem"),
        )
        .unwrap();
        assert!(
            hub.contains("ExecStart=:/usr/local/bin/anago server run"),
            "{hub}"
        );
        assert!(
            hub.contains("BindReadOnlyPaths=/usr/local/bin/anago /etc/ssl/${x}/fullchain.pem"),
            "{hub}"
        );
        assert!(!hub.contains("$$"), "{hub}");
    }

    #[test]
    fn every_command_line_turns_variable_expansion_off() {
        // One place each, and no ExecStart without it — the next unit
        // added here would otherwise start out expanding again.
        let units = [
            text(),
            service(),
            sync_timer_text(crate::cli::DEFAULT_INTERVAL),
        ];
        for unit in units {
            for line in directives(&unit) {
                if let Some(command) = line.strip_prefix("ExecStart=") {
                    assert!(command.starts_with(':'), "{line}");
                }
                assert!(
                    !line.starts_with("Environment"),
                    "nothing to expand: {line}"
                );
            }
        }
    }

    #[test]
    fn a_path_that_would_end_the_line_is_refused() {
        // A Unix filename may hold a newline, and `--tls-cert` and
        // `--config` both take one straight from the command line. A
        // unit file is read one line at a time, so quoting does not
        // help: the tail of such a path becomes a directive of its own,
        // and a half-written `BindPaths=` either breaks a root unit or
        // guards a directory nobody named.
        let broken = Path::new("/etc/ssl/a\nExecStart=/bin/sh -c evil\nb.pem");
        assert_eq!(
            unit_text(
                Path::new("/usr/local/bin/anago"),
                Path::new("/var/lib/anago"),
                Path::new("/etc/wireguard"),
                broken,
                Path::new("/etc/ssl/anago/privkey.pem"),
            ),
            Err(Unusable::NotPrintable(broken.to_path_buf()))
        );
        assert_eq!(
            sync_service_text(
                Path::new("/usr/local/bin/anago"),
                Path::new("/home/jo/.config/a\nb/device.json"),
                Path::new("/etc/wireguard/anago.conf"),
            ),
            Err(Unusable::NotPrintable(PathBuf::from(
                "/home/jo/.config/a\nb/device.json"
            )))
        );
        // The exec path goes through the same gate — it reaches both
        // units as an argument, not as a constant.
        assert_eq!(
            sync_service_text(
                Path::new("/opt/a\rb/anago"),
                Path::new("/home/jo/.config/anago/device.json"),
                Path::new("/etc/wireguard/anago.conf"),
            ),
            Err(Unusable::NotPrintable(PathBuf::from("/opt/a\rb/anago")))
        );
        // Every control character, not just the newline: a unit is a
        // file someone reads to find out what runs as root, and an
        // invisible character in a path defeats that on its own.
        for text in [
            "/opt/a\nb",
            "/opt/a\rb",
            "/opt/a\u{0}b",
            "/opt/a\tb",
            "/opt/a\u{1b}[2Kb",
        ] {
            assert_eq!(
                escape(Path::new(text)),
                Err(Unusable::NotPrintable(PathBuf::from(text))),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_path_that_is_not_text_is_refused() {
        use std::os::unix::ffi::OsStrExt;

        // `to_string_lossy` would swap the bad bytes for U+FFFD and
        // write that down instead — a unit whose ExecStart names a
        // binary that is not there and whose sandbox guards a
        // directory that does not exist, with nothing to say so.
        let bad = PathBuf::from(std::ffi::OsStr::from_bytes(
            b"/etc/ssl/\xff\xfe/fullchain.pem",
        ));
        assert_eq!(escape(&bad), Err(Unusable::NotText(bad.clone())));
        assert_eq!(
            unit_text(
                Path::new("/usr/local/bin/anago"),
                Path::new("/var/lib/anago"),
                Path::new("/etc/wireguard"),
                &bad,
                Path::new("/etc/ssl/anago/privkey.pem"),
            ),
            Err(Unusable::NotText(bad))
        );
    }

    #[test]
    fn the_complaint_about_a_newline_does_not_contain_one() {
        // Otherwise the message is the same bug one layer up: `init`
        // pushes it into a warning line and the sync timer would log
        // it, and both are read a line at a time too.
        for unusable in [
            Unusable::NotPrintable(PathBuf::from("/etc/ssl/a\nb.pem")),
            Unusable::NoDirectory(PathBuf::from("/device.json")),
            Unusable::NotText(PathBuf::from("/etc/a\u{fffd}b")),
        ] {
            let message = unusable.to_string();
            assert_eq!(message.lines().count(), 1, "{message:?}");
            assert!(!message.contains('\n'), "{message:?}");
        }
        assert!(
            Unusable::NotPrintable(PathBuf::from("/etc/ssl/a\nb.pem"))
                .to_string()
                .contains("/etc/ssl/a\\nb.pem"),
            "the path is still recognisable"
        );
    }

    #[test]
    fn an_install_that_cannot_name_a_path_writes_no_unit() {
        // `install` renders before it writes, so the refusal costs
        // nothing but the message. Checked here rather than by calling
        // `install` because the rest of it needs systemd and root.
        assert!(unit_text(
            Path::new("/usr/local/bin/anago"),
            Path::new("/var/lib/anago"),
            Path::new("/etc/wireguard"),
            Path::new("/etc/ssl/a\nb.pem"),
            Path::new("/etc/ssl/anago/privkey.pem"),
        )
        .is_err());
        let e = SystemdError::Path(Unusable::NotPrintable(PathBuf::from("/etc/ssl/a\nb.pem")));
        assert_eq!(e.to_string().lines().count(), 1, "{e}");
        assert!(e.to_string().contains("one line at a time"), "{e}");
    }

    #[test]
    fn both_sync_units_are_complete_ini_files() {
        let timer = sync_timer_text(crate::cli::DEFAULT_INTERVAL);
        let service = service();
        for (name, text, sections) in [
            (SYNC_SERVICE, &service, &["[Unit]", "[Service]"][..]),
            (SYNC_TIMER, &timer, &["[Unit]", "[Timer]", "[Install]"][..]),
        ] {
            for section in sections {
                assert_eq!(text.matches(section).count(), 1, "{section} in {name}");
            }
            assert!(text.ends_with('\n'), "{name} needs a final newline");
            for line in text.lines().filter(|line| !line.is_empty()) {
                assert!(
                    line.starts_with('[') || line.starts_with('#') || line.contains('='),
                    "unexpected line {line:?} in {name}"
                );
            }
        }
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
