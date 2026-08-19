//! The mac half of the sync timer (DESIGN.md §8).
//!
//! Same job as `systemd.rs`, a different file format and a different
//! way of loading it. Everything decidable is here: the property list
//! is a pure function of the paths and the period it is given, and the
//! two `launchctl` lines are values rather than side effects. Running
//! them needs a mac and root, so that half lands with the install
//! command.
//!
//! **A system daemon, not a user agent.** `sync` hands a configuration
//! to `wg syncconf` and reads a device file that is 0600 to whoever
//! joined, so it runs as root out of `/Library/LaunchDaemons` — the
//! same answer the Linux side gives, and the reason §8 tells people to
//! check it with `sudo launchctl print system/…` rather than
//! `launchctl list`, which only ever looks at their own login session.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::wg::Cmd;

/// What launchd calls the daemon, and where its file goes.
///
/// A reverse-DNS label is conventionally a domain its owner controls.
/// anago has no domain (§13), so this is the repository namespace
/// rather than a name nobody here holds.
pub const LABEL: &str = "com.github.elpalaiso.anago.sync";
pub const DAEMON_DIR: &str = "/Library/LaunchDaemons";

/// The domain a system daemon is bootstrapped into — never `gui/<uid>`.
pub const DOMAIN: &str = "system";

/// Where the run's own output goes.
///
/// launchd sends a daemon's stdout and stderr to `/dev/null` unless a
/// path says otherwise, and that would take §6.3's whole convention
/// with it: the exit codes still differ, but the one line explaining
/// that this device was removed from the hub would be written to
/// nothing. systemd gets the journal for free; here it has to be asked
/// for. Both streams go to one file so the order between them survives
/// and there is one place to look. Nothing rotates it — under
/// `--quiet` it is only written when something is actually wrong, so
/// the install output is where to say so.
pub const LOG: &str = "/var/log/anago-sync.log";

/// The tool that loads it.
pub const LAUNCHCTL: &str = "launchctl";

/// The hub daemon's label (§11.1 결정 3) — the sync label minus its
/// `.sync` suffix, so the two read as one family in `launchctl list`.
pub const SERVER_LABEL: &str = "com.github.elpalaiso.anago";

/// Where LaunchDaemons live on every mac.
pub const DAEMONS_DIR: &str = "/Library/LaunchDaemons";

/// Where the hub daemon's output goes.
pub const SERVER_LOG: &str = "/var/log/anago.log";

/// Full path of the installed hub daemon.
pub fn server_plist_path(dir: &Path) -> PathBuf {
    dir.join(format!("{SERVER_LABEL}.plist"))
}

/// The hub daemon's service target.
pub fn server_target() -> String {
    format!("{DOMAIN}/{SERVER_LABEL}")
}

/// The hub daemon's property list (§11.1 결정 3): start at boot, keep
/// it alive, both streams to one log. `KeepAlive` is what systemd's
/// `Restart=` is on Linux — the hub is the coordination plane and the
/// renewal loop, and a mac mini hub with nobody logged in still has to
/// answer joins.
pub fn server_plist(exec: &Path) -> Result<String, Unrepresentable> {
    let exec = string(exec)?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{SERVER_LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{exec}</string>
		<string>server</string>
		<string>run</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>{SERVER_LOG}</string>
	<key>StandardErrorPath</key>
	<string>{SERVER_LOG}</string>
</dict>
</plist>
"#
    ))
}

/// `launchctl bootout system/<server label>`.
pub fn bootout_server() -> Cmd {
    Cmd::new(LAUNCHCTL, &["bootout", &server_target()])
}

/// `launchctl print system/<server label>` — exit 0 while loaded.
pub fn print_server() -> Cmd {
    Cmd::new(LAUNCHCTL, &["print", &server_target()])
}

/// Full path of the installed daemon.
pub fn plist_path(dir: &Path) -> PathBuf {
    dir.join(format!("{LABEL}.plist"))
}

/// The service target `launchctl` addresses the loaded daemon by, and
/// the one §8 prints for people to check with.
pub fn target() -> String {
    format!("{DOMAIN}/{LABEL}")
}

/// The property list.
///
/// The command line is written out — `--quiet` and `--config <absolute
/// path>` — for the reason §8 gives: opening the file, or reading the
/// `ProgramArguments` that `launchctl print` shows, says which device
/// this mac syncs and why the run is silent.
///
/// **`ProgramArguments`, not `Program` plus a string.** Each argument
/// is its own element, so no shell is involved and a path with spaces
/// in it needs no quoting — the whole class of problem the Linux unit
/// has to escape its way around does not arise. What is left is XML's
/// own: `&` and `<` have to be written as entities, whitespace has to
/// be written as character references so the parser does not rewrite
/// it (see [`string`]), and a few characters cannot be written at all
/// (see [`Unrepresentable`]).
///
/// **Human verification needed**: that launchd accepts the file and
/// runs it on the period below. `plutil -lint` reads the syntax, but
/// only a mac says whether the daemon actually fires — and recent
/// macOS lets a person switch it off in System Settings, which looks
/// exactly like an install that did not take (§13).
pub fn sync_plist(
    exec: &Path,
    device_file: &Path,
    interval: Duration,
) -> Result<String, Unrepresentable> {
    let exec = string(exec)?;
    let device_file = string(device_file)?;
    let seconds = start_interval(interval);
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{exec}</string>
		<string>sync</string>
		<string>--quiet</string>
		<string>--config</string>
		<string>{device_file}</string>
	</array>
	<key>StartInterval</key>
	<integer>{seconds}</integer>
	<key>RunAtLoad</key>
	<true/>
	<key>StandardOutPath</key>
	<string>{LOG}</string>
	<key>StandardErrorPath</key>
	<string>{LOG}</string>
</dict>
</plist>
"#
    ))
}

/// `launchctl bootstrap system <plist>` — loads it and starts it.
///
/// `bootstrap`, not the older `load`: `load` still works and still
/// reports almost nothing when it fails, which on the one command a
/// person runs once is the wrong trade.
///
/// Note the shape, because the two commands do not match: bootstrap
/// takes a **domain and a file**, bootout takes a **service target**.
pub fn bootstrap(plist: &Path) -> Cmd {
    Cmd::with_path(LAUNCHCTL, &["bootstrap", DOMAIN], plist)
}

/// `launchctl bootout system/<label>` — unloads it and stops it.
///
/// The file still has to be deleted afterwards; booting out only takes
/// it out of launchd, and a plist left behind would come back at the
/// next boot.
pub fn bootout() -> Cmd {
    Cmd::new(LAUNCHCTL, &["bootout", &target()])
}

/// `launchctl print system/<label>` — exit 0 while it is loaded.
///
/// The command §8 tells people to run, and the one a removal runs
/// itself when a `bootout` failed: whether the daemon is still there is
/// a question with a yes-or-no answer, and this asks it rather than
/// reading launchctl's wording for a hint.
///
/// No `sudo` here — the removal is already root. The *printed* advice
/// keeps it, because a person's shell is not.
pub fn print() -> Cmd {
    Cmd::new(LAUNCHCTL, &["print", &target()])
}

/// The period, as launchd counts it.
///
/// Seconds, and nothing else: `StartInterval` is a plain integer, so
/// unlike the systemd side there is no unit to spell out and no way to
/// be read as something other than seconds.
///
/// launchd starts no second copy when the interval elapses while a run
/// is still going, and it fires once on wake for a period that passed
/// while the mac was asleep — neither is anything to catch up on
/// (§6.3), and neither needs a line here.
pub fn start_interval(interval: Duration) -> u64 {
    interval.as_secs()
}

/// Renders a path as the body of a `<string>`.
///
/// `&` and `<` have to be entities or the file does not parse; `>` is
/// only required inside `]]>`, but a plist that escapes one angle
/// bracket and not the other reads like a bug.
///
/// The three whitespace characters XML allows are written as character
/// references rather than literally, and that one is not cosmetic. An
/// XML processor **normalises line endings before anything else looks
/// at the document**: a literal `#xD`, or `#xD #xA`, is replaced by a
/// single `#xA`. So a path holding a carriage return, written straight
/// into the file, would reach launchd as a *different path* — and
/// `/Users/jo/a\r\nb` and `/Users/jo/a\nb` would reach it as the same
/// one. Character references are resolved after that pass, so `&#13;`
/// survives as a carriage return. Tab and newline go the same way for
/// one rule instead of three.
fn string(path: &Path) -> Result<String, Unrepresentable> {
    let Some(text) = path.to_str() else {
        return Err(Unrepresentable::NotText(path.to_path_buf()));
    };
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\t' => out.push_str("&#9;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            _ if in_xml(c) => out.push(c),
            _ => return Err(Unrepresentable::NotXml(path.to_path_buf())),
        }
    }
    Ok(out)
}

/// Whether XML 1.0 can hold this character at all.
///
/// Tab, newline and carriage return are in — [`string`] has already
/// turned those three into references by the time this is asked — and
/// the rest of the control range is not. That part is not an escaping
/// problem: there is no entity for it either, and `&#1;` is as
/// forbidden as the byte. This is where the mac and Linux rules part:
/// a newline in a path is refused for a systemd unit because that file
/// is read one line at a time, and kept here because XML is not.
fn in_xml(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r')
        || (' '..='\u{d7ff}').contains(&c)
        || ('\u{e000}'..='\u{fffd}').contains(&c)
        || c >= '\u{10000}'
}

/// A path no property list can hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unrepresentable {
    /// Not UTF-8. A plist declares itself UTF-8 in its first line, and
    /// `to_string_lossy` would write down a *different* path — one
    /// whose `--config` names a file that is not there, with nothing
    /// to say so.
    NotText(PathBuf),
    /// A character XML cannot encode. Not an escaping problem: most of
    /// the control range has no representation in XML 1.0, entity or
    /// otherwise, so there is nothing to write.
    NotXml(PathBuf),
}

impl fmt::Display for Unrepresentable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unrepresentable::NotText(path) => write!(
                f,
                "{} is not valid UTF-8, so a property list could only name a \
                 different path than the one you meant",
                shown(path)
            ),
            Unrepresentable::NotXml(path) => write!(
                f,
                "{} holds a character XML cannot encode, so there is no way to \
                 write it into a property list",
                shown(path)
            ),
        }
    }
}

impl std::error::Error for Unrepresentable {}

/// The offending path, written so the complaint about it stays one
/// line — the same reason `systemd::shown` exists.
fn shown(path: &Path) -> String {
    path.to_string_lossy().escape_debug().to_string()
}

#[cfg(all(test, unix))] // launchd only ever runs on macOS; path semantics differ on Windows
mod tests {
    use super::*;

    fn plist() -> String {
        sync_plist(
            Path::new("/usr/local/bin/anago"),
            Path::new("/Users/jo/.config/anago/device.json"),
            crate::cli::DEFAULT_INTERVAL,
        )
        .expect("every path here is one a plist can hold")
    }

    /// The `<string>` bodies, in order — what launchd actually reads.
    fn strings(text: &str) -> Vec<&str> {
        text.split("<string>")
            .skip(1)
            .filter_map(|rest| rest.split("</string>").next())
            .collect()
    }

    #[test]
    fn the_daemon_is_named_the_way_the_check_command_says() {
        // §8 tells people to run
        // `sudo launchctl print system/com.github.elpalaiso.anago.sync`.
        // That is only a true sentence while these are.
        assert_eq!(LABEL, "com.github.elpalaiso.anago.sync");
        assert_eq!(target(), "system/com.github.elpalaiso.anago.sync");
        assert_eq!(
            plist_path(Path::new(DAEMON_DIR)),
            Path::new("/Library/LaunchDaemons/com.github.elpalaiso.anago.sync.plist")
        );
        // A daemon, not a login agent: sync applies a WireGuard config.
        assert!(DAEMON_DIR.starts_with("/Library/LaunchDaemons"));
        assert_eq!(DOMAIN, "system");
        assert!(
            plist().contains(&format!("<string>{LABEL}</string>")),
            "{}",
            plist()
        );
    }

    #[test]
    fn the_daemon_runs_the_same_command_the_linux_unit_does() {
        assert_eq!(
            strings(&plist()),
            [
                LABEL,
                "/usr/local/bin/anago",
                "sync",
                "--quiet",
                "--config",
                "/Users/jo/.config/anago/device.json",
                LOG,
                LOG,
            ]
        );
    }

    #[test]
    fn each_argument_is_its_own_element_so_nothing_needs_quoting() {
        // The reason this file has no equivalent of the unit's
        // `escape`: there is no shell and no word splitting, so a path
        // with spaces is just a path.
        let text = sync_plist(
            Path::new("/Users/jo/my anago/anago"),
            Path::new("/Users/jo/my files/device.json"),
            crate::cli::DEFAULT_INTERVAL,
        )
        .unwrap();
        // The paths land in the file exactly as they were given —
        // nothing wrapped them, nothing split them.
        assert_eq!(
            strings(&text),
            [
                LABEL,
                "/Users/jo/my anago/anago",
                "sync",
                "--quiet",
                "--config",
                "/Users/jo/my files/device.json",
                LOG,
                LOG,
            ]
        );
    }

    #[test]
    fn the_period_is_the_one_the_command_documents() {
        assert!(
            plist().contains("<key>StartInterval</key>\n\t<integer>300</integer>"),
            "{}",
            plist()
        );
        // Seconds and nothing else — a plain integer cannot be read as
        // minutes, so unlike the systemd side there is no unit to spell.
        assert_eq!(start_interval(crate::cli::DEFAULT_INTERVAL), 300);
        assert_eq!(start_interval(crate::cli::MIN_INTERVAL), 60);
        assert_eq!(start_interval(crate::cli::MAX_INTERVAL), 86400);
        for interval in [
            crate::cli::MIN_INTERVAL,
            crate::cli::DEFAULT_INTERVAL,
            crate::cli::MAX_INTERVAL,
        ] {
            let text = sync_plist(
                Path::new("/usr/local/bin/anago"),
                Path::new("/Users/jo/.config/anago/device.json"),
                interval,
            )
            .unwrap();
            assert!(
                text.contains(&format!("<integer>{}</integer>", interval.as_secs())),
                "{text}"
            );
        }
    }

    #[test]
    fn a_daemon_with_no_log_path_would_say_nothing_at_all() {
        // launchd sends stdout and stderr to /dev/null without these,
        // and §6.3's one line about a removed device would go there.
        let text = plist();
        assert!(
            text.contains(&format!(
                "<key>StandardOutPath</key>\n\t<string>{LOG}</string>"
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "<key>StandardErrorPath</key>\n\t<string>{LOG}</string>"
            )),
            "{text}"
        );
        // One file, so the order between the two streams survives.
        assert_eq!(strings(&text).iter().filter(|s| **s == LOG).count(), 2);
        assert_eq!(LOG, "/var/log/anago-sync.log");
    }

    #[test]
    fn it_syncs_when_it_is_installed_and_is_not_kept_alive() {
        let text = plist();
        // The counterpart of OnBootSec=: StartInterval alone waits a
        // whole period before the first run.
        assert!(text.contains("<key>RunAtLoad</key>\n\t<true/>"), "{text}");
        // KeepAlive would restart a job that is meant to end — the
        // interval is the schedule, the way the timer is on Linux.
        assert!(!text.contains("KeepAlive"), "{text}");
        assert!(!text.contains("<key>Program</key>"), "{text}");
    }

    #[test]
    fn xml_special_characters_are_written_as_entities() {
        // `&` and `<` are not optional; an unescaped one makes the file
        // unparseable, and `plutil` would reject the whole daemon.
        let text = sync_plist(
            Path::new("/usr/local/bin/anago"),
            Path::new("/Users/jo/a&b/<c>/device.json"),
            crate::cli::DEFAULT_INTERVAL,
        )
        .unwrap();
        assert!(
            text.contains("<string>/Users/jo/a&amp;b/&lt;c&gt;/device.json</string>"),
            "{text}"
        );
        // The ampersand is escaped first, or it would go back and
        // escape the ones the other two just introduced.
        assert!(!text.contains("&amp;lt;"), "{text}");
    }

    #[test]
    fn a_path_xml_cannot_hold_is_refused() {
        // Not an escaping problem: most of the control range has no
        // representation in XML 1.0 at all, entity or otherwise.
        for text in [
            "/Users/jo/a\u{0}b",
            "/Users/jo/a\u{1}b",
            "/Users/jo/a\u{1b}[2Kb",
            "/Users/jo/a\u{b}b",
            "/Users/jo/a\u{c}b",
        ] {
            assert_eq!(
                sync_plist(
                    Path::new("/usr/local/bin/anago"),
                    Path::new(text),
                    crate::cli::DEFAULT_INTERVAL,
                ),
                Err(Unrepresentable::NotXml(PathBuf::from(text))),
                "{text:?}"
            );
        }
        // The binary goes through the same gate.
        assert_eq!(
            sync_plist(
                Path::new("/usr/local/bin/a\u{0}nago"),
                Path::new("/Users/jo/.config/anago/device.json"),
                crate::cli::DEFAULT_INTERVAL,
            ),
            Err(Unrepresentable::NotXml(PathBuf::from(
                "/usr/local/bin/a\u{0}nago"
            )))
        );
    }

    #[test]
    fn a_path_reaches_launchd_as_the_path_it_was() {
        // An XML processor rewrites line endings before anything else
        // reads the document: a literal #xD, or #xD #xA, becomes a
        // single #xA. Written straight into the file, three different
        // paths would arrive as one, and none of them the right one.
        // Character references are resolved after that pass.
        let bodies = |device: &str| {
            let text = sync_plist(
                Path::new("/usr/local/bin/anago"),
                Path::new(device),
                crate::cli::DEFAULT_INTERVAL,
            )
            .expect("XML can hold all of these");
            assert!(
                !text.contains('\r'),
                "a literal CR would be rewritten: {text}"
            );
            strings(&text)[5].to_string()
        };
        assert_eq!(bodies("/Users/jo/a\rb"), "/Users/jo/a&#13;b");
        assert_eq!(bodies("/Users/jo/a\r\nb"), "/Users/jo/a&#13;&#10;b");
        assert_eq!(bodies("/Users/jo/a\nb"), "/Users/jo/a&#10;b");
        assert_eq!(bodies("/Users/jo/a\tb"), "/Users/jo/a&#9;b");
        // Three paths in, three different files out — the whole point.
        let rendered: Vec<String> = ["/Users/jo/a\rb", "/Users/jo/a\r\nb", "/Users/jo/a\nb"]
            .iter()
            .map(|device| bodies(device))
            .collect();
        assert_eq!(
            rendered.len(),
            rendered
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            "{rendered:?}"
        );
        // Here the mac and Linux rules still part: a newline is refused
        // for a systemd unit because that file is read one line at a
        // time. XML is not, so the path is kept — just not literally.
        assert!(
            crate::systemd::sync_service_text(
                Path::new("/usr/local/bin/anago"),
                Path::new("/home/jo/a\nb/device.json"),
                Path::new("/etc/wireguard/anago.conf"),
            )
            .is_err(),
            "the same path has no unit file to live in"
        );
    }

    #[test]
    #[cfg(unix)] // exercises unix modes/ownership/symlinks
    fn a_path_that_is_not_text_is_refused() {
        #[cfg(unix)]
        use std::os::unix::ffi::OsStrExt;

        // The file declares itself UTF-8 in its first line, and
        // `to_string_lossy` would write down a path that is not there.
        let bad = PathBuf::from(std::ffi::OsStr::from_bytes(
            b"/Users/jo/\xff\xfe/device.json",
        ));
        assert_eq!(
            sync_plist(
                Path::new("/usr/local/bin/anago"),
                &bad,
                crate::cli::DEFAULT_INTERVAL
            ),
            Err(Unrepresentable::NotText(bad))
        );
    }

    #[test]
    fn the_complaint_about_a_path_is_one_line() {
        // It reaches a person as a warning line or a log line, and both
        // are read one line at a time even when the plist is not.
        for e in [
            Unrepresentable::NotXml(PathBuf::from("/Users/jo/a\u{1b}b")),
            Unrepresentable::NotText(PathBuf::from("/Users/jo/a\nb")),
        ] {
            let message = e.to_string();
            assert_eq!(message.lines().count(), 1, "{message:?}");
        }
        assert!(
            Unrepresentable::NotXml(PathBuf::from("/Users/jo/a\u{1b}b"))
                .to_string()
                .contains("/Users/jo/a\\u{1b}b"),
            "the path is still recognisable"
        );
    }

    #[test]
    fn the_two_launchctl_lines_address_the_daemon_the_way_it_wants() {
        // They are not symmetric, which is the mistake worth pinning:
        // bootstrap takes a domain and a file, bootout takes a service
        // target.
        let load = bootstrap(&plist_path(Path::new(DAEMON_DIR)));
        assert_eq!(
            load.display(),
            "launchctl bootstrap system \
             /Library/LaunchDaemons/com.github.elpalaiso.anago.sync.plist"
        );
        assert_eq!(
            bootout().display(),
            "launchctl bootout system/com.github.elpalaiso.anago.sync"
        );
        // The system domain, never gui/<uid>: §8's check command needs
        // sudo and `system/` for the same reason.
        for cmd in [load, bootout()] {
            assert_eq!(cmd.program, LAUNCHCTL);
            assert!(!cmd.display().contains("gui/"), "{}", cmd.display());
            // `load`/`unload` still work and still report nothing
            // useful when they fail.
            assert!(!cmd.args.contains(&"load".to_string()));
            assert!(!cmd.args.contains(&"unload".to_string()));
        }
    }

    #[test]
    fn the_plist_is_a_complete_property_list() {
        let text = plist();
        assert!(
            text.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"),
            "{text}"
        );
        assert!(
            text.contains("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\""),
            "{text}"
        );
        assert!(text.ends_with("</plist>\n"), "{text}");
        for (open, close) in [
            ("<plist version=\"1.0\">", "</plist>"),
            ("<dict>", "</dict>"),
            ("<array>", "</array>"),
        ] {
            assert_eq!(text.matches(open).count(), 1, "{open} in {text}");
            assert_eq!(text.matches(close).count(), 1, "{close} in {text}");
        }
        // Six keys: Label, ProgramArguments, StartInterval, RunAtLoad
        // and the two log paths.
        assert_eq!(text.matches("<key>").count(), 6, "{text}");
        assert_eq!(text.matches("</key>").count(), 6, "{text}");
        // A label, five arguments and two log paths.
        assert_eq!(strings(&text).len(), 8, "{text}");
        assert_eq!(text.matches("</string>").count(), 8, "{text}");
        assert_eq!(text.matches("<integer>").count(), 1, "{text}");
        assert_eq!(text.matches("<true/>").count(), 1, "{text}");
    }
}
