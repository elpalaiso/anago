//! Advice that more than one command needs to give.
//!
//! Most messages belong to the command that produces them. These two
//! do not: an I/O failure looks the same whether it came from `server
//! init`, `code`, or `rm`, and the thing worth saying about it —
//! usually "run this as root" — is the same too.
//!
//! The tests at the bottom are a checklist rather than a unit test:
//! they walk the situations a first-time M0 install actually hits and
//! hold each message to saying what happened *and* what to do next.

use std::io;
use std::path::{Path, PathBuf};

/// Who is supposed to own the thing that was being written.
///
/// Decided by the caller, never guessed from the path. A home
/// directory is not always under `/home` — `/var/home/alice` and
/// `/srv/alice` are both real layouts — and inferring "system" from the
/// prefix would tell those users to `sudo anago join`, which is the
/// advice this distinction exists to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// The person running the command: `~/.config/anago` and what is
    /// in it.
    User,
    /// root: `/var/lib/anago`, `/etc/wireguard`.
    System,
}

/// What a write was aimed at, and who should own it.
///
/// File versus directory is not pedantry: creating a file fails because
/// of the directory holding it, while creating a directory fails
/// because of *that* directory — and pointing at its parent would send
/// somebody to check permissions that are perfectly fine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    path: PathBuf,
    is_directory: bool,
    owner: Owner,
}

impl Target {
    pub fn user_file(path: impl Into<PathBuf>) -> Target {
        Target::new(path, false, Owner::User)
    }

    pub fn user_directory(path: impl Into<PathBuf>) -> Target {
        Target::new(path, true, Owner::User)
    }

    pub fn system_file(path: impl Into<PathBuf>) -> Target {
        Target::new(path, false, Owner::System)
    }

    pub fn system_directory(path: impl Into<PathBuf>) -> Target {
        Target::new(path, true, Owner::System)
    }

    fn new(path: impl Into<PathBuf>, is_directory: bool, owner: Owner) -> Target {
        Target {
            path: path.into(),
            is_directory,
            owner,
        }
    }

    /// The path that failed.
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn owner(&self) -> Owner {
        self.owner
    }

    /// The directory whose ownership or mode is actually at fault.
    pub fn blame(&self) -> &Path {
        if self.is_directory {
            &self.path
        } else {
            self.path.parent().unwrap_or(&self.path)
        }
    }
}

/// What to add to an I/O failure, when there is something to add.
///
/// `None` for the ordinary cases: a message that trails off into "or
/// maybe something else" is worse than one that stops.
///
/// The permission advice depends on who owns the target. Telling
/// somebody to `sudo anago join` because their own `~/.config/anago`
/// was unwritable would be wrong twice over: it does not address the
/// cause, and it leaves root-owned files in their home directory for
/// the next run to trip over.
pub fn advice_for(target: Option<&Target>, kind: io::ErrorKind) -> Option<String> {
    match kind {
        io::ErrorKind::PermissionDenied => Some(match target {
            // No target: the hub's own files, where the likeliest
            // first-run mistake is `anago server init` without sudo.
            None => "run this as root — the hub's files live in /var/lib/anago and \
                     /etc/wireguard"
                .to_string(),
            Some(target) => match target.owner() {
                Owner::System => format!(
                    "run this as root — {} belongs to the system",
                    target.blame().display()
                ),
                Owner::User => format!(
                    "check who owns {} — it should belong to you, and it will not if a \
                     `sudo anago` run created it",
                    target.blame().display()
                ),
            },
        }),
        io::ErrorKind::StorageFull => Some("the filesystem is full".to_string()),
        io::ErrorKind::ReadOnlyFilesystem => {
            Some("the filesystem is mounted read-only".to_string())
        }
        _ => None,
    }
}

/// Appends the advice for a failure with no path behind it.
pub fn with_advice(message: String, kind: io::ErrorKind) -> String {
    with_target_advice(message, None, kind)
}

/// Appends the advice for a failure at `target`, when there is any.
pub fn with_target_advice(message: String, target: Option<&Target>, kind: io::ErrorKind) -> String {
    match advice_for(target, kind) {
        Some(advice) => format!("{message} — {advice}"),
        None => message,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use anago_core::code::CodeStatus;
    use anago_core::json;
    use anago_core::proto::{ApiError, ErrorCode};
    use anago_core::state::JoinRejection;

    use super::*;
    use crate::tls;
    use crate::wg::{self, Platform, WgError};

    /// Every message a person sees has to answer two questions: what
    /// happened, and what do I do now.
    fn says_what_and_what_next(message: &str, what: &[&str], next: &[&str]) {
        for fragment in what {
            assert!(
                message.contains(fragment),
                "{message:?} does not say what happened ({fragment:?})"
            );
        }
        assert!(
            next.iter().any(|fragment| message.contains(fragment)),
            "{message:?} does not say what to do next (wanted one of {next:?})"
        );
    }

    fn error_body(code: ErrorCode, message: &str) -> String {
        json::to_string(&ApiError::new(code, message).to_json())
    }

    #[test]
    fn not_being_root_is_named_as_the_cause() {
        // `anago server init` without sudo, which is how a good share
        // of first runs go.
        let message = with_advice(
            "could not write the state file: Permission denied (os error 13)".to_string(),
            io::ErrorKind::PermissionDenied,
        );
        says_what_and_what_next(
            &message,
            &["could not write the state file", "Permission denied"],
            &["run this as root"],
        );
        assert!(message.contains("/var/lib/anago"), "{message}");

        // A system path the hub owns: root is the answer.
        let message = crate::join::JoinError::Save {
            what: "the WireGuard config",
            target: Target::system_file("/etc/wireguard/anago.conf"),
            kind: io::ErrorKind::PermissionDenied,
            source: "Permission denied (os error 13)".to_string(),
        }
        .to_string();
        says_what_and_what_next(
            &message,
            &["could not write the WireGuard config", "Permission denied"],
            &["run this as root"],
        );
        assert!(
            message.contains("/etc/wireguard belongs to the system"),
            "{message}"
        );

        // A failure with nothing useful to add does not invent advice.
        assert_eq!(advice_for(None, io::ErrorKind::NotFound), None);
        assert_eq!(
            with_advice("plain".to_string(), io::ErrorKind::NotFound),
            "plain"
        );
    }

    #[test]
    fn a_file_in_your_own_home_is_not_a_reason_to_use_sudo() {
        // `sudo anago join` because ~/.config was unwritable fixes
        // nothing and leaves root-owned files behind for the next run.
        let message = crate::join::JoinError::Save {
            what: "the device file",
            target: Target::user_file("/home/jo/.config/anago/device.json"),
            kind: io::ErrorKind::PermissionDenied,
            source: "Permission denied (os error 13)".to_string(),
        }
        .to_string();
        says_what_and_what_next(
            &message,
            &["could not write the device file", "Permission denied"],
            &["check who owns /home/jo/.config/anago"],
        );
        assert!(!message.contains("as root"), "{message}");
        assert!(message.contains("`sudo anago` run created it"), "{message}");

        // Ownership comes from the call site, not from the path — a
        // home directory under /var or /srv is still a home directory.
        for home in [
            "/var/home/alice/.config/anago/device.json",
            "/srv/alice/.config/anago/device.json",
            "/opt/people/alice/.config/anago/device.json",
        ] {
            let message = crate::join::JoinError::Save {
                what: "the device file",
                target: Target::user_file(home),
                kind: io::ErrorKind::PermissionDenied,
                source: "Permission denied (os error 13)".to_string(),
            }
            .to_string();
            assert!(
                !message.contains("as root"),
                "{home} is somebody's home, not the system's: {message}"
            );
            assert!(message.contains("check who owns"), "{message}");
        }
    }

    #[test]
    fn a_save_that_failed_for_another_reason_says_only_that() {
        // Not every write failure is about root, and pointing at sudo
        // for a full disk would send somebody the wrong way.
        let message = crate::join::JoinError::Save {
            what: "the device file",
            target: Target::user_file("/home/jo/.config/anago/device.json"),
            kind: io::ErrorKind::NotFound,
            source: "No such file or directory (os error 2)".to_string(),
        }
        .to_string();
        assert_eq!(
            message,
            "could not write the device file (/home/jo/.config/anago/device.json): \
             No such file or directory (os error 2)"
        );

        let message = crate::join::JoinError::Save {
            what: "the WireGuard config",
            target: Target::system_file("/etc/wireguard/anago.conf"),
            kind: io::ErrorKind::StorageFull,
            source: "No space left on device (os error 28)".to_string(),
        }
        .to_string();
        assert!(message.contains("the filesystem is full"), "{message}");
        assert!(!message.contains("as root"), "{message}");
    }

    #[test]
    fn missing_wireguard_tools_name_the_package() {
        let message = WgError::NotFound {
            tool: "wg-quick",
            hint: wg::install_hint(Platform::MacOs),
        }
        .to_string();
        says_what_and_what_next(
            &message,
            &["`wg-quick` is not installed"],
            &["brew install wireguard-tools"],
        );

        let message = WgError::NotFound {
            tool: "wg",
            hint: wg::install_hint(Platform::Linux),
        }
        .to_string();
        says_what_and_what_next(
            &message,
            &["`wg` is not installed"],
            &["apt install wireguard-tools"],
        );
    }

    #[test]
    fn a_missing_certificate_says_anago_will_not_make_one() {
        // M0 takes a certificate; it does not issue one (§11), and the
        // message has to say so or the person waits for an ACME run
        // that is not coming.
        let message = tls::TlsError::Io {
            path: Path::new("/etc/ssl/anago/fullchain.pem").to_path_buf(),
            kind: io::ErrorKind::NotFound,
            hint: tls::io_hint(io::ErrorKind::NotFound),
        }
        .to_string();
        says_what_and_what_next(
            &message,
            &["/etc/ssl/anago/fullchain.pem", "not found"],
            &["M0 does not issue certificates"],
        );

        // A certificate that exists but cannot be read points at root.
        let message = tls::TlsError::Io {
            path: Path::new("/etc/ssl/anago/privkey.pem").to_path_buf(),
            kind: io::ErrorKind::PermissionDenied,
            hint: tls::io_hint(io::ErrorKind::PermissionDenied),
        }
        .to_string();
        says_what_and_what_next(&message, &["permission denied"], &["as root"]);
    }

    #[test]
    fn a_spent_or_expired_code_sends_the_person_back_to_the_server() {
        // The hub says one thing for every bad code (§8); the device
        // turns it into the next step.
        let message = crate::join::explain(
            403,
            &error_body(ErrorCode::InvalidCode, "that join code is not valid"),
        );
        says_what_and_what_next(
            &message,
            &["that join code is not valid"],
            &["`anago code` on the server"],
        );
        assert!(message.contains("single use and expire"), "{message}");

        // Server-side the reason is kept apart, for the log rather than
        // for the caller.
        assert_eq!(
            JoinRejection::CodeNotUsable(CodeStatus::Expired).to_string(),
            "join code is expired"
        );
    }

    #[test]
    fn a_full_subnet_says_what_to_free() {
        assert_eq!(
            JoinRejection::SubnetFull.to_string(),
            "no free address left in the subnet"
        );
        let message = crate::join::explain(
            507,
            &error_body(ErrorCode::SubnetFull, "no free address left in the subnet"),
        );
        says_what_and_what_next(
            &message,
            &["no free address left in the subnet"],
            &["remove a device first"],
        );
    }

    #[test]
    fn usage_names_every_m0_command_and_where_the_rest_went() {
        let usage = crate::cli::help(None);
        for command in [
            "anago server init",
            "anago server run",
            "anago code",
            "anago join",
            "anago ls",
            "anago rm",
        ] {
            assert!(usage.contains(command), "usage omits {command}");
        }
        // The commands that are not M0 are accounted for, so their
        // absence does not read as a bug.
        assert!(usage.contains("M1"), "{usage}");
        assert!(usage.contains("M3"), "{usage}");
    }
}
