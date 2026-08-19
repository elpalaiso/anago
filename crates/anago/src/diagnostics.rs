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

    /// A fixed clock, for the messages whose wording turns on one.
    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 24 * 60 * 60;

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
    fn usage_names_every_built_command_and_where_the_rest_went() {
        let usage = crate::cli::help(None);
        for command in [
            "anago server init",
            "anago server renew",
            "anago server run",
            "anago code",
            "anago join",
            "anago sync",
            "anago ls",
            "anago rm",
        ] {
            assert!(usage.contains(command), "usage omits {command}");
        }
        // What is not built yet is accounted for, so its absence does
        // not read as a bug — and what *is* built is not, so nobody
        // goes looking for a flag they already have.
        assert!(!usage.contains("(M1)"), "{usage}");
        assert!(usage.contains("M3"), "{usage}");
    }

    // ------------------------------------------------- the M1 walk

    // The same checklist for what M1 added. Each of these is a wall a
    // first automated setup actually hits, and each is somewhere a
    // person can act — a port, a token, a record, a clock, a terminal.
    // What they have in common is that anago cannot fix any of them
    // itself, which is exactly why the message has to do the work.

    #[test]
    fn a_taken_or_privileged_port_80_says_which_and_offers_the_way_round() {
        use crate::acme::{AcmeError, ListenProblem};

        // A web server has it. Not a reason to stop: the challenge
        // needs the port for seconds, and dns-01 needs it never.
        let taken = AcmeError::Listen {
            port: 80,
            problem: ListenProblem::InUse,
            detail: "Address already in use (os error 98)".to_string(),
        }
        .to_string();
        says_what_and_what_next(
            &taken,
            &["already listening on port 80"],
            &["--acme-challenge dns-01"],
        );
        assert!(taken.contains("nginx"), "names a likely culprit: {taken}");

        // Not root. A different cause with a different fix, and the
        // two must not be described in the same words.
        let refused = AcmeError::Listen {
            port: 80,
            problem: ListenProblem::Permission,
            detail: "Permission denied (os error 13)".to_string(),
        }
        .to_string();
        says_what_and_what_next(
            &refused,
            &["cannot be opened without privilege", "below 1024"],
            &["sudo", "CAP_NET_BIND_SERVICE"],
        );
        assert!(
            !refused.contains("already listening"),
            "a privilege failure is not a busy port: {refused}"
        );
    }

    #[test]
    fn a_token_that_cannot_do_the_job_says_which_permission() {
        use crate::cfapi::CfError;

        // 403 — the shape a DNS *read* token takes. "Permission
        // denied" alone sends somebody to the dashboard with nothing
        // to look for, so both permissions are named.
        let forbidden = CfError::Forbidden("Actor is not authorized".to_string()).to_string();
        says_what_and_what_next(
            &forbidden,
            &["accepted the token but will not let it do this"],
            &["Zone → DNS → Edit"],
        );
        assert!(
            forbidden.contains("Zone → Zone → Read"),
            "the lookup permission is the one a write-only token is missing: {forbidden}"
        );

        // An empty zone list. The two causes are indistinguishable
        // from here, so both are named and both have an action.
        let missing = CfError::ZoneNotFound {
            domain: "net.example.com".to_string(),
            tried: vec!["net.example.com".to_string(), "example.com".to_string()],
        }
        .to_string();
        says_what_and_what_next(
            &missing,
            &["no Cloudflare zone holds net.example.com", "example.com"],
            &["Zone Resources"],
        );
        assert!(missing.contains("not on the account"), "{missing}");

        // Neither is fatal to `server init`: the record is ten seconds
        // of browser work, and the run says so (§6.1).
        let notice = crate::cfapi::fallback_notice(&CfError::Forbidden("nope".to_string()));
        says_what_and_what_next(&notice, &["could not set the DNS record"], &["by hand"]);

        // Both permissions are named in the usage too. A token is made
        // in a browser before anago ever runs, which leaves the failure
        // message as only the second-best place to say what it needs.
        let usage = crate::cli::help(Some("server"));
        assert!(usage.contains("Zone → DNS → Edit"), "{usage}");
        assert!(usage.contains("Zone → Zone → Read"), "{usage}");
    }

    #[test]
    fn a_proxied_record_says_why_the_grey_cloud_matters() {
        use anago_core::dns::Refusal;

        // The failure §13 calls the worst shape: the certificate
        // issues, the name resolves, and the tunnel is dead — because
        // 51820/udp does not go through the proxy.
        let refused = crate::cfapi::CfError::RecordRefused(Refusal::Proxied {
            record_id: "9c8b7a65".to_string(),
        })
        .to_string();
        says_what_and_what_next(
            &refused,
            &["proxied", "UDP port is not forwarded"],
            &["DNS only (grey cloud)"],
        );
        // anago will not turn it off itself: a proxy is somebody's
        // decision about their own name.
        assert!(refused.contains("will not turn that off"), "{refused}");
    }

    fn rate_limited(retry_after: Option<std::time::Duration>) -> crate::acme::AcmeError {
        crate::acme::AcmeError::Order {
            domain: "net.example.com".to_string(),
            detail: "urn:ietf:params:acme:error:rateLimited: too many certificates \
                     already issued for this exact set of identifiers"
                .to_string(),
            retry_after,
        }
    }

    #[test]
    fn a_rate_limit_says_that_waiting_is_the_fix() {
        use crate::acme::{self, AcmeError, FailureKind};

        // The interactive path: one attempt, no schedule, and the CA's
        // own sentence is all that would otherwise reach the screen.
        // Retrying is the thing a person does next, and it is the one
        // thing that does not help.
        let limited = rate_limited(None).to_string();
        says_what_and_what_next(
            &limited,
            &["rate limit", "refill over hours"],
            &["spends an attempt and changes nothing"],
        );
        // The way *round* it is not here, because it depends on
        // something an error type does not know — see below.
        assert!(!limited.contains("--acme-staging"), "{limited}");

        // §13: what the CA said about timing is passed on rather than
        // re-guessed. Only the unattended path was reading it, and the
        // person typing the command is the one who has to decide when
        // to come back.
        let timed = AcmeError::Order {
            domain: "net.example.com".to_string(),
            detail: "urn:ietf:params:acme:error:rateLimited: too many certificates".to_string(),
            retry_after: Some(std::time::Duration::from_secs(3 * 24 * 60 * 60)),
        }
        .to_string();
        assert!(timed.contains("about 72 hours"), "{timed}");

        // An ordinary refusal must not pick up the same advice —
        // waiting for a wall that is not there is its own dead end.
        let ordinary = AcmeError::Order {
            domain: "net.example.com".to_string(),
            detail: "connection reset".to_string(),
            retry_after: None,
        }
        .to_string();
        assert!(!ordinary.contains("rate limit"), "{ordinary}");

        // The unattended path says it in its own terms, because there
        // the question is why the next attempt is an hour away.
        let waiting = acme::waiting_line(
            std::time::Duration::from_secs(3600),
            1,
            FailureKind::RateLimited,
            Some(NOW + 30 * DAY),
            NOW,
        );
        says_what_and_what_next(
            &waiting,
            &["rate limiting"],
            &["keeps working until it expires"],
        );
    }

    fn renewing(error: crate::acme::AcmeError, not_after: Option<i64>) -> String {
        crate::renew::RenewError::Acme {
            source: Box::new(error),
            not_after,
            now: NOW,
        }
        .to_string()
    }

    #[test]
    fn what_to_do_about_a_rate_limit_depends_on_having_a_certificate() {
        use crate::acme::AcmeError;

        // `server init` has nothing to lose: no hub exists yet — it
        // refuses to run over one that does — so staging is exactly
        // the place to carry on checking the wiring (§13).
        let first_run = crate::init::InitError::Acme(rate_limited(None)).to_string();
        says_what_and_what_next(&first_run, &["rate limit"], &["--acme-staging"]);
        assert!(
            first_run.contains("nothing here has a certificate yet"),
            "{first_run}"
        );

        // `server renew` is the same failure with the opposite answer.
        // The flag that gets past the limit is a different CA, a
        // different CA re-issues (§8), and the re-issue would replace
        // what is on disk with one `join` refuses.
        let an_hour = Some(std::time::Duration::from_secs(3600));
        let with_a_month = renewing(rate_limited(an_hour), Some(NOW + 30 * DAY));
        says_what_and_what_next(
            &with_a_month,
            &["rate limit"],
            &["keeps working until it expires"],
        );
        assert!(
            with_a_month.contains("Not --acme-staging"),
            "{with_a_month}"
        );
        assert!(with_a_month.contains("nothing trusts"), "{with_a_month}");

        // And neither says the other's, which is the point of telling
        // them apart at all.
        assert!(!with_a_month.contains("check the wiring"), "{with_a_month}");
        assert!(!first_run.contains("Not --acme-staging"), "{first_run}");

        // A failure that is not a rate limit gets neither.
        let ordinary = renewing(
            AcmeError::Order {
                domain: "net.example.com".to_string(),
                detail: "connection reset".to_string(),
                retry_after: None,
            },
            Some(NOW + 30 * DAY),
        );
        assert!(!ordinary.contains("--acme-staging"), "{ordinary}");
        assert!(!ordinary.contains("keeps working"), "{ordinary}");
    }

    #[test]
    fn a_renewal_only_calls_waiting_free_when_the_certificate_outlasts_it() {
        // The same rate limit, three hubs. `server renew` is run
        // because something is already wrong, so the certificate it is
        // replacing is not always healthy — and "waiting costs nothing"
        // is a claim about a clock, not a fact about renewals.
        let three_days = Some(std::time::Duration::from_secs(3 * 24 * 60 * 60));

        // Weeks left: waiting really is free.
        let healthy = renewing(rate_limited(three_days), Some(NOW + 30 * DAY));
        assert!(healthy.contains("waiting costs nothing"), "{healthy}");

        // The CA wants three days and there is one left. Waiting is an
        // outage with a date on it, and saying it costs nothing would
        // send somebody away from a hub about to go quiet.
        let overtaken = renewing(rate_limited(three_days), Some(NOW + DAY));
        assert!(!overtaken.contains("costs nothing"), "{overtaken}");
        assert!(overtaken.contains("sooner than that"), "{overtaken}");
        assert!(overtaken.contains("stops being trusted"), "{overtaken}");

        // Already lapsed — the reason a person is running this by hand
        // in the first place. Nothing is "keeping working".
        let lapsed = renewing(rate_limited(three_days), Some(NOW - DAY));
        assert!(!lapsed.contains("keeps working"), "{lapsed}");
        assert!(lapsed.contains("expired 1d ago"), "{lapsed}");
        assert!(lapsed.contains("untrusted already"), "{lapsed}");

        // What none of them changes: the flag not to reach for.
        for said in [&healthy, &overtaken, &lapsed] {
            assert!(said.contains("Not --acme-staging"), "{said}");
        }
        // And where the API does go down, what that costs — the same
        // answer both times, and absent from the one where it does not
        // (§8).
        for said in [&overtaken, &lapsed] {
            assert!(said.contains("WireGuard uses no certificate"), "{said}");
        }
        assert!(!healthy.contains("WireGuard"), "{healthy}");

        // And an expiry that could not be read is not filled in with
        // an assumption in either direction.
        let unknown = renewing(rate_limited(three_days), None);
        assert!(unknown.contains("could not read the expiry"), "{unknown}");
        assert!(!unknown.contains("costs nothing"), "{unknown}");
    }

    #[test]
    fn a_record_that_never_spread_says_what_became_of_it() {
        use crate::cfapi::{self, CfError};
        use crate::dnsprobe::ProbeError;
        use std::time::Duration;

        // The slow failure. What a person cannot see is that anago
        // stopped *before* asking the CA, so no failed validation was
        // spent on a challenge that was going to fail.
        let waited = ProbeError::NotServed {
            name: "_acme-challenge.net.example.com".to_string(),
            waited: Duration::from_secs(120),
        }
        .to_string();
        says_what_and_what_next(
            &waited,
            &["_acme-challenge.net.example.com", "still not serving it"],
            &["--acme-challenge http-01"],
        );

        // The other thing they cannot see is whether the TXT record is
        // still in the zone. Removal is the guard's, it happens while
        // this run unwinds, and it can fail — so the message says what
        // is attempted and where the answer will be, rather than
        // reporting a result it was written before.
        let stopped = crate::acme::AcmeError::Propagation {
            detail: waited.clone(),
        }
        .to_string();
        assert!(stopped.contains("taken back out of the zone"), "{stopped}");
        assert!(stopped.contains("which record to delete"), "{stopped}");
        assert!(
            !stopped.contains("has been removed"),
            "not a result, an attempt: {stopped}"
        );

        // And when it does fail, that warning names the record itself.
        // Nobody goes looking for a stray TXT they were not told about.
        let left = cfapi::left_behind(
            "_acme-challenge.net.example.com",
            "9c8b7a6554433221100ffeeddccbbaa9",
            &CfError::Forbidden("Actor is not authorized".to_string()),
        );
        says_what_and_what_next(
            &left,
            &[
                "could not be removed",
                "9c8b7a6554433221100ffeeddccbbaa9",
                "_acme-challenge.net.example.com",
            ],
            &["delete the TXT record"],
        );
        // It is tidiness, not breakage, and saying so stops a person
        // hunting for what the leftover broke.
        assert!(left.contains("nothing needs it after validation"), "{left}");
    }

    #[test]
    fn a_machine_with_no_scheduler_is_told_so_rather_than_half_served() {
        use crate::timer::{self, Existing, Plan, Scheduler, Setup, TimerError};
        use std::time::Duration;

        let setup = Setup {
            exec: Path::new("/usr/local/bin/anago"),
            device_file: Path::new("/etc/anago/device.json"),
            wg_config: Path::new("/etc/wireguard/anago.conf"),
            interval: Duration::from_secs(300),
            unit_dir: Path::new("/etc/systemd/system"),
            daemon_dir: Path::new("/Library/LaunchDaemons"),
        };
        let nothing_installed = Existing {
            joined: true,
            schedule: Vec::new(),
        };

        // Neither systemd nor launchd: nothing is installed, and the
        // report has to be a line a person can use rather than an
        // apology.
        let plan = timer::plan(Scheduler::Neither, &nothing_installed, &setup)
            .expect("a machine with no scheduler still gets a plan");
        assert!(matches!(plan, Plan::ByHand { .. }), "{plan:?}");
        let report = timer::report(&plan, setup.device_file);
        says_what_and_what_next(
            &report,
            &["neither systemd nor launchd", "nothing was\ninstalled"],
            &["crontab"],
        );
        assert!(
            report.contains("anago sync"),
            "the by-hand run is the other way out: {report}"
        );

        // And a period cron cannot keep is refused with the periods it
        // can — cron repeats on the clock, not on a stopwatch.
        let odd = timer::plan(
            Scheduler::Neither,
            &nothing_installed,
            &Setup {
                interval: Duration::from_secs(7 * 60),
                ..setup
            },
        )
        .expect_err("7 minutes does not divide an hour");
        assert!(matches!(odd, TimerError::NotCron { .. }), "{odd:?}");
        says_what_and_what_next(
            &odd.to_string(),
            &["cron repeats on the clock"],
            &["5m", "15m"],
        );

        // And the usage says it before the attempt: --interval's range
        // is wider than a crontab can keep, so a machine with neither
        // scheduler would otherwise read the range, pick 7m, and be
        // refused by a rule it had no way to know.
        let usage = crate::cli::help(Some("sync"));
        assert!(usage.contains("divide"), "{usage}");
        assert!(usage.contains("on the clock"), "{usage}");
    }

    #[test]
    fn a_terminal_that_cannot_show_a_qr_says_so_before_and_after() {
        use crate::join::{export_note, Handed, JoinError};
        use anago_core::name::DeviceName;

        // Too narrow. Refused rather than drawn smaller: a QR wider
        // than the window wraps, and a wrapped one still looks like a
        // QR — the person finds out by holding a phone to it.
        let narrow = JoinError::TooNarrow {
            needed: 65,
            available: 40,
        }
        .to_string();
        says_what_and_what_next(
            &narrow,
            &[
                "40 columns",
                "needs 65",
                "wrapped one still looks like a QR",
            ],
            &["--export conf"],
        );

        // Wide enough, drawn, and the phone still will not read it —
        // the one QR failure with no error to attach advice to, since
        // whether the blocks meet is the font's business and anago
        // cannot see the screen. The note beside the code carries it.
        let note = export_note(&DeviceName::parse("phone").unwrap(), &Handed::Qr);
        let said = flowed(&note);
        says_what_and_what_next(
            &said,
            &["If the phone will not read it", "cannot be re-sent"],
            &["--export conf"],
        );
        assert!(
            said.contains("anago rm phone") && said.contains("anago code"),
            "the way out is a fresh registration, not a redraw: {note}"
        );

        // A window between the pre-flight floor and the real code's
        // width spends the join code before it fails, so what is worth
        // knowing is in the usage, before the code is typed. Not a
        // width: the code grows with the hub's name, so the usage says
        // *that* — `qrcode` holds both ends of it — and says where the
        // real number comes from.
        let usage = crate::cli::help(Some("join"));
        assert!(
            usage.contains("refused rather than drawn wrapped"),
            "{usage}"
        );
        assert!(usage.contains("follows the hub's name"), "{usage}");
        assert!(
            usage.contains("only known once the hub has answered"),
            "{usage}"
        );
    }

    /// A note's words with the hand-made wrapping taken back out, so an
    /// assertion is about what it says and not where a line broke.
    fn flowed(note: &str) -> String {
        note.lines().map(str::trim).collect::<Vec<_>>().join(" ")
    }
}
