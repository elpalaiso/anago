//! What anago prints (DESIGN.md §8).
//!
//! `ls` builds a table here; M1's three noisier moments — a `sync` run,
//! a certificate arriving, a profile leaving for a phone — build their
//! lines here too. Wording is a design decision as much as a format is:
//! §6.3 fixes what a sync run may say, §8 what `server renew` reports,
//! §7.3 what has to be said out loud before a private key goes on
//! screen. Keeping the strings in a pure module means those rules are
//! held by tests instead of by whoever last edited a `println!`.
//!
//! **Times are printed relative to now** — "in 59d", "2m ago" — and
//! never as calendar dates. §10.1 kept date handling out of core on
//! purpose, and a relative form answers the question a person actually
//! has ("do I need to do something about this soon?") without a
//! timezone or a leap year anywhere in it.
//!
//! Pure text: rows in, a table out. The two callers know different
//! things and both go through here — on the server, `ls` reads the
//! state file and asks `wg show` when each device was last heard from;
//! on a device, the API answers with identity only, so the handshake
//! column is [`LastHandshake::Unknown`] rather than a guess.
//!
//! Column widths count East Asian characters as two columns, because a
//! Korean device name is a first-class name here (§8.1) and a table
//! that only lines up for ASCII is a table that does not line up.

use std::fmt;
use std::net::Ipv4Addr;

use crate::name::DeviceName;
use crate::state::Challenge;
use crate::sync::Sync;

/// Characters of a public key kept before the ellipsis. Enough to tell
/// two keys apart at a glance, short enough to leave the table
/// readable on an 80-column terminal.
pub const KEY_PREFIX_LEN: usize = 8;

/// When a device last completed a handshake with the hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastHandshake {
    /// Nobody asked wg — `ls` run on a device, which only has the API
    /// (§8: M0's `GET /peers` carries identity, not liveness).
    Unknown,
    /// wg was asked and has never seen this peer.
    Never,
    /// Unix epoch seconds of the last handshake.
    At(i64),
}

/// One line of the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRow {
    pub name: String,
    pub address: Ipv4Addr,
    pub public_key: String,
    pub last_handshake: LastHandshake,
}

/// Renders the device table, or a line saying there are none.
///
/// `now` is Unix epoch seconds; handshakes are shown relative to it,
/// which is what a person actually wants to know ("2m ago" beats a
/// timestamp they have to subtract).
pub fn peer_table(rows: &[PeerRow], now: i64) -> String {
    if rows.is_empty() {
        return "no devices yet — run `anago code` on the server to add one\n".to_string();
    }

    let headers = ["NAME", "ADDRESS", "PUBLIC KEY", "LAST HANDSHAKE"];
    let cells: Vec<[String; 4]> = rows
        .iter()
        .map(|row| {
            [
                row.name.clone(),
                row.address.to_string(),
                abbreviate_key(&row.public_key),
                format_handshake(row.last_handshake, now),
            ]
        })
        .collect();

    let mut widths = headers.map(display_width);
    for row in &cells {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(display_width(cell));
        }
    }

    let mut out = String::new();
    write_row(&headers.map(String::from), &widths, &mut out);
    for row in &cells {
        write_row(row, &widths, &mut out);
    }
    out
}

/// Two spaces between columns, no trailing blanks — a padded last
/// column would show up as invisible whitespace in anything that pipes
/// this.
fn write_row(cells: &[String; 4], widths: &[usize; 4], out: &mut String) {
    let mut line = String::new();
    for (i, cell) in cells.iter().enumerate() {
        if i > 0 {
            line.push_str("  ");
        }
        line.push_str(cell);
        if i + 1 < cells.len() {
            for _ in display_width(cell)..widths[i] {
                line.push(' ');
            }
        }
    }
    out.push_str(line.trim_end());
    out.push('\n');
}

/// First [`KEY_PREFIX_LEN`] characters and an ellipsis. Keys shorter
/// than that are printed whole rather than padded into a lie.
pub fn abbreviate_key(key: &str) -> String {
    if key.chars().count() <= KEY_PREFIX_LEN {
        return key.to_string();
    }
    let prefix: String = key.chars().take(KEY_PREFIX_LEN).collect();
    format!("{prefix}…")
}

/// `2m ago`, `never`, or `—` when nothing asked.
pub fn format_handshake(handshake: LastHandshake, now: i64) -> String {
    match handshake {
        LastHandshake::Unknown => "—".to_string(),
        LastHandshake::Never => "never".to_string(),
        LastHandshake::At(at) => format_ago(now.saturating_sub(at)),
    }
}

/// Coarse relative time. Nobody reading `ls` needs the seconds in "3
/// days ago", and a clock that ran backwards should not print a
/// negative age.
fn format_ago(seconds: i64) -> String {
    match seconds {
        i64::MIN..=9 => "just now".to_string(),
        10..=59 => format!("{seconds}s ago"),
        60..=3599 => format!("{}m ago", seconds / 60),
        3600..=86_399 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86_400),
    }
}

// ------------------------------------------------------------ sync

/// The one line a `sync` run prints (§6.3).
///
/// Called **after** the work is done, so a rewrite is reported in the
/// past tense. Under `--quiet` the caller prints nothing at all for the
/// outcomes that need no attention; the wording here is for a person
/// who typed the command.
///
/// A detachment defers to [`crate::sync::Detachment`]'s own words: the
/// cleanup a person has to perform belongs beside the reason for it,
/// not in a formatting module.
pub fn sync_summary(outcome: &Sync, domain: &str) -> String {
    match outcome {
        Sync::Unchanged => format!("{domain}: in sync\n"),
        // Deliberately not "in sync". The roster was checked and this
        // device is still on it, but the hub reported nothing to
        // compare the local config against, so the config may well be
        // wrong (§6.3). Claiming otherwise would be an assertion with
        // nothing behind it.
        Sync::Unverifiable => format!(
            "{domain}: still registered; this hub does not report its own settings, \
             so the local config was not checked\n"
        ),
        Sync::Rewrite(changes) => format!("{domain}: updated the wg config ({changes})\n"),
        Sync::Detached(detachment) => format!("{domain}: {detachment}\n"),
    }
}

// ------------------------------------------------------------ ACME

/// A step of an ACME run, as it happens.
///
/// A closed vocabulary rather than free-form strings, so the binary
/// cannot narrate the same step two ways in two places — issuance and
/// renewal walk the same path and should read the same walking it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeStep {
    /// No account key on disk yet; registering one with the CA.
    RegisteringAccount,
    /// An account key was already there, so the CA is not asked again.
    ReusingAccount,
    /// The order is placed and the CA has named its challenges.
    Ordered,
    /// HTTP-01: anago is answering on this port until the CA has
    /// looked. Named because that port has to be reachable from
    /// outside, and this is the moment it matters (§13).
    ServingHttpChallenge { port: u16 },
    /// DNS-01: the TXT record is in the zone.
    PublishedDnsChallenge { name: String },
    /// DNS-01: waiting for the record to become visible. The slow step,
    /// and the one worth naming — a silent minute here looks like a
    /// hang.
    WaitingForDns,
    /// Waiting for the CA to check the challenge.
    WaitingForValidation,
    /// The challenge passed; asking for the certificate itself.
    Finalizing,
    /// DNS-01: the challenge record is gone again. Said out loud
    /// because a leftover TXT is something a person may go hunting for
    /// (§9.1).
    RemovedDnsChallenge,
    /// HTTP-01: the responder is down and the port is free again.
    StoppedHttpChallenge,
}

/// The line that opens an ACME run (§8), before any [`AcmeStep`].
///
/// Names the challenge and the CA up front, because those two decide
/// what has to be reachable and what a failure will mean: HTTP-01 needs
/// :80 from outside, DNS-01 needs the token to still work, and staging
/// means the result will not be trusted (§13).
pub fn acme_started(domain: &str, challenge: Challenge, staging: bool, renewing: bool) -> String {
    let what = if renewing { "renewing" } else { "requesting" };
    let ca = if staging {
        "Let's Encrypt staging"
    } else {
        "Let's Encrypt"
    };
    format!(
        "{what} a certificate for {domain} from {ca} via {}\n",
        challenge.as_str()
    )
}

/// One step of a run in progress.
///
/// Indented under [`acme_started`] so a run reads as one block rather
/// than as a pile of unrelated lines.
pub fn acme_progress(step: &AcmeStep) -> String {
    let line = match step {
        AcmeStep::RegisteringAccount => "registering an ACME account".to_string(),
        AcmeStep::ReusingAccount => "using the existing ACME account".to_string(),
        AcmeStep::Ordered => "order placed".to_string(),
        AcmeStep::ServingHttpChallenge { port } => {
            format!("answering the challenge on :{port} — it must be reachable from outside")
        }
        AcmeStep::PublishedDnsChallenge { name } => format!("published the record {name}"),
        AcmeStep::WaitingForDns => "waiting for the record to propagate".to_string(),
        AcmeStep::WaitingForValidation => "waiting for the CA to check it".to_string(),
        AcmeStep::Finalizing => "challenge accepted; requesting the certificate".to_string(),
        AcmeStep::RemovedDnsChallenge => "removed the challenge record".to_string(),
        AcmeStep::StoppedHttpChallenge => "stopped answering; the port is free again".to_string(),
    };
    format!("  {line}\n")
}

/// What `server init`/`server renew` say once a certificate is in hand
/// (§8).
///
/// `renewing` is the same flag [`acme_started`] takes, and it has to be
/// here too: §8 requires the run to say *what it did*, and "issued"
/// after a renewal is not that. The two endings look alike otherwise,
/// which is exactly why the word has to differ.
///
/// `not_after` is `None` when the expiry could not be read out of the
/// certificate — the message says so rather than inventing a date,
/// because §9.1 then renews on an assumed lifetime and a person is
/// entitled to know they are on the assumption.
pub fn certificate_ready(
    domain: &str,
    challenge: Challenge,
    not_after: Option<i64>,
    renew_after: i64,
    now: i64,
    staging: bool,
    renewing: bool,
) -> String {
    let what = if renewing {
        "renewed the certificate for"
    } else {
        "issued a certificate for"
    };
    let mut out = format!("{what} {domain} via {}\n", challenge.as_str());
    match not_after {
        Some(not_after) => out.push_str(&format!(
            "  expires {}, renewing {}\n",
            format_in(not_after.saturating_sub(now)),
            format_in(renew_after.saturating_sub(now))
        )),
        None => out.push_str(&format!(
            "  expiry could not be read from the certificate; renewing {} on an assumed lifetime\n",
            format_in(renew_after.saturating_sub(now))
        )),
    }
    if staging {
        out.push_str(&staging_warning());
    }
    out
}

/// The warning that has to follow a staging certificate (§8).
///
/// A staging certificate is not publicly trusted, so `join` fails with
/// `UnknownIssuer` — and that is the expected outcome at this stage,
/// not a fault. Saying only the first half would send someone hunting a
/// bug that is not there.
pub fn staging_warning() -> String {
    "\
  WARNING: this is a Let's Encrypt *staging* certificate. Devices will not
  trust it, so `anago join` fails with UnknownIssuer — that is expected.
  Use it to check the wiring, then switch with:
      anago server renew --acme-production
"
    .to_string()
}

/// `server renew` when nothing needed doing (§8): the command is
/// idempotent, so it says when it will act instead of acting.
pub fn renewal_not_due(due_at: i64, now: i64) -> String {
    format!(
        "the certificate is current — renewing {}\n",
        format_in(due_at.saturating_sub(now))
    )
}

/// `server renew` when flags changed settings that do not change the
/// certificate (§8): the challenge, the contact, the token path.
///
/// Saying which of the two happened is the point. Without it, "renewed"
/// and "recorded a setting" look identical from outside.
pub fn settings_recorded(due_at: i64, now: i64) -> String {
    format!(
        "settings recorded; the certificate is unchanged — renewing {}\n",
        format_in(due_at.saturating_sub(now))
    )
}

// ---------------------------------------------------------- --export

/// How an exported profile left this machine (§8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportForm {
    /// Printed as text.
    Conf,
    /// Drawn as a QR code.
    Qr,
}

/// The warning that goes to stderr beside an exported profile (§7.3).
///
/// The profile itself is the phone's private key in plain text, which
/// makes this the one place anago prints a secret on purpose. Every
/// clause is a rule from §7.3:
///
/// - it says what the text is, because "a config" does not sound like a
///   credential;
/// - it says to delete it after the transfer, and where from — the
///   terminal's scrollback for a QR, the file for `--out`;
/// - without `--out` it points at `--out`, because a shell redirect's
///   mode is the umask's business and commonly lands world-readable.
///   That advice comes from the flag, not from inspecting stdout: no
///   guessing what the output is attached to (§7.3).
pub fn export_warning(form: ExportForm, name: &DeviceName, out_path: Option<&str>) -> String {
    let mut out = format!(
        "WARNING: this is {name}'s private key in plain text. Anyone who reads it\n\
         can join the network as that device.\n"
    );
    match out_path {
        Some(path) => out.push_str(&format!(
            "  Written to {path} (0600). Delete it once the phone has imported it.\n"
        )),
        None => out.push_str(
            "  To put it in a file, use --out: a shell redirect (>) leaves the mode\n\
             \x20 to your umask, which is usually world-readable.\n",
        ),
    }
    if form == ExportForm::Qr {
        out.push_str(
            "  The code stays in this terminal's scrollback, which `clear` does not\n\
             \x20 erase and some terminals write to disk. Clear the scrollback after\n\
             \x20 scanning it.\n",
        );
    }
    out.push_str(&format!(
        "  This device cannot manage {name} afterwards — remove it from the hub\n\
         \x20 with `anago rm {name}`.\n"
    ));
    out
}

/// Future-facing twin of [`format_ago`]: `in 59d`, `now`.
///
/// A deadline already past reads as `now` rather than as a negative
/// duration — that is what it means to the person reading it.
fn format_in(seconds: i64) -> String {
    match seconds {
        i64::MIN..=0 => "now".to_string(),
        1..=59 => format!("in {seconds}s"),
        60..=3599 => format!("in {}m", seconds / 60),
        3600..=86_399 => format!("in {}h", seconds / 3600),
        _ => format!("in {}d", seconds / 86_400),
    }
}

/// Terminal columns a string occupies, counting East Asian wide
/// characters as two.
///
/// An approximation of UAX #11: the ranges below cover Hangul, Han,
/// Kana, and full-width forms, which is what device names in this
/// project actually contain. Getting the long tail exactly right needs
/// a Unicode table, and core takes no dependencies (§4).
fn display_width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

fn char_width(c: char) -> usize {
    match c as u32 {
        0x1100..=0x115F // Hangul Jamo
        | 0x2E80..=0x303E // CJK radicals, Kangxi, CJK symbols
        | 0x3041..=0x33FF // Kana, Hangul Compatibility Jamo, CJK compatibility
        | 0x3400..=0x4DBF // CJK Extension A
        | 0x4E00..=0x9FFF // CJK Unified Ideographs
        | 0xA960..=0xA97F // Hangul Jamo Extended-A
        | 0xAC00..=0xD7A3 // Hangul Syllables
        | 0xF900..=0xFAFF // CJK Compatibility Ideographs
        | 0xFE30..=0xFE6F // CJK compatibility forms
        | 0xFF00..=0xFF60 // Full-width forms
        | 0xFFE0..=0xFFE6
        | 0x20000..=0x3FFFD => 2,
        _ => 1,
    }
}

impl fmt::Display for LastHandshake {
    /// Absolute form, for logs and messages that have no `now` to be
    /// relative to.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LastHandshake::Unknown => f.write_str("unknown"),
            LastHandshake::Never => f.write_str("never"),
            LastHandshake::At(at) => write!(f, "{at}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------- M1 sync

    const DAY: i64 = 86_400;

    fn changes(endpoint: bool, key: bool) -> crate::sync::Changes {
        crate::sync::Changes {
            server_public_key: key,
            server_endpoint: endpoint,
            server_address: false,
        }
    }

    #[test]
    fn a_quiet_sync_says_so_in_one_line() {
        assert_eq!(
            sync_summary(&Sync::Unchanged, "net.example.com"),
            "net.example.com: in sync\n"
        );
        assert_eq!(
            sync_summary(&Sync::Unchanged, "net.example.com")
                .lines()
                .count(),
            1
        );
    }

    #[test]
    fn an_unverifiable_sync_does_not_claim_to_be_in_sync() {
        // The hub reported nothing to compare against, so the local
        // config may well be wrong (§6.3). "in sync" here would assert
        // something nothing checked.
        let line = sync_summary(&Sync::Unverifiable, "net.example.com");
        assert!(!line.contains("in sync"), "{line}");
        assert!(line.contains("still registered"), "{line}");
        assert!(line.contains("does not report its own settings"), "{line}");
        assert!(line.contains("was not checked"), "{line}");
    }

    // ---------------------------------------------------- M1 progress

    #[test]
    fn a_run_opens_by_naming_the_challenge_and_the_ca() {
        // The two facts that decide what has to be reachable and what a
        // failure will mean (§13).
        let line = acme_started("net.example.com", Challenge::Http01, false, false);
        assert_eq!(
            line,
            "requesting a certificate for net.example.com from Let's Encrypt via http-01\n"
        );
        let renewing = acme_started("net.example.com", Challenge::Dns01, true, true);
        assert!(renewing.starts_with("renewing a certificate"), "{renewing}");
        assert!(renewing.contains("staging"), "{renewing}");
        assert!(renewing.contains("dns-01"), "{renewing}");
    }

    #[test]
    fn every_step_renders_as_one_indented_line() {
        // A run has to read as one block, and no step may go missing:
        // the enum is the vocabulary, so this walks all of it.
        let steps = [
            AcmeStep::RegisteringAccount,
            AcmeStep::ReusingAccount,
            AcmeStep::Ordered,
            AcmeStep::ServingHttpChallenge { port: 80 },
            AcmeStep::PublishedDnsChallenge {
                name: "_acme-challenge.net.example.com".to_string(),
            },
            AcmeStep::WaitingForDns,
            AcmeStep::WaitingForValidation,
            AcmeStep::Finalizing,
            AcmeStep::RemovedDnsChallenge,
            AcmeStep::StoppedHttpChallenge,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for step in &steps {
            let line = acme_progress(step);
            assert!(line.starts_with("  "), "{line}");
            assert!(line.ends_with('\n'), "{line}");
            assert_eq!(line.lines().count(), 1, "{line}");
            assert!(seen.insert(line), "two steps render the same way");
        }
    }

    #[test]
    fn the_http_step_says_the_port_has_to_be_reachable() {
        // The commonest way HTTP-01 fails is a closed :80 (§13), so the
        // line that mentions the port says what it needs.
        let line = acme_progress(&AcmeStep::ServingHttpChallenge { port: 80 });
        assert!(line.contains(":80"), "{line}");
        assert!(line.contains("reachable from outside"), "{line}");
    }

    #[test]
    fn the_dns_steps_name_the_record_and_its_removal() {
        // A leftover TXT is something a person may go hunting for
        // (§9.1), so both ends of its life are printed.
        let published = acme_progress(&AcmeStep::PublishedDnsChallenge {
            name: "_acme-challenge.net.example.com".to_string(),
        });
        assert!(
            published.contains("_acme-challenge.net.example.com"),
            "{published}"
        );
        let removed = acme_progress(&AcmeStep::RemovedDnsChallenge);
        assert!(removed.contains("removed"), "{removed}");
    }

    #[test]
    fn the_slow_steps_say_what_is_being_waited_for() {
        // A silent minute looks like a hang.
        let dns = acme_progress(&AcmeStep::WaitingForDns);
        let ca = acme_progress(&AcmeStep::WaitingForValidation);
        assert!(dns.contains("propagate"), "{dns}");
        assert!(ca.contains("waiting for the CA"), "{ca}");
    }

    #[test]
    fn a_rewrite_names_what_moved() {
        let line = sync_summary(&Sync::Rewrite(changes(true, false)), "net.example.com");
        assert_eq!(
            line,
            "net.example.com: updated the wg config (server endpoint)\n"
        );
        let both = sync_summary(&Sync::Rewrite(changes(true, true)), "net.example.com");
        assert!(
            both.contains("server public key, server endpoint"),
            "{both}"
        );
    }

    #[test]
    fn a_detached_sync_carries_the_cleanup_it_was_given() {
        use crate::sync::Detachment;
        let line = sync_summary(&Sync::Detached(Detachment::Removed), "net.example.com");
        assert!(line.starts_with("net.example.com: "), "{line}");
        assert!(line.contains("join again"), "{line}");
    }

    // -------------------------------------------------------- M1 ACME

    #[test]
    fn a_renewal_says_it_renewed_not_that_it_issued() {
        // §8: the run has to say what it did, and the two endings look
        // alike otherwise.
        let issued = certificate_ready(
            "net.example.com",
            Challenge::Http01,
            Some(NOW + 90 * DAY),
            NOW + 60 * DAY,
            NOW,
            false,
            false,
        );
        let renewed = certificate_ready(
            "net.example.com",
            Challenge::Http01,
            Some(NOW + 90 * DAY),
            NOW + 60 * DAY,
            NOW,
            false,
            true,
        );
        assert!(issued.starts_with("issued a certificate for"), "{issued}");
        assert!(
            renewed.starts_with("renewed the certificate for"),
            "{renewed}"
        );
        assert!(!renewed.contains("issued"), "{renewed}");
        // Everything after the first word is the same report.
        assert_eq!(
            issued.lines().skip(1).collect::<Vec<_>>(),
            renewed.lines().skip(1).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_issued_certificate_reports_both_dates_relatively() {
        let line = certificate_ready(
            "net.example.com",
            Challenge::Http01,
            Some(NOW + 90 * DAY),
            NOW + 60 * DAY,
            NOW,
            false,
            false,
        );
        assert!(line.contains("net.example.com via http-01"), "{line}");
        assert!(line.contains("expires in 90d"), "{line}");
        assert!(line.contains("renewing in 60d"), "{line}");
        // No calendar dates anywhere (§10.1 keeps them out of core).
        assert!(!line.contains("20"), "{line}");
    }

    #[test]
    fn an_unreadable_expiry_is_said_out_loud() {
        // §9.1 renews on an assumed lifetime in this case; a person is
        // entitled to know they are on the assumption.
        let line = certificate_ready(
            "net.example.com",
            Challenge::Dns01,
            None,
            NOW + 30 * DAY,
            NOW,
            false,
            false,
        );
        assert!(line.contains("dns-01"), "{line}");
        assert!(line.contains("expiry could not be read"), "{line}");
        assert!(line.contains("assumed lifetime"), "{line}");
        assert!(line.contains("renewing in 30d"), "{line}");
    }

    #[test]
    fn a_staging_certificate_warns_that_join_will_fail() {
        // Saying only "issued" would send someone hunting a bug that is
        // not there (§8).
        let line = certificate_ready(
            "net.example.com",
            Challenge::Http01,
            Some(NOW + 90 * DAY),
            NOW + 60 * DAY,
            NOW,
            true,
            false,
        );
        assert!(line.contains("staging"), "{line}");
        assert!(line.contains("UnknownIssuer"), "{line}");
        assert!(line.contains("that is expected"), "{line}");
        assert!(line.contains("--acme-production"), "{line}");
    }

    #[test]
    fn a_production_certificate_carries_no_staging_warning() {
        let line = certificate_ready(
            "net.example.com",
            Challenge::Http01,
            Some(NOW + 90 * DAY),
            NOW + 60 * DAY,
            NOW,
            false,
            false,
        );
        assert!(!line.contains("staging"), "{line}");
    }

    #[test]
    fn renew_tells_the_two_no_op_endings_apart() {
        // "renewed" and "recorded a setting" look identical from
        // outside unless the output says which happened (§8).
        let not_due = renewal_not_due(NOW + 12 * DAY, NOW);
        let recorded = settings_recorded(NOW + 12 * DAY, NOW);
        assert!(not_due.contains("certificate is current"), "{not_due}");
        assert!(recorded.contains("settings recorded"), "{recorded}");
        assert!(recorded.contains("certificate is unchanged"), "{recorded}");
        assert_ne!(not_due, recorded);
        for line in [not_due, recorded] {
            assert!(line.contains("renewing in 12d"), "{line}");
        }
    }

    #[test]
    fn an_overdue_renewal_reads_as_now_not_as_a_negative() {
        let line = renewal_not_due(NOW - DAY, NOW);
        assert!(line.contains("renewing now"), "{line}");
        assert!(!line.contains('-'), "{line}");
    }

    // ------------------------------------------------------ M1 export

    fn phone() -> DeviceName {
        DeviceName::parse("폰").unwrap()
    }

    #[test]
    fn an_export_warning_says_what_the_text_is() {
        // "a config" does not sound like a credential (§7.3).
        let text = export_warning(ExportForm::Conf, &phone(), None);
        assert!(text.contains("private key in plain text"), "{text}");
        assert!(text.contains("폰"), "{text}");
        assert!(text.starts_with("WARNING:"), "{text}");
    }

    #[test]
    fn without_out_the_warning_points_at_out() {
        // Printed from the flag, not from inspecting stdout — no
        // guessing what the output is attached to (§7.3).
        let text = export_warning(ExportForm::Conf, &phone(), None);
        assert!(text.contains("--out"), "{text}");
        assert!(text.contains("umask"), "{text}");
    }

    #[test]
    fn with_out_the_warning_names_the_file_instead() {
        let text = export_warning(ExportForm::Conf, &phone(), Some("/tmp/phone.conf"));
        assert!(text.contains("/tmp/phone.conf"), "{text}");
        assert!(text.contains("0600"), "{text}");
        assert!(text.contains("Delete it"), "{text}");
        // The redirect advice would be noise once a file was written.
        assert!(!text.contains("umask"), "{text}");
    }

    #[test]
    fn a_qr_warns_about_the_scrollback() {
        let qr = export_warning(ExportForm::Qr, &phone(), None);
        assert!(qr.contains("scrollback"), "{qr}");
        assert!(qr.contains("`clear` does not"), "{qr}");
        // A plain conf has no scrollback problem to describe.
        let conf = export_warning(ExportForm::Conf, &phone(), None);
        assert!(!conf.contains("scrollback"), "{conf}");
    }

    #[test]
    fn the_warning_says_how_to_undo_the_export() {
        // The phone gets no device token (§8), so it can never remove
        // itself — the only way back is from the hub.
        let text = export_warning(ExportForm::Qr, &phone(), None);
        assert!(text.contains("anago rm 폰"), "{text}");
    }

    #[test]
    fn no_message_carries_a_collapsed_line_continuation() {
        // A wrapped string literal that loses its trailing `\` turns
        // the indentation into a run of spaces inside the message. It
        // reads fine in source and wrong on screen, so it gets a test.
        let messages = [
            sync_summary(&Sync::Unverifiable, "net.example.com"),
            sync_summary(&Sync::Unchanged, "net.example.com"),
            acme_started("net.example.com", Challenge::Http01, true, false),
            certificate_ready(
                "net.example.com",
                Challenge::Http01,
                None,
                NOW,
                NOW,
                true,
                false,
            ),
            certificate_ready(
                "net.example.com",
                Challenge::Dns01,
                None,
                NOW,
                NOW,
                false,
                true,
            ),
            renewal_not_due(NOW, NOW),
            settings_recorded(NOW, NOW),
            export_warning(ExportForm::Qr, &phone(), None),
            export_warning(ExportForm::Conf, &phone(), Some("/tmp/p.conf")),
            acme_progress(&AcmeStep::WaitingForDns),
        ];
        for message in messages {
            for line in message.lines() {
                assert!(
                    !line.trim_start().contains("  "),
                    "collapsed continuation in {line:?}"
                );
            }
        }
    }

    #[test]
    fn the_warning_never_carries_the_profile() {
        // It is not handed the config at all, which is the guarantee;
        // this pins that nothing key-shaped creeps into the wording.
        for form in [ExportForm::Conf, ExportForm::Qr] {
            let text = export_warning(form, &phone(), Some("/tmp/phone.conf"));
            assert!(!text.contains("PrivateKey"), "{text}");
            assert!(!text.contains("[Interface]"), "{text}");
        }
    }

    const NOW: i64 = 1_755_500_000;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    fn row(name: &str, address: &str, key: &str, handshake: LastHandshake) -> PeerRow {
        PeerRow {
            name: name.to_string(),
            address: ip(address),
            public_key: key.to_string(),
            last_handshake: handshake,
        }
    }

    #[test]
    fn an_empty_network_says_what_to_do_next() {
        // A bare header row would read like a bug on a fresh server.
        assert_eq!(
            peer_table(&[], NOW),
            "no devices yet — run `anago code` on the server to add one\n"
        );
    }

    #[test]
    fn renders_the_table_the_server_can_fill_in() {
        let rows = [
            row(
                "macbook",
                "10.100.0.2",
                "bWFjYm9va3B1YmxpY2tleQ==",
                LastHandshake::At(NOW - 120),
            ),
            row(
                "desktop",
                "10.100.0.3",
                "ZGVza3RvcHB1YmxpY2tleQ==",
                LastHandshake::Never,
            ),
        ];
        let expected = "\
NAME     ADDRESS     PUBLIC KEY  LAST HANDSHAKE
macbook  10.100.0.2  bWFjYm9v…   2m ago
desktop  10.100.0.3  ZGVza3Rv…   never
";
        assert_eq!(peer_table(&rows, NOW), expected);
    }

    #[test]
    fn a_device_that_cannot_ask_wg_shows_a_dash() {
        // `ls` over the API: M0's /peers carries identity only, so the
        // column says "not known" rather than "never".
        let rows = [row(
            "macbook",
            "10.100.0.2",
            "bWFjYm9va3B1YmxpY2tleQ==",
            LastHandshake::Unknown,
        )];
        let table = peer_table(&rows, NOW);
        assert!(table.ends_with("—\n"), "{table}");
        assert!(!table.contains("never"), "{table}");
    }

    #[test]
    fn columns_line_up_with_korean_names() {
        // 맥북 is four terminal columns, not two: padding by character
        // count would leave the table ragged.
        let rows = [
            row("맥북", "10.100.0.2", "a", LastHandshake::Never),
            row("macbook2", "10.100.0.3", "b", LastHandshake::Never),
        ];
        let table = peer_table(&rows, NOW);
        let starts: Vec<usize> = table
            .lines()
            .map(|line| display_width(line.split("10.100").next().unwrap()))
            .collect();
        // Header has no address, so compare the two data rows.
        assert_eq!(starts[1], starts[2], "{table}");
        assert!(table.contains("맥북      10.100.0.2"), "{table}");
    }

    #[test]
    fn column_widths_follow_the_longest_value() {
        let rows = [row(
            "a-very-long-device-name-here",
            "10.100.0.2",
            "k",
            LastHandshake::Never,
        )];
        let table = peer_table(&rows, NOW);
        let header = table.lines().next().unwrap();
        let data = table.lines().nth(1).unwrap();
        // Both rows put ADDRESS at the same column.
        assert_eq!(
            header.find("ADDRESS").unwrap(),
            data.find("10.100.0.2").unwrap(),
            "{table}"
        );
    }

    #[test]
    fn no_line_carries_trailing_whitespace() {
        let rows = [
            row("macbook", "10.100.0.2", "k", LastHandshake::Never),
            row("desktop", "10.100.0.3", "k", LastHandshake::At(NOW)),
        ];
        for line in peer_table(&rows, NOW).lines() {
            assert_eq!(line, line.trim_end(), "trailing space in {line:?}");
        }
    }

    #[test]
    fn keys_are_abbreviated_but_short_ones_are_left_alone() {
        assert_eq!(abbreviate_key("bWFjYm9va3B1YmxpY2tleQ=="), "bWFjYm9v…");
        assert_eq!(abbreviate_key("12345678"), "12345678");
        assert_eq!(abbreviate_key("123456789"), "12345678…");
        assert_eq!(abbreviate_key(""), "");
        // wg keys are base64, but the cut counts characters, so a
        // multi-byte string is never sliced mid-character.
        assert_eq!(abbreviate_key("맥북맥북맥북맥북맥북"), "맥북맥북맥북맥북…");
    }

    #[test]
    fn relative_times_read_the_way_a_person_asks() {
        let cases = [
            (0, "just now"),
            (9, "just now"),
            (10, "10s ago"),
            (59, "59s ago"),
            (60, "1m ago"),
            (119, "1m ago"),
            (3_599, "59m ago"),
            (3_600, "1h ago"),
            (86_399, "23h ago"),
            (86_400, "1d ago"),
            (172_800, "2d ago"),
        ];
        for (age, expected) in cases {
            assert_eq!(
                format_handshake(LastHandshake::At(NOW - age), NOW),
                expected,
                "age {age}"
            );
        }
    }

    #[test]
    fn a_clock_that_ran_backwards_does_not_print_a_negative_age() {
        assert_eq!(
            format_handshake(LastHandshake::At(NOW + 60), NOW),
            "just now"
        );
        assert_eq!(
            format_handshake(LastHandshake::At(i64::MAX), NOW),
            "just now"
        );
        // And an absurdly old timestamp saturates instead of wrapping.
        assert!(format_handshake(LastHandshake::At(i64::MIN), NOW).ends_with("d ago"));
    }

    #[test]
    fn handshake_has_an_absolute_form_for_logs() {
        assert_eq!(LastHandshake::Unknown.to_string(), "unknown");
        assert_eq!(LastHandshake::Never.to_string(), "never");
        assert_eq!(LastHandshake::At(NOW).to_string(), "1755500000");
    }
}
