//! `anago server renew` (DESIGN.md §8).
//!
//! A standing hub, changed in one of three ways: the certificate
//! ordered again, the issuance settings changed without touching the
//! certificate, or the A record pushed at this machine's address and
//! nothing else.
//!
//! **`wg` is never touched, by any path.** Neither a certificate nor a
//! DNS record has anything to do with the peer list, the addresses or
//! the keys, and bringing the interface back up would drop every tunnel
//! at that instant. The state file's `peers`, `server` and `subnet` are
//! read and never written — [`apply`] is a pure function and the test
//! for it compares the WireGuard config the state would produce, before
//! and after.
//!
//! The decision is pure and lives in [`plan`]: given what the hub is
//! and what was asked for, what should happen. Only [`run`] talks to a
//! CA or to Cloudflare.

use std::fmt;
use std::path::Path;

use anago_core::render;
use anago_core::state::{self, Acme, Challenge, ServerState, Tls};

use crate::acme;
use crate::cfapi;
use crate::cli::{Ca, ServerRenew};
use crate::init;
use crate::paths::ServerPaths;

/// What this run will do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// The A record, and nothing else (`--dns`).
    PushRecord,
    /// Nothing is due and nothing was asked for. The command says when
    /// it will act instead of acting, which is what makes it safe in
    /// cron (§8).
    NotDue { due_at: i64 },
    /// Settings recorded; the certificate stays as it is.
    Settings,
    /// Order a certificate, recording whatever settings came with it.
    Reissue { why: Why },
}

/// Why a run is ordering a certificate.
///
/// Carried rather than reduced to a bool because §8 requires the run to
/// say what it did, and "renewed because you asked" and "renewed
/// because the settings you gave produce a different certificate" are
/// different things to have been told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// `--force`, against the schedule.
    Forced,
    /// The schedule says so (§9.1).
    Due,
    /// A setting that changes which certificate comes back — so
    /// recording it without re-issuing would make the state file a lie.
    /// The flag that did it, for the line that reports the run.
    Different(&'static str),
}

/// Decides what `server renew` does (§8).
///
/// The rule for a settings change is one line: **would issuing with
/// these settings, right now, produce a different certificate?**
///
/// - **Yes → order one, and `--force` is not required.** Changing CA
///   is this, and so is a manual hub moving to ACME. Recording
///   "production" beside a staging certificate is false, and it fails
///   at the thing the person typed the command to get. Demanding
///   `--force` would not help either: what is being forced is not their
///   intent but the file catching up with the state, and there is
///   nothing to ask.
/// - **No → record it and leave the certificate alone.** `--acme-email`,
///   `--acme-challenge` and the token flags are this. A challenge is
///   how the *next* renewal proves ownership; the certificate it
///   produces is the same certificate from the same CA for the same
///   name.
///
/// Pure, and it takes `now` rather than reading a clock, so every
/// boundary here is a test.
pub fn plan(state: &ServerState, asked: &ServerRenew, now: i64) -> Result<Plan, RenewError> {
    let tls = &state.tls;
    if asked.dns_only {
        return Ok(Plan::PushRecord);
    }
    // Before every branch below, because every one of them can return
    // a re-issue: `--force` and a CA change both used to reach one
    // first, and the token they were handed was then quietly dropped.
    check_token_has_a_job(tls, asked)?;

    let Some(current) = tls.renewable() else {
        // Somebody else's certificate, and anago does not renew those
        // (§9.1). The one thing that changes that is being told where
        // to send the CA's expiry warnings, which is what an ACME hub
        // cannot be set up without (§8).
        if asked.acme_email.is_none() {
            return Err(RenewError::NotOurs {
                cert_path: tls.cert_path.clone(),
            });
        }
        return Ok(Plan::Reissue {
            why: Why::Different("--acme-email"),
        });
    };

    // A different CA is a different certificate — and a different
    // trust store, which is the whole point of the staging move.
    if let Some(flag) = changes_ca(current, asked.ca) {
        return Ok(Plan::Reissue {
            why: Why::Different(flag),
        });
    }
    if asked.force {
        return Ok(Plan::Reissue { why: Why::Forced });
    }
    if tls.needs_renewal(now, state::RENEWAL_LEAD_SECS) {
        return Ok(Plan::Reissue { why: Why::Due });
    }
    // Asked for, and not already true. Spelling out the CA the hub is
    // already on is a reasonable thing to type — "make sure" — and
    // answering it with "settings recorded" would claim a change that
    // did not happen.
    if changes_anything(state, asked) {
        return Ok(Plan::Settings);
    }
    Ok(Plan::NotDue {
        due_at: tls
            .renewal_due(state::RENEWAL_LEAD_SECS)
            .expect("a renewable certificate has a due date"),
    })
}

/// Refuses a token this hub has nowhere to put (§9.1).
///
/// A token is kept for one reason: a DNS-01 renewal has to write a TXT
/// record every time. On a hub that will renew over HTTP-01 there is
/// nothing to keep it for, and the schema says so — `token_path` is
/// null unless the challenge is dns-01. Accepting the flag and
/// discarding it would print "settings recorded" over a command that
/// recorded nothing.
///
/// `--dns` is the other thing a token does, and it says so on the
/// command line rather than in the state file.
fn check_token_has_a_job(tls: &Tls, asked: &ServerRenew) -> Result<(), RenewError> {
    let given = match (&asked.cf_token, &asked.cf_token_file) {
        (Some(_), _) => "--cf-token",
        (_, Some(_)) => "--cf-token-file",
        _ => return Ok(()),
    };
    if resulting_challenge(tls, asked) == Challenge::Dns01 {
        return Ok(());
    }
    Err(RenewError::TokenWithoutJob {
        given,
        challenge: resulting_challenge(tls, asked),
    })
}

/// The flag that moves this hub to another CA, when one does.
///
/// Asking for the CA the hub is already on is not a change: a person
/// spelling out `--acme-production` on a production hub means "make
/// sure", and re-issuing for that would spend a rate limit to confirm
/// something already true.
fn changes_ca(current: &Acme, asked: Option<Ca>) -> Option<&'static str> {
    let (wanted, flag) = match asked? {
        Ca::Staging => (acme::STAGING, "--acme-staging"),
        Ca::Production => (acme::PRODUCTION, "--acme-production"),
    };
    (current.directory != wanted).then_some(flag)
}

/// Whether any of the flags given would actually alter the state.
///
/// The CA is settled before this is reached, so what is left is the
/// three settings that do not change the certificate. A token given on
/// the command line always counts: the value may have been rotated
/// even when the path it lands at is the recorded one, and there is
/// nothing here to compare it against.
fn changes_anything(state: &ServerState, asked: &ServerRenew) -> bool {
    let current = match state.tls.renewable() {
        Some(acme) => acme,
        None => return true,
    };
    let recorded_token = state
        .cloudflare
        .as_ref()
        .and_then(|cloudflare| cloudflare.token_path.as_deref());
    (asked.acme_email.is_some() && asked.acme_email != current.contact)
        || asked
            .acme_challenge
            .is_some_and(|challenge| challenge != current.challenge)
        || asked.cf_token.is_some()
        || (asked.cf_token_file.is_some() && asked.cf_token_file.as_deref() != recorded_token)
}

/// What this run does about the Cloudflare token (§9.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Keeping {
    /// The hub stays where it was: no token recorded and none removed.
    Unchanged,
    /// The hub is leaving DNS-01, so the token it kept for renewals has
    /// no second job. §7.1: the secret that can be got rid of is got
    /// rid of.
    Forget,
    /// The hub will renew over DNS-01, so a renewal has to be able to
    /// find the token — and the zone, which is not something it can
    /// work out from the token alone.
    Token { zone_id: String, path: String },
}

/// Which of the three this run is, decided from the flags alone.
///
/// Separate from [`Keeping`] because the answer "keep it" leaves two
/// things to find out that no pure function can: which zone the domain
/// is in, and where the token will be readable from. The caller does
/// that and builds the [`Keeping`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Unchanged,
    Forget,
    Keep,
}

/// Pure. `Forget` is only the **transition** away from DNS-01, not
/// every hub that is not on it: a bare `server renew` on an HTTP-01 hub
/// is a check, and a check that deleted a file would be a surprise.
pub fn disposition(tls: &Tls, asked: &ServerRenew) -> Disposition {
    let was = tls.renewable().map(|acme| acme.challenge);
    match (resulting_challenge(tls, asked), was) {
        (Challenge::Dns01, _) => Disposition::Keep,
        (_, Some(Challenge::Dns01)) => Disposition::Forget,
        _ => Disposition::Unchanged,
    }
}

/// Writes what was asked into the state. Pure.
///
/// **Only what was given.** A flag left out means leave that alone —
/// reading an absent `--acme-staging` as "production" would move a hub
/// to another CA on an ordinary renewal (§8).
pub fn apply(state: &mut ServerState, asked: &ServerRenew, paths: &ServerPaths, keeping: &Keeping) {
    if state.tls.renewable().is_none() {
        // manual → acme. The files anago issues go where §9 fixes; the
        // certificate the operator gave is left exactly where it is, so
        // undoing this is putting the two old paths back.
        state.tls = Tls::acme(
            paths.certificate().display().to_string(),
            paths.private_key().display().to_string(),
            Acme {
                directory: acme::directory(asked.ca == Some(Ca::Staging)).to_string(),
                contact: asked.acme_email.clone(),
                account_key_path: paths.account_key().display().to_string(),
                account_url: String::new(),
                challenge: asked.acme_challenge.unwrap_or(Challenge::Http01),
                issued_at: 0,
                renew_after: 0,
            },
        );
        // The expiry belonged to a certificate this hub is about to
        // stop serving.
        state.tls.not_after = None;
    } else {
        let acme = state.tls.renewable_mut().expect("checked just above");
        if let Some(ca) = asked.ca {
            acme.directory = acme::directory(ca == Ca::Staging).to_string();
        }
        if asked.acme_email.is_some() {
            acme.contact.clone_from(&asked.acme_email);
        }
        if let Some(challenge) = asked.acme_challenge {
            acme.challenge = challenge;
        }
    }

    match keeping {
        Keeping::Unchanged => {}
        Keeping::Forget => {
            if let Some(cloudflare) = state.cloudflare.as_mut() {
                cloudflare.token_path = None;
            }
        }
        // **The block is created when there is none.** A hub set up
        // without a token has no Cloudflare settings at all, and
        // switching it to DNS-01 without writing them is a command
        // that succeeds and leaves every later renewal failing on "no
        // Cloudflare settings recorded" (§9.1).
        Keeping::Token { zone_id, path } => match state.cloudflare.as_mut() {
            Some(cloudflare) => {
                if cloudflare.zone_id != *zone_id {
                    // Another zone: a record id from the old one means
                    // nothing in the new one (§9.1).
                    cloudflare.zone_id.clone_from(zone_id);
                    cloudflare.record_id = None;
                }
                cloudflare.token_path = Some(path.clone());
            }
            None => {
                state.cloudflare = Some(anago_core::state::Cloudflare {
                    zone_id: zone_id.clone(),
                    // Nothing has been written at this name by anago,
                    // so there is no id to point at (§9.1).
                    record_id: None,
                    token_path: Some(path.clone()),
                })
            }
        },
    }
}

/// The challenge this hub will be on when the run is over.
///
/// Needed before the state is edited, because it decides whether the
/// token is worth keeping — and that in turn is a file to write.
pub fn resulting_challenge(tls: &Tls, asked: &ServerRenew) -> Challenge {
    match (asked.acme_challenge, tls.renewable()) {
        (Some(asked), _) => asked,
        (None, Some(current)) => current.challenge,
        // A manual hub becoming an ACME one, with nothing said: the
        // same default `server init` uses without a token (§8).
        (None, None) => Challenge::Http01,
    }
}

/// What the run says it did (§8).
///
/// Without this, "ordered a certificate" and "wrote down a setting"
/// look identical from outside — the same command, the same exit code,
/// and a state file the person cannot see.
pub fn report(plan: &Plan, state: &ServerState, now: i64) -> String {
    let due_at = state
        .tls
        .renewal_due(state::RENEWAL_LEAD_SECS)
        .unwrap_or(now);
    match plan {
        Plan::PushRecord => String::new(),
        Plan::NotDue { due_at } => render::renewal_not_due(*due_at, now),
        Plan::Settings => render::settings_recorded(due_at, now),
        Plan::Reissue { why } => {
            let Some(acme) = state.tls.renewable() else {
                // Only reachable if an issuance left the hub manual,
                // which it cannot; falling back beats a panic in a
                // printer.
                return String::new();
            };
            let mut out = String::new();
            if let Why::Different(flag) = why {
                out.push_str(&format!(
                    "{flag} changes which certificate this hub gets, so it was ordered again\n"
                ));
            }
            out.push_str(&render::certificate_ready(
                &state.domain,
                acme.challenge,
                state.tls.not_after,
                acme.renew_after,
                now,
                acme.directory == acme::STAGING,
                true,
            ));
            out
        }
    }
}

/// The warning `--force` comes with (§8).
///
/// A certificate ordered before it was needed is one out of the CA's
/// weekly allowance for this name, and the allowance is small enough
/// that a few impatient runs exhaust it.
pub fn forced_warning() -> String {
    "--force ordered a certificate that was not due yet. Let's Encrypt allows only a \
     few per week for one name, so a run that keeps failing will start being refused \
     by the CA rather than by anago"
        .to_string()
}

/// What a run leaves behind about the Cloudflare token, and the guard
/// that undoes it if the run does not finish.
struct Settled {
    keeping: Keeping,
    /// The zone, when one was looked up. A DNS-01 issuance needs it and
    /// recording the token needs its id, so it is asked for once.
    zone: Option<cfapi::Zone>,
    /// A file this run wrote, held until the state names it.
    kept: Option<Kept>,
    /// A file the state has stopped naming, removed after the commit.
    stale: Option<String>,
}

/// Works out what happens to the token, doing the two things no pure
/// function can: finding the zone, and putting the token where a
/// renewal will read it.
///
/// **A hub that has no Cloudflare settings gains them here.** Switching
/// to DNS-01 without writing the zone and the token path is a command
/// that succeeds and leaves every later renewal failing on "no
/// Cloudflare settings recorded" (§9.1) — the first issuance works,
/// because this run hands the token straight to it, and nothing after
/// it does.
fn settle(
    state: &ServerState,
    paths: &ServerPaths,
    token: Option<&cfapi::Token>,
    disposition: Disposition,
) -> Result<Settled, RenewError> {
    match disposition {
        Disposition::Unchanged => Ok(Settled {
            keeping: Keeping::Unchanged,
            zone: None,
            kept: None,
            stale: None,
        }),
        Disposition::Forget => Ok(Settled {
            keeping: Keeping::Forget,
            zone: None,
            kept: None,
            // Only a file anago wrote. A `--cf-token-file` names the
            // operator's own, and dropping our reference to it is the
            // whole of what we may do with it.
            stale: state
                .cloudflare
                .as_ref()
                .and_then(|cloudflare| cloudflare.token_path.clone())
                .filter(|path| Path::new(path) == paths.cf_token()),
        }),
        Disposition::Keep => {
            let token = token.ok_or(RenewError::NoTokenForDns01)?;
            let zone = cfapi::find_zone(token, &state.domain).map_err(RenewError::Cloudflare)?;
            let kept = store_token(paths, Some(token))?;
            Ok(Settled {
                keeping: Keeping::Token {
                    zone_id: zone.id.clone(),
                    path: kept.as_ref().map(Kept::path).unwrap_or_default(),
                },
                zone: Some(zone),
                kept,
                stale: None,
            })
        }
    }
}

/// Runs the command.
///
/// The order is `server init`'s, for the same reason: everything that
/// can refuse happens before anything is written, the issuance is
/// serialized on its own lock, and the state file is committed last —
/// so a failure leaves the hub exactly as it was (§8, §9.1).
///
/// **The edits land on the state as it is under the lock**, never as a
/// whole state written over the top. A join that finished while this
/// run was talking to a CA added a peer, and replacing the file with a
/// snapshot from before would remove a device that is already
/// connected — the one way this command could disturb WireGuard, by
/// arriving at the state file holding a stale copy of it.
///
/// **Human verification needed**: this talks to a real CA and a real
/// Cloudflare zone.
pub fn run(
    store: &crate::store::Store,
    paths: &ServerPaths,
    asked: &ServerRenew,
    env: Option<&str>,
    now: i64,
) -> Result<Outcome, RenewError> {
    let state = store.read().map_err(|e| RenewError::State(e.to_string()))?;
    let plan = plan(&state, asked, now)?;

    // **A check that is not due does nothing at all.** No token read,
    // no zone looked up, no file written, no state committed. That is
    // what "safe in cron" means (§8), and a check that could fail on a
    // Cloudflare hiccup while reporting that it had done nothing would
    // not be one.
    if let Plan::NotDue { .. } = plan {
        return Ok(Outcome {
            output: report(&plan, &state, now),
            plan,
            warnings: Vec::new(),
        });
    }

    // Taken before anything outside this machine, and held to the
    // commit: a `server renew` typed while the daemon's timer is
    // mid-flight would otherwise have two runs writing the same account
    // file and the same pair (§9.1).
    let _issuing = match crate::fsutil::FileLock::try_acquire(&paths.issue_lock()) {
        Ok(Some(lock)) => lock,
        Ok(None) => return Err(RenewError::Busy),
        Err(e) => return Err(RenewError::State(e.to_string())),
    };

    let mut warnings = Vec::new();

    if plan == Plan::PushRecord {
        let token = read_token(&state, asked, env, &mut warnings)?;
        let pushed = push_record(&state, token.as_ref(), &mut warnings)?;
        // The cache is written back, and only it: §9.1 records the id
        // right after the record is made or edited, or the same
        // re-lookup repeats for ever. The token path is **not**
        // touched — `--dns` means only DNS, and keeping a secret is a
        // setting.
        let mut guard = store.lock().map_err(|e| RenewError::State(e.to_string()))?;
        remember(guard.state_mut(), &pushed);
        guard
            .commit()
            .map_err(|e| RenewError::State(e.to_string()))?;
        return Ok(Outcome {
            plan,
            output: format!("{}\n", pushed.applied),
            warnings,
        });
    }

    // The token is read **only when this run has a use for it**. A hub
    // being moved off DNS-01 is often a hub whose token expired or
    // went missing, and demanding that the thing being abandoned still
    // works would shut the door this command exists to open.
    let disposition = disposition(&state.tls, asked);
    let token = match disposition {
        Disposition::Keep => read_token(&state, asked, env, &mut warnings)?,
        Disposition::Forget | Disposition::Unchanged => None,
    };
    let mut settled = settle(&state, paths, token.as_ref(), disposition)?;

    // Held outside the match so it lives until after the commit.
    let mut artifacts = None;

    let issued = match plan {
        Plan::Reissue { .. } => {
            // The settings the CA is asked under are the ones being
            // moved to, not the ones being replaced.
            let mut wanted = state.clone();
            apply(&mut wanted, asked, paths, &settled.keeping);
            // Everything the issuance is about to replace, as it is
            // now, and at the paths the **new** settings name. A
            // failure between the CA answering and the state file
            // agreeing has to leave both as they were (§8).
            artifacts = Some(Artifacts::watching(&wanted, paths)?);
            let issued =
                acme::renew_blocking(&wanted, paths, token.clone().zip(settled.zone.clone()), now)
                    .map_err(RenewError::Acme)?;
            warnings.extend(issued.warnings.iter().cloned());
            Some(issued)
        }
        _ => None,
    };

    let mut guard = store.lock().map_err(|e| RenewError::State(e.to_string()))?;
    if guard.state().tls != state.tls {
        return Err(RenewError::Moved);
    }
    apply(guard.state_mut(), asked, paths, &settled.keeping);
    if let Some(issued) = &issued {
        acme::record(guard.state_mut(), issued, now);
        // Before the commit, so a pair that cannot be served is a
        // renewal that did not happen rather than one that is recorded
        // and invisible (§9.1).
        let loaded = crate::tls::load(
            Path::new(&guard.state().tls.cert_path),
            Path::new(&guard.state().tls.key_path),
        )
        .map_err(|e| RenewError::State(e.to_string()))?;
        guard.state_mut().tls.not_after = loaded.not_after;
        warnings.extend(loaded.warnings);
    }

    let output = report(&plan, guard.state(), now);
    guard
        .commit()
        .map_err(|e| RenewError::State(e.to_string()))?;
    // The state agrees with the files now, so both stay.
    if let Some(artifacts) = artifacts.as_mut() {
        artifacts.keep();
    }
    if let Some(kept) = settled.kept.as_mut() {
        kept.keep();
    }
    // And the one the state has stopped naming goes, in that order: a
    // delete that fails after a commit that succeeded leaves a stray
    // secret and a correct state file, which is the recoverable half
    // of the two.
    if let Some(stale) = &settled.stale {
        if let Err(e) = std::fs::remove_file(stale) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warnings.push(format!(
                    "this hub does not renew over DNS-01 any more, so it no longer needs \
                     the Cloudflare token at {stale} — and could not remove it: {e}. \
                     Delete it by hand"
                ));
            }
        }
    }

    if asked.force {
        warnings.push(forced_warning());
    }
    Ok(Outcome {
        plan,
        output,
        warnings,
    })
}

/// The files an issuance replaces, as they were before it ran.
///
/// `server init` can undo an issuance by deleting what it made, because
/// there was nothing there before. A renewal replaces a **working**
/// account and a **working** certificate, so undoing means putting the
/// old bytes back.
///
/// The failure this exists for: the CA answers, the files are
/// replaced, and then the state file cannot be committed. Without a
/// restore, a staging-to-production run that lost the race would leave
/// production credentials and a production certificate under a state
/// file that still says staging — and the next renewal would present
/// an account the recorded CA has never heard of (§8's all-or-nothing
/// rule).
///
/// **The paths are the ones the issuance actually writes**, which are
/// not all in the same place:
///
/// - The **certificate and key** always land at [`ServerPaths`]'s
///   pair, whatever `tls.cert_path` currently says — `acme::renew`
///   saves there and reports those paths back, and `acme::record` then
///   moves the state to match. A guard watching the state's paths on a
///   hub that names something else would restore two files the
///   issuance never touched and leave the managed pair replaced.
/// - The **account key** goes to the path the state records. The
///   schema lets a hub keep its account anywhere and `acme::renew`
///   writes the credentials back to the path it read, so watching the
///   default here would leave the real account file holding the new
///   CA's credentials — the exact state this is meant to prevent.
struct Artifacts {
    /// Each file and what it held, `None` for one that did not exist.
    before: Vec<(std::path::PathBuf, Option<Vec<u8>>)>,
    keep: bool,
}

impl Artifacts {
    /// Snapshots the files an issuance under `state` will write.
    ///
    /// `state` is the hub **as this run is about to make it**: a CA
    /// change moves the account, and a manual hub being taken over
    /// gains an account path it did not have.
    ///
    /// A file that exists and cannot be read stops the run **before**
    /// the CA is called. Reading that as "there was nothing here"
    /// would arm a guard that deletes a working account on the way
    /// out, and a run that has not started costs nothing to abandon.
    fn watching(state: &ServerState, paths: &ServerPaths) -> Result<Artifacts, RenewError> {
        let account = match state.tls.renewable() {
            Some(acme) => std::path::PathBuf::from(&acme.account_key_path),
            // Only reachable if this is called for a hub the run is
            // leaving manual, which no re-issue does.
            None => paths.account_key(),
        };
        // A hub that points its account at one of the pair would
        // otherwise be snapshotted twice and restored from whichever
        // copy ran last.
        let mut watched: Vec<std::path::PathBuf> = Vec::with_capacity(3);
        for path in [paths.certificate(), paths.private_key(), account] {
            if !watched.contains(&path) {
                watched.push(path);
            }
        }

        let mut before = Vec::with_capacity(watched.len());
        for path in watched {
            let contents = match std::fs::read(&path) {
                Ok(contents) => Some(contents),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => {
                    return Err(RenewError::Unreadable {
                        path: path.display().to_string(),
                        detail: e.to_string(),
                    })
                }
            };
            before.push((path, contents));
        }
        Ok(Artifacts {
            before,
            keep: false,
        })
    }

    fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for Artifacts {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        for (path, before) in &self.before {
            let now = std::fs::read(path).ok();
            if &now == before {
                continue;
            }
            let undone = match before {
                Some(contents) => crate::fsutil::write_private_bytes(path, contents),
                None => std::fs::remove_file(path),
            };
            if let Err(e) = undone {
                // There is nobody to return this to — the run is
                // already failing — but a hub whose files and state
                // disagree is a hub that stops renewing, so it is said
                // out loud rather than swallowed.
                eprintln!(
                    "anago: warning: could not put {} back as it was after a failed \
                     renewal: {e}. The hub may now be serving a certificate its state \
                     file does not describe; `anago server renew --force` will make \
                     them agree again",
                    path.display()
                );
            }
        }
    }
}

/// What a run did, ready to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub plan: Plan,
    pub output: String,
    pub warnings: Vec<String>,
}

/// The token this run can use, in §8's order: **an explicit flag, then
/// the file the hub recorded, then the environment.**
///
/// The recorded path is a fallback and only a fallback. Passing it to
/// [`cfapi::choose`] alongside `--cf-token` would look like the two
/// command-line flags given together and be refused as such — so a hub
/// already renewing over DNS-01 could not be handed a rotated token
/// without first editing its state file by hand.
fn read_token(
    state: &ServerState,
    asked: &ServerRenew,
    env: Option<&str>,
    warnings: &mut Vec<String>,
) -> Result<Option<cfapi::Token>, RenewError> {
    let flag = asked.cf_token.as_ref().map(cfapi::Token::expose);
    let recorded = state
        .cloudflare
        .as_ref()
        .and_then(|cloudflare| cloudflare.token_path.clone());
    let file = match (&asked.cf_token_file, flag) {
        // Either flag given: this run was told where to look, and the
        // recorded path is not part of the question.
        (Some(path), _) => Some(path.as_str()),
        (None, Some(_)) => None,
        (None, None) => recorded.as_deref(),
    };

    let Some(source) = cfapi::choose(file, flag, env).map_err(RenewError::Cloudflare)? else {
        return Ok(None);
    };
    let loaded = cfapi::load(source, flag, env).map_err(RenewError::Cloudflare)?;
    if let Some(warning) = loaded.warning {
        warnings.push(warning);
    }
    Ok(Some(loaded.token))
}

/// Pushes the A record at this machine's address (`--dns`).
fn push_record(
    state: &ServerState,
    token: Option<&cfapi::Token>,
    warnings: &mut Vec<String>,
) -> Result<Pushed, RenewError> {
    let Some(token) = token else {
        return Err(RenewError::NoToken);
    };
    let Some(address) = init::detect_public_ip() else {
        return Err(RenewError::NoAddress);
    };
    let zone = cfapi::find_zone(token, &state.domain).map_err(RenewError::Cloudflare)?;
    let cached = state
        .cloudflare
        .as_ref()
        .and_then(|cloudflare| cloudflare.record_id.clone());
    let written = cfapi::apply_record(token, &zone.id, &state.domain, address, cached.as_deref())
        .map_err(RenewError::Cloudflare)?;
    if let Some(warning) = written.warning {
        warnings.push(warning);
    }
    Ok(Pushed {
        applied: written.applied,
        zone_id: zone.id,
    })
}

/// A record that was written, and the zone it went into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pushed {
    pub applied: cfapi::Applied,
    pub zone_id: String,
}

/// Writes the zone and record ids a push proved (§9.1). Pure.
///
/// A hub set up without a token has no Cloudflare settings at all, and
/// this is where it gains them — the ids are ones anago has now seen,
/// which is the only thing that makes a cache worth having. **The
/// token path is left alone**: `--dns` does not decide whether a secret
/// is kept.
pub fn remember(state: &mut ServerState, pushed: &Pushed) {
    let record_id = Some(pushed.applied.record_id().to_string());
    match state.cloudflare.as_mut() {
        Some(cloudflare) => {
            // A domain that moved to another zone: a record id from
            // the old one means nothing in the new one (§9.1), and the
            // one just written replaces it anyway.
            cloudflare.zone_id.clone_from(&pushed.zone_id);
            cloudflare.record_id = record_id;
        }
        None => {
            state.cloudflare = Some(anago_core::state::Cloudflare {
                zone_id: pushed.zone_id.clone(),
                record_id,
                token_path: None,
            })
        }
    }
}

/// Puts a token given on the command line where a renewal will find it.
///
/// A `--cf-token-file` is left where the operator put it — the state
/// points at their file rather than at a copy that would go stale the
/// next time they rotated it, and there is nothing to undo.
fn store_token(
    paths: &ServerPaths,
    token: Option<&cfapi::Token>,
) -> Result<Option<Kept>, RenewError> {
    let Some(token) = token else {
        return Ok(None);
    };
    if let cfapi::Source::File(path) = &token.source {
        return Ok(Some(Kept::theirs(path.display().to_string())));
    }
    let path = paths.cf_token();
    // What was there before, so a run that fails after this can put it
    // back. A token file is small and this happens once per command.
    let previous = std::fs::read_to_string(&path).ok();
    crate::fsutil::write_private(&path, token.expose())
        .map_err(|e| RenewError::State(e.to_string()))?;
    Ok(Some(Kept::written(path.display().to_string(), previous)))
}

/// A token file this run put in place, undone unless the state file
/// ends up naming it.
///
/// The rule the rest of this codebase follows: a secret written for a
/// command that then failed is a secret nothing will ever come back for
/// (§7.1). The wrinkle here is that the file may already have held a
/// token — a rotation — so undoing means putting the old one back
/// rather than deleting.
struct Kept {
    path: String,
    /// `None` for a file this run did not write: the operator's own,
    /// named by `--cf-token-file` and never ours to touch.
    undo: Option<Option<String>>,
    keep: bool,
}

impl Kept {
    fn theirs(path: String) -> Kept {
        Kept {
            path,
            undo: None,
            keep: false,
        }
    }

    fn written(path: String, previous: Option<String>) -> Kept {
        Kept {
            path,
            undo: Some(previous),
            keep: false,
        }
    }

    fn path(&self) -> String {
        self.path.clone()
    }

    fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for Kept {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        match self.undo.take() {
            None => {}
            Some(Some(previous)) => {
                let _ = crate::fsutil::write_private(Path::new(&self.path), &previous);
            }
            Some(None) => {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

/// Why `server renew` could not do what it was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewError {
    /// The certificate belongs to somebody else (§9.1).
    NotOurs {
        cert_path: String,
    },
    /// Another issuance holds the lock.
    Busy,
    /// `--dns` with no token anywhere.
    NoToken,
    /// DNS-01 asked for, with no token anywhere.
    NoTokenForDns01,
    /// A file the rollback would have to put back, and cannot read.
    Unreadable {
        path: String,
        detail: String,
    },
    /// A token given to a hub that will not renew over DNS-01.
    TokenWithoutJob {
        given: &'static str,
        challenge: Challenge,
    },
    /// `--dns` and no address to point the record at.
    NoAddress,
    /// The hub's TLS settings changed while this run was working.
    Moved,
    Cloudflare(cfapi::CfError),
    Acme(acme::AcmeError),
    State(String),
}

impl fmt::Display for RenewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RenewError::NotOurs { cert_path } => write!(
                f,
                "this hub serves {cert_path}, a certificate anago did not issue and does \
                 not renew — whatever wrote it (certbot, your provider) still owns it. \
                 To have anago take over instead, say where the CA should send expiry \
                 warnings:\n       anago server renew --acme-email you@example.com"
            ),
            RenewError::Busy => f.write_str(
                "another issuance is already running — the hub's own timer, or a \
                 `server renew` in another terminal. Nothing was changed",
            ),
            RenewError::Unreadable { path, detail } => write!(
                f,
                "{path} exists and could not be read: {detail}. Nothing has been done — \
                 a renewal has to be able to put this file back if it cannot finish, and \
                 one that could not would leave the hub serving a certificate its state \
                 file does not describe"
            ),
            RenewError::TokenWithoutJob { given, challenge } => write!(
                f,
                "{given} was given, but this hub will renew over {} and a token is only \
                 kept for dns-01 — anago would have thrown it away and told you it had \
                 recorded something. To renew over DNS instead, add --acme-challenge \
                 dns-01; to point the A record at this machine with it, run \
                 `anago server renew --dns {given} …`",
                challenge.as_str()
            ),
            RenewError::NoTokenForDns01 => f.write_str(
                "dns-01 answers the challenge by writing a TXT record, so this hub needs \
                 a Cloudflare token it can keep — every renewal will need it again, not \
                 just this one. Pass --cf-token-file <path>, or leave the challenge out \
                 and anago will keep using http-01, which needs port 80 open instead",
            ),
            RenewError::NoToken => f.write_str(
                "--dns needs a Cloudflare token and this hub has none recorded. Pass \
                 --cf-token-file <path>, or set CLOUDFLARE_API_TOKEN",
            ),
            RenewError::NoAddress => f.write_str(
                "anago could not work out this machine's public address, so it will not \
                 write an A record — a wrong one is worse than a stale one. Set the \
                 record by hand, or run this where the outbound address is the public one",
            ),
            RenewError::Moved => f.write_str(
                "the hub's TLS settings changed while this run was working, so nothing \
                 was recorded. Run it again",
            ),
            RenewError::Cloudflare(e) => write!(f, "{e}"),
            RenewError::Acme(e) => write!(f, "{e}"),
            RenewError::State(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RenewError {}

#[cfg(test)]
mod tests {
    use super::*;
    use anago_core::code::{IssuedCode, JoinCode};
    use anago_core::state::{PrivateKey, ServerKeys};
    use anago_core::subnet::Subnet;
    use anago_core::wgconf;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 24 * 60 * 60;
    const EMAIL: &str = "jo@example.com";

    fn paths() -> ServerPaths {
        ServerPaths::new("/var/lib/anago")
    }

    /// A standing hub with a device already on it, so that anything
    /// which replaced the state wholesale would be caught.
    fn hub(tls: Tls) -> ServerState {
        ServerState {
            domain: "net.example.com".to_string(),
            subnet: Subnet::parse("10.100.0.0/24").unwrap(),
            listen_port: 51820,
            api_port: 443,
            tls,
            cloudflare: None,
            server: ServerKeys {
                private_key: PrivateKey::new("c2VydmVyIHByaXZhdGU="),
                public_key: "c2VydmVyIHB1YmxpYw==".to_string(),
                address: "10.100.0.1".parse().unwrap(),
            },
            peers: Vec::new(),
            codes: vec![IssuedCode::issue(
                JoinCode::parse("7QX4-M2KD").unwrap(),
                NOW,
                900,
            )],
        }
    }

    fn acme_tls(directory: &str, challenge: Challenge, renew_after: i64) -> Tls {
        let mut tls = Tls::acme(
            "/var/lib/anago/tls/fullchain.pem",
            "/var/lib/anago/tls/privkey.pem",
            Acme {
                directory: directory.to_string(),
                contact: Some(EMAIL.to_string()),
                account_key_path: "/var/lib/anago/tls/account.key".to_string(),
                account_url: "https://acme-v02.api.letsencrypt.org/acme/acct/1".to_string(),
                challenge,
                issued_at: NOW - 30 * DAY,
                renew_after,
            },
        );
        tls.not_after = Some(NOW + 60 * DAY);
        tls
    }

    /// A hub whose certificate is nowhere near due.
    fn current() -> Tls {
        acme_tls(acme::PRODUCTION, Challenge::Http01, NOW + 30 * DAY)
    }

    fn manual() -> Tls {
        let mut tls = Tls::manual("/etc/ssl/anago/fullchain.pem", "/etc/ssl/anago/privkey.pem");
        tls.not_after = Some(NOW + 41 * DAY);
        tls
    }

    fn nothing() -> ServerRenew {
        ServerRenew {
            force: false,
            dns_only: false,
            ca: None,
            acme_email: None,
            acme_challenge: None,
            cf_token: None,
            cf_token_file: None,
        }
    }

    #[test]
    fn a_certificate_that_is_not_due_is_left_alone() {
        // The command is idempotent so that it is safe in cron: with
        // nothing asked for and nothing due, it says when it will act
        // instead of acting (§8).
        let plan = plan(&hub(current()), &nothing(), NOW).unwrap();
        assert_eq!(
            plan,
            Plan::NotDue {
                due_at: NOW + 30 * DAY
            }
        );
        let out = report(&plan, &hub(current()), NOW);
        assert!(out.contains("the certificate is current"), "{out}");
        assert!(out.contains("renewing in 30d"), "{out}");
    }

    #[test]
    fn a_certificate_that_is_due_is_ordered_without_being_asked() {
        let due = acme_tls(acme::PRODUCTION, Challenge::Http01, NOW - 1);
        assert_eq!(
            plan(&hub(due), &nothing(), NOW).unwrap(),
            Plan::Reissue { why: Why::Due }
        );
    }

    #[test]
    fn force_orders_one_against_the_schedule_and_says_what_that_costs() {
        assert_eq!(
            plan(
                &hub(current()),
                &ServerRenew {
                    force: true,
                    ..nothing()
                },
                NOW
            )
            .unwrap(),
            Plan::Reissue { why: Why::Forced }
        );
        // The warning matters because the limit is not anago's: a few
        // impatient runs and the CA starts refusing (§13).
        let warning = forced_warning();
        assert!(warning.contains("not due yet"), "{warning}");
        assert!(warning.contains("few per week"), "{warning}");
    }

    #[test]
    fn changing_ca_orders_a_certificate_without_being_forced() {
        // §8's rule: would issuing with these settings produce a
        // different certificate? A different CA does, and recording
        // "production" beside a staging certificate would be a state
        // file that lies about what is being served.
        let staging = acme_tls(acme::STAGING, Challenge::Http01, NOW + 30 * DAY);
        let asked = ServerRenew {
            ca: Some(Ca::Production),
            ..nothing()
        };
        assert_eq!(
            plan(&hub(staging), &asked, NOW).unwrap(),
            Plan::Reissue {
                why: Why::Different("--acme-production")
            }
        );

        // And the other direction, for the hub being taken back to
        // staging to debug something.
        let asked = ServerRenew {
            ca: Some(Ca::Staging),
            ..nothing()
        };
        assert_eq!(
            plan(&hub(current()), &asked, NOW).unwrap(),
            Plan::Reissue {
                why: Why::Different("--acme-staging")
            }
        );
    }

    #[test]
    fn naming_the_ca_the_hub_is_already_on_is_not_a_change() {
        // "Make sure it is production" is a reasonable thing to type,
        // and spending one of the CA's weekly certificates to confirm
        // something already true is not a reasonable answer.
        let asked = ServerRenew {
            ca: Some(Ca::Production),
            ..nothing()
        };
        assert_eq!(
            plan(&hub(current()), &asked, NOW).unwrap(),
            Plan::NotDue {
                due_at: NOW + 30 * DAY
            }
        );
    }

    #[test]
    fn a_challenge_or_a_contact_changes_settings_and_not_the_certificate() {
        // A challenge is how the *next* renewal proves ownership. The
        // certificate is the same certificate, from the same CA, for
        // the same name — ordering one to record a preference would
        // spend a rate limit on nothing (§8).
        for asked in [
            // A challenge, with the token it needs.
            ServerRenew {
                acme_challenge: Some(Challenge::Dns01),
                cf_token_file: Some("/root/cf-token".to_string()),
                ..nothing()
            },
            ServerRenew {
                acme_email: Some("someone@example.com".to_string()),
                ..nothing()
            },
        ] {
            assert_eq!(plan(&hub(current()), &asked, NOW).unwrap(), Plan::Settings);
        }

        // And rotating the token of a hub that is already on DNS-01.
        let on_dns01 = hub(acme_tls(acme::PRODUCTION, Challenge::Dns01, NOW + 30 * DAY));
        assert_eq!(
            plan(
                &on_dns01,
                &ServerRenew {
                    cf_token_file: Some("/root/rotated".to_string()),
                    ..nothing()
                },
                NOW
            )
            .unwrap(),
            Plan::Settings
        );

        let out = report(&Plan::Settings, &hub(current()), NOW);
        assert!(out.contains("certificate is unchanged"), "{out}");
        assert!(out.contains("renewing in 30d"), "{out}");
    }

    #[test]
    fn a_token_this_hub_has_nowhere_to_put_is_refused() {
        // Regression: a token on an HTTP-01 hub made the run report
        // "settings recorded" and then throw the token away — §9.1
        // keeps `token_path` null unless the challenge is dns-01, so
        // there was nowhere for it to go. Printing success over that
        // is worse than refusing.
        let e = plan(
            &hub(current()),
            &ServerRenew {
                cf_token_file: Some("/root/cf-token".to_string()),
                ..nothing()
            },
            NOW,
        )
        .unwrap_err();
        assert_eq!(
            e,
            RenewError::TokenWithoutJob {
                given: "--cf-token-file",
                challenge: Challenge::Http01,
            }
        );
        let message = e.to_string();
        assert!(
            message.contains("only \nkept for dns-01") || message.contains("only kept for dns-01"),
            "{message}"
        );
        assert!(
            message.contains("--acme-challenge \ndns-01") || message.contains("dns-01"),
            "{message}"
        );
        assert!(message.contains("--dns"), "{message}");

        // Regression: `--force` and a CA change both returned a
        // re-issue before the check ran, so these were accepted and
        // the token silently dropped.
        for asked in [
            ServerRenew {
                force: true,
                cf_token_file: Some("/root/cf-token".to_string()),
                ..nothing()
            },
            ServerRenew {
                ca: Some(Ca::Staging),
                cf_token_file: Some("/root/cf-token".to_string()),
                ..nothing()
            },
        ] {
            assert!(
                matches!(
                    plan(&hub(current()), &asked, NOW),
                    Err(RenewError::TokenWithoutJob { .. })
                ),
                "{asked:?} was accepted"
            );
        }

        // And a hub that is due, where the re-issue would have
        // happened anyway.
        let due = acme_tls(acme::PRODUCTION, Challenge::Http01, NOW - 1);
        assert!(matches!(
            plan(
                &hub(due),
                &ServerRenew {
                    cf_token_file: Some("/root/cf-token".to_string()),
                    ..nothing()
                },
                NOW
            ),
            Err(RenewError::TokenWithoutJob { .. })
        ));

        // The same on a hub being moved *off* DNS-01, which is where
        // handing over a token makes least sense of all.
        let on_dns01 = hub(acme_tls(acme::PRODUCTION, Challenge::Dns01, NOW + 30 * DAY));
        assert!(matches!(
            plan(
                &on_dns01,
                &ServerRenew {
                    acme_challenge: Some(Challenge::Http01),
                    cf_token: Some(
                        cfapi::Token::parse("cf-secret-value", cfapi::Source::Flag).unwrap()
                    ),
                    ..nothing()
                },
                NOW
            ),
            Err(RenewError::TokenWithoutJob { .. })
        ));

        // And on a manual hub being taken over as an HTTP-01 one.
        assert!(matches!(
            plan(
                &hub(manual()),
                &ServerRenew {
                    acme_email: Some(EMAIL.to_string()),
                    cf_token_file: Some("/root/cf-token".to_string()),
                    ..nothing()
                },
                NOW
            ),
            Err(RenewError::TokenWithoutJob { .. })
        ));

        // With dns-01 it has a job, and is taken.
        assert_eq!(
            plan(
                &hub(current()),
                &ServerRenew {
                    acme_challenge: Some(Challenge::Dns01),
                    cf_token_file: Some("/root/cf-token".to_string()),
                    ..nothing()
                },
                NOW
            )
            .unwrap(),
            Plan::Settings
        );
        // A forced re-issue on a DNS-01 hub keeps its token, because
        // that hub has somewhere to put it.
        let on_dns01 = hub(acme_tls(acme::PRODUCTION, Challenge::Dns01, NOW + 30 * DAY));
        assert_eq!(
            plan(
                &on_dns01,
                &ServerRenew {
                    force: true,
                    cf_token_file: Some("/root/rotated".to_string()),
                    ..nothing()
                },
                NOW
            )
            .unwrap(),
            Plan::Reissue { why: Why::Forced }
        );

        // So does `--dns`, which says on the command line what the
        // token is for rather than in the state file.
        assert_eq!(
            plan(
                &hub(current()),
                &ServerRenew {
                    dns_only: true,
                    cf_token_file: Some("/root/cf-token".to_string()),
                    ..nothing()
                },
                NOW
            )
            .unwrap(),
            Plan::PushRecord
        );
    }

    #[test]
    fn a_settings_change_on_a_hub_that_is_due_still_orders_one() {
        // Both are true, and the certificate wins: recording the
        // setting and going back to sleep would leave a hub that was
        // due when the person was looking right at it.
        let due = acme_tls(acme::PRODUCTION, Challenge::Http01, NOW - 1);
        let asked = ServerRenew {
            acme_challenge: Some(Challenge::Dns01),
            ..nothing()
        };
        assert_eq!(
            plan(&hub(due), &asked, NOW).unwrap(),
            Plan::Reissue { why: Why::Due }
        );
    }

    #[test]
    fn a_manual_hub_is_refused_and_told_the_command_that_would_work() {
        // anago does not renew a file somebody else manages (§9.1).
        // Refusing without saying what to type instead would leave the
        // M0 → M1 move undiscoverable.
        let e = plan(&hub(manual()), &nothing(), NOW).unwrap_err();
        assert_eq!(
            e,
            RenewError::NotOurs {
                cert_path: "/etc/ssl/anago/fullchain.pem".to_string()
            }
        );
        let message = e.to_string();
        assert!(
            message.contains("/etc/ssl/anago/fullchain.pem"),
            "{message}"
        );
        assert!(message.contains("did not issue"), "{message}");
        assert!(
            message.contains("anago server renew --acme-email"),
            "{message}"
        );

        // A flag that cannot describe an ACME hub does not change that
        // — there is nowhere for the CA to send an expiry warning.
        let asked = ServerRenew {
            ca: Some(Ca::Staging),
            ..nothing()
        };
        assert!(matches!(
            plan(&hub(manual()), &asked, NOW),
            Err(RenewError::NotOurs { .. })
        ));
    }

    #[test]
    fn an_email_on_a_manual_hub_means_take_this_over() {
        // The switch is the "different certificate" side of the rule —
        // anago does not have one at all yet — so it issues, and
        // `--force` has nothing to add (§8).
        let asked = ServerRenew {
            acme_email: Some(EMAIL.to_string()),
            ..nothing()
        };
        assert_eq!(
            plan(&hub(manual()), &asked, NOW).unwrap(),
            Plan::Reissue {
                why: Why::Different("--acme-email")
            }
        );
    }

    #[test]
    fn dns_only_never_looks_at_the_certificate() {
        // `--dns` is for a server whose public address changed. It has
        // nothing to say about the certificate — including on a manual
        // hub, which every other path here refuses.
        for tls in [current(), manual()] {
            let asked = ServerRenew {
                dns_only: true,
                ..nothing()
            };
            assert_eq!(plan(&hub(tls), &asked, NOW).unwrap(), Plan::PushRecord);
        }
    }

    fn keeping(zone: &str, path: &str) -> Keeping {
        Keeping::Token {
            zone_id: zone.to_string(),
            path: path.to_string(),
        }
    }

    #[test]
    fn only_what_was_given_is_written_into_the_state() {
        // A flag left out means leave it alone. Reading an absent
        // `--acme-staging` as "production" would move a hub to another
        // CA on an ordinary renewal (§8).
        let mut state = hub(acme_tls(acme::STAGING, Challenge::Http01, NOW + 30 * DAY));
        let before = state.clone();
        apply(&mut state, &nothing(), &paths(), &Keeping::Unchanged);
        assert_eq!(state, before, "an empty command line changed something");

        // And each flag writes its own field and no other.
        let mut state = before.clone();
        apply(
            &mut state,
            &ServerRenew {
                acme_challenge: Some(Challenge::Dns01),
                ..nothing()
            },
            &paths(),
            &keeping("zone-1", "/root/cf-token"),
        );
        let acme = state.tls.renewable().unwrap();
        assert_eq!(acme.challenge, Challenge::Dns01);
        assert_eq!(acme.directory, acme::STAGING, "the CA moved on its own");
        assert_eq!(acme.contact.as_deref(), Some(EMAIL));
    }

    #[test]
    fn a_manual_hub_switched_to_acme_points_at_anagos_own_files() {
        // The operator's certificate is left exactly where it is, so
        // undoing this is putting the two old paths back (§8).
        let mut state = hub(manual());
        apply(
            &mut state,
            &ServerRenew {
                acme_email: Some(EMAIL.to_string()),
                ca: Some(Ca::Staging),
                ..nothing()
            },
            &paths(),
            &Keeping::Unchanged,
        );
        assert_eq!(state.tls.cert_path, "/var/lib/anago/tls/fullchain.pem");
        assert_eq!(state.tls.key_path, "/var/lib/anago/tls/privkey.pem");
        let acme = state.tls.renewable().expect("this hub renews its own now");
        assert_eq!(acme.directory, acme::STAGING);
        assert_eq!(acme.contact.as_deref(), Some(EMAIL));
        assert_eq!(acme.account_key_path, "/var/lib/anago/tls/account.key");
        // Nothing has been issued yet, so the hub is due rather than
        // holding a certificate.
        assert_eq!(acme.account_url, "");
        assert_eq!(state.tls.not_after, None, "the old file's expiry was kept");
        assert!(state.tls.needs_renewal(NOW, 0));
    }

    #[test]
    fn a_hub_with_no_cloudflare_settings_gains_them_when_it_moves_to_dns01() {
        // Regression: the token path was only written when a
        // Cloudflare block already existed, so a hub set up without a
        // token switched to DNS-01, issued once from the token handed
        // straight to the run — and then failed every automatic
        // renewal after that on "no Cloudflare settings recorded"
        // (§9.1).
        let mut state = hub(current());
        assert_eq!(
            state.cloudflare, None,
            "this hub was set up without a token"
        );

        apply(
            &mut state,
            &ServerRenew {
                acme_challenge: Some(Challenge::Dns01),
                cf_token_file: Some("/root/cf-token".to_string()),
                ..nothing()
            },
            &paths(),
            &keeping("zone-1", "/root/cf-token"),
        );

        let cloudflare = state.cloudflare.clone().expect("a renewal needs these");
        assert_eq!(cloudflare.zone_id, "zone-1");
        assert_eq!(cloudflare.token_path.as_deref(), Some("/root/cf-token"));
        // Nothing has been written at this name by anago, so there is
        // no record id to point at.
        assert_eq!(cloudflare.record_id, None);

        // A manual hub taken over as a DNS-01 one lands the same way.
        let mut state = hub(manual());
        apply(
            &mut state,
            &ServerRenew {
                acme_email: Some(EMAIL.to_string()),
                acme_challenge: Some(Challenge::Dns01),
                cf_token_file: Some("/root/cf-token".to_string()),
                ..nothing()
            },
            &paths(),
            &keeping("zone-2", "/root/cf-token"),
        );
        let cloudflare = state.cloudflare.expect("a renewal needs these");
        assert_eq!(cloudflare.zone_id, "zone-2");
        assert_eq!(cloudflare.token_path.as_deref(), Some("/root/cf-token"));
    }

    #[test]
    fn an_existing_cache_keeps_its_record_id_unless_the_zone_moved() {
        let mut state = hub(current());
        state.cloudflare = Some(anago_core::state::Cloudflare {
            zone_id: "zone-1".to_string(),
            record_id: Some("rec-1".to_string()),
            token_path: None,
        });
        let asked = ServerRenew {
            acme_challenge: Some(Challenge::Dns01),
            ..nothing()
        };
        apply(&mut state, &asked, &paths(), &keeping("zone-1", "/root/cf"));
        let cloudflare = state.cloudflare.clone().unwrap();
        assert_eq!(cloudflare.record_id.as_deref(), Some("rec-1"));
        assert_eq!(cloudflare.token_path.as_deref(), Some("/root/cf"));

        // A domain that moved zones drops the id with it: a record id
        // from the old zone means nothing in the new one (§9.1).
        apply(&mut state, &asked, &paths(), &keeping("zone-2", "/root/cf"));
        let cloudflare = state.cloudflare.unwrap();
        assert_eq!(cloudflare.zone_id, "zone-2");
        assert_eq!(cloudflare.record_id, None);
    }

    #[test]
    fn leaving_dns01_forgets_the_token_it_was_keeping() {
        // §9.1's rule is "token_path only while DNS-01", and §7.1's is
        // that a secret with no job left is removed. A hub moved to
        // HTTP-01 has no use for a token that can rewrite its whole
        // zone.
        let on_dns01 = acme_tls(acme::PRODUCTION, Challenge::Dns01, NOW + 30 * DAY);
        let leaving = ServerRenew {
            acme_challenge: Some(Challenge::Http01),
            ..nothing()
        };
        assert_eq!(disposition(&on_dns01, &leaving), Disposition::Forget);

        let mut state = hub(on_dns01);
        state.cloudflare = Some(anago_core::state::Cloudflare {
            zone_id: "zone-1".to_string(),
            record_id: Some("rec-1".to_string()),
            token_path: Some("/var/lib/anago/cf-token".to_string()),
        });
        apply(&mut state, &leaving, &paths(), &Keeping::Forget);
        let cloudflare = state.cloudflare.unwrap();
        assert_eq!(cloudflare.token_path, None, "the token was kept anyway");
        // The zone cache is not a secret and is still true.
        assert_eq!(cloudflare.zone_id, "zone-1");
        assert_eq!(cloudflare.record_id.as_deref(), Some("rec-1"));
    }

    #[test]
    fn a_check_that_changes_nothing_does_not_delete_a_file() {
        // `Forget` is the *transition* away from DNS-01, not every hub
        // that is not on it. A bare `server renew` on an HTTP-01 hub
        // is a check, and a check that deleted a token file would be a
        // surprise.
        assert_eq!(disposition(&current(), &nothing()), Disposition::Unchanged);
        assert_eq!(disposition(&manual(), &nothing()), Disposition::Unchanged);
        // Already on DNS-01 and staying: the token is recorded again,
        // so a rotation lands and nothing is lost.
        let on_dns01 = acme_tls(acme::PRODUCTION, Challenge::Dns01, NOW + 30 * DAY);
        assert_eq!(disposition(&on_dns01, &nothing()), Disposition::Keep);
        // And a hub becoming an ACME one with nothing said defaults to
        // http-01, so there is nothing to keep.
        assert_eq!(
            disposition(
                &manual(),
                &ServerRenew {
                    acme_email: Some(EMAIL.to_string()),
                    ..nothing()
                }
            ),
            Disposition::Unchanged
        );
    }

    #[test]
    fn nothing_this_command_does_changes_the_wireguard_config() {
        // The claim the whole module rests on. A certificate and an A
        // record have nothing to do with the peer list, the addresses
        // or the keys — and bringing the interface back up would drop
        // every tunnel at that instant. So whatever the wg config would
        // be, it is the same config afterwards.
        let mut state = hub(manual());
        state.peers.push(anago_core::state::Peer {
            name: anago_core::name::DeviceName::parse("macbook").unwrap(),
            public_key: "cGVlciBwdWJsaWM=".to_string(),
            address: "10.100.0.2".parse().unwrap(),
            token_hash: anago_core::token::TokenHash::from_bytes(&[7; 32]),
            created_at: NOW - DAY,
            last_seen: None,
        });
        let before = wgconf::server_config(&state).expose().to_string();

        // The loudest change this command can make: manual to ACME, a
        // different CA, a different challenge, a token recorded.
        apply(
            &mut state,
            &ServerRenew {
                acme_email: Some(EMAIL.to_string()),
                ca: Some(Ca::Staging),
                acme_challenge: Some(Challenge::Dns01),
                cf_token_file: Some("/root/cf-token".to_string()),
                ..nothing()
            },
            &paths(),
            &keeping("zone-1", "/root/cf-token"),
        );

        assert_eq!(
            wgconf::server_config(&state).expose(),
            before,
            "a renewal changed the WireGuard config"
        );
        // And the peer is still there, with everything it joined with.
        assert_eq!(state.peers.len(), 1);
        assert_eq!(
            state.peers[0].address,
            "10.100.0.2".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(state.subnet, before_subnet());
        assert_eq!(state.server.public_key, "c2VydmVyIHB1YmxpYw==");
    }

    fn before_subnet() -> Subnet {
        Subnet::parse("10.100.0.0/24").unwrap()
    }

    #[test]
    fn a_reissue_says_what_it_did_and_why() {
        // §8: "renewed" and "recorded a setting" have to be different
        // sentences, and a re-issue that happened because a flag moved
        // the CA has to say so — otherwise it looks like the schedule
        // fired on its own.
        let mut state = hub(current());
        state.tls.not_after = Some(NOW + 90 * DAY);
        state
            .tls
            .renewable_mut()
            .unwrap()
            .issued(NOW, Some(NOW + 90 * DAY));

        let out = report(
            &Plan::Reissue {
                why: Why::Different("--acme-production"),
            },
            &state,
            NOW,
        );
        assert!(
            out.contains("--acme-production changes which certificate"),
            "{out}"
        );
        assert!(out.contains("renewed the certificate"), "{out}");
        assert!(out.contains("expires in 90d"), "{out}");
        assert!(out.contains("renewing in 60d"), "{out}");

        // A scheduled one says none of that first part.
        let out = report(&Plan::Reissue { why: Why::Due }, &state, NOW);
        assert!(!out.contains("changes which certificate"), "{out}");
        assert!(out.contains("renewed the certificate"), "{out}");
    }

    #[test]
    fn a_staging_reissue_carries_the_warning_that_join_will_fail() {
        let mut state = hub(acme_tls(acme::STAGING, Challenge::Http01, NOW + 30 * DAY));
        state.tls.not_after = Some(NOW + 90 * DAY);
        state
            .tls
            .renewable_mut()
            .unwrap()
            .issued(NOW, Some(NOW + 90 * DAY));
        let out = report(&Plan::Reissue { why: Why::Forced }, &state, NOW);
        assert!(out.contains("staging"), "{out}");
        assert!(out.contains("UnknownIssuer"), "{out}");
        assert!(out.contains("--acme-production"), "{out}");
    }

    fn pushed(zone: &str, record: &str) -> Pushed {
        Pushed {
            applied: cfapi::Applied::Updated {
                record_id: record.to_string(),
                adopted: false,
            },
            zone_id: zone.to_string(),
        }
    }

    #[test]
    fn a_pushed_record_is_remembered_so_the_next_one_finds_it() {
        // §9.1: the id is written down right after the record is made
        // or edited. Without that the same re-lookup and the same
        // "which of these is ours" question repeat at every push, and
        // the cache stops describing the hub.
        let mut state = hub(current());
        assert_eq!(
            state.cloudflare, None,
            "this hub was set up without a token"
        );

        remember(&mut state, &pushed("zone-1", "rec-1"));
        let cloudflare = state.cloudflare.clone().unwrap();
        assert_eq!(cloudflare.zone_id, "zone-1");
        assert_eq!(cloudflare.record_id.as_deref(), Some("rec-1"));
        // `--dns` does not decide whether a secret is kept, so it does
        // not record one.
        assert_eq!(cloudflare.token_path, None);

        // A token the hub already had is not disturbed either.
        state.cloudflare.as_mut().unwrap().token_path = Some("/root/cf-token".to_string());
        remember(&mut state, &pushed("zone-1", "rec-2"));
        let cloudflare = state.cloudflare.clone().unwrap();
        assert_eq!(cloudflare.record_id.as_deref(), Some("rec-2"));
        assert_eq!(cloudflare.token_path.as_deref(), Some("/root/cf-token"));

        // And a domain that moved zones takes the new ids together —
        // a record id from the old zone means nothing in the new one.
        remember(&mut state, &pushed("zone-2", "rec-9"));
        let cloudflare = state.cloudflare.unwrap();
        assert_eq!(cloudflare.zone_id, "zone-2");
        assert_eq!(cloudflare.record_id.as_deref(), Some("rec-9"));
    }

    #[test]
    fn a_pushed_record_changes_nothing_else_about_the_hub() {
        // `--dns` is the narrowest path here and has to stay that way:
        // no certificate, no settings, no wg.
        let mut state = hub(current());
        let before = state.clone();
        remember(&mut state, &pushed("zone-1", "rec-1"));
        assert_eq!(state.tls, before.tls);
        assert_eq!(state.peers, before.peers);
        assert_eq!(
            wgconf::server_config(&state).expose(),
            wgconf::server_config(&before).expose()
        );
    }

    #[test]
    fn a_token_file_this_run_wrote_does_not_outlive_a_failed_run() {
        // The same rule as everywhere: a secret written for a command
        // that then failed is one nothing comes back for (§7.1).
        let dir = std::env::temp_dir().join(format!("anago-renew-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = ServerPaths::new(&dir);
        let token = cfapi::Token::parse("cf-secret-value", cfapi::Source::Flag).unwrap();

        // Nothing was there: the file goes away again.
        let kept = store_token(&paths, Some(&token)).unwrap().unwrap();
        assert_eq!(kept.path(), paths.cf_token().display().to_string());
        assert_eq!(
            std::fs::read_to_string(paths.cf_token()).unwrap(),
            "cf-secret-value"
        );
        drop(kept);
        assert!(
            !paths.cf_token().exists(),
            "a failed run left a token behind"
        );

        // A rotation that failed puts the working token back, rather
        // than leaving the hub with no token at all — the state still
        // points at this file.
        crate::fsutil::write_private(&paths.cf_token(), "the-old-token").unwrap();
        let kept = store_token(&paths, Some(&token)).unwrap().unwrap();
        assert_eq!(
            std::fs::read_to_string(paths.cf_token()).unwrap(),
            "cf-secret-value"
        );
        drop(kept);
        assert_eq!(
            std::fs::read_to_string(paths.cf_token()).unwrap(),
            "the-old-token"
        );

        // And a run that got to the commit keeps what it wrote.
        let mut kept = store_token(&paths, Some(&token)).unwrap().unwrap();
        kept.keep();
        drop(kept);
        assert_eq!(
            std::fs::read_to_string(paths.cf_token()).unwrap(),
            "cf-secret-value"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_operators_own_token_file_is_pointed_at_and_never_touched() {
        // `--cf-token-file` names their file. Copying it would go stale
        // the next time they rotated it, and rolling one back would be
        // anago editing a file it does not own.
        let dir = std::env::temp_dir().join(format!("anago-renew-theirs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Deliberately not `paths.cf_token()`: the point is that
        // anago points at their path rather than copying to its own.
        let theirs = dir.join("their-cf-token");
        std::fs::write(&theirs, "cf-secret-value").unwrap();
        let paths = ServerPaths::new(&dir);

        let token =
            cfapi::Token::parse("cf-secret-value", cfapi::Source::File(theirs.clone())).unwrap();
        let kept = store_token(&paths, Some(&token)).unwrap().unwrap();
        assert_eq!(kept.path(), theirs.display().to_string());
        drop(kept);
        assert_eq!(
            std::fs::read_to_string(&theirs).unwrap(),
            "cf-secret-value",
            "anago rolled back a file it did not write"
        );
        assert!(!paths.cf_token().exists(), "a copy was made anyway");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The token source `read_token` settles on, without the reading.
    fn chosen(
        recorded: Option<&str>,
        flag: Option<&str>,
        file: Option<&str>,
        env: Option<&str>,
    ) -> Result<Option<cfapi::Source>, cfapi::CfError> {
        // The same three lines `read_token` runs before it loads
        // anything — the precedence, with the I/O left out.
        let chosen_file = match (file, flag) {
            (Some(path), _) => Some(path),
            (None, Some(_)) => None,
            (None, None) => recorded,
        };
        cfapi::choose(chosen_file, flag, env)
    }

    #[test]
    fn an_explicit_token_wins_over_the_one_the_hub_recorded() {
        // Regression: the recorded path went into `choose`'s file slot
        // whatever else was given, so a hub already renewing over
        // DNS-01 could not be handed a rotated token — the two looked
        // like `--cf-token` and `--cf-token-file` together and were
        // refused as such. §8's order is explicit flag, then the
        // recorded file, then the environment.
        let recorded = Some("/var/lib/anago/cf-token");

        assert_eq!(
            chosen(recorded, Some("rotated"), None, None),
            Ok(Some(cfapi::Source::Flag)),
            "a rotated token was refused because of the hub's own file"
        );
        assert_eq!(
            chosen(recorded, None, Some("/root/new-token"), None),
            Ok(Some(cfapi::Source::File(std::path::PathBuf::from(
                "/root/new-token"
            ))))
        );

        // With neither flag, the recorded file is what a renewal uses
        // — and it beats the environment, which is the last resort.
        assert_eq!(
            chosen(recorded, None, None, Some("from-the-environment")),
            Ok(Some(cfapi::Source::File(std::path::PathBuf::from(
                "/var/lib/anago/cf-token"
            ))))
        );
        assert_eq!(
            chosen(None, None, None, Some("from-the-environment")),
            Ok(Some(cfapi::Source::Env))
        );
        assert_eq!(chosen(None, None, None, None), Ok(None));

        // The two command-line flags together are still refused: that
        // is a person saying two different things, and it is the one
        // case the recorded path has nothing to do with.
        assert_eq!(
            chosen(recorded, Some("a"), Some("/root/b"), None),
            Err(cfapi::CfError::BothFlags)
        );
        assert_eq!(
            chosen(None, Some("a"), Some("/root/b"), None),
            Err(cfapi::CfError::BothFlags)
        );
    }

    #[test]
    fn only_a_token_file_anago_wrote_is_ever_removed() {
        // Leaving DNS-01 drops the reference either way, but the file
        // itself is only ours to delete when it is the one anago
        // wrote. A `--cf-token-file` names the operator's own.
        let dir = std::env::temp_dir().join(format!("anago-forget-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = ServerPaths::new(&dir);

        // The disposition this arrives at is `Forget` — pinned by
        // `leaving_dns01_forgets_the_token_it_was_keeping`; what is
        // under test here is which file that lets anago remove.
        let mut state = hub(acme_tls(acme::PRODUCTION, Challenge::Dns01, NOW + 30 * DAY));

        // anago's own file: named for removal.
        state.cloudflare = Some(anago_core::state::Cloudflare {
            zone_id: "zone-1".to_string(),
            record_id: None,
            token_path: Some(paths.cf_token().display().to_string()),
        });
        let settled = settle(&state, &paths, None, Disposition::Forget).unwrap();
        assert_eq!(settled.keeping, Keeping::Forget);
        assert_eq!(
            settled.stale.as_deref(),
            Some(paths.cf_token().display().to_string().as_str())
        );

        // Theirs: the reference goes, the file stays.
        state.cloudflare.as_mut().unwrap().token_path = Some("/root/cf-token".to_string());
        let settled = settle(&state, &paths, None, Disposition::Forget).unwrap();
        assert_eq!(settled.keeping, Keeping::Forget);
        assert_eq!(settled.stale, None, "anago offered to delete their file");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn asking_for_dns01_without_a_token_is_refused_before_anything_changes() {
        // The challenge would be recorded and every renewal after it
        // would fail on a token that is not there. Better to say so
        // now, and say what to pass.
        let dir = std::env::temp_dir().join(format!("anago-nodns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = ServerPaths::new(&dir);
        let e = match settle(&hub(current()), &paths, None, Disposition::Keep) {
            Err(e) => e,
            Ok(_) => panic!("dns-01 was accepted with no token anywhere"),
        };
        assert_eq!(e, RenewError::NoTokenForDns01);
        let message = e.to_string();
        assert!(
            message.contains("every renewal will need it again"),
            "{message}"
        );
        assert!(message.contains("--cf-token-file"), "{message}");
        assert!(message.contains("http-01"), "{message}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A hub whose recorded TLS paths are **not** where an issuance
    /// writes — the case the guard has to get right. `tls.cert_path`
    /// and `tls.key_path` name files somewhere else entirely (a
    /// hand-edited state, or one carried over from a manual
    /// certificate), while `acme::renew` saves to `ServerPaths`'s pair
    /// whatever they say.
    fn hub_at(dir: &Path, account: &Path) -> ServerState {
        let mut tls = acme_tls(acme::PRODUCTION, Challenge::Http01, NOW + 30 * DAY);
        tls.cert_path = dir.join("recorded-fullchain.pem").display().to_string();
        tls.key_path = dir.join("recorded-privkey.pem").display().to_string();
        tls.renewable_mut().unwrap().account_key_path = account.display().to_string();
        hub(tls)
    }

    /// Where `acme::renew` actually writes: the managed pair, and the
    /// account at the path the state records.
    fn issuer_writes(state: &ServerState, paths: &ServerPaths) -> Vec<std::path::PathBuf> {
        vec![
            paths.certificate(),
            paths.private_key(),
            std::path::PathBuf::from(&state.tls.renewable().unwrap().account_key_path),
        ]
    }

    #[test]
    fn an_issuance_that_is_never_committed_puts_the_old_files_back() {
        // The failure this exists for: the CA answers, the account and
        // the pair are replaced, and then the state file cannot be
        // committed — the lock is gone, or another run moved the
        // settings. Without a restore, a staging-to-production run
        // that lost that race would serve a production certificate
        // from a state file that says staging, and the next renewal
        // would present an account the recorded CA has never heard of
        // (§8's all-or-nothing rule).
        let dir = std::env::temp_dir().join(format!("anago-artifacts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = ServerPaths::new(&dir);
        crate::fsutil::ensure_private_dir(&paths.tls_dir()).unwrap();

        // Two regressions at once. The guard used to watch the
        // *default* account path — the schema lets a hub keep its
        // account anywhere and `acme::renew` writes back to the path
        // it read. Then it watched the *state's* certificate paths —
        // but the pair always lands at `ServerPaths`, whatever the
        // state says, so a hub with recorded paths of its own had the
        // managed pair replaced and left that way.
        let account = dir.join("elsewhere.key");
        let state = hub_at(&dir, &account);
        assert_ne!(account, paths.account_key(), "a non-default account path");
        assert_ne!(
            std::path::PathBuf::from(&state.tls.cert_path),
            paths.certificate(),
            "recorded paths that are not where the issuer writes"
        );

        let files = issuer_writes(&state, &paths);
        for path in &files {
            crate::fsutil::write_private(path, "the staging one").unwrap();
        }
        // And the recorded pair, which this issuance does not touch.
        crate::fsutil::write_private(Path::new(&state.tls.cert_path), "somebody else's").unwrap();

        let artifacts = Artifacts::watching(&state, &paths).unwrap();
        // What `acme::renew_blocking` does: the credentials first, the
        // pair after them, always at `ServerPaths` (§9.1).
        for path in &files {
            crate::fsutil::write_private(path, "the production one").unwrap();
        }
        drop(artifacts);

        for path in &files {
            assert_eq!(
                std::fs::read_to_string(path).unwrap(),
                "the staging one",
                "{} was left as the issuance wrote it",
                path.display()
            );
            // And 0600, because a restore that loosened the key would
            // be its own accident (§7.1).
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{}: {mode:04o}", path.display());
        }
        // A file the issuance never wrote is not the rollback's to
        // touch either.
        assert_eq!(
            std::fs::read_to_string(&state.tls.cert_path).unwrap(),
            "somebody else's"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_committed_issuance_keeps_what_it_wrote() {
        let dir = std::env::temp_dir().join(format!("anago-artifacts-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = ServerPaths::new(&dir);
        crate::fsutil::ensure_private_dir(&paths.tls_dir()).unwrap();
        let state = hub_at(&dir, &dir.join("account.key"));
        crate::fsutil::write_private(&paths.certificate(), "the old one").unwrap();

        let mut artifacts = Artifacts::watching(&state, &paths).unwrap();
        crate::fsutil::write_private(&paths.certificate(), "the new one").unwrap();
        artifacts.keep();
        drop(artifacts);
        assert_eq!(
            std::fs::read_to_string(paths.certificate()).unwrap(),
            "the new one"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_first_issuance_leaves_nothing_behind_when_it_is_not_committed() {
        // A hub taken over from a manual certificate has no account
        // and no managed pair yet, so putting things back means
        // removing them — the same rule `server init` follows.
        let dir = std::env::temp_dir().join(format!("anago-artifacts-new-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = ServerPaths::new(&dir);
        crate::fsutil::ensure_private_dir(&paths.tls_dir()).unwrap();
        let state = hub_at(&dir, &dir.join("account.key"));

        let artifacts = Artifacts::watching(&state, &paths).unwrap();
        for path in issuer_writes(&state, &paths) {
            crate::fsutil::write_private(&path, "fresh").unwrap();
        }
        drop(artifacts);

        for path in issuer_writes(&state, &paths) {
            assert!(!path.exists(), "{} survived", path.display());
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_account_kept_beside_the_certificate_is_watched_once() {
        // A state that points the account at one of the pair would
        // otherwise be snapshotted twice and restored from whichever
        // copy ran last.
        let dir = std::env::temp_dir().join(format!("anago-artifacts-dup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = ServerPaths::new(&dir);
        crate::fsutil::ensure_private_dir(&paths.tls_dir()).unwrap();
        let state = hub_at(&dir, &paths.certificate());

        crate::fsutil::write_private(&paths.certificate(), "before").unwrap();
        let artifacts = Artifacts::watching(&state, &paths).unwrap();
        assert_eq!(artifacts.before.len(), 2, "{:?}", artifacts.before);
        crate::fsutil::write_private(&paths.certificate(), "after").unwrap();
        drop(artifacts);
        assert_eq!(
            std::fs::read_to_string(paths.certificate()).unwrap(),
            "before"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_file_that_cannot_be_read_stops_the_run_before_the_ca_is_called() {
        // A read error is not "there was nothing here". Treating it as
        // one arms a guard that deletes a working account on the way
        // out — and a run that has not started costs nothing to
        // abandon.
        let dir = std::env::temp_dir().join(format!("anago-unreadable-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = ServerPaths::new(&dir);
        crate::fsutil::ensure_private_dir(&paths.tls_dir()).unwrap();
        let state = hub_at(&dir, &dir.join("account.key"));

        // A directory where the certificate belongs: it exists, and
        // reading it is not `NotFound`.
        std::fs::create_dir_all(paths.certificate()).unwrap();
        let e = match Artifacts::watching(&state, &paths) {
            Err(e) => e,
            Ok(_) => panic!("an unreadable file was taken for an absent one"),
        };
        assert_eq!(
            e,
            RenewError::Unreadable {
                path: paths.certificate().display().to_string(),
                detail: match std::fs::read(paths.certificate()) {
                    Err(e) => e.to_string(),
                    Ok(_) => unreachable!("a directory does not read as bytes"),
                },
            }
        );
        let message = e.to_string();
        assert!(message.contains("Nothing has been done"), "{message}");
        assert!(message.contains("put this file back"), "{message}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_hub_leaving_dns01_does_not_have_to_produce_the_token_it_is_dropping() {
        // The recovery this unblocks: a token that expired or went
        // missing is exactly why somebody moves a hub back to HTTP-01.
        // Demanding that the thing being abandoned still works would
        // shut the door the command exists to open.
        let dir = std::env::temp_dir().join(format!("anago-lost-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = ServerPaths::new(&dir);

        let mut state = hub(acme_tls(acme::PRODUCTION, Challenge::Dns01, NOW + 30 * DAY));
        state.cloudflare = Some(anago_core::state::Cloudflare {
            zone_id: "zone-1".to_string(),
            record_id: None,
            // A file that is not there any more.
            token_path: Some(paths.cf_token().display().to_string()),
        });
        let leaving = ServerRenew {
            acme_challenge: Some(Challenge::Http01),
            ..nothing()
        };

        // The plan is reached without the token being read at all...
        assert_eq!(plan(&state, &leaving, NOW).unwrap(), Plan::Settings);
        // ...and so is everything the run does about it.
        let settled = settle(&state, &paths, None, disposition(&state.tls, &leaving)).unwrap();
        assert_eq!(settled.keeping, Keeping::Forget);
        assert_eq!(
            settled.stale.as_deref(),
            Some(paths.cf_token().display().to_string().as_str())
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_check_that_is_not_due_reaches_no_further_than_the_state_file() {
        // The advertised contract: `server renew` in cron does nothing
        // and cannot fail on somebody else's outage. `run` returns on
        // `NotDue` before the lock, the token, the zone lookup and the
        // commit — so what is pinned here is that a hub with a
        // completely broken Cloudflare setup still reports cleanly.
        let mut state = hub(current());
        state.cloudflare = Some(anago_core::state::Cloudflare {
            zone_id: "zone-1".to_string(),
            record_id: None,
            token_path: Some("/does/not/exist".to_string()),
        });
        let plan = plan(&state, &nothing(), NOW).unwrap();
        assert_eq!(
            plan,
            Plan::NotDue {
                due_at: NOW + 30 * DAY
            }
        );
        let out = report(&plan, &state, NOW);
        assert!(out.contains("the certificate is current"), "{out}");
    }

    #[test]
    fn the_refusals_say_what_to_do_next() {
        assert!(RenewError::Busy.to_string().contains("Nothing was changed"));
        let e = RenewError::NoToken.to_string();
        assert!(e.contains("--cf-token-file"), "{e}");
        assert!(e.contains("CLOUDFLARE_API_TOKEN"), "{e}");
        let e = RenewError::NoAddress.to_string();
        assert!(e.contains("wrong one is worse"), "{e}");
        assert!(RenewError::Moved.to_string().contains("Run it again"));
    }
}
