//! Waiting for a DNS-01 record to be **served**, not merely stored
//! (DESIGN.md §9.1).
//!
//! Writing a record through Cloudflare's API and reading it back from
//! the same API establishes one thing: Cloudflare kept it. It says
//! nothing about whether the nameservers answering for the zone are
//! handing that TXT value out yet, and that is the only fact DNS-01
//! turns on — the ACME server does its own lookup, and a validation
//! asked for too early fails against a record that exists.
//!
//! So this module asks DNS. It sends a TXT question to the zone's
//! authoritative nameservers over UDP and reads what comes back;
//! building and reading the message is `anago_core::dnswire`, pure and
//! unit-tested, and what is here is the socket, the clock, and the
//! policy for what to do with each answer.
//!
//! The policy is pure too ([`look`] and [`next_step`]), because the
//! interesting decisions are all in it: whose silence to ignore, when
//! looking has stopped being worth it, and when to go ahead without
//! having seen anything.

use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant, SystemTime};

use anago_core::dnswire::{self, DnsError};

use crate::client;

/// How often to look.
///
/// Fixed rather than backed off: the whole window is a minute, so this
/// is thirty questions to two nameservers, and a backoff would only add
/// latency to the ordinary case, where the answer changes within a few
/// seconds.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How long to keep looking before giving up on the record.
pub const POLL_TIMEOUT: Duration = Duration::from_secs(60);

/// How long to keep trying when **nothing answers at all**.
///
/// Separate from [`POLL_TIMEOUT`] on purpose. A host that cannot send
/// UDP to port 53 — a firewall that only allows outbound 80 and 443 is
/// a real configuration — would otherwise spend the whole window
/// learning nothing, on every renewal, forever. Ten seconds is enough
/// to ride out a blip; past that, anago admits it cannot see and goes
/// on rather than failing a certificate over its own blindness.
pub const BLIND_AFTER: Duration = Duration::from_secs(10);

/// How long to wait after every nameserver that answers is serving the
/// value.
///
/// Cloudflare's nameservers are anycast: the address that answered here
/// is not the instance that will answer the ACME server. The zone's own
/// servers agreeing is the strong signal; this is slack for the rest of
/// the network, and it is short because there is now an actual
/// observation behind it rather than a guess.
pub const SETTLE: Duration = Duration::from_secs(5);

/// How long one nameserver gets to answer, across every address it
/// resolves to.
///
/// Two seconds against a poll interval of two: a server that is not
/// answering costs one look, not the window.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// The buffer one answer is read into.
///
/// [`dnswire::txt_query`] asks for answers up to
/// [`dnswire::UDP_PAYLOAD`] bytes with EDNS(0), so the buffer matches
/// that: a smaller one would cut a datagram the server was told it
/// could send, which is a truncation anago inflicted on itself.
const MAX_MESSAGE: usize = dnswire::UDP_PAYLOAD as usize;

/// What one nameserver said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// It is handing out the value.
    Serving,
    /// It answered, in full, and the value is not there — including
    /// "no such name", which is the ordinary state a second after
    /// publishing.
    NotYet,
    /// It did not answer, or could not: unreachable, timed out,
    /// SERVFAIL, an unreadable message — or an answer it had to
    /// truncate, which is the same thing in the end. **None of this is
    /// evidence about the record.**
    Silent,
}

/// What the nameservers say together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Look {
    /// Every server that answered is serving the value.
    Served,
    /// Somebody answered, and at least one of them is not serving it.
    Missing,
    /// Nobody answered. Nothing was learned.
    Unobservable,
}

/// Reads the answers as one observation.
///
/// The rule that needs stating: **a silent server does not hold up the
/// verdict.** If one of two nameservers is unreachable from this host —
/// blocked, or simply broken — requiring it to agree would stall every
/// renewal on a machine that can otherwise do the job perfectly, and
/// the server that did answer is authoritative for the same zone.
/// Silence is missing evidence, not contrary evidence; the only thing
/// it decides is [`Look::Unobservable`], when there is nothing else.
pub fn look(answers: &[Answer]) -> Look {
    let heard: Vec<Answer> = answers
        .iter()
        .copied()
        .filter(|answer| *answer != Answer::Silent)
        .collect();
    if heard.is_empty() {
        return Look::Unobservable;
    }
    if heard.iter().all(|answer| *answer == Answer::Serving) {
        Look::Served
    } else {
        Look::Missing
    }
}

/// What to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Sleep this long, then look again.
    Again(Duration),
    /// It is being served. Wait this long for the rest of the network,
    /// then hand the challenge over.
    Settle(Duration),
    /// Nothing can be seen from here. Wait this long and go on anyway,
    /// saying so.
    Blind(Duration),
    /// It was never served. Give up — and clean the record up. Carries
    /// how long the wait took, for the message.
    GiveUp(Duration),
}

/// The waiting policy, as a pure function of what was seen and how long
/// this has been going on.
///
/// Four things it fixes, each of which is only obvious written down:
///
/// - **Seeing it beats a clock that ran out.** The look that found it
///   is the answer; discarding it because the deadline passed between
///   the question and the answer would fail a challenge that had
///   succeeded.
/// - **Blindness has its own, much shorter deadline.** Not being able
///   to ask is a different fact from asking and being told no, and it
///   ends differently: anago goes ahead and says it could not check,
///   rather than failing a certificate because a firewall ate its
///   questions.
/// - **Being told no runs the full window**, because that is the case
///   where waiting is exactly what helps.
/// - **The sleep never runs past the deadline.** At the end of the
///   window the interval is clipped to what is left.
pub fn next_step(look: Look, elapsed: Duration) -> Step {
    match look {
        Look::Served => Step::Settle(SETTLE),
        Look::Unobservable if elapsed >= BLIND_AFTER => Step::Blind(SETTLE),
        Look::Unobservable => Step::Again(until(BLIND_AFTER, elapsed)),
        Look::Missing => match POLL_TIMEOUT.checked_sub(elapsed) {
            Some(remaining) if !remaining.is_zero() => Step::Again(POLL_INTERVAL.min(remaining)),
            _ => Step::GiveUp(elapsed),
        },
    }
}

/// The next interval, never reaching past `deadline`.
fn until(deadline: Duration, elapsed: Duration) -> Duration {
    POLL_INTERVAL.min(deadline.saturating_sub(elapsed))
}

/// How the wait ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Seen, at the zone's own nameservers.
    Served { waited: Duration },
    /// Never seen, because nothing here could ask. The challenge is
    /// handed over anyway — see [`BLIND_AFTER`].
    Blind { waited: Duration },
}

impl Outcome {
    /// What to tell the person, when there is something to tell.
    pub fn warning(&self) -> Option<String> {
        match self {
            Outcome::Served { .. } => None,
            Outcome::Blind { .. } => Some(
                "warning: anago could not check DNS from this machine — no nameserver \
                 answered its TXT question, which usually means outbound UDP port 53 is \
                 blocked. The challenge record was published and validation is going \
                 ahead without that check, so a failure here may just be a record that \
                 had not spread yet."
                    .to_string(),
            ),
        }
    }
}

/// Watches for `value` at `name` on the zone's authoritative
/// nameservers (as Cloudflare lists them).
///
/// **Human verification needed**: this sends real DNS queries.
pub fn wait(servers: &[String], name: &str, value: &str) -> Result<Outcome, ProbeError> {
    // A name that cannot be asked about is a caller's mistake, and it
    // is worth finding out before any waiting happens.
    dnswire::txt_query(0, name).map_err(ProbeError::Name)?;
    if servers.is_empty() {
        // Nothing to ask. Blind from the start, and no reason to spend
        // the blind window discovering it.
        return Ok(Outcome::Blind {
            waited: Duration::ZERO,
        });
    }

    let started = Instant::now();
    loop {
        let answers: Vec<Answer> = servers
            .iter()
            .map(|server| ask(server, name, value))
            .collect();
        match next_step(look(&answers), started.elapsed()) {
            Step::Settle(pause) => {
                std::thread::sleep(pause);
                return Ok(Outcome::Served {
                    waited: started.elapsed(),
                });
            }
            Step::Blind(pause) => {
                std::thread::sleep(pause);
                return Ok(Outcome::Blind {
                    waited: started.elapsed(),
                });
            }
            Step::Again(pause) => std::thread::sleep(pause),
            Step::GiveUp(waited) => {
                return Err(ProbeError::NotServed {
                    name: name.to_string(),
                    waited,
                })
            }
        }
    }
}

/// Asks one nameserver, and turns every way that can go wrong into
/// [`Answer::Silent`] — a server that cannot be reached has told us
/// nothing about the record, and pretending otherwise in either
/// direction is how this gets it wrong.
///
/// **Human verification needed**: this sends a real DNS query.
pub fn ask(server: &str, name: &str, value: &str) -> Answer {
    match query(server, name) {
        Ok(reply) => read(&reply, value),
        Err(_) => Answer::Silent,
    }
}

/// Turns one reply into one answer.
///
/// The case worth naming is the third: **a truncated answer without the
/// value is not "not there"**. The part that did not fit is exactly
/// where the value might be, and several TXT values at one
/// `_acme-challenge` name is a state DNS-01 allows — so reading a
/// truncated answer as absence would fail a challenge that had already
/// propagated. It counts as not having seen, which is what
/// [`Answer::Silent`] means.
///
/// The query asks for [`dnswire::UDP_PAYLOAD`] bytes with EDNS(0), so
/// truncation now takes an answer far larger than a challenge name
/// holds. Re-asking over TCP is the other half of the standard remedy
/// and is not implemented: it is a second transport for a case this
/// should no longer meet, and if it is met anyway, treating it as
/// unobservable ends in "anago could not check" rather than in a wrong
/// answer.
fn read(reply: &dnswire::Reply, value: &str) -> Answer {
    if !reply.answered() {
        return Answer::Silent;
    }
    if reply.holds(value) {
        return Answer::Serving;
    }
    if reply.truncated {
        return Answer::Silent;
    }
    Answer::NotYet
}

/// Asks one nameserver, trying **every address it resolves to**.
///
/// A nameserver name usually has both an A and an AAAA record, and the
/// order they come back in says nothing about which of them this host
/// can reach. Stopping at the first would make an IPv4-only machine
/// silent against a nameserver that answers perfectly well over IPv4,
/// and since silence at every server ends in "anago could not check"
/// (§9.1), the wait would quietly stop checking anything at all.
///
/// [`QUERY_TIMEOUT`] is the budget for the whole server, shared out
/// among its addresses by [`client::attempt_budget`] — the same rule
/// the HTTP client uses for a dual-stack hub — so an address that
/// hangs cannot eat the poll interval.
fn query(server: &str, name: &str) -> Result<dnswire::Reply, ProbeError> {
    let id = question_id();
    let message = dnswire::txt_query(id, name).map_err(ProbeError::Name)?;
    let addresses: Vec<SocketAddr> = (server, 53)
        .to_socket_addrs()
        .map_err(|e| ProbeError::Unreachable(e.to_string()))?
        .collect();
    if addresses.is_empty() {
        return Err(ProbeError::Unreachable(format!("{server} has no address")));
    }

    let started = Instant::now();
    let mut left = addresses.len();
    let mut last = None;
    for address in addresses {
        let remaining = QUERY_TIMEOUT.saturating_sub(started.elapsed());
        let budget = client::attempt_budget(remaining, left);
        left -= 1;
        if budget.is_zero() {
            break;
        }
        match ask_address(address, &message, id, name, budget) {
            Ok(reply) => return Ok(reply),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| ProbeError::Unreachable(format!("{server} ran out of time"))))
}

/// One question to one address.
fn ask_address(
    address: SocketAddr,
    message: &[u8],
    id: u16,
    name: &str,
    budget: Duration,
) -> Result<dnswire::Reply, ProbeError> {
    let local = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(local).map_err(|e| ProbeError::Unreachable(e.to_string()))?;
    socket
        .set_read_timeout(Some(budget))
        .map_err(|e| ProbeError::Unreachable(e.to_string()))?;
    socket
        .send_to(message, address)
        .map_err(|e| ProbeError::Unreachable(e.to_string()))?;

    // A few reads, not one: an answer to a question that is not this
    // one — a stray datagram, or a late reply to the previous look —
    // is skipped rather than taken as the answer. The read timeout
    // bounds each wait, and the count bounds the whole thing.
    let mut buffer = [0u8; MAX_MESSAGE];
    for _ in 0..4 {
        let (length, from) = socket
            .recv_from(&mut buffer)
            .map_err(|e| ProbeError::Unreachable(e.to_string()))?;
        if from != address {
            continue;
        }
        match dnswire::read_txt(&buffer[..length], id, name) {
            Err(DnsError::NotOurQuestion) => continue,
            other => return other.map_err(ProbeError::Unreadable),
        }
    }
    Err(ProbeError::Unreachable(format!(
        "{address} answered a different question"
    )))
}

/// The id that matches an answer to its question.
///
/// Not a security boundary and not trying to be — see
/// `anago_core::dnswire::txt_query`. It only has to be unlikely to
/// collide with the previous look's leftover datagram, which the clock
/// and the process id together manage.
fn question_id() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|since| since.subsec_nanos())
        .unwrap_or(0);
    (nanos as u16) ^ (std::process::id() as u16)
}

/// Why the wait ended badly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// The record was published and the nameservers never served it.
    NotServed {
        name: String,
        waited: Duration,
    },
    Name(DnsError),
    Unreachable(String),
    Unreadable(DnsError),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // What became of the record is deliberately not said here.
            // This module publishes nothing and removes nothing — the
            // record belongs to `cfapi::Challenge`, whose guard takes
            // it out as the run unwinds and says so itself when it
            // cannot. Claiming "the record has been removed" from here
            // would be a claim made before the attempt, and on the
            // path where the attempt fails a person would be told both
            // that it is gone and to go and delete it.
            ProbeError::NotServed { name, waited } => write!(
                f,
                "the DNS-01 record for {name} was published, and the nameservers for the \
                 zone were still not serving it {} seconds later — so anago did not ask \
                 for a validation that was going to fail. Try again, or use HTTP-01 \
                 (--acme-challenge http-01), which does not wait on DNS at all",
                waited.as_secs()
            ),
            ProbeError::Name(e) => write!(f, "{e}"),
            ProbeError::Unreachable(detail) => {
                write!(f, "a nameserver could not be asked: {detail}")
            }
            ProbeError::Unreadable(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProbeError {}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "_acme-challenge.net.example.com";
    const DIGEST: &str = "toxT9dGLhpBGCM3EhdcQoULLTuF-eqAaOJyBBnA_AbY";

    fn reply(rcode: u8, truncated: bool, values: &[&str]) -> dnswire::Reply {
        dnswire::Reply {
            rcode,
            truncated,
            values: values.iter().map(|value| value.to_string()).collect(),
        }
    }

    #[test]
    fn a_truncated_answer_without_the_value_is_not_an_absence() {
        // The part that did not fit is exactly where the value might
        // be, and several TXT values at one _acme-challenge name is a
        // state DNS-01 allows. Read as absence, this fails a challenge
        // that had already propagated — after waiting the full minute.
        let cut = reply(dnswire::RCODE_OK, true, &["someone-elses-challenge"]);
        assert_eq!(read(&cut, DIGEST), Answer::Silent);
        // Seeing it in the part that did arrive is still seeing it.
        let cut_but_there = reply(dnswire::RCODE_OK, true, &["someone-elses", DIGEST]);
        assert_eq!(read(&cut_but_there, DIGEST), Answer::Serving);
    }

    #[test]
    fn a_whole_answer_without_the_value_is_an_absence() {
        assert_eq!(
            read(&reply(dnswire::RCODE_OK, false, &["someone-elses"]), DIGEST),
            Answer::NotYet
        );
        // Nothing at the name at all — the ordinary state a second
        // after publishing.
        assert_eq!(
            read(&reply(dnswire::RCODE_NAME_ERROR, false, &[]), DIGEST),
            Answer::NotYet
        );
        assert_eq!(
            read(&reply(dnswire::RCODE_OK, false, &[DIGEST]), DIGEST),
            Answer::Serving
        );
    }

    #[test]
    fn a_server_that_could_not_answer_says_nothing_about_the_record() {
        for rcode in [2, 5] {
            assert_eq!(read(&reply(rcode, false, &[]), DIGEST), Answer::Silent);
        }
    }

    #[test]
    fn every_server_that_answered_has_to_be_serving_it() {
        assert_eq!(look(&[Answer::Serving, Answer::Serving]), Look::Served);
        assert_eq!(look(&[Answer::Serving, Answer::NotYet]), Look::Missing);
        assert_eq!(look(&[Answer::NotYet]), Look::Missing);
    }

    #[test]
    fn a_silent_server_is_missing_evidence_not_contrary_evidence() {
        // One of two nameservers unreachable from this host must not
        // stall a renewal that would otherwise work: the one that did
        // answer is authoritative for the same zone.
        assert_eq!(look(&[Answer::Serving, Answer::Silent]), Look::Served);
        assert_eq!(look(&[Answer::Silent, Answer::NotYet]), Look::Missing);
        // With nothing else to go on, silence is the whole answer.
        assert_eq!(look(&[Answer::Silent, Answer::Silent]), Look::Unobservable);
        assert_eq!(look(&[]), Look::Unobservable);
    }

    #[test]
    fn seeing_it_beats_a_clock_that_ran_out() {
        // The look that found it is the answer. Throwing it away
        // because the deadline passed between question and answer
        // would fail a challenge that had succeeded.
        assert_eq!(
            next_step(Look::Served, Duration::ZERO),
            Step::Settle(SETTLE)
        );
        assert_eq!(
            next_step(Look::Served, POLL_TIMEOUT + Duration::from_secs(30)),
            Step::Settle(SETTLE)
        );
    }

    #[test]
    fn being_told_no_runs_the_whole_window() {
        assert_eq!(
            next_step(Look::Missing, Duration::ZERO),
            Step::Again(POLL_INTERVAL)
        );
        // Clipped at the end, so the wait ends when it says it does.
        assert_eq!(
            next_step(Look::Missing, POLL_TIMEOUT - Duration::from_secs(1)),
            Step::Again(Duration::from_secs(1))
        );
        assert_eq!(
            next_step(Look::Missing, POLL_TIMEOUT),
            Step::GiveUp(POLL_TIMEOUT)
        );
    }

    #[test]
    fn blindness_ends_early_and_does_not_fail_the_run() {
        // A host that cannot send UDP/53 would otherwise spend the
        // whole window learning nothing, on every renewal — and then
        // fail a certificate over its own blindness.
        assert_eq!(
            next_step(Look::Unobservable, Duration::ZERO),
            Step::Again(POLL_INTERVAL)
        );
        assert_eq!(
            next_step(Look::Unobservable, BLIND_AFTER - Duration::from_secs(1)),
            Step::Again(Duration::from_secs(1))
        );
        assert_eq!(
            next_step(Look::Unobservable, BLIND_AFTER),
            Step::Blind(SETTLE)
        );
        assert!(BLIND_AFTER < POLL_TIMEOUT, "blindness ends sooner");
    }

    #[test]
    fn each_wait_ends_and_never_sleeps_past_its_own_window() {
        // Both loops on a fake clock: they terminate, and the time
        // they spend is the window each advertises — not a second more.
        for (look_at, window, ending) in [
            (Look::Missing, POLL_TIMEOUT, Step::GiveUp(POLL_TIMEOUT)),
            (Look::Unobservable, BLIND_AFTER, Step::Blind(SETTLE)),
        ] {
            let mut elapsed = Duration::ZERO;
            let mut looks = 0;
            loop {
                match next_step(look_at, elapsed) {
                    Step::Again(pause) => {
                        assert!(!pause.is_zero(), "a zero sleep would spin");
                        elapsed += pause;
                        looks += 1;
                        assert!(looks < 1_000, "{look_at:?} must end on its own");
                    }
                    step => {
                        assert_eq!(step, ending, "{look_at:?}");
                        break;
                    }
                }
            }
            assert_eq!(elapsed, window, "{look_at:?}");
        }
    }

    #[test]
    fn every_address_a_nameserver_resolves_to_gets_a_share_of_one_budget() {
        // A nameserver name usually has both an A and an AAAA record,
        // and their order says nothing about which this host can reach.
        // Stopping at the first would make an IPv4-only machine silent
        // against a server that answers fine over IPv4 — and silence
        // everywhere ends in "anago could not check", so the wait would
        // quietly stop checking anything.
        let mut spent = Duration::ZERO;
        let mut left = 3;
        while left > 0 {
            let budget = client::attempt_budget(QUERY_TIMEOUT - spent, left);
            assert!(!budget.is_zero(), "every address gets a turn");
            spent += budget;
            left -= 1;
        }
        assert!(spent <= QUERY_TIMEOUT, "one server, one budget: {spent:?}");
    }

    #[test]
    fn a_wait_with_nowhere_to_ask_does_not_spend_the_window_finding_out() {
        let outcome = wait(&[], NAME, "digest").unwrap();
        assert_eq!(
            outcome,
            Outcome::Blind {
                waited: Duration::ZERO
            }
        );
        let warning = outcome.warning().unwrap();
        assert!(warning.contains("could not check DNS"), "{warning}");
        assert!(warning.contains("UDP port 53"), "{warning}");
    }

    #[test]
    fn a_name_that_cannot_be_asked_about_is_caught_before_any_waiting() {
        let error = wait(&["ns1.example.com".to_string()], "맥북.example.com", "d").unwrap_err();
        assert!(matches!(error, ProbeError::Name(_)));
        assert!(error.to_string().contains("xn--"), "{error}");
    }

    #[test]
    fn a_served_record_says_nothing_extra() {
        assert_eq!(
            Outcome::Served {
                waited: Duration::from_secs(4)
            }
            .warning(),
            None
        );
    }

    #[test]
    fn giving_up_says_what_to_try_instead() {
        let error = ProbeError::NotServed {
            name: NAME.to_string(),
            waited: POLL_TIMEOUT,
        };
        let message = error.to_string();
        assert!(message.contains(NAME), "{message}");
        assert!(message.contains("60 seconds"), "{message}");
        // What the person needs from *this* module: HTTP-01 does not
        // wait on DNS at all.
        assert!(message.contains("http-01"), "{message}");
        // And what it must not say: this module publishes no record and
        // removes none, so it cannot report on one. The claim used to
        // be here, made before the removal was even attempted — and on
        // the path where the attempt fails the person was told both
        // that it was gone and to go and delete it.
        assert!(!message.contains("removed"), "{message}");
    }

    #[test]
    fn no_message_carries_a_collapsed_line_continuation() {
        for message in [
            ProbeError::NotServed {
                name: NAME.to_string(),
                waited: POLL_TIMEOUT,
            }
            .to_string(),
            ProbeError::Unreachable("timed out".to_string()).to_string(),
            Outcome::Blind {
                waited: Duration::ZERO,
            }
            .warning()
            .unwrap(),
        ] {
            for line in message.lines() {
                assert!(
                    !line.trim_start().contains("  "),
                    "collapsed continuation in {line:?}"
                );
            }
        }
    }
}
