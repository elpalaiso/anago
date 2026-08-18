//! `anago code` (DESIGN.md §8) — issue a join code on the server.
//!
//! Runs against the state file directly rather than the API: it is the
//! bootstrap step, and the person running it is the person with root on
//! the hub. The code it prints is the only thing a new device needs
//! besides the domain.
//!
//! The text it prints and the state change it makes are both pure
//! functions; [`run`] is the part that takes the lock and writes.

use std::fmt;
use std::path::Path;

use anago_core::code::{IssuedCode, JoinCode, DEFAULT_TTL_SECS};
use anago_core::state::ServerState;

use crate::secret;
use crate::store::{Store, StoreError};

/// How many times to redraw before giving up on finding an unused code.
///
/// A collision needs the same 8 characters out of 30^8 to come up
/// twice, so two attempts would do; eight makes the give-up path
/// unreachable in practice while keeping it a bounded loop.
pub const MAX_DRAWS: usize = 8;

/// Draws codes until one is absent from the state file.
///
/// Spent and expired entries are kept for the audit trail (§9.1), and
/// `add_peer` resolves a submitted code against the *first* matching
/// entry — so handing out a value that already appears there would
/// print a code that is reported as used or expired the moment somebody
/// tries it. Rare, but silent and unexplainable when it happens.
///
/// `draw` is a parameter so the retry can be tested without waiting for
/// a 1-in-6.6×10^11 event.
pub fn choose_unused<E>(
    state: &ServerState,
    mut draw: impl FnMut() -> Result<JoinCode, E>,
    draws: usize,
) -> Result<JoinCode, CodeError>
where
    E: fmt::Display,
{
    for _ in 0..draws {
        let candidate = draw().map_err(|e| CodeError::Random(e.to_string()))?;
        if !state.codes.iter().any(|issued| issued.code == candidate) {
            return Ok(candidate);
        }
    }
    Err(CodeError::NoFreeCode(draws))
}

/// Appends a freshly issued code.
///
/// Codes accumulate: issuing one does not cancel another. Two people
/// setting up two devices at the same time is ordinary, and a code that
/// silently died because someone else ran `anago code` would be a
/// confusing way to learn otherwise. Expiry and single use already
/// bound the risk (§7).
pub fn issue(state: &mut ServerState, code: JoinCode, now: i64, ttl_secs: i64) -> IssuedCode {
    let issued = IssuedCode::issue(code, now, ttl_secs);
    state.codes.push(issued.clone());
    issued
}

/// What `anago code` prints: a line to paste on the new device, and how
/// long it is good for.
pub fn output(domain: &str, code: &JoinCode, ttl_secs: i64) -> String {
    format!(
        "Run this on the device you are adding:\n\n     anago join {domain} {code}\n\n\
         Single use, good for {minutes} minutes.\n",
        minutes = ttl_secs / 60
    )
}

/// Issues a code, saves it, and returns what to print.
pub fn run(root: &Path, now: i64) -> Result<String, CodeError> {
    let store = Store::new(root);
    let mut guard = store.lock().map_err(CodeError::State)?;

    // Drawn under the lock, so the check against the history cannot
    // race another `anago code`.
    let code = choose_unused(guard.state(), secret::new_join_code, MAX_DRAWS)?;
    let issued = issue(guard.state_mut(), code, now, DEFAULT_TTL_SECS);
    let domain = guard.state().domain.clone();
    guard.commit().map_err(CodeError::State)?;

    Ok(output(&domain, &issued.code, DEFAULT_TTL_SECS))
}

/// Why a code could not be issued.
#[derive(Debug, Clone, PartialEq)]
pub enum CodeError {
    /// The state file could not be read or written — including "this
    /// machine is not a hub", which [`StoreError`] words for us.
    State(StoreError),
    /// The kernel would not give us randomness. Rather than fall back
    /// to something weaker, no code is issued (§7.1).
    Random(String),
    /// Every draw collided with a code already in the file.
    NoFreeCode(usize),
}

impl fmt::Display for CodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodeError::State(e) => write!(f, "{e}"),
            CodeError::Random(e) => write!(f, "could not read /dev/urandom: {e}"),
            CodeError::NoFreeCode(draws) => write!(
                f,
                "could not find an unused join code in {draws} tries — \
                 the state file's code history is implausibly large"
            ),
        }
    }
}

impl std::error::Error for CodeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use anago_core::code::CodeStatus;
    use anago_core::state::{PrivateKey, ServerKeys};
    use anago_core::subnet::Subnet;

    const NOW: i64 = 1_755_500_000;

    struct TempRoot {
        path: PathBuf,
    }

    impl TempRoot {
        fn new(state: &ServerState) -> TempRoot {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("anago-code-{}-{unique}", std::process::id()));
            fs::create_dir_all(&path).expect("temp dir");
            Store::new(&path).write(state).expect("write state");
            TempRoot { path }
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn state() -> ServerState {
        ServerState {
            domain: "net.example.com".to_string(),
            subnet: Subnet::parse("10.100.0.0/24").unwrap(),
            listen_port: 51820,
            api_port: 443,
            tls_cert_path: "/etc/ssl/anago/fullchain.pem".to_string(),
            tls_key_path: "/etc/ssl/anago/privkey.pem".to_string(),
            server: ServerKeys {
                private_key: PrivateKey::new("c2VydmVyIHByaXZhdGU="),
                public_key: "c2VydmVyIHB1YmxpYw==".to_string(),
                address: "10.100.0.1".parse::<Ipv4Addr>().unwrap(),
            },
            peers: Vec::new(),
            codes: Vec::new(),
        }
    }

    #[test]
    fn issuing_adds_a_live_code() {
        let mut state = state();
        let issued = issue(
            &mut state,
            JoinCode::parse("7QX4-M2KD").unwrap(),
            NOW,
            DEFAULT_TTL_SECS,
        );

        assert_eq!(state.codes, vec![issued.clone()]);
        assert_eq!(issued.issued_at, NOW);
        assert_eq!(issued.expires_at, NOW + DEFAULT_TTL_SECS);
        assert_eq!(issued.used_at, None);
        assert!(issued.is_usable(NOW));
        assert!(!issued.is_usable(NOW + DEFAULT_TTL_SECS));
    }

    #[test]
    fn a_new_code_does_not_cancel_the_last_one() {
        // Two devices being set up at once is ordinary; a code that
        // died because someone else ran `anago code` would not be.
        let mut state = state();
        issue(
            &mut state,
            JoinCode::parse("7QX4-M2KD").unwrap(),
            NOW,
            DEFAULT_TTL_SECS,
        );
        issue(
            &mut state,
            JoinCode::parse("HJKM-NPQR").unwrap(),
            NOW + 5,
            DEFAULT_TTL_SECS,
        );

        assert_eq!(state.codes.len(), 2);
        assert!(state.codes.iter().all(|code| code.is_usable(NOW + 6)));
    }

    #[test]
    fn a_code_that_is_already_in_the_history_is_redrawn() {
        // `add_peer` matches the first entry with that value, so
        // reissuing a spent code would print one that is reported as
        // already used.
        let mut state = state();
        let taken = JoinCode::parse("7QX4-M2KD").unwrap();
        let mut spent = IssuedCode::issue(taken.clone(), NOW - 10_000, DEFAULT_TTL_SECS);
        spent.used_at = Some(NOW - 9_000);
        state.codes.push(spent);

        let fresh = JoinCode::parse("HJKM-NPQR").unwrap();
        let mut draws = vec![fresh.clone(), taken.clone()];
        let chosen = choose_unused(
            &state,
            || Ok::<_, String>(draws.pop().expect("another draw")),
            MAX_DRAWS,
        )
        .unwrap();

        assert_eq!(chosen, fresh, "the colliding draw must be discarded");
        assert!(draws.is_empty(), "both draws were used");
    }

    #[test]
    fn an_unused_code_is_taken_on_the_first_draw() {
        let state = state();
        let mut draws = 0;
        let code = choose_unused(
            &state,
            || {
                draws += 1;
                Ok::<_, String>(JoinCode::parse("7QX4-M2KD").unwrap())
            },
            MAX_DRAWS,
        )
        .unwrap();
        assert_eq!(code.as_str(), "7QX4-M2KD");
        assert_eq!(draws, 1, "no redraw when there is no collision");
    }

    #[test]
    fn giving_up_is_bounded_and_says_why() {
        let mut state = state();
        let taken = JoinCode::parse("7QX4-M2KD").unwrap();
        state
            .codes
            .push(IssuedCode::issue(taken.clone(), NOW, DEFAULT_TTL_SECS));

        let mut draws = 0;
        let e = choose_unused(
            &state,
            || {
                draws += 1;
                Ok::<_, String>(taken.clone())
            },
            MAX_DRAWS,
        )
        .unwrap_err();
        assert_eq!(e, CodeError::NoFreeCode(MAX_DRAWS));
        assert_eq!(draws, MAX_DRAWS, "bounded, not a spin");
        assert!(e.to_string().contains("implausibly large"), "{e}");
    }

    #[test]
    fn a_failed_draw_is_not_retried_as_a_collision() {
        // No randomness means no code at all (§7.1), not eight tries.
        let state = state();
        let mut draws = 0;
        let e = choose_unused(
            &state,
            || {
                draws += 1;
                Err::<JoinCode, _>("No such file or directory")
            },
            MAX_DRAWS,
        )
        .unwrap_err();
        assert!(matches!(e, CodeError::Random(_)), "{e:?}");
        assert_eq!(draws, 1);
    }

    #[test]
    fn the_output_is_a_line_to_paste() {
        let text = output(
            "net.example.com",
            &JoinCode::parse("7QX4-M2KD").unwrap(),
            DEFAULT_TTL_SECS,
        );
        assert!(
            text.contains("anago join net.example.com 7QX4-M2KD"),
            "{text}"
        );
        assert!(text.contains("Single use, good for 15 minutes."), "{text}");
        // The command sits on its own line, so a double-click selects it.
        assert!(
            text.lines()
                .any(|line| line.trim() == "anago join net.example.com 7QX4-M2KD"),
            "{text}"
        );
    }

    #[test]
    fn running_saves_the_code_where_join_will_look_for_it() {
        let temp = TempRoot::new(&state());
        let text = run(&temp.path, NOW).unwrap();

        let stored = Store::new(&temp.path).read().unwrap();
        assert_eq!(stored.codes.len(), 1);
        let issued = &stored.codes[0];
        assert_eq!(issued.status(NOW), CodeStatus::Usable);
        // The printed code is the stored one — a mismatch here would
        // hand out codes that do not work.
        assert!(
            text.contains(&format!("anago join net.example.com {}", issued.code)),
            "{text} / {}",
            issued.code
        );
    }

    #[test]
    fn each_run_issues_a_different_code() {
        let temp = TempRoot::new(&state());
        run(&temp.path, NOW).unwrap();
        run(&temp.path, NOW + 1).unwrap();

        let stored = Store::new(&temp.path).read().unwrap();
        assert_eq!(stored.codes.len(), 2, "codes accumulate");
        assert_ne!(stored.codes[0].code, stored.codes[1].code);
        assert_eq!(stored.codes[1].issued_at, NOW + 1);
    }

    #[test]
    fn a_machine_that_is_not_a_hub_says_so() {
        let dir = std::env::temp_dir().join(format!("anago-code-none-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let e = run(&dir, NOW).unwrap_err();
        assert!(e.to_string().contains("anago server init"), "{e}");
        let _ = fs::remove_dir_all(&dir);
    }
}
