//! Join codes: the string `anago code` prints and `anago join` takes
//! (DESIGN.md §7.2).
//!
//! `XXXX-XXXX` over a 30-character alphabet that leaves out the pairs
//! people misread — `0`/`O`, `1`/`I`/`L`, and `U`/`V`. Someone reads
//! this off a VPS terminal and types it on a laptop, so the two bits
//! given up against a full base32 buy back every "is that an O or a
//! zero" retry.
//!
//! Randomness is the binary's job (`/dev/urandom`, §7.1). This module
//! owns the alphabet, the shape, normalization, and validation —
//! nothing here needs entropy, so all of it is pure and unit-tested.
//!
//! Liveness — unexpired, unused — is a separate question from shape,
//! and answered by [`status`] from the numbers the state file keeps
//! (§9.1), never by looking at the string.

use std::fmt;

/// Characters a join code may contain (§7.2). No `0`, `1`, `I`, `L`,
/// `O`, or `U`.
pub const ALPHABET: &str = "23456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Characters per hyphen-separated group.
pub const GROUP_LEN: usize = 4;

/// Number of groups.
pub const GROUPS: usize = 2;

/// Significant characters, hyphen excluded.
pub const CODE_LEN: usize = GROUP_LEN * GROUPS;

/// A syntactically valid join code, held in canonical form: upper case,
/// one hyphen, e.g. `7QX4-M2KD`.
///
/// Only [`JoinCode::parse`] builds one, so a `JoinCode` in hand is
/// always well-formed — callers compare and store it without re-checking
/// the shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinCode(String);

impl JoinCode {
    /// Accepts what a person retyping might produce: any case, hyphens
    /// wherever (or nowhere), surrounding or embedded whitespace. What
    /// it will not do is guess at a character outside the alphabet — a
    /// typed `O` is rejected rather than read as `Q` or `0`.
    pub fn parse(input: &str) -> Result<JoinCode, CodeError> {
        let mut chars = String::with_capacity(CODE_LEN);
        for c in input.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            let upper = c.to_ascii_uppercase();
            if !ALPHABET.contains(upper) {
                return Err(CodeError::BadChar(c));
            }
            if chars.len() == CODE_LEN {
                return Err(CodeError::WrongLength(CODE_LEN + 1));
            }
            chars.push(upper);
        }
        if chars.len() != CODE_LEN {
            return Err(CodeError::WrongLength(chars.len()));
        }
        let (first, second) = chars.split_at(GROUP_LEN);
        Ok(JoinCode(format!("{first}-{second}")))
    }

    /// Builds a code from `CODE_LEN` alphabet positions. The binary
    /// draws the numbers from `/dev/urandom` and calls this, so the
    /// alphabet lives in exactly one place.
    ///
    /// `None` if the count is wrong or an index is out of range.
    pub fn from_indices(indices: &[usize]) -> Option<JoinCode> {
        if indices.len() != CODE_LEN {
            return None;
        }
        let alphabet: Vec<char> = ALPHABET.chars().collect();
        let mut chars = String::with_capacity(CODE_LEN);
        for index in indices {
            chars.push(*alphabet.get(*index)?);
        }
        let (first, second) = chars.split_at(GROUP_LEN);
        Some(JoinCode(format!("{first}-{second}")))
    }

    /// The canonical form, e.g. `7QX4-M2KD`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JoinCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a string is not a join code. The shape only — an expired or
/// already-used code is a perfectly valid string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeError {
    /// A character outside the alphabet. Carries the character as
    /// typed, so the message can point at it.
    BadChar(char),
    /// Wrong number of significant characters (hyphens and whitespace
    /// already ignored). A count of `CODE_LEN + 1` means "too long";
    /// counting the rest of an overlong paste would not help anyone.
    WrongLength(usize),
}

impl fmt::Display for CodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodeError::BadChar(c) => {
                write!(f, "{c:?} is not used in join codes (alphabet: {ALPHABET})")
            }
            CodeError::WrongLength(len) if *len > CODE_LEN => {
                write!(f, "join code is longer than {CODE_LEN} characters")
            }
            CodeError::WrongLength(len) => {
                write!(f, "join code needs {CODE_LEN} characters, got {len}")
            }
        }
    }
}

impl std::error::Error for CodeError {}

// ------------------------------------------------------------ lifetime

/// How long a fresh code lives by default: 15 minutes (§7). A code is
/// the right to register, so it dies young.
pub const DEFAULT_TTL_SECS: i64 = 15 * 60;

/// Where a code stands right now. Shape is not in question here — a
/// spent code is still a well-formed string.
///
/// The server collapses every non-`Usable` answer into one
/// `invalid_code` on the wire (see `proto::ErrorCode`): telling an
/// unauthenticated caller *which* way a code failed only helps them
/// probe. The distinction is for the server's own log and for
/// `anago code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeStatus {
    /// Issued, unspent, not yet expired.
    Usable,
    /// Already redeemed — permanently, by the time in `used_at`.
    Used,
    /// Past its expiry.
    Expired,
}

impl CodeStatus {
    pub fn is_usable(self) -> bool {
        self == CodeStatus::Usable
    }
}

impl fmt::Display for CodeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodeStatus::Usable => f.write_str("usable"),
            CodeStatus::Used => f.write_str("already used"),
            CodeStatus::Expired => f.write_str("expired"),
        }
    }
}

/// Expiry instant for a code issued at `issued_at` with `ttl_secs`,
/// both Unix epoch seconds (§9.1).
///
/// Saturating: a TTL large enough to overflow parks the code at
/// `i64::MAX` rather than wrapping into the past, which would expire it
/// instantly.
pub fn expires_at(issued_at: i64, ttl_secs: i64) -> i64 {
    issued_at.saturating_add(ttl_secs)
}

/// Judges a code from what the state file stores about it: its expiry,
/// and when it was redeemed if it was.
///
/// - `Used` wins over `Expired`. A redeemed code is spent forever, and
///   saying "expired" would suggest a fresher one of the same string
///   might work.
/// - Expiry is exclusive: usable while `now < expires_at`, gone at
///   exactly `expires_at`. A zero or negative TTL therefore means the
///   code is born expired instead of living one extra second.
/// - `now` before the issue time (a clock stepping backwards on the
///   server) leaves the code usable. Skew is not the joining device's
///   fault, and the expiry still bounds it.
pub fn status(expires_at: i64, used_at: Option<i64>, now: i64) -> CodeStatus {
    if used_at.is_some() {
        return CodeStatus::Used;
    }
    if now >= expires_at {
        return CodeStatus::Expired;
    }
    CodeStatus::Usable
}

/// [`status`] for callers holding an issue time and a TTL rather than
/// an expiry — `anago code` deciding what to print, say. The state file
/// stores `expires_at`, so the server itself uses [`status`].
pub fn status_from_issue(
    issued_at: i64,
    ttl_secs: i64,
    used_at: Option<i64>,
    now: i64,
) -> CodeStatus {
    status(expires_at(issued_at, ttl_secs), used_at, now)
}

/// One entry of the state file's `codes[]` (§9.1).
///
/// Expired and spent entries are kept rather than deleted — the audit
/// trail of who registered when is worth more than the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCode {
    pub code: JoinCode,
    pub issued_at: i64,
    pub expires_at: i64,
    /// `None` until redeemed; the redemption time afterwards.
    pub used_at: Option<i64>,
}

impl IssuedCode {
    /// A code issued now, living for `ttl_secs`.
    pub fn issue(code: JoinCode, issued_at: i64, ttl_secs: i64) -> IssuedCode {
        IssuedCode {
            code,
            issued_at,
            expires_at: expires_at(issued_at, ttl_secs),
            used_at: None,
        }
    }

    pub fn status(&self, now: i64) -> CodeStatus {
        status(self.expires_at, self.used_at, now)
    }

    pub fn is_usable(&self, now: i64) -> bool {
        self.status(now).is_usable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabet_leaves_out_the_confusable_characters() {
        assert_eq!(ALPHABET.len(), 30);
        for c in ['0', '1', 'I', 'L', 'O', 'U'] {
            assert!(!ALPHABET.contains(c), "{c} should not be in the alphabet");
        }
        // No repeats, all upper case.
        let mut seen = String::new();
        for c in ALPHABET.chars() {
            assert!(c.is_ascii_uppercase() || c.is_ascii_digit(), "{c}");
            assert!(!seen.contains(c), "{c} appears twice");
            seen.push(c);
        }
    }

    #[test]
    fn parses_the_canonical_form() {
        let code = JoinCode::parse("7QX4-M2KD").unwrap();
        assert_eq!(code.as_str(), "7QX4-M2KD");
        assert_eq!(code.to_string(), "7QX4-M2KD");
    }

    #[test]
    fn accepts_what_a_person_retyping_produces() {
        let canonical = JoinCode::parse("7QX4-M2KD").unwrap();
        for input in [
            "7qx4-m2kd",       // lower case
            "7QX4M2KD",        // hyphen dropped
            "7qx4m2kd",        // both
            "  7QX4-M2KD  ",   // pasted with padding
            "7QX4 M2KD",       // space instead of hyphen
            "7-Q-X-4-M-2-K-D", // hyphens everywhere
            "7QX4-\nM2KD",     // wrapped across lines
        ] {
            assert_eq!(
                JoinCode::parse(input).unwrap(),
                canonical,
                "failed for {input:?}"
            );
        }
    }

    #[test]
    fn rejects_characters_outside_the_alphabet() {
        // The excluded confusables are refused, not silently remapped:
        // guessing wrong would hand out a registration to the wrong
        // string.
        assert_eq!(JoinCode::parse("OQX4-M2KD"), Err(CodeError::BadChar('O')));
        assert_eq!(JoinCode::parse("0QX4-M2KD"), Err(CodeError::BadChar('0')));
        assert_eq!(JoinCode::parse("1QX4-M2KD"), Err(CodeError::BadChar('1')));
        assert_eq!(JoinCode::parse("IQX4-M2KD"), Err(CodeError::BadChar('I')));
        assert_eq!(JoinCode::parse("lQX4-M2KD"), Err(CodeError::BadChar('l')));
        assert_eq!(JoinCode::parse("UQX4-M2KD"), Err(CodeError::BadChar('U')));
        // And anything else typed by accident.
        assert_eq!(JoinCode::parse("7QX4-M2K!"), Err(CodeError::BadChar('!')));
        assert_eq!(JoinCode::parse("7QX4-M2K맥"), Err(CodeError::BadChar('맥')));
    }

    #[test]
    fn rejects_wrong_lengths() {
        assert_eq!(JoinCode::parse(""), Err(CodeError::WrongLength(0)));
        assert_eq!(JoinCode::parse("-"), Err(CodeError::WrongLength(0)));
        assert_eq!(JoinCode::parse("   "), Err(CodeError::WrongLength(0)));
        assert_eq!(JoinCode::parse("7QX4"), Err(CodeError::WrongLength(4)));
        assert_eq!(JoinCode::parse("7QX4-M2K"), Err(CodeError::WrongLength(7)));
        assert_eq!(
            JoinCode::parse("7QX4-M2KDX"),
            Err(CodeError::WrongLength(CODE_LEN + 1))
        );
    }

    #[test]
    fn a_bad_character_beats_a_bad_length() {
        // Report the character the user can see and fix, even when the
        // string is also the wrong size.
        assert_eq!(JoinCode::parse("OO"), Err(CodeError::BadChar('O')));
    }

    #[test]
    fn errors_name_the_problem() {
        assert_eq!(
            CodeError::BadChar('O').to_string(),
            "'O' is not used in join codes (alphabet: 23456789ABCDEFGHJKMNPQRSTVWXYZ)"
        );
        assert_eq!(
            CodeError::WrongLength(4).to_string(),
            "join code needs 8 characters, got 4"
        );
        assert_eq!(
            CodeError::WrongLength(9).to_string(),
            "join code is longer than 8 characters"
        );
    }

    #[test]
    fn builds_from_alphabet_indices() {
        // What the binary does after drawing bytes from /dev/urandom.
        let first = JoinCode::from_indices(&[0; CODE_LEN]).unwrap();
        assert_eq!(first.as_str(), "2222-2222");
        let last = JoinCode::from_indices(&[ALPHABET.chars().count() - 1; CODE_LEN]).unwrap();
        assert_eq!(last.as_str(), "ZZZZ-ZZZZ");
        // 7 Q X 4 M 2 K D, spelled by position in ALPHABET.
        let mixed = JoinCode::from_indices(&[5, 21, 27, 2, 18, 0, 17, 11]).unwrap();
        assert_eq!(mixed.as_str(), "7QX4-M2KD");
        // Anything from_indices builds must parse back to itself.
        assert_eq!(JoinCode::parse(mixed.as_str()).unwrap(), mixed);
    }

    #[test]
    fn from_indices_refuses_bad_input() {
        assert_eq!(JoinCode::from_indices(&[]), None);
        assert_eq!(JoinCode::from_indices(&[0; CODE_LEN - 1]), None);
        assert_eq!(JoinCode::from_indices(&[0; CODE_LEN + 1]), None);
        // Out of range: an index the alphabet has no character for.
        assert_eq!(JoinCode::from_indices(&[0, 0, 0, 0, 0, 0, 0, 30]), None);
    }

    #[test]
    fn every_alphabet_character_survives_a_round_trip() {
        for (i, c) in ALPHABET.chars().enumerate() {
            let code = JoinCode::from_indices(&[i, 0, 0, 0, 0, 0, 0, 0]).unwrap();
            assert!(code.as_str().starts_with(c), "{c} lost in {code}");
            assert_eq!(JoinCode::parse(code.as_str()).unwrap(), code);
        }
    }

    // ------------------------------------------------------ lifetime

    const ISSUED: i64 = 1_755_500_000;

    fn code() -> JoinCode {
        JoinCode::parse("7QX4-M2KD").unwrap()
    }

    #[test]
    fn default_ttl_is_fifteen_minutes() {
        assert_eq!(DEFAULT_TTL_SECS, 900);
        assert_eq!(expires_at(ISSUED, DEFAULT_TTL_SECS), ISSUED + 900);
    }

    #[test]
    fn expiry_is_exclusive_at_the_boundary() {
        let end = expires_at(ISSUED, DEFAULT_TTL_SECS);
        assert_eq!(status(end, None, ISSUED), CodeStatus::Usable);
        assert_eq!(status(end, None, end - 1), CodeStatus::Usable);
        // The last usable instant is end - 1; end itself is too late.
        assert_eq!(status(end, None, end), CodeStatus::Expired);
        assert_eq!(status(end, None, end + 1), CodeStatus::Expired);
    }

    #[test]
    fn a_used_code_stays_used_whenever_it_is_asked() {
        let end = expires_at(ISSUED, DEFAULT_TTL_SECS);
        let used = Some(ISSUED + 10);
        // Used beats Expired in both directions of the boundary: a
        // spent code never becomes usable again.
        assert_eq!(status(end, used, ISSUED + 11), CodeStatus::Used);
        assert_eq!(status(end, used, end - 1), CodeStatus::Used);
        assert_eq!(status(end, used, end), CodeStatus::Used);
        assert_eq!(status(end, used, end + 100_000), CodeStatus::Used);
        // Even a used_at of 0 counts as used — presence, not truthiness.
        assert_eq!(status(end, Some(0), ISSUED), CodeStatus::Used);
    }

    #[test]
    fn a_zero_or_negative_ttl_is_born_expired() {
        assert_eq!(
            status_from_issue(ISSUED, 0, None, ISSUED),
            CodeStatus::Expired
        );
        assert_eq!(
            status_from_issue(ISSUED, -1, None, ISSUED),
            CodeStatus::Expired
        );
        assert_eq!(
            status_from_issue(ISSUED, -900, None, ISSUED),
            CodeStatus::Expired
        );
        // One second of life is one second of life.
        assert_eq!(
            status_from_issue(ISSUED, 1, None, ISSUED),
            CodeStatus::Usable
        );
        assert_eq!(
            status_from_issue(ISSUED, 1, None, ISSUED + 1),
            CodeStatus::Expired
        );
    }

    #[test]
    fn a_backwards_clock_does_not_reject_the_device() {
        // Server clock stepped back after issuing: skew is not the
        // joining device's fault, and expiry still bounds the code.
        assert_eq!(
            status_from_issue(ISSUED, DEFAULT_TTL_SECS, None, ISSUED - 3600),
            CodeStatus::Usable
        );
        assert_eq!(
            status_from_issue(ISSUED, DEFAULT_TTL_SECS, None, 0),
            CodeStatus::Usable
        );
        assert_eq!(
            status_from_issue(ISSUED, DEFAULT_TTL_SECS, None, i64::MIN),
            CodeStatus::Usable
        );
    }

    #[test]
    fn a_huge_ttl_saturates_instead_of_wrapping_into_the_past() {
        assert_eq!(expires_at(ISSUED, i64::MAX), i64::MAX);
        assert_eq!(expires_at(i64::MAX, 1), i64::MAX);
        assert_eq!(expires_at(i64::MIN, -1), i64::MIN);
        // Wrapping would have expired it instantly.
        assert_eq!(
            status_from_issue(ISSUED, i64::MAX, None, ISSUED),
            CodeStatus::Usable
        );
        // i64::MAX is still not usable *at* i64::MAX, by the exclusive rule.
        assert_eq!(status(i64::MAX, None, i64::MAX), CodeStatus::Expired);
    }

    #[test]
    fn issued_codes_answer_for_themselves() {
        let mut issued = IssuedCode::issue(code(), ISSUED, DEFAULT_TTL_SECS);
        assert_eq!(issued.expires_at, ISSUED + DEFAULT_TTL_SECS);
        assert_eq!(issued.used_at, None);
        assert!(issued.is_usable(ISSUED + 899));
        assert!(!issued.is_usable(ISSUED + 900));
        assert_eq!(issued.status(ISSUED + 900), CodeStatus::Expired);

        issued.used_at = Some(ISSUED + 5);
        assert_eq!(issued.status(ISSUED + 6), CodeStatus::Used);
        assert!(!issued.is_usable(ISSUED + 6));
        // The code string is untouched by any of this.
        assert_eq!(issued.code.as_str(), "7QX4-M2KD");
    }

    #[test]
    fn status_reads_as_a_sentence() {
        assert_eq!(CodeStatus::Usable.to_string(), "usable");
        assert_eq!(CodeStatus::Used.to_string(), "already used");
        assert_eq!(CodeStatus::Expired.to_string(), "expired");
        assert!(CodeStatus::Usable.is_usable());
        assert!(!CodeStatus::Used.is_usable());
        assert!(!CodeStatus::Expired.is_usable());
    }
}
