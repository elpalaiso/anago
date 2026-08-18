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
//! Whether a code is still *live* — unexpired, unused — is a separate
//! question answered against the state file, not against the string.

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
}
