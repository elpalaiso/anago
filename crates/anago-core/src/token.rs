//! Device tokens — the bearer credential a device gets from `join` and
//! presents on every later call (DESIGN.md §7.1).
//!
//! Format is 64 lower-case hex characters, 256 bits of randomness. The
//! server stores only the SHA-256 of that string, also 64 hex.
//!
//! What this module owns: the format, the hex encoding, and a
//! comparison that does not return early. What it does not own: the
//! randomness (`/dev/urandom`, in the binary) and the hashing (`sha2`,
//! in the binary) — core is pure std and writes no crypto (§4).
//!
//! [`DeviceToken`] redacts itself in `Debug` and has no `Display`. The
//! plaintext leaves through [`DeviceToken::as_str`] and nowhere else,
//! so a stray `{:?}` in a log line cannot spill it.

use std::fmt;

/// Random bytes behind a token: 32 → 256 bits.
pub const TOKEN_BYTES: usize = 32;

/// Hex characters in a token — and in a hash, both being 32 bytes.
pub const HEX_LEN: usize = TOKEN_BYTES * 2;

const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";

/// A well-formed device token, in the plaintext form the client stores
/// (0600) and sends as a bearer credential.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceToken(String);

impl DeviceToken {
    /// Checks the format of a token as received or read back from
    /// `~/.config/anago/device.json`.
    pub fn parse(input: &str) -> Result<DeviceToken, TokenError> {
        check_hex(input).map(|hex| DeviceToken(hex.to_string()))
    }

    /// Encodes 32 random bytes. The binary draws them from
    /// `/dev/urandom`; the hex format lives here so exactly one place
    /// knows what a token looks like.
    pub fn from_bytes(bytes: &[u8; TOKEN_BYTES]) -> DeviceToken {
        DeviceToken(to_hex(bytes))
    }

    /// The plaintext. The only way out — deliberately explicit at the
    /// call site.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DeviceToken {
    /// Never prints the secret: §7.1 keeps plaintext tokens out of logs
    /// and state files alike.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceToken(redacted)")
    }
}

/// The SHA-256 of a device token, hex, as `peers[].token_hash` stores
/// it (§9.1). Not a secret — it is what stays behind when the token
/// itself is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenHash(String);

impl TokenHash {
    /// Checks the format of a hash read from the state file or produced
    /// by the binary's hasher.
    pub fn parse(input: &str) -> Result<TokenHash, TokenError> {
        check_hex(input).map(|hex| TokenHash(hex.to_string()))
    }

    /// Encodes a 32-byte digest — what `sha2` hands back in the binary.
    pub fn from_bytes(bytes: &[u8; TOKEN_BYTES]) -> TokenHash {
        TokenHash(to_hex(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether two hashes are the same, without returning early on the
    /// first differing character.
    ///
    /// `PartialEq` is derived and *not* constant time; authentication
    /// must go through this method. See [`constant_time_eq`] for what
    /// the guarantee is and is not worth.
    pub fn matches(&self, other: &TokenHash) -> bool {
        constant_time_eq(self.0.as_bytes(), other.0.as_bytes())
    }
}

/// Compares two byte strings in time independent of *where* they
/// differ.
///
/// The length is not treated as a secret: both sides are fixed-width
/// hex here, and an attacker learns nothing from a length mismatch.
///
/// Rust makes no timing promises — a sufficiently clever compiler may
/// still reorder this. What it does remove is the early return, the
/// part that leaks a byte at a time and is actually exploitable over a
/// network. `black_box` keeps the accumulator from being optimized into
/// a short-circuit.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// Why a string is not a token or hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Not [`HEX_LEN`] characters. Carries the length offered.
    WrongLength(usize),
    /// A character outside `[0-9a-f]`. Upper case is included:
    /// §7.1 fixes one spelling so stored and presented forms compare as
    /// bytes.
    BadChar(char),
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::WrongLength(len) => {
                write!(f, "token must be {HEX_LEN} hex characters, got {len}")
            }
            TokenError::BadChar(c) => {
                write!(f, "{c:?} is not a lower-case hex digit")
            }
        }
    }
}

impl std::error::Error for TokenError {}

fn check_hex(input: &str) -> Result<&str, TokenError> {
    let len = input.chars().count();
    if len != HEX_LEN {
        return Err(TokenError::WrongLength(len));
    }
    match input.chars().find(|c| !matches!(c, '0'..='9' | 'a'..='f')) {
        Some(c) => Err(TokenError::BadChar(c)),
        None => Ok(input),
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX_DIGITS[usize::from(byte >> 4)] as char);
        out.push(HEX_DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(pattern: &str) -> String {
        pattern.repeat(HEX_LEN / pattern.chars().count())
    }

    #[test]
    fn accepts_sixty_four_lower_case_hex_characters() {
        let text = hex("0123456789abcdef");
        assert_eq!(text.len(), 64);
        assert_eq!(DeviceToken::parse(&text).unwrap().as_str(), text);
        assert_eq!(TokenHash::parse(&text).unwrap().as_str(), text);
    }

    #[test]
    fn rejects_wrong_lengths() {
        assert_eq!(DeviceToken::parse(""), Err(TokenError::WrongLength(0)));
        assert_eq!(DeviceToken::parse("ab"), Err(TokenError::WrongLength(2)));
        assert_eq!(
            DeviceToken::parse(&hex("ab")[..63]),
            Err(TokenError::WrongLength(63))
        );
        assert_eq!(
            DeviceToken::parse(&format!("{}0", hex("ab"))),
            Err(TokenError::WrongLength(65))
        );
        // Whitespace is not trimmed: a token comes from a file or a
        // header, never from a person typing.
        assert_eq!(
            DeviceToken::parse(&format!(" {}", hex("ab"))),
            Err(TokenError::WrongLength(65))
        );
    }

    #[test]
    fn rejects_upper_case_and_non_hex() {
        // One spelling only, so stored and presented forms compare as
        // bytes (§7.1).
        let mut upper = hex("ab");
        upper.replace_range(0..1, "A");
        assert_eq!(DeviceToken::parse(&upper), Err(TokenError::BadChar('A')));

        let mut with_g = hex("ab");
        with_g.replace_range(63..64, "g");
        assert_eq!(DeviceToken::parse(&with_g), Err(TokenError::BadChar('g')));

        let mut with_dash = hex("ab");
        with_dash.replace_range(4..5, "-");
        assert_eq!(TokenHash::parse(&with_dash), Err(TokenError::BadChar('-')));
    }

    #[test]
    fn encodes_bytes_the_way_the_hasher_prints_them() {
        assert_eq!(
            DeviceToken::from_bytes(&[0; TOKEN_BYTES]).as_str(),
            hex("00")
        );
        assert_eq!(
            DeviceToken::from_bytes(&[0xff; TOKEN_BYTES]).as_str(),
            hex("ff")
        );

        let mut bytes = [0u8; TOKEN_BYTES];
        bytes[0] = 0x0a;
        bytes[1] = 0xb0;
        bytes[TOKEN_BYTES - 1] = 0x5f;
        let token = DeviceToken::from_bytes(&bytes);
        assert!(token.as_str().starts_with("0ab0"));
        assert!(token.as_str().ends_with("5f"));

        // Anything from_bytes builds must parse back to itself.
        assert_eq!(DeviceToken::parse(token.as_str()).unwrap(), token);
        let digest = TokenHash::from_bytes(&bytes);
        assert_eq!(TokenHash::parse(digest.as_str()).unwrap(), digest);
    }

    #[test]
    fn every_byte_value_encodes_to_two_hex_digits() {
        for value in 0u8..=255 {
            let token = DeviceToken::from_bytes(&[value; TOKEN_BYTES]);
            assert_eq!(token.as_str().chars().count(), HEX_LEN);
            assert!(
                DeviceToken::parse(token.as_str()).is_ok(),
                "{value} encoded badly"
            );
        }
    }

    #[test]
    fn the_plaintext_token_never_prints_itself() {
        // §7.1: no plaintext in logs. A stray {:?} must stay harmless.
        let token = DeviceToken::from_bytes(&[0xab; TOKEN_BYTES]);
        let printed = format!("{token:?}");
        assert_eq!(printed, "DeviceToken(redacted)");
        assert!(!printed.contains("abab"));
        // The one way out is explicit.
        assert!(token.as_str().starts_with("abab"));
    }

    #[test]
    fn matching_hashes_match() {
        let a = TokenHash::parse(&hex("ab")).unwrap();
        let b = TokenHash::parse(&hex("ab")).unwrap();
        assert!(a.matches(&b));
        assert!(a.matches(&a));
    }

    #[test]
    fn a_difference_anywhere_fails_the_match() {
        let stored = TokenHash::parse(&hex("ab")).unwrap();
        for position in [0, 1, 31, 62, 63] {
            let mut other = hex("ab");
            let replacement = if other.as_bytes()[position] == b'a' {
                "b"
            } else {
                "a"
            };
            other.replace_range(position..position + 1, replacement);
            let other = TokenHash::parse(&other).unwrap();
            assert!(
                !stored.matches(&other),
                "difference at {position} slipped through"
            );
        }
    }

    #[test]
    fn constant_time_eq_handles_lengths_and_edges() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"bbc"));
        // Length mismatch is not a secret and is answered directly.
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
        // Prefixes must not pass.
        assert!(!constant_time_eq(
            hex("ab").as_bytes(),
            &hex("ab").as_bytes()[..32]
        ));
    }

    #[test]
    fn errors_say_what_is_wrong() {
        assert_eq!(
            TokenError::WrongLength(10).to_string(),
            "token must be 64 hex characters, got 10"
        );
        assert_eq!(
            TokenError::BadChar('Z').to_string(),
            "'Z' is not a lower-case hex digit"
        );
    }
}
