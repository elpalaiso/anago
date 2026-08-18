//! The parts of ACME that are string assembly (DESIGN.md §10.2).
//!
//! ACME issuance is mostly signing, key handling, and HTTP — all of it
//! `instant-acme`'s job in the binary crate. What is left over is a
//! handful of strings whose exact shape decides whether a challenge
//! validates: the path an HTTP-01 response is served at, the body it
//! serves, and the DNS name a DNS-01 record goes on. Those live here so
//! they are unit-tested rather than discovered on a real server.
//!
//! **What this module does not do, ever:** sign, hold a key, hash, or
//! talk to anything. Core is pure std (§4 principle 4) and writes no
//! crypto (§3). The two digests ACME needs are computed in the binary
//! and arrive here as strings:
//!
//! - the account key's **JWK thumbprint** — SHA-256 over the key's JSON
//!   form, base64url — which [`key_authorization`] appends to a token;
//! - the **DNS-01 record value** — SHA-256 over the key authorization,
//!   base64url — which the binary derives from what
//!   [`key_authorization`] returns. This module hands over the input to
//!   that digest and stops there.

use std::fmt;

/// Prefix of the path an HTTP-01 response is served at (RFC 8555 §8.3).
pub const HTTP01_PREFIX: &str = "/.well-known/acme-challenge/";

/// Label a DNS-01 record hangs under (RFC 8555 §8.4).
pub const DNS01_LABEL: &str = "_acme-challenge";

/// base64url of a SHA-256 digest, unpadded: 32 bytes → 43 characters.
pub const THUMBPRINT_LEN: usize = 43;

/// Longest token accepted. RFC 8555 sets no maximum, but this string
/// becomes a URL path segment, so an unbounded one from a confused or
/// hostile directory would become an unbounded path.
pub const MAX_TOKEN_LEN: usize = 255;

/// A challenge token as the CA issued it.
///
/// Validated because it is the one piece of ACME input that reaches a
/// **path**: served at `/.well-known/acme-challenge/<token>` (§8.3).
/// A token carrying `/` or `..` would turn the challenge responder into
/// a traversal, and one carrying a control character would split a
/// header. Holding this type means the string is safe to concatenate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeToken(String);

impl ChallengeToken {
    /// Accepts the base64url alphabet (`A-Z a-z 0-9 - _`), unpadded.
    ///
    /// There is no minimum length. RFC 8555 asks the CA for at least
    /// 128 bits of entropy, but that is the CA's promise to keep, and
    /// guessing a floor here would reject a directory that encodes its
    /// tokens differently. Nothing on our side gets weaker from a short
    /// token: the response we serve is public by design.
    pub fn parse(input: &str) -> Result<ChallengeToken, AcmeError> {
        if input.is_empty() {
            return Err(AcmeError::EmptyToken);
        }
        if input.len() > MAX_TOKEN_LEN {
            return Err(AcmeError::TokenTooLong(input.len()));
        }
        match input.chars().find(|c| !is_base64url(*c)) {
            Some(bad) => Err(AcmeError::TokenCharacter(bad)),
            None => Ok(ChallengeToken(input.to_string())),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ChallengeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The base64url SHA-256 thumbprint of the ACME account key.
///
/// Computed in the binary (`sha2`, then base64url) and parsed here so
/// that [`key_authorization`] cannot be handed a half-formed digest —
/// a stray newline in it would produce a body the CA reads as a
/// different key authorization, and the challenge would fail with
/// nothing obviously wrong in the logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thumbprint(String);

impl Thumbprint {
    /// Exactly [`THUMBPRINT_LEN`] base64url characters. The length is
    /// pinned because RFC 8555 §8.1 specifies SHA-256 and nothing else,
    /// so any other length means the binary computed the wrong thing.
    pub fn parse(input: &str) -> Result<Thumbprint, AcmeError> {
        if input.chars().count() != THUMBPRINT_LEN {
            return Err(AcmeError::ThumbprintLength(input.chars().count()));
        }
        match input.chars().find(|c| !is_base64url(*c)) {
            Some(bad) => Err(AcmeError::ThumbprintCharacter(bad)),
            None => Ok(Thumbprint(input.to_string())),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Where an HTTP-01 response is served: `/.well-known/acme-challenge/`
/// plus the token (RFC 8555 §8.3).
///
/// No escaping happens, and none is needed — [`ChallengeToken`] already
/// ruled out every character that would mean something in a path.
pub fn http01_path(token: &ChallengeToken) -> String {
    format!("{HTTP01_PREFIX}{token}")
}

/// The key authorization: `token || "." || thumbprint` (RFC 8555 §8.1).
///
/// Both challenges are built from this one string. HTTP-01 serves it
/// verbatim as the body at [`http01_path`]; DNS-01 publishes the
/// base64url SHA-256 **of** it, which the binary computes.
pub fn key_authorization(token: &ChallengeToken, thumbprint: &Thumbprint) -> String {
    format!("{}.{}", token.as_str(), thumbprint.as_str())
}

/// The name a DNS-01 TXT record goes on: `_acme-challenge.<domain>`
/// (RFC 8555 §8.4).
///
/// A trailing dot is dropped, because the same name is sent to the
/// Cloudflare API, which names records in relative form; keeping it
/// would create a second record beside the one we meant to edit.
/// Nothing else is rewritten: the domain is the hub's own `--domain`,
/// already checked when it entered the state file, and DNS labels are
/// compared case-insensitively.
pub fn dns01_record_name(domain: &str) -> String {
    format!(
        "{DNS01_LABEL}.{}",
        domain.strip_suffix('.').unwrap_or(domain)
    )
}

fn is_base64url(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Why an ACME string was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeError {
    EmptyToken,
    TokenTooLong(usize),
    TokenCharacter(char),
    ThumbprintLength(usize),
    ThumbprintCharacter(char),
}

impl fmt::Display for AcmeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AcmeError::EmptyToken => f.write_str("the challenge token is empty"),
            AcmeError::TokenTooLong(len) => write!(
                f,
                "the challenge token is {len} characters, more than the {MAX_TOKEN_LEN} allowed"
            ),
            AcmeError::TokenCharacter(c) => write!(
                f,
                "the challenge token contains {c:?}, which is not base64url"
            ),
            AcmeError::ThumbprintLength(len) => write!(
                f,
                "the account key thumbprint is {len} characters, not the {THUMBPRINT_LEN} \
                 a base64url SHA-256 digest has"
            ),
            AcmeError::ThumbprintCharacter(c) => write!(
                f,
                "the account key thumbprint contains {c:?}, which is not base64url"
            ),
        }
    }
}

impl std::error::Error for AcmeError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token the shape Let's Encrypt issues: 32 bytes, base64url.
    const TOKEN: &str = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";
    /// A thumbprint of the same shape — both are base64url SHA-256.
    const THUMB: &str = "9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI";

    fn token() -> ChallengeToken {
        ChallengeToken::parse(TOKEN).unwrap()
    }

    fn thumbprint() -> Thumbprint {
        Thumbprint::parse(THUMB).unwrap()
    }

    #[test]
    fn the_http01_path_is_the_well_known_one() {
        assert_eq!(
            http01_path(&token()),
            format!("/.well-known/acme-challenge/{TOKEN}")
        );
    }

    #[test]
    fn the_body_is_the_token_a_dot_and_the_thumbprint() {
        // RFC 8555 §8.1. One character wrong here and the CA reads a
        // different authorization; the challenge just fails.
        assert_eq!(
            key_authorization(&token(), &thumbprint()),
            format!("{TOKEN}.{THUMB}")
        );
    }

    #[test]
    fn the_key_authorization_has_exactly_one_separator() {
        let body = key_authorization(&token(), &thumbprint());
        assert_eq!(body.matches('.').count(), 1);
        // And no whitespace: the body is served byte for byte.
        assert!(!body.contains(char::is_whitespace), "{body}");
    }

    #[test]
    fn the_dns_record_hangs_under_the_acme_challenge_label() {
        assert_eq!(
            dns01_record_name("net.example.com"),
            "_acme-challenge.net.example.com"
        );
    }

    #[test]
    fn a_trailing_dot_does_not_become_a_second_record() {
        // Cloudflare names records relatively; the absolute form would
        // create a record beside the one we meant to edit.
        assert_eq!(
            dns01_record_name("net.example.com."),
            "_acme-challenge.net.example.com"
        );
        // Only one dot is dropped — a name ending in two is not a form
        // we invent a meaning for.
        assert_eq!(
            dns01_record_name("net.example.com.."),
            "_acme-challenge.net.example.com."
        );
    }

    #[test]
    fn the_domain_is_passed_through_as_written() {
        // DNS compares labels case-insensitively, so rewriting the case
        // would only make our records disagree with the zone's.
        assert_eq!(
            dns01_record_name("Net.Example.COM"),
            "_acme-challenge.Net.Example.COM"
        );
    }

    #[test]
    fn a_token_that_would_escape_the_challenge_path_is_refused() {
        // The reason this type exists: the token lands in a URL path.
        for bad in [
            "../../etc/passwd",
            "tok/en",
            "tok en",
            "tok\nen",
            "tok.en",
            "tok%2Fen",
            "tok+en",
            "tok=",
        ] {
            assert!(
                ChallengeToken::parse(bad).is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn a_token_keeps_the_whole_base64url_alphabet() {
        let all = "AZaz09-_";
        assert_eq!(ChallengeToken::parse(all).unwrap().as_str(), all);
    }

    #[test]
    fn token_length_boundaries() {
        assert_eq!(ChallengeToken::parse(""), Err(AcmeError::EmptyToken));
        let longest = "a".repeat(MAX_TOKEN_LEN);
        assert!(ChallengeToken::parse(&longest).is_ok());
        let over = "a".repeat(MAX_TOKEN_LEN + 1);
        assert_eq!(
            ChallengeToken::parse(&over),
            Err(AcmeError::TokenTooLong(MAX_TOKEN_LEN + 1))
        );
    }

    #[test]
    fn no_minimum_token_length_is_imposed() {
        // Entropy is the CA's promise (RFC 8555 §8.3), and a floor here
        // would reject a directory that encodes tokens differently.
        assert!(ChallengeToken::parse("a").is_ok());
    }

    #[test]
    fn a_thumbprint_is_exactly_one_sha256_digest() {
        assert_eq!(THUMB.chars().count(), THUMBPRINT_LEN);
        assert_eq!(
            Thumbprint::parse(&THUMB[..THUMBPRINT_LEN - 1]),
            Err(AcmeError::ThumbprintLength(THUMBPRINT_LEN - 1))
        );
        let padded = format!("{THUMB}=");
        assert_eq!(
            Thumbprint::parse(&padded),
            Err(AcmeError::ThumbprintLength(THUMBPRINT_LEN + 1))
        );
        assert_eq!(Thumbprint::parse(""), Err(AcmeError::ThumbprintLength(0)));
    }

    #[test]
    fn a_thumbprint_with_a_stray_newline_is_refused() {
        // The failure this prevents is silent: the body would still
        // look right in a terminal and still be the wrong string.
        let mut broken: String = THUMB.to_string();
        broken.pop();
        broken.push('\n');
        assert_eq!(
            Thumbprint::parse(&broken),
            Err(AcmeError::ThumbprintCharacter('\n'))
        );
    }

    #[test]
    fn errors_say_which_string_and_what_is_wrong() {
        assert_eq!(
            AcmeError::TokenCharacter('/').to_string(),
            "the challenge token contains '/', which is not base64url"
        );
        assert_eq!(
            AcmeError::EmptyToken.to_string(),
            "the challenge token is empty"
        );
        assert!(AcmeError::ThumbprintLength(10)
            .to_string()
            .contains("account key thumbprint"));
        assert!(AcmeError::TokenTooLong(300).to_string().contains("300"));
    }
}
