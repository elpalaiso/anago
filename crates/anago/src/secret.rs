//! Secrets the server mints: device tokens and their hashes
//! (DESIGN.md §7.1).
//!
//! Randomness comes from `/dev/urandom` — no crate, no fallback. If the
//! kernel cannot give us 32 bytes, the join fails rather than
//! proceeding with something weaker.
//!
//! Hashing is `sha2`, and it hashes the token's *text* — the same 64
//! hex characters the device sends back in the `Authorization` header,
//! so verification is one hash of the header value with nothing to get
//! wrong about encoding.

use std::fs::File;
use std::io::{self, Read};

use anago_core::token::{DeviceToken, TokenHash, TOKEN_BYTES};
use sha2::{Digest, Sha256};

/// Reads `N` bytes from the kernel's CSPRNG.
pub fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// A fresh device token: 256 bits of randomness in the hex form §7.1
/// fixes.
pub fn new_token() -> io::Result<DeviceToken> {
    Ok(DeviceToken::from_bytes(&random_bytes::<TOKEN_BYTES>()?))
}

/// The value the state file stores for a token. The token itself is
/// never written anywhere on the server.
pub fn hash_token(token: &DeviceToken) -> TokenHash {
    let digest = Sha256::digest(token.as_str().as_bytes());
    let bytes: [u8; TOKEN_BYTES] = digest.into();
    TokenHash::from_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_well_formed_and_do_not_repeat() {
        let first = new_token().expect("/dev/urandom");
        let second = new_token().expect("/dev/urandom");
        assert_eq!(first.as_str().len(), 64);
        assert!(DeviceToken::parse(first.as_str()).is_ok());
        assert_ne!(first, second, "two tokens must not collide");
    }

    #[test]
    fn random_bytes_fills_the_whole_buffer() {
        let bytes = random_bytes::<32>().expect("/dev/urandom");
        assert_eq!(bytes.len(), 32);
        // 32 zero bytes from a CSPRNG would be a once-in-2^256 event,
        // so this catches a read that silently did nothing.
        assert_ne!(bytes, [0u8; 32]);
    }

    #[test]
    fn hashing_matches_sha256_of_the_token_text() {
        // Pinned against `printf %s <token> | shasum -a 256`: the hash
        // covers the ASCII the device sends, not the bytes behind it.
        let token = DeviceToken::parse(&"0123456789abcdef".repeat(4)).unwrap();
        assert_eq!(
            hash_token(&token).as_str(),
            "a8ae6e6ee929abea3afcfc5258c8ccd6f85273e0d4626d26c7279f3250f77c8e"
        );
    }

    #[test]
    fn hashing_is_stable_and_distinguishes_tokens() {
        let token = new_token().unwrap();
        assert_eq!(hash_token(&token), hash_token(&token));
        assert_ne!(hash_token(&token), hash_token(&new_token().unwrap()));
        // And the hash never contains the token.
        assert_ne!(hash_token(&token).as_str(), token.as_str());
    }
}
