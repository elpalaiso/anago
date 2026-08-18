//! IP allocation inside the anago subnet (default 10.100.0.0/24).
//! Server is always .1; devices get the lowest free host address.
//! Pure functions — the server's state file owns the used set.

/// Lowest free host address in a /24, skipping .0 (network), .1
/// (server), and .255 (broadcast). `used` holds the last octet of
/// already-allocated devices.
pub fn next_free_octet(used: &[u8]) -> Option<u8> {
    (2..=254).find(|o| !used.contains(o))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_lowest_free_skipping_reserved() {
        assert_eq!(next_free_octet(&[]), Some(2));
        assert_eq!(next_free_octet(&[2, 3]), Some(4));
        assert_eq!(next_free_octet(&[2, 4]), Some(3)); // reuse gaps
        let full: Vec<u8> = (2..=254).collect();
        assert_eq!(next_free_octet(&full), None);
    }
}
