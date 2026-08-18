//! The anago subnet (default `10.100.0.0/24`) and address allocation
//! inside it. Server is always `.1`; devices get the lowest free host
//! address (DESIGN.md §5).
//!
//! M0 accepts `/24` only (§9.1). One prefix length keeps allocation a
//! single-octet problem and the wg config a single `AllowedIPs` line;
//! widening it later means changing the state schema, so the doc moves
//! first.
//!
//! Pure functions — the server's state file owns the set of addresses
//! already handed out.

use std::fmt;
use std::net::Ipv4Addr;

/// The only prefix length M0 supports.
pub const PREFIX_LEN: u8 = 24;

/// A `/24` network, identified by its network address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subnet {
    network: Ipv4Addr,
}

impl Subnet {
    /// Parses `10.100.0.0/24`. The address must be the network address
    /// itself — `10.100.0.5/24` is rejected rather than quietly masked
    /// to `10.100.0.0`, because a subnet typo is worth a message, not a
    /// silent correction.
    pub fn parse(text: &str) -> Result<Subnet, SubnetError> {
        let (address, prefix) = text.split_once('/').ok_or(SubnetError::MissingPrefix)?;
        let network: Ipv4Addr = address.parse().map_err(|_| SubnetError::BadAddress)?;

        // `"024".parse::<u8>()` would succeed; a canonical form keeps
        // the state file and the CLI in agreement.
        if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
            return Err(SubnetError::BadPrefix);
        }
        if prefix.len() > 1 && prefix.starts_with('0') {
            return Err(SubnetError::BadPrefix);
        }
        let prefix: u8 = prefix.parse().map_err(|_| SubnetError::BadPrefix)?;
        if prefix > 32 {
            return Err(SubnetError::BadPrefix);
        }
        if prefix != PREFIX_LEN {
            return Err(SubnetError::UnsupportedPrefix(prefix));
        }
        if network.octets()[3] != 0 {
            return Err(SubnetError::NotNetworkAddress(network));
        }
        Ok(Subnet { network })
    }

    /// The network address, e.g. `10.100.0.0`.
    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    /// The server's own address — always `.1` (§5).
    pub fn server_address(&self) -> Ipv4Addr {
        self.address_of(1)
    }

    /// Whether `addr` sits in this network. Includes the reserved
    /// `.0`/`.1`/`.255`, which are part of the network without being
    /// assignable to a device.
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        addr.octets()[..3] == self.network.octets()[..3]
    }

    /// The host octet of `addr`, or `None` if it belongs to another
    /// network.
    pub fn host_octet(&self, addr: Ipv4Addr) -> Option<u8> {
        self.contains(addr).then(|| addr.octets()[3])
    }

    /// The lowest free device address, or `None` when the subnet is
    /// full. Addresses in `used` that belong to another network are
    /// ignored — they cannot collide with anything handed out here.
    pub fn allocate(&self, used: &[Ipv4Addr]) -> Option<Ipv4Addr> {
        let used: Vec<u8> = used
            .iter()
            .filter_map(|addr| self.host_octet(*addr))
            .collect();
        next_free_octet(&used).map(|octet| self.address_of(octet))
    }

    fn address_of(&self, octet: u8) -> Ipv4Addr {
        let [a, b, c, _] = self.network.octets();
        Ipv4Addr::new(a, b, c, octet)
    }
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, PREFIX_LEN)
    }
}

/// Why a subnet string was refused. Each variant maps to one sentence
/// the user can act on — `server init --subnet` is where these surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubnetError {
    /// No `/` at all, e.g. `10.100.0.0`.
    MissingPrefix,
    /// The part before `/` is not an IPv4 address.
    BadAddress,
    /// The part after `/` is not a plain number in `0..=32`.
    BadPrefix,
    /// A valid prefix length, but not one M0 handles.
    UnsupportedPrefix(u8),
    /// Host bits are set, e.g. `10.100.0.5/24`.
    NotNetworkAddress(Ipv4Addr),
}

impl fmt::Display for SubnetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubnetError::MissingPrefix => {
                write!(
                    f,
                    "subnet needs a prefix length, e.g. 10.100.0.0/{PREFIX_LEN}"
                )
            }
            SubnetError::BadAddress => write!(f, "subnet does not start with an IPv4 address"),
            SubnetError::BadPrefix => write!(f, "prefix length must be a number in 0..=32"),
            SubnetError::UnsupportedPrefix(prefix) => {
                write!(f, "anago supports /{PREFIX_LEN} only, got /{prefix}")
            }
            SubnetError::NotNetworkAddress(addr) => {
                let [a, b, c, _] = addr.octets();
                write!(
                    f,
                    "{addr}/{PREFIX_LEN} is not a network address; use {a}.{b}.{c}.0/{PREFIX_LEN}"
                )
            }
        }
    }
}

impl std::error::Error for SubnetError {}

/// Lowest free host address in a /24, skipping .0 (network), .1
/// (server), and .255 (broadcast). `used` holds the last octet of
/// already-allocated devices.
pub fn next_free_octet(used: &[u8]) -> Option<u8> {
    (2..=254).find(|o| !used.contains(o))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subnet(text: &str) -> Subnet {
        Subnet::parse(text).expect("valid subnet")
    }

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().expect("valid address")
    }

    #[test]
    fn allocates_lowest_free_skipping_reserved() {
        assert_eq!(next_free_octet(&[]), Some(2));
        assert_eq!(next_free_octet(&[2, 3]), Some(4));
        assert_eq!(next_free_octet(&[2, 4]), Some(3)); // reuse gaps
        let full: Vec<u8> = (2..=254).collect();
        assert_eq!(next_free_octet(&full), None);
    }

    #[test]
    fn parses_a_slash_24_and_keeps_its_text_form() {
        let net = subnet("10.100.0.0/24");
        assert_eq!(net.network(), ip("10.100.0.0"));
        assert_eq!(net.to_string(), "10.100.0.0/24");
        assert_eq!(Subnet::parse(&net.to_string()), Ok(net));

        // Not just the default network.
        assert_eq!(subnet("192.168.7.0/24").network(), ip("192.168.7.0"));
        assert_eq!(subnet("172.16.30.0/24").to_string(), "172.16.30.0/24");
    }

    #[test]
    fn server_is_always_dot_one() {
        assert_eq!(subnet("10.100.0.0/24").server_address(), ip("10.100.0.1"));
        assert_eq!(subnet("192.168.7.0/24").server_address(), ip("192.168.7.1"));
    }

    #[test]
    fn rejects_a_missing_or_malformed_prefix() {
        assert_eq!(Subnet::parse("10.100.0.0"), Err(SubnetError::MissingPrefix));
        assert_eq!(Subnet::parse("10.100.0.0/"), Err(SubnetError::BadPrefix));
        assert_eq!(Subnet::parse("10.100.0.0/abc"), Err(SubnetError::BadPrefix));
        assert_eq!(Subnet::parse("10.100.0.0/24 "), Err(SubnetError::BadPrefix));
        assert_eq!(Subnet::parse("10.100.0.0/33"), Err(SubnetError::BadPrefix));
        assert_eq!(Subnet::parse("10.100.0.0/999"), Err(SubnetError::BadPrefix));
        assert_eq!(Subnet::parse("10.100.0.0/-1"), Err(SubnetError::BadPrefix));
        // Canonical spelling only: /024 is not /24.
        assert_eq!(Subnet::parse("10.100.0.0/024"), Err(SubnetError::BadPrefix));
    }

    #[test]
    fn rejects_prefix_lengths_m0_does_not_handle() {
        assert_eq!(
            Subnet::parse("10.100.0.0/16"),
            Err(SubnetError::UnsupportedPrefix(16))
        );
        assert_eq!(
            Subnet::parse("10.100.0.0/25"),
            Err(SubnetError::UnsupportedPrefix(25))
        );
        assert_eq!(
            Subnet::parse("10.100.0.0/32"),
            Err(SubnetError::UnsupportedPrefix(32))
        );
        assert_eq!(
            Subnet::parse("10.100.0.0/0"),
            Err(SubnetError::UnsupportedPrefix(0))
        );
    }

    #[test]
    fn rejects_a_bad_address() {
        assert_eq!(Subnet::parse("10.100.0/24"), Err(SubnetError::BadAddress));
        assert_eq!(
            Subnet::parse("10.100.0.256/24"),
            Err(SubnetError::BadAddress)
        );
        assert_eq!(Subnet::parse("not an ip/24"), Err(SubnetError::BadAddress));
        assert_eq!(
            Subnet::parse(" 10.100.0.0/24"),
            Err(SubnetError::BadAddress)
        );
        assert_eq!(Subnet::parse("fd00::/24"), Err(SubnetError::BadAddress));
        assert_eq!(Subnet::parse("/24"), Err(SubnetError::BadAddress));
        assert_eq!(Subnet::parse(""), Err(SubnetError::MissingPrefix));
    }

    #[test]
    fn rejects_host_bits_instead_of_masking_them() {
        // A typo'd subnet must be reported, not silently corrected.
        assert_eq!(
            Subnet::parse("10.100.0.5/24"),
            Err(SubnetError::NotNetworkAddress(ip("10.100.0.5")))
        );
        assert_eq!(
            Subnet::parse("10.100.0.1/24"),
            Err(SubnetError::NotNetworkAddress(ip("10.100.0.1")))
        );
    }

    #[test]
    fn errors_say_what_to_do() {
        assert_eq!(
            SubnetError::MissingPrefix.to_string(),
            "subnet needs a prefix length, e.g. 10.100.0.0/24"
        );
        assert_eq!(
            SubnetError::UnsupportedPrefix(16).to_string(),
            "anago supports /24 only, got /16"
        );
        assert_eq!(
            SubnetError::NotNetworkAddress(ip("10.100.0.5")).to_string(),
            "10.100.0.5/24 is not a network address; use 10.100.0.0/24"
        );
    }

    #[test]
    fn membership_covers_reserved_addresses_too() {
        let net = subnet("10.100.0.0/24");
        for addr in ["10.100.0.0", "10.100.0.1", "10.100.0.42", "10.100.0.255"] {
            assert!(net.contains(ip(addr)), "{addr} should be in {net}");
        }
        assert!(!net.contains(ip("10.100.1.2")));
        assert!(!net.contains(ip("192.168.7.2")));
        assert_eq!(net.host_octet(ip("10.100.0.42")), Some(42));
        assert_eq!(net.host_octet(ip("10.100.1.42")), None);
    }

    #[test]
    fn allocation_starts_at_two_and_reuses_gaps() {
        let net = subnet("10.100.0.0/24");
        assert_eq!(net.allocate(&[]), Some(ip("10.100.0.2")));
        assert_eq!(net.allocate(&[ip("10.100.0.2")]), Some(ip("10.100.0.3")));
        assert_eq!(
            net.allocate(&[ip("10.100.0.2"), ip("10.100.0.4")]),
            Some(ip("10.100.0.3"))
        );
    }

    #[test]
    fn allocation_never_returns_a_reserved_address() {
        // Drain the subnet: every address handed out is a host address,
        // and .0/.1/.255 never appear.
        let net = subnet("192.168.7.0/24");
        let mut used = Vec::new();
        while let Some(addr) = net.allocate(&used) {
            let octet = net.host_octet(addr).expect("allocated outside the subnet");
            assert!((2..=254).contains(&octet), "handed out reserved {addr}");
            used.push(addr);
        }
        assert_eq!(used.len(), 253);
        assert_eq!(used.first(), Some(&ip("192.168.7.2")));
        assert_eq!(used.last(), Some(&ip("192.168.7.254")));
        assert!(!used.contains(&net.server_address()));
    }

    #[test]
    fn a_full_subnet_allocates_nothing() {
        let net = subnet("10.100.0.0/24");
        let used: Vec<Ipv4Addr> = (2..=254).map(|o| ip(&format!("10.100.0.{o}"))).collect();
        assert_eq!(net.allocate(&used), None);
    }

    #[test]
    fn addresses_from_other_networks_do_not_block_allocation() {
        // A stale entry from a re-`init`ed server with a different
        // subnet must not eat an address here.
        let net = subnet("10.100.0.0/24");
        let used = [ip("192.168.7.2"), ip("10.100.1.3")];
        assert_eq!(net.allocate(&used), Some(ip("10.100.0.2")));
    }
}
