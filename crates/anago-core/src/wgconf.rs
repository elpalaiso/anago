//! WireGuard configuration generation.
//!
//! Text in, text out — anago writes the file and lets `wg`/`wg-quick`
//! do the rest (DESIGN.md §4 principle 1). This module is the only
//! place that knows what those files look like, so a snapshot test is
//! enough to see any change to them.
//!
//! Both files are wg-quick flavoured (`/etc/wireguard/anago.conf`):
//! they carry `Address`, which plain `wg` does not understand. The
//! server applies changes with `wg syncconf <iface> <(wg-quick strip
//! anago)`, which drops those keys for it.
//!
//! The two sides are deliberately asymmetric. The hub lists every
//! device with a `/32`; a device lists only the hub, with the whole
//! subnet — that single `AllowedIPs` line is what makes hub-and-spoke
//! work without the device knowing any other device exists (§5).
//!
//! Making packets actually cross between two devices also needs
//! `net.ipv4.ip_forward=1` on the server. That is a sysctl, not a
//! config line, so it belongs to the binary's setup path rather than
//! here.

use std::net::Ipv4Addr;

use crate::state::{PrivateKey, ServerState};
use crate::subnet::{Subnet, PREFIX_LEN};

/// Seconds between keepalives on the device side (§6.3). One config
/// line is the whole of anago's NAT story: it keeps the mapping open
/// from behind CGNAT, and it is why a device needs no daemon.
pub const PERSISTENT_KEEPALIVE_SECS: u32 = 25;

/// The server's `anago.conf`.
///
/// Each device gets its own `[Peer]` with `AllowedIPs = <addr>/32`.
/// A `/24` would be wrong here, not merely loose: WireGuard routes by
/// longest match over disjoint `AllowedIPs`, so two peers claiming the
/// same `/24` on the hub would make the second unreachable.
///
/// Peers appear in state order — the order they joined — so the file
/// only changes when the network does.
pub fn server_config(state: &ServerState) -> String {
    let mut out = String::new();
    out.push_str("[Interface]\n");
    out.push_str("# anago server — generated file, edits are overwritten\n");
    out.push_str(&format!(
        "Address = {}/{PREFIX_LEN}\n",
        state.server.address
    ));
    out.push_str(&format!("ListenPort = {}\n", state.listen_port));
    out.push_str(&format!(
        "PrivateKey = {}\n",
        state.server.private_key.as_str()
    ));

    for peer in &state.peers {
        out.push_str("\n[Peer]\n");
        out.push_str(&format!("# {}\n", peer.name));
        out.push_str(&format!("PublicKey = {}\n", peer.public_key));
        out.push_str(&format!("AllowedIPs = {}/32\n", peer.address));
    }
    out
}

/// What a device knows about the network after `join` — everything the
/// client config needs, and nothing about other devices.
///
/// `private_key` is generated on the device and never leaves it (§6.2);
/// it is [`PrivateKey`], so a stray `{:?}` prints `PrivateKey(redacted)`
/// rather than the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientProfile {
    /// This device's address inside the subnet.
    pub address: Ipv4Addr,
    pub subnet: Subnet,
    pub private_key: PrivateKey,
    pub server_public_key: String,
    /// `host:port` the device dials, e.g. `net.example.com:51820`.
    pub server_endpoint: String,
}

/// The device's `anago.conf`.
///
/// One `[Peer]`: the hub. `AllowedIPs` is the whole subnet, so packets
/// for any device go up the tunnel and the server routes them — which
/// is why a new device joining needs no change here at all (§6.3).
pub fn client_config(profile: &ClientProfile) -> String {
    let mut out = String::new();
    out.push_str("[Interface]\n");
    out.push_str("# anago — generated file, edits are overwritten\n");
    out.push_str(&format!("Address = {}/{PREFIX_LEN}\n", profile.address));
    out.push_str(&format!("PrivateKey = {}\n", profile.private_key.as_str()));

    out.push_str("\n[Peer]\n");
    out.push_str("# anago server\n");
    out.push_str(&format!("PublicKey = {}\n", profile.server_public_key));
    out.push_str(&format!("Endpoint = {}\n", profile.server_endpoint));
    out.push_str(&format!("AllowedIPs = {}\n", profile.subnet));
    out.push_str(&format!(
        "PersistentKeepalive = {PERSISTENT_KEEPALIVE_SECS}\n"
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::DeviceName;
    use crate::state::{Peer, PrivateKey, ServerKeys, ServerState};
    use crate::subnet::Subnet;
    use crate::token::TokenHash;

    const NOW: i64 = 1_755_500_000;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    fn peer(name: &str, key: &str, address: &str) -> Peer {
        Peer {
            name: DeviceName::parse(name).unwrap(),
            public_key: key.to_string(),
            address: ip(address),
            token_hash: TokenHash::parse(&"ab".repeat(32)).unwrap(),
            created_at: NOW,
            last_seen: None,
        }
    }

    fn state(peers: Vec<Peer>) -> ServerState {
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
                address: ip("10.100.0.1"),
            },
            peers,
            codes: Vec::new(),
        }
    }

    #[test]
    fn a_fresh_server_has_an_interface_and_no_peers() {
        let expected = "\
[Interface]
# anago server — generated file, edits are overwritten
Address = 10.100.0.1/24
ListenPort = 51820
PrivateKey = c2VydmVyIHByaXZhdGU=
";
        assert_eq!(server_config(&state(Vec::new())), expected);
    }

    #[test]
    fn each_device_gets_its_own_peer_block() {
        let config = server_config(&state(vec![
            peer("macbook", "bWFjYm9vaw==", "10.100.0.2"),
            peer("맥북", "ZGVza3RvcA==", "10.100.0.3"),
        ]));
        let expected = "\
[Interface]
# anago server — generated file, edits are overwritten
Address = 10.100.0.1/24
ListenPort = 51820
PrivateKey = c2VydmVyIHByaXZhdGU=

[Peer]
# macbook
PublicKey = bWFjYm9vaw==
AllowedIPs = 10.100.0.2/32

[Peer]
# 맥북
PublicKey = ZGVza3RvcA==
AllowedIPs = 10.100.0.3/32
";
        assert_eq!(config, expected);
    }

    #[test]
    fn allowed_ips_are_single_addresses() {
        // A /24 here would swallow the other peers' addresses and make
        // whichever peer came second unreachable.
        let config = server_config(&state(vec![
            peer("macbook", "bWFjYm9vaw==", "10.100.0.2"),
            peer("desktop", "ZGVza3RvcA==", "10.100.0.3"),
        ]));
        let allowed: Vec<&str> = config
            .lines()
            .filter(|line| line.starts_with("AllowedIPs"))
            .collect();
        assert_eq!(
            allowed,
            ["AllowedIPs = 10.100.0.2/32", "AllowedIPs = 10.100.0.3/32"]
        );
        assert!(!config.contains("AllowedIPs = 10.100.0.0/24"));
    }

    #[test]
    fn the_interface_follows_the_state_not_a_default() {
        let mut state = state(vec![peer("macbook", "bWFjYm9vaw==", "192.168.7.2")]);
        state.subnet = Subnet::parse("192.168.7.0/24").unwrap();
        state.server.address = ip("192.168.7.1");
        state.listen_port = 51999;

        let config = server_config(&state);
        assert!(config.contains("Address = 192.168.7.1/24\n"), "{config}");
        assert!(config.contains("ListenPort = 51999\n"), "{config}");
        assert!(config.contains("AllowedIPs = 192.168.7.2/32\n"), "{config}");
    }

    #[test]
    fn peers_keep_the_order_they_joined() {
        // The file changes only when the network does — a reshuffle
        // would make every regeneration look like a change.
        let peers = vec![
            peer("desktop", "ZGVza3RvcA==", "10.100.0.9"),
            peer("macbook", "bWFjYm9vaw==", "10.100.0.2"),
        ];
        let config = server_config(&state(peers.clone()));
        let names: Vec<&str> = config
            .lines()
            .filter(|line| line.starts_with("# ") && !line.contains("generated"))
            .collect();
        assert_eq!(names, ["# desktop", "# macbook"]);
        // Same state, same bytes.
        assert_eq!(config, server_config(&state(peers)));
    }

    #[test]
    fn the_file_is_shaped_the_way_wg_expects() {
        let config = server_config(&state(vec![peer("macbook", "bWFjYm9vaw==", "10.100.0.2")]));
        // One section header per section, blank line before each peer,
        // trailing newline at the end.
        assert!(config.starts_with("[Interface]\n"));
        assert!(config.ends_with("/32\n"));
        assert_eq!(config.matches("[Peer]").count(), 1);
        assert!(config.contains("\n\n[Peer]\n"));
        // Nothing wg would choke on: every non-blank line is a section
        // header, a comment, or `Key = value`.
        for line in config.lines().filter(|line| !line.is_empty()) {
            assert!(
                line.starts_with('[') || line.starts_with("# ") || line.contains(" = "),
                "unexpected line {line:?}"
            );
        }
    }

    // ------------------------------------------------------- client

    fn profile() -> ClientProfile {
        ClientProfile {
            address: ip("10.100.0.2"),
            subnet: Subnet::parse("10.100.0.0/24").unwrap(),
            private_key: PrivateKey::new("ZGV2aWNlIHByaXZhdGU="),
            server_public_key: "c2VydmVyIHB1YmxpYw==".to_string(),
            server_endpoint: "net.example.com:51820".to_string(),
        }
    }

    #[test]
    fn a_device_config_lists_only_the_hub() {
        let expected = "\
[Interface]
# anago — generated file, edits are overwritten
Address = 10.100.0.2/24
PrivateKey = ZGV2aWNlIHByaXZhdGU=

[Peer]
# anago server
PublicKey = c2VydmVyIHB1YmxpYw==
Endpoint = net.example.com:51820
AllowedIPs = 10.100.0.0/24
PersistentKeepalive = 25
";
        assert_eq!(client_config(&profile()), expected);
    }

    #[test]
    fn allowed_ips_is_the_whole_subnet_not_one_address() {
        // The line that makes hub-and-spoke work: traffic for any
        // device goes up the tunnel, so a new device joining needs no
        // change on this one (§6.3).
        let config = client_config(&profile());
        assert!(config.contains("AllowedIPs = 10.100.0.0/24\n"), "{config}");
        assert!(!config.contains("/32"), "{config}");
        assert_eq!(config.matches("[Peer]").count(), 1);
    }

    #[test]
    fn keepalive_is_set_so_the_device_needs_no_daemon() {
        assert_eq!(PERSISTENT_KEEPALIVE_SECS, 25);
        assert!(client_config(&profile()).contains("PersistentKeepalive = 25\n"));
    }

    #[test]
    fn the_config_follows_the_profile() {
        let other = ClientProfile {
            address: ip("192.168.7.9"),
            subnet: Subnet::parse("192.168.7.0/24").unwrap(),
            private_key: PrivateKey::new("b3RoZXIga2V5"),
            server_public_key: "b3RoZXIgc2VydmVy".to_string(),
            server_endpoint: "vpn.example.org:51999".to_string(),
        };
        let config = client_config(&other);
        assert!(config.contains("Address = 192.168.7.9/24\n"), "{config}");
        assert!(
            config.contains("Endpoint = vpn.example.org:51999\n"),
            "{config}"
        );
        assert!(config.contains("AllowedIPs = 192.168.7.0/24\n"), "{config}");
        assert!(config.contains("PrivateKey = b3RoZXIga2V5\n"), "{config}");
    }

    #[test]
    fn the_device_key_does_not_print_itself() {
        // The config file must carry the key; a debug line must not.
        let printed = format!("{:?}", profile());
        assert!(printed.contains("PrivateKey(redacted)"), "{printed}");
        assert!(!printed.contains("ZGV2aWNlIHByaXZhdGU="), "{printed}");
        assert!(client_config(&profile()).contains("ZGV2aWNlIHByaXZhdGU="));
    }

    #[test]
    fn the_two_sides_mirror_each_other() {
        // Server: one /32 per device. Device: one peer, whole subnet.
        let server = server_config(&state(vec![peer("macbook", "bWFjYm9vaw==", "10.100.0.2")]));
        let client = client_config(&profile());
        assert!(server.contains("AllowedIPs = 10.100.0.2/32\n"), "{server}");
        assert!(client.contains("AllowedIPs = 10.100.0.0/24\n"), "{client}");
        // Only the device side keeps the NAT mapping alive.
        assert!(!server.contains("PersistentKeepalive"));
        // Only the server side listens.
        assert!(server.contains("ListenPort = 51820\n"));
        assert!(!client.contains("ListenPort"));
    }

    #[test]
    fn the_device_file_is_shaped_the_way_wg_expects() {
        let config = client_config(&profile());
        assert!(config.starts_with("[Interface]\n"));
        assert!(config.ends_with("PersistentKeepalive = 25\n"));
        assert!(config.contains("\n\n[Peer]\n"));
        for line in config.lines().filter(|line| !line.is_empty()) {
            assert!(
                line.starts_with('[') || line.starts_with("# ") || line.contains(" = "),
                "unexpected line {line:?}"
            );
        }
    }
}
