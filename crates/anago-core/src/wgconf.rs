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
//! There is a third file, and it is the device one wearing different
//! clothes: the profile `join --export` hands to a phone (§8). Same
//! fields, same order, no comments — [`export_profile`] explains why.
//!
//! Every function here returns [`SecretText`], because every file it
//! renders has a private key in it. The type redacts itself in both
//! `Debug` and `Display`, so the only way the bytes reach a log line is
//! through [`SecretText::expose`] — one call that greps (§7.3).
//!
//! Making packets actually cross between two devices also needs
//! `net.ipv4.ip_forward=1` on the server. That is a sysctl, not a
//! config line, so it belongs to the binary's setup path rather than
//! here.

use std::fmt;
use std::net::Ipv4Addr;

use crate::state::{PrivateKey, ServerState};
use crate::subnet::{Subnet, PREFIX_LEN};

/// Rendered text with a private key in it (§7.3).
///
/// [`PrivateKey`] stops a stray `{:?}` on the *structs* that hold a key.
/// It stops nothing once those are rendered: a config is a plain
/// `String` with the key inside, and putting one in an error or a debug
/// line spills it. This type carries that protection across the render.
///
/// Both `Debug` and `Display` redact, so the bytes leave through
/// [`SecretText::expose`] and nowhere else — file, terminal, QR
/// encoder, and those three should be the whole list.
///
/// It cannot make a mistake impossible: an error type that puts
/// `expose()` in its message still leaks. It makes the mistake visible
/// at the call site, which is the most a type can do here.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretText(String);

impl SecretText {
    /// The bytes. Deliberately the only way out.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText(redacted)")
    }
}

impl fmt::Display for SecretText {
    /// Redacts too. A `Display` that printed the config would be the
    /// hole this type exists to close.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText(redacted)")
    }
}

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
pub fn server_config(state: &ServerState) -> SecretText {
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
    SecretText(out)
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

/// The device's `/etc/wireguard/anago.conf` — the file anago writes and
/// rewrites.
///
/// One `[Peer]`: the hub. `AllowedIPs` is the whole subnet, so packets
/// for any device go up the tunnel and the server routes them — which
/// is why a new device joining needs no change here at all (§6.3).
pub fn client_config(profile: &ClientProfile) -> SecretText {
    SecretText(render_client(profile, true))
}

/// The same profile for the official WireGuard app, as
/// `join --export qr|conf` hands it over (§8).
///
/// **Identical fields in identical order** — it is the same wg-quick
/// format, and a phone needs exactly what a laptop needs: an address, a
/// key, the hub, the whole subnet, and the keepalive that holds a NAT
/// mapping open from a phone network (§6.3).
///
/// What it drops is the comments, for three reasons that all point the
/// same way:
///
/// - "generated file, edits are overwritten" would be a lie. anago
///   never sees this file again; the phone owns it the moment it is
///   scanned.
/// - The official app does not show comments, so they cost the reader
///   nothing and gain them nothing.
/// - It also goes out as a QR (§8), and every byte dropped is a
///   sparser, easier-to-scan code.
///
/// The private key inside is this device's doing, not the phone's —
/// the one deliberate exception to "the private key never leaves the
/// machine", with its own security rules in §7.3.
pub fn export_profile(profile: &ClientProfile) -> SecretText {
    SecretText(render_client(profile, false))
}

/// Finds this device's private key in its own config.
///
/// The one copy of that key is in this file (§9.2) — `device.json`
/// never holds it — so a `sync` that has to rewrite the config starts
/// here. `None` when there is no `PrivateKey` line, and then §6.3's
/// rule applies: do not repair, tell the person to join again, because
/// there is nothing to build a config out of.
///
/// Deliberately forgiving about layout: a person may have reindented
/// the file or changed its line endings, and neither is a reason to
/// refuse. It returns the text rather than a validated key because the
/// shape of a WireGuard key is checked in one place, beside the tools
/// that print them.
pub fn private_key_line(config: &str) -> Option<&str> {
    config.lines().find_map(|line| {
        let (name, value) = line.trim().split_once('=')?;
        // `[Peer]` carries no `PrivateKey`, so there is no section to
        // track: the first one in the file is the interface's.
        name.trim()
            .eq_ignore_ascii_case("privatekey")
            .then(|| value.trim())
    })
}

/// The one renderer behind both. The files differ by their comments and
/// by nothing else, and keeping that true is the point of sharing it:
/// a phone that works and a laptop that does not would be a bug nobody
/// would think to look for here.
fn render_client(profile: &ClientProfile, comments: bool) -> String {
    let mut out = String::new();
    out.push_str("[Interface]\n");
    if comments {
        out.push_str("# anago — generated file, edits are overwritten\n");
    }
    out.push_str(&format!("Address = {}/{PREFIX_LEN}\n", profile.address));
    out.push_str(&format!("PrivateKey = {}\n", profile.private_key.as_str()));

    out.push_str("\n[Peer]\n");
    if comments {
        out.push_str("# anago server\n");
    }
    out.push_str(&format!("PublicKey = {}\n", profile.server_public_key));
    out.push_str(&format!("Endpoint = {}\n", profile.server_endpoint));
    out.push_str(&format!("AllowedIPs = {}\n", profile.subnet));
    out.push_str(&format!(
        "PersistentKeepalive = {PERSISTENT_KEEPALIVE_SECS}\n"
    ));
    out
}

/// Drops the keys only wg-quick understands, leaving what `wg
/// setconf`/`syncconf` accepts.
///
/// wg-quick ships a `strip` for this; Windows has no wg-quick (§11.1
/// 결정 2 — the official client's tunnel service replaces it), so the
/// stripping anago relies on is a pure function wherever it runs.
/// Section headers and every plain wg key pass through untouched.
pub fn strip_quick_keys(conf: &str) -> String {
    const QUICK_KEYS: [&str; 9] = [
        "Address", "DNS", "MTU", "Table", "PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig",
    ];
    let mut out = String::new();
    for line in conf.lines() {
        let key = line.split('=').next().unwrap_or("").trim();
        if QUICK_KEYS.iter().any(|quick| key.eq_ignore_ascii_case(quick)) {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::DeviceName;
    use crate::state::{Peer, PrivateKey, ServerKeys, ServerState, Tls};
    use crate::subnet::Subnet;
    use crate::token::TokenHash;

    const NOW: i64 = 1_755_500_000;

    // The renderers return `SecretText`; these unwrap once so the
    // assertions below read as the text they are checking.
    fn server_config(state: &ServerState) -> String {
        super::server_config(state).expose().to_string()
    }

    fn client_config(profile: &ClientProfile) -> String {
        super::client_config(profile).expose().to_string()
    }

    fn export_profile(profile: &ClientProfile) -> String {
        super::export_profile(profile).expose().to_string()
    }

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
            tls: Tls::manual("/etc/ssl/anago/fullchain.pem", "/etc/ssl/anago/privkey.pem"),
            cloudflare: None,
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
    fn the_private_key_is_found_wherever_a_person_left_it() {
        // The one copy of a device's key is in this file (§9.2), so a
        // `sync` that has to rewrite the config starts by reading it
        // back. A file somebody reindented or saved with CRLF is not a
        // reason to refuse.
        let key = "dGhpcyBkZXZpY2UncyBwcml2YXRlIGtleSA0NCBjaGE=";
        let profile = ClientProfile {
            address: "10.100.0.2".parse().unwrap(),
            subnet: Subnet::parse("10.100.0.0/24").unwrap(),
            private_key: PrivateKey::new(key),
            server_public_key: "c2VydmVyIGtleQ==".to_string(),
            server_endpoint: "net.example.com:51820".to_string(),
        };
        assert_eq!(private_key_line(&client_config(&profile)), Some(key));

        for text in [
            format!("[Interface]\nPrivateKey={key}\n"),
            format!("[Interface]\n   PrivateKey   =   {key}   \n"),
            format!("[Interface]\r\nprivatekey = {key}\r\n"),
            format!("[Interface]\nPRIVATEKEY = {key}\n[Peer]\n"),
        ] {
            assert_eq!(private_key_line(&text), Some(key), "{text:?}");
        }

        // Nothing to find is `None`, and §6.3 turns that into "join
        // again" rather than into a repair anago cannot make.
        assert_eq!(private_key_line(""), None);
        assert_eq!(
            private_key_line("[Interface]\nAddress = 10.100.0.2/24\n"),
            None
        );
        assert_eq!(
            private_key_line("[Peer]\nPublicKey = c2VydmVyIGtleQ==\n"),
            None,
            "a public key is not a private one"
        );
        // A commented-out line is not a setting. wg-quick reads `#`
        // as a comment, and so does this.
        assert_eq!(private_key_line(&format!("# PrivateKey = {key}\n")), None);
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
    fn an_exported_profile_is_the_same_file_without_the_comments() {
        // What a phone's official app reads (§8). Comments are the only
        // difference, and this snapshot is what says so.
        let expected = "\
[Interface]
Address = 10.100.0.2/24
PrivateKey = ZGV2aWNlIHByaXZhdGU=

[Peer]
PublicKey = c2VydmVyIHB1YmxpYw==
Endpoint = net.example.com:51820
AllowedIPs = 10.100.0.0/24
PersistentKeepalive = 25
";
        assert_eq!(export_profile(&profile()), expected);
    }

    #[test]
    fn the_two_client_files_differ_only_in_comments() {
        // The property the shared renderer exists to hold. A phone that
        // works and a laptop that does not — or the reverse — would be a
        // bug nobody would look for in here.
        let exported = export_profile(&profile());
        let local: String = client_config(&profile())
            .lines()
            .filter(|line| !line.starts_with('#'))
            .map(|line| format!("{line}\n"))
            .collect();
        assert_eq!(exported, local);
        assert!(!exported.contains('#'), "{exported}");
    }

    #[test]
    fn an_exported_profile_carries_the_key_the_phone_needs() {
        // It is a standalone file: without the private key the phone
        // has nothing to bring a tunnel up with. §7.3 covers what that
        // costs and how the output warns about it.
        let text = export_profile(&profile());
        assert!(text.contains("PrivateKey = ZGV2aWNlIHByaXZhdGU="), "{text}");
        assert!(text.contains("PersistentKeepalive = 25"), "{text}");
        assert!(text.contains("AllowedIPs = 10.100.0.0/24"), "{text}");
    }

    #[test]
    fn an_exported_profile_still_routes_the_whole_subnet_and_no_more() {
        // Not `0.0.0.0/0`: anago is a private network between devices,
        // not a full VPN (§3). A phone importing this keeps using its
        // own connection for everything else.
        let text = export_profile(&profile());
        assert!(!text.contains("0.0.0.0/0"), "{text}");
        let allowed: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("AllowedIPs"))
            .collect();
        assert_eq!(allowed, ["AllowedIPs = 10.100.0.0/24"]);
    }

    #[test]
    fn rendered_configs_redact_themselves() {
        // §7.3: the key survives the render, so the type has to as well.
        let secret = super::client_config(&profile());
        assert_eq!(format!("{secret:?}"), "SecretText(redacted)");
        assert_eq!(format!("{secret}"), "SecretText(redacted)");
        assert!(!format!("{secret:?}{secret}").contains("ZGV2aWNl"));
        // And the server's own key gets the same treatment.
        let secret = super::server_config(&state(Vec::new()));
        assert_eq!(format!("{secret}"), "SecretText(redacted)");
        assert!(secret.expose().contains("c2VydmVyIHByaXZhdGU="));
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

#[cfg(test)]
mod strip_tests {
    use super::strip_quick_keys;

    #[test]
    fn stripping_leaves_only_what_wg_understands() {
        let conf = "[Interface]\nAddress = 10.100.0.1/24\nPrivateKey = abc\nListenPort = 51820\nDNS = 1.1.1.1\nMTU = 1420\nPostUp = echo hi\nSaveConfig = true\n\n[Peer]\nPublicKey = xyz\nAllowedIPs = 10.100.0.2/32\nPersistentKeepalive = 25\n";
        let stripped = strip_quick_keys(conf);
        assert!(!stripped.contains("Address"), "{stripped}");
        assert!(!stripped.contains("DNS"), "{stripped}");
        assert!(!stripped.contains("MTU"), "{stripped}");
        assert!(!stripped.contains("PostUp"), "{stripped}");
        assert!(!stripped.contains("SaveConfig"), "{stripped}");
        // Everything wg itself reads survives, sections included.
        for kept in ["[Interface]", "PrivateKey = abc", "ListenPort = 51820", "[Peer]", "PublicKey = xyz", "AllowedIPs = 10.100.0.2/32", "PersistentKeepalive = 25"] {
            assert!(stripped.contains(kept), "{kept} missing:\n{stripped}");
        }
        // A key that merely *starts* like a quick key is not one.
        assert!(strip_quick_keys("AddressBook = x\n").contains("AddressBook"));
    }
}
