//! The M0 lifecycle, end to end, in pure functions.
//!
//! `anago server init` → `anago code` → two devices join → the wg
//! configs both sides run → `anago rm` → the address comes back. The
//! binary does this with files, sockets, and `wg`; every *decision*
//! along the way is here, and this walks them in order.
//!
//! It is an integration test in the crate's own terms: it may only use
//! the public API, so anything the binary needs has to be reachable
//! from outside. Nothing here touches the filesystem, the network, or
//! the clock — the times are constants.

use std::net::Ipv4Addr;

use anago_core::code::{CodeStatus, IssuedCode, JoinCode, DEFAULT_TTL_SECS};
use anago_core::json;
use anago_core::name::DeviceName;
use anago_core::proto::{JoinResponse, PeerInfo, PeersResponse};
use anago_core::render::{self, LastHandshake, PeerRow};
use anago_core::state::{JoinRejection, PrivateKey, Registration, ServerKeys, ServerState, Tls};
use anago_core::subnet::Subnet;
use anago_core::token::{DeviceToken, TokenHash};
use anago_core::wgconf::{self, ClientProfile};

const NOW: i64 = 1_755_500_000;
const DOMAIN: &str = "net.example.com";

/// Keys are opaque to core — the binary gets them from `wg genkey` —
/// but the configs this test builds are meant to be ones `wg` would
/// accept, so the fixtures are real WireGuard-shaped keys: 32 bytes,
/// base64, 44 characters ending in `=`. [`keys_are_wireguard_shaped`]
/// holds them to that.
const SERVER_PUBLIC: &str = "z9+mKJJd2PowS08tr6+iTyyG7kk/u+zHRUJCEhPhpVg=";
const SERVER_PRIVATE: &str = "Xfy4pGor4ZUau4qmws4X5POG5FB+WwcjSxiLxHs3XMk=";
const MACBOOK_PUBLIC: &str = "/im+jPwrJqLD3ugcMCseND+B/OSibpNGVD52Yj5fsH4=";
const MACBOOK_PRIVATE: &str = "XgPx3NyTqlrrk7kghmNJ0Xsjk717fpOJ/r1CiPtWoic=";
const DESKTOP_PUBLIC: &str = "Lml+MfcXNX4gvlOSYQVXcK6+UgQLbnLjqrjBnEj0Jc4=";

/// What `anago server init` builds.
fn fresh_hub() -> ServerState {
    let subnet = Subnet::parse("10.100.0.0/24").expect("the default subnet");
    ServerState {
        domain: DOMAIN.to_string(),
        subnet,
        listen_port: 51820,
        api_port: 443,
        tls: Tls::manual("/etc/ssl/anago/fullchain.pem", "/etc/ssl/anago/privkey.pem"),
        cloudflare: None,
        server: ServerKeys {
            private_key: PrivateKey::new(SERVER_PRIVATE),
            public_key: SERVER_PUBLIC.to_string(),
            address: subnet.server_address(),
        },
        peers: Vec::new(),
        codes: Vec::new(),
    }
}

/// What `anago code` adds.
fn issue(state: &mut ServerState, code: &str, at: i64) -> JoinCode {
    let code = JoinCode::parse(code).expect("a well-formed code");
    state
        .codes
        .push(IssuedCode::issue(code.clone(), at, DEFAULT_TTL_SECS));
    code
}

/// What `POST /api/v1/join` decides.
fn join(
    state: &mut ServerState,
    code: &JoinCode,
    name: &str,
    public_key: &str,
    token: &DeviceToken,
    at: i64,
) -> Result<JoinResponse, JoinRejection> {
    // The binary hashes the token with sha2; core only ever sees the
    // hash, so the test stands in with a fixed one derived from the
    // token's own text.
    let token_hash = stand_in_hash(token);
    let peer = state.add_peer(
        Registration {
            code: code.clone(),
            name: DeviceName::parse(name).expect("a valid name"),
            public_key: public_key.to_string(),
            token_hash,
        },
        at,
    )?;
    Ok(JoinResponse {
        name: peer.name.to_string(),
        address: peer.address.to_string(),
        subnet: state.subnet.to_string(),
        token: token.as_str().to_string(),
        server_public_key: state.server.public_key.clone(),
        server_endpoint: format!("{}:{}", state.domain, state.listen_port),
        server_address: state.subnet.server_address().to_string(),
    })
}

/// A hash that is not SHA-256 but behaves like one for these purposes:
/// same token in, same 64 hex out, different tokens apart.
fn stand_in_hash(token: &DeviceToken) -> TokenHash {
    let mut bytes = [0u8; 32];
    for (i, byte) in token.as_str().bytes().enumerate() {
        bytes[i % 32] ^= byte.wrapping_add(i as u8);
    }
    TokenHash::from_bytes(&bytes)
}

/// A distinct code per index, built from alphabet positions the way
/// the binary builds one from random bytes.
fn nth_code(index: usize) -> JoinCode {
    let size = anago_core::code::ALPHABET.chars().count();
    let indices: Vec<usize> = (0..anago_core::code::CODE_LEN)
        .map(|position| (index / size.pow(position as u32)) % size)
        .collect();
    JoinCode::from_indices(&indices).expect("in range")
}

fn token(fill: &str) -> DeviceToken {
    DeviceToken::parse(&fill.repeat(32)).expect("a 64-character token")
}

fn ip(text: &str) -> Ipv4Addr {
    text.parse().expect("an address")
}

/// The fixtures have to be keys `wg` would take, or the configs this
/// test builds prove nothing about the configs anago writes.
#[test]
fn keys_are_wireguard_shaped() {
    for key in [
        SERVER_PUBLIC,
        SERVER_PRIVATE,
        MACBOOK_PUBLIC,
        MACBOOK_PRIVATE,
        DESKTOP_PUBLIC,
    ] {
        assert_eq!(key.len(), 44, "{key} is not a 32-byte base64 key");
        assert!(key.ends_with('='), "{key}");
        assert!(
            key[..43]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/'),
            "{key} is not base64"
        );
    }
}

#[test]
fn the_whole_m0_lifecycle_runs_on_pure_functions() {
    // --- `anago server init` --------------------------------------
    let mut hub = fresh_hub();
    assert_eq!(hub.server.address, ip("10.100.0.1"), "the hub is always .1");
    assert!(hub.peers.is_empty());
    // What init writes is what a later run reads.
    assert_eq!(
        ServerState::parse(&hub.to_json_string()).expect("the state file reads back"),
        hub
    );

    // --- `anago code` ---------------------------------------------
    let first_code = issue(&mut hub, "7QX4-M2KD", NOW);
    assert_eq!(hub.codes[0].status(NOW), CodeStatus::Usable);

    // --- first device joins ---------------------------------------
    let macbook_token = token("a1");
    let macbook = join(
        &mut hub,
        &first_code,
        "MacBook",
        MACBOOK_PUBLIC,
        &macbook_token,
        NOW + 30,
    )
    .expect("the first join");

    assert_eq!(macbook.name, "macbook", "the normalized name comes back");
    assert_eq!(macbook.address, "10.100.0.2");
    assert_eq!(macbook.server_endpoint, "net.example.com:51820");
    assert_eq!(hub.codes[0].used_at, Some(NOW + 30), "the code is spent");
    // And spending it is final.
    assert_eq!(
        join(
            &mut hub,
            &first_code,
            "desktop",
            DESKTOP_PUBLIC,
            &token("b2"),
            NOW + 40
        ),
        Err(JoinRejection::CodeNotUsable(CodeStatus::Used))
    );

    // --- second device joins --------------------------------------
    let second_code = issue(&mut hub, "HJKM-NPQR", NOW + 60);
    let desktop_token = token("b2");
    let desktop = join(
        &mut hub,
        &second_code,
        "데스크톱",
        DESKTOP_PUBLIC,
        &desktop_token,
        NOW + 70,
    )
    .expect("the second join");
    assert_eq!(desktop.address, "10.100.0.3", "addresses go in order");
    assert_eq!(hub.peers.len(), 2);

    // --- the configs both sides run -------------------------------
    let server_config = wgconf::server_config(&hub);
    let server_config = server_config.expose();
    assert!(
        server_config.contains("Address = 10.100.0.1/24"),
        "{server_config}"
    );
    assert!(
        server_config.contains("AllowedIPs = 10.100.0.2/32"),
        "{server_config}"
    );
    assert!(
        server_config.contains("AllowedIPs = 10.100.0.3/32"),
        "{server_config}"
    );
    assert!(
        !server_config.contains("PersistentKeepalive"),
        "the hub does not keepalive"
    );

    let macbook_profile = ClientProfile {
        address: ip(&macbook.address),
        subnet: Subnet::parse(&macbook.subnet).expect("the subnet the hub sent"),
        private_key: PrivateKey::new(MACBOOK_PRIVATE),
        server_public_key: macbook.server_public_key.clone(),
        server_endpoint: macbook.server_endpoint.clone(),
    };
    let rendered = wgconf::client_config(&macbook_profile);
    let macbook_config = rendered.expose();
    // The asymmetry that makes hub-and-spoke work: the device routes
    // the whole subnet through the hub and knows nothing of the other
    // device.
    assert!(
        macbook_config.contains("AllowedIPs = 10.100.0.0/24"),
        "{macbook_config}"
    );
    assert!(!macbook_config.contains("10.100.0.3"), "{macbook_config}");
    assert!(
        macbook_config.contains("PersistentKeepalive = 25"),
        "{macbook_config}"
    );

    // --- what `anago ls` shows ------------------------------------
    let table = render::peer_table(&rows(&hub), NOW + 100);
    assert!(table.contains("macbook"), "{table}");
    assert!(table.contains("데스크톱"), "{table}");
    assert!(table.contains("10.100.0.3"), "{table}");

    // --- the state survives a write and a read --------------------
    let text = hub.to_json_string();
    let reread = ServerState::parse(&text).expect("the state file reads back");
    assert_eq!(reread, hub);
    assert!(
        !text.contains(macbook_token.as_str()),
        "no token in the file"
    );

    // --- `anago rm macbook` ---------------------------------------
    let removed = hub
        .remove_peer(&DeviceName::parse("MacBook").expect("a valid name"))
        .expect("the device was registered");
    assert_eq!(removed.address, ip("10.100.0.2"));
    assert_eq!(hub.peers.len(), 1);

    let after_removal = wgconf::server_config(&hub);
    let after_removal = after_removal.expose();
    assert!(!after_removal.contains("10.100.0.2/32"), "{after_removal}");
    assert!(after_removal.contains("10.100.0.3/32"), "{after_removal}");

    // --- and the address comes back -------------------------------
    let third_code = issue(&mut hub, "PQRS-TVWX", NOW + 200);
    let phone = join(
        &mut hub,
        &third_code,
        "phone",
        MACBOOK_PUBLIC,
        &token("c3"),
        NOW + 210,
    )
    .expect("the third join");
    assert_eq!(phone.address, "10.100.0.2", "the freed address is reused");

    // Every code ever issued is still on file, spent or not (§9.1).
    assert_eq!(hub.codes.len(), 3);
    assert!(hub.codes.iter().all(|code| code.used_at.is_some()));
    assert_eq!(
        ServerState::parse(&hub.to_json_string()).expect("still readable"),
        hub
    );
}

/// The rows `anago ls` renders on the hub.
fn rows(state: &ServerState) -> Vec<PeerRow> {
    state
        .peers
        .iter()
        .map(|peer| PeerRow {
            name: peer.name.to_string(),
            address: peer.address,
            public_key: peer.public_key.clone(),
            last_handshake: LastHandshake::Unknown,
        })
        .collect()
}

#[test]
fn the_answers_the_hub_gives_survive_the_wire() {
    // The same walk, but through JSON: what the hub decides has to
    // arrive at the device unchanged.
    let mut hub = fresh_hub();
    let code = issue(&mut hub, "7QX4-M2KD", NOW);
    let response = join(
        &mut hub,
        &code,
        "macbook",
        MACBOOK_PUBLIC,
        &token("a1"),
        NOW + 10,
    )
    .expect("the join");

    let text = json::to_string(&response.to_json());
    assert_eq!(
        JoinResponse::from_json(&json::parse(&text).expect("valid JSON")).expect("decodes"),
        response
    );

    let listed = PeersResponse {
        peers: hub
            .peers
            .iter()
            .map(|peer| PeerInfo {
                name: peer.name.to_string(),
                public_key: peer.public_key.clone(),
                address: peer.address.to_string(),
            })
            .collect(),
    };
    let text = json::to_string(&listed.to_json());
    assert_eq!(
        PeersResponse::from_json(&json::parse(&text).expect("valid JSON")).expect("decodes"),
        listed
    );
    // The peer list carries identity and nothing else (§8).
    assert!(!text.contains("token"), "{text}");
    assert!(!text.contains("endpoint"), "{text}");
}

#[test]
fn a_full_subnet_is_the_end_of_the_line() {
    // The one limit M0 has: 253 devices, and the 254th is refused
    // rather than allocated something impossible.
    let mut hub = fresh_hub();
    for octet in 2..=254u8 {
        // A distinct code each time. Re-issuing a spent string would
        // not work: `add_peer` resolves a code against the first entry
        // that matches, which is why the binary redraws until the value
        // is absent from the file.
        let code = nth_code(usize::from(octet));
        hub.codes
            .push(IssuedCode::issue(code.clone(), NOW, DEFAULT_TTL_SECS));
        join(
            &mut hub,
            &code,
            &format!("device-{octet}"),
            MACBOOK_PUBLIC,
            &token("a1"),
            NOW,
        )
        .expect("a free address");
    }
    assert_eq!(hub.peers.len(), 253);
    assert_eq!(
        hub.peers.last().expect("a peer").address,
        ip("10.100.0.254")
    );

    let code = issue(&mut hub, "HJKM-NPQR", NOW);
    assert_eq!(
        join(
            &mut hub,
            &code,
            "one-too-many",
            MACBOOK_PUBLIC,
            &token("b2"),
            NOW
        ),
        Err(JoinRejection::SubnetFull)
    );
    // Refused, and the code it was refused with is still good.
    assert_eq!(hub.codes.last().expect("a code").used_at, None);
}
