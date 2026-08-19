//! The lifecycle, end to end, in pure functions.
//!
//! Two walks, one per milestone. M0: `anago server init` → `anago code`
//! → two devices join → the wg configs both sides run → `anago rm` →
//! the address comes back. M1 adds what automation put in the middle —
//! the A record, the ACME fields the state file now carries, a phone
//! that joins by `--export` and never runs anago at all, and the
//! `anago sync` verdict after every one of those — and ends the same
//! way, at `rm`.
//!
//! The binary does this with files, sockets, and `wg`; every *decision*
//! along the way is here, and this walks them in order.
//!
//! It is an integration test in the crate's own terms: it may only use
//! the public API, so anything the binary needs has to be reachable
//! from outside. Nothing here touches the filesystem, the network, or
//! the clock — the times are constants.

use std::net::Ipv4Addr;

use anago_core::acme::{self, ChallengeToken, Thumbprint};
use anago_core::code::{CodeStatus, IssuedCode, JoinCode, DEFAULT_TTL_SECS};
use anago_core::dns::{self, Record, Refusal, Upsert};
use anago_core::json;
use anago_core::name::DeviceName;
use anago_core::proto::{HubInfo, JoinResponse, PeerInfo, PeersResponse};
use anago_core::render::{self, LastHandshake, PeerRow};
use anago_core::state::{
    Acme, Challenge, Cloudflare, JoinRejection, PrivateKey, Registration, ServerKeys, ServerState,
    Tls, RENEWAL_LEAD_SECS,
};
use anago_core::subnet::Subnet;
use anago_core::sync::{self, Changes, Detachment, Local, Member, Reported, Sync};
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
/// The phone. Its private key is the one anago deliberately hands over
/// (§7.3), so it is a fixture here the way a device's own key never is.
const PHONE_PUBLIC: &str = "B0kAft8BG1g4n53XdAoP/q+1VVVSMlFnLItd1BUs8FA=";
const PHONE_PRIVATE: &str = "5y3A5H2R30n0/pr8SHoY1yU/6PfpqGsATV6fxg5d/+M=";

// ------------------------------------------------------- M1 fixtures

const DAY: i64 = 86_400;
/// A Let's Encrypt certificate's lifetime today. The renewal date is
/// two thirds of *whatever* this is (§9.1), so the walk below computes
/// against it rather than against a number of days.
const CERT_LIFETIME: i64 = 90 * DAY;

/// The hub's public address — what its A record has to carry.
/// TEST-NET-3, which is what documentation addresses are for.
const PUBLIC_IP: &str = "203.0.113.10";

const ACME_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";
const ACCOUNT_URL: &str = "https://acme-v02.api.letsencrypt.org/acct/9701";
const ACCOUNT_KEY_PATH: &str = "/var/lib/anago/acme/account.key";
const ZONE_ID: &str = "0f9a1c3b5d7e9f1123456789abcdef01";
const RECORD_ID: &str = "9c8b7a6554433221100ffeeddccbbaa9";
const CF_TOKEN_PATH: &str = "/var/lib/anago/cloudflare.token";
/// The Cloudflare API token itself, here for one assertion only: that
/// it never reaches the state file, which keeps the path and nothing
/// else (§9.1).
const CF_TOKEN: &str = "v1.0-if-this-string-is-in-state-json-something-is-wrong";

/// The account key's JWK thumbprint, as the binary computes it: 43
/// base64url characters (§10.2). Core never hashes; it is handed this.
const THUMBPRINT: &str = "gMfaPe0ssRFNZqeNs6QgRIQ5lGPV1EEPuVnN4DQL-F8";
/// A challenge token in the shape a CA issues them.
const CHALLENGE_TOKEN: &str = "lDzM4kyZv4OgbcvdHKId7g";

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

fn named(text: &str) -> DeviceName {
    DeviceName::parse(text).expect("a valid name")
}

/// The `[Interface]` half of a device's config, built from the answer
/// the hub gave it. The private key is the device's own and was never
/// part of that answer, which is why it comes in separately.
fn profile_from(joined: &JoinResponse, private_key: &str) -> ClientProfile {
    ClientProfile {
        address: ip(&joined.address),
        subnet: Subnet::parse(&joined.subnet).expect("the subnet the hub sent"),
        private_key: PrivateKey::new(private_key),
        server_public_key: joined.server_public_key.clone(),
        server_endpoint: joined.server_endpoint.clone(),
    }
}

/// What `device.json` holds after a join (§9.2) — the same answer,
/// remembered.
fn believed(joined: &JoinResponse) -> Local {
    Local {
        name: named(&joined.name),
        address: ip(&joined.address),
        subnet: Subnet::parse(&joined.subnet).expect("the subnet the hub sent"),
        server_public_key: joined.server_public_key.clone(),
        server_endpoint: joined.server_endpoint.clone(),
        server_address: ip(&joined.server_address),
    }
}

/// `GET /api/v1/peers` as a device receives it: built from the hub's
/// state, serialized, and decoded again.
///
/// Going through JSON rather than reading the state directly is the
/// point. `sync` compares what the device remembers against what
/// *arrived*, so anything that would not survive the wire must not
/// count as a match here either.
fn on_the_wire(state: &ServerState) -> PeersResponse {
    let sent = PeersResponse {
        peers: state
            .peers
            .iter()
            .map(|peer| PeerInfo {
                name: peer.name.to_string(),
                public_key: peer.public_key.clone(),
                address: peer.address.to_string(),
            })
            .collect(),
        hub: Some(HubInfo {
            subnet: state.subnet.to_string(),
            server_public_key: state.server.public_key.clone(),
            server_endpoint: format!("{}:{}", state.domain, state.listen_port),
            server_address: state.server.address.to_string(),
        }),
    };
    let text = json::to_string(&sent.to_json());
    PeersResponse::from_json(&json::parse(&text).expect("valid JSON")).expect("decodes")
}

fn hub_says(response: &PeersResponse) -> Option<Reported> {
    let hub = response.hub.as_ref()?;
    Some(Reported {
        subnet: Subnet::parse(&hub.subnet).expect("the hub's own subnet"),
        server_public_key: hub.server_public_key.clone(),
        server_endpoint: hub.server_endpoint.clone(),
        server_address: ip(&hub.server_address),
    })
}

fn members(response: &PeersResponse) -> Vec<Member> {
    response
        .peers
        .iter()
        .map(|peer| Member {
            name: named(&peer.name),
            address: ip(&peer.address),
        })
        .collect()
}

/// One `anago sync` run, from the device's side: ask the hub, decide.
fn sync_run(hub: &ServerState, local: &Local) -> Sync {
    let seen = on_the_wire(hub);
    sync::decide(local, hub_says(&seen).as_ref(), &members(&seen))
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
        PHONE_PUBLIC,
        PHONE_PRIVATE,
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

    let macbook_profile = profile_from(&macbook, MACBOOK_PRIVATE);
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
        hub: None,
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

// ============================================================== M1

/// What `anago server init --cloudflare-token … --acme` builds once the
/// CA has answered: the M0 hub plus the two things automation left
/// behind — how to renew the certificate, and where the zone is (§9.1).
fn acme_hub(issued_at: i64, not_after: i64) -> ServerState {
    let mut acme = Acme {
        directory: ACME_DIRECTORY.to_string(),
        contact: Some("mailto:me@example.com".to_string()),
        account_key_path: ACCOUNT_KEY_PATH.to_string(),
        account_url: ACCOUNT_URL.to_string(),
        challenge: Challenge::Dns01,
        issued_at: 0,
        renew_after: 0,
    };
    // Set together, from the certificate's own expiry — that is the
    // whole reason `issued` exists rather than two assignments.
    acme.issued(issued_at, Some(not_after));
    let mut tls = Tls::acme(
        "/var/lib/anago/tls/fullchain.pem",
        "/var/lib/anago/tls/privkey.pem",
        acme,
    );
    tls.not_after = Some(not_after);
    ServerState {
        tls,
        cloudflare: Some(Cloudflare {
            zone_id: ZONE_ID.to_string(),
            record_id: Some(RECORD_ID.to_string()),
            // Kept, because DNS-01 renewal needs it again (§9.1).
            token_path: Some(CF_TOKEN_PATH.to_string()),
        }),
        ..fresh_hub()
    }
}

#[test]
fn the_whole_m1_lifecycle_runs_on_pure_functions() {
    // --- `anago server init`, now with DNS and a CA ----------------
    // Nothing answers at the name yet, so the record is created —
    // unproxied, since the orange cloud does not forward 51820/udp.
    assert_eq!(dns::decide(&[], ip(PUBLIC_IP), None), Upsert::Create);
    // And the shape init will not touch: proxied, the certificate
    // would still issue while the tunnel stayed dead (§13).
    assert_eq!(
        dns::decide(
            &[Record {
                proxied: true,
                ..Record::a(RECORD_ID, PUBLIC_IP)
            }],
            ip(PUBLIC_IP),
            Some(RECORD_ID),
        )
        .refusal(),
        Some(&Refusal::Proxied {
            record_id: RECORD_ID.to_string()
        })
    );

    // DNS-01 proves the domain. Core builds the two strings whose exact
    // shape decides whether the challenge validates; the digests behind
    // them are the binary's (§10.2).
    let challenge_token = ChallengeToken::parse(CHALLENGE_TOKEN).expect("a base64url token");
    let thumbprint = Thumbprint::parse(THUMBPRINT).expect("43 base64url characters");
    assert_eq!(
        acme::dns01_record_name(DOMAIN),
        "_acme-challenge.net.example.com"
    );
    assert_eq!(
        acme::key_authorization(&challenge_token, &thumbprint),
        format!("{CHALLENGE_TOKEN}.{THUMBPRINT}")
    );

    // --- the ACME state fields -------------------------------------
    let not_after = NOW + CERT_LIFETIME;
    let mut hub = acme_hub(NOW, not_after);
    assert!(hub.peers.is_empty(), "nothing has joined yet");
    assert_eq!(hub.server.address, ip("10.100.0.1"), "the hub is always .1");
    let acme_state = hub.tls.renewable().expect("anago issued this one");
    assert_eq!(acme_state.issued_at, NOW);
    assert_eq!(
        acme_state.renew_after,
        NOW + 60 * DAY,
        "two thirds of the lifetime, not a fixed 60 days"
    );
    assert_eq!(hub.tls.renewal_due(RENEWAL_LEAD_SECS), Some(NOW + 60 * DAY));
    assert!(!hub.tls.needs_renewal(NOW + 60 * DAY - 1, RENEWAL_LEAD_SECS));
    assert!(hub.tls.needs_renewal(NOW + 60 * DAY, RENEWAL_LEAD_SECS));
    // What the run says is the same date it will act on.
    let said = render::certificate_ready(
        DOMAIN,
        Challenge::Dns01,
        hub.tls.not_after,
        acme_state.renew_after,
        NOW,
        false,
        false,
    );
    assert!(said.contains("expires in 90d, renewing in 60d"), "{said}");

    // --- and they survive the file ---------------------------------
    let text = hub.to_json_string();
    assert_eq!(
        ServerState::parse(&text).expect("the state file reads back"),
        hub
    );
    assert!(text.contains(ACCOUNT_URL), "{text}");
    assert!(text.contains("dns-01"), "{text}");
    assert!(text.contains(CF_TOKEN_PATH), "{text}");
    // The path to the token, never the token (§9.1).
    assert!(!text.contains(CF_TOKEN), "{text}");

    // A second run finds its own record and leaves it alone, using the
    // id it cached rather than picking among records by name.
    assert_eq!(
        dns::decide(
            &[Record::a(RECORD_ID, PUBLIC_IP)],
            ip(PUBLIC_IP),
            hub.cloudflare
                .as_ref()
                .and_then(|cf| cf.record_id.as_deref()),
        ),
        Upsert::Unchanged {
            record_id: RECORD_ID.to_string()
        }
    );

    // --- the laptop joins and syncs --------------------------------
    let first_code = issue(&mut hub, "7QX4-M2KD", NOW + 60);
    let laptop_token = token("a1");
    let laptop = join(
        &mut hub,
        &first_code,
        "macbook",
        MACBOOK_PUBLIC,
        &laptop_token,
        NOW + 70,
    )
    .expect("the first join");
    let mut laptop_believes = believed(&laptop);
    assert_eq!(sync_run(&hub, &laptop_believes), Sync::Unchanged);

    // --- the phone joins by `--export` -----------------------------
    // No anago on the phone: the key is made here, the conf goes over
    // by QR or file, and this machine keeps nothing (§8).
    let second_code = issue(&mut hub, "HJKM-NPQR", NOW + 120);
    let phone = join(
        &mut hub,
        &second_code,
        "phone",
        PHONE_PUBLIC,
        &token("c3"),
        NOW + 130,
    )
    .expect("the phone joins");
    assert_eq!(phone.address, "10.100.0.3");

    let phone_profile = profile_from(&phone, PHONE_PRIVATE);
    let exported = wgconf::export_profile(&phone_profile);
    let exported = exported.expose();
    // Complete: everything wg-quick needs, with nothing left to look
    // up on a device that has no anago to look it up with.
    for line in [
        "Address = 10.100.0.3/24",
        &format!("PrivateKey = {PHONE_PRIVATE}"),
        &format!("PublicKey = {SERVER_PUBLIC}"),
        "Endpoint = net.example.com:51820",
        "AllowedIPs = 10.100.0.0/24",
        "PersistentKeepalive = 25",
    ] {
        assert!(exported.contains(line), "{line} missing from:\n{exported}");
    }
    assert_eq!(
        wgconf::private_key_line(exported),
        Some(PHONE_PRIVATE),
        "the key the phone will run is the one this machine generated"
    );
    // It is the file a laptop would run, minus the comments and
    // nothing else — a phone that works and a laptop that does not
    // would be a difference nobody would think to look for.
    let as_a_laptop_would = wgconf::client_config(&phone_profile);
    let uncommented: String = as_a_laptop_would
        .expose()
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .map(|line| format!("{line}\n"))
        .collect();
    assert_eq!(uncommented, exported);

    // The hub does not know it is a phone, and that is the point: it
    // is registered, listed and removable like anything else (§8).
    assert_eq!(hub.peers.len(), 2);
    assert_eq!(
        hub.peer(&named("phone")).expect("registered").address,
        ip("10.100.0.3")
    );
    let table = render::peer_table(&rows(&hub), NOW + 200);
    assert!(table.contains("phone"), "{table}");
    // The key that went to the phone was never on the hub — the hub
    // only ever saw the public half (§7.3).
    let text = hub.to_json_string();
    assert!(!text.contains(PHONE_PRIVATE), "{text}");
    assert!(text.contains(PHONE_PUBLIC), "{text}");
    // Its token is on file as a hash, which is what `rm` takes away
    // below; asserted here so that "gone afterwards" means something.
    let phone_hash = hub
        .peer(&named("phone"))
        .expect("registered")
        .token_hash
        .clone();
    assert!(text.contains(phone_hash.as_str()), "{text}");

    // --- what the laptop's sync makes of all that ------------------
    assert_eq!(
        sync_run(&hub, &laptop_believes),
        Sync::Unchanged,
        "another device joining changes nothing on a spoke (§6.3)"
    );
    assert_eq!(
        render::sync_summary(&Sync::Unchanged, DOMAIN),
        "net.example.com: in sync\n"
    );

    // --- renewal day -----------------------------------------------
    let renewed_at = NOW + 60 * DAY;
    let renewed_until = renewed_at + CERT_LIFETIME;
    hub.tls
        .renewable_mut()
        .expect("ours to renew")
        .issued(renewed_at, Some(renewed_until));
    hub.tls.not_after = Some(renewed_until);
    assert_eq!(
        hub.tls.renewal_due(RENEWAL_LEAD_SECS),
        Some(renewed_at + 60 * DAY),
        "the next date moves with the new certificate"
    );
    assert!(!hub.tls.needs_renewal(renewed_at + 1, RENEWAL_LEAD_SECS));
    // A certificate is the control API's business; the tunnel does not
    // notice, and the device's next run says so.
    assert_eq!(
        sync_run(&hub, &laptop_believes),
        Sync::Unchanged,
        "a renewed certificate does not move the tunnel"
    );

    // --- the hub moves its wg port ---------------------------------
    // The rare run that has something to do: the endpoint a device
    // dials is now wrong, and the config has to be rewritten.
    hub.listen_port = 51821;
    let moved = sync_run(&hub, &laptop_believes);
    assert_eq!(
        moved,
        Sync::Rewrite(Changes {
            server_endpoint: true,
            ..Changes::default()
        })
    );
    let said = render::sync_summary(&moved, DOMAIN);
    assert!(
        said.contains("updated the wg config (server endpoint)"),
        "{said}"
    );
    // The order §6.3 sets: rewrite the config and apply it, record
    // afterwards. Recording first would leave the next run believing
    // it already matched a hub it had failed to follow.
    laptop_believes.server_endpoint = format!("{DOMAIN}:51821");
    assert_eq!(sync_run(&hub, &laptop_believes), Sync::Unchanged);

    // An M0 hub answers the same call without describing itself. Then
    // there is nothing to compare against, and that is said rather than
    // called a match (§6.3).
    let quiet = PeersResponse {
        hub: None,
        ..on_the_wire(&hub)
    };
    assert_eq!(
        sync::decide(&laptop_believes, None, &members(&quiet)),
        Sync::Unverifiable
    );
    let said = render::sync_summary(&Sync::Unverifiable, DOMAIN);
    assert!(said.contains("was not checked"), "{said}");

    // --- `anago rm phone` ------------------------------------------
    let removed = hub.remove_peer(&named("phone")).expect("registered");
    assert_eq!(removed.address, ip("10.100.0.3"));
    assert_eq!(removed.token_hash, phone_hash);
    assert!(
        !hub.to_json_string().contains(phone_hash.as_str()),
        "the removed device's token hash goes with it"
    );
    assert_eq!(
        sync_run(&hub, &laptop_believes),
        Sync::Unchanged,
        "another device leaving is not the laptop's business either"
    );

    // --- `anago rm macbook` ----------------------------------------
    hub.remove_peer(&named("macbook")).expect("registered");
    assert_eq!(
        sync_run(&hub, &laptop_believes),
        Sync::Detached(Detachment::Removed),
        "the device that was removed is the one that finds out"
    );
    let said = render::sync_summary(&Sync::Detached(Detachment::Removed), DOMAIN);
    assert!(said.contains("no longer lists this device"), "{said}");
    // Nothing is torn down here: an unattended timer hands the person
    // the cleanup instead (§6.3).
    let cleanup = render::rejoin_steps("/etc/wireguard/anago.conf", "/etc/anago/device.json");
    assert!(cleanup.contains("/etc/wireguard/anago.conf"), "{cleanup}");

    // --- and both addresses come back ------------------------------
    let third_code = issue(&mut hub, "PQRS-TVWX", NOW + 300);
    let again = join(
        &mut hub,
        &third_code,
        "macbook",
        MACBOOK_PUBLIC,
        &token("d4"),
        NOW + 310,
    )
    .expect("re-joining is the cleanup");
    assert_eq!(again.address, "10.100.0.2", "the freed address is reused");

    // Everything the walk changed is still a file that reads back.
    assert_eq!(
        ServerState::parse(&hub.to_json_string()).expect("still readable"),
        hub
    );
    assert_eq!(hub.codes.len(), 3);
}
