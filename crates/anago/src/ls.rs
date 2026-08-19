//! `anago ls` (DESIGN.md §8) — the device list, from wherever this
//! machine can see it.
//!
//! Two sources, and the difference is visible in the output. On the hub
//! the state file is right there, and `wg show` knows when each device
//! last spoke. On a device there is only the API, which answers with
//! identity and no liveness (§8) — so the handshake column reads as
//! unknown rather than as "never", which would be a different claim.

use std::fmt;
use std::path::Path;

use anago_core::json;
use anago_core::name::DeviceName;
use anago_core::proto::{ErrorCode, PeersResponse, PATH_PEERS};
use anago_core::render::{self, LastHandshake, PeerRow};
use anago_core::state::ServerState;
use anago_core::token::DeviceToken;

use crate::client::{self, Method, Request};
use crate::join::{DeviceConfig, JoinError};
use crate::paths::{self, ClientPaths, PathError, ServerPaths};
use crate::store::{Store, StoreError};
use crate::wg::{self, DumpPeer};

/// Where the list comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// This machine is the hub: read the state file.
    Server,
    /// This machine is a device: ask the hub.
    Device,
}

/// What to tell somebody on a machine that is neither.
pub const NOT_SET_UP: &str = "this machine is neither a hub nor a joined device — run \
     `anago server init` here, or `anago join` with a code from one";

/// Picks a source, or `None` when this machine is neither.
///
/// The hub wins when both are present — a hub that also joined itself
/// is odd, but if it happens the local file is both faster and more
/// complete than asking itself over TLS.
///
/// Shared with `rm`, which faces exactly the same question.
pub fn choose_source(has_state: bool, has_device_file: bool) -> Option<Source> {
    match (has_state, has_device_file) {
        (true, _) => Some(Source::Server),
        (false, true) => Some(Source::Device),
        (false, false) => None,
    }
}

/// Rows from the hub's own state, with handshakes from `wg show`.
///
/// `dump` is `None` when `wg show` could not be run at all — no
/// permission, no interface, no wg. Everything is then `Unknown`,
/// because "never" is a claim only the kernel can support: a peer that
/// has been up for a week would otherwise be listed as never seen for
/// want of root. A peer missing from a dump we *did* get is unknown for
/// the same reason; only wg's own `0` means never.
pub fn rows_from_state(state: &ServerState, dump: Option<&[DumpPeer]>) -> Vec<PeerRow> {
    state
        .peers
        .iter()
        .map(|peer| PeerRow {
            name: peer.name.to_string(),
            address: peer.address,
            public_key: peer.public_key.clone(),
            last_handshake: match dump {
                None => LastHandshake::Unknown,
                Some(entries) => entries
                    .iter()
                    .find(|entry| entry.public_key == peer.public_key)
                    .map_or(LastHandshake::Unknown, |entry| match entry.last_handshake {
                        Some(at) => LastHandshake::At(at),
                        None => LastHandshake::Never,
                    }),
            },
        })
        .collect()
}

/// Rows from the API's answer.
///
/// The decoder checks shape, not content (§8), so the values are parsed
/// here: a hub answering with a broken address should be reported, not
/// rendered as though `0.0.0.0` had been assigned to somebody.
pub fn rows_from_response(response: &PeersResponse) -> Result<Vec<PeerRow>, LsError> {
    response
        .peers
        .iter()
        .map(|peer| {
            let bad = |what: &str| LsError::BadResponse(format!("peer {:?}: {what}", peer.name));
            Ok(PeerRow {
                name: DeviceName::parse(&peer.name)
                    .map_err(|e| bad(&e.to_string()))?
                    .to_string(),
                address: peer
                    .address
                    .parse()
                    .map_err(|_| bad(&format!("{:?} is not an address", peer.address)))?,
                public_key: wg::parse_key(&peer.public_key).map_err(|e| bad(&e.to_string()))?,
                // M0's /peers carries no liveness, and guessing "never"
                // would be a claim the hub never made.
                last_handshake: LastHandshake::Unknown,
            })
        })
        .collect()
}

/// Lists the network's devices./// Lists the network's devices.
pub fn run(
    server_root: &Path,
    wg_dir: &Path,
    client_paths: impl FnOnce() -> Result<ClientPaths, PathError>,
    now: i64,
) -> Result<String, LsError> {
    let has_state = ServerPaths::new(server_root).state_file().exists();
    // The device path is the only one that needs a home directory, so
    // it is the only one that asks for one — a hub running from cron
    // with no HOME still lists its devices.
    let client_paths = if has_state {
        None
    } else {
        Some(client_paths().map_err(|e| LsError::NoConfigDir(e.to_string()))?)
    };
    let has_device_file = client_paths
        .as_ref()
        .is_some_and(|paths| paths.device_file().exists());

    let rows = match choose_source(has_state, has_device_file).ok_or(LsError::NotSetUp)? {
        Source::Server => {
            let state = Store::new(server_root).read().map_err(LsError::State)?;
            rows_from_state(&state, handshakes(wg_dir).as_deref())
        }
        Source::Device => {
            let paths = client_paths.expect("the device path resolved its own directory");
            let text = std::fs::read_to_string(paths.device_file()).map_err(|e| {
                LsError::DeviceFile(format!("{}: {e}", paths.device_file().display()))
            })?;
            let config = DeviceConfig::parse(&text).map_err(LsError::Join)?;
            rows_from_response(&ask_hub(
                &config,
                &paths.device_file(),
                &paths::wg_config(wg_dir),
            )?)?
        }
    };
    Ok(render::peer_table(&rows, now))
}

/// What `wg show` says, or `None` when it could not be asked.
///
/// **Human verification needed**: runs `wg`. The distinction matters:
/// `None` means "unknown", not "never" — see [`rows_from_state`].
fn handshakes(wg_dir: &Path) -> Option<Vec<DumpPeer>> {
    let interface = paths::wg_config(wg_dir)
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| paths::WG_INTERFACE.to_string());
    match wg::run(&wg::show_dump(&interface), None) {
        Ok(text) => Some(wg::parse_dump(&text)),
        Err(e) => {
            eprintln!("anago: could not ask wg when devices were last seen ({e})");
            None
        }
    }
}

/// Asks the hub for its peer list.
///
/// **Human verification needed**: makes a real HTTPS call.
fn ask_hub(
    config: &DeviceConfig,
    device_file: &Path,
    wg_config: &Path,
) -> Result<PeersResponse, LsError> {
    let token = DeviceToken::parse(&config.token)
        .map_err(|e| LsError::DeviceFile(format!("token: {e}")))?;
    let response = client::send(&Request {
        method: Method::Get,
        host: &config.domain,
        port: config.api_port(),
        path: PATH_PEERS,
        body: None,
        authorization: Some(&client::HeaderValue::device_token(&token)),
    })
    .map_err(LsError::Client)?;

    if !response.is_success() {
        return Err(LsError::Refused(explain(
            response.status,
            &response.body,
            device_file,
            wg_config,
        )));
    }
    let value = json::parse(&response.body).map_err(|e| LsError::BadResponse(e.to_string()))?;
    PeersResponse::from_json(&value).map_err(|e| LsError::BadResponse(e.to_string()))
}

/// What to tell the person when the hub refuses to list.
///
/// The same reading as everywhere else ([`client::describe`]) with
/// advice about *this* command — telling somebody who ran `anago ls`
/// that "the hub refused the join" describes work they never asked for.
///
/// The 401 case names the files by path. A device whose token was
/// revoked cannot simply run `anago join` again: the local config is
/// still there, and join refuses while it is. Nor can it `anago rm`
/// itself — the token that would authorize that is the one that just
/// stopped working. So the way back is local cleanup, and the message
/// spells it.
pub fn explain(status: u16, body: &str, device_file: &Path, wg_config: &Path) -> String {
    let failure = client::describe(status, body);
    let advice = match failure.code {
        Some(ErrorCode::Unauthorized) => format!(
            " — this device's token is no longer accepted, which is what `anago rm` on the \
             hub does. To join again: `sudo wg-quick down {wg}`, delete {wg} and {device}, \
             then `anago join <domain> <code>` with a fresh code from `anago code`",
            wg = wg_config.display(),
            device = device_file.display()
        ),
        _ => String::new(),
    };
    format!(
        "the hub would not list devices: {}{advice}",
        failure.message
    )
}

/// Why the list could not be produced.
#[derive(Debug, Clone, PartialEq)]
pub enum LsError {
    /// Neither a hub nor a joined device.
    NotSetUp,
    /// A device that cannot work out where its config lives.
    NoConfigDir(String),
    State(StoreError),
    DeviceFile(String),
    Join(JoinError),
    Client(client::ClientError),
    Refused(String),
    BadResponse(String),
}

impl fmt::Display for LsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LsError::NotSetUp => f.write_str(NOT_SET_UP),
            LsError::NoConfigDir(detail) => write!(f, "{detail}"),
            LsError::State(e) => write!(f, "{e}"),
            LsError::DeviceFile(detail) => write!(f, "device file: {detail}"),
            LsError::Join(e) => write!(f, "{e}"),
            LsError::Client(e) => write!(f, "{e}"),
            LsError::Refused(detail) => write!(f, "{detail}"),
            LsError::BadResponse(detail) => {
                write!(f, "the hub's answer made no sense: {detail}")
            }
        }
    }
}

impl std::error::Error for LsError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use anago_core::name::DeviceName;
    use anago_core::proto::PeerInfo;
    use anago_core::state::{Peer, PrivateKey, ServerKeys, Tls};
    use anago_core::subnet::Subnet;
    use anago_core::token::TokenHash;

    const NOW: i64 = 1_755_500_000;
    /// wg-shaped keys: 44 base64 characters.
    const KEY_ONE: &str = "YiB/o4zzTPM9aaV5C93CP5kPJVGzqIyceUlne0CAoO0=";
    const KEY_TWO: &str = "Xtt7u1I5qnMB8k6yMkjTDpJAc+3tPLPV9dg/yeb+qdE=";

    fn peer(name: &str, address: &str, key: &str) -> Peer {
        Peer {
            name: DeviceName::parse(name).unwrap(),
            public_key: key.to_string(),
            address: address.parse().unwrap(),
            token_hash: TokenHash::parse(&"ab".repeat(32)).unwrap(),
            created_at: NOW,
            last_seen: None,
        }
    }

    fn state() -> ServerState {
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
                address: "10.100.0.1".parse::<Ipv4Addr>().unwrap(),
            },
            peers: vec![
                peer("macbook", "10.100.0.2", "bWFjYm9vaw=="),
                peer("맥북", "10.100.0.3", "ZGVza3RvcA=="),
            ],
            codes: Vec::new(),
        }
    }

    #[test]
    fn the_hub_reads_its_own_file_even_if_it_also_joined() {
        assert_eq!(choose_source(true, false), Some(Source::Server));
        assert_eq!(choose_source(true, true), Some(Source::Server));
        assert_eq!(choose_source(false, true), Some(Source::Device));
        assert_eq!(choose_source(false, false), None);

        let e = LsError::NotSetUp;
        assert!(e.to_string().contains("anago server init"), "{e}");
        assert!(e.to_string().contains("anago join"), "{e}");
    }

    #[test]
    fn the_hub_reports_handshakes_from_the_kernel() {
        let dump = vec![
            DumpPeer {
                public_key: "bWFjYm9vaw==".to_string(),
                last_handshake: Some(NOW - 120),
            },
            DumpPeer {
                public_key: "ZGVza3RvcA==".to_string(),
                last_handshake: None,
            },
        ];
        let rows = rows_from_state(&state(), Some(&dump));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "macbook");
        assert_eq!(rows[0].last_handshake, LastHandshake::At(NOW - 120));
        // wg said 0 for this one, which the hub can honestly call never.
        assert_eq!(rows[1].last_handshake, LastHandshake::Never);

        let table = render::peer_table(&rows, NOW);
        assert!(table.contains("2m ago"), "{table}");
        assert!(table.contains("never"), "{table}");
    }

    #[test]
    fn a_hub_that_could_not_ask_wg_says_unknown_not_never() {
        // Regression: no permission, no interface, or no wg used to
        // print "never" for peers that had been up for a week.
        let rows = rows_from_state(&state(), None);
        assert_eq!(rows.len(), 2, "every registered device is still listed");
        assert!(rows
            .iter()
            .all(|row| row.last_handshake == LastHandshake::Unknown));
        assert!(!render::peer_table(&rows, NOW).contains("never"));

        // A dump that does not mention a peer is the same situation:
        // only wg's explicit 0 means never.
        let dump = vec![DumpPeer {
            public_key: "bWFjYm9vaw==".to_string(),
            last_handshake: Some(NOW - 30),
        }];
        let rows = rows_from_state(&state(), Some(&dump));
        assert_eq!(rows[0].last_handshake, LastHandshake::At(NOW - 30));
        assert_eq!(rows[1].last_handshake, LastHandshake::Unknown);
    }

    #[test]
    fn the_api_path_does_not_invent_liveness() {
        // §8: M0's /peers carries identity only. "never" would be a
        // claim the hub never made.
        let response = PeersResponse {
            peers: vec![
                PeerInfo {
                    name: "macbook".to_string(),
                    public_key: KEY_ONE.to_string(),
                    address: "10.100.0.2".to_string(),
                },
                PeerInfo {
                    name: "맥북".to_string(),
                    public_key: KEY_TWO.to_string(),
                    address: "10.100.0.3".to_string(),
                },
            ],
            hub: None,
        };
        let rows = rows_from_response(&response).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .all(|row| row.last_handshake == LastHandshake::Unknown));
        assert_eq!(rows[1].address.to_string(), "10.100.0.3");

        let table = render::peer_table(&rows, NOW);
        assert!(table.contains('—'), "{table}");
        assert!(!table.contains("never"), "{table}");
    }

    #[test]
    fn a_broken_answer_is_reported_rather_than_rendered() {
        // Regression: an unparseable address became 0.0.0.0 and was
        // printed as though somebody had been assigned it.
        let peer = |name: &str, key: &str, address: &str| PeersResponse {
            peers: vec![PeerInfo {
                name: name.to_string(),
                public_key: key.to_string(),
                address: address.to_string(),
            }],
            hub: None,
        };

        let e = rows_from_response(&peer("macbook", KEY_ONE, "not an address")).unwrap_err();
        assert!(matches!(e, LsError::BadResponse(_)), "{e:?}");
        assert!(e.to_string().contains("macbook"), "{e}");

        assert!(rows_from_response(&peer("mac book", KEY_ONE, "10.100.0.2")).is_err());
        assert!(rows_from_response(&peer("macbook", "nope", "10.100.0.2")).is_err());
        assert!(rows_from_response(&peer("macbook", KEY_ONE, "10.100.0.2")).is_ok());
    }

    /// A throwaway directory tree, so these tests never read the
    /// machine's real state file or its real device token.
    struct TempTree {
        root: std::path::PathBuf,
    }

    impl TempTree {
        fn new() -> TempTree {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("anago-ls-{}-{unique}", std::process::id()));
            std::fs::create_dir_all(root.join("var")).unwrap();
            std::fs::create_dir_all(root.join("config")).unwrap();
            std::fs::create_dir_all(root.join("wireguard")).unwrap();
            TempTree { root }
        }

        fn server_root(&self) -> std::path::PathBuf {
            self.root.join("var")
        }

        fn wg_dir(&self) -> std::path::PathBuf {
            self.root.join("wireguard")
        }

        fn client(&self) -> ClientPaths {
            ClientPaths::new(self.root.join("config"))
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn a_machine_that_is_neither_is_told_which_command_to_run() {
        let tree = TempTree::new();
        let client = tree.client();
        let e = run(
            &tree.server_root(),
            &tree.wg_dir(),
            || Ok(client.clone()),
            NOW,
        )
        .unwrap_err();
        assert_eq!(e, LsError::NotSetUp);
        assert!(e.to_string().contains("anago server init"), "{e}");
        assert!(e.to_string().contains("anago join"), "{e}");
    }

    #[test]
    fn a_hub_lists_its_devices_without_a_home_directory() {
        // Regression: resolving the client config directory first made
        // `anago ls` fail on a hub run from cron, where HOME is unset.
        let tree = TempTree::new();
        Store::new(tree.server_root()).write(&state()).unwrap();

        let table = run(
            &tree.server_root(),
            &tree.wg_dir(),
            || Err(PathError::NoHome),
            NOW,
        )
        .expect("the hub path must not need a home directory");
        assert!(table.contains("macbook"), "{table}");
        assert!(table.contains("10.100.0.3"), "{table}");
        // No wg on the test machine, so liveness is unknown rather than
        // a claim.
        assert!(!table.contains("never"), "{table}");
    }

    #[test]
    fn a_refusal_describes_listing_not_joining() {
        // Regression: `ls` reused the join wording, so a 401 told the
        // person the hub had refused a join they never attempted.
        let body = json::to_string(
            &anago_core::proto::ApiError::new(
                ErrorCode::Unauthorized,
                "a valid device token is required",
            )
            .to_json(),
        );
        let device_file = Path::new("/home/jo/.config/anago/device.json");
        let wg_config = Path::new("/etc/wireguard/anago.conf");
        let text = explain(401, &body, device_file, wg_config);
        assert!(text.contains("would not list devices"), "{text}");
        assert!(!text.contains("refused the join"), "{text}");

        // A revoked device cannot re-join or `anago rm` itself, so the
        // way back is local cleanup — named, with paths.
        assert!(text.contains("no longer accepted"), "{text}");
        assert!(
            text.contains("wg-quick down /etc/wireguard/anago.conf"),
            "{text}"
        );
        assert!(
            text.contains("/home/jo/.config/anago/device.json"),
            "{text}"
        );
        assert!(text.contains("anago join"), "{text}");
        assert!(
            text.contains("`anago code`"),
            "a fresh code is needed too: {text}"
        );

        // A body that is not one of ours still reaches the person.
        let text = explain(502, "<html>bad gateway</html>", device_file, wg_config);
        assert!(text.contains("HTTP 502"), "{text}");
        assert!(text.contains("bad gateway"), "{text}");
        assert!(
            !text.contains("wg-quick"),
            "no advice that does not apply: {text}"
        );
    }

    #[test]
    fn an_empty_network_still_prints_something_useful() {
        let mut state = state();
        state.peers.clear();
        let table = render::peer_table(&rows_from_state(&state, Some(&[])), NOW);
        assert!(table.contains("no devices yet"), "{table}");
    }
}
