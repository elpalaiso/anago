//! `anago rm <name>` (DESIGN.md §8) — take a device off the network.
//!
//! Same two vantage points as `ls`: on the hub the state file is edited
//! directly and the interface follows immediately; on a device the API
//! does it. The difference matters for what happens next — a hub can
//! confirm the tunnel was updated, a device can only report what the
//! hub said.

use std::fmt;
use std::net::Ipv4Addr;
use std::path::Path;

use anago_core::json;
use anago_core::name::DeviceName;
use anago_core::proto::{ErrorCode, PeerInfo, PATH_PEERS};
use anago_core::state::Peer;

use crate::client::{self, Method, Request};
use crate::join::DeviceConfig;
use crate::ls::{self, Source};
use crate::paths::{self, ClientPaths, PathError, ServerPaths};
use crate::store::{Store, StoreError};
use crate::wgapply::{Applier, Interface, WgApplier};

/// What happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removed {
    pub name: String,
    pub address: String,
    /// Whether the hub's WireGuard interface was updated to match.
    /// `None` on a device, which cannot see the hub's interface.
    pub interface_updated: Option<bool>,
    /// True when a device removed itself, which leaves its own config
    /// pointing at a network that no longer knows it.
    pub was_self: bool,
}

/// What to print.
pub fn report(removed: &Removed, device_file: &Path, wg_config: &Path) -> String {
    let mut out = format!(
        "Removed {name} ({address}); its address is free again and its token no longer works.\n",
        name = removed.name,
        address = removed.address
    );
    match removed.interface_updated {
        Some(true) => out.push_str("The hub's WireGuard interface has been updated.\n"),
        Some(false) => out.push_str(
            "The state file is updated, but the WireGuard interface was not — \
             the device may still reach the hub until `anago server run` applies \
             the state again.\n",
        ),
        None => {}
    }
    if removed.was_self {
        out.push_str(&format!(
            "\nThat was this device. Its config is now stale: \
             `sudo wg-quick down {wg}`, then delete {wg} and {device} \
             before joining again.\n",
            wg = wg_config.display(),
            device = device_file.display()
        ));
    }
    out
}

/// Removes a device.
pub fn run(
    name: &DeviceName,
    server_root: &Path,
    wg_dir: &Path,
    client_paths: impl FnOnce() -> Result<ClientPaths, PathError>,
) -> Result<Removed, RmError> {
    let has_state = ServerPaths::new(server_root).state_file().exists();
    // Only the device path needs a home directory (see `ls`).
    let client_paths = if has_state {
        None
    } else {
        Some(client_paths().map_err(|e| RmError::NoConfigDir(e.to_string()))?)
    };
    let has_device_file = client_paths
        .as_ref()
        .is_some_and(|paths| paths.device_file().exists());

    match ls::choose_source(has_state, has_device_file).ok_or(RmError::NotSetUp)? {
        Source::Server => remove_locally(name, server_root, wg_dir),
        Source::Device => {
            let paths = client_paths.expect("the device path resolved its own directory");
            let text = std::fs::read_to_string(paths.device_file()).map_err(|e| {
                RmError::DeviceFile(format!("{}: {e}", paths.device_file().display()))
            })?;
            let config =
                DeviceConfig::parse(&text).map_err(|e| RmError::DeviceFile(e.to_string()))?;
            remove_remotely(name, &config, &paths, &paths::wg_config(wg_dir))
        }
    }
}

/// The hub's own path: edit the state, then make the interface match.
///
/// **Human verification needed**: the interface update runs `wg`.
fn remove_locally(
    name: &DeviceName,
    server_root: &Path,
    wg_dir: &Path,
) -> Result<Removed, RmError> {
    let store = Store::new(server_root);
    let mut guard = store.lock().map_err(RmError::State)?;
    let peer = guard
        .state_mut()
        .remove_peer(name)
        .ok_or_else(|| RmError::NotFound(name.to_string()))?;
    guard.commit().map_err(RmError::State)?;

    // Re-read under the lock, as the API does: the interface is built
    // from what is on disk, never from a snapshot that a later write
    // may already have replaced.
    let applied = match store.lock() {
        Ok(guard) => {
            let applier = WgApplier::new(Interface {
                name: paths::WG_INTERFACE.to_string(),
                config_path: paths::wg_config(wg_dir),
            });
            match applier.apply(guard.state()) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("anago: the wg interface was not updated: {e}");
                    false
                }
            }
        }
        Err(e) => {
            eprintln!("anago: could not re-read the state to update the interface: {e}");
            false
        }
    };

    Ok(from_peer(peer, Some(applied), false))
}

/// A device's path: ask the hub.
fn remove_remotely(
    name: &DeviceName,
    config: &DeviceConfig,
    client_paths: &ClientPaths,
    wg_config: &Path,
) -> Result<Removed, RmError> {
    let token = anago_core::token::DeviceToken::parse(&config.token)
        .map_err(|e| RmError::DeviceFile(format!("token: {e}")))?;
    let path = format!("{PATH_PEERS}/{}", client::encode_segment(name.as_str()));
    let response = client::send(&Request {
        method: Method::Delete,
        host: &config.domain,
        port: config.api_port(),
        path: &path,
        body: None,
        token: Some(&token),
    })
    .map_err(RmError::Client)?;

    if !response.is_success() {
        return Err(RmError::Refused(explain(
            response.status,
            &response.body,
            name,
            &client_paths.device_file(),
            wg_config,
        )));
    }
    let value = json::parse(&response.body).map_err(|e| RmError::BadResponse(e.to_string()))?;
    let removed = PeerInfo::from_json(&value).map_err(|e| RmError::BadResponse(e.to_string()))?;
    let (name_back, address) = checked_peer(&removed, name)?;
    Ok(Removed {
        name: name_back,
        address,
        // A device cannot see the hub's interface, and the hub updates
        // it as part of the same request.
        interface_updated: None,
        was_self: name.as_str() == config.name,
    })
}

/// Checks that the hub removed the device that was asked for.
///
/// The decoder checks shape, not content (§8). Without this, a hub
/// answering with a different name — or an unparseable address — would
/// have the CLI report that some other device had been removed, which
/// is worse than an error.
fn checked_peer(peer: &PeerInfo, requested: &DeviceName) -> Result<(String, String), RmError> {
    let name = DeviceName::parse(&peer.name)
        .map_err(|e| RmError::BadResponse(format!("the removed device's name: {e}")))?;
    if name != *requested {
        return Err(RmError::BadResponse(format!(
            "asked to remove {requested}, but the hub says it removed {name}"
        )));
    }
    peer.address
        .parse::<Ipv4Addr>()
        .map_err(|_| RmError::BadResponse(format!("{:?} is not an address", peer.address)))?;
    crate::wg::parse_key(&peer.public_key)
        .map_err(|e| RmError::BadResponse(format!("the removed device's public key: {e}")))?;
    Ok((name.to_string(), peer.address.clone()))
}

fn from_peer(peer: Peer, interface_updated: Option<bool>, was_self: bool) -> Removed {
    Removed {
        name: peer.name.to_string(),
        address: peer.address.to_string(),
        interface_updated,
        was_self,
    }
}

/// What to tell the person when the hub refuses to remove.
pub fn explain(
    status: u16,
    body: &str,
    name: &DeviceName,
    device_file: &Path,
    wg_config: &Path,
) -> String {
    let failure = client::describe(status, body);
    let advice = match failure.code {
        Some(ErrorCode::NotFound) => {
            format!(" — no device called {name} is registered; `anago ls` shows what is")
        }
        // The whole cleanup, not just the device file: a join with the
        // wg config still in place is refused before it reaches the
        // network, and the tunnel is probably still up.
        Some(ErrorCode::Unauthorized) => format!(
            " — this device's token is no longer accepted, so it cannot remove anything. \
             If it was removed from the hub: `sudo wg-quick down {wg}`, delete {wg} and \
             {device}, then join again with a fresh code",
            wg = wg_config.display(),
            device = device_file.display()
        ),
        _ => String::new(),
    };
    format!(
        "the hub would not remove {name}: {}{advice}",
        failure.message
    )
}

/// Why the device could not be removed.
#[derive(Debug, Clone, PartialEq)]
pub enum RmError {
    NotSetUp,
    NoConfigDir(String),
    /// No device by that name on this hub.
    NotFound(String),
    State(StoreError),
    DeviceFile(String),
    Client(client::ClientError),
    Refused(String),
    BadResponse(String),
}

impl fmt::Display for RmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RmError::NotSetUp => f.write_str(ls::NOT_SET_UP),
            RmError::NoConfigDir(detail) => write!(f, "{detail}"),
            RmError::NotFound(name) => write!(
                f,
                "no device called {name} is registered — `anago ls` shows what is"
            ),
            RmError::State(e) => write!(f, "{e}"),
            RmError::DeviceFile(detail) => write!(f, "device file: {detail}"),
            RmError::Client(e) => write!(f, "{e}"),
            RmError::Refused(detail) => write!(f, "{detail}"),
            RmError::BadResponse(detail) => {
                write!(f, "the hub's answer made no sense: {detail}")
            }
        }
    }
}

impl std::error::Error for RmError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU32, Ordering};

    use anago_core::proto::ApiError;
    use anago_core::state::{PrivateKey, ServerKeys, ServerState, Tls};
    use anago_core::subnet::Subnet;
    use anago_core::token::TokenHash;

    const NOW: i64 = 1_755_500_000;

    struct TempTree {
        root: std::path::PathBuf,
    }

    impl TempTree {
        fn new() -> TempTree {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("anago-rm-{}-{unique}", std::process::id()));
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

    fn peer(name: &str, address: &str) -> Peer {
        Peer {
            name: DeviceName::parse(name).unwrap(),
            public_key: "YiB/o4zzTPM9aaV5C93CP5kPJVGzqIyceUlne0CAoO0=".to_string(),
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
            peers: vec![peer("macbook", "10.100.0.2"), peer("맥북", "10.100.0.3")],
            codes: Vec::new(),
        }
    }

    fn name(text: &str) -> DeviceName {
        DeviceName::parse(text).unwrap()
    }

    #[test]
    fn the_hub_edits_its_own_state_and_updates_the_interface() {
        let tree = TempTree::new();
        Store::new(tree.server_root()).write(&state()).unwrap();

        let removed = run(
            &name("macbook"),
            &tree.server_root(),
            &tree.wg_dir(),
            || Err(PathError::NoHome),
        )
        .expect("the hub path must not need a home directory");

        assert_eq!(removed.name, "macbook");
        assert_eq!(removed.address, "10.100.0.2");
        assert!(!removed.was_self, "a hub does not remove itself this way");

        // Gone from the file, and the wg config beside it was rewritten
        // from the new state.
        let stored = Store::new(tree.server_root()).read().unwrap();
        assert_eq!(stored.peers.len(), 1);
        assert_eq!(stored.peers[0].name.as_str(), "맥북");
        let config = std::fs::read_to_string(paths::wg_config(tree.wg_dir())).unwrap();
        assert!(!config.contains("10.100.0.2/32"), "{config}");
        assert!(config.contains("10.100.0.3/32"), "{config}");
    }

    #[test]
    fn removing_a_name_that_is_not_there_changes_nothing() {
        let tree = TempTree::new();
        Store::new(tree.server_root()).write(&state()).unwrap();

        let e = run(
            &name("desktop"),
            &tree.server_root(),
            &tree.wg_dir(),
            || Err(PathError::NoHome),
        )
        .unwrap_err();
        assert_eq!(e, RmError::NotFound("desktop".to_string()));
        assert!(e.to_string().contains("anago ls"), "{e}");
        assert_eq!(
            Store::new(tree.server_root()).read().unwrap().peers.len(),
            2
        );
    }

    #[test]
    fn a_machine_that_is_neither_is_told_which_command_to_run() {
        let tree = TempTree::new();
        let client = tree.client();
        let e = run(
            &name("macbook"),
            &tree.server_root(),
            &tree.wg_dir(),
            || Ok(client.clone()),
        )
        .unwrap_err();
        assert_eq!(e, RmError::NotSetUp);
        assert!(e.to_string().contains("anago server init"), "{e}");
    }

    #[test]
    fn the_report_says_what_went_and_what_followed() {
        let removed = Removed {
            name: "macbook".to_string(),
            address: "10.100.0.2".to_string(),
            interface_updated: Some(true),
            was_self: false,
        };
        let text = report(
            &removed,
            Path::new("/home/jo/.config/anago/device.json"),
            Path::new("/etc/wireguard/anago.conf"),
        );
        assert!(text.contains("Removed macbook (10.100.0.2)"), "{text}");
        assert!(text.contains("token no longer works"), "{text}");
        assert!(text.contains("interface has been updated"), "{text}");
        assert!(!text.contains("This device"), "{text}");
    }

    #[test]
    fn a_state_change_the_interface_did_not_follow_is_not_hidden() {
        // The device stays reachable until the interface catches up,
        // which is the opposite of what "removed" suggests.
        let removed = Removed {
            name: "macbook".to_string(),
            address: "10.100.0.2".to_string(),
            interface_updated: Some(false),
            was_self: false,
        };
        let text = report(&removed, Path::new("/d.json"), Path::new("/w.conf"));
        assert!(text.contains("interface was not"), "{text}");
        assert!(text.contains("may still reach the hub"), "{text}");
    }

    #[test]
    fn a_device_that_removed_itself_is_told_to_clean_up() {
        let removed = Removed {
            name: "macbook".to_string(),
            address: "10.100.0.2".to_string(),
            interface_updated: None,
            was_self: true,
        };
        let text = report(
            &removed,
            Path::new("/home/jo/.config/anago/device.json"),
            Path::new("/etc/wireguard/anago.conf"),
        );
        assert!(text.contains("That was this device"), "{text}");
        assert!(
            text.contains("wg-quick down /etc/wireguard/anago.conf"),
            "{text}"
        );
        assert!(
            text.contains("/home/jo/.config/anago/device.json"),
            "{text}"
        );
        // A device knows nothing about the hub's interface.
        assert!(!text.contains("interface has been updated"), "{text}");
    }

    #[test]
    fn a_refusal_describes_removing_not_joining() {
        let device_file = Path::new("/home/jo/.config/anago/device.json");
        let wg_config = Path::new("/etc/wireguard/anago.conf");
        let body = json::to_string(
            &ApiError::new(ErrorCode::NotFound, "no device named \"desktop\"").to_json(),
        );
        let text = explain(404, &body, &name("desktop"), device_file, wg_config);
        assert!(text.contains("would not remove desktop"), "{text}");
        assert!(text.contains("`anago ls` shows what is"), "{text}");
        assert!(!text.contains("join"), "{text}");

        let body = json::to_string(
            &ApiError::new(ErrorCode::Unauthorized, "a valid device token is required").to_json(),
        );
        let text = explain(401, &body, &name("macbook"), device_file, wg_config);
        assert!(text.contains("cannot remove anything"), "{text}");
        // The whole cleanup: a join with the wg config still there is
        // refused before it reaches the network.
        assert!(
            text.contains("wg-quick down /etc/wireguard/anago.conf"),
            "{text}"
        );
        assert!(text.contains("delete /etc/wireguard/anago.conf"), "{text}");
        assert!(
            text.contains("/home/jo/.config/anago/device.json"),
            "{text}"
        );
        assert!(text.contains("fresh code"), "{text}");

        // And something that is not one of ours still reaches them.
        let text = explain(
            502,
            "<html>bad gateway</html>",
            &name("macbook"),
            device_file,
            wg_config,
        );
        assert!(text.contains("HTTP 502"), "{text}");
        assert!(
            !text.contains("wg-quick"),
            "no advice that does not apply: {text}"
        );
    }

    #[test]
    fn the_hub_has_to_say_it_removed_what_was_asked_for() {
        // Shape-only decoding would let a different name, or an
        // unparseable address, be reported as a successful removal.
        let good = PeerInfo {
            name: "macbook".to_string(),
            public_key: "YiB/o4zzTPM9aaV5C93CP5kPJVGzqIyceUlne0CAoO0=".to_string(),
            address: "10.100.0.2".to_string(),
        };
        assert_eq!(
            checked_peer(&good, &name("macbook")).unwrap(),
            ("macbook".to_string(), "10.100.0.2".to_string())
        );

        let e = checked_peer(&good, &name("desktop")).unwrap_err();
        assert!(
            e.to_string().contains("asked to remove desktop"),
            "the mismatch has to be named: {e}"
        );

        let mut bad_address = good.clone();
        bad_address.address = "10.100.0.999".to_string();
        assert!(checked_peer(&bad_address, &name("macbook")).is_err());

        let mut bad_key = good.clone();
        bad_key.public_key = "nope".to_string();
        assert!(checked_peer(&bad_key, &name("macbook")).is_err());

        let mut bad_name = good.clone();
        bad_name.name = "mac book".to_string();
        assert!(checked_peer(&bad_name, &name("macbook")).is_err());
    }
}
