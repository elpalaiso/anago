//! Running the hub (DESIGN.md §6.1 step 4, §8 `server run`).
//!
//! One process: the control API over TLS, and the WireGuard interface
//! kept in step with the state file. systemd normally starts it;
//! `server init --no-systemd` prints the command to run it by hand.
//!
//! Almost everything here is I/O by nature — bind a port, spawn `wg`,
//! wait for a signal — so the testable parts are the small decisions:
//! what to listen on, and what to say at startup.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use anago_core::state::ServerState;

use crate::api::{self, Api};
use crate::paths;
use crate::store::{Store, StoreError};
use crate::tls;
use crate::wg;
use crate::wgapply::{Applier, Interface, WgApplier};

/// The address the control API binds.
///
/// All interfaces, because a hub that only answered on localhost could
/// not be joined from anywhere — the port is the thing to keep closed
/// or open, not the bind address.
pub fn listen_addr(api_port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), api_port)
}

/// What to print when the hub comes up.
pub fn startup_banner(state: &ServerState, addr: SocketAddr) -> String {
    format!(
        "anago is serving {domain}\n  control API   https://{domain}:{api} (listening on {addr})\n  \
         WireGuard     udp/{wg}\n  devices       {peers}\n",
        domain = state.domain,
        api = state.api_port,
        addr = addr,
        wg = state.listen_port,
        peers = state.peers.len()
    )
}

/// Runs the hub until it is asked to stop.
///
/// **Human verification needed**: binds ports, drives `wg-quick`, and
/// waits on signals — none of which a unit test can stand in for.
pub fn run(root: &Path, wg_dir: &Path) -> Result<(), ServeError> {
    let store = Store::new(root);
    let state = store.read().map_err(ServeError::State)?;

    wg::check_tools_from_env().map_err(|e| ServeError::Wg(e.to_string()))?;

    let loaded = tls::load(
        Path::new(&state.tls.cert_path),
        Path::new(&state.tls.key_path),
    )
    .map_err(|e| ServeError::Tls(e.to_string()))?;
    for warning in &loaded.warnings {
        eprintln!("anago: warning: {warning}");
    }

    // Bring the interface to whatever the state file says before
    // answering any request: a hub that accepts a join it cannot route
    // is worse than one that has not started.
    let applier = WgApplier::new(Interface {
        name: paths::WG_INTERFACE.to_string(),
        config_path: paths::wg_config(wg_dir),
    });
    applier
        .apply(&state)
        .map_err(|e| ServeError::Wg(e.to_string()))?;

    let addr = listen_addr(state.api_port);
    print!("{}", startup_banner(&state, addr));

    let api = Api {
        store: Arc::new(store),
        wg: Arc::new(applier),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| ServeError::Runtime(e.to_string()))?;
    runtime
        .block_on(tls::serve(addr, loaded.config, api::router(api)))
        .map_err(|e| ServeError::Listen {
            addr,
            source: e.to_string(),
        })
}

/// Why the hub could not run.
#[derive(Debug)]
pub enum ServeError {
    State(StoreError),
    Tls(String),
    Wg(String),
    Runtime(String),
    Listen { addr: SocketAddr, source: String },
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServeError::State(e) => write!(f, "{e}"),
            ServeError::Tls(e) => write!(f, "{e}"),
            ServeError::Wg(e) => write!(f, "{e}"),
            ServeError::Runtime(e) => write!(f, "could not start the async runtime: {e}"),
            ServeError::Listen { addr, source } => {
                let hint = if addr.port() < 1024 {
                    " — ports below 1024 need root"
                } else {
                    ""
                };
                write!(f, "could not listen on {addr}: {source}{hint}")
            }
        }
    }
}

impl std::error::Error for ServeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use anago_core::state::{PrivateKey, ServerKeys, Tls};
    use anago_core::subnet::Subnet;

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
                address: "10.100.0.1".parse().unwrap(),
            },
            peers: Vec::new(),
            codes: Vec::new(),
        }
    }

    #[test]
    fn the_api_listens_on_every_interface() {
        // Binding localhost would make the hub unjoinable; the firewall
        // decides who reaches the port, not the bind address.
        assert_eq!(listen_addr(443).to_string(), "0.0.0.0:443");
        assert_eq!(listen_addr(8443).port(), 8443);
        assert!(listen_addr(443).ip().is_unspecified());
    }

    #[test]
    fn the_banner_says_where_to_reach_the_hub() {
        let state = state();
        let banner = startup_banner(&state, listen_addr(state.api_port));
        assert!(banner.contains("https://net.example.com:443"), "{banner}");
        assert!(banner.contains("udp/51820"), "{banner}");
        assert!(banner.contains("devices       0"), "{banner}");
    }

    #[test]
    fn a_privileged_port_failure_says_why() {
        // The likeliest cause of "address in use"-shaped confusion on
        // first run.
        let e = ServeError::Listen {
            addr: listen_addr(443),
            source: "Permission denied (os error 13)".to_string(),
        };
        assert!(e.to_string().contains("below 1024 need root"), "{e}");

        let e = ServeError::Listen {
            addr: listen_addr(8443),
            source: "Address already in use (os error 48)".to_string(),
        };
        assert!(!e.to_string().contains("below 1024"), "{e}");
        assert!(e.to_string().contains("Address already in use"), "{e}");
    }
}
