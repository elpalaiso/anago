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
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anago_core::state::ServerState;

use crate::acme;
use crate::api::{self, Api};
use crate::fsutil::FileLock;
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
    let handle = tls::reloadable(loaded.config);
    runtime
        .block_on(async {
            // The renewal check runs beside the listener for as long as
            // the hub does — and **only** as long as it does. The task
            // never returns on its own, so if it ends at all it
            // panicked, and a hub that keeps serving HTTPS while
            // nothing renews is the failure that turns up months later
            // as an expired certificate. Ending the process hands it to
            // systemd, which restarts on failure (§6.1).
            let mut renewals = tokio::spawn(renewal_task(root.to_path_buf(), handle.clone()));
            let served = tokio::select! {
                served = tls::serve(addr, handle, api::router(api)) => served,
                stopped = &mut renewals => Err(renewal_stopped(stopped)),
            };
            renewals.abort();
            served
        })
        .map_err(|e| ServeError::Listen {
            addr,
            source: e.to_string(),
        })
}

/// What to say when the renewal task is the thing that ended.
///
/// It is declared to run forever, so the only ways here are a panic and
/// a cancellation nothing asked for. Either way the certificate has
/// stopped being looked after, which is worth the hub's life.
pub fn renewal_stopped<Never>(stopped: Result<Never, tokio::task::JoinError>) -> io::Error {
    let why = match stopped {
        // The task's own type says it cannot return; only a panic or a
        // cancellation gets here.
        Ok(_) => "the renewal check ended without saying why".to_string(),
        Err(e) if e.is_panic() => "the renewal check panicked".to_string(),
        Err(e) => format!("the renewal check stopped: {e}"),
    };
    io::Error::other(format!(
        "{why} — the certificate would stop being renewed, so the hub is stopping \
         rather than serving on quietly"
    ))
}

/// The periodic certificate check (DESIGN.md §9.1).
///
/// Reads the state file each time round rather than closing over what
/// `server run` started with: `server renew` by hand, or a certificate
/// swapped for a manual one, changes what should happen next, and the
/// loop should notice within the hour.
///
/// **Human verification needed**: renewing needs a real CA.
async fn renewal_task(root: PathBuf, handle: tls::Reloadable) -> ! {
    let store = Store::new(&root);
    // The store owns the state file and its lock; where the issued
    // certificate lives is a separate family of paths (§9), so it is
    // built here rather than reached for through the store.
    let paths = paths::ServerPaths::new(&root);
    acme::renewal_loop(
        // The error travels: a state file that cannot be read is not a
        // hub with nothing to renew (§9.1).
        || {
            store
                .read()
                .map(|state| state.tls)
                .map_err(|e| e.to_string())
        },
        || renew_once(&store, &paths, &handle),
        now,
    )
    .await
}

/// One renewal: issue, save, record, and put the new certificate in
/// front of the listener.
///
/// **The whole attempt is serialized on the issuance lock**, taken
/// before the state is even read. Without it, a `server renew` typed by
/// hand while the timer is mid-flight would have two runs writing the
/// same account file and the same certificate pair, and the loser would
/// record what it got against settings the winner had already changed —
/// pointing a manual hub's `cert_path` at anago's own files, or mixing
/// one CA's account with another's order (§9.1).
///
/// The lock is *tried*, not waited for: if a person is already renewing,
/// the timer has nothing to add by queueing behind them for two
/// minutes.
///
/// The order after that is §9.1's, and each step is arranged so the one
/// after it cannot fail in a way that matters: the account credentials
/// and the certificate pair are written by `acme::renew`, the new pair
/// is **loaded and validated before the state file is written**, and
/// the swap that follows the commit cannot fail at all. A hub never
/// records a renewal it is not serving.
async fn renew_once(
    store: &Store,
    paths: &paths::ServerPaths,
    handle: &tls::Reloadable,
) -> Result<(), acme::RenewalFailure> {
    let _issuing = match FileLock::try_acquire(&paths.issue_lock()) {
        Ok(Some(lock)) => lock,
        Ok(None) => return Err(acme::RenewalFailure::busy()),
        Err(e) => return Err(acme::RenewalFailure::local(e.to_string())),
    };

    let state = store
        .read()
        .map_err(|e| acme::RenewalFailure::local(e.to_string()))?;
    // What this renewal is for. Anything else about TLS changing while
    // the CA was being talked to means the answer belongs to a hub that
    // no longer exists.
    let witness = state.tls.clone();
    let at = now();

    let renewed = acme::renew(&state, paths, at)
        .await
        .map_err(acme::RenewalFailure::from)?;

    // Before the commit, so that a pair which cannot be served is a
    // renewal that did not happen rather than one that is recorded and
    // invisible.
    let loaded = tls::load(
        Path::new(&renewed.certificate_path),
        Path::new(&renewed.key_path),
    )
    .map_err(|e| acme::RenewalFailure::local(e.to_string()))?;

    let mut guard = store
        .lock()
        .map_err(|e| acme::RenewalFailure::local(e.to_string()))?;
    if guard.state().tls != witness {
        return Err(acme::RenewalFailure::local(
            "the hub's TLS settings changed while the certificate was being issued; \
             nothing was recorded",
        ));
    }
    acme::record(guard.state_mut(), &renewed, at);
    guard
        .commit()
        .map_err(|e| acme::RenewalFailure::local(e.to_string()))?;

    tls::swap(handle, loaded.config);
    for warning in loaded.warnings.iter().chain(renewed.warnings.iter()) {
        eprintln!("anago: warning: {warning}");
    }
    println!("anago: renewed the certificate for {}", state.domain);
    Ok(())
}

/// Seconds since the epoch. A wrong clock is a wrong renewal date and
/// nothing worse, so a clock before 1970 reads as zero rather than
/// stopping the hub.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or(0)
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

    #[test]
    fn a_renewal_check_that_dies_takes_the_hub_with_it() {
        // A hub that keeps serving HTTPS while nothing renews is the
        // failure that turns up months later as an expired certificate.
        // systemd restarts on failure; serving on quietly has nobody to
        // notice it.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let panicked = runtime.block_on(async {
            let task = tokio::spawn(async { panic!("the renewal check fell over") });
            task.await
        });
        let error = renewal_stopped(panicked);
        let message = error.to_string();
        assert!(message.contains("panicked"), "{message}");
        assert!(message.contains("stop being renewed"), "{message}");
        assert!(message.contains("hub is stopping"), "{message}");

        // An abort is the other way here, and reads as itself.
        let cancelled = runtime.block_on(async {
            let task = tokio::spawn(async { std::future::pending::<()>().await });
            task.abort();
            task.await
        });
        assert!(renewal_stopped(cancelled).to_string().contains("stopped"));
    }

    #[test]
    fn two_renewals_on_one_hub_do_not_run_at_once() {
        // The timer coming round while somebody types `server renew` is
        // ordinary. Both writing the same account file and the same
        // certificate pair is not: the loser would record what it got
        // against settings the winner had already changed (§9.1).
        let dir = std::env::temp_dir().join(format!("anago-issue-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = paths::ServerPaths::new(&dir);

        let held = FileLock::try_acquire(&paths.issue_lock())
            .expect("the lock file")
            .expect("nobody holds it yet");
        assert!(
            FileLock::try_acquire(&paths.issue_lock())
                .expect("the lock file")
                .is_none(),
            "a second issuance started while the first was running"
        );

        // And it frees when the run that had it is done.
        drop(held);
        assert!(FileLock::try_acquire(&paths.issue_lock())
            .expect("the lock file")
            .is_some());

        // The issuance lock is its own file: the state lock is held for
        // the length of a join, and an issuance takes minutes.
        assert_ne!(paths.issue_lock(), paths.state_lock());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_renewal_is_not_recorded_against_settings_it_did_not_run_under() {
        // The check `renew_once` makes before committing: TLS as it was
        // when the issuance started, against TLS as it is now.
        let before = Tls::manual("/etc/ssl/anago/fullchain.pem", "/etc/ssl/anago/privkey.pem");
        assert_eq!(before, before.clone());

        // A hub that was switched to ACME mid-flight is a different
        // hub, and recording anago's own paths over the manual ones is
        // exactly the damage.
        let after = Tls::acme(
            "/var/lib/anago/tls/fullchain.pem",
            "/var/lib/anago/tls/privkey.pem",
            anago_core::state::Acme {
                directory: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
                contact: Some("jo@example.com".to_string()),
                account_key_path: "/var/lib/anago/tls/account.key".to_string(),
                account_url: "https://acme-v02.api.letsencrypt.org/acme/acct/1".to_string(),
                challenge: anago_core::state::Challenge::Http01,
                issued_at: 0,
                renew_after: 0,
            },
        );
        assert_ne!(before, after);
    }
}
