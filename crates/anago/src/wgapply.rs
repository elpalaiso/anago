//! Pushing state changes into the running WireGuard interface
//! (DESIGN.md §5, plan D5).
//!
//! When a device joins or leaves, the server's `anago.conf` is
//! regenerated from the state file and applied in place with `wg
//! syncconf` — not `wg-quick down`/`up`, which would drop every live
//! tunnel to punish one join.
//!
//! Deciding *what* to do is pure and tested here: whether the file
//! changed, whether the interface is already up, what to say about
//! `ip_forward`. Running the commands needs a real machine and root, so
//! [`Applier::apply`] is marked for human verification.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anago_core::state::ServerState;
use anago_core::wgconf;
use anago_core::wgconf::SecretText;

use crate::fsutil;
use crate::wg::{self, Platform, WgError};

/// The interface anago manages and the file that describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub config_path: PathBuf,
}

/// What applying a change requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// The interface is up: hand it the new peer list, keeping every
    /// established tunnel.
    Sync,
    /// Nothing is up yet — first start, or after a reboot.
    BringUp,
}

/// What to do, given what the kernel looks like and what was last
/// applied *successfully*.
///
/// The config file matching the state proves nothing about the kernel:
/// a write that succeeded and a `syncconf` that failed leave exactly
/// that shape, and so does a reboot. So the skip is decided by the last
/// successful apply, never by the file.
pub fn plan(interface_is_up: bool, last_applied: Option<&str>, wanted: &str) -> Option<Action> {
    if !interface_is_up {
        // Down for any reason — first start, reboot, someone ran
        // `wg-quick down` — and the config on disk is irrelevant.
        return Some(Action::BringUp);
    }
    if last_applied == Some(wanted) {
        return None;
    }
    Some(Action::Sync)
}

/// Writes the server config for `state`, returning whether the file
/// changed.
///
/// An unchanged file means nothing to apply: a failed join or a `rm` of
/// something that was not there should not disturb a running interface.
pub fn write_config(state: &ServerState, path: &Path) -> Result<bool, WgError> {
    let wanted = wgconf::server_config(state);
    if std::fs::read_to_string(path).is_ok_and(|current| current == wanted.expose()) {
        return Ok(false);
    }
    fsutil::write_private(path, wanted.expose()).map_err(|e| WgError::Spawn {
        line: format!("write {}", path.display()),
        source: e.to_string(),
    })?;
    Ok(true)
}

/// Whether the kernel is forwarding IPv4 — the setting that makes
/// hub-and-spoke work at all.
///
/// Pure: the caller reads `/proc/sys/net/ipv4/ip_forward` (or `sysctl`
/// on macOS) and passes what it found.
pub fn forwarding_is_enabled(reported: &str) -> bool {
    // Linux prints "1"; `sysctl net.inet.ip.forwarding` prints
    // "net.inet.ip.forwarding: 1".
    reported
        .rsplit(':')
        .next()
        .map(str::trim)
        .is_some_and(|value| value == "1")
}

/// What to tell an operator whose kernel is not forwarding.
///
/// Without this, a device reaches the server and nothing else: packets
/// for another device arrive at the hub and die there. It is the single
/// most likely reason a fresh M0 install "connects but cannot ping".
pub fn forwarding_hint(platform: Platform) -> &'static str {
    match platform {
        Platform::Linux => {
            "IPv4 forwarding is off, so devices can reach this server but not each other. \
             Turn it on now with `sysctl -w net.ipv4.ip_forward=1`, and keep it across \
             reboots with `echo net.ipv4.ip_forward=1 > /etc/sysctl.d/99-anago.conf`"
        }
        Platform::MacOs => {
            "IPv4 forwarding is off, so devices can reach this server but not each other. \
             Turn it on with `sysctl -w net.inet.ip.forwarding=1` (macOS resets this on reboot)"
        }
        Platform::Other => {
            "IPv4 forwarding is off, so devices can reach this server but not each other. \
             Enable IP forwarding for this host"
        }
    }
}

/// Where Linux exposes the forwarding flag.
pub const IP_FORWARD_PROC: &str = "/proc/sys/net/ipv4/ip_forward";

/// Reads the forwarding flag, or `None` where this host does not expose
/// it the way we know how to read.
///
/// **Human verification needed** on macOS, where the value comes from
/// `sysctl` rather than a file.
pub fn read_forwarding() -> Option<bool> {
    std::fs::read_to_string(IP_FORWARD_PROC)
        .ok()
        .map(|value| forwarding_is_enabled(&value))
}

/// Prints the hint when the kernel is not forwarding.
///
/// Called after every successful apply and at server start: a hub that
/// is not forwarding looks perfectly healthy — devices connect, the
/// handshake completes — right up until two of them try to reach each
/// other. Saying nothing would leave the operator debugging WireGuard
/// for a sysctl.
///
/// Where the flag cannot be read (no `/proc`, e.g. macOS) nothing is
/// printed rather than a guess.
pub fn warn_if_forwarding_is_off(platform: Platform) {
    if read_forwarding() == Some(false) {
        eprintln!("anago: {}", forwarding_hint(platform));
    }
}

/// Applies state changes to a real interface.
pub trait Applier: Send + Sync {
    /// Regenerates the config and pushes it to the kernel.
    fn apply(&self, state: &ServerState) -> Result<(), WgError>;
}

/// The real thing: writes the file, then syncs or brings the interface
/// up.
#[derive(Debug)]
pub struct WgApplier {
    pub interface: Interface,
    /// The config text of the last *successful* apply. `None` after a
    /// failure, which is what makes the next attempt retry instead of
    /// deciding the file already looks right.
    /// The last text handed to the interface. Kept as [`SecretText`]
    /// rather than `String` because it is the server config, private
    /// key and all, and this struct derives `Debug` (§7.3).
    last_applied: Mutex<Option<SecretText>>,
    platform: Platform,
}

impl WgApplier {
    pub fn new(interface: Interface) -> WgApplier {
        WgApplier {
            interface,
            last_applied: Mutex::new(None),
            platform: wg::platform_from(std::env::consts::OS),
        }
    }

    /// Whether `wg show <iface>` finds the interface.
    fn interface_is_up(&self) -> bool {
        wg::run(&wg::show_dump(&self.interface.name), None).is_ok()
    }
}

impl Applier for WgApplier {
    /// **Human verification needed**: this runs `wg-quick`/`wg` and
    /// needs root and a kernel with WireGuard. The decisions it makes —
    /// what to write, sync versus bring-up — are unit-tested above.
    fn apply(&self, state: &ServerState) -> Result<(), WgError> {
        let wanted = wgconf::server_config(state);
        write_config(state, &self.interface.config_path)?;

        let action = {
            let last_applied = self.last_applied.lock().expect("applier mutex");
            plan(
                self.interface_is_up(),
                last_applied.as_ref().map(SecretText::expose),
                wanted.expose(),
            )
        };
        let Some(action) = action else {
            return Ok(());
        };

        match action {
            Action::BringUp => {
                wg::run(&wg::quick_up(&self.interface.config_path), None)?;
            }
            Action::Sync => {
                // `wg` does not understand wg-quick's keys, so the file
                // goes through `wg-quick strip` first. The stripped copy
                // holds the server's private key, so it is written 0600
                // and removed straight after. Callers hold the state
                // lock across this, so two applies never share the path.
                let stripped = wg::run(&wg::quick_strip(&self.interface.config_path), None)?;
                let path = self.interface.config_path.with_extension("stripped");
                fsutil::write_private(&path, &stripped).map_err(|e| WgError::Spawn {
                    line: format!("write {}", path.display()),
                    source: e.to_string(),
                })?;
                let result = wg::run(&wg::syncconf(&self.interface.name, &path), None);
                let _ = std::fs::remove_file(&path);
                result?;
            }
        }

        // Recorded only now: a failure above leaves `None`, so the next
        // apply tries again even though the file is already correct.
        *self.last_applied.lock().expect("applier mutex") = Some(wanted);
        warn_if_forwarding_is_off(self.platform);
        Ok(())
    }
}

/// An applier that does nothing, for tests that must not touch the
/// kernel. The program itself always has a real interface to keep in
/// step — `--no-systemd` changes who starts the server, not whether
/// WireGuard is configured.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct NoopApplier;

#[cfg(test)]
impl Applier for NoopApplier {
    fn apply(&self, _state: &ServerState) -> Result<(), WgError> {
        Ok(())
    }
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.config_path.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::Ipv4Addr;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU32, Ordering};

    use anago_core::name::DeviceName;
    use anago_core::state::{Peer, PrivateKey, ServerKeys, Tls};
    use anago_core::subnet::Subnet;
    use anago_core::token::TokenHash;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> TempDir {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("anago-wgapply-{}-{unique}", std::process::id()));
            fs::create_dir_all(&path).expect("temp dir");
            TempDir { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
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
                address: "10.100.0.1".parse::<Ipv4Addr>().unwrap(),
            },
            peers,
            codes: Vec::new(),
        }
    }

    fn peer(name: &str, address: &str) -> Peer {
        Peer {
            name: DeviceName::parse(name).unwrap(),
            public_key: "cGVlciBwdWJsaWMga2V5".to_string(),
            address: address.parse().unwrap(),
            token_hash: TokenHash::parse(&"ab".repeat(32)).unwrap(),
            created_at: 1_755_500_000,
            last_seen: None,
        }
    }

    #[test]
    #[cfg(unix)] // exercises unix modes/ownership/symlinks
    fn the_config_is_written_from_the_state() {
        let dir = TempDir::new();
        let path = dir.path.join("anago.conf");
        let state = state(vec![peer("macbook", "10.100.0.2")]);

        assert!(write_config(&state, &path).unwrap());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            wgconf::server_config(&state).expose()
        );
        // It holds the server's private key, so it is private.
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn an_unchanged_state_does_not_touch_the_interface() {
        // A refused join or a `rm` of nothing must not disturb live
        // tunnels.
        let dir = TempDir::new();
        let path = dir.path.join("anago.conf");
        let state = state(vec![peer("macbook", "10.100.0.2")]);

        assert!(write_config(&state, &path).unwrap(), "first write");
        assert!(!write_config(&state, &path).unwrap(), "identical state");

        let mut changed = state.clone();
        changed.peers.push(peer("desktop", "10.100.0.3"));
        assert!(
            write_config(&changed, &path).unwrap(),
            "a new peer changes it"
        );
        assert!(fs::read_to_string(&path).unwrap().contains("10.100.0.3/32"));

        // And removing one changes it back.
        assert!(write_config(&state, &path).unwrap());
        assert!(!fs::read_to_string(&path).unwrap().contains("10.100.0.3/32"));
    }

    #[test]
    fn a_running_interface_is_synced_rather_than_restarted() {
        // `wg-quick down`/`up` would drop every established tunnel.
        assert_eq!(plan(true, Some("old"), "new"), Some(Action::Sync));
        // Down is the only reason to bring the interface up.
        assert_eq!(plan(false, Some("new"), "new"), Some(Action::BringUp));
    }

    #[test]
    fn a_failed_apply_is_retried_even_though_the_file_is_correct() {
        // The file is written before the kernel is touched, so "file
        // matches state" is true after a failure too. Only a recorded
        // successful apply may skip the work.
        let config = "[Interface]\n";
        assert_eq!(plan(true, None, config), Some(Action::Sync));
        assert_eq!(plan(true, Some("older config"), config), Some(Action::Sync));
        assert_eq!(
            plan(true, Some(config), config),
            None,
            "steady state does nothing"
        );
    }

    #[test]
    fn an_interface_that_went_down_is_brought_back_up() {
        // A reboot or a stray `wg-quick down` leaves the file matching
        // and the last apply recorded; the kernel still has nothing.
        let config = "[Interface]\n";
        assert_eq!(plan(false, Some(config), config), Some(Action::BringUp));
        assert_eq!(plan(false, None, config), Some(Action::BringUp));
    }

    #[test]
    fn forwarding_is_read_from_either_shape_of_output() {
        assert!(forwarding_is_enabled("1"));
        assert!(forwarding_is_enabled("1\n"));
        assert!(forwarding_is_enabled("net.inet.ip.forwarding: 1\n"));
        assert!(!forwarding_is_enabled("0"));
        assert!(!forwarding_is_enabled("0\n"));
        assert!(!forwarding_is_enabled("net.ipv4.ip_forward = 0"));
        assert!(!forwarding_is_enabled(""));
        assert!(!forwarding_is_enabled("yes"));
    }

    #[test]
    fn the_forwarding_hint_says_what_breaks_and_how_to_fix_it() {
        // The most likely reason a fresh install "connects but cannot
        // ping": every hint has to name both halves.
        for platform in [Platform::Linux, Platform::MacOs, Platform::Other] {
            let hint = forwarding_hint(platform);
            assert!(hint.contains("not each other"), "{hint}");
        }
        assert!(forwarding_hint(Platform::Linux).contains("net.ipv4.ip_forward=1"));
        assert!(
            forwarding_hint(Platform::Linux).contains("/etc/sysctl.d/"),
            "must survive reboot"
        );
        assert!(forwarding_hint(Platform::MacOs).contains("net.inet.ip.forwarding=1"));
    }

    #[test]
    fn the_noop_applier_leaves_everything_alone() {
        let dir = TempDir::new();
        let path = dir.path.join("anago.conf");
        NoopApplier.apply(&state(Vec::new())).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn an_interface_prints_as_name_and_file() {
        let interface = Interface {
            name: "anago".to_string(),
            config_path: PathBuf::from("/etc/wireguard/anago.conf"),
        };
        assert_eq!(interface.to_string(), "anago (/etc/wireguard/anago.conf)");
    }
}
