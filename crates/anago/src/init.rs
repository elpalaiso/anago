//! `anago server init` (DESIGN.md §6.1, §11).
//!
//! M0 does the parts that need no third party: keys, the state file,
//! and the two things the operator must do by hand — point DNS at this
//! machine and open the ports. ACME and the Cloudflare API arrive in
//! M1, so what would be automation here is instructions instead.
//!
//! The text of those instructions is a pure function of the state, and
//! so is the state itself. Only [`run`] touches disk, the network, or
//! `wg`.

use std::fmt;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};

use anago_core::code::{IssuedCode, JoinCode, DEFAULT_TTL_SECS};
use anago_core::state::{PrivateKey, ServerKeys, ServerState};
use anago_core::wgconf;

use crate::cli::ServerInit;
use crate::fsutil;
use crate::paths::{self, ServerPaths};
use crate::secret;
use crate::systemd;
use crate::wg::{self, WgError};

/// Builds the initial state. Pure — the keys, the clock, and the code
/// come from the caller.
pub fn build_state(
    args: &ServerInit,
    keys: (PrivateKey, String),
    code: JoinCode,
    now: i64,
) -> ServerState {
    let (private_key, public_key) = keys;
    ServerState {
        domain: args.domain.clone(),
        subnet: args.subnet,
        listen_port: args.listen_port,
        api_port: args.api_port,
        tls_cert_path: args.tls_cert.clone(),
        tls_key_path: args.tls_key.clone(),
        server: ServerKeys {
            private_key,
            public_key,
            // The hub is always the subnet's .1 (§5).
            address: args.subnet.server_address(),
        },
        peers: Vec::new(),
        // The first code is issued here so `server init` ends with a
        // line the operator can paste on their laptop (§6.1 step 5).
        codes: vec![IssuedCode::issue(code, now, DEFAULT_TTL_SECS)],
    }
}

/// What to print when the state file is written: what the operator must
/// still do, and how to add the first device.
///
/// `public_ip` is best-effort. When the lookup failed, the A record
/// line keeps a placeholder instead of inventing an address — a wrong
/// IP in a copy-pasteable instruction is worse than an obvious blank.
pub fn instructions(state: &ServerState, public_ip: Option<Ipv4Addr>, ttl_secs: i64) -> String {
    let domain = &state.domain;
    let address = match public_ip {
        Some(ip) => ip.to_string(),
        None => "<this server's public IP>".to_string(),
    };
    let code = state
        .codes
        .last()
        .map(|issued| issued.code.to_string())
        .unwrap_or_default();
    let minutes = ttl_secs / 60;

    let mut out = String::new();
    out.push_str(&format!(
        "anago is set up for {domain}. Two things are still yours to do:\n\n"
    ));

    out.push_str("1. DNS — point the domain at this machine:\n\n");
    out.push_str(&format!("     {domain}.  A  {address}\n\n"));
    if public_ip.is_none() {
        out.push_str(
            "   (anago could not work out this machine's public address; use the one\n\
             \x20   your provider shows.)\n\n",
        );
    } else {
        out.push_str(
            "   (that is the address this machine sends traffic from; if the server is\n\
             \x20   behind NAT, use the public address your provider shows instead.)\n\n",
        );
    }

    out.push_str("2. Firewall — open these, or nothing can reach the hub:\n\n");
    out.push_str(&format!(
        "     {}/tcp   control API (HTTPS)\n",
        state.api_port
    ));
    out.push_str(&format!("     {}/udp WireGuard\n\n", state.listen_port));

    out.push_str("Then add a device — run this on it:\n\n");
    out.push_str(&format!("     anago join {domain} {code}\n\n"));
    out.push_str(&format!(
        "That code is single use and expires in {minutes} minutes; \
         `anago code` issues another.\n"
    ));
    out
}

/// This machine's outbound address, when that address is one the world
/// could actually reach.
///
/// No packet is sent: connecting a UDP socket only fixes which local
/// address the kernel would use for that destination. On a plain VPS
/// that is the public address — but on AWS, GCP, and anything else that
/// 1:1 NATs a public address onto a private NIC, it is a `10.x` the
/// operator must not put in DNS. Those are filtered out by
/// [`routable_address`], so the instructions fall back to a placeholder
/// rather than printing a pasteable lie.
pub fn detect_public_ip() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    match socket.local_addr().ok()? {
        std::net::SocketAddr::V4(addr) => routable_address(*addr.ip()),
        std::net::SocketAddr::V6(_) => None,
    }
}

/// Keeps only addresses that can appear in a public A record.
///
/// Pure, so every range below is a test rather than a claim.
pub fn routable_address(ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let [a, b, ..] = ip.octets();
    let carrier_grade_nat = a == 100 && (64..=127).contains(&b);
    let reserved = ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || ip.is_unspecified()
        || carrier_grade_nat
        || a == 0
        || a >= 240;
    if reserved {
        None
    } else {
        Some(ip)
    }
}

/// What `server init` produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Initialized {
    pub instructions: String,
    /// Non-fatal notes about the certificate files, from [`tls::load`].
    pub warnings: Vec<String>,
}

/// Runs the command: check, validate, generate, publish, explain.
///
/// The order is the point. Everything that can refuse — an existing
/// hub, a certificate that will not load, missing tools — happens
/// before a single file is written, and the state file is published
/// last, because its existence is what "already initialized" means.
///
/// **Human verification needed** for the parts that need a real
/// machine: `wg genkey`, writing under `/var/lib` and `/etc/wireguard`,
/// and whether the detected address is really this server's public one.
pub fn run(
    args: &ServerInit,
    root: &Path,
    wg_dir: &Path,
    now: i64,
) -> Result<Initialized, InitError> {
    check_not_initialized(root, wg_dir)?;

    // Before anything permanent: M0 serves with a certificate the
    // operator already has, so a bad path or a mismatched pair is a
    // refusal, not something to discover at first start — by which
    // time a half-made hub would block the retry.
    let loaded = crate::tls::load(Path::new(&args.tls_cert), Path::new(&args.tls_key))
        .map_err(InitError::Tls)?;

    wg::check_tools_from_env().map_err(InitError::Wg)?;
    let keys = wg::generate_keypair().map_err(InitError::Wg)?;
    let code = secret::new_join_code().map_err(|e| InitError::Io {
        what: "read /dev/urandom",
        kind: e.kind(),
        source: e.to_string(),
    })?;
    let state = build_state(args, keys, code, now);

    publish_once(&state, root, wg_dir)?;

    let mut warnings = loaded.warnings;
    // No systemd on this host means no unit to install, whatever the
    // flag says — offering one would leave a file nothing reads.
    let start = if args.systemd && systemd::is_available() {
        match systemd::install(
            &std::env::current_exe().unwrap_or_else(|_| PathBuf::from("anago")),
            root,
            wg_dir,
            Path::new(&args.tls_cert),
            Path::new(&args.tls_key),
            Path::new(systemd::UNIT_DIR),
        ) {
            Ok(path) => systemd_note(&path),
            Err(e) => {
                // The hub is configured either way; only the babysitter
                // is missing, and the operator can still run it by hand.
                warnings.push(format!("could not install the systemd unit: {e}"));
                foreground_hint()
            }
        }
    } else {
        foreground_hint()
    };

    Ok(Initialized {
        instructions: assemble(
            &instructions(&state, detect_public_ip(), DEFAULT_TTL_SECS),
            &start,
        ),
        warnings,
    })
}

/// The finished output: what the operator must do, then how this hub
/// starts. Exactly one start note, so nothing can contradict it.
pub fn assemble(instructions: &str, start_note: &str) -> String {
    format!("{instructions}\n{start_note}")
}

/// What `server init` says when systemd took over.
pub fn systemd_note(unit_path: &Path) -> String {
    format!(
        "The hub is running under systemd ({}) and comes back on reboot.\n\
         `systemctl status anago` shows it, `journalctl -u anago` its log.\n",
        unit_path.display()
    )
}

/// What to run when nothing will run it for you — `--no-systemd`, a
/// container, or a failed unit install.
pub fn foreground_hint() -> String {
    "Start the hub with:\n\n     anago server run\n\n     It stays in the foreground; nothing keeps it alive across a reboot.\n"
        .to_string()
}

/// Refuses when either output is already there.
///
/// Checking the wg config too: overwriting a live `anago.conf` would
/// take down whatever interface it describes, and it may not even be
/// anago's.
pub fn check_not_initialized(root: &Path, wg_dir: &Path) -> Result<(), InitError> {
    let state_file = ServerPaths::new(root).state_file();
    if state_file.exists() {
        return Err(InitError::AlreadyInitialized(
            state_file.display().to_string(),
        ));
    }
    let config_path = paths::wg_config(wg_dir);
    if config_path.exists() {
        return Err(InitError::ConfigExists(config_path.display().to_string()));
    }
    Ok(())
}

/// Checks and publishes under one lock, so exactly one `server init`
/// can win.
///
/// The earlier [`check_not_initialized`] is a courtesy — it fails fast
/// before generating keys. This is the one that decides: two inits
/// racing would both pass an unlocked check, generate different keys,
/// and the later writer would re-key a hub the earlier one had already
/// finished.
pub fn publish_once(state: &ServerState, root: &Path, wg_dir: &Path) -> Result<(), InitError> {
    // The lock lives beside the state file, so the directory has to
    // exist first. An empty directory is not a hub — the state file is.
    fsutil::ensure_private_dir(root).map_err(|e| InitError::Io {
        what: "create the state directory",
        kind: e.kind(),
        source: e.to_string(),
    })?;
    let lock_path = ServerPaths::new(root).state_lock();
    let _lock = fsutil::FileLock::acquire(&lock_path).map_err(|e| InitError::Io {
        what: "take the initialization lock",
        kind: e.kind(),
        source: e.to_string(),
    })?;

    check_not_initialized(root, wg_dir)?;
    publish(state, root, wg_dir)
}

/// Writes both files, state last, and removes what it created if the
/// second write fails.
///
/// The state file is the marker for "this machine is a hub", so it must
/// not exist unless the wg config beside it does. Both are published
/// with [`fsutil::create_new_private`], which refuses to replace an
/// existing file — so a config that appeared after the check belongs to
/// somebody else, is left alone, and is never rolled back by us.
pub fn publish(state: &ServerState, root: &Path, wg_dir: &Path) -> Result<(), InitError> {
    fsutil::ensure_private_dir(wg_dir).map_err(|e| InitError::Io {
        what: "create the WireGuard directory",
        kind: e.kind(),
        source: e.to_string(),
    })?;
    let config_path = paths::wg_config(wg_dir);
    fsutil::create_new_private(&config_path, &wgconf::server_config(state)).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            InitError::ConfigExists(config_path.display().to_string())
        } else {
            InitError::Io {
                what: "write the WireGuard config",
                kind: e.kind(),
                source: e.to_string(),
            }
        }
    })?;

    let published = fsutil::ensure_private_dir(root)
        .map_err(|e| InitError::Io {
            what: "create the state directory",
            kind: e.kind(),
            source: e.to_string(),
        })
        .and_then(|()| {
            let state_file = ServerPaths::new(root).state_file();
            fsutil::create_new_private(&state_file, &state.to_json_string()).map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    InitError::AlreadyInitialized(state_file.display().to_string())
                } else {
                    InitError::Io {
                        what: "write the state file",
                        kind: e.kind(),
                        source: e.to_string(),
                    }
                }
            })
        });

    if published.is_err() {
        // Only the config this call created: anything that was already
        // there made `create_new_private` fail above, so we never get
        // here holding somebody else's file.
        let _ = std::fs::remove_file(&config_path);
    }
    published
}

/// Why `server init` could not finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitError {
    /// A state file is already there.
    AlreadyInitialized(String),
    /// A WireGuard config with anago's name is already there.
    ConfigExists(String),
    /// The certificate and key could not be loaded.
    Tls(crate::tls::TlsError),
    /// The WireGuard tools are missing, or one of them failed.
    Wg(WgError),
    Io {
        what: &'static str,
        kind: std::io::ErrorKind,
        source: String,
    },
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InitError::AlreadyInitialized(path) => write!(
                f,
                "this machine is already a hub — {path} exists. \
                 Remove it to start over, but every registered device \
                 will have to join again"
            ),
            InitError::ConfigExists(path) => write!(
                f,
                "{path} already exists — anago will not overwrite a WireGuard \
                 config it did not write. Move it aside first"
            ),
            InitError::Tls(e) => write!(f, "{e}"),
            InitError::Wg(e) => write!(f, "{e}"),
            InitError::Io { what, kind, source } => f.write_str(&crate::diagnostics::with_advice(
                format!("could not {what}: {source}"),
                *kind,
            )),
        }
    }
}

impl std::error::Error for InitError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use anago_core::subnet::Subnet;

    const NOW: i64 = 1_755_500_000;

    fn args() -> ServerInit {
        ServerInit {
            domain: "net.example.com".to_string(),
            tls_cert: "/etc/ssl/anago/fullchain.pem".to_string(),
            tls_key: "/etc/ssl/anago/privkey.pem".to_string(),
            subnet: Subnet::parse("10.100.0.0/24").unwrap(),
            listen_port: 51820,
            api_port: 443,
            systemd: true,
        }
    }

    fn keys() -> (PrivateKey, String) {
        (
            PrivateKey::new("c2VydmVyIHByaXZhdGU="),
            "c2VydmVyIHB1YmxpYw==".to_string(),
        )
    }

    fn state_from(args: &ServerInit) -> ServerState {
        build_state(args, keys(), JoinCode::parse("7QX4-M2KD").unwrap(), NOW)
    }

    #[test]
    fn the_initial_state_is_the_server_and_one_code() {
        let state = state_from(&args());
        assert_eq!(state.domain, "net.example.com");
        assert_eq!(
            state.server.address,
            "10.100.0.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(state.server.public_key, "c2VydmVyIHB1YmxpYw==");
        assert_eq!(state.tls_cert_path, "/etc/ssl/anago/fullchain.pem");
        assert!(state.peers.is_empty(), "a fresh hub has no devices");

        // One live code, so init can end with a join line (§6.1).
        assert_eq!(state.codes.len(), 1);
        assert_eq!(state.codes[0].issued_at, NOW);
        assert_eq!(state.codes[0].expires_at, NOW + DEFAULT_TTL_SECS);
        assert_eq!(state.codes[0].used_at, None);
        assert!(state.codes[0].is_usable(NOW));
    }

    #[test]
    fn the_server_address_follows_the_subnet() {
        let mut args = args();
        args.subnet = Subnet::parse("192.168.7.0/24").unwrap();
        let state = state_from(&args);
        assert_eq!(
            state.server.address,
            "192.168.7.1".parse::<Ipv4Addr>().unwrap()
        );
        // And the state round-trips, so init writes something readable.
        assert_eq!(ServerState::parse(&state.to_json_string()).unwrap(), state);
    }

    #[test]
    fn the_instructions_carry_the_dns_record_to_add() {
        let state = state_from(&args());
        let text = instructions(
            &state,
            Some("203.0.113.7".parse().unwrap()),
            DEFAULT_TTL_SECS,
        );
        assert!(text.contains("net.example.com.  A  203.0.113.7"), "{text}");
        assert!(
            text.contains("behind NAT"),
            "the address is a guess: {text}"
        );
    }

    #[test]
    fn a_failed_lookup_leaves_a_blank_rather_than_a_wrong_address() {
        let state = state_from(&args());
        let text = instructions(&state, None, DEFAULT_TTL_SECS);
        assert!(text.contains("A  <this server's public IP>"), "{text}");
        assert!(text.contains("could not work out"), "{text}");
        // Nothing that looks like an address it made up.
        assert!(!text.contains("0.0.0.0"), "{text}");
    }

    #[test]
    fn the_instructions_list_both_ports() {
        let state = state_from(&args());
        let text = instructions(&state, None, DEFAULT_TTL_SECS);
        assert!(text.contains("443/tcp"), "{text}");
        assert!(text.contains("51820/udp"), "{text}");
        assert!(text.contains("nothing can reach the hub"), "{text}");

        // And they follow the flags, not the defaults.
        let mut args = args();
        args.api_port = 8443;
        args.listen_port = 51999;
        let text = instructions(&state_from(&args), None, DEFAULT_TTL_SECS);
        assert!(text.contains("8443/tcp"), "{text}");
        assert!(text.contains("51999/udp"), "{text}");
    }

    #[test]
    fn the_instructions_end_with_a_line_to_paste_on_the_device() {
        let state = state_from(&args());
        let text = instructions(&state, None, DEFAULT_TTL_SECS);
        assert!(
            text.contains("anago join net.example.com 7QX4-M2KD"),
            "{text}"
        );
        assert!(
            text.contains("single use and expires in 15 minutes"),
            "{text}"
        );
        assert!(text.contains("`anago code` issues another"), "{text}");
    }

    #[test]
    fn without_systemd_the_operator_is_told_what_to_run() {
        // `--no-systemd` is for containers and non-systemd hosts: the
        // hub is configured, but nothing will start it.
        let hint = foreground_hint();
        assert!(hint.contains("anago server run"), "{hint}");
        assert!(hint.contains("across a reboot"), "{hint}");
    }

    #[test]
    fn the_output_says_exactly_one_thing_about_starting() {
        // Regression: a fixed "not running yet" line used to follow the
        // real answer, contradicting the systemd case and denying the
        // command the foreground case had just recommended.
        let state = state_from(&args());
        let base = instructions(&state, None, DEFAULT_TTL_SECS);

        let under_systemd = assemble(
            &base,
            &systemd_note(Path::new("/etc/systemd/system/anago.service")),
        );
        assert!(
            under_systemd.contains("running under systemd"),
            "{under_systemd}"
        );
        assert!(
            under_systemd.contains("systemctl status anago"),
            "{under_systemd}"
        );
        assert!(
            !under_systemd.contains("not running yet"),
            "{under_systemd}"
        );
        assert!(
            !under_systemd.contains("Start the hub with"),
            "one start note only: {under_systemd}"
        );

        let by_hand = assemble(&base, &foreground_hint());
        assert!(by_hand.contains("anago server run"), "{by_hand}");
        assert!(!by_hand.contains("running under systemd"), "{by_hand}");
        assert!(!by_hand.contains("next M0 slice"), "{by_hand}");

        // Both keep everything the operator still has to do.
        for text in [&under_systemd, &by_hand] {
            assert!(text.contains("A  <this server's public IP>"), "{text}");
            assert!(text.contains("51820/udp"), "{text}");
            assert!(
                text.contains("anago join net.example.com 7QX4-M2KD"),
                "{text}"
            );
        }
    }

    #[test]
    fn a_second_init_is_refused_before_anything_is_generated() {
        // Re-keying a live hub would strand every registered device.
        let e = InitError::AlreadyInitialized("/var/lib/anago/state.json".to_string());
        let message = e.to_string();
        assert!(message.contains("/var/lib/anago/state.json"), "{message}");
        assert!(message.contains("join again"), "{message}");
    }

    #[test]
    fn init_errors_say_which_step_failed() {
        let e = InitError::Io {
            what: "write the state file",
            kind: std::io::ErrorKind::PermissionDenied,
            source: "Permission denied (os error 13)".to_string(),
        };
        // The step, the cause, and — for this cause — what to do.
        assert!(
            e.to_string().starts_with("could not write the state file"),
            "{e}"
        );
        assert!(e.to_string().contains("run this as root"), "{e}");
    }

    // ------------------------------------------------ publishing

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> TempDir {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("anago-init-{}-{unique}", std::process::id()));
            std::fs::create_dir_all(&path).expect("temp dir");
            TempDir { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn publishing_writes_the_config_and_the_state() {
        let dir = TempDir::new();
        let root = dir.path.join("var");
        let wg_dir = dir.path.join("wireguard");
        let state = state_from(&args());

        publish_once(&state, &root, &wg_dir).unwrap();
        assert_eq!(
            std::fs::read_to_string(paths::wg_config(&wg_dir)).unwrap(),
            wgconf::server_config(&state)
        );
        assert_eq!(
            Store::new(&root).read().unwrap(),
            state,
            "the state file is what a later run reads"
        );
        // A finished hub answers "already initialized" to a second run.
        assert!(check_not_initialized(&root, &wg_dir).is_err());
    }

    #[test]
    fn a_failed_state_write_leaves_nothing_behind() {
        // Regression: the state file used to be written first, so a
        // later failure left a marker that blocked every retry — while
        // a failure after it left a hub with no interface config.
        let dir = TempDir::new();
        let wg_dir = dir.path.join("wireguard");
        // A regular file where the state directory must go: creating it
        // fails, after the config has already been written.
        let blocker = dir.path.join("blocked");
        std::fs::write(&blocker, "not a directory").unwrap();
        let root = blocker.join("anago");

        let e = publish(&state_from(&args()), &root, &wg_dir).unwrap_err();
        assert!(matches!(e, InitError::Io { .. }), "{e:?}");
        assert!(
            !paths::wg_config(&wg_dir).exists(),
            "the config must be rolled back so the next run can retry"
        );
        assert!(
            check_not_initialized(&root, &wg_dir).is_ok(),
            "a retry is possible"
        );
    }

    #[test]
    fn an_existing_hub_or_config_stops_the_run_before_anything_happens() {
        let dir = TempDir::new();
        let root = dir.path.join("var");
        let wg_dir = dir.path.join("wireguard");
        assert!(check_not_initialized(&root, &wg_dir).is_ok());

        // Someone else's anago.conf is not ours to replace.
        std::fs::create_dir_all(&wg_dir).unwrap();
        std::fs::write(paths::wg_config(&wg_dir), "[Interface]\n").unwrap();
        let e = check_not_initialized(&root, &wg_dir).unwrap_err();
        assert!(matches!(e, InitError::ConfigExists(_)), "{e:?}");
        assert!(e.to_string().contains("did not write"), "{e}");

        // An existing state file wins, since it is the hub marker.
        std::fs::create_dir_all(&root).unwrap();
        Store::new(&root).write(&state_from(&args())).unwrap();
        let e = check_not_initialized(&root, &wg_dir).unwrap_err();
        assert!(matches!(e, InitError::AlreadyInitialized(_)), "{e:?}");
    }

    #[test]
    fn only_a_reachable_address_is_offered_for_dns() {
        // The common VPS shape this gets wrong: a public address 1:1
        // NATed onto a private NIC, where the local address is a lie.
        for private in [
            "10.0.0.5",
            "172.16.0.5",
            "172.31.255.254",
            "192.168.7.2",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
        ] {
            assert_eq!(
                routable_address(private.parse().unwrap()),
                None,
                "{private} must not reach an A record"
            );
        }
        for public in [
            "5.6.7.8",
            "1.1.1.1",
            "93.184.216.34",
            "172.32.0.1",
            "100.128.0.1",
        ] {
            let ip = public.parse().unwrap();
            assert_eq!(routable_address(ip), Some(ip), "{public} is routable");
        }
    }

    #[test]
    fn exactly_one_of_two_racing_inits_wins() {
        // Regression: check and publish used to be separate steps with
        // nothing between them, so both runs passed the check,
        // generated different keys, and the later writer re-keyed a hub
        // the earlier one had already finished.
        let dir = TempDir::new();
        let root = dir.path.join("var");
        let wg_dir = dir.path.join("wireguard");

        let mut first = args();
        first.domain = "first.example.com".to_string();
        let mut second = args();
        second.domain = "second.example.com".to_string();

        let outcomes: Vec<Result<(), InitError>> = std::thread::scope(|scope| {
            let handles: Vec<_> = [state_from(&first), state_from(&second)]
                .into_iter()
                .map(|state| {
                    let root = root.clone();
                    let wg_dir = wg_dir.clone();
                    scope.spawn(move || publish_once(&state, &root, &wg_dir))
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        let winners = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
        assert_eq!(winners, 1, "{outcomes:?}");
        let loser = outcomes.iter().find(|outcome| outcome.is_err()).unwrap();
        assert!(
            matches!(
                loser,
                Err(InitError::AlreadyInitialized(_)) | Err(InitError::ConfigExists(_))
            ),
            "{loser:?}"
        );

        // The two files describe the same hub — the winner's.
        let stored = Store::new(&root).read().unwrap();
        let config = std::fs::read_to_string(paths::wg_config(&wg_dir)).unwrap();
        assert_eq!(config, wgconf::server_config(&stored));
        assert!(
            ["first.example.com", "second.example.com"].contains(&stored.domain.as_str()),
            "{}",
            stored.domain
        );
    }

    #[test]
    fn a_config_that_appears_after_the_check_is_left_alone() {
        // Somebody else's anago.conf must survive, and must not be
        // swept up by our rollback.
        let dir = TempDir::new();
        let root = dir.path.join("var");
        let wg_dir = dir.path.join("wireguard");
        std::fs::create_dir_all(&wg_dir).unwrap();
        std::fs::write(paths::wg_config(&wg_dir), "not ours\n").unwrap();

        let e = publish(&state_from(&args()), &root, &wg_dir).unwrap_err();
        assert!(matches!(e, InitError::ConfigExists(_)), "{e:?}");
        assert_eq!(
            std::fs::read_to_string(paths::wg_config(&wg_dir)).unwrap(),
            "not ours\n"
        );
        assert!(
            !ServerPaths::new(&root).state_file().exists(),
            "no hub was published"
        );
    }
}
