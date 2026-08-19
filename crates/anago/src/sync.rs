//! `anago sync` (DESIGN.md §6.3).
//!
//! On a device: read `device.json`, ask the hub for its peer list, and
//! act on the answer — which almost always means doing nothing. In
//! hub-and-spoke a device's config is one `AllowedIPs = <subnet>` line,
//! so another device joining changes nothing here; "pull the peer list
//! and update the config" ends in "nothing to update" nearly every
//! time, and that is the correct ending.
//!
//! The judgement is [`anago_core::sync::decide`]'s. What is left here
//! is the call, the two files, and — the part that needs the most care
//! — **which endings are worth a non-zero exit**. A timer runs this
//! every five minutes, and a laptop that is off the network is not a
//! failure; recording one would bury the 401 that matters under a
//! hundred that do not (§6.3).
//!
//! **Human verification needed** beyond the call and `wg`: this runs
//! as root over files in somebody's home, and the two things that
//! follow from that — the write landing back as *their* file, and a
//! renamed directory not redirecting it — can only be half-checked
//! without privileges (§13).
//!
//! Nothing here is destructive. Every ending that means "this device no
//! longer fits" stops and hands the person a cleanup: an unattended job
//! does not take somebody's tunnel down on its own.

use std::fmt;
use std::path::{Path, PathBuf};

use anago_core::json;
use anago_core::name::DeviceName;
use anago_core::proto::{PeersResponse, PATH_PEERS};
use anago_core::render;
use anago_core::state::PrivateKey;
use anago_core::subnet::Subnet;
use anago_core::sync::{Detachment, Local, Member, Reported, Sync};
use anago_core::token::DeviceToken;
use anago_core::wgconf::{self, ClientProfile};

use crate::client::{self, Method, Request};
use crate::join::DeviceConfig;
use crate::paths::{self, ClientPaths};
use crate::wg;

/// How a run ended, which is the same question as what to exit with.
///
/// §6.3 splits the endings in two, and the split is about journals
/// rather than about correctness: systemd records a non-zero exit as a
/// failed unit, so a laptop that spent the day on a café network would
/// file hundreds of them and bury the one a person has to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// Nothing needed doing, or it was done. Exit 0, and silent under
    /// `--quiet`.
    Fine,
    /// The hub was not reachable, or another run holds the lock.
    /// Ordinary for a laptop, so also exit 0 and also silent — a
    /// device that cannot sync still works (§6.3).
    Passed,
    /// A person has to do something: this device was removed, the
    /// device file is gone, TLS did not verify, the apply failed. Exit
    /// non-zero, and one line on stderr even when quiet.
    Stop,
}

impl Ending {
    pub fn exit_code(self) -> i32 {
        match self {
            Ending::Fine | Ending::Passed => 0,
            Ending::Stop => 1,
        }
    }
}

/// What a run produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Synced {
    pub ending: Ending,
    /// The line to print. Empty when `--quiet` swallowed it.
    pub report: String,
}

/// Which of the three endings an outcome deserves (§6.3's table).
///
/// Pure, and the reason a timer can be trusted: everything that is
/// merely inconvenient exits zero, and everything a person has to act
/// on does not.
pub fn ending_of(outcome: &Sync) -> Ending {
    match outcome {
        // Not "in sync", but nothing to do and nothing wrong: an M0
        // hub reports nothing to compare against, and reading absence
        // as difference would rewrite the config every five minutes.
        Sync::Unchanged | Sync::Unverifiable | Sync::Rewrite(_) => Ending::Fine,
        Sync::Detached(_) => Ending::Stop,
    }
}

/// The line a run prints, and whether `--quiet` keeps it.
///
/// Quiet keeps only what a person has to act on. That is what makes the
/// timer's unit file readable: it is silent for the ordinary case by
/// construction rather than by sniffing for a tty (§8).
///
/// A detachment carries the way back with it, **on the same line**.
/// "This device was removed" on its own is a dead end read every five
/// minutes, and a remedy on a second line is one a journal shows
/// somewhere else entirely (§6.3).
pub fn report(outcome: &Sync, hub: &Hub, quiet: bool) -> String {
    if quiet && ending_of(outcome) != Ending::Stop {
        return String::new();
    }
    let out = render::sync_summary(outcome, &hub.domain);
    let Sync::Detached(_) = outcome else {
        return out;
    };
    // **One line, reason and remedy together.** A journal entry is a
    // line; splitting this in two means `journalctl` shows the half
    // that says something is wrong beside a hundred other entries, and
    // the half that says what to do about it somewhere else (§6.3).
    format!(
        "{}. To use this device again: {}\n",
        out.trim_end(),
        render::rejoin_steps(&hub.wg_config, &hub.device_file)
    )
}

/// The three strings every report needs: which hub, and the two files
/// on this machine a person may have to clear away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hub {
    pub domain: String,
    pub wg_config: String,
    pub device_file: String,
}

/// Runs the command.
///
/// **Human verification needed**: makes a real HTTPS call and drives
/// `wg`.
pub fn run(config_path: Option<&Path>, wg_config: &Path, quiet: bool) -> Synced {
    match attempt(config_path, wg_config, quiet) {
        Ok(synced) => synced,
        Err(e) => Synced {
            ending: e.ending(),
            report: complaint(&e, quiet),
        },
    }
}

/// What a failure says, and whether `--quiet` keeps it.
///
/// **The same rule as [`report`], and it has to be.** A timer on a
/// laptop that spent the day elsewhere hits `Unreachable` every five
/// minutes; letting that through would be exactly the repeated noise
/// §6.3 asks the quiet form to swallow, and it would drown the one
/// line — a 401, a broken device file — that a person has to read.
pub fn complaint(e: &SyncError, quiet: bool) -> String {
    if quiet && e.ending() != Ending::Stop {
        return String::new();
    }
    format!("anago: {e}\n")
}

fn attempt(config_path: Option<&Path>, wg_config: &Path, quiet: bool) -> Result<Synced, SyncError> {
    let device_file = device_file(config_path)?;

    // **One handle, held from the read to the last write.** This
    // process is root and `device.json` is in somebody's home, so
    // checking a path and then using the path again is a race the
    // person who owns that path can win: rename `~/.config/anago`
    // between the two, point it at a symlink, and the write lands
    // wherever they chose. A descriptor cannot be redirected, so
    // everything below happens in the directory this open resolved —
    // the same rule `join` follows for the same reason (§13).
    let home = Home::open(&device_file)?;
    let config = home.read()?;
    let local = local_of(&config)?;

    // Held from before the call to after the last write. Two runs —
    // the timer coming round while somebody types the command — would
    // otherwise rewrite the same config and the same `device.json`
    // from two different answers, and share the one filename
    // `wg syncconf` is handed, so one could delete the file the other
    // was about to read. **Tried, not waited for**: a run that is
    // already happening is doing this run's work (§6.3).
    let _syncing = home.lock()?;

    let hub = Hub {
        domain: config.domain.clone(),
        wg_config: wg_config.display().to_string(),
        device_file: home.path().display().to_string(),
    };

    // A 401 is an ending, not a transport failure: the token died the
    // moment the hub removed this device (§7.1). Turning it into an
    // outcome here rather than an error is what puts it through the
    // same report — so "you were removed" arrives with the cleanup
    // beside it, exactly like the roster saying the same thing.
    let response = match ask_hub(&config) {
        Ok(response) => response,
        Err(SyncError::Detached(detachment)) => {
            let outcome = Sync::Detached(detachment);
            return Ok(Synced {
                ending: ending_of(&outcome),
                report: report(&outcome, &hub, quiet),
            });
        }
        Err(e) => return Err(e),
    };

    let reported = reported_of(&response)?;
    let outcome = anago_core::sync::decide(&local, reported.as_ref(), &roster_of(&response)?);

    if let Sync::Rewrite(_) = &outcome {
        // §6.3's order, and the order is the point: the config, then
        // the apply, then `device.json` — see `apply`.
        apply(&config, reported.as_ref(), wg_config, &home)?;
    }

    Ok(Synced {
        ending: ending_of(&outcome),
        report: report(&outcome, &hub, quiet),
    })
}

/// The directory `device.json` lives in, opened once.
///
/// Everything this command does to a user's files goes through here:
/// the read, the lock, and the write back. Two things follow from that
/// and neither is optional when a root timer is walking a path a person
/// controls.
///
/// **The directory cannot be swapped underneath it.** A held descriptor
/// resolves `openat` against the inode it already has, so a rename
/// between the read and the write changes nothing about where the write
/// goes (§13).
///
/// **The file goes back to whoever owned it.** `write_private` on its
/// own would create the replacement as root and rename it into place,
/// and from the next server change onwards a 0600 `device.json` would
/// belong to root — so `anago ls` and `anago rm`, which §9 promises a
/// person can run from their own shell, would stop being able to read
/// it.
struct Home {
    dir: crate::fsutil::DirHandle,
    name: String,
}

impl Home {
    fn open(device_file: &Path) -> Result<Home, SyncError> {
        let unusable = |detail: String| SyncError::NoDeviceFile {
            path: device_file.display().to_string(),
            detail,
        };
        let dir = device_file
            .parent()
            .ok_or_else(|| unusable("it has no directory".to_string()))?;
        let name = device_file
            .file_name()
            .ok_or_else(|| unusable("it has no file name".to_string()))?
            .to_string_lossy()
            .into_owned();
        Ok(Home {
            dir: crate::fsutil::DirHandle::open(dir).map_err(|e| unusable(e.to_string()))?,
            name,
        })
    }

    fn read(&self) -> Result<DeviceConfig, SyncError> {
        let text = self
            .dir
            .read_to_string(&self.name)
            .map_err(|e| SyncError::NoDeviceFile {
                path: self.path().display().to_string(),
                detail: e.to_string(),
            })?;
        DeviceConfig::parse(&text).map_err(|e| SyncError::DeviceFile(e.to_string()))
    }

    fn lock(&self) -> Result<crate::fsutil::FileLock, SyncError> {
        // A lock file this call creates belongs to whoever owns the
        // device file beside it, for the same reason the device file
        // itself does. One that is already there belongs to somebody
        // and is left alone.
        match self.dir.try_lock(paths::SYNC_LOCK, self.owner().ok()) {
            Ok(Some(lock)) => Ok(lock),
            Ok(None) => Err(SyncError::Busy),
            Err(e) => Err(SyncError::Write {
                path: self.dir.path().join(paths::SYNC_LOCK).display().to_string(),
                detail: e.to_string(),
            }),
        }
    }

    /// Who owns `device.json` now — read from the file rather than
    /// guessed from the environment, because a timer has no `SUDO_UID`
    /// and the file is right here.
    fn owner(&self) -> Result<(u32, u32), SyncError> {
        self.dir
            .owner_of(&self.name)
            .map_err(|e| SyncError::NoDeviceFile {
                path: self.path().display().to_string(),
                detail: e.to_string(),
            })
    }

    fn write(&self, config: &DeviceConfig) -> Result<(), SyncError> {
        let owner = self.owner()?;
        self.dir
            .write_private(&self.name, &config.to_json_string(), Some(owner))
            .map_err(|e| SyncError::Write {
                path: self.path().display().to_string(),
                detail: e.to_string(),
            })
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join(&self.name)
    }
}

/// Where `device.json` is.
///
/// `--config` wins outright. Without it the §9 rules apply, which need
/// a user session — which is exactly why a timer carries the path on
/// its command line instead (§8).
///
/// `--install-timer` resolves the path through this same function and
/// bakes the answer into the unit (§8). One resolver, so the file the
/// schedule reads is by construction the file a person's own
/// `anago sync` would have read.
pub fn device_file(config_path: Option<&Path>) -> Result<PathBuf, SyncError> {
    match config_path {
        Some(path) => Ok(path.to_path_buf()),
        None => paths::client_config_dir_from_env()
            .map(|paths: ClientPaths| paths.device_file())
            .map_err(|e| SyncError::DeviceFile(e.to_string())),
    }
}

/// What this device believes, from its own file. Pure.
pub fn local_of(config: &DeviceConfig) -> Result<Local, SyncError> {
    let field =
        |what: &'static str, detail: String| SyncError::DeviceFile(format!("{what}: {detail}"));
    Ok(Local {
        name: DeviceName::parse(&config.name).map_err(|e| field("name", e.to_string()))?,
        address: config.address.parse().map_err(|_| {
            field(
                "address",
                format!("{:?} is not an IPv4 address", config.address),
            )
        })?,
        subnet: Subnet::parse(&config.subnet).map_err(|e| field("subnet", e.to_string()))?,
        server_public_key: config.server_public_key.clone(),
        server_endpoint: config.server_endpoint.clone(),
        server_address: config.server_address.parse().map_err(|_| {
            field(
                "server_address",
                format!("{:?} is not an IPv4 address", config.server_address),
            )
        })?,
    })
}

/// What the hub said about itself, `None` from an M0 hub.
///
/// **Every value is checked before it is believed, exactly as `join`
/// checks the same four (§7).** TLS says the answer came from the hub;
/// it does not say the hub is well. These strings are about to be
/// rendered into a root-owned `wg-quick` config, and that format is a
/// list of directives — a `server_endpoint` of
/// `"net.example.com:51820\nPostUp = curl … | sh"` is a valid endpoint
/// followed by a command `wg-quick up` runs as root at the next reboot.
/// `wg-quick strip` would even drop the `PostUp` before `syncconf` saw
/// it, so the apply would succeed and the file and `device.json` would
/// both be committed with it in place.
///
/// Refusing here rather than at the write is deliberate: nothing
/// downstream — the comparison, the config, the device file — ever
/// holds a value that has not been through this.
///
/// Pure.
pub fn reported_of(response: &PeersResponse) -> Result<Option<Reported>, SyncError> {
    let Some(hub) = &response.hub else {
        return Ok(None);
    };
    let bad =
        |what: &'static str, detail: String| SyncError::BadResponse(format!("{what}: {detail}"));
    Ok(Some(Reported {
        subnet: Subnet::parse(&hub.subnet).map_err(|e| bad("subnet", e.to_string()))?,
        server_public_key: wg::parse_key(&hub.server_public_key)
            .map_err(|e| bad("server_public_key", e.to_string()))?,
        server_endpoint: crate::join::checked_endpoint(&hub.server_endpoint)
            .map_err(|e| bad("server_endpoint", e.to_string()))?,
        server_address: hub.server_address.parse().map_err(|_| {
            bad(
                "server_address",
                format!("{:?} is not an IPv4 address", hub.server_address),
            )
        })?,
    }))
}

/// The roster, reduced to what identifies a device. Pure.
pub fn roster_of(response: &PeersResponse) -> Result<Vec<Member>, SyncError> {
    response
        .peers
        .iter()
        .map(|peer| {
            Ok(Member {
                name: DeviceName::parse(&peer.name)
                    .map_err(|e| SyncError::BadResponse(format!("peer name: {e}")))?,
                address: peer.address.parse().map_err(|_| {
                    SyncError::BadResponse(format!("{:?} is not an IPv4 address", peer.address))
                })?,
            })
        })
        .collect()
}

/// `GET /api/v1/peers`.
///
/// **Human verification needed**: a real HTTPS call.
fn ask_hub(config: &DeviceConfig) -> Result<PeersResponse, SyncError> {
    let token = DeviceToken::parse(&config.token)
        .map_err(|e| SyncError::DeviceFile(format!("token: {e}")))?;
    let response = client::send(&Request {
        method: Method::Get,
        host: &config.domain,
        port: config.api_port(),
        path: PATH_PEERS,
        body: None,
        authorization: Some(&client::HeaderValue::device_token(&token)),
    })
    .map_err(unreachable_or_worse)?;

    if response.status == 401 {
        // The token died the moment the hub removed this device
        // (§7.1). Said, never repaired.
        return Err(SyncError::Detached(Detachment::Unauthorized));
    }
    if !response.is_success() {
        return Err(SyncError::Refused(
            client::describe(response.status, &response.body).message,
        ));
    }
    let value = json::parse(&response.body).map_err(|e| SyncError::BadResponse(e.to_string()))?;
    PeersResponse::from_json(&value).map_err(|e| SyncError::BadResponse(e.to_string()))
}

/// Sorts a call that did not come back into §6.3's two halves.
///
/// **Silence is for what goes away on its own.** §6.3 names the set:
/// DNS, a refused connection, a timeout — a laptop is usually
/// somewhere else and that is what hub-and-spoke is for, so recording
/// those as failures would fill a journal and bury the one line that
/// matters.
///
/// Everything else is said, because everything else is a thing a
/// person has to fix and a timer would otherwise hide for ever:
///
/// - **A certificate that does not verify** is trust, not reach. A
///   captive portal is the likely cause and the message says so first,
///   but a real interception looks identical, so it is never swallowed.
/// - **A hostname or a token that cannot be sent** is a `device.json`
///   that has been edited or corrupted. Waiting will not mend it.
/// - **An answer this client cannot read** — not HTTP, or larger than
///   it will hold — is a proxy in the way or a hub serving something
///   else. Retrying every five minutes finds the same thing.
fn unreachable_or_worse(e: client::ClientError) -> SyncError {
    match &e {
        // Went away by itself, or will.
        client::ClientError::Resolve { .. }
        | client::ClientError::Connect { .. }
        | client::ClientError::Timeout { .. }
        | client::ClientError::Io(_) => SyncError::Unreachable(e.to_string()),

        client::ClientError::Tls(_) | client::ClientError::NoRoots => {
            SyncError::Untrusted(e.to_string())
        }
        client::ClientError::BadHost(_) | client::ClientError::BadHeaderValue(_) => {
            SyncError::DeviceFile(e.to_string())
        }
        client::ClientError::TooLarge(_) | client::ClientError::Malformed(_) => {
            SyncError::BadResponse(e.to_string())
        }
    }
}

/// Rewrites the config and applies it (§6.3's four steps).
///
/// The order is the whole of this function's reason to exist:
///
/// 1. Read the private key out of the existing config. It is the only
///    copy (§9.2), and without it there is nothing to build from — so
///    a missing or unreadable one is a re-join, not a repair.
/// 2. Write the new config atomically.
/// 3. `wg syncconf`, which changes a running interface without
///    dropping the tunnels on it.
/// 4. **Only then** write `device.json`.
///
/// Step 4 last is what makes a failure retry itself. `device.json`
/// means "the last state matched to the hub"; committing it before the
/// apply succeeded would make the next run see local and hub as equal
/// and never try again — leaving the kernel on the old settings for
/// ever, with the symptom "the hub answers but the tunnel is dead" and
/// nobody saying so.
///
/// **Human verification needed**: drives `wg`.
fn apply(
    config: &DeviceConfig,
    reported: Option<&Reported>,
    wg_config: &Path,
    home: &Home,
) -> Result<(), SyncError> {
    let existing = std::fs::read_to_string(wg_config).map_err(|e| SyncError::NoPrivateKey {
        path: wg_config.display().to_string(),
        detail: e.to_string(),
    })?;
    let private_key = wgconf::private_key_line(&existing)
        .and_then(|text| wg::parse_key(text).ok())
        .ok_or_else(|| SyncError::NoPrivateKey {
            path: wg_config.display().to_string(),
            detail: "no usable PrivateKey line".to_string(),
        })?;

    let updated = updated(config, reported);
    let profile = profile_of(&updated, PrivateKey::new(private_key))?;
    crate::fsutil::write_private(wg_config, wgconf::client_config(&profile).expose()).map_err(
        |e| SyncError::Write {
            path: wg_config.display().to_string(),
            detail: e.to_string(),
        },
    )?;

    // `wg-quick strip` turns the file into what `wg` itself
    // understands (it drops `Address`, which is wg-quick's not wg's),
    // and `syncconf` then changes the running interface **without
    // dropping the tunnels on it** — which `down`/`up` would.
    let stripped = wg::run(&wg::quick_strip(wg_config), None).map_err(|e| SyncError::Apply {
        detail: e.to_string(),
    })?;
    let interface = interface_of(wg_config);
    let stripped_file = Stripped::write(wg_config, &stripped)?;
    wg::run(&wg::syncconf(&interface, stripped_file.path()), None).map_err(|e| {
        SyncError::Apply {
            detail: e.to_string(),
        }
    })?;
    drop(stripped_file);

    // Last, and only now — through the handle this run has held all
    // along, so it lands in the directory that was read and belongs to
    // whoever owned it before.
    home.write(&updated)
}

/// The stripped config, on disk only for as long as `wg syncconf`
/// needs a filename.
///
/// It holds this device's private key — the same key as the config
/// beside it — so it goes away on every path out, including the ones
/// that fail. A sibling rather than a temp directory, because it is
/// created 0600 in a directory that is already root-only and because a
/// rename across filesystems is not what is wanted here anyway.
struct Stripped {
    path: PathBuf,
}

impl Stripped {
    fn write(wg_config: &Path, contents: &str) -> Result<Stripped, SyncError> {
        let mut name = wg_config.file_name().unwrap_or_default().to_os_string();
        name.push(".stripped");
        let path = wg_config.with_file_name(name);
        crate::fsutil::write_private(&path, contents).map_err(|e| SyncError::Write {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        Ok(Stripped { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Stripped {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// `device.json` with the hub's current values. Pure.
///
/// Takes the **checked** values rather than the response, so there is
/// no path by which a string the hub sent reaches this file — or the
/// wg config rendered from it — without having been through
/// [`reported_of`].
///
/// Only the three the hub reports move; the token, the name and this
/// device's own address are not the hub's to change here — a moved
/// address is a [`Detachment::Reassigned`], which stops rather than
/// repairs (§6.3).
pub fn updated(config: &DeviceConfig, reported: Option<&Reported>) -> DeviceConfig {
    let mut updated = config.clone();
    if let Some(reported) = reported {
        updated
            .server_public_key
            .clone_from(&reported.server_public_key);
        updated
            .server_endpoint
            .clone_from(&reported.server_endpoint);
        updated.server_address = reported.server_address.to_string();
    }
    updated
}

/// The profile the new config is rendered from. Pure.
pub fn profile_of(
    config: &DeviceConfig,
    private_key: PrivateKey,
) -> Result<ClientProfile, SyncError> {
    let local = local_of(config)?;
    Ok(ClientProfile {
        address: local.address,
        subnet: local.subnet,
        private_key,
        server_public_key: config.server_public_key.clone(),
        server_endpoint: config.server_endpoint.clone(),
    })
}

/// The interface name a config file describes: its stem, the way
/// `wg-quick` reads it.
pub fn interface_of(wg_config: &Path) -> String {
    wg_config
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| paths::WG_INTERFACE.to_string())
}

/// Why a run ended the way it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncError {
    /// The hub was not reachable. Ordinary (§6.3).
    Unreachable(String),
    /// Another run holds the lock — the timer and a person at once.
    /// Also ordinary: the other run is doing this run's work.
    Busy,
    /// The certificate did not verify.
    Untrusted(String),
    /// This device no longer fits the hub.
    Detached(Detachment),
    NoDeviceFile {
        path: String,
        detail: String,
    },
    DeviceFile(String),
    BadResponse(String),
    Refused(String),
    NoPrivateKey {
        path: String,
        detail: String,
    },
    Write {
        path: String,
        detail: String,
    },
    Apply {
        detail: String,
    },
}

impl SyncError {
    /// §6.3's table, as code.
    pub fn ending(&self) -> Ending {
        match self {
            SyncError::Unreachable(_) | SyncError::Busy => Ending::Passed,
            _ => Ending::Stop,
        }
    }
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncError::Unreachable(detail) => write!(
                f,
                "could not reach the hub ({detail}). Nothing is wrong with the tunnel — \
                 the hub routes between devices whether or not this one has synced"
            ),
            SyncError::Busy => f.write_str(
                "another sync is already running, so this one stopped — whatever it \
                 finds is what this run would have found",
            ),
            SyncError::Untrusted(detail) => write!(
                f,
                "the hub's certificate did not verify: {detail}. On a café or hotel \
                 network this is usually the portal intercepting the connection — but a \
                 real interception looks the same, so nothing was sent"
            ),
            SyncError::Detached(detachment) => write!(f, "{detachment}"),
            SyncError::NoDeviceFile { path, detail } => write!(
                f,
                "{path}: {detail}. This device has not joined a hub, or the file was \
                 moved — `anago join <domain> <code>` writes it"
            ),
            SyncError::DeviceFile(detail) => write!(f, "the device file is unusable: {detail}"),
            SyncError::BadResponse(detail) => write!(
                f,
                "the hub's answer could not be read: {detail}. Nothing was changed"
            ),
            SyncError::Refused(detail) => write!(f, "the hub refused: {detail}"),
            SyncError::NoPrivateKey { path, detail } => write!(
                f,
                "the hub's settings changed, but {path} has no key to build a new config \
                 from ({detail}). The private key exists only in that file, so there is \
                 nothing to repair — join again with `anago join <domain> <code>`"
            ),
            SyncError::Write { path, detail } => write!(f, "could not write {path}: {detail}"),
            SyncError::Apply { detail } => write!(
                f,
                "the new config was written but `wg` would not take it: {detail}. The \
                 next run writes the same file and tries again"
            ),
        }
    }
}

impl std::error::Error for SyncError {}

#[cfg(test)]
mod tests {
    use super::*;
    use anago_core::proto::{HubInfo, PeerInfo};
    use anago_core::sync::Changes;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    const KEY: &str = "c2VydmVyIHB1YmxpYyBrZXkgNDQgY2hhcnMgbG9uZ2c=";
    const OTHER_KEY: &str = "YW5vdGhlciBzZXJ2ZXIga2V5IDQ0IGNoYXJzIGxvbmc=";
    const OURS: &str = "dGhpcyBkZXZpY2UncyBwcml2YXRlIGtleSA0NCBjaGE=";

    fn config() -> DeviceConfig {
        DeviceConfig {
            domain: "net.example.com".to_string(),
            api_port: 443,
            name: "macbook".to_string(),
            address: "10.100.0.2".to_string(),
            subnet: "10.100.0.0/24".to_string(),
            token: "aa".repeat(32),
            server_public_key: KEY.to_string(),
            server_endpoint: "net.example.com:51820".to_string(),
            server_address: "10.100.0.1".to_string(),
        }
    }

    /// What an M1 hub answers with: the roster, and itself.
    fn response(hub: Option<HubInfo>) -> PeersResponse {
        PeersResponse {
            peers: vec![
                PeerInfo {
                    name: "macbook".to_string(),
                    public_key: "cGVlciBvbmU=".to_string(),
                    address: "10.100.0.2".to_string(),
                },
                PeerInfo {
                    name: "맥북".to_string(),
                    public_key: "cGVlciB0d28=".to_string(),
                    address: "10.100.0.3".to_string(),
                },
            ],
            hub,
        }
    }

    fn hub() -> HubInfo {
        HubInfo {
            subnet: "10.100.0.0/24".to_string(),
            server_public_key: KEY.to_string(),
            server_endpoint: "net.example.com:51820".to_string(),
            server_address: "10.100.0.1".to_string(),
        }
    }

    /// The three strings a report needs, as a run on this machine
    /// would have them.
    fn hub_paths() -> Hub {
        Hub {
            domain: "net.example.com".to_string(),
            wg_config: "/etc/wireguard/anago.conf".to_string(),
            device_file: "/home/jo/.config/anago/device.json".to_string(),
        }
    }

    fn decide(config: &DeviceConfig, response: &PeersResponse) -> Sync {
        anago_core::sync::decide(
            &local_of(config).unwrap(),
            reported_of(response).unwrap().as_ref(),
            &roster_of(response).unwrap(),
        )
    }

    #[test]
    fn the_ordinary_run_finds_nothing_to_do() {
        // §6.3's whole point: another device joining changes nothing
        // here, because `AllowedIPs` is the subnet and the hub routes.
        // "Nothing to update" is the correct ending, not a wasted run.
        let outcome = decide(&config(), &response(Some(hub())));
        assert_eq!(outcome, Sync::Unchanged);
        assert_eq!(ending_of(&outcome), Ending::Fine);
        assert_eq!(Ending::Fine.exit_code(), 0);

        // A person who typed it gets a line; a timer gets silence.
        assert_eq!(
            report(&outcome, &hub_paths(), false),
            "net.example.com: in sync\n"
        );
        assert_eq!(report(&outcome, &hub_paths(), true), "");
    }

    #[test]
    fn a_new_device_on_the_roster_is_not_a_change() {
        let mut response = response(Some(hub()));
        response.peers.push(PeerInfo {
            name: "phone".to_string(),
            public_key: "cGVlciB0aHJlZQ==".to_string(),
            address: "10.100.0.4".to_string(),
        });
        assert_eq!(decide(&config(), &response), Sync::Unchanged);
    }

    #[test]
    fn an_m0_hub_is_not_a_difference() {
        // Four fields absent, not four fields changed. Reading absence
        // as difference would rewrite the config every five minutes,
        // for ever (§6.3).
        let outcome = decide(&config(), &response(None));
        assert_eq!(outcome, Sync::Unverifiable);
        assert_eq!(
            ending_of(&outcome),
            Ending::Fine,
            "an M0 hub is not a fault"
        );

        // And it does not claim to be in sync, because nothing was
        // checked.
        let line = report(&outcome, &hub_paths(), false);
        assert!(line.contains("still registered"), "{line}");
        assert!(!line.contains("in sync"), "{line}");
        assert_eq!(report(&outcome, &hub_paths(), true), "");
    }

    #[test]
    fn a_moved_server_key_or_endpoint_is_the_one_thing_worth_writing() {
        for (hub, expected) in [
            (
                HubInfo {
                    server_public_key: OTHER_KEY.to_string(),
                    ..hub()
                },
                Changes {
                    server_public_key: true,
                    ..Changes::default()
                },
            ),
            (
                HubInfo {
                    server_endpoint: "net.example.com:51999".to_string(),
                    ..hub()
                },
                Changes {
                    server_endpoint: true,
                    ..Changes::default()
                },
            ),
            (
                HubInfo {
                    server_address: "10.100.0.9".to_string(),
                    ..hub()
                },
                Changes {
                    server_address: true,
                    ..Changes::default()
                },
            ),
        ] {
            let outcome = decide(&config(), &response(Some(hub)));
            assert_eq!(outcome, Sync::Rewrite(expected));
            // Still exit zero: it was handled.
            assert_eq!(ending_of(&outcome), Ending::Fine);
        }
    }

    #[test]
    fn everything_that_means_this_device_no_longer_fits_stops() {
        // §6.3: sync does nothing destructive. It does not take the
        // tunnel down or delete the device file — the hub may be
        // half-restored, and an unattended job every five minutes is
        // the wrong thing to be making that decision.
        let removed = decide(&config(), &{
            let mut response = response(Some(hub()));
            response.peers.retain(|peer| peer.name != "macbook");
            response
        });
        assert_eq!(removed, Sync::Detached(Detachment::Removed));

        let reassigned = decide(&config(), &{
            let mut response = response(Some(hub()));
            response.peers[0].address = "10.100.0.7".to_string();
            response
        });
        assert!(matches!(
            reassigned,
            Sync::Detached(Detachment::Reassigned { .. })
        ));

        let rebuilt = decide(
            &config(),
            &response(Some(HubInfo {
                subnet: "10.200.0.0/24".to_string(),
                ..hub()
            })),
        );
        assert!(matches!(
            rebuilt,
            Sync::Detached(Detachment::SubnetChanged { .. })
        ));

        for outcome in [removed, reassigned, rebuilt] {
            assert_eq!(ending_of(&outcome), Ending::Stop);
            // Said even under --quiet: this is the line the timer
            // exists to surface.
            assert!(!report(&outcome, &hub_paths(), true).is_empty());
        }
        assert_eq!(Ending::Stop.exit_code(), 1);
    }

    #[test]
    fn a_removed_device_is_told_where_the_two_files_are() {
        // §6.3: sync does not repair a 401 and does not take the
        // tunnel down for one. What it owes the person is the way back
        // — and "delete the device file" is a noun, not something
        // anybody can act on. The paths are this machine's.
        for detachment in [
            Detachment::Unauthorized,
            Detachment::Removed,
            Detachment::Reassigned {
                theirs: "10.100.0.7".parse().unwrap(),
            },
            Detachment::SubnetChanged {
                theirs: anago_core::subnet::Subnet::parse("10.200.0.0/24").unwrap(),
            },
        ] {
            let outcome = Sync::Detached(detachment.clone());
            let line = report(&outcome, &hub_paths(), false);
            assert!(line.contains("net.example.com:"), "{line}");
            assert!(
                line.contains("sudo wg-quick down /etc/wireguard/anago.conf"),
                "{detachment:?}: {line}"
            );
            assert!(
                line.contains("/home/jo/.config/anago/device.json"),
                "{detachment:?}: {line}"
            );
            assert!(line.contains("anago join"), "{detachment:?}: {line}");
            assert!(line.contains("`anago code`"), "{detachment:?}: {line}");

            // Said under `--quiet` too: this is the one line the timer
            // exists to surface, and swallowing it is how a device
            // sits dead for a week.
            assert_eq!(report(&outcome, &hub_paths(), true), line);
        }
    }

    #[test]
    fn every_report_and_every_complaint_is_one_line() {
        // The whole convention rests on this: a timer's journal shows
        // entries, and an ending that spans two of them is one a
        // person reads half of (§6.3).
        for outcome in [
            Sync::Unchanged,
            Sync::Unverifiable,
            Sync::Rewrite(Changes {
                server_public_key: true,
                server_endpoint: true,
                server_address: true,
            }),
            Sync::Detached(Detachment::Unauthorized),
            Sync::Detached(Detachment::Reassigned {
                theirs: "10.100.0.7".parse().unwrap(),
            }),
        ] {
            let line = report(&outcome, &hub_paths(), false);
            assert_eq!(line.lines().count(), 1, "{outcome:?}: {line}");
        }

        for e in [
            SyncError::Unreachable("connection refused".to_string()),
            SyncError::Busy,
            SyncError::Untrusted("UnknownIssuer".to_string()),
            SyncError::Detached(Detachment::Removed),
            SyncError::NoDeviceFile {
                path: "/home/jo/.config/anago/device.json".to_string(),
                detail: "No such file or directory".to_string(),
            },
            SyncError::DeviceFile("no version".to_string()),
            SyncError::BadResponse("subnet: bad".to_string()),
            SyncError::Refused("the hub is starting up".to_string()),
            SyncError::NoPrivateKey {
                path: "/etc/wireguard/anago.conf".to_string(),
                detail: "no usable PrivateKey line".to_string(),
            },
            SyncError::Write {
                path: "/etc/wireguard/anago.conf".to_string(),
                detail: "No space left on device".to_string(),
            },
            SyncError::Apply {
                detail: "wg: Unable to modify interface".to_string(),
            },
        ] {
            let line = complaint(&e, false);
            assert_eq!(line.lines().count(), 1, "{e:?}: {line}");
        }
    }

    #[test]
    fn nothing_that_is_fine_carries_a_cleanup() {
        // The cleanup is for the endings that need one. Printing it
        // beside "in sync" would teach a person to skip the whole
        // line.
        for outcome in [
            Sync::Unchanged,
            Sync::Unverifiable,
            Sync::Rewrite(Changes {
                server_endpoint: true,
                ..Changes::default()
            }),
        ] {
            let line = report(&outcome, &hub_paths(), false);
            assert!(!line.contains("wg-quick down"), "{line}");
            assert!(!line.contains("device.json"), "{line}");
        }
    }

    #[test]
    fn a_401_is_an_ending_and_not_a_transport_failure() {
        // The token died the moment the hub ran `anago rm` (§7.1), so
        // this is the roster saying the same thing by another route —
        // and it has to arrive with the same cleanup, not as a bare
        // "the hub refused".
        let removed = SyncError::Detached(Detachment::Unauthorized);
        assert_eq!(removed.ending(), Ending::Stop);
        // Carried as an error only between the call and the decision;
        // what a person sees is the outcome, with the paths.
        let line = report(
            &Sync::Detached(Detachment::Unauthorized),
            &hub_paths(),
            true,
        );
        assert_eq!(line.lines().count(), 1, "{line}");
        assert!(line.contains("removed with `anago rm`"), "{line}");
        assert!(line.contains("To use this device again"), "{line}");

        // And it is not confused with the hub refusing for some other
        // reason, which says so and carries no cleanup.
        let other = SyncError::Refused("the hub is starting up".to_string());
        assert_eq!(other.ending(), Ending::Stop);
        assert!(!complaint(&other, false).contains("wg-quick down"));
    }

    #[test]
    fn a_laptop_that_is_somewhere_else_is_not_a_failure() {
        // The reason this matters is the journal: a non-zero exit is a
        // failed unit, and a day of café wifi would file hundreds of
        // them with the one 401 buried in the middle (§6.3).
        let away = SyncError::Unreachable("connection refused".to_string());
        assert_eq!(away.ending(), Ending::Passed);
        assert_eq!(away.ending().exit_code(), 0);
        let message = away.to_string();
        assert!(
            message.contains("Nothing is wrong with the tunnel"),
            "{message}"
        );

        // A certificate that does not verify is a different kind of
        // thing — trust, not reach — so it is never swallowed.
        let intercepted = SyncError::Untrusted("invalid peer certificate".to_string());
        assert_eq!(intercepted.ending(), Ending::Stop);
        let message = intercepted.to_string();
        assert!(message.contains("portal"), "{message}");
        assert!(message.contains("nothing was sent"), "{message}");

        // And so is everything else a person has to act on.
        for e in [
            SyncError::Detached(Detachment::Unauthorized),
            SyncError::NoDeviceFile {
                path: "/home/jo/.config/anago/device.json".to_string(),
                detail: "No such file or directory".to_string(),
            },
            SyncError::DeviceFile("no version".to_string()),
            SyncError::Apply {
                detail: "wg: Unable to modify interface".to_string(),
            },
        ] {
            assert_eq!(e.ending(), Ending::Stop, "{e:?}");
        }
    }

    #[test]
    fn quiet_swallows_the_failures_a_person_cannot_act_on() {
        // Regression: only the *successful* outcomes went through the
        // quiet rule, so a laptop that was somewhere else printed a
        // line every five minutes — exactly the noise §6.3 asks the
        // quiet form to swallow, and enough of it to drown the one
        // line that matters.
        let away = SyncError::Unreachable("connection refused".to_string());
        assert_eq!(complaint(&away, true), "");
        assert!(complaint(&away, false).contains("could not reach the hub"));

        let busy = SyncError::Busy;
        assert_eq!(complaint(&busy, true), "");
        assert!(complaint(&busy, false).contains("already running"));

        // And every ending a person has to act on is said whatever
        // the flags say.
        for e in [
            SyncError::Detached(Detachment::Unauthorized),
            SyncError::Untrusted("invalid peer certificate".to_string()),
            SyncError::DeviceFile("no version".to_string()),
            SyncError::Apply {
                detail: "wg: Unable to modify interface".to_string(),
            },
        ] {
            assert!(!complaint(&e, true).is_empty(), "{e:?} went unsaid");
            assert_eq!(complaint(&e, true), complaint(&e, false));
        }
    }

    /// A device directory with a `device.json` in it, as a run finds
    /// one.
    fn home(dir: &Path) -> Home {
        std::fs::create_dir_all(dir).unwrap();
        let device_file = dir.join("device.json");
        crate::fsutil::write_private(&device_file, &config().to_json_string()).unwrap();
        Home::open(&device_file).unwrap()
    }

    #[test]
    fn two_runs_do_not_rewrite_the_same_files_at_once() {
        // The timer coming round while somebody types the command is
        // ordinary. Both rewriting the config and `device.json` from
        // two different answers is not — and they share the one
        // filename `wg syncconf` is handed, so one can delete the file
        // the other is about to read.
        let dir = std::env::temp_dir().join(format!("anago-sync-lock-{}", std::process::id()));
        let home = home(&dir);

        // Beside the device file this run read — including the one
        // `--config` named, which is not where §9's rules would look.
        let lock_file = dir.join(paths::SYNC_LOCK);
        let held = home.lock().expect("nobody holds it yet");
        assert!(lock_file.exists());
        assert!(
            matches!(home.lock(), Err(SyncError::Busy)),
            "a second sync started while the first was running"
        );

        // Losing that race is not a failure: the run that has the lock
        // is doing this run's work. Exit zero, and silent (§6.3).
        assert_eq!(SyncError::Busy.ending(), Ending::Passed);
        assert_eq!(SyncError::Busy.ending().exit_code(), 0);
        assert_eq!(complaint(&SyncError::Busy, true), "");

        // And it frees when that run is done.
        drop(held);
        assert!(home.lock().is_ok());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)] // exercises unix modes/ownership/symlinks
    fn the_device_file_goes_back_to_whoever_owned_it() {
        // sync runs as root and `device.json` is in somebody's home.
        // Writing it the ordinary way would create the replacement as
        // root and rename it into place, so from the first server
        // change onwards a 0600 file would belong to root — and `ls`
        // and `rm`, which §9 promises a person can run from their own
        // shell, would stop being able to read it.
        let dir = std::env::temp_dir().join(format!("anago-sync-owner-{}", std::process::id()));
        let home = home(&dir);
        let before = home.owner().unwrap();

        let mut changed = config();
        changed.server_endpoint = "net.example.com:51999".to_string();
        home.write(&changed).unwrap();

        assert_eq!(home.owner().unwrap(), before, "the owner changed");
        // **Human verification needed** for the half this cannot
        // reach: only root can `fchown` a file to somebody else, so a
        // test running as an ordinary user would pass even if the
        // owner were never handed back. What is pinned here is that
        // the write goes through the handle and keeps the mode; that
        // it lands as the joining user has to be seen on a real
        // machine, under `sudo`.
        let mode = std::fs::metadata(home.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:04o}");
        assert_eq!(home.read().unwrap(), changed);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_directory_cannot_be_swapped_out_from_under_the_run() {
        // The race a root timer walking a user-controlled path loses
        // if it works by path: rename the directory between the read
        // and the write, put something else at the old name, and the
        // write lands wherever the person chose (§13). A held
        // descriptor resolves against the inode it already has.
        let base = std::env::temp_dir().join(format!("anago-sync-swap-{}", std::process::id()));
        let dir = base.join("anago");
        let home = home(&dir);
        let moved = base.join("moved");
        let decoy = base.join("anago");

        std::fs::rename(&dir, &moved).unwrap();
        std::fs::create_dir_all(&decoy).unwrap();

        let mut changed = config();
        changed.server_endpoint = "net.example.com:51999".to_string();
        home.write(&changed).unwrap();

        // The write followed the directory, not the name.
        assert_eq!(
            DeviceConfig::parse(&std::fs::read_to_string(moved.join("device.json")).unwrap())
                .unwrap(),
            changed
        );
        assert!(
            !decoy.join("device.json").exists(),
            "the write landed at the old name, which is now something else"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    #[cfg(unix)] // exercises unix modes/ownership/symlinks
    fn a_device_file_that_is_a_symlink_is_not_followed() {
        // The other half of the same race: swapping the file rather
        // than the directory. Root reading — or worse, replacing —
        // whatever a symlink points at is how a device file becomes a
        // way to rewrite somebody else's.
        let dir = std::env::temp_dir().join(format!("anago-sync-link-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let elsewhere = dir.join("elsewhere.json");
        crate::fsutil::write_private(&elsewhere, &config().to_json_string()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.join("device.json")).unwrap();

        let home = Home::open(&dir.join("device.json")).unwrap();
        assert!(
            matches!(home.read(), Err(SyncError::NoDeviceFile { .. })),
            "a symlinked device file was read through"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_hub_is_not_trusted_as_a_compiler_for_root_config() {
        // TLS says the answer came from the hub. It does not say the
        // hub is well — a restored backup, a bug, or a hub somebody
        // else now controls. These strings are about to be rendered
        // into a root-owned `wg-quick` file, and that format is a list
        // of directives: a valid endpoint followed by a newline and a
        // `PostUp` is a command root runs at the next reboot. Worse,
        // `wg-quick strip` drops `PostUp` before `syncconf` sees it,
        // so the apply would succeed and both files would be committed
        // with it in place. `join` checks the same four for the same
        // reason (§7).
        let injected = [
            HubInfo {
                server_endpoint: "net.example.com:51820\nPostUp = curl x | sh".to_string(),
                ..hub()
            },
            HubInfo {
                server_public_key: format!("{KEY}\nPostUp = curl x | sh"),
                ..hub()
            },
            HubInfo {
                server_endpoint: "net.example.com:51820 # \n[Interface]".to_string(),
                ..hub()
            },
            // And the ordinary malformed cases, which the same check
            // catches on the way past.
            HubInfo {
                server_public_key: "not a key".to_string(),
                ..hub()
            },
            HubInfo {
                server_endpoint: "net.example.com".to_string(),
                ..hub()
            },
            HubInfo {
                server_endpoint: "net.example.com:0".to_string(),
                ..hub()
            },
            HubInfo {
                server_address: "10.100.0.1\nPostUp = x".to_string(),
                ..hub()
            },
        ];

        for hub in injected {
            let response = response(Some(hub.clone()));
            let e = reported_of(&response)
                .expect_err(&format!("{hub:?} was believed"))
                .to_string();
            assert!(e.contains("could not be read"), "{e}");
            assert!(e.contains("Nothing was changed"), "{e}");
        }
        // Refused *before* anything is written: the run stops at the
        // answer, so neither the wg config nor `device.json` is
        // reached — and it is an ending a person has to act on.
        assert_eq!(SyncError::BadResponse(String::new()).ending(), Ending::Stop);

        // Nothing is copied verbatim, either: what reaches the files
        // is what the check returned. A key with surrounding
        // whitespace is accepted and lands trimmed.
        let padded = response(Some(HubInfo {
            server_public_key: format!("  {OTHER_KEY}  "),
            ..hub()
        }));
        let reported = reported_of(&padded).unwrap().unwrap();
        assert_eq!(reported.server_public_key, OTHER_KEY);
        let after = updated(&config(), Some(&reported));
        assert_eq!(after.server_public_key, OTHER_KEY);

        // Which is the whole point: a config rendered from it holds
        // one `[Peer]` and no directives the hub chose.
        let text = wgconf::client_config(&profile_of(&after, PrivateKey::new(OURS)).unwrap());
        assert_eq!(text.expose().matches("PostUp").count(), 0);
        assert_eq!(text.expose().matches("[Interface]").count(), 1);
        assert_eq!(text.expose().matches("[Peer]").count(), 1);
    }

    #[test]
    fn only_what_goes_away_by_itself_is_passed_over() {
        // Regression: everything that was not a TLS error counted as
        // "could not reach the hub", so a `device.json` with a
        // mangled domain, or a portal answering with HTML, exited
        // zero and — under `--quiet` — was hidden for ever. §6.3 names
        // the silent set exactly: DNS, a refused connection, a
        // timeout.
        for transient in [
            client::ClientError::Resolve {
                host: "net.example.com".to_string(),
                source: "no such host".to_string(),
            },
            client::ClientError::Connect {
                address: "203.0.113.7:443".to_string(),
                source: "Connection refused".to_string(),
            },
            client::ClientError::Timeout {
                what: "the response",
                after: Duration::from_secs(10),
            },
            client::ClientError::Io("connection reset".to_string()),
        ] {
            let e = unreachable_or_worse(transient.clone());
            assert!(
                matches!(e, SyncError::Unreachable(_)),
                "{transient:?} → {e:?}"
            );
            assert_eq!(e.ending(), Ending::Passed);
            assert_eq!(complaint(&e, true), "");
        }

        // A hostname that cannot be reached is different from one that
        // cannot be *used*: the second is a device file to repair, and
        // no amount of waiting mends it.
        for (permanent, expected) in [
            (
                client::ClientError::BadHost("net example com".to_string()),
                "the device file is unusable",
            ),
            (
                client::ClientError::BadHeaderValue("a header cannot hold a newline"),
                "the device file is unusable",
            ),
            (
                client::ClientError::TooLarge(1 << 20),
                "the hub's answer could not be read",
            ),
            (
                client::ClientError::Malformed("no status line"),
                "the hub's answer could not be read",
            ),
            (
                client::ClientError::Tls("UnknownIssuer".to_string()),
                "certificate did not verify",
            ),
            (client::ClientError::NoRoots, "certificate did not verify"),
        ] {
            let e = unreachable_or_worse(permanent.clone());
            assert_eq!(e.ending(), Ending::Stop, "{permanent:?} → {e:?}");
            let said = complaint(&e, true);
            assert!(said.contains(expected), "{permanent:?} → {said}");
        }
    }

    #[test]
    fn a_config_with_no_key_to_rebuild_from_says_to_join_again() {
        // The private key exists in that one file (§9.2). Without it
        // there is nothing to build a config out of, so §6.3 says do
        // not repair — say so and stop.
        let e = SyncError::NoPrivateKey {
            path: "/etc/wireguard/anago.conf".to_string(),
            detail: "no usable PrivateKey line".to_string(),
        };
        assert_eq!(e.ending(), Ending::Stop);
        let message = e.to_string();
        assert!(message.contains("nothing to repair"), "{message}");
        assert!(message.contains("anago join"), "{message}");
    }

    #[test]
    fn only_the_hubs_own_values_are_written_back() {
        // A moved address is a `Reassigned` and stops; it is not
        // something a sync quietly adopts (§6.3). Neither is a name or
        // a token.
        let moved = HubInfo {
            server_public_key: OTHER_KEY.to_string(),
            server_endpoint: "net.example.com:51999".to_string(),
            server_address: "10.100.0.9".to_string(),
            ..hub()
        };
        let after = updated(
            &config(),
            reported_of(&response(Some(moved))).unwrap().as_ref(),
        );
        assert_eq!(after.server_public_key, OTHER_KEY);
        assert_eq!(after.server_endpoint, "net.example.com:51999");
        assert_eq!(after.server_address, "10.100.0.9");

        let before = config();
        assert_eq!(after.name, before.name);
        assert_eq!(after.address, before.address);
        assert_eq!(after.token, before.token);
        assert_eq!(after.domain, before.domain);
        assert_eq!(after.api_port, before.api_port);

        // An M0 hub reported nothing, so nothing is written back.
        assert_eq!(
            updated(&before, reported_of(&response(None)).unwrap().as_ref()),
            before
        );
    }

    #[test]
    fn the_rewritten_config_keeps_this_devices_key_and_takes_the_rest() {
        let after = updated(
            &config(),
            reported_of(&response(Some(HubInfo {
                server_public_key: OTHER_KEY.to_string(),
                ..hub()
            })))
            .unwrap()
            .as_ref(),
        );
        let profile = profile_of(&after, PrivateKey::new(OURS)).unwrap();
        let rendered = wgconf::client_config(&profile);
        let text = rendered.expose();

        assert!(text.contains(&format!("PrivateKey = {OURS}")), "{text}");
        assert!(text.contains(&format!("PublicKey = {OTHER_KEY}")), "{text}");
        assert!(
            text.contains(&format!(
                "Address = 10.100.0.2/{}",
                anago_core::subnet::PREFIX_LEN
            )),
            "{text}"
        );
        assert!(text.contains("AllowedIPs = 10.100.0.0/24"), "{text}");
        assert!(text.contains("Endpoint = net.example.com:51820"), "{text}");
        // The old key is gone, not merely joined by the new one.
        assert!(!text.contains(KEY), "{text}");
    }

    #[test]
    fn a_device_file_that_cannot_be_read_is_named_field_by_field() {
        // A file edited by hand is the likely cause, and "the device
        // file is unusable" without saying which field is a person
        // reading the whole thing looking for it.
        for (broken, field) in [
            (
                DeviceConfig {
                    address: "not an address".to_string(),
                    ..config()
                },
                "address",
            ),
            (
                DeviceConfig {
                    subnet: "10.100.0.0/99".to_string(),
                    ..config()
                },
                "subnet",
            ),
            (
                DeviceConfig {
                    server_address: "".to_string(),
                    ..config()
                },
                "server_address",
            ),
            (
                DeviceConfig {
                    name: "".to_string(),
                    ..config()
                },
                "name",
            ),
        ] {
            let e = local_of(&broken).unwrap_err();
            assert_eq!(e.ending(), Ending::Stop);
            assert!(e.to_string().contains(field), "{field}: {e}");
        }
    }

    #[test]
    fn an_answer_that_cannot_be_read_changes_nothing() {
        let e = reported_of(&response(Some(HubInfo {
            subnet: "not a subnet".to_string(),
            ..hub()
        })))
        .unwrap_err();
        assert!(e.to_string().contains("could not be read"), "{e}");
        assert!(e.to_string().contains("Nothing was changed"), "{e}");

        let mut response = response(Some(hub()));
        response.peers[0].address = "10.100.0.999".to_string();
        assert!(roster_of(&response).is_err());
    }

    #[test]
    fn the_interface_is_the_config_files_own_name() {
        // `wg-quick` reads it that way, and `syncconf` has to be given
        // the same one or it edits an interface nobody asked about.
        assert_eq!(
            interface_of(Path::new("/etc/wireguard/anago.conf")),
            "anago"
        );
        assert_eq!(interface_of(Path::new("/etc/wireguard/wg0.conf")), "wg0");
        assert_eq!(interface_of(Path::new("")), paths::WG_INTERFACE);
    }

    #[test]
    #[cfg(unix)] // exercises unix modes/ownership/symlinks
    fn the_stripped_config_never_outlives_the_command() {
        // It holds the same private key as the config beside it, and
        // it exists only because `wg syncconf` takes a filename.
        let dir = std::env::temp_dir().join(format!("anago-sync-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let wg_config = dir.join("anago.conf");

        let stripped = Stripped::write(&wg_config, "[Interface]\n").unwrap();
        let path = stripped.path().to_path_buf();
        assert!(path.exists());
        assert_eq!(path.file_name().unwrap(), "anago.conf.stripped");
        // 0600, like everything else that holds a key (§7.1).
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:04o}");

        drop(stripped);
        assert!(!path.exists(), "a stripped config was left behind");

        std::fs::remove_dir_all(&dir).ok();
    }
}
