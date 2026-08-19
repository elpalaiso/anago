//! The server's state file — `/var/lib/anago/state.json` (DESIGN.md
//! §9.1). One file, no database; this module is its schema.
//!
//! Reading and writing live here so the shape has exactly one
//! definition. The binary supplies the atomic write and the lock; what
//! it gets from core is text in, value out.
//!
//! The transitions the server performs on it — redeeming a code to
//! register a device, removing one — are here too, as functions that
//! either change the whole state or none of it.
//!
//! Decoding validates every field against the rules of the type that
//! owns it — a subnet through [`Subnet`], a name through
//! [`DeviceName`], a hash through [`TokenHash`]. Unknown fields are
//! ignored (§9.1). Versions are handled in exactly three ways:
//! [`SCHEMA_VERSION`] reads as written, [`LEGACY_SCHEMA_VERSION`] is
//! upgraded in memory, and anything else stops the read — so an older
//! binary cannot overwrite a newer file.

use std::fmt;
use std::net::Ipv4Addr;

use crate::code::{CodeStatus, IssuedCode, JoinCode};
use crate::json::{self, Object, Value};
use crate::name::{self, DeviceName};
use crate::proto::{self, DecodeError, ErrorCode};
use crate::subnet::Subnet;
use crate::token::TokenHash;

/// Schema version this build writes. M1 = 2 (§9.1).
pub const SCHEMA_VERSION: i64 = 2;

const DAY_SECS: i64 = 86_400;

/// How long before `not_after` the safety net fires (§9.1): time for a
/// person to notice failing renewals and fix them. It never lands
/// before `renew_after` at any realistic lifetime, so reaching it means
/// something is off.
pub const RENEWAL_LEAD_SECS: i64 = 7 * DAY_SECS;

/// What to assume when the certificate's expiry could not be read: the
/// shortest lifetime we might be issued, renewed at its two thirds
/// (§9.1). Not knowing is not a reason to be optimistic.
pub const UNKNOWN_LIFETIME_RENEW_SECS: i64 = 30 * DAY_SECS;

/// The version M0 wrote: flat `tls_cert_path`/`tls_key_path`, no ACME.
/// Still read — the upgrade to 2 is total, so there is nothing to ask
/// about (§9.1) — but never written back until something else changes
/// the state.
pub const LEGACY_SCHEMA_VERSION: i64 = 1;

/// The server's wg private key. Debug-redacted like a device token:
/// this key decrypts every hub-routed packet, so it must not reach a
/// log line by accident (§7).
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKey(String);

impl PrivateKey {
    pub fn new(key: impl Into<String>) -> PrivateKey {
        PrivateKey(key.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(redacted)")
    }
}

/// Which ACME challenge proves control of the domain (§8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Challenge {
    /// Needs :80 open, leaves no secret on the server.
    Http01,
    /// Needs no :80, but a DNS-editing token has to live on the server
    /// for renewals (§13).
    Dns01,
}

impl Challenge {
    pub fn as_str(self) -> &'static str {
        match self {
            Challenge::Http01 => "http-01",
            Challenge::Dns01 => "dns-01",
        }
    }

    pub fn parse(text: &str) -> Option<Challenge> {
        match text {
            "http-01" => Some(Challenge::Http01),
            "dns-01" => Some(Challenge::Dns01),
            _ => None,
        }
    }
}

/// What anago needs to renew a certificate it issued (§9.1).
///
/// `directory` is what separates staging from production, so it is
/// stored rather than re-derived: a renewal must go back to the same
/// CA the current certificate came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acme {
    pub directory: String,
    /// `--acme-email`. Only needed to register an account again.
    pub contact: Option<String>,
    pub account_key_path: String,
    pub account_url: String,
    pub challenge: Challenge,
    /// When the current certificate was received.
    pub issued_at: i64,
    /// When to renew. A decision, not the expiry — the expiry is
    /// [`Tls::not_after`] (§9.1).
    pub renew_after: i64,
}

impl Acme {
    /// Records a fresh issuance: when it happened, and — from the
    /// certificate's own expiry — when to come back.
    ///
    /// The two are set together because a stale `renew_after` beside a
    /// new `issued_at` is exactly the state that renews too late.
    pub fn issued(&mut self, at: i64, not_after: Option<i64>) {
        self.issued_at = at;
        self.renew_after = renew_after(at, not_after);
    }
}

/// When a certificate received at `issued_at` and expiring at
/// `not_after` should be renewed: **two thirds of its lifetime** (§9.1).
///
/// Not a fixed number of days. Let's Encrypt is moving the default
/// lifetime from 90 days to 64 and then 45, and moves the recommended
/// renewal with it — day 60 of 90, day 30 of 45. The fraction is what
/// stays put; "60 days" is a number that only fits a 90-day
/// certificate.
///
/// With no expiry to divide, it assumes the shortest lifetime we might
/// be handed ([`UNKNOWN_LIFETIME_RENEW_SECS`]).
pub fn renew_after(issued_at: i64, not_after: Option<i64>) -> i64 {
    let Some(not_after) = not_after else {
        return issued_at.saturating_add(UNKNOWN_LIFETIME_RENEW_SECS);
    };
    // A certificate that expires before it was issued is nonsense —
    // a wrong clock, a hand-edited file. The arithmetic lands at or
    // before `issued_at`, which reads as "renew now": the safe way to
    // be wrong.
    let lifetime = not_after.saturating_sub(issued_at);
    issued_at.saturating_add(lifetime.saturating_mul(2) / 3)
}

/// **The expiry safety net, on its own**: whether `now` has reached the
/// last `lead_secs` of a certificate expiring at `expires_at` (§9.1).
///
/// This function knows nothing about the stored plan. It is the floor
/// that holds when the plan is wrong — a `renew_after` computed against
/// a longer lifetime than the certificate actually has, or a date
/// somebody edited badly. The boundary is inclusive: at the net's
/// second, it is due.
///
/// A negative lead would push the net past the expiry it guards, so it
/// counts as none.
///
/// Callers holding a whole [`Tls`] want [`Tls::needs_renewal`], which
/// combines this with the stored decision. This is the piece it is
/// built from, kept separate so the net can be tested — and reasoned
/// about — without a state file.
pub fn needs_renewal(expires_at: i64, now: i64, lead_secs: i64) -> bool {
    now >= safety_net_at(expires_at, lead_secs)
}

/// The instant [`needs_renewal`] starts saying yes.
fn safety_net_at(expires_at: i64, lead_secs: i64) -> i64 {
    expires_at.saturating_sub(lead_secs.max(0))
}

/// When renewal is actually due: the stored decision, pulled earlier if
/// it would otherwise fall inside the safety net (§9.1).
///
/// The clamp only bites when `renew_after` is wrong for the certificate
/// on disk. With no expiry to check against, the stored decision stands
/// alone — there is nothing to pull it toward.
///
/// Callers print this value rather than recomputing it, so what is said
/// matches what is done.
pub fn renewal_due(renew_after: i64, not_after: Option<i64>, lead_secs: i64) -> i64 {
    match not_after {
        None => renew_after,
        Some(not_after) => renew_after.min(safety_net_at(not_after, lead_secs)),
    }
}

/// Where the hub's certificate comes from, and — the part that decides
/// behaviour — **who is allowed to write those files** (§9.1).
///
/// The paths are filled either way, so the code that hands PEM files to
/// rustls never branches on the source. Overwriting a certificate
/// somebody else manages is not undoable, which is why this distinction
/// lives in the state file rather than being guessed from the paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsSource {
    /// Paths a person gave with `--tls-cert/--tls-key`. anago reads
    /// them and never writes them; certbot or whatever else put them
    /// there owns them.
    Manual,
    /// anago issued this certificate and anago renews it.
    Acme(Acme),
}

/// The hub's TLS material as the state file records it.
///
/// Encoding the source as an enum rather than a tag plus an optional
/// object makes the one invariant §9.1 states — ACME details exist
/// exactly when the source is ACME — unrepresentable otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls {
    pub cert_path: String,
    pub key_path: String,
    /// `notAfter` read out of the certificate, or `None` when it could
    /// not be read. This value never decides trust — rustls does the
    /// verifying (§7); it schedules renewal and prints an expiry, so
    /// failing to read it is safe.
    pub not_after: Option<i64>,
    pub source: TlsSource,
}

impl Tls {
    /// A certificate a person supplied and keeps up to date themselves.
    pub fn manual(cert_path: impl Into<String>, key_path: impl Into<String>) -> Tls {
        Tls {
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            not_after: None,
            source: TlsSource::Manual,
        }
    }

    /// A certificate anago issued through ACME.
    pub fn acme(cert_path: impl Into<String>, key_path: impl Into<String>, acme: Acme) -> Tls {
        Tls {
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            not_after: None,
            source: TlsSource::Acme(acme),
        }
    }

    /// The ACME details to change after a renewal — the same test as
    /// [`Tls::renewable`], for the caller that has just been to the CA.
    pub fn renewable_mut(&mut self) -> Option<&mut Acme> {
        match &mut self.source {
            TlsSource::Acme(acme) => Some(acme),
            TlsSource::Manual => None,
        }
    }

    /// The ACME details when this certificate is ours to renew, `None`
    /// when it is somebody else's file.
    pub fn renewable(&self) -> Option<&Acme> {
        match &self.source {
            TlsSource::Manual => None,
            TlsSource::Acme(acme) => Some(acme),
        }
    }

    /// When this certificate is due for renewal, or `None` when it is
    /// not ours to renew — a manual certificate has an owner, and it is
    /// not anago (§9.1).
    pub fn renewal_due(&self, lead_secs: i64) -> Option<i64> {
        let acme = self.renewable()?;
        Some(renewal_due(acme.renew_after, self.not_after, lead_secs))
    }

    /// Whether anago should renew this certificate now — the composed
    /// answer: the stored decision, floored by [`needs_renewal`]'s
    /// expiry net.
    ///
    /// A manual certificate is never due: answering "yes" here would
    /// overwrite a file somebody else manages.
    pub fn needs_renewal(&self, now: i64, lead_secs: i64) -> bool {
        match self.renewal_due(lead_secs) {
            None => false,
            Some(due) => now >= due,
        }
    }
}

/// What anago remembers about the Cloudflare side of the domain
/// (§9.1). Present once a token has been used to touch DNS at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cloudflare {
    /// The zone the domain lives in. Worth caching: it never changes
    /// while the domain does, and DNS-01 renewal needs it without
    /// having to list zones again.
    pub zone_id: String,
    /// The A record anago created, so a later upsert edits *that*
    /// record rather than picking one of several with the same name.
    /// `None` before one exists, and again once the cache is found to
    /// be stale (§9.1).
    pub record_id: Option<String>,
    /// Where the API token was stored, and `None` when it was not
    /// stored at all — the token is only kept when DNS-01 renewal will
    /// need it again (§9.1). Never the token itself.
    pub token_path: Option<String>,
}

/// The hub's own wg identity and address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerKeys {
    pub private_key: PrivateKey,
    pub public_key: String,
    /// Always the subnet's `.1` (§5); [`ServerState::parse`] refuses a
    /// file that says otherwise.
    pub address: Ipv4Addr,
}

/// A registered device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub name: DeviceName,
    pub public_key: String,
    pub address: Ipv4Addr,
    /// SHA-256 of the device token. The plaintext is never here (§7.1).
    pub token_hash: TokenHash,
    pub created_at: i64,
    /// Last authenticated API call, or `None` if there has not been one.
    pub last_seen: Option<i64>,
}

/// Everything `anago server` knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerState {
    pub domain: String,
    pub subnet: Subnet,
    /// wg UDP port.
    pub listen_port: u16,
    /// Control API TCP port.
    pub api_port: u16,
    pub tls: Tls,
    /// `None` when Cloudflare was never used for this domain — the
    /// manual DNS path of M0 (§6.1).
    pub cloudflare: Option<Cloudflare>,
    pub server: ServerKeys,
    pub peers: Vec<Peer>,
    /// Issued join codes, spent and expired ones included — the record
    /// of who registered when is worth the bytes (§9.1).
    pub codes: Vec<IssuedCode>,
}

impl ServerState {
    /// Serializes to the JSON text that goes on disk: two-space indent,
    /// because a person may open this file (§10.1).
    pub fn to_json_string(&self) -> String {
        json::to_string_pretty(&self.to_json())
    }

    pub fn to_json(&self) -> Value {
        Value::obj([
            ("version", Value::Int(SCHEMA_VERSION)),
            ("domain", Value::str(self.domain.as_str())),
            ("subnet", Value::str(self.subnet.to_string())),
            ("listen_port", Value::Int(i64::from(self.listen_port))),
            ("api_port", Value::Int(i64::from(self.api_port))),
            ("tls", tls_to_json(&self.tls)),
            ("cloudflare", cloudflare_to_json(self.cloudflare.as_ref())),
            (
                "server",
                Value::obj([
                    ("private_key", Value::str(self.server.private_key.as_str())),
                    ("public_key", Value::str(self.server.public_key.as_str())),
                    ("address", Value::str(self.server.address.to_string())),
                ]),
            ),
            (
                "peers",
                Value::Arr(self.peers.iter().map(peer_to_json).collect()),
            ),
            (
                "codes",
                Value::Arr(self.codes.iter().map(code_to_json).collect()),
            ),
        ])
    }

    /// Reads the file's text.
    pub fn parse(text: &str) -> Result<ServerState, StateError> {
        let value = json::parse(text).map_err(StateError::Json)?;
        ServerState::from_json(&value)
    }

    pub fn from_json(value: &Value) -> Result<ServerState, StateError> {
        let obj = proto::object(value)?;

        // Version first: on a newer file, nothing below is trustworthy.
        let version = int_field(obj, "version")?;
        if version != SCHEMA_VERSION && version != LEGACY_SCHEMA_VERSION {
            return Err(StateError::UnsupportedVersion(version));
        }

        let subnet_text = proto::string_field(obj, "subnet")?;
        let subnet = Subnet::parse(&subnet_text)
            .map_err(|e| StateError::bad_value("subnet", e.to_string()))?;

        let server = server_from_json(obj.get("server").ok_or(DecodeError::missing("server"))?)?;
        if server.address != subnet.server_address() {
            return Err(StateError::bad_value(
                "server.address",
                format!("{} is not {}'s .1 address", server.address, subnet),
            ));
        }

        let mut peers = Vec::new();
        for (i, item) in array_field(obj, "peers")?.iter().enumerate() {
            peers.push(peer_from_json(item).map_err(|e| e.within(&format!("peers[{i}]")))?);
        }

        let mut codes = Vec::new();
        for (i, item) in array_field(obj, "codes")?.iter().enumerate() {
            codes.push(code_from_json(item).map_err(|e| e.within(&format!("codes[{i}]")))?);
        }

        Ok(ServerState {
            domain: proto::string_field(obj, "domain")?,
            subnet,
            listen_port: port_field(obj, "listen_port")?,
            api_port: port_field(obj, "api_port")?,
            tls: tls_from_json(obj, version)?,
            cloudflare: cloudflare_from_json(obj, version)?,
            server,
            peers,
            codes,
        })
    }
}

fn tls_to_json(tls: &Tls) -> Value {
    let (source, acme) = match &tls.source {
        TlsSource::Manual => ("manual", Value::Null),
        TlsSource::Acme(acme) => ("acme", acme_to_json(acme)),
    };
    Value::obj([
        ("source", Value::str(source)),
        ("cert_path", Value::str(tls.cert_path.as_str())),
        ("key_path", Value::str(tls.key_path.as_str())),
        ("not_after", opt_time(tls.not_after)),
        ("acme", acme),
    ])
}

/// Reads the `tls` object — or, on a version 1 file, the two flat paths
/// M0 wrote.
///
/// The upgrade is total: a file without ACME fields can only have meant
/// a manually supplied certificate, so there is nothing to ask and
/// nothing to lose. `not_after` stays `None` because reading is reading
/// — the expiry gets filled in the next time the certificate is loaded
/// (§9.1).
fn tls_from_json(obj: &Object, version: i64) -> Result<Tls, StateError> {
    if version == LEGACY_SCHEMA_VERSION {
        return Ok(Tls::manual(
            proto::string_field(obj, "tls_cert_path")?,
            proto::string_field(obj, "tls_key_path")?,
        ));
    }

    let tls = object_field(obj, "tls")?;
    let source = proto::string_field(tls, "source").map_err(|e| e.within("tls"))?;
    let acme = opt_object_field(tls, "acme").map_err(|e| e.within("tls"))?;
    let source = match (source.as_str(), acme) {
        ("manual", None) => TlsSource::Manual,
        ("acme", Some(found)) => TlsSource::Acme(acme_from_json(found)?),
        // The two contradictions the enum exists to rule out. Guessing
        // which half is right would either renew somebody else's
        // certificate or stop renewing ours.
        ("manual", Some(_)) => {
            return Err(StateError::bad_value(
                "tls.acme",
                "source is \"manual\" but acme details are present".to_string(),
            ))
        }
        ("acme", None) => {
            return Err(StateError::bad_value(
                "tls.acme",
                "source is \"acme\" but acme details are null".to_string(),
            ))
        }
        (other, _) => {
            return Err(StateError::bad_value(
                "tls.source",
                format!("{other:?} is not \"manual\" or \"acme\""),
            ))
        }
    };

    Ok(Tls {
        cert_path: proto::string_field(tls, "cert_path").map_err(|e| e.within("tls"))?,
        key_path: proto::string_field(tls, "key_path").map_err(|e| e.within("tls"))?,
        not_after: opt_int_field(tls, "not_after").map_err(|e| e.within("tls"))?,
        source,
    })
}

fn cloudflare_to_json(cloudflare: Option<&Cloudflare>) -> Value {
    match cloudflare {
        None => Value::Null,
        Some(cf) => Value::obj([
            ("zone_id", Value::str(cf.zone_id.as_str())),
            ("record_id", opt_str(cf.record_id.as_deref())),
            ("token_path", opt_str(cf.token_path.as_deref())),
        ]),
    }
}

/// A version 1 file predates the field entirely, and M0 had no way to
/// touch Cloudflare, so its absence there means `None` rather than a
/// missing key (§9.1). From version 2 on the writer always emits it.
fn cloudflare_from_json(obj: &Object, version: i64) -> Result<Option<Cloudflare>, StateError> {
    if version == LEGACY_SCHEMA_VERSION {
        return Ok(None);
    }
    let at = |e: DecodeError| e.within("cloudflare");
    let Some(cf) = opt_object_field(obj, "cloudflare")? else {
        return Ok(None);
    };
    Ok(Some(Cloudflare {
        zone_id: proto::string_field(cf, "zone_id").map_err(at)?,
        record_id: opt_string_field(cf, "record_id").map_err(at)?,
        token_path: opt_string_field(cf, "token_path").map_err(at)?,
    }))
}

fn acme_to_json(acme: &Acme) -> Value {
    Value::obj([
        ("directory", Value::str(acme.directory.as_str())),
        ("contact", opt_str(acme.contact.as_deref())),
        (
            "account_key_path",
            Value::str(acme.account_key_path.as_str()),
        ),
        ("account_url", Value::str(acme.account_url.as_str())),
        ("challenge", Value::str(acme.challenge.as_str())),
        ("issued_at", Value::Int(acme.issued_at)),
        ("renew_after", Value::Int(acme.renew_after)),
    ])
}

fn acme_from_json(obj: &Object) -> Result<Acme, StateError> {
    let at = |e: DecodeError| e.within("tls.acme");
    let challenge = proto::string_field(obj, "challenge").map_err(at)?;
    Ok(Acme {
        directory: proto::string_field(obj, "directory").map_err(at)?,
        contact: opt_string_field(obj, "contact").map_err(at)?,
        account_key_path: proto::string_field(obj, "account_key_path").map_err(at)?,
        account_url: proto::string_field(obj, "account_url").map_err(at)?,
        challenge: Challenge::parse(&challenge).ok_or_else(|| {
            StateError::bad_value(
                "tls.acme.challenge",
                format!("{challenge:?} is not \"http-01\" or \"dns-01\""),
            )
        })?,
        issued_at: int_field(obj, "issued_at").map_err(at)?,
        renew_after: int_field(obj, "renew_after").map_err(at)?,
    })
}

fn peer_to_json(peer: &Peer) -> Value {
    Value::obj([
        ("name", Value::str(peer.name.as_str())),
        ("public_key", Value::str(peer.public_key.as_str())),
        ("address", Value::str(peer.address.to_string())),
        ("token_hash", Value::str(peer.token_hash.as_str())),
        ("created_at", Value::Int(peer.created_at)),
        ("last_seen", opt_time(peer.last_seen)),
    ])
}

fn peer_from_json(value: &Value) -> Result<Peer, StateError> {
    let obj = proto::object(value)?;
    let name = proto::string_field(obj, "name")?;
    let token_hash = proto::string_field(obj, "token_hash")?;
    Ok(Peer {
        // Canonicalizing here means a hand-edited `MacBook` loads as
        // `macbook` rather than sitting in the file as a name no
        // command can match.
        name: DeviceName::parse(&name).map_err(|e| StateError::bad_value("name", e.to_string()))?,
        public_key: proto::string_field(obj, "public_key")?,
        address: address_field(obj, "address")?,
        token_hash: TokenHash::parse(&token_hash)
            .map_err(|e| StateError::bad_value("token_hash", e.to_string()))?,
        created_at: int_field(obj, "created_at")?,
        last_seen: opt_int_field(obj, "last_seen")?,
    })
}

fn code_to_json(code: &IssuedCode) -> Value {
    Value::obj([
        ("code", Value::str(code.code.as_str())),
        ("issued_at", Value::Int(code.issued_at)),
        ("expires_at", Value::Int(code.expires_at)),
        ("used_at", opt_time(code.used_at)),
    ])
}

fn code_from_json(value: &Value) -> Result<IssuedCode, StateError> {
    let obj = proto::object(value)?;
    let code = proto::string_field(obj, "code")?;
    Ok(IssuedCode {
        code: JoinCode::parse(&code).map_err(|e| StateError::bad_value("code", e.to_string()))?,
        issued_at: int_field(obj, "issued_at")?,
        expires_at: int_field(obj, "expires_at")?,
        used_at: opt_int_field(obj, "used_at")?,
    })
}

fn server_from_json(value: &Value) -> Result<ServerKeys, StateError> {
    let obj = proto::object(value).map_err(|e| e.within("server"))?;
    Ok(ServerKeys {
        private_key: PrivateKey::new(
            proto::string_field(obj, "private_key").map_err(|e| e.within("server"))?,
        ),
        public_key: proto::string_field(obj, "public_key").map_err(|e| e.within("server"))?,
        address: address_field(obj, "address").map_err(|e| e.within("server"))?,
    })
}

fn opt_str(text: Option<&str>) -> Value {
    match text {
        Some(text) => Value::str(text),
        None => Value::Null,
    }
}

fn opt_time(at: Option<i64>) -> Value {
    match at {
        Some(at) => Value::Int(at),
        None => Value::Null,
    }
}

fn int_field(obj: &Object, name: &str) -> Result<i64, DecodeError> {
    match obj.get(name) {
        None => Err(DecodeError::missing(name)),
        Some(found) => found.as_i64().ok_or_else(|| DecodeError::wrong_type(name)),
    }
}

/// A field that is present but may be `null` — `last_seen`, `used_at`.
/// Missing is still an error: the writer always emits the key, so an
/// absent one means a file we did not write.
fn opt_int_field(obj: &Object, name: &str) -> Result<Option<i64>, DecodeError> {
    match obj.get(name) {
        None => Err(DecodeError::missing(name)),
        Some(Value::Null) => Ok(None),
        Some(found) => found
            .as_i64()
            .map(Some)
            .ok_or_else(|| DecodeError::wrong_type(name)),
    }
}

/// A string field that is present but may be `null` — `contact`.
fn opt_string_field(obj: &Object, name: &str) -> Result<Option<String>, DecodeError> {
    match obj.get(name) {
        None => Err(DecodeError::missing(name)),
        Some(Value::Null) => Ok(None),
        Some(found) => found
            .as_str()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| DecodeError::wrong_type(name)),
    }
}

fn object_field<'a>(obj: &'a Object, name: &str) -> Result<&'a Object, DecodeError> {
    match obj.get(name) {
        None => Err(DecodeError::missing(name)),
        Some(found) => found
            .as_object()
            .ok_or_else(|| DecodeError::wrong_type(name)),
    }
}

/// An object field that is present but may be `null` — `tls.acme`.
fn opt_object_field<'a>(obj: &'a Object, name: &str) -> Result<Option<&'a Object>, DecodeError> {
    match obj.get(name) {
        None => Err(DecodeError::missing(name)),
        Some(Value::Null) => Ok(None),
        Some(found) => found
            .as_object()
            .map(Some)
            .ok_or_else(|| DecodeError::wrong_type(name)),
    }
}

fn port_field(obj: &Object, name: &str) -> Result<u16, StateError> {
    let value = int_field(obj, name)?;
    u16::try_from(value).map_err(|_| StateError::bad_value(name, format!("{value} is not a port")))
}

fn address_field(obj: &Object, name: &str) -> Result<Ipv4Addr, StateError> {
    let text = proto::string_field(obj, name)?;
    text.parse()
        .map_err(|_| StateError::bad_value(name, format!("{text:?} is not an IPv4 address")))
}

fn array_field<'a>(obj: &'a Object, name: &str) -> Result<&'a [Value], DecodeError> {
    match obj.get(name) {
        None => Err(DecodeError::missing(name)),
        Some(found) => found
            .as_array()
            .ok_or_else(|| DecodeError::wrong_type(name)),
    }
}

/// Why a state file could not be read.
#[derive(Debug, Clone, PartialEq)]
pub enum StateError {
    /// The text is not JSON at all.
    Json(json::Error),
    /// A field is missing or of the wrong JSON type.
    Shape(DecodeError),
    /// `version` is neither [`SCHEMA_VERSION`] nor the readable
    /// [`LEGACY_SCHEMA_VERSION`]. Refusing beats guessing: a newer file
    /// half-read and rewritten would lose whatever the newer version
    /// added.
    UnsupportedVersion(i64),
    /// Right JSON type, but not a valid value for that field — a
    /// malformed subnet, a port above 65535, a name breaking §8.1.
    BadValue { field: String, message: String },
}

impl StateError {
    fn bad_value(field: &str, message: String) -> StateError {
        StateError::BadValue {
            field: field.to_string(),
            message,
        }
    }

    /// Re-roots a nested error, so a bad peer is reported as
    /// `peers[1].token_hash` rather than `token_hash`.
    fn within(self, prefix: &str) -> StateError {
        match self {
            StateError::Shape(e) => StateError::Shape(e.within(prefix)),
            StateError::BadValue { field, message } => StateError::BadValue {
                field: if field.is_empty() {
                    prefix.to_string()
                } else {
                    format!("{prefix}.{field}")
                },
                message,
            },
            other => other,
        }
    }
}

impl From<DecodeError> for StateError {
    fn from(e: DecodeError) -> StateError {
        StateError::Shape(e)
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateError::Json(e) => write!(f, "state file is not valid JSON: {e}"),
            StateError::Shape(e) => write!(f, "{e}"),
            StateError::UnsupportedVersion(version) => write!(
                f,
                "state file is version {version}, this build writes {SCHEMA_VERSION} \
                 and reads {LEGACY_SCHEMA_VERSION}"
            ),
            StateError::BadValue { field, message } => {
                write!(f, "field {field:?}: {message}")
            }
        }
    }
}

impl std::error::Error for StateError {}

// -------------------------------------------------------- transitions

/// What a device offers when it registers: the code it was given, the
/// name it wants, its wg public key, and the hash of the token the
/// server is about to hand it (§7.1 — the plaintext is never stored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub code: JoinCode,
    pub name: DeviceName,
    pub public_key: String,
    pub token_hash: TokenHash,
}

/// Why a registration was turned down.
///
/// The server answers all of these with one `invalid_code`/`name_taken`
/// on the wire via [`JoinRejection::error_code`]; the detail is for its
/// own log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinRejection {
    /// No code by that name was ever issued here.
    UnknownCode,
    /// The code exists but cannot be redeemed now.
    CodeNotUsable(CodeStatus),
    /// Another device already answers to that name.
    NameTaken,
    /// Every host address in the subnet is handed out.
    SubnetFull,
}

impl JoinRejection {
    /// The wire code for this rejection. Every code-related refusal
    /// collapses to `invalid_code`: telling an unauthenticated caller
    /// whether a code was unknown, spent, or merely late only helps
    /// them probe (§8).
    pub fn error_code(&self) -> ErrorCode {
        match self {
            JoinRejection::UnknownCode | JoinRejection::CodeNotUsable(_) => ErrorCode::InvalidCode,
            JoinRejection::NameTaken => ErrorCode::NameTaken,
            JoinRejection::SubnetFull => ErrorCode::SubnetFull,
        }
    }
}

impl fmt::Display for JoinRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JoinRejection::UnknownCode => write!(f, "no such join code"),
            JoinRejection::CodeNotUsable(status) => write!(f, "join code is {status}"),
            JoinRejection::NameTaken => write!(f, "a device with that name is already registered"),
            JoinRejection::SubnetFull => write!(f, "no free address left in the subnet"),
        }
    }
}

impl ServerState {
    /// The device registered under `name`, if any.
    pub fn peer(&self, name: &DeviceName) -> Option<&Peer> {
        self.peers.iter().find(|peer| peer.name == *name)
    }

    /// Redeems a join code and registers a device: allocates the lowest
    /// free address, marks the code used at `now`, and appends the peer.
    ///
    /// All or nothing. A rejection leaves the state byte-identical — in
    /// particular a name collision does **not** burn the code, because
    /// the person's next move is to retry with another name and they
    /// would find their code gone.
    pub fn add_peer(
        &mut self,
        registration: Registration,
        now: i64,
    ) -> Result<Peer, JoinRejection> {
        let index = self
            .codes
            .iter()
            .position(|issued| issued.code == registration.code)
            .ok_or(JoinRejection::UnknownCode)?;
        let status = self.codes[index].status(now);
        if !status.is_usable() {
            return Err(JoinRejection::CodeNotUsable(status));
        }
        if name::is_taken(
            self.peers.iter().map(|peer| peer.name.as_str()),
            &registration.name,
        ) {
            return Err(JoinRejection::NameTaken);
        }
        let used: Vec<Ipv4Addr> = self.peers.iter().map(|peer| peer.address).collect();
        let address = self
            .subnet
            .allocate(&used)
            .ok_or(JoinRejection::SubnetFull)?;

        // Past every check: now the state may change.
        self.codes[index].used_at = Some(now);
        let peer = Peer {
            name: registration.name,
            public_key: registration.public_key,
            address,
            token_hash: registration.token_hash,
            created_at: now,
            last_seen: None,
        };
        self.peers.push(peer.clone());
        Ok(peer)
    }

    /// Removes a device, returning what was removed — `None` if no such
    /// name, so `anago rm typo` can say so instead of reporting success.
    ///
    /// Its address goes back into the pool for the next join, and its
    /// token dies with it: nothing is left to match against (§7.1).
    pub fn remove_peer(&mut self, name: &DeviceName) -> Option<Peer> {
        let index = self.peers.iter().position(|peer| peer.name == *name)?;
        Some(self.peers.remove(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::DEFAULT_TTL_SECS;

    const NOW: i64 = 1_755_500_000;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    fn hash(pattern: &str) -> TokenHash {
        TokenHash::parse(&pattern.repeat(64 / pattern.chars().count())).unwrap()
    }

    fn sample() -> ServerState {
        ServerState {
            domain: "net.example.com".to_string(),
            subnet: Subnet::parse("10.100.0.0/24").unwrap(),
            listen_port: 51820,
            api_port: 443,
            tls: Tls::manual("/etc/ssl/anago/fullchain.pem", "/etc/ssl/anago/privkey.pem"),
            cloudflare: None,
            server: ServerKeys {
                private_key: PrivateKey::new("cHJpdmF0ZSBrZXk="),
                public_key: "cHVibGljIGtleQ==".to_string(),
                address: ip("10.100.0.1"),
            },
            peers: vec![
                Peer {
                    name: DeviceName::parse("macbook").unwrap(),
                    public_key: "bWFjYm9vaw==".to_string(),
                    address: ip("10.100.0.2"),
                    token_hash: hash("ab"),
                    created_at: NOW,
                    last_seen: Some(NOW + 600),
                },
                Peer {
                    name: DeviceName::parse("맥북").unwrap(),
                    public_key: "ZGVza3RvcA==".to_string(),
                    address: ip("10.100.0.3"),
                    token_hash: hash("cd"),
                    created_at: NOW + 1,
                    last_seen: None,
                },
            ],
            codes: vec![
                IssuedCode {
                    code: JoinCode::parse("7QX4-M2KD").unwrap(),
                    issued_at: NOW - 900,
                    expires_at: NOW,
                    used_at: Some(NOW - 800),
                },
                IssuedCode::issue(JoinCode::parse("HJKM-NPQR").unwrap(), NOW, DEFAULT_TTL_SECS),
            ],
        }
    }

    fn empty() -> ServerState {
        ServerState {
            peers: Vec::new(),
            codes: Vec::new(),
            ..sample()
        }
    }

    /// Mutates one field of the sample's JSON, for the failure cases.
    fn with_field(key: &str, value: Value) -> Value {
        let mut obj = Object::new();
        for (k, v) in sample().to_json().as_object().unwrap().iter() {
            if k == key {
                obj.insert(k, value.clone()).unwrap();
            } else {
                obj.insert(k, v.clone()).unwrap();
            }
        }
        Value::Obj(obj)
    }

    fn err(value: &Value) -> StateError {
        ServerState::from_json(value).expect_err("should have failed")
    }

    #[test]
    fn round_trips_through_the_file_text() {
        let state = sample();
        let text = state.to_json_string();
        assert_eq!(ServerState::parse(&text).unwrap(), state);
        // And through the value form.
        assert_eq!(ServerState::from_json(&state.to_json()).unwrap(), state);
    }

    #[test]
    fn round_trips_a_fresh_server_with_no_peers_or_codes() {
        let state = empty();
        let text = state.to_json_string();
        assert!(text.contains("\"peers\": []"));
        assert!(text.contains("\"codes\": []"));
        assert_eq!(ServerState::parse(&text).unwrap(), state);
    }

    #[test]
    fn the_file_is_written_in_the_documented_shape() {
        // §9.1 pins these names and this order; a rename here changes
        // what every installed server reads.
        let text = empty().to_json_string();
        let keys: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("  \""))
            .map(|line| line.trim_start().split('"').nth(1).unwrap())
            .collect();
        assert_eq!(
            keys,
            [
                "version",
                "domain",
                "subnet",
                "listen_port",
                "api_port",
                "tls",
                "cloudflare",
                "server",
                "peers",
                "codes",
            ]
        );
        assert!(text.starts_with("{\n  \"version\": 2,"));
    }

    #[test]
    fn null_is_how_absent_times_are_written() {
        let text = sample().to_json_string();
        assert!(text.contains("\"last_seen\": null"), "{text}");
        assert!(text.contains("\"used_at\": null"), "{text}");
        assert!(text.contains("\"last_seen\": 1755500600"), "{text}");
    }

    #[test]
    fn an_unknown_version_stops_the_read() {
        // 3 is a file from a build that knows something we do not;
        // 0 is not a version at all. Both refuse rather than guess.
        assert_eq!(
            err(&with_field("version", Value::Int(3))),
            StateError::UnsupportedVersion(3)
        );
        assert_eq!(
            err(&with_field("version", Value::Int(0))),
            StateError::UnsupportedVersion(0)
        );
        assert_eq!(
            err(&with_field("version", Value::Int(3))).to_string(),
            "state file is version 3, this build writes 2 and reads 1"
        );
        // Shape problems in `version` are still shape problems.
        assert_eq!(
            err(&with_field("version", Value::str("1"))),
            StateError::Shape(DecodeError::wrong_type("version"))
        );
    }

    // ------------------------------------------------------------ tls

    fn acme() -> Acme {
        Acme {
            directory: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            contact: Some("jo@example.com".to_string()),
            account_key_path: "/var/lib/anago/tls/account.key".to_string(),
            account_url: "https://acme-v02.api.letsencrypt.org/acme/acct/1234".to_string(),
            challenge: Challenge::Http01,
            issued_at: 1755500000,
            renew_after: 1760684000,
        }
    }

    fn issued() -> ServerState {
        let mut state = sample();
        state.tls = Tls::acme(
            "/var/lib/anago/tls/fullchain.pem",
            "/var/lib/anago/tls/privkey.pem",
            acme(),
        );
        state.tls.not_after = Some(1763276000);
        state
    }

    /// Replaces one field inside the `tls` object.
    fn with_tls_field(key: &str, value: Value) -> Value {
        let state = issued().to_json();
        let mut tls = Object::new();
        for (k, v) in state.get("tls").unwrap().as_object().unwrap().iter() {
            let v = if k == key { value.clone() } else { v.clone() };
            tls.insert(k, v).unwrap();
        }
        let mut obj = Object::new();
        for (k, v) in state.as_object().unwrap().iter() {
            let v = if k == "tls" {
                Value::Obj(tls.clone())
            } else {
                v.clone()
            };
            obj.insert(k, v).unwrap();
        }
        Value::Obj(obj)
    }

    /// Replaces one field inside the `tls.acme` object.
    fn with_acme_field(key: &str, value: Value) -> Value {
        let state = issued().to_json();
        let current = state.get("tls").unwrap().get("acme").unwrap();
        let mut acme = Object::new();
        for (k, v) in current.as_object().unwrap().iter() {
            let v = if k == key { value.clone() } else { v.clone() };
            acme.insert(k, v).unwrap();
        }
        with_tls_field("acme", Value::Obj(acme))
    }

    #[test]
    fn an_acme_certificate_round_trips() {
        let state = issued();
        assert_eq!(ServerState::parse(&state.to_json_string()).unwrap(), state);
    }

    #[test]
    fn a_manual_certificate_round_trips() {
        let state = sample();
        assert_eq!(ServerState::parse(&state.to_json_string()).unwrap(), state);
        assert_eq!(state.tls.source, TlsSource::Manual);
    }

    #[test]
    fn both_challenges_survive_the_file() {
        for challenge in [Challenge::Http01, Challenge::Dns01] {
            let mut state = issued();
            if let TlsSource::Acme(acme) = &mut state.tls.source {
                acme.challenge = challenge;
            }
            let read = ServerState::parse(&state.to_json_string()).unwrap();
            assert_eq!(read.tls.renewable().unwrap().challenge, challenge);
        }
    }

    #[test]
    fn a_missing_contact_is_null_not_absent() {
        let mut state = issued();
        if let TlsSource::Acme(acme) = &mut state.tls.source {
            acme.contact = None;
        }
        let text = state.to_json_string();
        assert!(text.contains("\"contact\": null"), "{text}");
        assert_eq!(ServerState::parse(&text).unwrap(), state);
    }

    #[test]
    fn the_tls_object_is_written_in_the_documented_shape() {
        // §9.1 pins these names and this order.
        let text = issued().to_json_string();
        let keys: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("    \""))
            .map(|line| line.trim_start().split('"').nth(1).unwrap())
            .take(5)
            .collect();
        assert_eq!(
            keys,
            ["source", "cert_path", "key_path", "not_after", "acme"]
        );
    }

    #[test]
    fn a_manual_source_writes_a_null_acme_and_a_null_expiry() {
        let text = sample().to_json_string();
        assert!(text.contains("\"source\": \"manual\""), "{text}");
        assert!(text.contains("\"acme\": null"), "{text}");
        assert!(text.contains("\"not_after\": null"), "{text}");
    }

    #[test]
    fn who_renews_is_the_question_the_source_answers() {
        assert!(sample().tls.renewable().is_none());
        assert_eq!(issued().tls.renewable(), Some(&acme()));
    }

    #[test]
    fn the_two_contradictions_are_refused() {
        // Neither half of a mismatch can be trusted: guessing "manual"
        // stops renewals, guessing "acme" overwrites someone's file.
        assert_eq!(
            err(&with_tls_field("source", Value::str("manual"))),
            StateError::bad_value(
                "tls.acme",
                "source is \"manual\" but acme details are present".to_string()
            )
        );
        assert_eq!(
            err(&with_tls_field("acme", Value::Null)),
            StateError::bad_value(
                "tls.acme",
                "source is \"acme\" but acme details are null".to_string()
            )
        );
    }

    #[test]
    fn an_unknown_source_or_challenge_is_refused() {
        assert_eq!(
            err(&with_tls_field("source", Value::str("certbot"))),
            StateError::bad_value(
                "tls.source",
                "\"certbot\" is not \"manual\" or \"acme\"".to_string()
            )
        );
        assert_eq!(
            err(&with_acme_field("challenge", Value::str("tls-alpn-01"))),
            StateError::bad_value(
                "tls.acme.challenge",
                "\"tls-alpn-01\" is not \"http-01\" or \"dns-01\"".to_string()
            )
        );
    }

    #[test]
    fn tls_fields_are_named_when_they_are_missing_or_mistyped() {
        assert_eq!(
            err(&with_tls_field("cert_path", Value::Int(1))),
            StateError::Shape(DecodeError::wrong_type("cert_path").within("tls"))
        );
        assert_eq!(
            err(&with_tls_field("not_after", Value::str("soon"))),
            StateError::Shape(DecodeError::wrong_type("not_after").within("tls"))
        );
        assert_eq!(
            err(&with_field("tls", Value::str("/etc/ssl/x.pem"))),
            StateError::Shape(DecodeError::wrong_type("tls"))
        );
    }

    // ------------------------------------------------------ renewal

    const DAY: i64 = 86_400;
    const T0: i64 = 1_755_500_000;

    /// An ACME certificate issued at `issued_at` and expiring at
    /// `not_after`, with both times recorded the way issuance does.
    fn issued_tls(issued_at: i64, not_after: Option<i64>) -> Tls {
        let mut tls = issued().tls;
        tls.not_after = not_after;
        if let TlsSource::Acme(acme) = &mut tls.source {
            acme.issued(issued_at, not_after);
        }
        tls
    }

    #[test]
    fn renewal_lands_at_two_thirds_of_the_lifetime() {
        // The three lifetimes Let's Encrypt is moving between, and the
        // renewal day each one implies (§9.1).
        for (lifetime_days, renew_day) in [(90, 60), (45, 30), (6, 4)] {
            assert_eq!(
                renew_after(T0, Some(T0 + lifetime_days * DAY)),
                T0 + renew_day * DAY,
                "{lifetime_days}-day certificate"
            );
        }
        // 64 days does not divide evenly; two thirds of it in seconds
        // does, and that is what the arithmetic uses.
        assert_eq!(renew_after(T0, Some(T0 + 64 * DAY)), T0 + 64 * DAY * 2 / 3);
    }

    #[test]
    fn an_unreadable_expiry_assumes_the_shortest_lifetime() {
        assert_eq!(renew_after(T0, None), T0 + 30 * DAY);
        assert_eq!(UNKNOWN_LIFETIME_RENEW_SECS, 30 * DAY);
        // Never later than what a real short-lived certificate would
        // have produced: not knowing must not renew later than knowing.
        assert!(renew_after(T0, None) <= renew_after(T0, Some(T0 + 45 * DAY)));
    }

    #[test]
    fn a_certificate_that_is_already_expired_is_due_at_once() {
        // A wrong clock or a hand-edited file. Landing at or before the
        // issue time reads as "renew now", which is the safe way to be
        // wrong.
        assert!(renew_after(T0, Some(T0)) <= T0);
        assert!(renew_after(T0, Some(T0 - 10 * DAY)) <= T0);
        let expired = issued_tls(T0, Some(T0 - 10 * DAY));
        assert!(expired.needs_renewal(T0, RENEWAL_LEAD_SECS));
    }

    // The bare safety net (§9.1), on its own terms.

    #[test]
    fn the_net_opens_one_lead_before_the_expiry() {
        let expires_at = T0 + 45 * DAY;
        let opens = expires_at - RENEWAL_LEAD_SECS;
        assert!(!needs_renewal(expires_at, opens - 1, RENEWAL_LEAD_SECS));
        assert!(needs_renewal(expires_at, opens, RENEWAL_LEAD_SECS));
        assert!(needs_renewal(expires_at, opens + 1, RENEWAL_LEAD_SECS));
        // And it stays open past the expiry itself.
        assert!(needs_renewal(
            expires_at,
            expires_at + DAY,
            RENEWAL_LEAD_SECS
        ));
    }

    #[test]
    fn the_net_with_no_lead_is_the_expiry_itself() {
        let expires_at = T0 + 45 * DAY;
        assert!(!needs_renewal(expires_at, expires_at - 1, 0));
        assert!(needs_renewal(expires_at, expires_at, 0));
        // A negative lead would open the net *after* the expiry it
        // guards, so it counts as none.
        assert!(!needs_renewal(expires_at, expires_at - 1, -DAY));
        assert!(needs_renewal(expires_at, expires_at, -DAY));
    }

    #[test]
    fn the_net_saturates_at_the_edges_of_time() {
        assert!(needs_renewal(i64::MIN, i64::MIN, RENEWAL_LEAD_SECS));
        assert!(!needs_renewal(i64::MAX, 0, RENEWAL_LEAD_SECS));
        assert!(needs_renewal(i64::MAX, i64::MAX, RENEWAL_LEAD_SECS));
    }

    #[test]
    fn extreme_times_saturate_rather_than_panic() {
        // Nothing here should overflow on a nonsense file.
        let _ = renew_after(i64::MAX, Some(i64::MAX));
        let _ = renew_after(i64::MIN, Some(i64::MAX));
        let _ = renew_after(i64::MAX, None);
        let _ = renewal_due(i64::MIN, Some(i64::MIN), RENEWAL_LEAD_SECS);
        let _ = renewal_due(i64::MAX, Some(i64::MAX), RENEWAL_LEAD_SECS);
    }

    #[test]
    fn the_due_second_is_due() {
        let tls = issued_tls(T0, Some(T0 + 90 * DAY));
        let due = tls.renewal_due(RENEWAL_LEAD_SECS).unwrap();
        assert_eq!(due, T0 + 60 * DAY);
        assert!(!tls.needs_renewal(due - 1, RENEWAL_LEAD_SECS));
        assert!(tls.needs_renewal(due, RENEWAL_LEAD_SECS));
        assert!(tls.needs_renewal(due + 1, RENEWAL_LEAD_SECS));
    }

    #[test]
    fn without_an_expiry_the_stored_decision_stands_alone() {
        let stored = T0 + 60 * DAY;
        assert_eq!(renewal_due(stored, None, RENEWAL_LEAD_SECS), stored);
    }

    #[test]
    fn the_safety_net_pulls_a_late_decision_forward() {
        // The case §9.1 built it for: a `renew_after` computed against a
        // 90-day lifetime sitting on a 45-day certificate.
        let not_after = T0 + 45 * DAY;
        let stale = T0 + 60 * DAY; // past the expiry entirely
        assert_eq!(
            renewal_due(stale, Some(not_after), RENEWAL_LEAD_SECS),
            not_after - RENEWAL_LEAD_SECS
        );
        // Which is exactly where the bare net opens.
        assert!(needs_renewal(
            not_after,
            not_after - RENEWAL_LEAD_SECS,
            RENEWAL_LEAD_SECS
        ));
    }

    #[test]
    fn the_safety_net_does_not_fire_on_a_healthy_certificate() {
        // At every lifetime, two thirds comes before the last week.
        for lifetime_days in [45, 64, 90] {
            let not_after = T0 + lifetime_days * DAY;
            let planned = renew_after(T0, Some(not_after));
            assert_eq!(
                renewal_due(planned, Some(not_after), RENEWAL_LEAD_SECS),
                planned,
                "{lifetime_days}-day certificate"
            );
        }
    }

    #[test]
    fn the_lead_is_a_boundary_of_its_own() {
        let not_after = T0 + 45 * DAY;
        let stale = not_after + DAY;
        // No lead: the net sits exactly on the expiry.
        assert_eq!(renewal_due(stale, Some(not_after), 0), not_after);
        // A negative lead would push the net past the expiry it guards,
        // so it is treated as none.
        assert_eq!(renewal_due(stale, Some(not_after), -DAY), not_after);
        assert_eq!(RENEWAL_LEAD_SECS, 7 * DAY);
    }

    #[test]
    fn recording_an_issuance_sets_both_times_together() {
        let mut acme = acme();
        acme.issued(T0, Some(T0 + 45 * DAY));
        assert_eq!(acme.issued_at, T0);
        assert_eq!(acme.renew_after, T0 + 30 * DAY);
    }

    #[test]
    fn a_manual_certificate_is_never_due() {
        // Saying yes here would overwrite a file anago does not own.
        let tls = Tls::manual("/etc/ssl/anago/fullchain.pem", "/etc/ssl/anago/privkey.pem");
        assert_eq!(tls.renewal_due(RENEWAL_LEAD_SECS), None);
        assert!(!tls.needs_renewal(i64::MAX, RENEWAL_LEAD_SECS));
    }

    #[test]
    fn a_short_certificate_is_caught_by_the_net_not_the_plan() {
        // Why the two are composed: a stored decision that predates a
        // lifetime change must not outlive the certificate.
        let not_after = T0 + 45 * DAY;
        let mut tls = issued_tls(T0, Some(not_after));
        if let TlsSource::Acme(acme) = &mut tls.source {
            acme.renew_after = T0 + 60 * DAY; // computed for 90 days
        }
        assert_eq!(
            tls.renewal_due(RENEWAL_LEAD_SECS),
            Some(not_after - RENEWAL_LEAD_SECS)
        );
        assert!(tls.needs_renewal(not_after - RENEWAL_LEAD_SECS, RENEWAL_LEAD_SECS));
        assert!(!tls.needs_renewal(not_after - RENEWAL_LEAD_SECS - 1, RENEWAL_LEAD_SECS));
    }

    #[test]
    fn a_hand_edited_date_is_honoured() {
        // §9.1 makes this a value a person may pull forward; the only
        // thing that overrides them is the expiry safety net.
        let mut tls = issued().tls;
        tls.not_after = Some(T0 + 90 * DAY);
        if let TlsSource::Acme(acme) = &mut tls.source {
            acme.renew_after = T0;
        }
        assert_eq!(tls.renewal_due(RENEWAL_LEAD_SECS), Some(T0));
        assert!(tls.needs_renewal(T0, RENEWAL_LEAD_SECS));
    }

    // --------------------------------------------------- cloudflare

    fn cloudflare() -> Cloudflare {
        Cloudflare {
            zone_id: "023e105f4ecef8ad9ca31a8372d0c353".to_string(),
            record_id: Some("372e67954025e0ba6aaa6d586b9e0b59".to_string()),
            token_path: Some("/var/lib/anago/cf-token".to_string()),
        }
    }

    #[test]
    fn a_cloudflare_block_round_trips() {
        let mut state = issued();
        state.cloudflare = Some(cloudflare());
        assert_eq!(ServerState::parse(&state.to_json_string()).unwrap(), state);
    }

    #[test]
    fn a_zone_without_a_record_or_a_stored_token_round_trips() {
        // The HTTP-01 shape: the zone is known, no record has been made
        // yet, and the token was used once and forgotten (§9.1).
        let mut state = issued();
        state.cloudflare = Some(Cloudflare {
            record_id: None,
            token_path: None,
            ..cloudflare()
        });
        let text = state.to_json_string();
        assert!(text.contains("\"record_id\": null"), "{text}");
        assert!(text.contains("\"token_path\": null"), "{text}");
        assert_eq!(ServerState::parse(&text).unwrap(), state);
    }

    #[test]
    fn no_cloudflare_is_written_as_null_not_left_out() {
        let text = sample().to_json_string();
        assert!(text.contains("\n  \"cloudflare\": null,"), "{text}");
        assert_eq!(ServerState::parse(&text).unwrap().cloudflare, None);
    }

    #[test]
    fn the_cloudflare_block_is_written_in_the_documented_shape() {
        let mut state = issued();
        state.cloudflare = Some(cloudflare());
        let text = state.to_json_string();
        let start = text.find("\"cloudflare\": {").unwrap();
        let keys: Vec<&str> = text[start..]
            .lines()
            .skip(1)
            .take(3)
            .map(|line| line.trim_start().split('"').nth(1).unwrap())
            .collect();
        assert_eq!(keys, ["zone_id", "record_id", "token_path"]);
    }

    #[test]
    fn cloudflare_fields_are_named_when_they_are_wrong() {
        let mut state = issued();
        state.cloudflare = Some(cloudflare());
        let value = state.to_json();
        let mut cf = Object::new();
        for (k, v) in value.get("cloudflare").unwrap().as_object().unwrap().iter() {
            let v = if k == "zone_id" {
                Value::Int(1)
            } else {
                v.clone()
            };
            cf.insert(k, v).unwrap();
        }
        let mut obj = Object::new();
        for (k, v) in value.as_object().unwrap().iter() {
            let v = if k == "cloudflare" {
                Value::Obj(cf.clone())
            } else {
                v.clone()
            };
            obj.insert(k, v).unwrap();
        }
        assert_eq!(
            err(&Value::Obj(obj)),
            StateError::Shape(DecodeError::wrong_type("zone_id").within("cloudflare"))
        );
        assert_eq!(
            err(&with_field("cloudflare", Value::str("023e105f"))),
            StateError::Shape(DecodeError::wrong_type("cloudflare"))
        );
    }

    #[test]
    fn a_version_two_file_without_the_key_is_refused() {
        // The writer always emits it, so an absent key means a file we
        // did not write — the same rule `last_seen` follows.
        let mut obj = Object::new();
        for (k, v) in sample().to_json().as_object().unwrap().iter() {
            if k != "cloudflare" {
                obj.insert(k, v.clone()).unwrap();
            }
        }
        assert_eq!(
            err(&Value::Obj(obj)),
            StateError::Shape(DecodeError::missing("cloudflare"))
        );
    }

    // ------------------------------------------- reading an M0 file

    /// A version 1 file exactly as M0 wrote it.
    fn legacy_text() -> String {
        let text = sample().to_json_string();
        let mut obj = Object::new();
        for (k, v) in json::parse(&text).unwrap().as_object().unwrap().iter() {
            match k {
                "version" => obj.insert("version", Value::Int(1)).unwrap(),
                "tls" => {
                    obj.insert("tls_cert_path", Value::str("/etc/ssl/anago/fullchain.pem"))
                        .unwrap();
                    obj.insert("tls_key_path", Value::str("/etc/ssl/anago/privkey.pem"))
                        .unwrap();
                }
                // M0 never wrote this key; a v1 file has no trace of it.
                "cloudflare" => {}
                _ => obj.insert(k, v.clone()).unwrap(),
            }
        }
        json::to_string_pretty(&Value::Obj(obj))
    }

    #[test]
    fn a_version_one_file_upgrades_to_a_manual_certificate() {
        let read = ServerState::parse(&legacy_text()).unwrap();
        // The upgrade is total, so it lands on exactly the sample.
        assert_eq!(read, sample());
        assert_eq!(read.tls.source, TlsSource::Manual);
        assert_eq!(read.tls.not_after, None);
        assert_eq!(read.cloudflare, None);
    }

    #[test]
    fn upgrading_does_not_rewrite_the_file() {
        // Reading is reading (§9.1): the caller gets a value, and the
        // file on disk is still version 1 until something else saves.
        let text = legacy_text();
        let before = text.clone();
        let _ = ServerState::parse(&text).unwrap();
        assert_eq!(text, before);
        assert!(text.contains("\"version\": 1"), "{text}");
    }

    #[test]
    fn saving_an_upgraded_state_writes_version_two() {
        let read = ServerState::parse(&legacy_text()).unwrap();
        let written = read.to_json_string();
        assert!(written.starts_with("{\n  \"version\": 2,"), "{written}");
        assert!(!written.contains("tls_cert_path"), "{written}");
        // A file stamped 2 has to *be* a version 2 file, absent parts
        // included — that is what the stamp promises (§9.1).
        assert!(written.contains("\n  \"cloudflare\": null,"), "{written}");
        assert_eq!(ServerState::parse(&written).unwrap(), read);
    }

    #[test]
    fn a_version_one_file_without_the_old_paths_is_refused() {
        let text = legacy_text().replace("tls_cert_path", "cert_path");
        assert_eq!(
            err(&json::parse(&text).unwrap()),
            StateError::Shape(DecodeError::missing("tls_cert_path"))
        );
    }

    #[test]
    fn missing_and_mistyped_fields_are_named() {
        let mut obj = Object::new();
        obj.insert("version", Value::Int(1)).unwrap();
        assert_eq!(
            err(&Value::Obj(obj)),
            StateError::Shape(DecodeError::missing("subnet"))
        );

        assert_eq!(
            err(&with_field("domain", Value::Int(1))),
            StateError::Shape(DecodeError::wrong_type("domain"))
        );
        assert_eq!(
            err(&with_field("peers", Value::str("macbook"))),
            StateError::Shape(DecodeError::wrong_type("peers"))
        );
        assert_eq!(
            err(&Value::Int(1)),
            StateError::Shape(DecodeError::wrong_type(""))
        );
    }

    #[test]
    fn values_are_checked_against_the_rules_of_their_own_type() {
        assert_eq!(
            err(&with_field("subnet", Value::str("10.100.0.0/16"))),
            StateError::BadValue {
                field: "subnet".to_string(),
                message: "anago supports /24 only, got /16".to_string(),
            }
        );
        assert!(matches!(
            err(&with_field("listen_port", Value::Int(65_536))),
            StateError::BadValue { field, .. } if field == "listen_port"
        ));
        assert!(matches!(
            err(&with_field("api_port", Value::Int(-1))),
            StateError::BadValue { field, .. } if field == "api_port"
        ));
    }

    #[test]
    fn the_server_address_must_be_the_subnets_dot_one() {
        // A hand-edited mismatch would otherwise generate wg configs
        // pointing at an address nothing answers on.
        let mut server = Object::new();
        server
            .insert("private_key", Value::str("cHJpdmF0ZSBrZXk="))
            .unwrap();
        server
            .insert("public_key", Value::str("cHVibGljIGtleQ=="))
            .unwrap();
        server.insert("address", Value::str("10.100.0.9")).unwrap();
        let e = err(&with_field("server", Value::Obj(server)));
        assert!(
            matches!(&e, StateError::BadValue { field, .. } if field == "server.address"),
            "{e}"
        );
    }

    #[test]
    fn a_bad_peer_is_reported_with_its_index() {
        let mut peer = Object::new();
        peer.insert("name", Value::str("desktop")).unwrap();
        peer.insert("public_key", Value::str("ZGVza3RvcA=="))
            .unwrap();
        peer.insert("address", Value::str("10.100.0.300")).unwrap();
        peer.insert("token_hash", Value::str(hash("ab").as_str()))
            .unwrap();
        peer.insert("created_at", Value::Int(NOW)).unwrap();
        peer.insert("last_seen", Value::Null).unwrap();
        let list = Value::Arr(vec![peer_to_json(&sample().peers[0]), Value::Obj(peer)]);
        let e = err(&with_field("peers", list));
        assert!(
            matches!(&e, StateError::BadValue { field, .. } if field == "peers[1].address"),
            "{e}"
        );

        // A missing key inside an element keeps the index too.
        let list = Value::Arr(vec![Value::obj([("name", Value::str("desktop"))])]);
        assert_eq!(
            err(&with_field("peers", list)),
            StateError::Shape(DecodeError::missing("peers[0].token_hash"))
        );
        // And an element that is not an object at all.
        let list = Value::Arr(vec![Value::Int(1)]);
        assert_eq!(
            err(&with_field("peers", list)),
            StateError::Shape(DecodeError::wrong_type("peers[0]"))
        );
    }

    #[test]
    fn a_bad_code_is_reported_with_its_index() {
        let list = Value::Arr(vec![Value::obj([
            ("code", Value::str("OOOO-OOOO")),
            ("issued_at", Value::Int(NOW)),
            ("expires_at", Value::Int(NOW + 900)),
            ("used_at", Value::Null),
        ])]);
        let e = err(&with_field("codes", list));
        assert!(
            matches!(&e, StateError::BadValue { field, .. } if field == "codes[0].code"),
            "{e}"
        );
    }

    #[test]
    fn absent_optional_times_must_still_be_written_as_null() {
        // The writer always emits the key; a missing one means a file
        // we did not write, and guessing `None` would hide that.
        let list = Value::Arr(vec![Value::obj([
            ("code", Value::str("7QX4-M2KD")),
            ("issued_at", Value::Int(NOW)),
            ("expires_at", Value::Int(NOW + 900)),
        ])]);
        assert_eq!(
            err(&with_field("codes", list)),
            StateError::Shape(DecodeError::missing("codes[0].used_at"))
        );
    }

    #[test]
    fn hand_edited_names_are_canonicalized_on_read() {
        let list = Value::Arr(vec![Value::obj([
            ("name", Value::str("MacBook")),
            ("public_key", Value::str("bWFjYm9vaw==")),
            ("address", Value::str("10.100.0.2")),
            ("token_hash", Value::str(hash("ab").as_str())),
            ("created_at", Value::Int(NOW)),
            ("last_seen", Value::Null),
        ])]);
        let state = ServerState::from_json(&with_field("peers", list)).unwrap();
        assert_eq!(state.peers[0].name.as_str(), "macbook");
        // A name no rule can accept is refused rather than repaired.
        let list = Value::Arr(vec![Value::obj([
            ("name", Value::str("mac book")),
            ("public_key", Value::str("bWFjYm9vaw==")),
            ("address", Value::str("10.100.0.2")),
            ("token_hash", Value::str(hash("ab").as_str())),
            ("created_at", Value::Int(NOW)),
            ("last_seen", Value::Null),
        ])]);
        assert!(matches!(
            err(&with_field("peers", list)),
            StateError::BadValue { field, .. } if field == "peers[0].name"
        ));
    }

    #[test]
    fn unknown_fields_are_ignored() {
        // A file written by a future build that added a field: the keys
        // this build knows still load (§9.1).
        let mut obj = sample().to_json().as_object().unwrap().clone();
        obj.insert("dns_provider", Value::str("cloudflare"))
            .unwrap();
        assert_eq!(ServerState::from_json(&Value::Obj(obj)).unwrap(), sample());
    }

    #[test]
    fn malformed_text_is_reported_as_such() {
        let e = ServerState::parse("{not json").unwrap_err();
        assert!(matches!(e, StateError::Json(_)), "{e}");
        assert!(
            e.to_string().starts_with("state file is not valid JSON:"),
            "{e}"
        );
    }

    #[test]
    fn secrets_do_not_print_themselves() {
        let state = sample();
        let printed = format!("{:?}", state.server);
        assert!(printed.contains("PrivateKey(redacted)"), "{printed}");
        assert!(!printed.contains("cHJpdmF0ZSBrZXk="), "{printed}");
        // The state file itself does carry the key — that is the point
        // of 0600 — so serialization still writes it.
        assert!(state.to_json_string().contains("cHJpdmF0ZSBrZXk="));
    }

    // --------------------------------------------------- transitions

    fn device(name: &str) -> DeviceName {
        DeviceName::parse(name).unwrap()
    }

    fn registration(code: &str, name: &str) -> Registration {
        Registration {
            code: JoinCode::parse(code).unwrap(),
            name: device(name),
            public_key: format!("{name}-key"),
            token_hash: hash("ef"),
        }
    }

    /// A server with one live code and no devices yet.
    fn fresh() -> ServerState {
        let mut state = empty();
        state.codes = vec![IssuedCode::issue(
            JoinCode::parse("7QX4-M2KD").unwrap(),
            NOW,
            DEFAULT_TTL_SECS,
        )];
        state
    }

    #[test]
    fn a_join_allocates_an_address_and_spends_the_code() {
        let mut state = fresh();
        let peer = state
            .add_peer(registration("7QX4-M2KD", "macbook"), NOW + 5)
            .unwrap();

        assert_eq!(peer.address, ip("10.100.0.2"));
        assert_eq!(peer.name, device("macbook"));
        assert_eq!(peer.created_at, NOW + 5);
        assert_eq!(peer.last_seen, None);
        assert_eq!(state.peers, vec![peer.clone()]);
        assert_eq!(state.peer(&device("macbook")), Some(&peer));

        // The code is spent, and spent codes stay in the file (§9.1).
        assert_eq!(state.codes[0].used_at, Some(NOW + 5));
        assert_eq!(state.codes[0].status(NOW + 6), CodeStatus::Used);
        assert_eq!(state.codes.len(), 1);
    }

    #[test]
    fn a_second_device_gets_the_next_address() {
        let mut state = fresh();
        state.codes.push(IssuedCode::issue(
            JoinCode::parse("HJKM-NPQR").unwrap(),
            NOW,
            DEFAULT_TTL_SECS,
        ));
        state
            .add_peer(registration("7QX4-M2KD", "macbook"), NOW)
            .unwrap();
        let second = state
            .add_peer(registration("HJKM-NPQR", "데스크톱"), NOW)
            .unwrap();
        assert_eq!(second.address, ip("10.100.0.3"));
        assert_eq!(state.peers.len(), 2);
    }

    #[test]
    fn one_code_registers_one_device() {
        let mut state = fresh();
        state
            .add_peer(registration("7QX4-M2KD", "macbook"), NOW)
            .unwrap();
        // Same code again: single use, so it is spent now.
        assert_eq!(
            state.add_peer(registration("7QX4-M2KD", "desktop"), NOW),
            Err(JoinRejection::CodeNotUsable(CodeStatus::Used))
        );
        assert_eq!(state.peers.len(), 1);
    }

    #[test]
    fn an_unknown_or_expired_code_registers_nothing() {
        let mut state = fresh();
        assert_eq!(
            state.add_peer(registration("HJKM-NPQR", "macbook"), NOW),
            Err(JoinRejection::UnknownCode)
        );
        // The code exists but its 15 minutes are up.
        assert_eq!(
            state.add_peer(registration("7QX4-M2KD", "macbook"), NOW + DEFAULT_TTL_SECS),
            Err(JoinRejection::CodeNotUsable(CodeStatus::Expired))
        );
        assert!(state.peers.is_empty());
        assert_eq!(state.codes[0].used_at, None);
    }

    #[test]
    fn a_duplicate_name_is_refused_without_burning_the_code() {
        let mut state = fresh();
        state
            .add_peer(registration("7QX4-M2KD", "macbook"), NOW)
            .unwrap();
        state.codes.push(IssuedCode::issue(
            JoinCode::parse("HJKM-NPQR").unwrap(),
            NOW,
            DEFAULT_TTL_SECS,
        ));

        let before = state.clone();
        assert_eq!(
            state.add_peer(registration("HJKM-NPQR", "MacBook"), NOW),
            Err(JoinRejection::NameTaken)
        );
        // Byte-identical: the retry with another name must still work.
        assert_eq!(state, before);
        assert_eq!(state.codes[1].used_at, None);

        let peer = state
            .add_peer(registration("HJKM-NPQR", "macbook-2"), NOW)
            .unwrap();
        assert_eq!(peer.address, ip("10.100.0.3"));
    }

    #[test]
    fn a_full_subnet_refuses_the_join_and_keeps_the_code() {
        let mut state = fresh();
        state.peers = (2..=254)
            .map(|octet| Peer {
                name: device(&format!("device-{octet}")),
                public_key: format!("key-{octet}"),
                address: ip(&format!("10.100.0.{octet}")),
                token_hash: hash("ab"),
                created_at: NOW,
                last_seen: None,
            })
            .collect();
        assert_eq!(state.peers.len(), 253);

        let before = state.clone();
        assert_eq!(
            state.add_peer(registration("7QX4-M2KD", "one-too-many"), NOW),
            Err(JoinRejection::SubnetFull)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn rejections_carry_the_wire_code_the_server_answers_with() {
        // Nothing about *which* way a code failed reaches the caller.
        assert_eq!(
            JoinRejection::UnknownCode.error_code(),
            ErrorCode::InvalidCode
        );
        assert_eq!(
            JoinRejection::CodeNotUsable(CodeStatus::Expired).error_code(),
            ErrorCode::InvalidCode
        );
        assert_eq!(
            JoinRejection::CodeNotUsable(CodeStatus::Used).error_code(),
            ErrorCode::InvalidCode
        );
        assert_eq!(JoinRejection::NameTaken.error_code(), ErrorCode::NameTaken);
        assert_eq!(
            JoinRejection::SubnetFull.error_code(),
            ErrorCode::SubnetFull
        );

        assert_eq!(JoinRejection::UnknownCode.to_string(), "no such join code");
        assert_eq!(
            JoinRejection::CodeNotUsable(CodeStatus::Expired).to_string(),
            "join code is expired"
        );
    }

    #[test]
    fn removing_a_device_frees_its_address() {
        let mut state = fresh();
        state.codes.push(IssuedCode::issue(
            JoinCode::parse("HJKM-NPQR").unwrap(),
            NOW,
            DEFAULT_TTL_SECS,
        ));
        let first = state
            .add_peer(registration("7QX4-M2KD", "macbook"), NOW)
            .unwrap();

        let removed = state.remove_peer(&device("macbook")).unwrap();
        assert_eq!(removed, first);
        assert!(state.peers.is_empty());
        assert_eq!(state.peer(&device("macbook")), None);

        // .2 is free again for the next device.
        let next = state
            .add_peer(registration("HJKM-NPQR", "desktop"), NOW)
            .unwrap();
        assert_eq!(next.address, ip("10.100.0.2"));
    }

    #[test]
    fn removing_a_name_that_is_not_there_changes_nothing() {
        let mut state = sample();
        let before = state.clone();
        assert_eq!(state.remove_peer(&device("phone")), None);
        assert_eq!(state, before);

        // Only the named device goes.
        assert_eq!(
            state.remove_peer(&device("macbook")).unwrap().address,
            ip("10.100.0.2")
        );
        assert_eq!(state.peers.len(), 1);
        assert_eq!(state.peers[0].name, device("맥북"));
    }

    #[test]
    fn a_state_survives_a_round_trip_after_transitions() {
        let mut state = fresh();
        state
            .add_peer(registration("7QX4-M2KD", "macbook"), NOW)
            .unwrap();
        state.remove_peer(&device("macbook"));
        state.codes.push(IssuedCode::issue(
            JoinCode::parse("HJKM-NPQR").unwrap(),
            NOW,
            DEFAULT_TTL_SECS,
        ));
        state
            .add_peer(registration("HJKM-NPQR", "맥북"), NOW + 1)
            .unwrap();

        let text = state.to_json_string();
        assert_eq!(ServerState::parse(&text).unwrap(), state);
    }
}
