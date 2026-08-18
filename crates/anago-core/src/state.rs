//! The server's state file — `/var/lib/anago/state.json` (DESIGN.md
//! §9.1). One file, no database; this module is its schema.
//!
//! Reading and writing live here so the shape has exactly one
//! definition. The binary supplies the atomic write and the lock; what
//! it gets from core is text in, value out.
//!
//! Decoding validates every field against the rules of the type that
//! owns it — a subnet through [`Subnet`], a name through
//! [`DeviceName`], a hash through [`TokenHash`]. Unknown fields are
//! ignored (§9.1), and a `version` that is not [`SCHEMA_VERSION`] stops
//! the read, so an older binary cannot overwrite a newer file.

use std::fmt;
use std::net::Ipv4Addr;

use crate::code::{IssuedCode, JoinCode};
use crate::json::{self, Object, Value};
use crate::name::DeviceName;
use crate::proto::{self, DecodeError};
use crate::subnet::Subnet;
use crate::token::TokenHash;

/// Schema version of the state file. M0 writes and accepts 1 only.
pub const SCHEMA_VERSION: i64 = 1;

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
    pub tls_cert_path: String,
    pub tls_key_path: String,
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
            ("tls_cert_path", Value::str(self.tls_cert_path.as_str())),
            ("tls_key_path", Value::str(self.tls_key_path.as_str())),
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
        if version != SCHEMA_VERSION {
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
            tls_cert_path: proto::string_field(obj, "tls_cert_path")?,
            tls_key_path: proto::string_field(obj, "tls_key_path")?,
            server,
            peers,
            codes,
        })
    }
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
    /// `version` is not [`SCHEMA_VERSION`]. Refusing beats guessing: a
    /// newer file half-read and rewritten would lose whatever the newer
    /// version added.
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
                "state file is version {version}, this build writes {SCHEMA_VERSION}"
            ),
            StateError::BadValue { field, message } => {
                write!(f, "field {field:?}: {message}")
            }
        }
    }
}

impl std::error::Error for StateError {}

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
            tls_cert_path: "/etc/ssl/anago/fullchain.pem".to_string(),
            tls_key_path: "/etc/ssl/anago/privkey.pem".to_string(),
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
                "tls_cert_path",
                "tls_key_path",
                "server",
                "peers",
                "codes",
            ]
        );
        assert!(text.starts_with("{\n  \"version\": 1,"));
    }

    #[test]
    fn null_is_how_absent_times_are_written() {
        let text = sample().to_json_string();
        assert!(text.contains("\"last_seen\": null"), "{text}");
        assert!(text.contains("\"used_at\": null"), "{text}");
        assert!(text.contains("\"last_seen\": 1755500600"), "{text}");
    }

    #[test]
    fn a_different_version_stops_the_read() {
        assert_eq!(
            err(&with_field("version", Value::Int(2))),
            StateError::UnsupportedVersion(2)
        );
        assert_eq!(
            err(&with_field("version", Value::Int(0))),
            StateError::UnsupportedVersion(0)
        );
        assert_eq!(
            err(&with_field("version", Value::Int(2))).to_string(),
            "state file is version 2, this build writes 1"
        );
        // Shape problems in `version` are still shape problems.
        assert_eq!(
            err(&with_field("version", Value::str("1"))),
            StateError::Shape(DecodeError::wrong_type("version"))
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
}
