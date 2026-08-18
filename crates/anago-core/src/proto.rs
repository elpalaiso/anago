//! Control-plane API types (DESIGN.md §8) — the source of truth for
//! the wire schema, which is why they live in core rather than in the
//! server (§4 principle 4).
//!
//! Each type carries its own `to_json`/`from_json` over
//! [`crate::json`], so the wire format and the fields cannot drift
//! apart.
//!
//! M0 serves three endpoints; `POST /api/v1/endpoint` is M2 and has no
//! type here yet. Two field-level omissions are deliberate and match
//! §8/§9.1:
//!
//! - no peer `endpoint`: in a hub-and-spoke network the server observes
//!   a device's endpoint from the wg kernel, and device-reported
//!   endpoints arrive with M2.
//! - no `last_seen`/handshake in [`PeerInfo`]: `anago ls` run *on the
//!   server* reads that from `wg show`; over the API M0 answers with
//!   identity only. Adding it later means updating §8 first.

use std::fmt;

use crate::json::{Object, Value};

/// `POST /api/v1/join` — path of the only endpoint a device may call
/// before it has a token.
pub const PATH_JOIN: &str = "/api/v1/join";

/// `GET /api/v1/peers` — also the prefix of
/// `DELETE /api/v1/peers/{name}`.
pub const PATH_PEERS: &str = "/api/v1/peers";

/// Registration request. Authenticated by `code` alone — this is the
/// one call that carries no device token, because the token is what it
/// returns.
///
/// The device generates its wg keypair locally and sends only the
/// public half (§6.2): the private key never leaves the machine.
#[derive(Debug, Clone, PartialEq)]
pub struct JoinRequest {
    /// Join code from `anago code`, single-use and short-lived (§7).
    pub code: String,
    /// Requested device name. `--name` if given, otherwise the client
    /// fills in the hostname before sending — the server never has to
    /// invent a name.
    pub name: String,
    /// wg public key, base64 as `wg pubkey` prints it.
    pub public_key: String,
}

/// Everything a device needs to write its wg config and to make
/// authenticated calls afterwards.
#[derive(Debug, Clone, PartialEq)]
pub struct JoinResponse {
    /// The name as registered. May differ from the requested one after
    /// normalization, so the client stores what comes back rather than
    /// what it sent.
    pub name: String,
    /// Private address assigned to this device, e.g. `10.100.0.2`.
    pub address: String,
    /// Network CIDR, e.g. `10.100.0.0/24`. Becomes the client's
    /// `AllowedIPs` — the one line that makes hub-and-spoke route every
    /// peer through the server without a per-peer entry.
    pub subnet: String,
    /// Bearer token, plaintext, 64 hex chars (§7.1). Sent once, at
    /// registration; the server keeps only its hash.
    pub token: String,
    /// Server's wg public key.
    pub server_public_key: String,
    /// wg endpoint to dial, `host:port` — the domain from
    /// `server init` and the UDP port, e.g. `net.example.com:51820`.
    pub server_endpoint: String,
    /// Server's private address (the subnet's `.1`), which `join` pings
    /// to confirm the tunnel came up.
    pub server_address: String,
}

/// One registered device, as `GET /api/v1/peers` reports it.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerInfo {
    pub name: String,
    pub public_key: String,
    pub address: String,
}

/// `GET /api/v1/peers`. The list includes the calling device itself —
/// the caller filters by its own name if it wants the others.
#[derive(Debug, Clone, PartialEq)]
pub struct PeersResponse {
    pub peers: Vec<PeerInfo>,
}

/// Error body for any failing call. `code` is for programs, `message`
/// for the person reading the terminal.
#[derive(Debug, Clone, PartialEq)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> ApiError {
        ApiError {
            code,
            message: message.into(),
        }
    }
}

/// The closed vocabulary of failures M0 can return. A closed set (not
/// free-form strings) so the client can branch on a cause — an expired
/// code deserves "run `anago code` again", a full subnet does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Join code unknown, malformed, expired, or already used. One code
    /// for all four: telling an unauthenticated caller *which* one only
    /// helps them probe.
    InvalidCode,
    /// Device name rejected by normalization (§B `name.rs`).
    InvalidName,
    /// A device of that name is already registered.
    NameTaken,
    /// wg public key not in the expected base64 shape.
    InvalidPublicKey,
    /// No free address left in the subnet.
    SubnetFull,
    /// Missing, malformed, or unknown bearer token.
    Unauthorized,
    /// No such device (e.g. `DELETE /api/v1/peers/{name}`).
    NotFound,
    /// Body was not the JSON this endpoint expects.
    BadRequest,
    /// The server broke, not the caller.
    Internal,
}

impl ErrorCode {
    /// The wire spelling. Stable — clients match on these strings.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidCode => "invalid_code",
            ErrorCode::InvalidName => "invalid_name",
            ErrorCode::NameTaken => "name_taken",
            ErrorCode::InvalidPublicKey => "invalid_public_key",
            ErrorCode::SubnetFull => "subnet_full",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::NotFound => "not_found",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Internal => "internal",
        }
    }

    /// Parses a wire spelling. `None` for anything else — a newer
    /// server's unknown code must not be mistaken for a known one.
    pub fn from_wire(s: &str) -> Option<ErrorCode> {
        let code = match s {
            "invalid_code" => ErrorCode::InvalidCode,
            "invalid_name" => ErrorCode::InvalidName,
            "name_taken" => ErrorCode::NameTaken,
            "invalid_public_key" => ErrorCode::InvalidPublicKey,
            "subnet_full" => ErrorCode::SubnetFull,
            "unauthorized" => ErrorCode::Unauthorized,
            "not_found" => ErrorCode::NotFound,
            "bad_request" => ErrorCode::BadRequest,
            "internal" => ErrorCode::Internal,
            _ => return None,
        };
        Some(code)
    }
}

// ---------------------------------------------------------------- codec

/// A JSON body did not have the shape a type needs.
///
/// Unknown fields are deliberately *not* an error: a newer peer may
/// send more than this build knows, and ignoring what we cannot read
/// keeps a mixed-version network working — the same rule the state
/// file follows (§9.1).
#[derive(Debug, Clone, PartialEq)]
pub struct DecodeError {
    /// Field path, e.g. `name` or `peers[1].address`. Empty for the
    /// top-level value.
    pub field: String,
    pub kind: DecodeErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeErrorKind {
    /// The field is not there at all.
    Missing,
    /// Present, but holding the wrong JSON type.
    WrongType,
    /// Right type, but not a value this build knows — an error code
    /// spelling from a newer server, say.
    UnknownValue,
}

impl DecodeError {
    fn missing(field: &str) -> DecodeError {
        DecodeError {
            field: field.to_string(),
            kind: DecodeErrorKind::Missing,
        }
    }

    fn wrong_type(field: &str) -> DecodeError {
        DecodeError {
            field: field.to_string(),
            kind: DecodeErrorKind::WrongType,
        }
    }

    fn unknown_value(field: &str) -> DecodeError {
        DecodeError {
            field: field.to_string(),
            kind: DecodeErrorKind::UnknownValue,
        }
    }

    /// Re-roots the error under `prefix` as it travels up a nested
    /// decode: `address` becomes `peers[1].address`, so the message
    /// names the element that actually failed. An error carrying no
    /// path — the element was not an object at all — becomes just
    /// `peers[1]`.
    fn within(self, prefix: &str) -> DecodeError {
        let field = if self.field.is_empty() {
            // The element itself was wrong, not a field inside it —
            // no dangling "peers[1]." path.
            prefix.to_string()
        } else {
            format!("{prefix}.{}", self.field)
        };
        DecodeError {
            field,
            kind: self.kind,
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.field.is_empty() {
            return write!(f, "expected a JSON object");
        }
        match self.kind {
            DecodeErrorKind::Missing => write!(f, "missing field {:?}", self.field),
            DecodeErrorKind::WrongType => write!(f, "field {:?} has the wrong type", self.field),
            DecodeErrorKind::UnknownValue => {
                write!(f, "field {:?} has an unknown value", self.field)
            }
        }
    }
}

impl std::error::Error for DecodeError {}

fn object(value: &Value) -> Result<&Object, DecodeError> {
    value.as_object().ok_or_else(|| DecodeError::wrong_type(""))
}

fn string_field(obj: &Object, name: &str) -> Result<String, DecodeError> {
    match obj.get(name) {
        None => Err(DecodeError::missing(name)),
        Some(found) => found
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| DecodeError::wrong_type(name)),
    }
}

impl JoinRequest {
    pub fn to_json(&self) -> Value {
        Value::obj([
            ("code", Value::str(self.code.as_str())),
            ("name", Value::str(self.name.as_str())),
            ("public_key", Value::str(self.public_key.as_str())),
        ])
    }

    /// Decodes a body. Shape only — that a code is still valid, or a
    /// name acceptable, is the server's call once it holds the state
    /// file, not something a decoder can know.
    pub fn from_json(value: &Value) -> Result<JoinRequest, DecodeError> {
        let obj = object(value)?;
        Ok(JoinRequest {
            code: string_field(obj, "code")?,
            name: string_field(obj, "name")?,
            public_key: string_field(obj, "public_key")?,
        })
    }
}

impl JoinResponse {
    pub fn to_json(&self) -> Value {
        Value::obj([
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

    pub fn from_json(value: &Value) -> Result<JoinResponse, DecodeError> {
        let obj = object(value)?;
        Ok(JoinResponse {
            name: string_field(obj, "name")?,
            address: string_field(obj, "address")?,
            subnet: string_field(obj, "subnet")?,
            token: string_field(obj, "token")?,
            server_public_key: string_field(obj, "server_public_key")?,
            server_endpoint: string_field(obj, "server_endpoint")?,
            server_address: string_field(obj, "server_address")?,
        })
    }
}

impl PeerInfo {
    pub fn to_json(&self) -> Value {
        Value::obj([
            ("name", Value::str(self.name.as_str())),
            ("public_key", Value::str(self.public_key.as_str())),
            ("address", Value::str(self.address.as_str())),
        ])
    }

    pub fn from_json(value: &Value) -> Result<PeerInfo, DecodeError> {
        let obj = object(value)?;
        Ok(PeerInfo {
            name: string_field(obj, "name")?,
            public_key: string_field(obj, "public_key")?,
            address: string_field(obj, "address")?,
        })
    }
}

impl PeersResponse {
    pub fn to_json(&self) -> Value {
        Value::obj([(
            "peers",
            Value::Arr(self.peers.iter().map(PeerInfo::to_json).collect()),
        )])
    }

    pub fn from_json(value: &Value) -> Result<PeersResponse, DecodeError> {
        let obj = object(value)?;
        let items = match obj.get("peers") {
            None => return Err(DecodeError::missing("peers")),
            Some(found) => found
                .as_array()
                .ok_or_else(|| DecodeError::wrong_type("peers"))?,
        };
        let mut peers = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            peers.push(PeerInfo::from_json(item).map_err(|e| e.within(&format!("peers[{i}]")))?);
        }
        Ok(PeersResponse { peers })
    }
}

impl ApiError {
    pub fn to_json(&self) -> Value {
        Value::obj([
            ("code", Value::str(self.code.as_str())),
            ("message", Value::str(self.message.as_str())),
        ])
    }

    /// An unrecognized `code` fails rather than collapsing to
    /// `Internal`: a client that cannot name the cause should say so,
    /// not blame the server.
    pub fn from_json(value: &Value) -> Result<ApiError, DecodeError> {
        let obj = object(value)?;
        let code = string_field(obj, "code")?;
        let code = ErrorCode::from_wire(&code).ok_or_else(|| DecodeError::unknown_value("code"))?;
        Ok(ApiError {
            code,
            message: string_field(obj, "message")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    /// Every variant M0 can return, for the exhaustiveness checks below.
    const ALL_CODES: [ErrorCode; 9] = [
        ErrorCode::InvalidCode,
        ErrorCode::InvalidName,
        ErrorCode::NameTaken,
        ErrorCode::InvalidPublicKey,
        ErrorCode::SubnetFull,
        ErrorCode::Unauthorized,
        ErrorCode::NotFound,
        ErrorCode::BadRequest,
        ErrorCode::Internal,
    ];

    #[test]
    fn error_codes_round_trip_through_their_wire_spelling() {
        for code in ALL_CODES {
            assert_eq!(ErrorCode::from_wire(code.as_str()), Some(code));
        }
    }

    #[test]
    fn error_code_spellings_are_distinct() {
        let mut seen: Vec<&str> = Vec::new();
        for code in ALL_CODES {
            assert!(
                !seen.contains(&code.as_str()),
                "duplicate spelling {:?}",
                code.as_str()
            );
            seen.push(code.as_str());
        }
    }

    #[test]
    fn unknown_wire_codes_are_not_guessed() {
        assert_eq!(ErrorCode::from_wire("code_expired"), None);
        assert_eq!(ErrorCode::from_wire("Invalid_Code"), None);
        assert_eq!(ErrorCode::from_wire(""), None);
    }

    /// If a variant is added, this stops compiling until `as_str`,
    /// `from_wire`, and `ALL_CODES` are all extended — the three places
    /// that must move together.
    #[test]
    fn every_variant_is_covered() {
        fn spelled(code: ErrorCode) -> &'static str {
            match code {
                ErrorCode::InvalidCode
                | ErrorCode::InvalidName
                | ErrorCode::NameTaken
                | ErrorCode::InvalidPublicKey
                | ErrorCode::SubnetFull
                | ErrorCode::Unauthorized
                | ErrorCode::NotFound
                | ErrorCode::BadRequest
                | ErrorCode::Internal => code.as_str(),
            }
        }
        assert_eq!(ALL_CODES.len(), 9);
        for code in ALL_CODES {
            assert_eq!(spelled(code), code.as_str());
        }
    }

    #[test]
    fn join_carries_a_public_key_and_answers_with_a_token() {
        let request = JoinRequest {
            code: "CODE-7QX4".to_string(),
            name: "맥북".to_string(),
            public_key: "SERVERkey+abc/def=".to_string(),
        };
        let response = JoinResponse {
            name: "maekbuk".to_string(),
            address: "10.100.0.2".to_string(),
            subnet: "10.100.0.0/24".to_string(),
            token: "0".repeat(64),
            server_public_key: "SERVERkey+abc/def=".to_string(),
            server_endpoint: "net.example.com:51820".to_string(),
            server_address: "10.100.0.1".to_string(),
        };
        // The request never carries a private key, and the response is
        // the only place the plaintext token appears (§7.1).
        assert_eq!(request.public_key, response.server_public_key);
        assert_eq!(response.token.len(), 64);
        assert!(response.server_endpoint.ends_with(":51820"));
    }

    #[test]
    fn peers_response_lists_identity_only() {
        let peers = PeersResponse {
            peers: vec![
                PeerInfo {
                    name: "macbook".to_string(),
                    public_key: "A+a/1=".to_string(),
                    address: "10.100.0.2".to_string(),
                },
                PeerInfo {
                    name: "desktop".to_string(),
                    public_key: "B+b/2=".to_string(),
                    address: "10.100.0.3".to_string(),
                },
            ],
        };
        assert_eq!(peers.peers.len(), 2);
        assert_eq!(peers.peers[1].address, "10.100.0.3");
    }

    #[test]
    fn api_error_pairs_a_code_with_a_human_message() {
        let e = ApiError::new(
            ErrorCode::SubnetFull,
            "10.100.0.0/24 has no free address left",
        );
        assert_eq!(e.code.as_str(), "subnet_full");
        assert!(e.message.contains("free address"));
    }

    #[test]
    fn endpoint_paths_match_the_design_doc() {
        assert_eq!(PATH_JOIN, "/api/v1/join");
        assert_eq!(PATH_PEERS, "/api/v1/peers");
    }

    // ------------------------------------------------------- codec

    fn sample_join_request() -> JoinRequest {
        JoinRequest {
            code: "CODE-7QX4".to_string(),
            name: "맥북".to_string(),
            public_key: "aGVsbG8gd2c=".to_string(),
        }
    }

    fn sample_join_response() -> JoinResponse {
        JoinResponse {
            name: "macbook".to_string(),
            address: "10.100.0.2".to_string(),
            subnet: "10.100.0.0/24".to_string(),
            token: "a1".repeat(32),
            server_public_key: "c2VydmVyIGtleQ==".to_string(),
            server_endpoint: "net.example.com:51820".to_string(),
            server_address: "10.100.0.1".to_string(),
        }
    }

    fn sample_peers() -> PeersResponse {
        PeersResponse {
            peers: vec![
                PeerInfo {
                    name: "macbook".to_string(),
                    public_key: "A+a/1=".to_string(),
                    address: "10.100.0.2".to_string(),
                },
                PeerInfo {
                    name: "데스크톱".to_string(),
                    public_key: "B+b/2=".to_string(),
                    address: "10.100.0.3".to_string(),
                },
            ],
        }
    }

    /// Value -> JSON text -> Value -> type: the path a real request
    /// takes, not just the in-memory hop.
    #[test]
    fn types_round_trip_through_json_text() {
        let request = sample_join_request();
        let text = json::to_string(&request.to_json());
        assert_eq!(
            JoinRequest::from_json(&json::parse(&text).unwrap()).unwrap(),
            request
        );

        let response = sample_join_response();
        let text = json::to_string(&response.to_json());
        assert_eq!(
            JoinResponse::from_json(&json::parse(&text).unwrap()).unwrap(),
            response
        );

        let peers = sample_peers();
        let text = json::to_string(&peers.to_json());
        assert_eq!(
            PeersResponse::from_json(&json::parse(&text).unwrap()).unwrap(),
            peers
        );

        let peer = sample_peers().peers.remove(0);
        let text = json::to_string(&peer.to_json());
        assert_eq!(
            PeerInfo::from_json(&json::parse(&text).unwrap()).unwrap(),
            peer
        );

        let error = ApiError::new(ErrorCode::NameTaken, "이미 등록된 이름입니다");
        let text = json::to_string(&error.to_json());
        assert_eq!(
            ApiError::from_json(&json::parse(&text).unwrap()).unwrap(),
            error
        );
    }

    #[test]
    fn every_error_code_survives_a_round_trip() {
        for code in ALL_CODES {
            let error = ApiError::new(code, "boom");
            let decoded = ApiError::from_json(&error.to_json()).unwrap();
            assert_eq!(decoded.code, code);
        }
    }

    #[test]
    fn empty_peer_list_round_trips() {
        let empty = PeersResponse { peers: Vec::new() };
        assert_eq!(json::to_string(&empty.to_json()), r#"{"peers":[]}"#);
        assert_eq!(PeersResponse::from_json(&empty.to_json()).unwrap(), empty);
    }

    #[test]
    fn wire_field_names_are_pinned() {
        // The server and every client agree on these spellings; a
        // rename here is a protocol change, so it has to be visible.
        assert_eq!(
            json::to_string(&sample_join_request().to_json()),
            r#"{"code":"CODE-7QX4","name":"맥북","public_key":"aGVsbG8gd2c="}"#
        );
        assert_eq!(
            json::to_string(&ApiError::new(ErrorCode::Unauthorized, "no token").to_json()),
            r#"{"code":"unauthorized","message":"no token"}"#
        );
    }

    #[test]
    fn missing_fields_name_the_field() {
        let body = Value::obj([
            ("code", Value::str("CODE-7QX4")),
            ("name", Value::str("맥북")),
        ]);
        let e = JoinRequest::from_json(&body).unwrap_err();
        assert_eq!(
            e,
            DecodeError {
                field: "public_key".to_string(),
                kind: DecodeErrorKind::Missing
            }
        );
        assert_eq!(e.to_string(), "missing field \"public_key\"");

        let body = Value::obj([("peers", Value::Arr(vec![]))]);
        assert_eq!(PeersResponse::from_json(&body).unwrap().peers, vec![]);
        let e = PeersResponse::from_json(&Value::obj([])).unwrap_err();
        assert_eq!(e.kind, DecodeErrorKind::Missing);
        assert_eq!(e.field, "peers");

        let e = ApiError::from_json(&Value::obj([("code", Value::str("internal"))])).unwrap_err();
        assert_eq!(e.to_string(), "missing field \"message\"");
    }

    #[test]
    fn type_mismatches_are_rejected_not_coerced() {
        // A number where a string belongs must not become "51820".
        let body = Value::obj([
            ("code", Value::str("CODE-7QX4")),
            ("name", Value::Int(51820)),
            ("public_key", Value::str("aGVsbG8gd2c=")),
        ]);
        let e = JoinRequest::from_json(&body).unwrap_err();
        assert_eq!(
            e,
            DecodeError {
                field: "name".to_string(),
                kind: DecodeErrorKind::WrongType
            }
        );
        assert_eq!(e.to_string(), "field \"name\" has the wrong type");

        // null is a value, not an absent field.
        let body = Value::obj([
            ("code", Value::str("CODE-7QX4")),
            ("name", Value::Null),
            ("public_key", Value::str("aGVsbG8gd2c=")),
        ]);
        assert_eq!(
            JoinRequest::from_json(&body).unwrap_err().kind,
            DecodeErrorKind::WrongType
        );

        // peers must be an array, and each element an object.
        let body = Value::obj([("peers", Value::str("macbook"))]);
        let e = PeersResponse::from_json(&body).unwrap_err();
        assert_eq!(e.field, "peers");
        assert_eq!(e.kind, DecodeErrorKind::WrongType);
    }

    #[test]
    fn a_bad_element_is_reported_with_its_index() {
        // Second element lacks "address" — the path must point at it,
        // not at the list.
        let body = Value::obj([(
            "peers",
            Value::Arr(vec![
                sample_peers().peers[0].to_json(),
                Value::obj([
                    ("name", Value::str("desktop")),
                    ("public_key", Value::str("B+b/2=")),
                ]),
            ]),
        )]);
        let e = PeersResponse::from_json(&body).unwrap_err();
        assert_eq!(e.field, "peers[1].address");
        assert_eq!(e.to_string(), "missing field \"peers[1].address\"");
    }

    #[test]
    fn a_non_object_element_is_reported_as_the_element_itself() {
        for element in [Value::Int(1), Value::Null, Value::str("macbook")] {
            let body = Value::obj([("peers", Value::Arr(vec![element]))]);
            let e = PeersResponse::from_json(&body).unwrap_err();
            // Names the element, with no trailing dot and no field it
            // never had.
            assert_eq!(e.field, "peers[0]");
            assert_eq!(e.kind, DecodeErrorKind::WrongType);
            assert_eq!(e.to_string(), "field \"peers[0]\" has the wrong type");
        }
    }

    #[test]
    fn non_objects_are_rejected_at_the_top_level() {
        for value in [
            Value::Int(1),
            Value::Null,
            Value::str("join"),
            Value::Arr(vec![]),
        ] {
            let e = JoinRequest::from_json(&value).unwrap_err();
            assert_eq!(e.kind, DecodeErrorKind::WrongType);
            assert_eq!(e.to_string(), "expected a JSON object");
        }
    }

    #[test]
    fn unknown_fields_are_ignored_for_forward_compatibility() {
        // A newer server answering an older client: the extra field is
        // dropped, the known ones still decode.
        let mut body = sample_join_response().to_json();
        if let Value::Obj(obj) = &mut body {
            obj.insert("keepalive_secs", Value::Int(25)).unwrap();
        }
        assert_eq!(
            JoinResponse::from_json(&body).unwrap(),
            sample_join_response()
        );
    }

    #[test]
    fn unknown_error_codes_fail_rather_than_masquerade() {
        let body = Value::obj([
            ("code", Value::str("teapot")),
            ("message", Value::str("from a newer server")),
        ]);
        let e = ApiError::from_json(&body).unwrap_err();
        assert_eq!(
            e,
            DecodeError {
                field: "code".to_string(),
                kind: DecodeErrorKind::UnknownValue
            }
        );
        assert_eq!(e.to_string(), "field \"code\" has an unknown value");
    }

    #[test]
    fn decoding_does_not_validate_content() {
        // Shape is this module's job; whether the code is live or the
        // key well-formed belongs to the server holding the state file.
        let body = Value::obj([
            ("code", Value::str("")),
            ("name", Value::str("   ")),
            ("public_key", Value::str("not base64")),
        ]);
        let decoded = JoinRequest::from_json(&body).unwrap();
        assert_eq!(decoded.public_key, "not base64");
    }
}
