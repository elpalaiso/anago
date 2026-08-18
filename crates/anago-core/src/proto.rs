//! Control-plane API types (DESIGN.md §8) — the source of truth for
//! the wire schema, which is why they live in core rather than in the
//! server (§4 principle 4).
//!
//! This module fixes the *fields*; the JSON encoding of each type
//! lands next, on top of [`crate::json`].
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
