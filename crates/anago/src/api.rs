//! The control-plane API (DESIGN.md §8). M0 endpoint: `POST
//! /api/v1/join`.
//!
//! Each handler splits in two. [`decide_join`] is the whole decision —
//! validate, register, answer — as a function of a state and a request,
//! so every rule below is a unit test with no socket and no file. The
//! axum handler around it does only what cannot be pure: take the lock,
//! read the state, mint a token, stamp the clock, write back.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anago_core::json;
use anago_core::name::DeviceName;
use anago_core::proto::{
    ApiError, ErrorCode, JoinRequest, JoinResponse, PeerInfo, PeersResponse, PATH_JOIN, PATH_PEERS,
};
use anago_core::state::{Registration, ServerState};
use anago_core::token::{DeviceToken, TokenHash};
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;

/// The single answer to every unusable join code: unknown, malformed,
/// spent, or expired. Anything more specific would let an
/// unauthenticated caller probe which codes exist and how they died
/// (§8).
const INVALID_CODE: &str = "that join code is not valid";

/// The single answer to every authentication failure, for the same
/// reason as [`INVALID_CODE`]: absent, wrong scheme, wrong shape, and
/// unknown all look the same from outside.
const UNAUTHORIZED: &str = "a valid device token is required";

use crate::secret;
use crate::store::Store;
use crate::wg;

/// What the handlers need: the state file, and nothing else.
#[derive(Clone)]
pub struct Api {
    pub store: Arc<Store>,
}

/// The M0 routes.
pub fn router(api: Api) -> Router {
    Router::new()
        .route(PATH_JOIN, post(join))
        .route(PATH_PEERS, get(peers))
        .route(&format!("{PATH_PEERS}/{{name}}"), delete(remove))
        .with_state(api)
}

/// `POST /api/v1/join`.
///
/// Thin on purpose: the ordering that matters — code before name,
/// registration before the token is spent — lives in [`decide_join`]
/// and in `anago_core`'s `add_peer`.
async fn join(State(api): State<Api>, body: Bytes) -> Response {
    let request = match parse_body(&body) {
        Ok(request) => request,
        Err(error) => return error_response(&error),
    };

    // Minted before the lock so the CSPRNG is not read while holding
    // it; discarded untouched if the join is refused.
    let token = match secret::new_token() {
        Ok(token) => token,
        Err(e) => {
            eprintln!("anago: cannot read /dev/urandom: {e}");
            return error_response(&ApiError::new(
                ErrorCode::Internal,
                "the server could not generate a token",
            ));
        }
    };
    let token_hash = secret::hash_token(&token);

    let mut guard = match api.store.lock() {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("anago: {e}");
            return error_response(&ApiError::new(
                ErrorCode::Internal,
                "the server could not read its state",
            ));
        }
    };

    let response = match decide_join(guard.state_mut(), request, token, token_hash, now()) {
        Ok(response) => response,
        Err(error) => return error_response(&error),
    };
    if let Err(e) = guard.commit() {
        eprintln!("anago: {e}");
        return error_response(&ApiError::new(
            ErrorCode::Internal,
            "the server could not save the new device",
        ));
    }

    json_response(StatusCode::OK, &json::to_string(&response.to_json()))
}

/// `GET /api/v1/peers`. Identity only — M0 does not report endpoints or
/// liveness over the API (§8).
async fn peers(State(api): State<Api>, headers: HeaderMap) -> Response {
    with_caller(&api, &headers, |state, caller, now| {
        touch_last_seen(state, &caller, now);
        Ok(json::to_string(&decide_peers(state).to_json()))
    })
}

/// `DELETE /api/v1/peers/{name}`.
async fn remove(State(api): State<Api>, headers: HeaderMap, Path(name): Path<String>) -> Response {
    with_caller(&api, &headers, |state, caller, now| {
        let removed = decide_remove(state, &name)?;
        // A device that removed itself is gone; there is nothing left
        // to stamp.
        if removed.name != caller.as_str() {
            touch_last_seen(state, &caller, now);
        }
        Ok(json::to_string(&removed.to_json()))
    })
}

/// Authenticates, takes the lock, runs `change`, and commits only if it
/// succeeded.
///
/// Both authenticated endpoints write — they stamp `last_seen` (§9.1) —
/// so both take the write lock. In M0 these are typed by a person, not
/// polled by a timer, so the contention is somebody running `anago ls`.
fn with_caller(
    api: &Api,
    headers: &HeaderMap,
    change: impl FnOnce(&mut ServerState, DeviceName, i64) -> Result<String, ApiError>,
) -> Response {
    let token = match bearer_token(headers.get(header::AUTHORIZATION)) {
        Ok(token) => token,
        Err(error) => return error_response(&error),
    };

    let mut guard = match api.store.lock() {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("anago: {e}");
            return error_response(&ApiError::new(
                ErrorCode::Internal,
                "the server could not read its state",
            ));
        }
    };

    let caller = match authenticate(guard.state(), &token) {
        Ok(caller) => caller,
        Err(error) => return error_response(&error),
    };
    let body = match change(guard.state_mut(), caller, now()) {
        Ok(body) => body,
        Err(error) => return error_response(&error),
    };
    if let Err(e) = guard.commit() {
        eprintln!("anago: {e}");
        return error_response(&ApiError::new(
            ErrorCode::Internal,
            "the server could not save its state",
        ));
    }
    json_response(StatusCode::OK, &body)
}

/// Reads a bearer token out of an `Authorization` header.
pub fn bearer_token(header: Option<&HeaderValue>) -> Result<DeviceToken, ApiError> {
    let value = header.ok_or_else(unauthorized)?;
    let value = value.to_str().map_err(|_| unauthorized())?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .ok_or_else(unauthorized)?;
    DeviceToken::parse(token.trim()).map_err(|_| unauthorized())
}

/// Finds the device a token belongs to.
///
/// The token is hashed and compared against the stored hashes without
/// an early return (§7.1), and an unknown token gets the same answer as
/// a missing one.
pub fn authenticate(state: &ServerState, token: &DeviceToken) -> Result<DeviceName, ApiError> {
    let offered = secret::hash_token(token);
    let mut found = None;
    for peer in &state.peers {
        // No `break`: every peer is visited whatever matches, so how
        // long this takes says nothing about which peer it was.
        if peer.token_hash.matches(&offered) {
            found = Some(peer.name.clone());
        }
    }
    found.ok_or_else(unauthorized)
}

fn unauthorized() -> ApiError {
    ApiError::new(ErrorCode::Unauthorized, UNAUTHORIZED)
}

/// The peer list as `GET /peers` reports it — including the caller,
/// which is how a device sees its own address without storing it twice.
pub fn decide_peers(state: &ServerState) -> PeersResponse {
    PeersResponse {
        peers: state
            .peers
            .iter()
            .map(|peer| PeerInfo {
                name: peer.name.to_string(),
                public_key: peer.public_key.clone(),
                address: peer.address.to_string(),
            })
            .collect(),
    }
}

/// Removes `name`, answering with what was removed.
///
/// Any registered device may remove any other. The trust boundary is
/// the network itself: §3 rules out roles and ACLs because these are
/// one person's devices.
pub fn decide_remove(state: &mut ServerState, name: &str) -> Result<PeerInfo, ApiError> {
    let not_found = || ApiError::new(ErrorCode::NotFound, format!("no device named {name:?}"));
    // A name that breaks §8.1 cannot be registered, so it is a missing
    // device rather than a bad request.
    let parsed = DeviceName::parse(name).map_err(|_| not_found())?;
    let peer = state.remove_peer(&parsed).ok_or_else(not_found)?;
    Ok(PeerInfo {
        name: peer.name.to_string(),
        public_key: peer.public_key,
        address: peer.address.to_string(),
    })
}

/// Stamps the caller's last authenticated call (§9.1).
pub fn touch_last_seen(state: &mut ServerState, name: &DeviceName, now: i64) {
    if let Some(peer) = state.peers.iter_mut().find(|peer| peer.name == *name) {
        peer.last_seen = Some(now);
    }
}

/// Validates a registration and applies it to `state`.
///
/// Pure: a state in, a state changed, an answer or a refusal out. The
/// token is passed in rather than generated here so the caller owns the
/// randomness — and so this is testable.
pub fn decide_join(
    state: &mut ServerState,
    request: JoinRequest,
    token: DeviceToken,
    token_hash: TokenHash,
    now: i64,
) -> Result<JoinResponse, ApiError> {
    let code = anago_core::code::JoinCode::parse(&request.code)
        .map_err(|_| ApiError::new(ErrorCode::InvalidCode, INVALID_CODE))?;
    let name = DeviceName::parse(&request.name)
        .map_err(|e| ApiError::new(ErrorCode::InvalidName, e.to_string()))?;
    let public_key = wg::parse_key(&request.public_key).map_err(|_| {
        ApiError::new(
            ErrorCode::InvalidPublicKey,
            "expected a WireGuard public key (44 base64 characters)",
        )
    })?;

    let peer = state
        .add_peer(
            Registration {
                code,
                name,
                public_key,
                token_hash,
            },
            now,
        )
        .map_err(|rejection| {
            let code = rejection.error_code();
            match code {
                // `no such code` / `already used` / `expired` are for
                // the server's log, never for the caller.
                ErrorCode::InvalidCode => ApiError::new(code, INVALID_CODE),
                _ => ApiError::new(code, rejection.to_string()),
            }
        })?;

    Ok(JoinResponse {
        name: peer.name.to_string(),
        address: peer.address.to_string(),
        subnet: state.subnet.to_string(),
        token: token.as_str().to_string(),
        server_public_key: state.server.public_key.clone(),
        server_endpoint: format!("{}:{}", state.domain, state.listen_port),
        server_address: state.subnet.server_address().to_string(),
    })
}

fn parse_body(body: &[u8]) -> Result<JoinRequest, ApiError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| ApiError::new(ErrorCode::BadRequest, "the request body is not UTF-8"))?;
    let value = json::parse(text)
        .map_err(|e| ApiError::new(ErrorCode::BadRequest, format!("invalid JSON: {e}")))?;
    JoinRequest::from_json(&value).map_err(|e| ApiError::new(ErrorCode::BadRequest, e.to_string()))
}

/// The HTTP status for each failure. A closed mapping so a new error
/// code cannot quietly become a 500.
pub fn status_for(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::BadRequest | ErrorCode::InvalidName | ErrorCode::InvalidPublicKey => {
            StatusCode::BAD_REQUEST
        }
        ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
        // The code is the credential, so a bad one is a refusal to act,
        // not a missing credential.
        ErrorCode::InvalidCode => StatusCode::FORBIDDEN,
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::NameTaken => StatusCode::CONFLICT,
        // Nothing the caller can fix and nothing the server can store.
        ErrorCode::SubnetFull => StatusCode::INSUFFICIENT_STORAGE,
        ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn error_response(error: &ApiError) -> Response {
    let status = status_for(error.code);
    let body = json::to_string(&error.to_json());
    if status == StatusCode::UNAUTHORIZED {
        // RFC 9110 §11.6.1: a 401 must name a scheme to authenticate
        // with, or a client has nothing to retry against.
        return (
            status,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::WWW_AUTHENTICATE, "Bearer"),
            ],
            Body::from(body),
        )
            .into_response();
    }
    json_response(status, &body)
}

fn json_response(status: StatusCode, body: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        Body::from(body.to_string()),
    )
        .into_response()
}

/// Unix epoch seconds. A clock before 1970 is not worth a `Result`
/// here; it saturates to 0 and the code-expiry rules handle it.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use anago_core::code::{IssuedCode, JoinCode, DEFAULT_TTL_SECS};
    use anago_core::state::{PrivateKey, ServerKeys};
    use anago_core::subnet::Subnet;

    const NOW: i64 = 1_755_500_000;
    const CODE: &str = "7QX4-M2KD";
    /// 44 base64 characters, the shape `wg pubkey` prints.
    const PUBKEY: &str = "YiB/o4zzTPM9aaV5C93CP5kPJVGzqIyceUlne0CAoO0=";

    fn fresh_state() -> ServerState {
        ServerState {
            domain: "net.example.com".to_string(),
            subnet: Subnet::parse("10.100.0.0/24").unwrap(),
            listen_port: 51820,
            api_port: 443,
            tls_cert_path: "/etc/ssl/anago/fullchain.pem".to_string(),
            tls_key_path: "/etc/ssl/anago/privkey.pem".to_string(),
            server: ServerKeys {
                private_key: PrivateKey::new("c2VydmVyIHByaXZhdGU="),
                public_key: "c2VydmVyIHB1YmxpYw==".to_string(),
                address: "10.100.0.1".parse::<Ipv4Addr>().unwrap(),
            },
            peers: Vec::new(),
            codes: vec![IssuedCode::issue(
                JoinCode::parse(CODE).unwrap(),
                NOW,
                DEFAULT_TTL_SECS,
            )],
        }
    }

    fn request(code: &str, name: &str) -> JoinRequest {
        JoinRequest {
            code: code.to_string(),
            name: name.to_string(),
            public_key: PUBKEY.to_string(),
        }
    }

    fn token() -> (DeviceToken, TokenHash) {
        let token = DeviceToken::parse(&"ab".repeat(32)).unwrap();
        let hash = secret::hash_token(&token);
        (token, hash)
    }

    fn join_with(state: &mut ServerState, request: JoinRequest) -> Result<JoinResponse, ApiError> {
        let (token, hash) = token();
        decide_join(state, request, token, hash, NOW)
    }

    #[test]
    fn a_good_request_registers_the_device_and_answers_with_its_network() {
        let mut state = fresh_state();
        let response = join_with(&mut state, request(CODE, "MacBook")).unwrap();

        assert_eq!(response.name, "macbook", "the normalized name comes back");
        assert_eq!(response.address, "10.100.0.2");
        assert_eq!(response.subnet, "10.100.0.0/24");
        assert_eq!(response.server_public_key, "c2VydmVyIHB1YmxpYw==");
        assert_eq!(response.server_endpoint, "net.example.com:51820");
        assert_eq!(response.server_address, "10.100.0.1");
        assert_eq!(response.token, "ab".repeat(32));

        // Registered, with the hash and not the token (§7.1).
        assert_eq!(state.peers.len(), 1);
        assert_eq!(state.peers[0].public_key, PUBKEY);
        assert_eq!(state.peers[0].token_hash, secret::hash_token(&token().0));
        assert_ne!(state.peers[0].token_hash.as_str(), response.token);
        assert_eq!(state.peers[0].created_at, NOW);
        // And the code is spent.
        assert_eq!(state.codes[0].used_at, Some(NOW));
    }

    #[test]
    fn the_second_device_gets_the_next_address() {
        let mut state = fresh_state();
        state.codes.push(IssuedCode::issue(
            JoinCode::parse("HJKM-NPQR").unwrap(),
            NOW,
            DEFAULT_TTL_SECS,
        ));
        join_with(&mut state, request(CODE, "macbook")).unwrap();
        let second = join_with(&mut state, request("HJKM-NPQR", "맥북")).unwrap();
        assert_eq!(second.address, "10.100.0.3");
    }

    #[test]
    fn every_bad_code_gets_byte_identical_answers() {
        // Unknown, malformed, spent, expired — one reply, down to the
        // message, so a caller cannot tell which codes exist or how
        // they died (§8).
        let expected = ApiError::new(ErrorCode::InvalidCode, INVALID_CODE);
        let expected_body = json::to_string(&expected.to_json());

        let mut state = fresh_state();
        let mut answers = Vec::new();
        // Well-formed but unknown, and various malformed shapes.
        for code in ["HJKM-NPQR", "nonsense", "", "OOOO-OOOO", "7QX4M2KD9"] {
            answers.push(join_with(&mut state, request(code, "macbook")).unwrap_err());
        }
        // Spent.
        join_with(&mut state, request(CODE, "macbook")).unwrap();
        answers.push(join_with(&mut state, request(CODE, "desktop")).unwrap_err());
        // Expired.
        let mut fresh = fresh_state();
        let (token, hash) = token();
        answers.push(
            decide_join(
                &mut fresh,
                request(CODE, "macbook"),
                token,
                hash,
                NOW + DEFAULT_TTL_SECS,
            )
            .unwrap_err(),
        );

        for answer in &answers {
            assert_eq!(answer, &expected, "a caller could tell these apart");
            assert_eq!(json::to_string(&answer.to_json()), expected_body);
        }
        assert_eq!(status_for(expected.code), StatusCode::FORBIDDEN);
    }

    #[test]
    fn a_refused_join_changes_nothing() {
        let mut state = fresh_state();
        let before = state.clone();
        assert!(join_with(&mut state, request("HJKM-NPQR", "macbook")).is_err());
        assert_eq!(state, before, "a bad code must not spend anything");

        assert!(join_with(&mut state, request(CODE, "server")).is_err());
        assert_eq!(state, before, "a bad name must not spend the code");
    }

    #[test]
    fn names_and_keys_are_checked_before_anything_is_spent() {
        let mut state = fresh_state();

        // `server` is reserved (§8.1).
        let e = join_with(&mut state, request(CODE, "server")).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidName);
        assert!(e.message.contains("reserved"), "{}", e.message);

        let e = join_with(&mut state, request(CODE, "my mac")).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidName);

        let mut bad_key = request(CODE, "macbook");
        bad_key.public_key = "not a key".to_string();
        let e = join_with(&mut state, bad_key).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidPublicKey);
        // The rejection does not echo what was sent.
        assert!(!e.message.contains("not a key"), "{}", e.message);

        assert!(state.peers.is_empty());
        assert_eq!(state.codes[0].used_at, None);
    }

    #[test]
    fn a_taken_name_is_refused_without_burning_the_code() {
        let mut state = fresh_state();
        join_with(&mut state, request(CODE, "macbook")).unwrap();
        state.codes.push(IssuedCode::issue(
            JoinCode::parse("HJKM-NPQR").unwrap(),
            NOW,
            DEFAULT_TTL_SECS,
        ));

        let e = join_with(&mut state, request("HJKM-NPQR", "MacBook")).unwrap_err();
        assert_eq!(e.code, ErrorCode::NameTaken);
        assert_eq!(
            state.codes[1].used_at, None,
            "retry with another name must work"
        );
        assert!(join_with(&mut state, request("HJKM-NPQR", "macbook-2")).is_ok());
    }

    #[test]
    fn a_full_subnet_is_reported_as_such() {
        let mut state = fresh_state();
        for octet in 2..=254u8 {
            state.peers.push(anago_core::state::Peer {
                name: DeviceName::parse(&format!("device-{octet}")).unwrap(),
                public_key: PUBKEY.to_string(),
                address: format!("10.100.0.{octet}").parse().unwrap(),
                token_hash: TokenHash::parse(&"cd".repeat(32)).unwrap(),
                created_at: NOW,
                last_seen: None,
            });
        }
        let e = join_with(&mut state, request(CODE, "one-too-many")).unwrap_err();
        assert_eq!(e.code, ErrorCode::SubnetFull);
        assert_eq!(status_for(e.code), StatusCode::INSUFFICIENT_STORAGE);
    }

    #[test]
    fn a_body_that_is_not_a_join_request_is_a_bad_request() {
        assert_eq!(
            parse_body(b"not json").unwrap_err().code,
            ErrorCode::BadRequest
        );
        assert_eq!(parse_body(b"{}").unwrap_err().code, ErrorCode::BadRequest);
        assert_eq!(
            parse_body(br#"{"code":"7QX4-M2KD","name":"macbook"}"#)
                .unwrap_err()
                .message,
            "missing field \"public_key\""
        );
        assert_eq!(
            parse_body(&[0xff, 0xfe]).unwrap_err().message,
            "the request body is not UTF-8"
        );

        let body = format!(r#"{{"code":"{CODE}","name":"macbook","public_key":"{PUBKEY}"}}"#);
        assert_eq!(
            parse_body(body.as_bytes()).unwrap(),
            request(CODE, "macbook")
        );
    }

    #[test]
    fn every_error_code_has_a_status() {
        // A closed mapping: adding a code without a status would not
        // compile, and none of them should quietly become a 500.
        for (code, expected) in [
            (ErrorCode::BadRequest, StatusCode::BAD_REQUEST),
            (ErrorCode::InvalidName, StatusCode::BAD_REQUEST),
            (ErrorCode::InvalidPublicKey, StatusCode::BAD_REQUEST),
            (ErrorCode::InvalidCode, StatusCode::FORBIDDEN),
            (ErrorCode::Unauthorized, StatusCode::UNAUTHORIZED),
            (ErrorCode::NotFound, StatusCode::NOT_FOUND),
            (ErrorCode::NameTaken, StatusCode::CONFLICT),
            (ErrorCode::SubnetFull, StatusCode::INSUFFICIENT_STORAGE),
            (ErrorCode::Internal, StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            assert_eq!(status_for(code), expected, "{code:?}");
        }
    }

    #[test]
    fn the_response_is_the_documented_json() {
        let mut state = fresh_state();
        let response = join_with(&mut state, request(CODE, "macbook")).unwrap();
        let text = json::to_string(&response.to_json());
        // Field names are the wire contract (§8); a rename shows up here.
        assert!(
            text.starts_with(r#"{"name":"macbook","address":"10.100.0.2""#),
            "{text}"
        );
        assert!(
            text.contains(r#""server_endpoint":"net.example.com:51820""#),
            "{text}"
        );
        assert_eq!(
            JoinResponse::from_json(&json::parse(&text).unwrap()).unwrap(),
            response
        );
    }

    // -------------------------------------------------- peers and rm

    /// A state with two registered devices and their tokens.
    fn network() -> (ServerState, DeviceToken, DeviceToken) {
        let mut state = fresh_state();
        state.codes.push(IssuedCode::issue(
            JoinCode::parse("HJKM-NPQR").unwrap(),
            NOW,
            DEFAULT_TTL_SECS,
        ));
        let first = DeviceToken::parse(&"11".repeat(32)).unwrap();
        let second = DeviceToken::parse(&"22".repeat(32)).unwrap();
        decide_join(
            &mut state,
            request(CODE, "macbook"),
            first.clone(),
            secret::hash_token(&first),
            NOW,
        )
        .unwrap();
        decide_join(
            &mut state,
            request("HJKM-NPQR", "맥북"),
            second.clone(),
            secret::hash_token(&second),
            NOW,
        )
        .unwrap();
        (state, first, second)
    }

    fn header(value: &str) -> HeaderValue {
        HeaderValue::from_str(value).unwrap()
    }

    #[test]
    fn a_bearer_header_yields_the_token() {
        let token = "ab".repeat(32);
        let parsed = bearer_token(Some(&header(&format!("Bearer {token}")))).unwrap();
        assert_eq!(parsed.as_str(), token);
        // Some clients lower-case the scheme.
        assert!(bearer_token(Some(&header(&format!("bearer {token}")))).is_ok());
        assert!(bearer_token(Some(&header(&format!("Bearer {token} ")))).is_ok());
    }

    #[test]
    fn every_way_of_having_no_token_looks_the_same() {
        let expected = ApiError::new(ErrorCode::Unauthorized, UNAUTHORIZED);
        let cases = [
            None,
            Some(header("")),
            Some(header("Basic YWJjOmRlZg==")),
            Some(header("Bearer")),
            Some(header("Bearer not-a-token")),
            Some(header(&format!("Bearer {}", "zz".repeat(32)))),
            Some(header(&"ab".repeat(32))),
        ];
        for case in &cases {
            let e = bearer_token(case.as_ref()).unwrap_err();
            assert_eq!(e, expected, "{case:?}");
        }
        assert_eq!(status_for(expected.code), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn a_token_identifies_its_own_device() {
        let (state, first, second) = network();
        assert_eq!(authenticate(&state, &first).unwrap().as_str(), "macbook");
        assert_eq!(authenticate(&state, &second).unwrap().as_str(), "맥북");
    }

    #[test]
    fn an_unknown_token_is_refused_like_a_missing_one() {
        let (state, _, _) = network();
        let stranger = DeviceToken::parse(&"99".repeat(32)).unwrap();
        assert_eq!(
            authenticate(&state, &stranger).unwrap_err(),
            ApiError::new(ErrorCode::Unauthorized, UNAUTHORIZED)
        );
        // And a token that belonged to a device that has been removed.
        let (mut state, first, _) = network();
        decide_remove(&mut state, "macbook").unwrap();
        assert!(
            authenticate(&state, &first).is_err(),
            "a removed device stays out"
        );
    }

    #[test]
    fn the_peer_list_carries_identity_and_nothing_else() {
        let (state, _, _) = network();
        let listed = decide_peers(&state);
        assert_eq!(listed.peers.len(), 2);
        assert_eq!(listed.peers[0].name, "macbook");
        assert_eq!(listed.peers[0].address, "10.100.0.2");
        assert_eq!(listed.peers[1].name, "맥북");
        assert_eq!(listed.peers[1].address, "10.100.0.3");

        // The wire form has no endpoint, no handshake, no token (§8).
        let text = json::to_string(&listed.to_json());
        for absent in ["endpoint", "last_seen", "token", "handshake"] {
            assert!(!text.contains(absent), "{absent} leaked into {text}");
        }
        assert_eq!(
            PeersResponse::from_json(&json::parse(&text).unwrap()).unwrap(),
            listed
        );
    }

    #[test]
    fn removing_a_device_answers_with_what_went() {
        let (mut state, _, _) = network();
        let removed = decide_remove(&mut state, "macbook").unwrap();
        assert_eq!(removed.name, "macbook");
        assert_eq!(removed.address, "10.100.0.2");
        assert_eq!(state.peers.len(), 1);
        assert_eq!(decide_peers(&state).peers[0].name, "맥북");

        // The address is free again for the next join.
        state.codes.push(IssuedCode::issue(
            JoinCode::parse("PQRS-TVWX").unwrap(),
            NOW,
            DEFAULT_TTL_SECS,
        ));
        let (token, hash) = token();
        let response = decide_join(
            &mut state,
            request("PQRS-TVWX", "desktop"),
            token,
            hash,
            NOW,
        )
        .unwrap();
        assert_eq!(response.address, "10.100.0.2");
    }

    #[test]
    fn removing_a_name_that_is_not_registered_is_a_404() {
        let (mut state, _, _) = network();
        // Unregistered, reserved, and names no device could ever have.
        for name in ["desktop", "macbook-2", "server", "not a name", ""] {
            let e = decide_remove(&mut state, name).unwrap_err();
            assert_eq!(e.code, ErrorCode::NotFound, "{name:?}");
            assert_eq!(status_for(e.code), StatusCode::NOT_FOUND);
        }
        assert_eq!(state.peers.len(), 2, "nothing was removed");
    }

    #[test]
    fn a_name_is_matched_in_its_canonical_form() {
        // `anago rm MacBook` reaches the device registered as `macbook`.
        let (mut state, _, _) = network();
        assert_eq!(
            decide_remove(&mut state, "MacBook").unwrap().name,
            "macbook"
        );
        // Korean names survive the round trip through the URL path.
        assert_eq!(decide_remove(&mut state, "맥북").unwrap().name, "맥북");
        assert!(state.peers.is_empty());
    }

    #[test]
    fn an_authenticated_call_stamps_the_caller() {
        let (mut state, _, _) = network();
        assert_eq!(state.peers[0].last_seen, None);

        let caller = DeviceName::parse("macbook").unwrap();
        touch_last_seen(&mut state, &caller, NOW + 60);
        assert_eq!(state.peers[0].last_seen, Some(NOW + 60));
        assert_eq!(state.peers[1].last_seen, None, "only the caller is stamped");

        // A name nobody answers to changes nothing.
        touch_last_seen(&mut state, &DeviceName::parse("ghost").unwrap(), NOW + 120);
        assert_eq!(state.peers[0].last_seen, Some(NOW + 60));
    }

    // ------------------------------------------------ through the router

    use axum::http::Request;
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tower::ServiceExt;

    /// A store on a temp directory, deleted when the test ends.
    struct TempServer {
        root: std::path::PathBuf,
        api: Api,
    }

    impl TempServer {
        fn new(state: &ServerState) -> TempServer {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("anago-api-{}-{unique}", std::process::id()));
            fs::create_dir_all(&root).expect("temp dir");
            let store = Store::new(&root);
            store.write(state).expect("write state");
            TempServer {
                root,
                api: Api {
                    store: Arc::new(store),
                },
            }
        }

        async fn send(&self, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
            let response = router(self.api.clone())
                .oneshot(request)
                .await
                .expect("router");
            let status = response.status();
            let headers = response.headers().clone();
            let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .expect("body");
            (status, headers, String::from_utf8_lossy(&body).into_owned())
        }
    }

    impl Drop for TempServer {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn get(uri: &str, token: Option<&DeviceToken>) -> Request<Body> {
        build(axum::http::Method::GET, uri, token)
    }

    fn build(method: axum::http::Method, uri: &str, token: Option<&DeviceToken>) -> Request<Body> {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {}", token.as_str()));
        }
        request.body(Body::empty()).expect("request")
    }

    #[tokio::test]
    async fn an_unauthenticated_request_gets_a_challenge() {
        // RFC 9110 §11.6.1: a 401 without WWW-Authenticate leaves a
        // client with nothing to retry against.
        let (state, _, _) = network();
        let server = TempServer::new(&state);
        let expected_body = json::to_string(&unauthorized().to_json());

        for request in [
            get(PATH_PEERS, None),
            build(axum::http::Method::DELETE, "/api/v1/peers/macbook", None),
        ] {
            let (status, headers, body) = server.send(request).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
            assert_eq!(headers[header::CONTENT_TYPE], "application/json");
            assert_eq!(body, expected_body);
        }

        // A token of the right shape that belongs to nobody answers
        // identically, challenge included.
        let stranger = DeviceToken::parse(&"99".repeat(32)).unwrap();
        let (status, headers, body) = server.send(get(PATH_PEERS, Some(&stranger))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
        assert_eq!(body, expected_body);
    }

    #[tokio::test]
    async fn a_token_holder_can_list_and_remove() {
        let (state, first, _) = network();
        let server = TempServer::new(&state);

        let (status, headers, body) = server.send(get(PATH_PEERS, Some(&first))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        assert!(headers.get(header::WWW_AUTHENTICATE).is_none());
        let listed = PeersResponse::from_json(&json::parse(&body).unwrap()).unwrap();
        assert_eq!(listed.peers.len(), 2);

        // The call was authenticated, so it left a mark (§9.1).
        let stored = server.api.store.read().unwrap();
        assert!(stored.peers[0].last_seen.is_some());

        let (status, _, body) = server
            .send(build(
                axum::http::Method::DELETE,
                "/api/v1/peers/%EB%A7%A5%EB%B6%81",
                Some(&first),
            ))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains("맥북"),
            "the percent-encoded name decoded: {body}"
        );

        // And the removal is on disk, not just in the answer.
        let stored = server.api.store.read().unwrap();
        assert_eq!(stored.peers.len(), 1);
        assert_eq!(stored.peers[0].name.as_str(), "macbook");
    }

    #[tokio::test]
    async fn removing_something_that_is_not_there_is_a_404() {
        let (state, first, _) = network();
        let server = TempServer::new(&state);
        let (status, _, body) = server
            .send(build(
                axum::http::Method::DELETE,
                "/api/v1/peers/desktop",
                Some(&first),
            ))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("not_found"), "{body}");
        // Nothing was removed.
        assert_eq!(server.api.store.read().unwrap().peers.len(), 2);
    }

    #[tokio::test]
    async fn a_join_goes_through_the_router_too() {
        // The handler stamps the real clock, so the fixture's code has
        // to be live now rather than at the tests' fixed NOW.
        let mut state = fresh_state();
        state.codes[0].expires_at = i64::MAX;
        let server = TempServer::new(&state);
        let body = format!(r#"{{"code":"{CODE}","name":"macbook","public_key":"{PUBKEY}"}}"#);
        let request = Request::builder()
            .method(axum::http::Method::POST)
            .uri(PATH_JOIN)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();

        let (status, headers, body) = server.send(request).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        let response = JoinResponse::from_json(&json::parse(&body).unwrap()).unwrap();
        assert_eq!(response.address, "10.100.0.2");

        // The token it just handed out works on the authenticated route.
        let token = DeviceToken::parse(&response.token).unwrap();
        let (status, _, _) = server.send(get(PATH_PEERS, Some(&token))).await;
        assert_eq!(status, StatusCode::OK);
    }
}
