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
use anago_core::proto::{ApiError, ErrorCode, JoinRequest, JoinResponse, PATH_JOIN};
use anago_core::state::{Registration, ServerState};
use anago_core::token::{DeviceToken, TokenHash};
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;

/// The single answer to every unusable join code: unknown, malformed,
/// spent, or expired. Anything more specific would let an
/// unauthenticated caller probe which codes exist and how they died
/// (§8).
const INVALID_CODE: &str = "that join code is not valid";

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
    Router::new().route(PATH_JOIN, post(join)).with_state(api)
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
    json_response(status_for(error.code), &json::to_string(&error.to_json()))
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
}
