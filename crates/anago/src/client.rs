//! The device's HTTPS client (DESIGN.md §8).
//!
//! Small on purpose: three requests, one connection each, no async.
//! `join`, `ls`, and `rm` each make a single call and exit, so a
//! blocking TLS stream over `std::net::TcpStream` is the whole
//! requirement — and it keeps the client side free of a runtime.
//!
//! Building a request and reading a response are pure functions over
//! bytes, so the wire format is unit-tested. [`send`] is the part that
//! opens a socket.

use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anago_core::json;
use anago_core::proto::{ApiError, ErrorCode};
use anago_core::token::DeviceToken;

/// How long to wait for the TCP connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for the hub to answer.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest response the client will hold. The peer list of a personal
/// network is kilobytes; anything near this is a server that has lost
/// its mind, and reading it into memory would not help.
pub const MAX_RESPONSE: usize = 1 << 20;

/// An HTTP method, spelled the way the request line needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Delete,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Delete => "DELETE",
        }
    }
}

/// What to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    pub method: Method,
    /// Hostname, without a port — it goes in `Host` and is what the
    /// certificate is checked against.
    pub host: &'a str,
    pub port: u16,
    /// Absolute path, already percent-encoded.
    pub path: &'a str,
    pub body: Option<&'a str>,
    pub token: Option<&'a DeviceToken>,
}

/// What came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

impl Response {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Serializes a request.
///
/// `Connection: close` on purpose: one call per process, and it makes
/// the response length unambiguous — the body is whatever arrives
/// before EOF, so a hub that omits `Content-Length` is still readable.
pub fn request_bytes(request: &Request) -> Vec<u8> {
    let mut text = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: anago/{version}\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n",
        method = request.method.as_str(),
        path = request.path,
        host = host_header(request.host, request.port),
        version = env!("CARGO_PKG_VERSION"),
    );
    if let Some(token) = request.token {
        text.push_str(&format!("Authorization: Bearer {}\r\n", token.as_str()));
    }
    if let Some(body) = request.body {
        text.push_str("Content-Type: application/json\r\n");
        text.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    text.push_str("\r\n");

    let mut bytes = text.into_bytes();
    if let Some(body) = request.body {
        bytes.extend_from_slice(body.as_bytes());
    }
    bytes
}

/// `Host` header: the port is included only when it is not the default,
/// which is what a server comparing it to its certificate expects.
pub fn host_header(host: &str, port: u16) -> String {
    if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// Percent-encodes one path segment — a device name on its way into
/// `DELETE /api/v1/peers/{name}`.
///
/// Device names are Unicode (§8.1), so `맥북` has to survive the trip
/// as `%EB%A7%A5%EB%B6%81` rather than being sent raw.
pub fn encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.as_bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// [`parse_response`] with the size limit applied.
///
/// The caller reads one byte past [`MAX_RESPONSE`] so that "exactly the
/// limit" and "more than the limit" are distinguishable — a plain
/// `take(MAX_RESPONSE)` ends in an artificial EOF, and a truncated body
/// would come back as a confusing JSON error instead of the real
/// problem.
pub fn parse_bounded(bytes: &[u8]) -> Result<Response, ClientError> {
    if bytes.len() > MAX_RESPONSE {
        return Err(ClientError::TooLarge(MAX_RESPONSE));
    }
    parse_response(bytes)
}

/// Reads a response off the wire.
pub fn parse_response(bytes: &[u8]) -> Result<Response, ClientError> {
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(ClientError::Malformed("no end of headers"))?;
    let head = std::str::from_utf8(&bytes[..split])
        .map_err(|_| ClientError::Malformed("headers are not UTF-8"))?;
    // Not lossy: JSON is UTF-8 by definition, and replacing bad bytes
    // with U+FFFD would hand the decoder something the hub never sent.
    let body = std::str::from_utf8(&bytes[split + 4..])
        .map_err(|_| ClientError::Malformed("the body is not UTF-8"))?
        .to_string();

    let status_line = head.lines().next().unwrap_or_default();
    let mut parts = status_line.split(' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(ClientError::Malformed("not an HTTP/1.x response"));
    }
    let status: u16 = parts
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or(ClientError::Malformed("no status code"))?;

    // The server never chunks — it writes one JSON body — but a proxy
    // in between might, and silently handing back framing bytes as JSON
    // would be worse than saying so.
    if head
        .lines()
        .skip(1)
        .any(|line| line.to_ascii_lowercase().starts_with("transfer-encoding:"))
    {
        return Err(ClientError::Malformed(
            "chunked responses are not supported",
        ));
    }

    Ok(Response { status, body })
}

/// Sends a request and reads the answer.
///
/// **Human verification needed**: this opens a socket and completes a
/// TLS handshake against a real hub.
pub fn send(request: &Request) -> Result<Response, ClientError> {
    let config = client_config()?;
    let server_name = rustls::pki_types::ServerName::try_from(request.host.to_string())
        .map_err(|_| ClientError::BadHost(request.host.to_string()))?;
    let connection = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| ClientError::Tls(e.to_string()))?;

    let addresses: Vec<std::net::SocketAddr> = (request.host, request.port)
        .to_socket_addrs()
        .map_err(|e| ClientError::Resolve {
            host: request.host.to_string(),
            source: e.to_string(),
        })?
        .collect();
    if addresses.is_empty() {
        return Err(ClientError::Resolve {
            host: request.host.to_string(),
            source: "no addresses".to_string(),
        });
    }

    let socket = connect_any(&addresses)?;
    socket
        .set_read_timeout(Some(READ_TIMEOUT))
        .and_then(|()| socket.set_write_timeout(Some(READ_TIMEOUT)))
        .map_err(|e| ClientError::Connect {
            address: request.host.to_string(),
            source: e.to_string(),
        })?;

    let mut stream = rustls::StreamOwned::new(connection, socket);
    // The handshake happens inside this write, so a hang here is a hub
    // that accepted the connection and then said nothing.
    stream
        .write_all(&request_bytes(request))
        .map_err(|e| io_error("sending the request", &e))?;
    stream
        .flush()
        .map_err(|e| io_error("sending the request", &e))?;

    let mut buffer = Vec::new();
    stream
        // One byte past the limit, so a response *at* the limit is not
        // mistaken for a truncated one.
        .take(MAX_RESPONSE as u64 + 1)
        .read_to_end(&mut buffer)
        .map_err(|e| io_error("waiting for the answer", &e))?;
    parse_bounded(&buffer)
}

/// Tries every address DNS returned, within one connection budget.
///
/// A dual-stack hub whose AAAA is unreachable from this network is an
/// ordinary Tuesday; giving up on the first address would make that
/// look like the hub being down.
fn connect_any(addresses: &[std::net::SocketAddr]) -> Result<TcpStream, ClientError> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut last: Option<(std::net::SocketAddr, String)> = None;

    for (index, address) in addresses.iter().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let budget = attempt_budget(remaining, addresses.len() - index);
        if budget.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(address, budget) {
            Ok(socket) => return Ok(socket),
            Err(e) => last = Some((*address, e.to_string())),
        }
    }

    let (address, source) = last.unwrap_or_else(|| {
        (
            addresses[0],
            format!("timed out after {}s", CONNECT_TIMEOUT.as_secs()),
        )
    });
    Err(ClientError::Connect {
        address: if addresses.len() > 1 {
            format!("{address} (and {} other address(es))", addresses.len() - 1)
        } else {
            address.to_string()
        },
        source,
    })
}

/// How long one address gets: an even share of what is left, so a
/// hanging first address cannot eat the whole budget.
pub fn attempt_budget(remaining: Duration, addresses_left: usize) -> Duration {
    if addresses_left <= 1 {
        return remaining;
    }
    remaining / addresses_left as u32
}

/// Sorts an I/O failure into what actually went wrong.
///
/// rustls does the handshake inside the first read or write, and
/// reports a rejected certificate as an `io::Error` — so without
/// unwrapping it, "unknown issuer" arrives as "the connection broke"
/// and the operator never sees the advice about installing a private
/// CA.
fn io_error(what: &'static str, e: &std::io::Error) -> ClientError {
    if let Some(reason) = tls_reason(e) {
        return ClientError::Tls(reason);
    }
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => ClientError::Timeout {
            what,
            after: READ_TIMEOUT,
        },
        _ => ClientError::Io(format!("{what}: {e}")),
    }
}

/// The rustls error hiding inside an `io::Error`, if there is one.
///
/// It usually arrives as the io error's inner error; the
/// `InvalidData` fallback catches the paths that only set a kind,
/// which on this stream can come from nowhere but the TLS layer.
pub fn tls_reason(e: &std::io::Error) -> Option<String> {
    if let Some(tls) = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        return Some(tls.to_string());
    }
    if e.kind() == std::io::ErrorKind::InvalidData {
        return Some(e.to_string());
    }
    None
}

/// Trusts what the machine trusts.
///
/// Not a bundled root list: a hub can legitimately serve a certificate
/// from a private CA — a Cloudflare origin certificate, say (§11) — and
/// the way to accept that is to install its CA on the device, which is
/// a thing the operator already knows how to do.
fn client_config() -> Result<rustls::ClientConfig, ClientError> {
    let mut roots = rustls::RootCertStore::empty();
    let loaded = rustls_native_certs::load_native_certs();
    for certificate in loaded.certs {
        let _ = roots.add(certificate);
    }
    if roots.is_empty() {
        return Err(ClientError::NoRoots);
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| ClientError::Tls(e.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(config)
}

/// A failing answer, read as far as it can be.
///
/// Operation-neutral on purpose: `join`, `ls`, and `rm` all get the
/// same reading and each adds its own advice. Saying "the hub refused
/// the join" to somebody who ran `anago ls` describes work they never
/// asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// `None` when the body was not one of anago's error objects — a
    /// proxy's HTML, say.
    pub code: Option<ErrorCode>,
    /// What to show, before any command-specific advice.
    pub message: String,
}

/// Reads a failing response.
pub fn describe(status: u16, body: &str) -> Failure {
    match json::parse(body)
        .ok()
        .and_then(|value| ApiError::from_json(&value).ok())
    {
        Some(error) => Failure {
            code: Some(error.code),
            message: error.message,
        },
        None => Failure {
            code: None,
            message: format!("HTTP {status}: {}", body.trim()),
        },
    }
}

/// Why a call did not happen, in the words the person running `anago
/// join` needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// The domain is not a name TLS can verify.
    BadHost(String),
    /// DNS said nothing.
    Resolve {
        host: String,
        source: String,
    },
    /// The socket did not open.
    Connect {
        address: String,
        source: String,
    },
    /// The handshake or the transport failed.
    Tls(String),
    Io(String),
    /// The hub accepted the connection and then took too long.
    Timeout {
        what: &'static str,
        after: Duration,
    },
    /// The answer was bigger than [`MAX_RESPONSE`].
    TooLarge(usize),
    /// The machine has no trust store to check the hub against.
    NoRoots,
    /// The answer was not an HTTP response this client can read.
    Malformed(&'static str),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::BadHost(host) => {
                write!(
                    f,
                    "{host:?} is not a hostname a certificate can be checked against"
                )
            }
            ClientError::Resolve { host, source } => write!(
                f,
                "could not resolve {host}: {source} — is the A record in place?"
            ),
            ClientError::Connect { address, source } => write!(
                f,
                "could not reach {address}: {source} — is the port open on the server?"
            ),
            ClientError::Tls(detail) => write!(
                f,
                "TLS failed: {detail} — if the hub uses a private CA \\
                 (a Cloudflare origin certificate, say), install that CA on this device"
            ),
            ClientError::Io(detail) => write!(f, "the connection broke: {detail}"),
            ClientError::Timeout { what, after } => write!(
                f,
                "timed out after {}s {what} — the hub answered the connection but not the request",
                after.as_secs()
            ),
            ClientError::TooLarge(limit) => write!(
                f,
                "the hub's answer is larger than {limit} bytes, which no anago response is"
            ),
            ClientError::NoRoots => write!(
                f,
                "this machine has no CA certificates installed, so the hub cannot be verified"
            ),
            ClientError::Malformed(what) => write!(f, "the hub's answer made no sense: {what}"),
        }
    }
}

impl std::error::Error for ClientError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> DeviceToken {
        DeviceToken::parse(&"ab".repeat(32)).unwrap()
    }

    fn text_of(request: &Request) -> String {
        String::from_utf8(request_bytes(request)).unwrap()
    }

    #[test]
    fn a_get_is_a_complete_http_request() {
        let request = Request {
            method: Method::Get,
            host: "net.example.com",
            port: 443,
            path: "/api/v1/peers",
            body: None,
            token: Some(&token()),
        };
        let expected = format!(
            "GET /api/v1/peers HTTP/1.1\r\n\
             Host: net.example.com\r\n\
             User-Agent: anago/{}\r\n\
             Accept: application/json\r\n\
             Connection: close\r\n\
             Authorization: Bearer {}\r\n\
             \r\n",
            env!("CARGO_PKG_VERSION"),
            "ab".repeat(32)
        );
        assert_eq!(text_of(&request), expected);
    }

    #[test]
    fn a_post_carries_its_body_and_length() {
        let body = r#"{"code":"7QX4-M2KD"}"#;
        let request = Request {
            method: Method::Post,
            host: "net.example.com",
            port: 443,
            path: "/api/v1/join",
            body: Some(body),
            token: None,
        };
        let text = text_of(&request);
        assert!(text.starts_with("POST /api/v1/join HTTP/1.1\r\n"), "{text}");
        assert!(
            text.contains("Content-Type: application/json\r\n"),
            "{text}"
        );
        assert!(
            text.contains(&format!("Content-Length: {}\r\n", body.len())),
            "{text}"
        );
        assert!(text.ends_with(&format!("\r\n\r\n{body}")), "{text}");
        // No token on the one call that has none to send.
        assert!(!text.contains("Authorization"), "{text}");
    }

    #[test]
    fn the_host_header_names_a_non_default_port() {
        assert_eq!(host_header("net.example.com", 443), "net.example.com");
        assert_eq!(host_header("net.example.com", 8443), "net.example.com:8443");

        let request = Request {
            method: Method::Get,
            host: "net.example.com",
            port: 8443,
            path: "/api/v1/peers",
            body: None,
            token: None,
        };
        assert!(text_of(&request).contains("Host: net.example.com:8443\r\n"));
    }

    #[test]
    fn the_body_length_is_counted_in_bytes_not_characters() {
        // A Korean device name is three bytes per character; a
        // character count would truncate the body at the server.
        let body = r#"{"name":"맥북"}"#;
        let request = Request {
            method: Method::Post,
            host: "net.example.com",
            port: 443,
            path: "/api/v1/join",
            body: Some(body),
            token: None,
        };
        let text = text_of(&request);
        assert!(text.contains("Content-Length: 17\r\n"), "{text}");
        assert_eq!(body.len(), 17, "bytes");
        assert_eq!(body.chars().count(), 13, "characters");
    }

    #[test]
    fn path_segments_are_percent_encoded() {
        // `DELETE /api/v1/peers/{name}` with a Unicode name.
        assert_eq!(encode_segment("macbook"), "macbook");
        assert_eq!(encode_segment("mac-book_2.0~x"), "mac-book_2.0~x");
        assert_eq!(encode_segment("맥북"), "%EB%A7%A5%EB%B6%81");
        // And anything that could change the request line.
        assert_eq!(encode_segment("a b"), "a%20b");
        assert_eq!(encode_segment("a/b"), "a%2Fb");
        assert_eq!(encode_segment("a?b#c"), "a%3Fb%23c");
        assert_eq!(encode_segment("a\r\nX: y"), "a%0D%0AX%3A%20y");
    }

    #[test]
    fn a_response_is_split_into_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"peers\":[]}";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, r#"{"peers":[]}"#);
        assert!(response.is_success());
    }

    #[test]
    fn an_error_response_keeps_its_body_for_the_message() {
        let raw = b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"code\":\"invalid_code\"}";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.status, 403);
        assert!(!response.is_success());
        assert!(response.body.contains("invalid_code"));
    }

    #[test]
    fn a_response_without_a_body_is_fine() {
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.status, 204);
        assert_eq!(response.body, "");
    }

    #[test]
    fn nonsense_is_reported_rather_than_guessed_at() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\n"),
            Err(ClientError::Malformed("no end of headers"))
        );
        assert_eq!(
            parse_response(b"hello there\r\n\r\n"),
            Err(ClientError::Malformed("not an HTTP/1.x response"))
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 fine\r\n\r\n"),
            Err(ClientError::Malformed("no status code"))
        );
        // A proxy that chunks the answer: say so instead of handing
        // framing bytes back as JSON.
        assert_eq!(
            parse_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
            ),
            Err(ClientError::Malformed(
                "chunked responses are not supported"
            ))
        );
    }

    #[test]
    fn a_failing_answer_is_read_without_naming_an_operation() {
        // Shared by join, ls, and rm — so it says what the hub said,
        // and nothing about which command asked.
        let body = json::to_string(
            &ApiError::new(ErrorCode::Unauthorized, "a valid device token is required").to_json(),
        );
        let failure = describe(401, &body);
        assert_eq!(failure.code, Some(ErrorCode::Unauthorized));
        assert_eq!(failure.message, "a valid device token is required");
        assert!(!failure.message.contains("join"), "{}", failure.message);

        // A proxy's HTML still reaches the person, with the status.
        let failure = describe(502, "<html>bad gateway</html>");
        assert_eq!(failure.code, None);
        assert!(failure.message.contains("HTTP 502"), "{}", failure.message);
        assert!(
            failure.message.contains("bad gateway"),
            "{}",
            failure.message
        );
    }

    #[test]
    fn failures_say_what_to_check() {
        let e = ClientError::Resolve {
            host: "net.example.com".to_string(),
            source: "nodename nor servname provided".to_string(),
        };
        assert!(e.to_string().contains("is the A record in place?"), "{e}");

        let e = ClientError::Connect {
            address: "203.0.113.7:443".to_string(),
            source: "Connection refused".to_string(),
        };
        assert!(e.to_string().contains("is the port open"), "{e}");

        let e = ClientError::Tls("invalid peer certificate: UnknownIssuer".to_string());
        assert!(
            e.to_string().contains("install that CA on this device"),
            "{e}"
        );
    }

    #[test]
    fn a_response_at_the_limit_is_kept_and_one_past_it_is_refused() {
        // Regression: reading exactly MAX_RESPONSE bytes ends in an
        // artificial EOF, so a truncated body used to come back as a
        // successful parse and fail later as confusing JSON.
        let head = b"HTTP/1.1 200 OK\r\n\r\n";
        let mut at_limit = head.to_vec();
        at_limit.resize(MAX_RESPONSE, b'x');
        assert_eq!(at_limit.len(), MAX_RESPONSE);
        let response = parse_bounded(&at_limit).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body.len(), MAX_RESPONSE - head.len());

        let mut past_limit = at_limit.clone();
        past_limit.push(b'x');
        assert_eq!(
            parse_bounded(&past_limit),
            Err(ClientError::TooLarge(MAX_RESPONSE))
        );
        assert!(ClientError::TooLarge(MAX_RESPONSE)
            .to_string()
            .contains("larger than"),);
    }

    #[test]
    fn a_body_that_is_not_utf8_is_refused_rather_than_patched() {
        // U+FFFD substitution would hand the JSON decoder bytes the hub
        // never sent.
        let mut raw = b"HTTP/1.1 200 OK\r\n\r\n{\"name\":\"".to_vec();
        raw.extend_from_slice(&[0xff, 0xfe]);
        raw.extend_from_slice(b"\"}");
        assert_eq!(
            parse_response(&raw),
            Err(ClientError::Malformed("the body is not UTF-8"))
        );
        // Valid multi-byte text still comes through untouched.
        let good = "HTTP/1.1 200 OK\r\n\r\n{\"name\":\"맥북\"}".as_bytes();
        assert_eq!(parse_response(good).unwrap().body, r#"{"name":"맥북"}"#);
    }

    #[test]
    fn the_connection_budget_is_shared_between_addresses() {
        // A hub with an unreachable AAAA must not eat the whole budget
        // before its A record is tried.
        let ten = Duration::from_secs(10);
        assert_eq!(attempt_budget(ten, 1), ten);
        assert_eq!(attempt_budget(ten, 2), Duration::from_secs(5));
        assert_eq!(attempt_budget(ten, 4), Duration::from_millis(2500));
        // Nothing left means nothing to wait for.
        assert!(attempt_budget(Duration::ZERO, 3).is_zero());
    }

    #[test]
    fn a_rejected_certificate_is_reported_as_a_tls_problem() {
        // Regression: rustls hands back certificate failures as
        // io::Errors during the first read/write, so they used to be
        // classified as "the connection broke" — losing the one piece
        // of advice that fixes a private-CA setup.
        let rejected = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        );
        let e = io_error("sending the request", &rejected);
        assert!(matches!(e, ClientError::Tls(_)), "{e:?}");
        let message = e.to_string();
        assert!(message.contains("UnknownIssuer"), "{message}");
        assert!(
            message.contains("install that CA on this device"),
            "{message}"
        );

        // A hostname mismatch travels the same way.
        let mismatch = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName),
        );
        assert!(matches!(io_error("x", &mismatch), ClientError::Tls(_)));

        // And a TLS layer error that only set a kind.
        let bare = std::io::Error::new(std::io::ErrorKind::InvalidData, "received corrupt message");
        assert!(matches!(io_error("x", &bare), ClientError::Tls(_)));
    }

    #[test]
    fn ordinary_socket_failures_stay_ordinary() {
        // The mapping must not swallow everything into TLS.
        let reset = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset by peer");
        assert!(matches!(io_error("x", &reset), ClientError::Io(_)));
        assert_eq!(tls_reason(&reset), None);

        let timed_out = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        assert!(matches!(
            io_error("x", &timed_out),
            ClientError::Timeout { .. }
        ));
        assert_eq!(tls_reason(&timed_out), None);
    }

    #[test]
    fn a_timeout_says_which_step_hung() {
        let e = ClientError::Timeout {
            what: "waiting for the answer",
            after: READ_TIMEOUT,
        };
        let message = e.to_string();
        assert!(message.contains("timed out after 30s"), "{message}");
        assert!(message.contains("waiting for the answer"), "{message}");
        // Distinct from a broken pipe, which is not a timeout.
        assert!(!ClientError::Io("broken pipe".to_string())
            .to_string()
            .contains("timed out"));
    }
}
