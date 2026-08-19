//! anago's HTTPS client (DESIGN.md §8, §10.2).
//!
//! Small on purpose: one connection per call, no async. `join`, `ls`
//! and `rm` each make a single call and exit, so a blocking TLS stream
//! over `std::net::TcpStream` is the whole requirement — and it keeps
//! the client side free of a runtime.
//!
//! M1 points the same client at Cloudflare rather than adding a second
//! HTTP stack (§10.2). That is the reason for the general shape here:
//! any method, any host, a settable `Authorization` and content type.
//! What it buys is one set of timeouts, one trust store and one
//! vocabulary of errors for everything anago sends outward — a second
//! client would mean two of each, drifting.
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

/// How long to wait for an answer.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest response the client will hold. The peer list of a personal
/// network is kilobytes, and a Cloudflare zone listing is not much
/// more; anything near this is a server that has lost its mind, and
/// reading it into memory would not help.
pub const MAX_RESPONSE: usize = 1 << 20;

/// The content type anago's own API speaks.
pub const JSON: &str = "application/json";

/// An HTTP method, spelled the way the request line needs it.
// The rest of the Cloudflare surface ([`HeaderValue::bearer`],
// [`Body::new`], [`Response::header`], [`ClientError::BadHeaderValue`])
// is exercised by tests here and called for real by `cfapi`. Kept
// together so this module is reviewed as one wire format rather than
// grown a field at a time.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    /// Cloudflare's record update. `PATCH`, not `PUT`, on purpose:
    /// `PUT` replaces a whole record, so pointing an **adopted** record
    /// at the hub would also reset the TTL, comment, and tags its owner
    /// set. `PATCH` sends only the field anago is changing.
    Patch,
    /// Removing a DNS-01 challenge record once it has been checked.
    Delete,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }
}

/// A header value that is safe to put on the wire.
///
/// The one thing this rules out is the one thing that matters: a value
/// carrying CR or LF would end the header early and let whatever
/// follows be read as more headers. That is not a hypothetical here —
/// an API token arrives from a file or an environment variable, and a
/// **trailing newline on a token file is the normal case**, not an
/// attack. Catching it as "the token has a newline in it" beats sending
/// a corrupted request and reading a puzzling 400 back.
/// Redacts itself in `Debug`, the way [`DeviceToken`] does. Wrapping a
/// token in this type must not be the step that undoes that protection
/// — and a Cloudflare token is the widest-reaching secret anago holds
/// (§13), so it is the last one that should reach a log line.
#[derive(Clone, PartialEq, Eq)]
pub struct HeaderValue(String);

impl fmt::Debug for HeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HeaderValue(redacted)")
    }
}

#[allow(dead_code)]
impl HeaderValue {
    /// Accepts printable ASCII and horizontal tab, which is what a
    /// header value may hold.
    pub fn parse(value: &str) -> Result<HeaderValue, ClientError> {
        if value.is_empty() {
            return Err(ClientError::BadHeaderValue("it is empty"));
        }
        if value.contains(['\r', '\n']) {
            return Err(ClientError::BadHeaderValue(
                "it contains a line break — check for a trailing newline",
            ));
        }
        if value
            .chars()
            .any(|c| c != '\t' && (c.is_control() || !c.is_ascii()))
        {
            return Err(ClientError::BadHeaderValue(
                "it contains a character that is not printable ASCII",
            ));
        }
        Ok(HeaderValue(value.to_string()))
    }

    /// `Bearer <secret>` for an API token that came from outside —
    /// `--cf-token`, an environment variable, a file (§8).
    pub fn bearer(secret: &str) -> Result<HeaderValue, ClientError> {
        HeaderValue::parse(&format!("Bearer {secret}"))
    }

    /// `Bearer <token>` for a device token. Infallible: [`DeviceToken`]
    /// is 64 hex characters by construction (§7.1), so there is nothing
    /// left to check.
    pub fn device_token(token: &DeviceToken) -> HeaderValue {
        HeaderValue(format!("Bearer {}", token.as_str()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A request body and the type it is sent as.
///
/// The content type is carried rather than assumed because M1 talks to
/// somebody else's API: `application/json` is anago's own answer, not
/// a universal one.
/// The content is redacted in `Debug` too: a join body carries the join
/// code, which is the registration right itself (§7.2). The type and
/// the length are what someone debugging a request actually wants.
#[derive(Clone, PartialEq, Eq)]
pub struct Body<'a> {
    pub content_type: &'a str,
    pub content: &'a str,
}

impl fmt::Debug for Body<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Body")
            .field("content_type", &self.content_type)
            .field("bytes", &self.content.len())
            .finish()
    }
}

#[allow(dead_code)]
impl<'a> Body<'a> {
    pub fn json(content: &'a str) -> Body<'a> {
        Body {
            content_type: JSON,
            content,
        }
    }

    pub fn new(content_type: &'a str, content: &'a str) -> Body<'a> {
        Body {
            content_type,
            content,
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
    pub body: Option<Body<'a>>,
    /// The `Authorization` header, when there is one. A device token
    /// for anago's own API, an API token for Cloudflare.
    pub authorization: Option<&'a HeaderValue>,
}

/// What came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    /// Header names lower-cased, values as sent. Kept because a rate
    /// limit answers with `Retry-After`, and §13 says anago follows
    /// that rather than guessing its own interval.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Response {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// First value of a header, matched without regard to case.
    #[allow(dead_code)]
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
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
    if let Some(authorization) = request.authorization {
        text.push_str(&format!("Authorization: {}\r\n", authorization.as_str()));
    }
    if let Some(body) = &request.body {
        text.push_str(&format!("Content-Type: {}\r\n", body.content_type));
        // Bytes, not characters: a Korean device name in a JSON body
        // would otherwise under-count and truncate the request.
        text.push_str(&format!("Content-Length: {}\r\n", body.content.len()));
    }
    text.push_str("\r\n");

    let mut bytes = text.into_bytes();
    if let Some(body) = &request.body {
        bytes.extend_from_slice(body.content.as_bytes());
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

    let headers = parse_headers(head);

    // Neither anago nor Cloudflare chunks — each writes one JSON body —
    // but a proxy in between might, and silently handing back framing
    // bytes as JSON would be worse than saying so.
    if headers.iter().any(|(name, _)| name == "transfer-encoding") {
        return Err(ClientError::Malformed(
            "chunked responses are not supported",
        ));
    }

    Ok(Response {
        status,
        headers,
        body,
    })
}

/// Splits header lines into lower-cased names and trimmed values.
///
/// A line without a colon is dropped rather than refused: a header this
/// client does not need is not a reason to fail a response that is
/// otherwise fine.
fn parse_headers(head: &str) -> Vec<(String, String)> {
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect()
}

/// Sends a request and reads the answer.
///
/// **Human verification needed**: this opens a socket and completes a
/// TLS handshake against a real host — the hub, or Cloudflare.
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
    /// A header value could not be sent as given — see
    /// [`HeaderValue::parse`].
    #[allow(dead_code)]
    BadHeaderValue(&'static str),
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
            ClientError::BadHeaderValue(why) => {
                write!(f, "that credential cannot be sent as a header: {why}")
            }
            ClientError::BadHost(host) => {
                write!(
                    f,
                    "{host:?} is not a hostname a certificate can be checked against"
                )
            }
            // These reach a person for calls to the hub *and* to
            // Cloudflare now, so nothing here may assume which one it
            // was. Naming the host is what tells them which end to
            // look at; sending someone to check their own A record
            // because api.cloudflare.com failed to resolve would point
            // them at the wrong end entirely.
            ClientError::Resolve { host, source } => write!(
                f,
                "could not resolve {host}: {source} — check that the name has a DNS record"
            ),
            ClientError::Connect { address, source } => write!(
                f,
                "could not reach {address}: {source} — check that the port is open"
            ),
            ClientError::Tls(detail) => write!(
                f,
                "TLS failed: {detail} — if that was your hub and it uses a private CA \
                 (a Cloudflare origin certificate, say), install that CA on this device"
            ),
            ClientError::Io(detail) => write!(f, "the connection broke: {detail}"),
            ClientError::Timeout { what, after } => write!(
                f,
                "timed out after {}s {what} — the connection was accepted but the \
                 request was not answered",
                after.as_secs()
            ),
            ClientError::TooLarge(limit) => {
                write!(f, "the answer is larger than {limit} bytes")
            }
            ClientError::NoRoots => write!(
                f,
                "this machine has no CA certificates installed, so the server cannot be verified"
            ),
            ClientError::Malformed(what) => write!(f, "the answer made no sense: {what}"),
        }
    }
}

impl std::error::Error for ClientError {}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------- redaction

    #[test]
    fn a_credential_never_reaches_a_debug_line() {
        // Wrapping a token must not be the step that undoes
        // `DeviceToken`'s protection, and a Cloudflare token is the
        // widest-reaching secret anago holds (§13).
        let cf = HeaderValue::bearer("cf-api-token").unwrap();
        assert_eq!(format!("{cf:?}"), "HeaderValue(redacted)");
        assert!(!format!("{cf:?}").contains("cf-api-token"));

        let device = HeaderValue::device_token(&token());
        assert!(!format!("{device:?}").contains(token().as_str()));
    }

    #[test]
    fn debugging_a_request_prints_neither_the_token_nor_the_body() {
        // A join body carries the join code, which is the registration
        // right itself (§7.2).
        let cf = HeaderValue::bearer("cf-api-token").unwrap();
        let body = r#"{"code":"7QX4-M2KD"}"#;
        let request = Request {
            method: Method::Post,
            host: "api.cloudflare.com",
            port: 443,
            path: "/client/v4/zones",
            body: Some(Body::json(body)),
            authorization: Some(&cf),
        };
        let printed = format!("{request:?}");
        assert!(!printed.contains("cf-api-token"), "{printed}");
        assert!(!printed.contains("7QX4-M2KD"), "{printed}");
        // What is left is what someone debugging actually wants.
        assert!(printed.contains("api.cloudflare.com"), "{printed}");
        assert!(printed.contains("application/json"), "{printed}");
        assert!(
            printed.contains(&format!("bytes: {}", body.len())),
            "{printed}"
        );
        // The value still goes on the wire in full.
        assert!(text(&request).contains("Authorization: Bearer cf-api-token\r\n"));
    }

    // ------------------------------------------------ error wording

    #[test]
    fn errors_do_not_send_a_person_to_the_wrong_end() {
        // The same errors now come from Cloudflare calls, so none of
        // them may assume the hub was the other end.
        let errors = [
            ClientError::Resolve {
                host: "api.cloudflare.com".to_string(),
                source: "no address".to_string(),
            },
            ClientError::Connect {
                address: "1.2.3.4:443".to_string(),
                source: "refused".to_string(),
            },
            ClientError::Timeout {
                what: "waiting for the answer",
                after: READ_TIMEOUT,
            },
            ClientError::TooLarge(MAX_RESPONSE),
            ClientError::NoRoots,
            ClientError::Malformed("no status code"),
            ClientError::Io("reset".to_string()),
        ];
        for error in errors {
            let message = error.to_string();
            assert!(!message.contains("hub"), "{message}");
            assert!(!message.contains("A record"), "{message}");
            assert!(!message.contains("anago response"), "{message}");
            // And nothing carries a stray line continuation.
            assert!(!message.contains('\\'), "{message}");
            for line in message.lines() {
                assert!(!line.trim_start().contains("  "), "{message}");
            }
        }
    }

    #[test]
    fn the_errors_that_can_name_a_host_do() {
        // Which end to look at is the one thing the message can still
        // say once it stops guessing.
        let resolve = ClientError::Resolve {
            host: "api.cloudflare.com".to_string(),
            source: "no address".to_string(),
        }
        .to_string();
        assert!(resolve.contains("api.cloudflare.com"), "{resolve}");
        let connect = ClientError::Connect {
            address: "1.2.3.4:443".to_string(),
            source: "refused".to_string(),
        }
        .to_string();
        assert!(connect.contains("1.2.3.4:443"), "{connect}");
    }

    #[test]
    fn the_private_ca_hint_is_offered_not_asserted() {
        // Still useful for the hub — origin certificates are a real
        // trap (§11) — but phrased so it is not wrong for Cloudflare.
        let message = ClientError::Tls("UnknownIssuer".to_string()).to_string();
        assert!(message.contains("if that was your hub"), "{message}");
        assert!(message.contains("origin certificate"), "{message}");
    }

    // ------------------------------------------- third-party requests

    fn cf_token() -> HeaderValue {
        HeaderValue::bearer("cf-api-token").unwrap()
    }

    fn text(request: &Request) -> String {
        String::from_utf8(request_bytes(request)).unwrap()
    }

    #[test]
    fn every_method_reaches_the_request_line() {
        for (method, spelled) in [
            (Method::Get, "GET"),
            (Method::Post, "POST"),
            (Method::Patch, "PATCH"),
            (Method::Delete, "DELETE"),
        ] {
            let request = Request {
                method,
                host: "api.cloudflare.com",
                port: 443,
                path: "/client/v4/zones",
                body: None,
                authorization: Some(&cf_token()),
            };
            assert!(
                text(&request).starts_with(&format!("{spelled} /client/v4/zones HTTP/1.1\r\n")),
                "{spelled}"
            );
        }
    }

    #[test]
    fn a_third_party_host_gets_its_own_host_header() {
        let request = Request {
            method: Method::Get,
            host: "api.cloudflare.com",
            port: 443,
            path: "/client/v4/zones",
            body: None,
            authorization: Some(&cf_token()),
        };
        let text = text(&request);
        assert!(text.contains("Host: api.cloudflare.com\r\n"), "{text}");
        assert!(
            text.contains("Authorization: Bearer cf-api-token\r\n"),
            "{text}"
        );
    }

    #[test]
    fn the_content_type_follows_the_body_not_a_default() {
        // M1 talks to somebody else's API, so `application/json` is
        // anago's own answer rather than a universal one.
        let body = Body::new("application/jose+json", "{}");
        let request = Request {
            method: Method::Post,
            host: "acme-v02.api.letsencrypt.org",
            port: 443,
            path: "/acme/new-order",
            body: Some(body),
            authorization: None,
        };
        let text = text(&request);
        assert!(
            text.contains("Content-Type: application/jose+json\r\n"),
            "{text}"
        );
        assert!(
            !text.contains("Content-Type: application/json\r\n"),
            "{text}"
        );
        assert!(text.contains("Content-Length: 2\r\n"), "{text}");
        assert!(text.ends_with("\r\n\r\n{}"), "{text}");
    }

    #[test]
    fn content_length_counts_bytes_not_characters() {
        // A Korean device name in a body would otherwise under-count
        // and truncate the request.
        let json = r#"{"name":"맥북"}"#;
        let request = Request {
            method: Method::Post,
            host: "net.example.com",
            port: 443,
            path: "/api/v1/join",
            body: Some(Body::json(json)),
            authorization: None,
        };
        let text = text(&request);
        assert!(
            text.contains(&format!("Content-Length: {}\r\n", json.len())),
            "{text}"
        );
        assert_ne!(json.len(), json.chars().count());
    }

    #[test]
    fn a_request_without_a_body_declares_neither_type_nor_length() {
        let request = Request {
            method: Method::Delete,
            host: "api.cloudflare.com",
            port: 443,
            path: "/client/v4/zones/z1/dns_records/r1",
            body: None,
            authorization: Some(&cf_token()),
        };
        let text = text(&request);
        assert!(!text.contains("Content-Type"), "{text}");
        assert!(!text.contains("Content-Length"), "{text}");
    }

    // ------------------------------------------------- header values

    #[test]
    fn a_token_with_a_trailing_newline_is_caught_here() {
        // The normal case, not an attack: `cat`-ing a token file keeps
        // the newline, and a raw CR/LF would end the header early and
        // let what follows be read as more headers.
        let error = HeaderValue::bearer("cf-api-token\n").unwrap_err();
        assert_eq!(
            error,
            ClientError::BadHeaderValue("it contains a line break — check for a trailing newline")
        );
        assert!(error.to_string().contains("trailing newline"));
        assert!(HeaderValue::bearer("a\rb").is_err());
    }

    #[test]
    fn a_header_value_refuses_what_cannot_be_sent() {
        assert!(HeaderValue::parse("").is_err());
        assert!(HeaderValue::parse("Bearer \u{7f}").is_err());
        // Non-ASCII cannot go in a header value as it stands.
        assert!(HeaderValue::parse("Bearer 토큰").is_err());
        // Ordinary token characters and tabs are fine.
        assert!(HeaderValue::parse("Bearer aB3-_.~").is_ok());
        assert!(HeaderValue::parse("Bearer\ta").is_ok());
    }

    #[test]
    fn a_device_token_needs_no_checking() {
        // 64 hex characters by construction (§7.1), so the infallible
        // constructor is honest rather than lazy.
        let value = HeaderValue::device_token(&token());
        assert_eq!(value.as_str(), format!("Bearer {}", token().as_str()));
        assert!(HeaderValue::parse(value.as_str()).is_ok());
    }

    // --------------------------------------------- response headers

    #[test]
    fn response_headers_are_kept_and_matched_without_case() {
        // §13: a rate limit answers with `Retry-After`, and anago
        // follows that rather than guessing its own interval.
        let raw = b"HTTP/1.1 429 Too Many Requests\r\n\
                    Retry-After: 42\r\n\
                    Content-Type: application/json\r\n\
                    \r\n{}";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.status, 429);
        assert_eq!(response.header("retry-after"), Some("42"));
        assert_eq!(response.header("Retry-After"), Some("42"));
        assert_eq!(response.header("RETRY-AFTER"), Some("42"));
        assert_eq!(response.header("x-absent"), None);
        assert!(!response.is_success());
    }

    #[test]
    fn a_header_line_without_a_colon_does_not_fail_the_response() {
        // A header this client does not need is no reason to reject an
        // answer that is otherwise fine.
        let raw = b"HTTP/1.1 200 OK\r\nnonsense\r\nLocation: /acct/1\r\n\r\n{}";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.header("location"), Some("/acct/1"));
        assert_eq!(response.body, "{}");
    }

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
            authorization: Some(&HeaderValue::device_token(&token())),
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
            body: Some(Body::json(body)),
            authorization: None,
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
            authorization: None,
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
            body: Some(Body::json(body)),
            authorization: None,
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
        assert!(
            e.to_string()
                .contains("check that the name has a DNS record"),
            "{e}"
        );

        let e = ClientError::Connect {
            address: "203.0.113.7:443".to_string(),
            source: "Connection refused".to_string(),
        };
        assert!(e.to_string().contains("check that the port is open"), "{e}");

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
