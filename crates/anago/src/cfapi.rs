//! Talking to Cloudflare (DESIGN.md §8, §9.1, §13).
//!
//! This slice is the front door: **where the API token comes from**,
//! whether Cloudflare still accepts it, and what to tell a person when
//! it does not. The record judgement itself is pure and lives in
//! `anago_core::dns`; the calls that act on it land next.
//!
//! Three ways in, in this order (§8):
//!
//! 1. `--cf-token-file <path>`
//! 2. `--cf-token <value>`
//! 3. `CLOUDFLARE_API_TOKEN`
//!
//! and **none of them is also an answer**: without a token anago does
//! not touch DNS at all and M0's manual instructions stand (§6.1).
//!
//! The file path is first on purpose. `--cf-token` puts a credential in
//! `argv`, where `ps` and shell history can see it; it stays because
//! typing one flag by hand is a reasonable thing to do once, but a
//! script should use the file.
//!
//! Responses are read with `serde_json`, not with anago-core's mini
//! JSON: this is somebody else's schema, and the strictness that is
//! right for our own would fail a whole response over a field we never
//! look at (§10.2).

use std::fmt;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anago_core::acme;
use anago_core::dns::{self, Record, Refusal, Upsert};

use crate::client::{self, Body, ClientError, HeaderValue, Method, Request};

/// Cloudflare's API host.
pub const API_HOST: &str = "api.cloudflare.com";

/// The endpoint that answers "is this token any good?".
pub const VERIFY_PATH: &str = "/client/v4/user/tokens/verify";

/// Where zones are listed.
pub const ZONES_PATH: &str = "/client/v4/zones";

/// The environment variable, spelled the way Cloudflare's own tools
/// spell it — people already have it exported.
pub const TOKEN_ENV: &str = "CLOUDFLARE_API_TOKEN";

/// Where a token is to be read from, once the precedence is settled.
///
/// Carries the *source*, not the secret, so the decision can be made
/// and tested without a token anywhere near it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    File(PathBuf),
    /// `--cf-token`.
    Flag,
    /// `CLOUDFLARE_API_TOKEN`.
    Env,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::File(path) => write!(f, "{}", path.display()),
            Source::Flag => f.write_str("--cf-token"),
            Source::Env => f.write_str(TOKEN_ENV),
        }
    }
}

/// A Cloudflare API token.
///
/// Redacted in `Debug`, like every other credential in this codebase:
/// this one can rewrite every record in the zone, which makes it the
/// widest-reaching secret anago handles (§13).
#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    value: String,
    pub source: Source,
}

impl Token {
    /// Checks a token as read from a flag, a file, or the environment.
    ///
    /// Surrounding whitespace is trimmed, because a token file ends
    /// with a newline far more often than not and refusing that would
    /// be pedantry rather than safety. Whitespace *inside* is refused:
    /// that is a truncated copy-paste, and sending it produces a 401
    /// that looks like a permissions problem.
    pub fn parse(value: &str, source: Source) -> Result<Token, CfError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(CfError::Empty(source));
        }
        if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(CfError::Malformed(source));
        }
        Ok(Token {
            value: trimmed.to_string(),
            source,
        })
    }

    /// The `Authorization` header this token sends.
    pub fn header(&self) -> Result<HeaderValue, ClientError> {
        HeaderValue::bearer(&self.value)
    }

    /// The secret. Deliberately the only way out.
    pub fn expose(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("value", &"redacted")
            .field("source", &self.source)
            .finish()
    }
}

/// Decides which of the three ways in wins (§8).
///
/// Pure, and takes the environment as an argument rather than reading
/// it, so precedence is unit-tested without touching the process
/// environment.
///
/// `Ok(None)` is the ordinary no-Cloudflare case: anago prints M0's
/// manual DNS instructions and carries on (§6.1). Only the two flags
/// together are an error — that is a person telling anago two different
/// things, and picking one of them silently is how the wrong credential
/// gets used.
pub fn choose(
    file: Option<&str>,
    flag: Option<&str>,
    env: Option<&str>,
) -> Result<Option<Source>, CfError> {
    match (file, flag) {
        (Some(_), Some(_)) => return Err(CfError::BothFlags),
        (Some(path), None) => return Ok(Some(Source::File(PathBuf::from(path)))),
        (None, Some(_)) => return Ok(Some(Source::Flag)),
        (None, None) => {}
    }
    // An empty variable is how a shell spells "unset" half the time;
    // treating it as a token would fail later with a puzzling 401.
    match env {
        Some(value) if !value.trim().is_empty() => Ok(Some(Source::Env)),
        _ => Ok(None),
    }
}

/// A token and anything the person should hear about where it came
/// from.
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded {
    pub token: Token,
    /// Printed by the caller. `None` when there is nothing to say.
    pub warning: Option<String>,
}

/// Reads the token named by a [`Source`].
///
/// The flag and environment values are handed back in, because
/// [`choose`] deliberately does not carry secrets.
///
/// A file is checked for its mode on the way past, and the result rides
/// along in [`Loaded::warning`] rather than being a separate call a
/// caller could forget to make.
pub fn load(source: Source, flag: Option<&str>, env: Option<&str>) -> Result<Loaded, CfError> {
    match &source {
        Source::File(path) => {
            let path = path.clone();
            let contents = std::fs::read_to_string(&path).map_err(|e| CfError::Read {
                path: path.clone(),
                source: e.to_string(),
            })?;
            let mode = file_mode(&path);
            from_file(&contents, &path, mode)
        }
        Source::Flag => Ok(Loaded {
            token: Token::parse(flag.unwrap_or_default(), source)?,
            warning: None,
        }),
        Source::Env => Ok(Loaded {
            token: Token::parse(env.unwrap_or_default(), source)?,
            warning: None,
        }),
    }
}

/// The file case with the I/O already done, so the mode check and the
/// parse are tested together without a filesystem.
fn from_file(contents: &str, path: &Path, mode: Option<u32>) -> Result<Loaded, CfError> {
    Ok(Loaded {
        token: Token::parse(contents, Source::File(path.to_path_buf()))?,
        warning: file_permission_warning(path, mode),
    })
}

#[cfg(unix)]
fn file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .ok()
        .map(|meta| meta.permissions().mode())
}

#[cfg(not(unix))]
fn file_mode(_path: &Path) -> Option<u32> {
    None
}

/// Warns when a token file is readable by anyone else.
///
/// A warning rather than a refusal, the same call [`crate::tls`] makes
/// about a private key: the file belongs to the person who pointed at
/// it, and refusing to start over its mode would be anago deciding how
/// someone else's machine is arranged. Saying nothing would be worse.
pub fn file_permission_warning(path: &Path, mode: Option<u32>) -> Option<String> {
    let mode = mode?;
    if mode & 0o077 == 0 {
        return None;
    }
    Some(format!(
        "{} is readable by other users (mode {:04o}) — that token can edit every \
         record in the zone; `chmod 600 {}`",
        path.display(),
        mode & 0o7777,
        path.display()
    ))
}

/// What Cloudflare says about a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub id: String,
    /// `active`, and anything else is a problem — see [`parse_verify`].
    pub status: String,
}

/// Classifies **any** Cloudflare response and hands back its `result`.
///
/// Every call anago makes goes through here so that one status means
/// one thing everywhere. The split that matters is 401 against 403:
///
/// - **401** — the credential itself was not accepted. Wrong token,
///   truncated token, revoked token.
/// - **403** — the token is fine and is *not allowed to do that*. This
///   is what a DNS **Read** token gets when anago tries to write, and
///   it is the only place that mistake can surface: Cloudflare's verify
///   endpoint reports `active`/`disabled`/`expired` and says nothing
///   about permissions, so a read-only token verifies perfectly and
///   fails at the first edit (§7).
///
/// Pure over the status and body, so both are pinned by tests rather
/// than discovered against a live account.
pub fn parse_result(status: u16, body: &str) -> Result<serde_json::Value, CfError> {
    if status == 401 {
        return Err(CfError::Rejected(first_api_message(body)));
    }
    if status == 403 {
        return Err(CfError::Forbidden(first_api_message(body)));
    }

    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| CfError::Undecodable(e.to_string()))?;

    if value.get("success").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(CfError::ApiFailure {
            status,
            message: first_api_message(body),
        });
    }

    value
        .get("result")
        .cloned()
        .ok_or_else(|| CfError::ApiFailure {
            status,
            message: "the response has no result".to_string(),
        })
}

/// Reads the answer from `GET /client/v4/user/tokens/verify`.
///
/// **This proves the token exists and is active. It does not prove the
/// token may edit DNS** — see [`parse_result`]. A read-only token gets
/// through here and fails at the first write, which is why 403 has its
/// own error rather than being folded into "rejected".
pub fn parse_verify(status: u16, body: &str) -> Result<Verified, CfError> {
    let result = parse_result(status, body)?;
    let token_status = result
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    if token_status != "active" {
        return Err(CfError::NotActive(token_status));
    }

    Ok(Verified {
        id: result
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        status: token_status,
    })
}

/// Cloudflare puts the useful sentence in `errors[0].message`. When it
/// is not there, say so rather than printing an empty string.
fn first_api_message(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            let error = value.get("errors")?.as_array()?.first()?.clone();
            let message = error.get("message")?.as_str()?.to_string();
            match error.get("code").and_then(serde_json::Value::as_i64) {
                Some(code) => Some(format!("{message} (code {code})")),
                None => Some(message),
            }
        })
        .unwrap_or_else(|| "Cloudflare gave no reason".to_string())
}

/// Asks Cloudflare whether the token exists and is active.
///
/// Worth doing at `server init` because "expired" and "disabled" are
/// cheap to catch and confusing to meet later. Worth being clear about
/// what it is not: **an `Ok` here does not mean the token may edit
/// DNS.** Cloudflare has no endpoint that answers that question for a
/// scoped token, so the answer arrives as a 403 on the first real call
/// and reaches the person as [`CfError::Forbidden`].
///
/// **Human verification needed**: this call needs a real account.
pub fn verify(token: &Token) -> Result<Verified, CfError> {
    let authorization = token.header().map_err(CfError::Client)?;
    let response = client::send(&Request {
        method: Method::Get,
        host: API_HOST,
        port: 443,
        path: VERIFY_PATH,
        body: None,
        authorization: Some(&authorization),
    })
    .map_err(CfError::Client)?;
    parse_verify(response.status, &response.body)
}

/// A Cloudflare zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    pub id: String,
    pub name: String,
    /// `active` when Cloudflare is actually serving this zone's DNS.
    pub status: String,
    /// The nameservers Cloudflare answers for this zone with.
    ///
    /// Carried because a DNS-01 challenge has to be watched at the
    /// servers that will actually be asked — Cloudflare's own API can
    /// only say that it stored the record (`dnsprobe`). Empty when the
    /// answer did not name any, which leaves the wait blind rather than
    /// failing it.
    pub name_servers: Vec<String>,
}

/// The names to ask about, most specific first (§6.1).
///
/// The hub's name is usually a subdomain — `net.example.com` — while
/// the zone is `example.com`, so anago walks up one label at a time and
/// stops at the first zone that exists. Going most-specific-first is
/// what makes a delegated subzone win over its parent: if someone runs
/// `net.example.com` as its own zone, that is the one their records
/// belong in.
///
/// The walk stops at two labels. It does not know where the public
/// suffix is — `example.co.uk` and `example.com` look alike from here —
/// but it does not need to: a match happens before the walk reaches a
/// suffix nobody can own.
///
/// **Every suffix is walked; the list is not truncated.** Cutting it
/// short would cut the *general* end, and the registrable name at that
/// end is the candidate most likely to be the answer — a bound meant as
/// insurance would drop the zone it was insuring. The cost of walking a
/// long name is a handful of extra requests on a path that was going to
/// fail anyway, and DNS caps a name at 127 labels regardless.
pub fn zone_candidates(domain: &str) -> Result<Vec<String>, CfError> {
    let domain = dns_name(domain)?;
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|label| label.is_empty()) {
        return Err(CfError::NotADomain(domain));
    }

    Ok((0..=labels.len() - 2)
        .map(|start| labels[start..].join("."))
        .collect())
}

/// The path for one candidate: an exact-name query.
///
/// Exact rather than listing every zone and matching locally, because
/// a listing is paginated and a person with a page and a half of zones
/// would silently get the wrong answer. Two round trips for the usual
/// hub name is a fair price for not having that bug.
pub fn zones_query(candidate: &str) -> String {
    format!("{ZONES_PATH}?name={}", client::encode_segment(candidate))
}

/// Reads one `GET /zones?name=...` answer.
pub fn parse_zones(status: u16, body: &str) -> Result<Vec<Zone>, CfError> {
    let result = parse_result(status, body)?;
    let items = result.as_array().ok_or_else(|| CfError::ApiFailure {
        status,
        message: "the zone list is not a list".to_string(),
    })?;
    items
        .iter()
        .map(|zone| {
            Ok(Zone {
                id: string_at(zone, "id", "zone", status)?,
                name: string_at(zone, "name", "zone", status)?,
                status: string_at(zone, "status", "zone", status)?,
                name_servers: name_servers_at(zone),
            })
        })
        .collect()
}

/// A field anago actually reads, and therefore one it will not invent.
///
/// Defaulting a missing `id` to an empty string would hand the next
/// call a zone id of `""`; the failure would arrive later, somewhere
/// else, wearing a reason that has nothing to do with the real problem.
/// A response that does not have what it is documented to have is a
/// malformed response, and saying so puts the run on the manual
/// fallback path where it belongs.
fn string_at(
    value: &serde_json::Value,
    key: &str,
    what: &str,
    status: u16,
) -> Result<String, CfError> {
    match value.get(key).and_then(serde_json::Value::as_str) {
        Some(text) if !text.is_empty() => Ok(text.to_string()),
        Some(_) => Err(CfError::ApiFailure {
            status,
            message: format!("a {what} in the answer has an empty {key}"),
        }),
        None => Err(CfError::ApiFailure {
            status,
            message: format!("a {what} in the answer has no usable {key}"),
        }),
    }
}

/// Turns one candidate's answer into a decision.
///
/// `Ok(None)` means "not this one, keep walking". The two refusals are
/// states a person has to resolve:
///
/// - **more than one zone with the same name** — anago will not guess
///   which account's zone was meant;
/// - **a zone that is not active** — Cloudflare holds the records but
///   is not answering for the name, so anago would write a record that
///   changes nothing while reporting success. That is §13's worst shape
///   of failure, and it belongs to the person who has to repoint the
///   nameservers.
pub fn pick(zones: Vec<Zone>, candidate: &str) -> Result<Option<Zone>, CfError> {
    let mut matching: Vec<Zone> = zones
        .into_iter()
        .filter(|zone| zone.name.eq_ignore_ascii_case(candidate))
        .collect();
    if matching.len() > 1 {
        return Err(CfError::ZoneAmbiguous {
            name: candidate.to_string(),
            count: matching.len(),
        });
    }
    let Some(zone) = matching.pop() else {
        return Ok(None);
    };
    if zone.status != "active" {
        return Err(CfError::ZoneNotActive {
            name: zone.name,
            status: zone.status,
        });
    }
    Ok(Some(zone))
}

/// Finds the zone a domain lives in.
///
/// **Human verification needed**: this call needs a real account.
pub fn find_zone(token: &Token, domain: &str) -> Result<Zone, CfError> {
    let candidates = zone_candidates(domain)?;
    let authorization = token.header().map_err(CfError::Client)?;
    for candidate in &candidates {
        let response = client::send(&Request {
            method: Method::Get,
            host: API_HOST,
            port: 443,
            path: &zones_query(candidate),
            body: None,
            authorization: Some(&authorization),
        })
        .map_err(CfError::Client)?;
        if let Some(zone) = pick(parse_zones(response.status, &response.body)?, candidate)? {
            return Ok(zone);
        }
    }
    Err(CfError::ZoneNotFound {
        domain: domain.to_string(),
        tried: candidates,
    })
}

// ------------------------------------------------------- A record

/// Cloudflare's automatic TTL. `1` is how the API spells "let
/// Cloudflare decide", which for a DNS-only record is five minutes —
/// short enough to repoint a hub that moved, and not a number anago has
/// any business pinning on someone else's zone.
pub const TTL_AUTOMATIC: i64 = 1;

/// How many records one listing page holds.
pub const PER_PAGE: usize = 100;

/// A zone's records.
pub fn records_path(zone_id: &str) -> String {
    format!(
        "{ZONES_PATH}/{}/dns_records",
        client::encode_segment(zone_id)
    )
}

/// One record within a zone.
pub fn record_path(zone_id: &str, record_id: &str) -> String {
    format!(
        "{}/{}",
        records_path(zone_id),
        client::encode_segment(record_id)
    )
}

/// Every record at one name.
///
/// The list is asked for **by name and not by type**: a CNAME in the
/// way and a cached id that changed type are both things the judgement
/// reports rather than trips over (`anago_core::dns::decide`), and
/// filtering to `type=A` at the API would hide exactly those.
///
/// The filter is spelled `name.exact`, which is how the current List
/// DNS Records API models it — `name` is an object there, with
/// `exact`, `contains`, `startswith`, and `endswith` under it. A bare
/// `name=` is the older spelling, and an unrecognised filter that gets
/// *ignored* rather than refused is the bad case: the answer becomes
/// the zone's whole first page, which in a zone of any size is a full
/// page, and [`parse_records`] refuses to judge from that. A name with
/// one record would take the manual path for no reason.
pub fn records_query(zone_id: &str, name: &str) -> String {
    format!(
        "{}?name.exact={}&per_page={PER_PAGE}",
        records_path(zone_id),
        client::encode_segment(name)
    )
}

/// Reads a record listing into the shape the judgement takes.
///
/// `name` is filtered on again here, locally. Cloudflare's `name=`
/// filter is an exact match, but the difference between an exact filter
/// and a prefix or substring one is the difference between "the record
/// for this hub" and "every record whose name contains it", and the
/// second would let `old.net.example.com` be counted as a second A
/// record at `net.example.com` — ambiguity where there is none. Which
/// records are ours is not a thing to take on trust from a query
/// parameter.
///
/// A full page is refused rather than judged: the page after it could
/// hold the second A record that makes this name ambiguous (§9.1), and
/// deciding from a truncated list is how a round-robin survives a run
/// that reported success.
pub fn parse_records(status: u16, body: &str, name: &str) -> Result<Vec<Record>, CfError> {
    let result = parse_result(status, body)?;
    let items = result.as_array().ok_or_else(|| CfError::ApiFailure {
        status,
        message: "the record list is not a list".to_string(),
    })?;
    if items.len() >= PER_PAGE {
        return Err(CfError::ApiFailure {
            status,
            message: format!(
                "{name} has at least {PER_PAGE} records, more than one page — \
                 anago will not judge what to do here from a partial list"
            ),
        });
    }

    let wanted = fold_name(name);
    let mut records = Vec::new();
    for item in items {
        if fold_name(&string_at(item, "name", "record", status)?) != wanted {
            continue;
        }
        let kind = string_at(item, "type", "record", status)?;
        records.push(Record {
            id: string_at(item, "id", "record", status)?,
            content: string_at(item, "content", "record", status)?,
            proxied: proxied_at(item, &kind, status)?,
            comment: comment_at(item),
            kind,
        });
    }
    Ok(records)
}

/// Reads the single record a create or an update answers with.
pub fn parse_record(status: u16, body: &str) -> Result<Record, CfError> {
    let result = parse_result(status, body)?;
    let kind = string_at(&result, "type", "record", status)?;
    Ok(Record {
        id: string_at(&result, "id", "record", status)?,
        content: string_at(&result, "content", "record", status)?,
        proxied: proxied_at(&result, &kind, status)?,
        comment: comment_at(&result),
        kind,
    })
}

/// The zone's nameservers, when the answer names them.
///
/// Missing is not an error: a zone that Cloudflare has not taken over
/// yet has none, and that case is already refused for being inactive.
/// What is here only decides whether the DNS-01 wait can see anything.
fn name_servers_at(zone: &serde_json::Value) -> Vec<String> {
    zone.get("name_servers")
        .and_then(serde_json::Value::as_array)
        .map(|servers| {
            servers
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// A record's comment, if it has a usable one.
///
/// Absent, `null`, and empty are one thing here — no marker — because
/// what the caller asks is "did anago write this?", and all three
/// answer no.
fn comment_at(record: &serde_json::Value) -> Option<String> {
    record
        .get("comment")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|comment| !comment.is_empty())
        .map(str::to_string)
}

/// The one spelling of a DNS name anago sends and compares.
///
/// Case and a trailing root dot are noise — `NET.Example.com.` and
/// `net.example.com` are one name — so both are folded away.
///
/// **A non-ASCII name is refused, not converted.** Cloudflare takes and
/// returns complete record names in Punycode, so an internationalized
/// name sent as UTF-8 goes wrong twice: the write can be rejected, and
/// a record that already exists comes back as `xn--…`, fails the local
/// name match, and is judged absent — a create beside a record that was
/// already there, which is the round-robin §9.1 refuses.
///
/// Converting it here is not the fix. IDNA is mapping, normalization,
/// and bidi rules, not just Punycode, and anago hand-rolling a subtly
/// wrong version of it would point the hub's record at a name nobody
/// types. The `xn--` form is exact, it is what Cloudflare's dashboard
/// shows beside the name, and it is what TLS and the `Host` header want
/// as well — so anago asks for it and uses it everywhere unchanged.
fn dns_name(name: &str) -> Result<String, CfError> {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() {
        return Err(CfError::NotADomain(name.to_string()));
    }
    if !name.is_ascii() {
        return Err(CfError::NotAscii(name.to_string()));
    }
    Ok(name.to_ascii_lowercase())
}

/// The same folding for a name Cloudflare handed back, where there is
/// nothing to refuse — a name in the answer is already Punycode, and a
/// name anago cannot fold is simply not the one it asked about.
fn fold_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Whether the orange cloud can be on for this type at all.
fn proxiable(kind: &str) -> bool {
    ["A", "AAAA", "CNAME"]
        .iter()
        .any(|proxiable| kind.eq_ignore_ascii_case(proxiable))
}

/// Reads `proxied`, and **will not default it to `false`**.
///
/// `false` is exactly the answer that lets a run carry on, so inventing
/// it on a record anago could not read properly is how §13's silent
/// failure happens: the certificate issues, the output is green, and
/// the tunnel is dead behind the proxy. A record that should carry the
/// flag and does not is a malformed answer, and saying so sends the run
/// to the manual path with the reason attached.
///
/// Types that cannot be proxied — TXT, MX — legitimately come back
/// without the field, and the judgement never looks at their flag.
fn proxied_at(record: &serde_json::Value, kind: &str, status: u16) -> Result<bool, CfError> {
    match record.get("proxied") {
        Some(serde_json::Value::Bool(on)) => Ok(*on),
        Some(_) => Err(CfError::ApiFailure {
            status,
            message: format!("a {kind} record in the answer has a proxied flag that is not true or false"),
        }),
        None if proxiable(kind) => Err(CfError::ApiFailure {
            status,
            message: format!("a {kind} record in the answer has no proxied flag, so anago cannot tell whether it is behind the proxy"),
        }),
        None => Ok(false),
    }
}

/// The body that creates the hub's A record.
///
/// `name` is the folded, ASCII form — see [`dns_name`]. Cloudflare
/// stores what it is given, so a name spelled differently here from the
/// one the listing was matched against would create a second record
/// rather than the one that was missing.
///
/// `proxied: false` is stated rather than left out: a zone can be set
/// to proxy new records by default, and inheriting that would be §13's
/// trap arriving through the automation that was meant to avoid it.
pub fn create_body(name: &str, desired: Ipv4Addr) -> String {
    serde_json::json!({
        "type": "A",
        "name": name,
        "content": desired.to_string(),
        "ttl": TTL_AUTOMATIC,
        "proxied": false,
    })
    .to_string()
}

/// The body that points an existing record at the hub.
///
/// **Only `content`.** The record may be one a person made by hand and
/// anago is adopting, carrying their TTL and comment; sending a whole
/// record would reset those to anago's defaults on the way past. This
/// goes out as `PATCH` for the same reason (see [`Method::Patch`]).
///
/// Note what is *not* here: `proxied`. Turning the proxy off is not
/// anago's call either — a proxied record is refused before this point,
/// never quietly un-proxied (§13).
pub fn update_body(desired: Ipv4Addr) -> String {
    serde_json::json!({ "content": desired.to_string() }).to_string()
}

/// What happened to the hub's A record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    Created {
        record_id: String,
    },
    Updated {
        record_id: String,
        /// The record was already there and anago did not make it —
        /// somebody followed M0's manual instructions. Said out loud
        /// because anago has just edited something it did not write.
        adopted: bool,
    },
    Unchanged {
        record_id: String,
    },
}

impl Applied {
    /// The id to cache (§9.1).
    pub fn record_id(&self) -> &str {
        match self {
            Applied::Created { record_id }
            | Applied::Updated { record_id, .. }
            | Applied::Unchanged { record_id } => record_id,
        }
    }
}

impl fmt::Display for Applied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Applied::Created { record_id } => write!(
                f,
                "created the A record, DNS only — no orange cloud ({record_id})"
            ),
            Applied::Updated {
                record_id,
                adopted: false,
            } => write!(f, "pointed the A record at this server ({record_id})"),
            Applied::Updated {
                record_id,
                adopted: true,
            } => write!(
                f,
                "took over the A record that was already at this name and pointed it \
                 at this server ({record_id}) — anago did not create that record"
            ),
            Applied::Unchanged { record_id } => write!(
                f,
                "the A record already points at this server; left alone ({record_id})"
            ),
        }
    }
}

/// A record that was written, and anything worth saying about it.
pub struct Written {
    pub applied: Applied,
    /// Printed beside the success line, not instead of it: the record
    /// is written, and something about it still needs a person.
    pub warning: Option<String>,
}

/// Whether a record Cloudflare just handed back needs saying something
/// about.
///
/// Both checks are for the same failure: anago asked for one thing, the
/// answer says another, and every later step still succeeds. A proxied
/// record still passes HTTP-01 and still gets a certificate — only the
/// tunnel is dead (§13) — so the one moment this is catchable is here,
/// while the answer is in hand.
pub fn record_warning(record: &Record, desired: Ipv4Addr) -> Option<String> {
    if record.proxied {
        return Some(format!(
            "warning: Cloudflare says that record is proxied (orange cloud) although \
             anago asked for DNS only. WireGuard's UDP port is not forwarded through \
             the proxy, so HTTPS will work and the tunnel will not. Set the record to \
             DNS only in the dashboard ({}).",
            record.id
        ));
    }
    if record.content.trim().parse::<Ipv4Addr>() != Ok(desired) {
        return Some(format!(
            "warning: the record now reads {:?}, not {desired}. Check it in the \
             dashboard before relying on the name ({}).",
            record.content, record.id
        ));
    }
    None
}

/// Lists the name, decides, and does it (§9.1).
///
/// The listing happens **every time, cache or no cache**: the cached id
/// says which record is ours, not that the record is still unproxied or
/// still correct. Skipping the read to save a round trip is how a
/// proxied record gets reported as fine.
///
/// A refusal is an error rather than a warning because the states it
/// covers — proxied, a CNAME in the way, several A records — are all
/// ones where carrying on would report success over a network that does
/// not work.
///
/// **Human verification needed**: these calls need a real Cloudflare
/// account and a real zone.
pub fn apply_record(
    token: &Token,
    zone_id: &str,
    name: &str,
    desired: Ipv4Addr,
    cached_id: Option<&str>,
) -> Result<Written, CfError> {
    // Folded once, then used for the query, the local match, and the
    // record anago creates — one spelling, so "not found" cannot mean
    // "spelled differently".
    let name = dns_name(name)?;
    let authorization = token.header().map_err(CfError::Client)?;
    let listed = get(&authorization, &records_query(zone_id, &name))?;
    let records = parse_records(listed.status, &listed.body, &name)?;

    match dns::decide(&records, desired, cached_id) {
        Upsert::Refuse(refusal) => Err(CfError::RecordRefused(refusal)),
        Upsert::Unchanged { record_id } => Ok(Written {
            applied: Applied::Unchanged { record_id },
            warning: None,
        }),
        Upsert::Create => {
            let written = write_record(
                &authorization,
                Method::Post,
                &records_path(zone_id),
                &create_body(&name, desired),
            )?;
            Ok(Written {
                warning: record_warning(&written, desired),
                applied: Applied::Created {
                    record_id: written.id,
                },
            })
        }
        Upsert::Update { record_id, adopted } => {
            let written = write_record(
                &authorization,
                Method::Patch,
                &record_path(zone_id, &record_id),
                &update_body(desired),
            )?;
            Ok(Written {
                warning: record_warning(&written, desired),
                applied: Applied::Updated {
                    record_id: written.id,
                    adopted,
                },
            })
        }
    }
}

/// One write, whichever way round it is.
///
/// This is where a read-only token finally fails, as a 403 — verify
/// says `active` and nothing about permissions (§7).
fn write_record(
    authorization: &HeaderValue,
    method: Method,
    path: &str,
    body: &str,
) -> Result<Record, CfError> {
    let response = client::send(&Request {
        method,
        host: API_HOST,
        port: 443,
        path,
        body: Some(Body::json(body)),
        authorization: Some(authorization),
    })
    .map_err(CfError::Client)?;
    parse_record(response.status, &response.body)
}

// ------------------------------------------- DNS-01 challenge record

/// TTL for a challenge record. Sixty seconds, because the record is
/// created, checked, and deleted within a few minutes and a long TTL
/// only means a resolver holds an answer that no longer exists.
pub const CHALLENGE_TTL: i64 = 60;

/// The name a DNS-01 challenge goes on, in the spelling anago sends.
pub fn challenge_name(domain: &str) -> Result<String, CfError> {
    dns_name(&acme::dns01_record_name(&dns_name(domain)?))
}

/// What anago writes at the start of every challenge record's comment.
///
/// The marker is what makes cleanup **specific**. DNS-01 puts several
/// TXT values on one name legitimately — a wildcard order and a plain
/// one validating at the same time is the documented case — so a record
/// at `_acme-challenge.<domain>` is not anago's by virtue of being
/// there, and deleting it on that basis would break somebody else's
/// issuance mid-flight.
///
/// A comment rather than a tag: record comments are available on every
/// Cloudflare plan, and tags are not.
pub const CHALLENGE_MARKER: &str = "anago DNS-01 challenge";

/// How long a challenge record can be in use before anago is willing to
/// call one **its own** litter.
///
/// The marker alone cannot say that. It proves anago wrote the record,
/// not that the run which wrote it has finished with it — and two
/// anago runs on one zone is not exotic: the renewal timer firing while
/// somebody types `server renew` is exactly it. Sweeping on the marker
/// alone means the second run deletes the first run's live challenge
/// and fails its issuance.
///
/// So a record is swept only once it is older than any run could still
/// be using it. Ten minutes is generous for a wait capped at a minute
/// plus a validation measured in seconds, and short enough that litter
/// does not outlive the next renewal.
pub const CHALLENGE_LIFETIME_SECS: i64 = 10 * 60;

/// The comment for a record published now.
///
/// The time is in the comment because it is the one place anago can
/// keep it and read it back without a date parser: Cloudflare's own
/// `created_on` is RFC 3339, and anago has no library that reads one
/// (§10.2). The process id is there for a person reading the dashboard
/// and wondering what left it; nothing reads it back.
pub fn challenge_comment(now: i64) -> String {
    format!("{CHALLENGE_MARKER} at={now} pid={}", std::process::id())
}

/// When anago wrote a record, from its comment.
///
/// `None` means "cannot tell" — a comment anago did not write, or one
/// somebody has edited. Cleanup treats that as a record to leave alone,
/// the same way it treats a stranger's.
pub fn written_at(comment: &str) -> Option<i64> {
    if !comment.starts_with(CHALLENGE_MARKER) {
        return None;
    }
    comment
        .split_whitespace()
        .find_map(|field| field.strip_prefix("at="))
        .and_then(|stamp| stamp.parse().ok())
}

/// The body that publishes a challenge.
pub fn txt_body(name: &str, value: &str, now: i64) -> String {
    serde_json::json!({
        "type": "TXT",
        "name": name,
        "content": value,
        "ttl": CHALLENGE_TTL,
        "comment": challenge_comment(now),
    })
    .to_string()
}

/// The records a sweep removes: TXT records **anago wrote**.
///
/// Not "everything at the name". Several TXT values on one
/// `_acme-challenge` name is a documented, ordinary state — Let's
/// Encrypt names validating a wildcard and a non-wildcard order at the
/// same time — so another client's challenge is not a conflict to
/// resolve, it is somebody's certificate mid-issue. Deleting it would
/// break their validation and anago would never know it had.
///
/// What anago does have to remove is its own litter: a run that died
/// between creating a record and deleting it leaves one behind, nobody
/// else is coming for it, and the id was deliberately not kept in the
/// state file so that the next run finds these by looking rather than
/// by inheriting a ghost (§9.1). Left alone they accumulate, and
/// [Let's Encrypt rejects the answer once it grows too
/// big](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge)
/// — so the cleanup matters, and so does its aim.
///
/// Two things have to be true, and the second is the one that is easy
/// to miss:
///
/// 1. **anago wrote it** — [`CHALLENGE_MARKER`]. A record with no
///    comment, or somebody else's, is left where it is: leaving one
///    costs a stale record that does not stop this validation, and
///    removing one costs a stranger their certificate.
/// 2. **No anago run can still be using it** —
///    [`CHALLENGE_LIFETIME_SECS`]. The marker says who wrote the
///    record, not whether they are done with it, and two anago runs on
///    one zone is an ordinary Tuesday: the renewal timer fires while
///    somebody is typing `server renew`. Sweeping on the marker alone,
///    the second run deletes the first's live challenge and fails its
///    issuance — a stranger's certificate broken by the rule that was
///    written to protect it, except the stranger is us.
///
/// A record whose comment carries no readable time is left alone. Not
/// being able to tell how old something is, is not a reason to delete
/// it.
pub fn stale_challenges(records: &[Record], now: i64) -> Vec<&Record> {
    records
        .iter()
        .filter(|record| is_txt(record) && past_lifetime(record, now))
        .collect()
}

fn past_lifetime(record: &Record, now: i64) -> bool {
    record
        .comment
        .as_deref()
        .and_then(written_at)
        .is_some_and(|written| now.saturating_sub(written) > CHALLENGE_LIFETIME_SECS)
}

fn is_txt(record: &Record) -> bool {
    record.kind.eq_ignore_ascii_case("TXT")
}

/// A published DNS-01 challenge record, which removes itself.
///
/// The point of the type is the [`Drop`]: between publishing a record
/// and validating a certificate there are a dozen ways out — an ACME
/// error, a timeout, `?` three calls down, a panic — and every one of
/// them must still take the record with it. A record left behind is a
/// TXT entry on a person's domain that nothing will ever come back for.
///
/// [`Challenge::remove`] is the ordinary way out, and it reports what
/// went wrong. `Drop` is the one that cannot report anything, so it
/// says its piece on stderr and carries on: by then the run is already
/// failing, and a cleanup error is not the news.
pub struct Challenge<'a> {
    token: &'a Token,
    zone_id: String,
    name: String,
    /// `None` once the record is gone — the disarmed state, so `Drop`
    /// after an explicit [`Challenge::remove`] does nothing.
    record_id: Option<String>,
}

impl<'a> Challenge<'a> {
    /// Sweeps anago's own leftovers at the name, then publishes (§9.1).
    ///
    /// The sweep comes first on purpose, and it is deliberately narrow:
    /// a leftover record does not stop this validation — an ACME server
    /// accepts the name if *any* TXT on it matches — so the reason to
    /// remove one is that nothing else ever will. That reason applies
    /// only to records anago wrote **and** is long since done with; a
    /// challenge another run published a minute ago is neither. See
    /// [`stale_challenges`].
    ///
    /// Two runs of anago on one zone still want serializing at a higher
    /// level — the issuance slice takes a lock, so the renewal timer
    /// and a hand-typed `server renew` do not both order certificates
    /// (§9.1). The rule here is what keeps the *records* safe when they
    /// overlap anyway, on this host or another.
    ///
    /// **Human verification needed**: these calls need a real zone.
    pub fn publish(
        token: &'a Token,
        zone_id: &str,
        domain: &str,
        value: &str,
        now: i64,
    ) -> Result<Challenge<'a>, CfError> {
        let name = challenge_name(domain)?;
        let authorization = token.header().map_err(CfError::Client)?;

        let listed = get(&authorization, &records_query(zone_id, &name))?;
        let records = parse_records(listed.status, &listed.body, &name)?;
        for stale in stale_challenges(&records, now) {
            delete_record(&authorization, zone_id, &stale.id)?;
        }

        let created = write_record(
            &authorization,
            Method::Post,
            &records_path(zone_id),
            &txt_body(&name, value, now),
        )?;
        Ok(Challenge {
            token,
            zone_id: zone_id.to_string(),
            name,
            record_id: Some(created.id),
        })
    }

    /// `_acme-challenge.<domain>`, as published.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Removes the record and says so if it could not.
    ///
    /// **The guard is disarmed only by a delete that worked.** Taking
    /// the id first and then failing would be the worst of both ways
    /// out: the record is still there, `Drop` has nothing left to try,
    /// and the warning naming the record to delete by hand never
    /// prints. A failure here leaves the challenge armed, so the `Drop`
    /// at the end of this call tries once more and, if that fails too,
    /// says which record was left behind.
    ///
    /// **Human verification needed**: needs a real zone.
    pub fn remove(mut self) -> Result<(), CfError> {
        let Some(record_id) = self.record_id.clone() else {
            return Ok(());
        };
        let removed = self
            .token
            .header()
            .map_err(CfError::Client)
            .and_then(|authorization| delete_record(&authorization, &self.zone_id, &record_id));
        self.settle(removed)
    }

    /// Disarms the guard if — and only if — the record is gone.
    ///
    /// Split out from [`Challenge::remove`] so that the rule can be
    /// tested without a network: which of the two states this leaves
    /// behind is the whole contract.
    fn settle(&mut self, removed: Result<(), CfError>) -> Result<(), CfError> {
        if removed.is_ok() {
            self.record_id = None;
        }
        removed
    }
}

impl Drop for Challenge<'_> {
    fn drop(&mut self) {
        let Some(record_id) = self.record_id.take() else {
            return;
        };
        let removed = self
            .token
            .header()
            .map_err(CfError::Client)
            .and_then(|authorization| delete_record(&authorization, &self.zone_id, &record_id));
        if let Err(e) = removed {
            eprintln!("anago: warning: the DNS-01 challenge record could not be removed: {e}");
            eprintln!(
                "       delete the TXT record {record_id} at {} in the Cloudflare dashboard; \
                 nothing needs it after validation",
                self.name
            );
        }
    }
}

impl fmt::Debug for Challenge<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Challenge")
            .field("name", &self.name)
            .field("record_id", &self.record_id)
            .finish()
    }
}

/// Deletes one record, and treats "it is not there" as done.
///
/// A cleanup path that fails because the thing it wanted gone is
/// already gone is a cleanup path people learn to ignore.
fn delete_record(
    authorization: &HeaderValue,
    zone_id: &str,
    record_id: &str,
) -> Result<(), CfError> {
    let response = client::send(&Request {
        method: Method::Delete,
        host: API_HOST,
        port: 443,
        path: &record_path(zone_id, record_id),
        body: None,
        authorization: Some(authorization),
    })
    .map_err(CfError::Client)?;
    parse_delete(response.status, &response.body)
}

/// Reads a delete answer. 404 is success — see [`delete_record`].
pub fn parse_delete(status: u16, body: &str) -> Result<(), CfError> {
    if status == 404 {
        return Ok(());
    }
    parse_result(status, body)?;
    Ok(())
}

/// One GET, with the two error conversions every caller here repeats.
fn get(authorization: &HeaderValue, path: &str) -> Result<client::Response, CfError> {
    client::send(&Request {
        method: Method::Get,
        host: API_HOST,
        port: 443,
        path,
        body: None,
        authorization: Some(authorization),
    })
    .map_err(CfError::Client)
}

/// The line that explains why the manual DNS step is still there (§6.1).
///
/// Failing to reach Cloudflare is **not** a reason to stop setting up a
/// hub: everything else — the certificate over HTTP-01, wg, the unit —
/// works without it, and the record is a thing a person can add in a
/// browser in ten seconds. So the automation steps aside and says why,
/// and M0's instructions carry on underneath.
///
/// A DNS-01 challenge is the one place this does not apply: there, the
/// token is not a convenience but the whole mechanism, and its caller
/// treats the same error as fatal.
pub fn fallback_notice(error: &CfError) -> String {
    format!(
        "Cloudflare could not set the DNS record: {error}\n\
         Nothing else is affected — add the record below by hand and carry on.\n"
    )
}

/// What can go wrong before anago has a usable token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfError {
    /// `--cf-token` and `--cf-token-file` together.
    BothFlags,
    Empty(Source),
    Malformed(Source),
    Read {
        path: PathBuf,
        source: String,
    },
    /// Cloudflare refused the credential outright — 401.
    Rejected(String),
    /// The credential was accepted but is not allowed to do this — 403.
    /// The shape a DNS **Read** token takes when anago tries to write.
    Forbidden(String),
    /// The token exists but is not usable — expired, or disabled.
    NotActive(String),
    /// `success: false`, or a shape that is not the documented one.
    ApiFailure {
        status: u16,
        message: String,
    },
    /// Not a name a zone could be found for.
    NotADomain(String),
    /// An internationalized name that has not been written in its
    /// `xn--` form. Refused rather than converted — see [`dns_name`].
    NotAscii(String),
    /// No zone at any of the names walked.
    ZoneNotFound {
        domain: String,
        tried: Vec<String>,
    },
    /// The same zone name in more than one account the token can see.
    ZoneAmbiguous {
        name: String,
        count: usize,
    },
    /// Cloudflare holds the zone but is not answering for it.
    ZoneNotActive {
        name: String,
        status: String,
    },
    /// The name is in a state anago will not edit its way out of —
    /// proxied, a CNAME in the way, several A records (§9.1, §13).
    RecordRefused(Refusal),
    Undecodable(String),
    Client(ClientError),
}

/// What a scoped token has to be able to do (§7). Repeated in the
/// messages below because "permission denied" without it sends a person
/// to the dashboard with nothing to look for.
///
/// **Both permissions, and each for its own step.** DNS → Edit writes
/// the record; Zone → Read is what lets anago find the zone the domain
/// lives in, which happens first. A token with only the write
/// permission verifies as active and then fails at the lookup — and if
/// the message named only DNS → Edit, the person would go add a
/// permission they already have and hit the same wall again.
const SCOPE_HINT: &str = "it must be an API token (not the Global API Key) with both \
                          Zone → DNS → Edit (to write the record) and Zone → Zone → Read \
                          (to find the zone), on the zone that holds this domain";

impl fmt::Display for CfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CfError::BothFlags => f.write_str(
                "--cf-token and --cf-token-file were both given; pass one. \
                 The file is the safer of the two — a token in argv is visible \
                 to `ps` and lands in shell history",
            ),
            CfError::Empty(source) => write!(f, "the Cloudflare token from {source} is empty"),
            CfError::Malformed(source) => write!(
                f,
                "the Cloudflare token from {source} has whitespace inside it, \
                 so it is probably a partial copy"
            ),
            CfError::Read { path, source } => write!(
                f,
                "could not read the Cloudflare token from {}: {source}",
                path.display()
            ),
            CfError::Rejected(detail) => write!(
                f,
                "Cloudflare would not accept the token: {detail}. Check it was copied \
                 whole, and that {SCOPE_HINT}"
            ),
            CfError::Forbidden(detail) => write!(
                f,
                "Cloudflare accepted the token but will not let it do this: {detail}. \
                 A token that only *reads* DNS passes every check until this point — \
                 {SCOPE_HINT}"
            ),
            CfError::NotActive(status) if status == "expired" => write!(
                f,
                "that Cloudflare token has expired. Create a new one — {SCOPE_HINT}"
            ),
            CfError::NotActive(status) if status == "disabled" => f.write_str(
                "that Cloudflare token is disabled. Re-enable it in the dashboard, \
                 or create a new one",
            ),
            CfError::NotActive(status) => write!(
                f,
                "that Cloudflare token is not active (status {status:?}); \
                 check it in the dashboard"
            ),
            CfError::ApiFailure { status, message } => {
                write!(f, "Cloudflare answered {status}: {message}")
            }
            CfError::NotADomain(domain) => write!(
                f,
                "{domain:?} is not a domain a zone can be found for — it needs at least \
                 a name and a suffix, like example.com"
            ),
            CfError::NotAscii(name) => write!(
                f,
                "{name:?} is an internationalized name, and Cloudflare, TLS, and DNS all \
                 want its Punycode spelling (xn--...). anago will not convert it for you: \
                 doing that correctly is more than Punycode, and getting it subtly wrong \
                 would point this record at a name nobody types. Cloudflare's dashboard \
                 shows the xn-- form beside the name — use that spelling"
            ),
            CfError::ZoneNotFound { domain, tried } => write!(
                f,
                "no Cloudflare zone holds {domain} (tried {}). Either the domain is not \
                 on this Cloudflare account, or the token is scoped to a different zone",
                tried.join(", ")
            ),
            CfError::ZoneAmbiguous { name, count } => write!(
                f,
                "{count} zones are named {name} on the accounts this token can see; \
                 anago will not guess which one you meant. Scope the token to one zone"
            ),
            CfError::ZoneNotActive { name, status } => write!(
                f,
                "the zone {name} is {status:?}, not active — Cloudflare holds its records \
                 but is not answering for the name, so a record added here would change \
                 nothing. Point the domain's nameservers at Cloudflare first"
            ),
            CfError::RecordRefused(refusal) => write!(
                f,
                "anago did not change the DNS record for this name: {refusal}"
            ),
            CfError::Undecodable(detail) => {
                write!(f, "Cloudflare's answer could not be read: {detail}")
            }
            CfError::Client(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CfError {}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> TempDir {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("anago-cfapi-{}-{unique}", std::process::id()));
            std::fs::create_dir_all(&path).expect("temp dir");
            TempDir { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn file(path: &str) -> Source {
        Source::File(PathBuf::from(path))
    }

    // ------------------------------------------------- precedence

    #[test]
    fn the_file_flag_wins_over_everything() {
        assert_eq!(
            choose(Some("/root/cf-token"), None, Some("env-token")),
            Ok(Some(file("/root/cf-token")))
        );
    }

    #[test]
    fn the_value_flag_wins_over_the_environment() {
        assert_eq!(
            choose(None, Some("flag-token"), Some("env-token")),
            Ok(Some(Source::Flag))
        );
    }

    #[test]
    fn the_environment_is_the_last_resort() {
        assert_eq!(choose(None, None, Some("env-token")), Ok(Some(Source::Env)));
    }

    #[test]
    fn no_token_anywhere_is_not_an_error() {
        // It is the ordinary M0 path: anago prints the manual DNS
        // instructions and carries on (§6.1).
        assert_eq!(choose(None, None, None), Ok(None));
    }

    #[test]
    fn an_empty_variable_counts_as_unset() {
        // Half the shells spell "unset" as "", and treating that as a
        // token fails later with a puzzling 401.
        assert_eq!(choose(None, None, Some("")), Ok(None));
        assert_eq!(choose(None, None, Some("   ")), Ok(None));
    }

    #[test]
    fn both_flags_together_are_refused_rather_than_ranked() {
        // Two different instructions; picking one quietly is how the
        // wrong credential gets used.
        assert_eq!(
            choose(Some("/root/cf-token"), Some("flag-token"), None),
            Err(CfError::BothFlags)
        );
        let message = CfError::BothFlags.to_string();
        assert!(message.contains("pass one"), "{message}");
        assert!(message.contains("`ps`"), "{message}");
    }

    #[test]
    fn choosing_never_carries_the_secret() {
        // The decision is made and tested without a token near it; the
        // value is fetched afterwards by `load`.
        let chosen = choose(None, Some("flag-token"), None).unwrap().unwrap();
        assert_eq!(chosen, Source::Flag);
        assert!(!format!("{chosen:?}").contains("flag-token"));
    }

    // ------------------------------------------------ token values

    #[test]
    fn a_trailing_newline_from_a_file_is_trimmed_not_refused() {
        // A token file ends with a newline more often than not.
        let token = Token::parse("cf-api-token\n", file("/root/cf-token")).unwrap();
        assert_eq!(token.expose(), "cf-api-token");
        assert_eq!(
            token.header().unwrap().as_str(),
            "Bearer cf-api-token",
            "the trimmed value is what goes on the wire"
        );
    }

    #[test]
    fn whitespace_inside_a_token_is_a_partial_copy() {
        // Sending it produces a 401 that reads like a permissions
        // problem, which is the wrong thing to go looking at.
        let error = Token::parse("cf-api tok", Source::Flag).unwrap_err();
        assert_eq!(error, CfError::Malformed(Source::Flag));
        assert!(error.to_string().contains("partial copy"));
    }

    #[test]
    fn an_empty_token_names_where_it_came_from() {
        assert_eq!(
            Token::parse("  \n", Source::Env).unwrap_err(),
            CfError::Empty(Source::Env)
        );
        assert!(Token::parse("", Source::Env)
            .unwrap_err()
            .to_string()
            .contains(TOKEN_ENV));
    }

    #[test]
    fn a_token_never_reaches_a_debug_line() {
        let token = Token::parse("cf-api-token", file("/root/cf-token")).unwrap();
        let printed = format!("{token:?}");
        assert!(!printed.contains("cf-api-token"), "{printed}");
        // Where it came from is still useful and not a secret.
        assert!(printed.contains("/root/cf-token"), "{printed}");
    }

    #[test]
    fn loading_reads_the_flag_and_the_environment_without_touching_the_disk() {
        let loaded = load(Source::Flag, Some("flag-token"), None).unwrap();
        assert_eq!(loaded.token.expose(), "flag-token");
        // Nothing to warn about: a flag has no mode.
        assert_eq!(loaded.warning, None);
        let loaded = load(Source::Env, None, Some("env-token\n")).unwrap();
        assert_eq!(loaded.token.expose(), "env-token");
        assert_eq!(loaded.warning, None);
    }

    #[test]
    fn loading_a_file_carries_its_permission_warning_along() {
        // The check has to ride with the load rather than be a call a
        // caller could forget to make.
        let loose = from_file(
            "cf-api-token\n",
            Path::new("/root/cf-token"),
            Some(0o100644),
        )
        .unwrap();
        assert_eq!(loose.token.expose(), "cf-api-token");
        let warning = loose.warning.expect("a 0644 token file is worth a word");
        assert!(warning.contains("0644"), "{warning}");
        assert!(warning.contains("chmod 600"), "{warning}");

        let tight = from_file(
            "cf-api-token\n",
            Path::new("/root/cf-token"),
            Some(0o100600),
        )
        .unwrap();
        assert_eq!(tight.warning, None);
    }

    #[test]
    fn a_real_world_readable_file_is_warned_about_end_to_end() {
        // Proves the mode actually reaches the warning through `load`,
        // not just through the helper it calls.
        let dir = TempDir::new();
        let path = dir.path.join("cf-token");
        std::fs::write(&path, "cf-api-token\n").unwrap();
        set_mode(&path, 0o644);

        let loaded = load(Source::File(path.clone()), None, None).unwrap();
        assert_eq!(loaded.token.expose(), "cf-api-token");
        assert!(loaded.warning.is_some(), "0644 should be warned about");

        set_mode(&path, 0o600);
        let loaded = load(Source::File(path), None, None).unwrap();
        assert_eq!(loaded.warning, None);
    }

    #[test]
    fn a_missing_token_file_says_which_file() {
        let error = load(file("/nonexistent/cf-token"), None, None).unwrap_err();
        assert!(
            error.to_string().contains("/nonexistent/cf-token"),
            "{error}"
        );
    }

    // ------------------------------------------------ permissions

    #[test]
    fn a_world_readable_token_file_is_warned_about() {
        let warning = file_permission_warning(Path::new("/root/cf-token"), Some(0o100644)).unwrap();
        assert!(warning.contains("0644"), "{warning}");
        assert!(warning.contains("chmod 600"), "{warning}");
        // Says why it matters, which is what makes it worth printing.
        assert!(warning.contains("every record in the zone"), "{warning}");
    }

    #[test]
    fn a_private_token_file_is_not_complained_about() {
        assert_eq!(
            file_permission_warning(Path::new("/root/cf-token"), Some(0o100600)),
            None
        );
        // Nothing known about the mode is nothing to say.
        assert_eq!(
            file_permission_warning(Path::new("/root/cf-token"), None),
            None
        );
    }

    // ---------------------------------------------------- verify

    const ACTIVE: &str = r#"{
      "result": { "id": "ed17574386854bf78a67040be0a770b0", "status": "active" },
      "success": true,
      "errors": [],
      "messages": [{ "code": 10000, "message": "This API Token is valid and active" }]
    }"#;

    #[test]
    fn an_active_token_verifies() {
        let verified = parse_verify(200, ACTIVE).unwrap();
        assert_eq!(verified.id, "ed17574386854bf78a67040be0a770b0");
        assert_eq!(verified.status, "active");
    }

    #[test]
    fn fields_we_do_not_read_do_not_break_the_response() {
        // The reason §10.2 sends third-party JSON to serde_json: the
        // mini JSON in core refuses floats and would fail this whole
        // response over a field anago never looks at.
        let body = r#"{
          "result": { "id": "abc", "status": "active", "not_before": null },
          "success": true,
          "errors": [],
          "timing": { "seconds": 0.0123 },
          "messages": []
        }"#;
        assert_eq!(parse_verify(200, body).unwrap().id, "abc");
    }

    #[test]
    fn a_rejected_token_says_what_to_check() {
        let body = r#"{
          "success": false,
          "errors": [{ "code": 1000, "message": "Invalid API Token" }],
          "result": null
        }"#;
        let error = parse_verify(401, body).unwrap_err();
        assert_eq!(
            error,
            CfError::Rejected("Invalid API Token (code 1000)".to_string())
        );
        let message = error.to_string();
        assert!(message.contains("Invalid API Token"), "{message}");
        assert!(message.contains("copied whole"), "{message}");
        // "Permission denied" with nothing to look for is not guidance.
        assert!(message.contains("Zone → DNS → Edit"), "{message}");
        assert!(message.contains("Zone → Zone → Read"), "{message}");
        assert!(message.contains("not the Global API Key"), "{message}");
    }

    #[test]
    fn a_403_is_a_different_conversation_from_a_401() {
        // 401 is "not this credential"; 403 is "this credential is not
        // allowed to". They send a person to different places, so they
        // are not the same error.
        let body = r#"{
          "success": false,
          "errors": [{ "code": 9109, "message": "Unauthorized to access requested resource" }],
          "result": null
        }"#;
        let forbidden = parse_result(403, body).unwrap_err();
        assert_eq!(
            forbidden,
            CfError::Forbidden("Unauthorized to access requested resource (code 9109)".to_string())
        );
        assert!(matches!(
            parse_result(401, body).unwrap_err(),
            CfError::Rejected(_)
        ));
        assert_ne!(
            parse_result(401, body).unwrap_err(),
            parse_result(403, body).unwrap_err()
        );
    }

    #[test]
    fn a_read_only_token_is_told_it_needs_edit() {
        // The failure this exists for: Cloudflare's verify endpoint
        // reports active/disabled/expired and nothing about
        // permissions, so a DNS **Read** token verifies perfectly and
        // then 403s on the first write. That 403 is the only place the
        // mistake can be named, so it names it.
        let message =
            CfError::Forbidden("Unauthorized to access requested resource".to_string()).to_string();
        assert!(message.contains("accepted the token"), "{message}");
        assert!(message.contains("only *reads* DNS"), "{message}");
        assert!(message.contains("not the Global API Key"), "{message}");
        // Both permissions, or the person adds one they already have
        // and meets the same wall.
        assert!(message.contains("Zone → DNS → Edit"), "{message}");
        assert!(message.contains("Zone → Zone → Read"), "{message}");
    }

    #[test]
    fn the_scope_hint_says_which_permission_does_which_job() {
        // Two steps fail differently — the zone lookup comes first and
        // needs the read, the record write comes second and needs the
        // edit — so the hint has to let a person tell which one they
        // are missing.
        for message in [
            CfError::Rejected("Invalid API Token".to_string()).to_string(),
            CfError::Forbidden("Unauthorized".to_string()).to_string(),
            CfError::NotActive("expired".to_string()).to_string(),
        ] {
            if !message.contains("Zone →") {
                continue;
            }
            assert!(message.contains("to write the record"), "{message}");
            assert!(message.contains("to find the zone"), "{message}");
        }
    }

    #[test]
    fn verifying_does_not_claim_the_token_may_edit_dns() {
        // An active token verifies whatever its scope is — this pins
        // that `verify` is not doing a permission check, so nothing
        // downstream may treat it as one.
        let read_only = r#"{
          "success": true,
          "errors": [],
          "result": { "id": "read-only-token", "status": "active" }
        }"#;
        assert!(parse_verify(200, read_only).is_ok());
    }

    #[test]
    fn every_cloudflare_call_shares_one_classifier() {
        // A zone listing and a record edit answer in the same shapes,
        // so one status means one thing everywhere.
        let listing = r#"{"success":true,"errors":[],"result":[{"id":"z1"}]}"#;
        let result = parse_result(200, listing).unwrap();
        assert!(result.is_array());
        assert_eq!(result[0]["id"], "z1");
    }

    #[test]
    fn an_expired_token_is_told_apart_from_a_disabled_one() {
        // Different fixes: one is "make a new one", the other is "turn
        // it back on".
        let expired = parse_verify(
            200,
            r#"{"success":true,"errors":[],"result":{"id":"a","status":"expired"}}"#,
        )
        .unwrap_err();
        assert_eq!(expired, CfError::NotActive("expired".to_string()));
        assert!(expired.to_string().contains("has expired"));
        assert!(expired.to_string().contains("Create a new one"));

        let disabled = parse_verify(
            200,
            r#"{"success":true,"errors":[],"result":{"id":"a","status":"disabled"}}"#,
        )
        .unwrap_err();
        assert!(disabled.to_string().contains("Re-enable it"));
        assert!(!disabled.to_string().contains("expired"));
    }

    #[test]
    fn an_unknown_status_is_reported_rather_than_assumed_fine() {
        let error = parse_verify(
            200,
            r#"{"success":true,"errors":[],"result":{"id":"a","status":"pending"}}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("\"pending\""), "{error}");
    }

    #[test]
    fn success_false_is_a_failure_even_with_a_200() {
        let body = r#"{"success":false,"errors":[{"code":9109,"message":"Invalid access"}]}"#;
        assert_eq!(
            parse_verify(200, body).unwrap_err(),
            CfError::ApiFailure {
                status: 200,
                message: "Invalid access (code 9109)".to_string()
            }
        );
    }

    #[test]
    fn a_body_that_is_not_json_says_so_plainly() {
        // A captive portal or a proxy page, most likely.
        let error = parse_verify(200, "<html>nope</html>").unwrap_err();
        assert!(matches!(error, CfError::Undecodable(_)));
        assert!(error.to_string().contains("could not be read"));
    }

    // ------------------------------------------------ zone lookup

    /// One zone as `GET /zones?name=` returns it, trimmed to the parts
    /// anago reads plus a couple it does not.
    fn zone_body(name: &str, status: &str) -> String {
        format!(
            r#"{{
              "success": true,
              "errors": [],
              "messages": [],
              "result_info": {{ "page": 1, "per_page": 20, "count": 1, "total_count": 1 }},
              "result": [{{
                "id": "023e105f4ecef8ad9ca31a8372d0c353",
                "name": "{name}",
                "status": "{status}",
                "paused": false,
                "development_mode": 7200,
                "name_servers": ["tim.ns.cloudflare.com", "walt.ns.cloudflare.com"],
                "meta": {{ "step": 4, "custom_certificate_quota": 0 }}
              }}]
            }}"#
        )
    }

    const NO_ZONES: &str = r#"{
      "success": true,
      "errors": [],
      "messages": [],
      "result_info": { "page": 1, "per_page": 20, "count": 0, "total_count": 0 },
      "result": []
    }"#;

    #[test]
    fn a_subdomain_walks_up_to_its_zone() {
        // The usual hub name: the zone is the registered domain and the
        // hub is a label under it.
        assert_eq!(
            zone_candidates("net.example.com").unwrap(),
            ["net.example.com", "example.com"]
        );
    }

    #[test]
    fn the_most_specific_name_is_tried_first() {
        // Someone who runs `net.example.com` as a delegated zone of its
        // own should get that zone, not its parent.
        let candidates = zone_candidates("a.b.net.example.com").unwrap();
        assert_eq!(candidates.first().unwrap(), "a.b.net.example.com");
        assert_eq!(candidates.last().unwrap(), "example.com");
    }

    #[test]
    fn the_walk_stops_before_a_suffix_nobody_owns() {
        assert_eq!(zone_candidates("example.com").unwrap(), ["example.com"]);
        // A multi-part suffix needs no special knowledge: the match
        // happens at example.co.uk, before co.uk is ever reached.
        assert_eq!(
            zone_candidates("net.example.co.uk").unwrap(),
            ["net.example.co.uk", "example.co.uk", "co.uk"]
        );
    }

    #[test]
    fn a_deep_name_still_reaches_its_registrable_zone() {
        // The whole point of walking: the answer is almost always at
        // the *general* end, so the list may not be cut short there.
        let deep = "a.b.c.d.e.f.example.com";
        let candidates = zone_candidates(deep).unwrap();
        assert_eq!(candidates.first().unwrap(), deep);
        assert_eq!(
            candidates.last().unwrap(),
            "example.com",
            "truncating the walk would drop the zone it was meant to find"
        );
        assert_eq!(candidates.len(), 7);
        // Every step is one label shorter than the last, in order.
        for pair in candidates.windows(2) {
            assert_eq!(
                pair[1],
                pair[0].split_once('.').unwrap().1,
                "{candidates:?}"
            );
        }
    }

    #[test]
    fn a_name_that_cannot_hold_a_zone_is_refused() {
        for bad in ["", "localhost", ".", "example.", ".com", "a..com", "   "] {
            assert!(
                matches!(zone_candidates(bad), Err(CfError::NotADomain(_))),
                "{bad:?} should be refused"
            );
        }
        assert!(CfError::NotADomain("localhost".to_string())
            .to_string()
            .contains("like example.com"));
    }

    #[test]
    fn a_trailing_dot_and_upper_case_are_the_same_name() {
        assert_eq!(
            zone_candidates("NET.Example.COM.").unwrap(),
            zone_candidates("net.example.com").unwrap()
        );
    }

    #[test]
    fn the_query_asks_for_one_exact_name() {
        // Exact rather than listing every zone: a listing is paginated,
        // and a person with more than a page of zones would silently
        // get the wrong answer.
        assert_eq!(
            zones_query("example.com"),
            "/client/v4/zones?name=example.com"
        );
        // An internationalized zone is asked about in its Punycode
        // spelling, which needs no escaping — and is the only spelling
        // that gets this far (see the IDN test below).
        assert_eq!(
            zone_candidates("XN--HU5B.example.com.").unwrap()[0],
            "xn--hu5b.example.com"
        );
        assert_eq!(
            zones_query("xn--hu5b.example.com"),
            "/client/v4/zones?name=xn--hu5b.example.com"
        );
    }

    #[test]
    fn an_internationalized_name_is_refused_rather_than_converted() {
        // Cloudflare takes and returns record names in Punycode. Sent
        // as UTF-8, a name goes wrong twice: the write can be rejected,
        // and a record that already exists comes back as `xn--…`, fails
        // the local match, and is judged absent — a create beside a
        // record that was already there (§9.1).
        //
        // Converting it here would be IDNA, not Punycode: mapping,
        // normalization, bidi. A subtly wrong version of that points
        // the hub's record at a name nobody types.
        let error = zone_candidates("맥북.example.com").unwrap_err();
        assert_eq!(error, CfError::NotAscii("맥북.example.com".to_string()));
        let message = error.to_string();
        assert!(message.contains("xn--"), "{message}");
        assert!(message.contains("dashboard"), "{message}");
        assert!(dns_name("맥북.example.com").is_err());
        // The Punycode spelling of the same name is ordinary ASCII and
        // goes through untouched.
        assert_eq!(
            dns_name("XN--HU5B.example.com."),
            Ok("xn--hu5b.example.com".to_string())
        );
    }

    #[test]
    fn a_zone_is_read_out_of_the_documented_shape() {
        let zones = parse_zones(200, &zone_body("example.com", "active")).unwrap();
        assert_eq!(
            zones,
            [Zone {
                id: "023e105f4ecef8ad9ca31a8372d0c353".to_string(),
                name: "example.com".to_string(),
                status: "active".to_string(),
                name_servers: vec![
                    "tim.ns.cloudflare.com".to_string(),
                    "walt.ns.cloudflare.com".to_string(),
                ],
            }]
        );
        // The nameservers come along because a DNS-01 challenge has to
        // be watched at the servers that will actually be asked. The
        // fields around them — meta, result_info, development_mode —
        // are none of anago's business.
        assert_eq!(pick(zones, "example.com").unwrap().unwrap().id.len(), 32);
    }

    #[test]
    fn an_empty_answer_means_keep_walking() {
        let zones = parse_zones(200, NO_ZONES).unwrap();
        assert!(zones.is_empty());
        assert_eq!(pick(zones, "net.example.com").unwrap(), None);
    }

    #[test]
    fn a_zone_that_is_not_active_is_refused_rather_than_written_into() {
        // §13's worst shape: Cloudflare holds the records, nothing is
        // answering for the name, and the record we add changes nothing
        // while the run reports success.
        let zones = parse_zones(200, &zone_body("example.com", "pending")).unwrap();
        let error = pick(zones, "example.com").unwrap_err();
        assert_eq!(
            error,
            CfError::ZoneNotActive {
                name: "example.com".to_string(),
                status: "pending".to_string(),
            }
        );
        let message = error.to_string();
        assert!(message.contains("would change nothing"), "{message}");
        assert!(message.contains("nameservers"), "{message}");
    }

    #[test]
    fn two_zones_with_one_name_are_not_guessed_between() {
        let zones = vec![
            Zone {
                id: "z1".to_string(),
                name: "example.com".to_string(),
                status: "active".to_string(),
                name_servers: Vec::new(),
            },
            Zone {
                id: "z2".to_string(),
                name: "example.com".to_string(),
                status: "active".to_string(),
                name_servers: Vec::new(),
            },
        ];
        let error = pick(zones, "example.com").unwrap_err();
        assert_eq!(
            error,
            CfError::ZoneAmbiguous {
                name: "example.com".to_string(),
                count: 2
            }
        );
        assert!(error.to_string().contains("Scope the token to one zone"));
    }

    #[test]
    fn a_zone_with_a_different_name_is_not_this_candidate() {
        // Cloudflare answers an exact-name query, but a filter that
        // ever loosens must not quietly adopt a neighbour's zone.
        let zones = parse_zones(200, &zone_body("other.com", "active")).unwrap();
        assert_eq!(pick(zones, "example.com").unwrap(), None);
    }

    #[test]
    fn a_403_during_the_zone_walk_names_the_missing_permission() {
        // The read-only-token case surfaces here first, because the
        // lookup happens before any record is written.
        let body = r#"{"success":false,"errors":[{"code":9109,"message":"Unauthorized"}]}"#;
        let error = parse_zones(403, body).unwrap_err();
        assert!(matches!(error, CfError::Forbidden(_)));
        assert!(error.to_string().contains("Zone → Zone → Read"), "{error}");
    }

    #[test]
    fn a_zone_missing_a_field_anago_reads_is_malformed_not_blank() {
        // An id of "" would be handed to the next call, and the failure
        // would arrive later wearing a reason unrelated to the real
        // problem. Saying so here puts the run on the manual fallback.
        let no_id = r#"{"success":true,"errors":[],"result":[
          {"name":"example.com","status":"active"}
        ]}"#;
        let error = parse_zones(200, no_id).unwrap_err();
        assert_eq!(
            error,
            CfError::ApiFailure {
                status: 200,
                message: "a zone in the answer has no usable id".to_string()
            }
        );

        let no_status = r#"{"success":true,"errors":[],"result":[
          {"id":"z1","name":"example.com"}
        ]}"#;
        assert!(parse_zones(200, no_status)
            .unwrap_err()
            .to_string()
            .contains("no usable status"));
    }

    #[test]
    fn a_field_of_the_wrong_type_or_empty_is_refused_too() {
        // A number where a string belongs, and an empty string, are the
        // same problem as an absent field: nothing usable.
        let numeric = r#"{"success":true,"errors":[],"result":[
          {"id":42,"name":"example.com","status":"active"}
        ]}"#;
        assert!(parse_zones(200, numeric)
            .unwrap_err()
            .to_string()
            .contains("no usable id"));

        let blank = r#"{"success":true,"errors":[],"result":[
          {"id":"z1","name":"","status":"active"}
        ]}"#;
        assert!(parse_zones(200, blank)
            .unwrap_err()
            .to_string()
            .contains("empty name"));
    }

    #[test]
    fn a_result_that_is_not_a_list_is_reported_not_ignored() {
        let body = r#"{"success":true,"errors":[],"result":{"id":"z1"}}"#;
        assert!(matches!(
            parse_zones(200, body),
            Err(CfError::ApiFailure { .. })
        ));
    }

    // -------------------------------------------- manual fallback

    #[test]
    fn a_failed_lookup_says_what_to_do_by_hand() {
        // Failing to reach Cloudflare is not a reason to stop setting
        // up a hub: the record is ten seconds of browser work, and
        // everything else is unaffected (§6.1).
        let notice = fallback_notice(&CfError::ZoneNotFound {
            domain: "net.example.com".to_string(),
            tried: vec!["net.example.com".to_string(), "example.com".to_string()],
        });
        assert!(notice.contains("could not set the DNS record"), "{notice}");
        assert!(notice.contains("Nothing else is affected"), "{notice}");
        assert!(notice.contains("by hand"), "{notice}");
        // The reason travels with it, so the person can fix the token
        // rather than wonder why the automation went quiet.
        assert!(notice.contains("scoped to a different zone"), "{notice}");
    }

    #[test]
    fn the_fallback_notice_never_carries_the_token() {
        let notice = fallback_notice(&CfError::Rejected("Invalid API Token".to_string()));
        assert!(!notice.contains("cf-api-token"), "{notice}");
    }

    // ----------------------------------------------------- records

    const HUB_IP: &str = "203.0.113.10";
    const NAME: &str = "net.example.com";
    const ZONE: &str = "023e105f4ecef8ad9ca31a8372d0c353";

    fn hub_ip() -> Ipv4Addr {
        HUB_IP.parse().unwrap()
    }

    /// One record the way Cloudflare lists it, fields anago ignores
    /// included — `zone_name`, `locked`, `meta` are not its business.
    fn record_json(id: &str, kind: &str, name: &str, content: &str, proxied: &str) -> String {
        format!(
            r#"{{"id":"{id}","zone_id":"{ZONE}","zone_name":"example.com",
                "name":"{name}","type":"{kind}","content":"{content}",
                "ttl":1,"locked":false,{proxied}
                "meta":{{"auto_added":false}},
                "created_on":"2026-08-19T00:00:00.000000Z"}}"#
        )
    }

    fn a_record(id: &str, content: &str, proxied: bool) -> String {
        record_json(id, "A", NAME, content, &format!(r#""proxied":{proxied},"#))
    }

    fn listing(records: &[String]) -> String {
        format!(
            r#"{{"success":true,"errors":[],"messages":[],
                "result":[{}],
                "result_info":{{"page":1,"per_page":100,"count":{},"total_count":{}}}}}"#,
            records.join(","),
            records.len(),
            records.len()
        )
    }

    fn single(record: String) -> String {
        format!(r#"{{"success":true,"errors":[],"messages":[],"result":{record}}}"#)
    }

    #[test]
    fn the_record_query_asks_for_one_name_and_one_page() {
        // `name.exact` is how the current List DNS Records API spells
        // the filter. A bare `name=` that gets ignored rather than
        // refused would answer with the zone's whole first page, and a
        // full page is refused below — a name with one record would
        // take the manual path for nothing.
        assert_eq!(
            records_query(ZONE, NAME),
            format!("/client/v4/zones/{ZONE}/dns_records?name.exact=net.example.com&per_page=100")
        );
        assert_eq!(
            record_path(ZONE, "372e6795"),
            format!("/client/v4/zones/{ZONE}/dns_records/372e6795")
        );
    }

    #[test]
    fn the_listing_is_read_into_the_judgement() {
        // Everything at the name, not only the A records: the CNAME and
        // the cached id that changed type are cases `dns::decide`
        // reports rather than trips over, and `type=A` would hide them.
        let body = listing(&[
            a_record("r1", HUB_IP, false),
            record_json("r2", "TXT", NAME, "v=spf1 -all", ""),
        ]);
        let records = parse_records(200, &body, NAME).unwrap();
        assert_eq!(
            records,
            [
                Record::a("r1", HUB_IP),
                Record {
                    id: "r2".to_string(),
                    kind: "TXT".to_string(),
                    content: "v=spf1 -all".to_string(),
                    proxied: false,
                    comment: None,
                },
            ]
        );
        assert_eq!(
            dns::decide(&records, hub_ip(), Some("r1")),
            Upsert::Unchanged {
                record_id: "r1".to_string()
            }
        );
    }

    #[test]
    fn a_record_at_another_name_is_not_counted_as_ours() {
        // Cloudflare's `name=` is an exact filter, but the difference
        // between exact and "contains" is the difference between one A
        // record and an ambiguous name — not a thing to take on trust
        // from a query parameter.
        let body = listing(&[
            a_record("r1", HUB_IP, false),
            record_json(
                "r2",
                "A",
                "old.net.example.com",
                "198.51.100.7",
                r#""proxied":false,"#,
            ),
        ]);
        let records = parse_records(200, &body, NAME).unwrap();
        assert_eq!(records, [Record::a("r1", HUB_IP)]);
        // The trailing root dot and case are the same name.
        assert_eq!(
            parse_records(200, &body, "NET.Example.com.").unwrap().len(),
            1
        );
    }

    #[test]
    fn a_punycode_name_in_the_answer_is_the_name_we_asked_about() {
        // Cloudflare returns complete record names in Punycode. Since
        // that is also the only spelling anago sends, the two match and
        // the existing record is found — rather than being read as a
        // different name and a second record created beside it.
        let puny = "xn--hu5b.example.com";
        let body = listing(&[record_json(
            "r1",
            "A",
            "XN--HU5B.example.com",
            HUB_IP,
            r#""proxied":false,"#,
        )]);
        let records = parse_records(200, &body, puny).unwrap();
        assert_eq!(records, [Record::a("r1", HUB_IP)]);
        assert_eq!(
            dns::decide(&records, hub_ip(), Some("r1")),
            Upsert::Unchanged {
                record_id: "r1".to_string()
            }
        );
    }

    #[test]
    fn a_full_page_is_refused_rather_than_judged_from() {
        // The page after this one could hold the second A record that
        // makes the name ambiguous (§9.1). Judging from a partial list
        // is how a round-robin survives a run that reported success.
        let records: Vec<String> = (0..PER_PAGE)
            .map(|n| record_json(&format!("r{n}"), "TXT", NAME, "filler", ""))
            .collect();
        let error = parse_records(200, &listing(&records), NAME).unwrap_err();
        assert!(error.to_string().contains("more than one page"), "{error}");
    }

    #[test]
    fn an_a_record_without_a_proxied_flag_is_malformed_not_unproxied() {
        // `false` is exactly the answer that lets the run carry on, so
        // inventing it is how §13's silent failure happens: certificate
        // issued, output green, tunnel dead behind the proxy.
        let body = listing(&[record_json("r1", "A", NAME, HUB_IP, "")]);
        let error = parse_records(200, &body, NAME).unwrap_err();
        assert!(error.to_string().contains("no proxied flag"), "{error}");
        assert!(
            error.to_string().contains("behind the proxy"),
            "the reason travels with it: {error}"
        );

        let not_a_bool = listing(&[record_json("r1", "A", NAME, HUB_IP, r#""proxied":"yes","#)]);
        assert!(parse_records(200, &not_a_bool, NAME)
            .unwrap_err()
            .to_string()
            .contains("not true or false"));
    }

    #[test]
    fn a_type_that_cannot_be_proxied_may_leave_the_flag_out() {
        // TXT and MX come back without it, and the judgement never
        // looks at their flag.
        for kind in ["TXT", "MX"] {
            let body = listing(&[record_json("r1", kind, NAME, "whatever", "")]);
            assert!(!parse_records(200, &body, NAME).unwrap()[0].proxied);
        }
    }

    #[test]
    fn a_record_missing_a_field_anago_reads_is_malformed() {
        let no_content = r#"{"success":true,"errors":[],"result":[
          {"id":"r1","name":"net.example.com","type":"A","proxied":false}
        ]}"#;
        assert_eq!(
            parse_records(200, no_content, NAME).unwrap_err(),
            CfError::ApiFailure {
                status: 200,
                message: "a record in the answer has no usable content".to_string()
            }
        );

        // No id means nothing to update or cache later.
        let no_id = r#"{"success":true,"errors":[],"result":[
          {"name":"net.example.com","type":"A","content":"203.0.113.10","proxied":false}
        ]}"#;
        assert!(parse_records(200, no_id, NAME)
            .unwrap_err()
            .to_string()
            .contains("no usable id"));

        let not_a_list = r#"{"success":true,"errors":[],"result":{"id":"r1"}}"#;
        assert!(matches!(
            parse_records(200, not_a_list, NAME),
            Err(CfError::ApiFailure { .. })
        ));
    }

    #[test]
    fn the_create_body_says_dns_only_out_loud() {
        // A zone can be set to proxy new records by default; inheriting
        // that would be §13's trap arriving through the automation
        // meant to avoid it.
        let body: serde_json::Value = serde_json::from_str(&create_body(NAME, hub_ip())).unwrap();
        assert_eq!(body["type"], "A");
        assert_eq!(body["name"], NAME);
        assert_eq!(body["content"], HUB_IP);
        assert_eq!(body["proxied"], false);
        assert_eq!(body["ttl"], TTL_AUTOMATIC);
    }

    #[test]
    fn the_update_body_touches_only_the_address() {
        // The record may be one a person made by hand, carrying their
        // TTL and comment. Sending a whole record would reset those on
        // the way past — and `proxied` is absent on purpose too, since
        // turning the proxy off is not anago's call either (§13).
        let body: serde_json::Value = serde_json::from_str(&update_body(hub_ip())).unwrap();
        assert_eq!(body["content"], HUB_IP);
        assert_eq!(
            body.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["content"]
        );
    }

    #[test]
    fn the_answer_to_a_write_is_read_back() {
        let record = parse_record(200, &single(a_record("r9", HUB_IP, false))).unwrap();
        assert_eq!(record, Record::a("r9", HUB_IP));
        assert_eq!(record_warning(&record, hub_ip()), None);
    }

    #[test]
    fn a_record_that_comes_back_proxied_is_warned_about() {
        // The write succeeded, HTTP-01 will pass, the certificate will
        // issue — and the tunnel is dead. This answer is the one moment
        // that is catchable (§13).
        let record = parse_record(200, &single(a_record("r9", HUB_IP, true))).unwrap();
        let warning = record_warning(&record, hub_ip()).unwrap();
        assert!(warning.contains("orange cloud"), "{warning}");
        assert!(warning.contains("UDP"), "{warning}");
        assert!(warning.contains("r9"), "{warning}");
    }

    #[test]
    fn an_address_that_is_not_the_one_asked_for_is_warned_about() {
        let record = parse_record(200, &single(a_record("r9", "198.51.100.7", false))).unwrap();
        let warning = record_warning(&record, hub_ip()).unwrap();
        assert!(warning.contains("198.51.100.7"), "{warning}");
        assert!(warning.contains(HUB_IP), "{warning}");
    }

    #[test]
    fn a_hand_made_record_is_adopted_and_said_so() {
        // M0's manual instructions are still there, so meeting a record
        // anago did not create is the ordinary case, not an anomaly.
        let body = listing(&[a_record("r1", "198.51.100.7", false)]);
        let records = parse_records(200, &body, NAME).unwrap();
        assert_eq!(
            dns::decide(&records, hub_ip(), None),
            Upsert::Update {
                record_id: "r1".to_string(),
                adopted: true
            }
        );
        let line = Applied::Updated {
            record_id: "r1".to_string(),
            adopted: true,
        }
        .to_string();
        assert!(line.contains("did not create"), "{line}");
    }

    #[test]
    fn a_proxied_record_stops_the_run_instead_of_being_un_proxied() {
        // Somebody may be serving that domain through the proxy on
        // purpose; rerouting their traffic is not anago's business.
        let body = listing(&[a_record("r1", HUB_IP, true)]);
        let records = parse_records(200, &body, NAME).unwrap();
        let Upsert::Refuse(refusal) = dns::decide(&records, hub_ip(), Some("r1")) else {
            panic!("a proxied record must be refused");
        };
        assert!(matches!(refusal, Refusal::Proxied { .. }));

        let error = CfError::RecordRefused(refusal);
        let message = error.to_string();
        assert!(message.contains("did not change"), "{message}");
        assert!(message.contains("grey cloud"), "{message}");
        // And the fallback line carries the same reason, since the hub
        // is still worth setting up (§6.1).
        assert!(fallback_notice(&error).contains("grey cloud"));
    }

    #[test]
    fn several_a_records_are_reported_rather_than_half_fixed() {
        let body = listing(&[
            a_record("r1", HUB_IP, false),
            a_record("r2", "198.51.100.7", false),
        ]);
        let records = parse_records(200, &body, NAME).unwrap();
        let error = CfError::RecordRefused(match dns::decide(&records, hub_ip(), Some("r1")) {
            Upsert::Refuse(refusal) => refusal,
            other => panic!("{other:?}"),
        });
        let message = error.to_string();
        assert!(message.contains("2 A records"), "{message}");
        // The cache earns its keep here: it names which one is ours.
        assert!(message.contains("anago created r1"), "{message}");
    }

    #[test]
    fn a_403_on_a_write_names_the_permission_that_is_missing() {
        // A read-only token gets through `verify` and through the zone
        // walk, and fails here — the first time anago writes anything.
        let body = r#"{"success":false,"errors":[{"code":9109,"message":"Unauthorized"}]}"#;
        let error = parse_record(403, body).unwrap_err();
        assert!(matches!(error, CfError::Forbidden(_)));
        assert!(error.to_string().contains("Zone → DNS → Edit"), "{error}");
    }

    #[test]
    fn what_happened_reads_as_a_sentence_and_carries_the_id() {
        for applied in [
            Applied::Created {
                record_id: "r1".to_string(),
            },
            Applied::Updated {
                record_id: "r1".to_string(),
                adopted: false,
            },
            Applied::Unchanged {
                record_id: "r1".to_string(),
            },
        ] {
            assert_eq!(applied.record_id(), "r1");
            assert!(applied.to_string().contains("r1"), "{applied}");
        }
        assert!(Applied::Created {
            record_id: "r1".to_string()
        }
        .to_string()
        .contains("DNS only"));
    }

    // --------------------------------------------- DNS-01 challenge

    /// A key authorization digest: base64url of a SHA-256, 43 chars.
    const DIGEST: &str = "toxT9dGLhpBGCM3EhdcQoULLTuF-eqAaOJyBBnA_AbY";
    const CHALLENGE: &str = "_acme-challenge.net.example.com";

    fn txt_record(id: &str, content: &str) -> String {
        record_json(id, "TXT", CHALLENGE, content, "")
    }

    fn commented_txt(id: &str, content: &str, comment: &str) -> String {
        record_json(id, "TXT", CHALLENGE, content, "")
            .replace(r#""ttl":1,"#, &format!(r#""ttl":1,"comment":"{comment}","#))
    }

    #[test]
    fn the_challenge_goes_on_the_name_rfc_8555_names() {
        assert_eq!(challenge_name("NET.Example.com.").unwrap(), CHALLENGE);
        // The same ASCII rule as every other name anago sends.
        assert!(matches!(
            challenge_name("맥북.example.com"),
            Err(CfError::NotAscii(_))
        ));
    }

    #[test]
    fn the_challenge_record_is_a_short_lived_txt() {
        // Created, checked, and deleted within minutes — a long TTL
        // only means a resolver holds an answer that is already gone.
        let body: serde_json::Value =
            serde_json::from_str(&txt_body(CHALLENGE, DIGEST, NOW)).unwrap();
        assert_eq!(body["type"], "TXT");
        assert_eq!(body["name"], CHALLENGE);
        assert_eq!(body["content"], DIGEST);
        assert_eq!(body["ttl"], CHALLENGE_TTL);
        const { assert!(CHALLENGE_TTL <= 300, "a challenge record is not a fixture") };
    }

    /// A fixed "now" for the sweep tests, and the ages around it.
    const NOW: i64 = 1_755_561_600;
    const LIVE: i64 = NOW - 30;
    const LITTER: i64 = NOW - CHALLENGE_LIFETIME_SECS - 60;

    #[test]
    fn a_sweep_removes_anagos_own_leftovers_and_leaves_the_rest_alone() {
        // Several TXT values on one _acme-challenge name is a state
        // DNS-01 documents, not a conflict: a wildcard order and a
        // plain one validate at the same time. So "everything at this
        // name" is somebody's certificate mid-issue, and the marker is
        // what makes cleanup specific.
        let records = parse_records(
            200,
            &listing(&[
                commented_txt(
                    "t1",
                    "left-over-from-a-crashed-run",
                    &challenge_comment(LITTER),
                ),
                txt_record("t2", "another-clients-challenge"),
                commented_txt("t3", "someones-verification", "google-site-verification"),
                record_json("a1", "A", CHALLENGE, HUB_IP, r#""proxied":false,"#),
            ]),
            CHALLENGE,
        )
        .unwrap();

        let swept: Vec<&str> = stale_challenges(&records, NOW)
            .iter()
            .map(|record| record.id.as_str())
            .collect();
        assert_eq!(swept, ["t1"], "only the record anago wrote");
        // The cost of leaving one is a stale record that does not stop
        // this validation; the cost of removing one is a stranger's
        // failed issuance.
        for spared in ["t2", "t3", "a1"] {
            assert!(
                !swept.contains(&spared),
                "{spared} is not anago's to delete"
            );
        }
    }

    #[test]
    fn a_challenge_another_run_is_still_using_is_not_litter() {
        // The renewal timer firing while somebody types `server renew`
        // is an ordinary Tuesday. The marker says anago wrote the
        // record, not that anago is done with it — sweeping on the
        // marker alone, the second run deletes the first's live
        // challenge and fails its issuance.
        let records = parse_records(
            200,
            &listing(&[
                commented_txt("live", "the-other-runs-digest", &challenge_comment(LIVE)),
                commented_txt("old", "a-dead-runs-digest", &challenge_comment(LITTER)),
            ]),
            CHALLENGE,
        )
        .unwrap();

        let swept: Vec<&str> = stale_challenges(&records, NOW)
            .iter()
            .map(|record| record.id.as_str())
            .collect();
        assert_eq!(swept, ["old"]);

        // The boundary itself: a record exactly at the lifetime is
        // still somebody's, one second past it is not.
        let at_the_edge = parse_records(
            200,
            &listing(&[commented_txt(
                "edge",
                "d",
                &challenge_comment(NOW - CHALLENGE_LIFETIME_SECS),
            )]),
            CHALLENGE,
        )
        .unwrap();
        assert!(stale_challenges(&at_the_edge, NOW).is_empty());
        assert_eq!(stale_challenges(&at_the_edge, NOW + 1).len(), 1);
    }

    #[test]
    fn a_record_whose_age_cannot_be_read_is_left_alone() {
        // Not being able to tell how old something is, is not a reason
        // to delete it — including a stamp from the future, which is a
        // clock that disagrees rather than a record that is finished.
        let records = parse_records(
            200,
            &listing(&[
                commented_txt("edited", "d", CHALLENGE_MARKER),
                commented_txt("nonsense", "d", &format!("{CHALLENGE_MARKER} at=soon")),
                commented_txt("future", "d", &challenge_comment(NOW + 3600)),
            ]),
            CHALLENGE,
        )
        .unwrap();
        assert!(stale_challenges(&records, NOW).is_empty());
    }

    #[test]
    fn a_published_challenge_carries_the_marker_and_the_time() {
        // Without both on the way in, the sweep above has nothing to
        // aim at: no marker and the litter is permanent, no time and it
        // cannot tell litter from a challenge in use.
        let body: serde_json::Value =
            serde_json::from_str(&txt_body(CHALLENGE, DIGEST, NOW)).unwrap();
        let comment = body["comment"].as_str().unwrap();
        assert!(comment.starts_with(CHALLENGE_MARKER), "{comment}");
        assert_eq!(written_at(comment), Some(NOW));
        assert!(comment.contains("pid="), "{comment}");
        assert!(comment.len() <= 100, "Cloudflare caps a comment: {comment}");

        // And it survives the round trip: what Cloudflare hands back is
        // what the next run reads.
        let written = parse_record(
            200,
            &single(commented_txt("t1", DIGEST, &challenge_comment(LITTER))),
        )
        .unwrap();
        assert_eq!(
            written_at(written.comment.as_deref().unwrap()),
            Some(LITTER)
        );
        assert_eq!(stale_challenges(&[written], NOW)[0].id, "t1");
    }

    #[test]
    fn a_comment_that_is_not_anagos_has_no_time_to_read() {
        assert_eq!(written_at("google-site-verification at=1"), None);
        assert_eq!(written_at(""), None);
    }

    #[test]
    fn deleting_a_record_that_is_already_gone_is_not_a_failure() {
        // A cleanup path that fails because the thing it wanted gone is
        // already gone is a cleanup path people learn to ignore.
        assert_eq!(
            parse_delete(404, r#"{"success":false,"errors":[]}"#),
            Ok(())
        );
        assert_eq!(
            parse_delete(200, r#"{"success":true,"errors":[],"result":{"id":"t1"}}"#),
            Ok(())
        );
        // A permission problem still is one.
        let refused = parse_delete(403, r#"{"success":false,"errors":[{"message":"no"}]}"#);
        assert!(matches!(refused, Err(CfError::Forbidden(_))));
        assert!(refused
            .unwrap_err()
            .to_string()
            .contains("Zone → DNS → Edit"));
    }

    #[test]
    fn only_a_delete_that_worked_disarms_the_cleanup() {
        // The failure this protects: take the id first, then fail, and
        // the record is still there while `Drop` has nothing left to
        // try and the warning naming it never prints — the one path
        // the whole guard exists for, gone silently.
        let token = Token::parse("cf-api-token", Source::Flag).unwrap();
        let mut challenge = Challenge {
            token: &token,
            zone_id: ZONE.to_string(),
            name: CHALLENGE.to_string(),
            record_id: Some("t1".to_string()),
        };

        let failed = challenge.settle(Err(CfError::Forbidden("nope".to_string())));
        assert!(failed.is_err());
        assert_eq!(
            challenge.record_id.as_deref(),
            Some("t1"),
            "a failed delete leaves the record to be tried again and reported"
        );

        assert!(challenge.settle(Ok(())).is_ok());
        assert_eq!(
            challenge.record_id, None,
            "a delete that worked is not tried twice"
        );
        assert_eq!(challenge.name(), CHALLENGE);
        // No id, so no call — this drop is a no-op, network or not.
        drop(challenge);
    }

    #[test]
    fn a_challenge_never_prints_the_token() {
        let token = Token::parse("cf-api-token", Source::Flag).unwrap();
        let challenge = Challenge {
            token: &token,
            zone_id: ZONE.to_string(),
            name: CHALLENGE.to_string(),
            record_id: None,
        };
        let shown = format!("{challenge:?}");
        assert!(!shown.contains("cf-api-token"), "{shown}");
        assert!(shown.contains(CHALLENGE), "{shown}");
    }

    #[test]
    fn no_message_carries_a_collapsed_line_continuation() {
        // A `\` continuation that lost its leading-whitespace strip
        // leaves a run of spaces mid-sentence. Cheap to catch, and
        // invisible in a diff.
        let refusal = Refusal::Proxied {
            record_id: "r1".to_string(),
        };
        let mut messages = vec![
            CfError::RecordRefused(refusal.clone()).to_string(),
            fallback_notice(&CfError::RecordRefused(refusal)),
            record_warning(&Record::a("r1", "198.51.100.7"), hub_ip()).unwrap(),
            record_warning(
                &Record {
                    proxied: true,
                    ..Record::a("r1", HUB_IP)
                },
                hub_ip(),
            )
            .unwrap(),
            CfError::NotAscii("맥북.example.com".to_string()).to_string(),
            parse_records(
                200,
                &listing(&[record_json("r1", "A", NAME, HUB_IP, "")]),
                NAME,
            )
            .unwrap_err()
            .to_string(),
        ];
        messages.extend(
            [
                Applied::Created {
                    record_id: "r1".to_string(),
                },
                Applied::Updated {
                    record_id: "r1".to_string(),
                    adopted: true,
                },
                Applied::Unchanged {
                    record_id: "r1".to_string(),
                },
            ]
            .iter()
            .map(ToString::to_string),
        );
        for message in messages {
            for line in message.lines() {
                assert!(
                    !line.trim_start().contains("  "),
                    "collapsed continuation in {line:?}"
                );
            }
        }
    }

    #[test]
    fn no_error_message_ever_carries_the_token() {
        let token = Token::parse("cf-api-token", Source::Flag).unwrap();
        for error in [
            CfError::Empty(Source::Flag),
            CfError::Malformed(Source::Flag),
            CfError::Rejected("Invalid API Token".to_string()),
            CfError::NotActive("expired".to_string()),
        ] {
            assert!(!error.to_string().contains(token.expose()), "{error}");
        }
    }
}
