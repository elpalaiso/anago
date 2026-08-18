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
use std::path::{Path, PathBuf};

use crate::client::{self, ClientError, HeaderValue, Method, Request};

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
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = domain.split('.').collect();
    if domain.is_empty() || labels.len() < 2 || labels.iter().any(|label| label.is_empty()) {
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
                id: string_at(zone, "id", status)?,
                name: string_at(zone, "name", status)?,
                status: string_at(zone, "status", status)?,
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
fn string_at(value: &serde_json::Value, key: &str, status: u16) -> Result<String, CfError> {
    match value.get(key).and_then(serde_json::Value::as_str) {
        Some(text) if !text.is_empty() => Ok(text.to_string()),
        Some(_) => Err(CfError::ApiFailure {
            status,
            message: format!("a zone in the answer has an empty {key}"),
        }),
        None => Err(CfError::ApiFailure {
            status,
            message: format!("a zone in the answer has no usable {key}"),
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
#[derive(Debug, Clone, PartialEq)]
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
        // A name is percent-encoded on the way into the query.
        assert_eq!(
            zones_query("맥북.example.com"),
            "/client/v4/zones?name=%EB%A7%A5%EB%B6%81.example.com"
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
            }]
        );
        // And the fields around it — nameservers, meta, result_info —
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
            },
            Zone {
                id: "z2".to_string(),
                name: "example.com".to_string(),
                status: "active".to_string(),
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
