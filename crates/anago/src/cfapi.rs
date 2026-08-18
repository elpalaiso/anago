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
