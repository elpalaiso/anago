//! Choosing how the hub gets its certificate (DESIGN.md §8).
//!
//! One pure function decides the whole fork: the certificate comes from
//! paths a person already has, or anago orders one over HTTP-01, or
//! over DNS-01 — and if it orders, from which CA directory. Everything
//! that makes that decision is an argument, so the rules are pinned by
//! unit tests rather than discovered on a VPS at issuance time.
//!
//! Nothing here talks to an ACME server. The account, the order, and
//! the challenge live in the issuance slice; this is the part that has
//! to be right before any of that starts, because a wrong turn here is
//! not an error — it is a hub that quietly never renews.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anago_core::acme::ChallengeToken;
use anago_core::state::{Acme, Challenge};
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use instant_acme::RetryPolicy;

use crate::cfapi::{self, CfError, Source, Token, Zone};
use crate::dnsprobe;
use crate::fsutil;

/// What `server init` was told.
///
/// The Cloudflare token arrives as **where it came from**, not as the
/// secret: the decision only needs to know whether there is one
/// (`cfapi::choose`), and a decision function is a poor place to keep a
/// credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    /// `--tls-cert`.
    pub tls_cert: Option<&'a str>,
    /// `--tls-key`.
    pub tls_key: Option<&'a str>,
    /// `--acme-email`.
    pub acme_email: Option<&'a str>,
    /// `--acme-staging`.
    pub staging: bool,
    /// `--acme-challenge`, when it was given. `None` means "decide".
    pub challenge: Option<Challenge>,
    /// Where a Cloudflare token was found, if anywhere.
    pub token: Option<&'a Source>,
}

/// How this hub will have a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// M0's path: a certificate somebody else issued and renews.
    /// anago reads these files and nothing more (§9.1).
    Manual { cert: String, key: String },
    /// anago orders one and renews it.
    Acme {
        /// The CA's directory URL. It goes into the state file, so
        /// renewals return to the same CA rather than depending on a
        /// flag being repeated (§9.1).
        directory: &'static str,
        challenge: Challenge,
        /// `--acme-email`, the address the CA warns when renewal has
        /// quietly stopped working (§8).
        contact: String,
        staging: bool,
    },
}

impl Plan {
    /// Whether the Cloudflare token is **needed**, as opposed to merely
    /// useful.
    ///
    /// DNS-01 cannot proceed without it. The A record can: that is
    /// Cloudflare doing a job a person can do in a browser, and when
    /// there is no token M0's manual instructions print instead (§6.1).
    /// Keeping the two apart is why `--acme-challenge http-01` with a
    /// token is a sensible thing to ask for.
    pub fn needs_token(&self) -> bool {
        matches!(
            self,
            Plan::Acme {
                challenge: Challenge::Dns01,
                ..
            }
        )
    }

    pub fn is_manual(&self) -> bool {
        matches!(self, Plan::Manual { .. })
    }
}

/// Let's Encrypt's production directory.
pub const PRODUCTION: &str = instant_acme::LetsEncrypt::Production.url();

/// Let's Encrypt's staging directory — untrusted certificates, and no
/// meaningful rate limit (§13).
pub const STAGING: &str = instant_acme::LetsEncrypt::Staging.url();

/// Decides how the certificate will be obtained.
///
/// The rules, in the order they are applied:
///
/// 1. **`--tls-cert` and `--tls-key` come as a pair.** One without the
///    other is refused rather than guessed at.
/// 2. **The pair decides the whole fork.** With it, this is M0's manual
///    path and ACME never runs — so an `--acme-*` flag alongside it is
///    an error, not something to ignore. Ignoring it would leave a
///    person believing automatic renewal is on, and they would find out
///    when the certificate expires.
/// 3. **Without it, ACME, and `--acme-email` is required.** The CA's
///    expiry warning is the only alarm that reaches a person when
///    renewal has silently broken, and "set it up and forget it" is not
///    a promise worth trading for one flag (§8).
/// 4. **The challenge defaults to what the machine can actually do**:
///    DNS-01 when there is a Cloudflare token, HTTP-01 when there is
///    not. `--acme-challenge` overrides that either way — asking for
///    DNS-01 without a token is an error, and asking for HTTP-01 with
///    one is an ordinary thing to want.
pub fn plan(request: &Request) -> Result<Plan, PlanError> {
    match (request.tls_cert, request.tls_key) {
        (Some(cert), Some(key)) => {
            let given = acme_flags(request);
            if !given.is_empty() {
                return Err(PlanError::AcmeFlagsWithCertificate(given));
            }
            Ok(Plan::Manual {
                cert: cert.to_string(),
                key: key.to_string(),
            })
        }
        (Some(_), None) => Err(PlanError::HalfAPair {
            given: "--tls-cert",
            missing: "--tls-key",
        }),
        (None, Some(_)) => Err(PlanError::HalfAPair {
            given: "--tls-key",
            missing: "--tls-cert",
        }),
        (None, None) => {
            let Some(contact) = request.acme_email.map(str::trim).filter(|e| !e.is_empty()) else {
                return Err(PlanError::NoContact);
            };
            let challenge = match request.challenge {
                Some(Challenge::Dns01) if request.token.is_none() => {
                    return Err(PlanError::Dns01WithoutToken)
                }
                Some(asked) => asked,
                None if request.token.is_some() => Challenge::Dns01,
                None => Challenge::Http01,
            };
            Ok(Plan::Acme {
                directory: directory(request.staging),
                challenge,
                contact: contact.to_string(),
                staging: request.staging,
            })
        }
    }
}

/// The CA this run orders from.
pub fn directory(staging: bool) -> &'static str {
    if staging {
        STAGING
    } else {
        PRODUCTION
    }
}

/// Which ACME flags were given — for the message that refuses them
/// beside a certificate. Naming the actual flags is the difference
/// between an error a person can act on and one they have to guess at.
fn acme_flags(request: &Request) -> Vec<&'static str> {
    let mut given = Vec::new();
    if request.acme_email.is_some() {
        given.push("--acme-email");
    }
    if request.staging {
        given.push("--acme-staging");
    }
    if request.challenge.is_some() {
        given.push("--acme-challenge");
    }
    given
}

/// Why these flags do not describe a hub anago can set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    HalfAPair {
        given: &'static str,
        missing: &'static str,
    },
    /// `--acme-*` beside `--tls-cert/--tls-key`.
    AcmeFlagsWithCertificate(Vec<&'static str>),
    /// ACME without `--acme-email`.
    NoContact,
    /// `--acme-challenge dns-01` with no Cloudflare token anywhere.
    Dns01WithoutToken,
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanError::HalfAPair { given, missing } => write!(
                f,
                "{given} was given without {missing}. Both are needed to use a certificate \
                 you already have — or leave both out and anago will get one for you"
            ),
            PlanError::AcmeFlagsWithCertificate(flags) => write!(
                f,
                "{} cannot be used with --tls-cert/--tls-key: that pair means anago serves \
                 the certificate you gave it and never orders one, so nothing here would \
                 renew. Leave the pair out to have anago issue and renew a certificate, \
                 or drop these flags to keep serving your own",
                flags.join(" and ")
            ),
            PlanError::NoContact => f.write_str(
                "--acme-email is needed to order a certificate. It is the address Let's \
                 Encrypt writes to when a certificate is about to expire, which is the \
                 one warning that arrives if automatic renewal quietly stops working",
            ),
            PlanError::Dns01WithoutToken => f.write_str(
                "--acme-challenge dns-01 needs a Cloudflare token — the challenge is a TXT \
                 record anago has to write. Pass --cf-token-file <path>, or leave the \
                 challenge out and anago will use http-01, which needs port 80 open instead",
            ),
        }
    }
}

impl std::error::Error for PlanError {}

// ------------------------------------------------------- the account

/// A contact as ACME spells it (RFC 8555 §7.3).
pub fn contact_uri(email: &str) -> String {
    format!("mailto:{}", email.trim())
}

/// Why anago is registering rather than signing in.
///
/// Carried so the output can say which of these happened. "Registered a
/// new account with Let's Encrypt" is reassuring the first time and
/// alarming the fifth, and the difference is worth printing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fresh {
    /// No ACME account has ever been recorded for this hub.
    FirstTime,
    /// The recorded account belongs to a different CA. An ACME account
    /// is per-directory: staging's account is meaningless at
    /// production, so moving between them means registering again.
    DifferentCa { was: String },
    /// The recorded account's key file is not there any more. Whatever
    /// account it named cannot be signed into without it — the key
    /// **is** the account, as far as the CA is concerned.
    KeyGone { path: String },
}

/// Whether to sign in with the account on disk or register a new one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registration {
    Reuse {
        credentials: PathBuf,
        /// What the state recorded the account URL as. Informational:
        /// the key is what identifies the account to the CA.
        account_url: String,
        /// The contact has changed since the account was registered, so
        /// it has to be pushed to the CA as well as written to the
        /// state. Leaving the CA with the old address would point the
        /// expiry warning — the one alarm that survives everything else
        /// failing (§8) — at a mailbox nobody reads.
        update_contact: bool,
    },
    Register {
        credentials: PathBuf,
        why: Fresh,
    },
}

impl Registration {
    /// The file this decision reads or writes.
    pub fn credentials(&self) -> &Path {
        match self {
            Registration::Reuse { credentials, .. }
            | Registration::Register { credentials, .. } => credentials,
        }
    }
}

/// Decides whether the hub already has an ACME account it can use.
///
/// Pure: `key_exists` is the caller's answer about the **recorded**
/// path, and `default_path` is where a new account's credentials go
/// when there is nothing recorded.
///
/// Reusing matters more than it looks. A CA counts new accounts, and
/// registering one per renewal is the kind of thing that works all year
/// and then hits a rate limit on the day a certificate expires (§13).
/// It is also how a hub keeps one identity at the CA rather than
/// accumulating orphans.
///
/// Three things force a new registration, and each is a fact about the
/// account rather than a preference:
///
/// - nothing was ever recorded ([`Fresh::FirstTime`]);
/// - the recorded account is at a **different directory** — an account
///   exists at one CA and nowhere else ([`Fresh::DifferentCa`]);
/// - the key file is gone, so the recorded account cannot be proven to
///   be ours ([`Fresh::KeyGone`]).
///
/// The contact changing is **not** one of them: the same account can be
/// told a new address, and throwing the account away to change an email
/// would be a strange way to spend a rate limit.
pub fn registration(
    existing: Option<&Acme>,
    directory: &str,
    contact: &str,
    default_path: &Path,
    key_exists: bool,
) -> Registration {
    let Some(acme) = existing else {
        return Registration::Register {
            credentials: default_path.to_path_buf(),
            why: Fresh::FirstTime,
        };
    };

    let recorded = PathBuf::from(&acme.account_key_path);
    if acme.directory != directory {
        return Registration::Register {
            credentials: recorded,
            why: Fresh::DifferentCa {
                was: acme.directory.clone(),
            },
        };
    }
    if !key_exists {
        return Registration::Register {
            credentials: recorded,
            why: Fresh::KeyGone {
                path: acme.account_key_path.clone(),
            },
        };
    }

    Registration::Reuse {
        credentials: recorded,
        account_url: acme.account_url.clone(),
        update_contact: acme.contact.as_deref() != Some(contact),
    }
}

/// The account credentials file, and whatever is waiting to be written
/// into it.
///
/// A type of its own because the *timing* is the point: registering
/// happens before the certificate exists, and the file must not be
/// replaced until it does — see [`Pending::commit`].
pub struct Pending {
    path: PathBuf,
    /// Serialized credentials for an account this run registered.
    /// Private, and kept out of `Debug`: it holds the account's private
    /// key.
    fresh: Option<String>,
}

impl Pending {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether anything is waiting to be written.
    pub fn uncommitted(&self) -> bool {
        self.fresh.is_some()
    }

    /// Writes newly registered credentials, replacing whatever the file
    /// held. Does nothing when this run signed in to an account that
    /// was already there.
    ///
    /// **Call this at the end, with the state write.** Registering
    /// happens first — an order needs an account — but the file must
    /// not be replaced until the certificate is in hand, because the
    /// file it replaces is the only copy of the *previous* account's
    /// key. Writing it early turns "the issuance failed, nothing
    /// changed" into "the issuance failed and the account this hub had
    /// is gone": on a staging → production switch the state stays at
    /// staging by design (§8, all-or-nothing) while the file no longer
    /// holds a staging account, and nothing can put it back.
    ///
    /// Write this **before** the state file. The two are not one atomic
    /// write, so one of them lands first; this order leaves the newly
    /// registered account on disk, and a state file that still names
    /// the old one is caught loudly by [`belongs_to`] on the next run
    /// rather than quietly signing in to the wrong CA.
    pub fn commit(&self) -> Result<(), AcmeError> {
        match &self.fresh {
            Some(text) => store_text(&self.path, text),
            None => Ok(()),
        }
    }
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field("path", &self.path)
            .field("uncommitted", &self.uncommitted())
            .finish()
    }
}

/// An ACME account anago can order certificates with.
pub struct SignedIn {
    pub account: instant_acme::Account,
    /// The account's URL at the CA, as the CA gives it — recorded in
    /// the state (§9.1).
    pub url: String,
    /// The credentials file, and the write that is still owed to it.
    pub credentials: Pending,
    /// True when this run registered rather than signed in.
    pub registered: bool,
}

impl fmt::Debug for SignedIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The account holds the private key; only its name goes out.
        f.debug_struct("SignedIn")
            .field("url", &self.url)
            .field("credentials", &self.credentials)
            .field("registered", &self.registered)
            .finish()
    }
}

/// Signs in to the CA, registering an account if [`registration`] said
/// to.
///
/// The directory lookup is the library's: handing it the URL is what
/// makes it fetch `newAccount`, `newOrder` and the rest, so there is no
/// separate "fetch the directory" step to get wrong. What anago adds is
/// where the credentials live and what to say when the CA will not have
/// us.
///
/// **Human verification needed**: this talks to a real CA.
pub async fn sign_in(
    plan: &Registration,
    directory: &str,
    contact: &str,
) -> Result<SignedIn, AcmeError> {
    match plan {
        Registration::Reuse {
            credentials,
            account_url,
            update_contact,
        } => {
            let stored = load(credentials, directory, account_url)?;
            let account = instant_acme::Account::builder()
                .map_err(|e| AcmeError::Client(e.to_string()))?
                .from_credentials(stored)
                .await
                .map_err(|e| AcmeError::SignIn {
                    directory: directory.to_string(),
                    detail: e.to_string(),
                })?;
            if *update_contact {
                account
                    .update_contacts(&[&contact_uri(contact)])
                    .await
                    .map_err(|e| AcmeError::Contact {
                        contact: contact.to_string(),
                        detail: e.to_string(),
                    })?;
            }
            Ok(SignedIn {
                url: account.id().to_string(),
                account,
                credentials: Pending {
                    path: credentials.clone(),
                    fresh: None,
                },
                registered: false,
            })
        }
        Registration::Register { credentials, .. } => {
            let (account, stored) = instant_acme::Account::builder()
                .map_err(|e| AcmeError::Client(e.to_string()))?
                .create(
                    &instant_acme::NewAccount {
                        contact: &[&contact_uri(contact)],
                        // Required by RFC 8555 §7.3.1, and true: this
                        // runs because somebody asked anago to get them
                        // a certificate from this CA. The CA's terms
                        // are named in the directory metadata, and the
                        // output points at them.
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    directory.to_string(),
                    None,
                )
                .await
                .map_err(|e| AcmeError::Register {
                    directory: directory.to_string(),
                    detail: e.to_string(),
                })?;
            Ok(SignedIn {
                url: account.id().to_string(),
                account,
                credentials: Pending {
                    path: credentials.clone(),
                    // Held, not written: see `Pending::commit`.
                    fresh: Some(serialize(&stored, credentials)?),
                },
                registered: true,
            })
        }
    }
}

/// The credentials as they will be stored.
///
/// Kept apart from writing them, because *when* they are written is a
/// decision of its own — see [`SignedIn::commit`].
fn serialize(
    credentials: &instant_acme::AccountCredentials,
    path: &Path,
) -> Result<String, AcmeError> {
    serde_json::to_string(credentials).map_err(|e| AcmeError::Write {
        path: path.display().to_string(),
        detail: e.to_string(),
    })
}

/// The write itself, apart from what is being written — so the rules
/// that matter (a 0700 directory, a 0600 file, atomic replacement) can
/// be tested without an ACME server on the other end of a socket.
fn store_text(path: &Path, text: &str) -> Result<(), AcmeError> {
    if let Some(dir) = path.parent() {
        fsutil::ensure_private_dir(dir).map_err(|e| AcmeError::Write {
            path: dir.display().to_string(),
            detail: e.to_string(),
        })?;
    }
    fsutil::write_private(path, text).map_err(|e| AcmeError::Write {
        path: path.display().to_string(),
        detail: e.to_string(),
    })
}

/// Reads the account credentials back, **after checking they are the
/// ones the state means**.
fn load(
    path: &Path,
    directory: &str,
    account_url: &str,
) -> Result<instant_acme::AccountCredentials, AcmeError> {
    let text = std::fs::read_to_string(path).map_err(|e| AcmeError::Read {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    if let Err(wrong) = belongs_to(&text, directory, account_url) {
        return Err(match wrong {
            Wrong::Unreadable(detail) => AcmeError::Unreadable {
                path: path.display().to_string(),
                detail,
            },
            wrong => AcmeError::WrongAccount {
                path: path.display().to_string(),
                wrong,
                directory: directory.to_string(),
            },
        });
    }
    parse_credentials(&text).map_err(|detail| AcmeError::Unreadable {
        path: path.display().to_string(),
        detail,
    })
}

/// How a credentials file fails to be the one the state records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wrong {
    Unreadable(String),
    /// The file was issued by another CA.
    Ca {
        found: Option<String>,
    },
    /// The file is another account at the same CA.
    Account {
        found: Option<String>,
        expected: String,
    },
}

/// Checks a credentials file against the account the state records.
///
/// This exists because **the file, not the argument, decides which CA
/// gets talked to.** `Account::from_credentials` reads the directory
/// URL out of the JSON; the `directory` anago passes around is never
/// consulted. So a file that has been restored from the wrong backup,
/// copied from another hub, or replaced by a half-finished CA switch
/// would quietly order from a CA nobody asked for — with `--acme-staging`
/// on the command line and a production certificate coming back, or the
/// reverse, which is worse: an untrusted certificate served by a hub
/// whose state says it is trusted (§13).
///
/// The account id is checked for the same reason, one level down: the
/// same CA can hold many accounts, and the state names one of them.
/// Checking it here also covers what the CA later returns, since
/// `from_credentials` takes the account id straight out of this file.
///
/// A mismatch is **refused, not repaired**. Registering a new account
/// over the top would destroy whatever the file was — possibly another
/// hub's account — to recover from what is most likely a mistake at the
/// keyboard.
///
/// Pure, so both mismatches are pinned by fixtures rather than met on a
/// hub in the middle of a renewal.
fn belongs_to(text: &str, directory: &str, account_url: &str) -> Result<(), Wrong> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| Wrong::Unreadable(e.to_string()))?;
    let found = |key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };

    let ca = found("directory");
    if ca.as_deref() != Some(directory) {
        return Err(Wrong::Ca { found: ca });
    }
    // An empty recorded URL is a state file from before the account was
    // registered; there is nothing to compare and the key is what
    // proves the account anyway.
    let id = found("id");
    if !account_url.is_empty() && id.as_deref() != Some(account_url) {
        return Err(Wrong::Account {
            found: id,
            expected: account_url.to_string(),
        });
    }
    Ok(())
}

/// The credentials file's contents, parsed.
///
/// Split out from [`load`] so the failure has a message of its own: a
/// file that exists and cannot be read is a different problem from one
/// that is missing, and the person's next move differs — restore the
/// file, or delete it and let anago register again.
fn parse_credentials(text: &str) -> Result<instant_acme::AccountCredentials, String> {
    serde_json::from_str(text).map_err(|e| e.to_string())
}

// ------------------------------------------------------ HTTP-01

/// The port an HTTP-01 challenge is fetched on. Not configurable: the
/// CA connects to port 80 and nothing else (RFC 8555 §8.3), which is
/// the whole cost of this challenge type (§13).
pub const CHALLENGE_PORT: u16 = 80;

/// How long to wait for the CA to check the challenge, and then to
/// issue.
///
/// Validation is usually seconds. The generous end of this is for a CA
/// under load; the point of having a limit at all is that `server init`
/// must not hang forever on a hub whose port 80 never opens — it has to
/// fail with something a person can read (§13).
pub const VALIDATION_TIMEOUT: Duration = Duration::from_secs(90);

fn retry_policy() -> RetryPolicy {
    RetryPolicy::new()
        .initial_delay(Duration::from_secs(1))
        .backoff(2.0)
        .timeout(VALIDATION_TIMEOUT)
}

/// A listener that answers exactly one kind of request: the CA fetching
/// a challenge token.
///
/// It exists for the seconds between "the challenge is ready" and "the
/// CA has looked", and then it stops. Nothing else is routed — a hub
/// that is briefly on port 80 should not be a web server, even for one
/// request.
#[derive(Debug)]
pub struct Http01 {
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Http01 {
    /// Binds and starts serving `answers`, keyed by challenge token.
    ///
    /// **Both address families are required**, each as its own socket:
    /// the IPv6 one is opened `IPV6_V6ONLY` so that "IPv6 is bound" and
    /// "IPv6 and IPv4 are bound" cannot be the same call. Without that
    /// distinction a foreign process holding one family looks exactly
    /// like a dual-stack socket covering both — and the CA, which picks
    /// the family it likes, would be answered by that other process
    /// while anago reports success.
    ///
    /// The one family that may be missing is one this host does not
    /// have at all ([`family_unavailable`]). That is a fact about the
    /// machine, not something in the way.
    ///
    /// **Human verification needed**: needs a real port 80.
    pub async fn start(port: u16, answers: HashMap<String, String>) -> Result<Http01, AcmeError> {
        let app = router(Arc::new(answers));
        let v6 = bind_v6_only(port);
        let v4 = bind_v4(port);

        let mut bound = Vec::new();
        let mut refused = Vec::new();
        for family in [v6, v4] {
            match family {
                Ok(listener) => bound.push(listener),
                Err(e) => refused.push(e),
            }
        }
        accept_families(port, bound.len(), &refused)?;

        let mut tasks = Vec::new();
        for listener in bound {
            let app = app.clone();
            tasks.push(tokio::spawn(async move {
                // A failure here is the listener going away, which is
                // what stopping looks like. There is nobody to tell.
                let _ = axum::serve(listener, app).await;
            }));
        }
        Ok(Http01 { tasks })
    }

    /// Stops serving and gives the port back.
    ///
    /// Abrupt on purpose: by the time this is called the CA has either
    /// fetched the token or given up, so there is no request worth
    /// draining — and a graceful shutdown that waits on a half-open
    /// connection from anywhere on the internet would hold port 80 for
    /// as long as a stranger cared to keep it.
    pub async fn stop(mut self) {
        for task in &self.tasks {
            task.abort();
        }
        // Cancelled is the expected outcome; the wait is what makes the
        // socket closed by the time this returns, which `Drop` alone
        // cannot promise.
        for task in std::mem::take(&mut self.tasks) {
            let _ = task.await;
        }
    }
}

impl Drop for Http01 {
    /// Gives the port back even when nobody called [`Http01::stop`].
    ///
    /// A `JoinHandle` that is simply dropped detaches: the task keeps
    /// running and keeps the socket. So if the issuance future is
    /// cancelled — a timeout above, an abort, a panic unwinding through
    /// it — port 80 would stay held by a task nothing refers to any
    /// more, and the next renewal in the same process would find its
    /// own listener in the way.
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// One route, one answer, nothing else.
fn router(answers: Arc<HashMap<String, String>>) -> Router {
    Router::new()
        .route("/.well-known/acme-challenge/{token}", get(answer))
        .with_state(answers)
}

async fn answer(
    AxumPath(token): AxumPath<String>,
    State(answers): State<Arc<HashMap<String, String>>>,
) -> Response {
    match answers.get(&token) {
        // RFC 8555 §8.3: the key authorization, and nothing around it.
        Some(authorization) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            authorization.clone(),
        )
            .into_response(),
        // A token anago is not waiting for is not this hub's business,
        // and saying so is better than serving an empty 200 that the CA
        // would read as a wrong answer.
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// What went wrong with port 80, in the terms a person can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenProblem {
    /// Ports below 1024 are privileged.
    Permission,
    /// A web server already has it.
    InUse,
    Other,
}

/// Classifies a bind failure. Pure, so the advice below is pinned by
/// tests rather than by whatever a VPS did once.
pub fn listen_problem(kind: io::ErrorKind) -> ListenProblem {
    match kind {
        io::ErrorKind::PermissionDenied => ListenProblem::Permission,
        io::ErrorKind::AddrInUse => ListenProblem::InUse,
        _ => ListenProblem::Other,
    }
}

/// Whether the sockets that bound are enough to serve the challenge.
///
/// The policy, apart from the binding, so that what it decides is
/// pinned by tests rather than by what the machine running them happens
/// to allow:
///
/// - **A family that failed for a reason other than not existing stops
///   the run.** Serving one family while a stranger's process holds the
///   other is the quiet failure this exists to prevent: the CA picks,
///   and it may pick theirs.
/// - **A family this host does not have is fine.** An IPv4-only VPS is
///   an ordinary VPS.
/// - **Neither is not.** A hub has to be reachable somehow.
pub fn accept_families(port: u16, bound: usize, refused: &[io::Error]) -> Result<(), AcmeError> {
    for failure in refused {
        if !family_unavailable(failure.raw_os_error(), failure.kind()) {
            return Err(listen_failure(port, std::slice::from_ref(failure)));
        }
    }
    match bound {
        0 => Err(AcmeError::NoAddressFamily { port }),
        _ => Ok(()),
    }
}

/// Whether a bind failure means "this host does not do that address
/// family" rather than "something is in the way".
///
/// The difference decides whether anago carries on with one family or
/// stops: an IPv4-only VPS is ordinary, and a web server holding one
/// family is not. Both the raw code and the mapped kind are consulted,
/// because which of them carries the answer depends on the platform and
/// the standard library's version.
pub fn family_unavailable(raw: Option<i32>, kind: io::ErrorKind) -> bool {
    if let Some(raw) = raw {
        if raw == libc::EAFNOSUPPORT || raw == libc::EPROTONOSUPPORT || raw == libc::EADDRNOTAVAIL {
            return true;
        }
    }
    matches!(
        kind,
        io::ErrorKind::Unsupported | io::ErrorKind::AddrNotAvailable
    )
}

/// The failure to report for a family that could not be bound.
fn listen_failure(port: u16, refused: &[io::Error]) -> AcmeError {
    let problem = refused
        .first()
        .map(|e| listen_problem(e.kind()))
        .unwrap_or(ListenProblem::Other);
    let detail = refused
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    AcmeError::Listen {
        port,
        problem,
        detail,
    }
}

/// An IPv6 listener that serves **only** IPv6.
///
/// `std` cannot set `IPV6_V6ONLY`, and its default is the platform's:
/// on Linux one `[::]` socket usually answers IPv4 too, on the BSDs it
/// does not. Leaving that to the platform means anago cannot tell which
/// families it actually holds — see [`Http01::start`] — so the option
/// is set explicitly and the two families are two sockets everywhere.
fn bind_v6_only(port: u16) -> io::Result<tokio::net::TcpListener> {
    use std::os::fd::{FromRawFd, OwnedFd};

    // SAFETY: every call is checked, and the descriptor is owned from
    // the moment it exists so no path leaks it.
    let listener = unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = OwnedFd::from_raw_fd(fd);

        set_flag(&owned, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY)?;
        // What `std` does for every listener: a socket in TIME_WAIT
        // from the previous issuance must not make the next one look
        // like a busy port.
        set_flag(&owned, libc::SOL_SOCKET, libc::SO_REUSEADDR)?;

        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        addr.sin6_port = port.to_be();
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        {
            addr.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
        }
        if libc::bind(
            fd,
            &addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        if libc::listen(fd, LISTEN_BACKLOG) != 0 {
            return Err(io::Error::last_os_error());
        }
        std::net::TcpListener::from(owned)
    };
    from_std(listener)
}

/// How many pending connections the kernel holds. One CA fetching one
/// file needs nothing, and this is what `std` uses.
const LISTEN_BACKLOG: libc::c_int = 128;

fn set_flag(
    fd: &impl std::os::fd::AsFd,
    level: libc::c_int,
    option: libc::c_int,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let on: libc::c_int = 1;
    // SAFETY: `on` outlives the call and its size is passed with it.
    let set = unsafe {
        libc::setsockopt(
            fd.as_fd().as_raw_fd(),
            level,
            option,
            &on as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    match set {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

fn bind_v4(port: u16) -> io::Result<tokio::net::TcpListener> {
    from_std(std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))?)
}

/// tokio wants a socket that never blocks the runtime.
fn from_std(listener: std::net::TcpListener) -> io::Result<tokio::net::TcpListener> {
    listener.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(listener)
}

/// A certificate, and the key it belongs to.
pub struct Issued {
    /// The chain, PEM, leaf first — what goes in `fullchain.pem`.
    pub certificate: String,
    /// PEM. Private, because it is the only copy and a `Debug` that
    /// printed it would end up in a log (§7).
    private_key: String,
    /// Things that went well enough to carry on with and still need
    /// saying — a DNS-01 wait that could not see anything, say. Printed
    /// beside the success, not instead of it.
    pub warnings: Vec<String>,
}

impl Issued {
    pub fn expose_key(&self) -> &str {
        &self.private_key
    }
}

impl fmt::Debug for Issued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issued")
            .field(
                "certificate",
                &format_args!("{} bytes", self.certificate.len()),
            )
            .field("private_key", &"redacted")
            .finish()
    }
}

/// Orders a certificate for `domain`, proving control over port 80.
///
/// The shape is RFC 8555's: order, authorization, challenge, tell the
/// CA to look, wait, finalize, collect. What anago adds is the listener
/// in the middle and the fact that it is **always taken down**, whether
/// the order worked or not — the port belongs to whatever was using it
/// before.
///
/// **Human verification needed**: this orders a real certificate and
/// needs a real port 80 reachable from the CA.
pub async fn issue_http01(
    account: &instant_acme::Account,
    domain: &str,
    port: u16,
) -> Result<Issued, AcmeError> {
    let identifiers = [instant_acme::Identifier::Dns(domain.to_string())];
    let mut order = account
        .new_order(&instant_acme::NewOrder::new(&identifiers))
        .await
        .map_err(|e| AcmeError::Order {
            domain: domain.to_string(),
            detail: e.to_string(),
        })?;

    // First pass: what the CA will ask for. The token's shape is
    // checked by the core parser, because it is about to be part of a
    // URL path this process serves.
    let mut answers = HashMap::new();
    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization.map_err(|e| AcmeError::Order {
            domain: domain.to_string(),
            detail: e.to_string(),
        })?;
        // An authorization the CA already considers valid — a recent
        // order for the same name — needs no challenge at all.
        if authorization.status == instant_acme::AuthorizationStatus::Valid {
            continue;
        }
        let challenge = authorization
            .challenge(instant_acme::ChallengeType::Http01)
            .ok_or_else(|| AcmeError::NoChallenge {
                domain: domain.to_string(),
                challenge: Challenge::Http01,
            })?;
        let token = ChallengeToken::parse(&challenge.token).map_err(|e| AcmeError::BadToken {
            detail: e.to_string(),
        })?;
        answers.insert(
            token.as_str().to_string(),
            challenge.key_authorization().as_str().to_string(),
        );
    }

    // Nothing to prove: every authorization was already valid.
    if answers.is_empty() {
        return finish(&mut order, domain).await;
    }

    let paths: Vec<String> = answers
        .keys()
        .map(|token| format!("http://{domain}/.well-known/acme-challenge/{token}"))
        .collect();
    let listener = Http01::start(port, answers).await?;

    // Second pass: tell the CA each challenge is ready, then wait for
    // it to look. The authorizations were fetched above, so telling it
    // makes no extra requests for them.
    let checked = match tell_the_ca(&mut order, domain).await {
        Ok(()) => wait_for_ready(&mut order, domain, Challenge::Http01, &paths).await,
        Err(e) => Err(e),
    };

    // The port goes back **here**, not at the end: once the CA has
    // looked, nothing will fetch the token again, and finalizing plus
    // waiting for the certificate can take another minute and a half.
    // Holding port 80 through that would turn "stop your web server
    // for a few seconds" into something else entirely — and it is what
    // a person was told this would cost (§9.1).
    listener.stop().await;
    checked?;

    finish(&mut order, domain).await
}

/// Marks every pending HTTP-01 challenge ready.
async fn tell_the_ca(order: &mut instant_acme::Order, domain: &str) -> Result<(), AcmeError> {
    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization.map_err(|e| AcmeError::Order {
            domain: domain.to_string(),
            detail: e.to_string(),
        })?;
        if authorization.status == instant_acme::AuthorizationStatus::Valid {
            continue;
        }
        let Some(mut challenge) = authorization.challenge(instant_acme::ChallengeType::Http01)
        else {
            continue;
        };
        challenge.set_ready().await.map_err(|e| AcmeError::Order {
            domain: domain.to_string(),
            detail: e.to_string(),
        })?;
    }
    Ok(())
}

/// Waits for the CA to check the challenge. Nothing after this needs
/// the listener.
async fn wait_for_ready(
    order: &mut instant_acme::Order,
    domain: &str,
    challenge: Challenge,
    looked_at: &[String],
) -> Result<(), AcmeError> {
    let failed = |detail: String| AcmeError::Validation {
        domain: domain.to_string(),
        challenge,
        looked_at: looked_at.to_vec(),
        detail,
    };

    let status = order
        .poll_ready(&retry_policy())
        .await
        .map_err(|e| failed(e.to_string()))?;
    if status != instant_acme::OrderStatus::Ready {
        return Err(failed(format!("the CA left the order {status:?}")));
    }
    Ok(())
}

/// Finalizes and collects. The private key is generated here, by the
/// library, and never leaves this process except into `privkey.pem`.
async fn finish(order: &mut instant_acme::Order, domain: &str) -> Result<Issued, AcmeError> {
    let private_key = order.finalize().await.map_err(|e| AcmeError::Finalize {
        domain: domain.to_string(),
        detail: e.to_string(),
    })?;
    let certificate =
        order
            .poll_certificate(&retry_policy())
            .await
            .map_err(|e| AcmeError::Finalize {
                domain: domain.to_string(),
                detail: e.to_string(),
            })?;
    Ok(Issued {
        certificate,
        private_key,
        warnings: Vec::new(),
    })
}

// ------------------------------------------------------- DNS-01

/// What to tell someone whose DNS-01 attempt failed.
///
/// **anago does not answer a DNS-01 failure by trying HTTP-01.** This
/// is the one place that decision is written down, and it is not a
/// convenience question: the two challenges have different blast radii
/// (§13), and someone who chose DNS-01 may have chosen it precisely so
/// that port 80 stays shut — on a host where opening it is a change to
/// a firewall, a security group, or somebody else's web server. Falling
/// back would undo that choice silently, and the run would report
/// success.
///
/// The A record is the opposite case and falls back happily
/// (`cfapi::fallback_notice`): there Cloudflare is doing a job a person
/// can do in a browser in ten seconds, and M0's instructions are still
/// printed underneath. Here the token is not a convenience, it is the
/// whole mechanism.
///
/// So the failure stops the run, and the alternative is offered as
/// something for a person to choose.
pub fn no_automatic_switch() -> String {
    format!(
        "anago did not switch to another challenge on its own: http-01 needs port \
         {CHALLENGE_PORT} open to the internet, and that is not a change to make on \
         somebody's behalf. Fix the token or the zone and run this again, or ask for \
         it with --acme-challenge http-01"
    )
}

/// Orders a certificate for `domain`, proving control by writing a TXT
/// record — no port 80 anywhere.
///
/// The shape is the same as [`issue_http01`], with the challenge record
/// in place of the listener and one step more: **waiting for the record
/// to be served** before telling the CA to look (`dnsprobe`). A CA that
/// looks too early sees nothing and spends one of the failed-validation
/// attempts a rate limit counts (§13).
///
/// Cleanup is not conditional. Each published record is held by a guard
/// that removes it on the way out, whichever way out that is — an error,
/// an early return, a panic (§9.1).
///
/// **Human verification needed**: this orders a real certificate and
/// needs a real Cloudflare zone.
pub async fn issue_dns01(
    account: &instant_acme::Account,
    domain: &str,
    zone: &Zone,
    token: &Token,
    now: i64,
) -> Result<Issued, AcmeError> {
    let identifiers = [instant_acme::Identifier::Dns(domain.to_string())];
    let mut order = account
        .new_order(&instant_acme::NewOrder::new(&identifiers))
        .await
        .map_err(|e| AcmeError::Order {
            domain: domain.to_string(),
            detail: e.to_string(),
        })?;

    // First pass: the values the CA will look for. For one hub that is
    // one value, but the loop is the general shape — several TXT values
    // at one name is a state DNS-01 allows for.
    let mut values = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization.map_err(|e| AcmeError::Order {
            domain: domain.to_string(),
            detail: e.to_string(),
        })?;
        if authorization.status == instant_acme::AuthorizationStatus::Valid {
            continue;
        }
        let challenge = authorization
            .challenge(instant_acme::ChallengeType::Dns01)
            .ok_or_else(|| AcmeError::NoChallenge {
                domain: domain.to_string(),
                challenge: Challenge::Dns01,
            })?;
        values.push(challenge.key_authorization().dns_value());
    }

    if values.is_empty() {
        // Every authorization was already valid: nothing to publish,
        // nothing to clean up.
        return finish(&mut order, domain).await;
    }

    // The guards live until this function returns, so every path out of
    // it — including the `?`s below — takes the records with it.
    let mut published = Vec::new();
    for value in &values {
        published.push(
            cfapi::Challenge::publish(token, &zone.id, domain, value, now)
                .map_err(|e| dns01_error(domain, e))?,
        );
    }
    let name = published[0].name().to_string();

    let mut warnings = Vec::new();
    for value in &values {
        let outcome = look_for(&zone.name_servers, &name, value).await?;
        warnings.extend(outcome.warning());
    }

    tell_the_ca_dns01(&mut order, domain).await?;
    let record = vec![format!("the TXT record at {name}")];
    wait_for_ready(&mut order, domain, Challenge::Dns01, &record).await?;

    // The CA has looked; the records have done their job. Removing them
    // here — rather than letting the guards do it on the way out —
    // means the report says whether it worked, and the zone is tidy
    // before the certificate arrives.
    for challenge in published {
        challenge.remove().map_err(|e| dns01_error(domain, e))?;
    }

    let mut issued = finish(&mut order, domain).await?;
    issued.warnings = warnings;
    Ok(issued)
}

/// Waits for one value to be served, off the async runtime.
///
/// `dnsprobe` is ordinary blocking code — a UDP socket and a sleep —
/// and running it directly here would stall the runtime thread it
/// happens to be on for up to a minute.
async fn look_for(
    nameservers: &[String],
    name: &str,
    value: &str,
) -> Result<dnsprobe::Outcome, AcmeError> {
    let nameservers = nameservers.to_vec();
    let watched = name.to_string();
    let value = value.to_string();
    tokio::task::spawn_blocking(move || dnsprobe::wait(&nameservers, &watched, &value))
        .await
        .map_err(|e| AcmeError::Propagation {
            detail: format!("the wait for {name} did not finish: {e}"),
        })?
        .map_err(|e| AcmeError::Propagation {
            detail: e.to_string(),
        })
}

/// Marks every pending DNS-01 challenge ready.
async fn tell_the_ca_dns01(order: &mut instant_acme::Order, domain: &str) -> Result<(), AcmeError> {
    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization.map_err(|e| AcmeError::Order {
            domain: domain.to_string(),
            detail: e.to_string(),
        })?;
        if authorization.status == instant_acme::AuthorizationStatus::Valid {
            continue;
        }
        let Some(mut challenge) = authorization.challenge(instant_acme::ChallengeType::Dns01)
        else {
            continue;
        };
        challenge.set_ready().await.map_err(|e| AcmeError::Order {
            domain: domain.to_string(),
            detail: e.to_string(),
        })?;
    }
    Ok(())
}

fn dns01_error(domain: &str, e: CfError) -> AcmeError {
    AcmeError::Dns01 {
        domain: domain.to_string(),
        detail: e.to_string(),
    }
}

/// Writes the certificate and its key under `/var/lib/anago/tls/`
/// (§9), 0600 in a 0700 directory.
///
/// **The two are published as a pair** ([`fsutil::write_private_pair`]).
/// A certificate and its key are one thing in two files: either half on
/// its own is a hub that will not start, so a failure while saving must
/// not be able to leave one new and one old. Both are written and made
/// durable before either is published, and an ordinary error — a full
/// disk, a path that is not writable — leaves the working pair exactly
/// where it was.
///
/// The key goes first of the two, so that in the one case this cannot
/// close (a crash between two renames) the public half is never the
/// newer one and the mismatch always points the same way. The recovery
/// is `server renew --force`.
pub fn save(certificate: &Path, key: &Path, issued: &Issued) -> Result<(), AcmeError> {
    if let Some(dir) = key.parent() {
        fsutil::ensure_private_dir(dir).map_err(|e| AcmeError::Write {
            path: dir.display().to_string(),
            detail: e.to_string(),
        })?;
    }
    fsutil::write_private_pair(
        (key, issued.expose_key()),
        (certificate, &issued.certificate),
    )
    .map_err(|e| AcmeError::Write {
        path: format!("{} and {}", key.display(), certificate.display()),
        detail: e.to_string(),
    })
}

/// Why the account step failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeError {
    /// The HTTP client could not be built at all.
    Client(String),
    Register {
        directory: String,
        detail: String,
    },
    SignIn {
        directory: String,
        detail: String,
    },
    Contact {
        contact: String,
        detail: String,
    },
    Read {
        path: String,
        detail: String,
    },
    Write {
        path: String,
        detail: String,
    },
    Unreadable {
        path: String,
        detail: String,
    },
    /// The credentials file is not the account the state records.
    WrongAccount {
        path: String,
        wrong: Wrong,
        directory: String,
    },
    /// Port 80 could not be bound for the challenge.
    Listen {
        port: u16,
        problem: ListenProblem,
        detail: String,
    },
    /// The order itself — creating it, reading its authorizations,
    /// telling the CA a challenge is ready.
    Order {
        domain: String,
        detail: String,
    },
    /// The CA does not offer the challenge type that was chosen.
    NoChallenge {
        domain: String,
        challenge: Challenge,
    },
    /// The CA's challenge token is not a shape anago will put in a URL.
    BadToken {
        detail: String,
    },
    /// Neither IPv6 nor IPv4 exists on this host.
    NoAddressFamily {
        port: u16,
    },
    /// The challenge record could not be written or removed.
    Dns01 {
        domain: String,
        detail: String,
    },
    /// The record was written and the nameservers never served it.
    /// The detail is `dnsprobe`'s, which already names the record.
    Propagation {
        detail: String,
    },
    /// The CA looked and was not satisfied.
    Validation {
        domain: String,
        /// Which challenge was being proven. The two fail for entirely
        /// different reasons and are fixed in entirely different
        /// places, so they are never described in the same words.
        challenge: Challenge,
        /// What the CA looked at: the URLs it fetches for HTTP-01, the
        /// record name it resolves for DNS-01.
        looked_at: Vec<String>,
        detail: String,
    },
    /// The order was authorized and the certificate still did not
    /// arrive.
    Finalize {
        domain: String,
        detail: String,
    },
}

impl fmt::Display for AcmeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AcmeError::Client(detail) => {
                write!(f, "the ACME client could not be started: {detail}")
            }
            AcmeError::Register { directory, detail } => write!(
                f,
                "could not register an account with the CA at {directory}: {detail}. \
                 Check that this machine can reach it, and that the address given to \
                 --acme-email is one the CA will accept"
            ),
            AcmeError::SignIn { directory, detail } => write!(
                f,
                "could not use the existing ACME account at {directory}: {detail}. \
                 If the account was removed at the CA, delete the credentials file and \
                 anago will register a new one"
            ),
            AcmeError::Contact { contact, detail } => write!(
                f,
                "the CA would not take {contact} as the contact address: {detail}. \
                 The certificate is unaffected, but expiry warnings would go to the \
                 old address"
            ),
            AcmeError::Read { path, detail } => {
                write!(f, "could not read the ACME account key at {path}: {detail}")
            }
            AcmeError::Write { path, detail } => {
                write!(f, "could not save the ACME account key at {path}: {detail}")
            }
            AcmeError::WrongAccount {
                path,
                wrong: Wrong::Ca { found },
                directory,
            } => write!(
                f,
                "the ACME account key at {path} belongs to {}, not to {directory}. anago \
                 will not use it: the file decides which CA is contacted, so this would \
                 quietly order from a CA you did not ask for. Restore the right file, or \
                 delete this one and anago will register a new account with {directory}",
                found.as_deref().unwrap_or("no CA it will name")
            ),
            AcmeError::WrongAccount {
                path,
                wrong: Wrong::Account { found, expected },
                ..
            } => write!(
                f,
                "the ACME account key at {path} is account {}, but this hub is registered \
                 as {expected}. Restore the right file, or delete this one and anago will \
                 register a new account",
                found.as_deref().unwrap_or("one with no id")
            ),
            AcmeError::WrongAccount { path, .. } => {
                write!(f, "the ACME account key at {path} could not be checked")
            }
            AcmeError::Listen {
                port,
                problem: ListenProblem::Permission,
                ..
            } => write!(
                f,
                "port {port} cannot be opened without privilege — ports below 1024 belong \
                 to root. Run this with sudo, or give the binary CAP_NET_BIND_SERVICE. \
                 A DNS-01 challenge needs no port at all: pass --acme-challenge dns-01 \
                 with a Cloudflare token"
            ),
            AcmeError::Listen {
                port,
                problem: ListenProblem::InUse,
                ..
            } => write!(
                f,
                "something is already listening on port {port} — a web server (nginx, \
                 caddy, apache) is the usual answer. anago needs it for the seconds the \
                 CA takes to fetch one file: stop that server for a moment and run this \
                 again, or use --acme-challenge dns-01 with a Cloudflare token and leave \
                 port {port} alone"
            ),
            AcmeError::Listen { port, detail, .. } => {
                write!(f, "port {port} could not be opened: {detail}")
            }
            AcmeError::NoAddressFamily { port } => write!(
                f,
                "port {port} could not be opened on IPv4 or IPv6 — this host appears to \
                 have neither. A hub needs one of them to be reachable at all"
            ),
            AcmeError::Dns01 { domain, detail } => write!(
                f,
                "the DNS-01 challenge record for {domain} could not be managed: {detail}\n{}",
                no_automatic_switch()
            ),
            AcmeError::Propagation { detail } => {
                write!(f, "{detail}\n{}", no_automatic_switch())
            }
            AcmeError::Order { domain, detail } => write!(
                f,
                "the certificate order for {domain} did not go through: {detail}"
            ),
            AcmeError::NoChallenge { domain, challenge } => write!(
                f,
                "the CA does not offer a {} challenge for {domain}",
                challenge.as_str()
            ),
            AcmeError::BadToken { detail } => write!(
                f,
                "the CA sent a challenge token anago will not serve: {detail}"
            ),
            AcmeError::Validation {
                domain,
                challenge: Challenge::Http01,
                looked_at,
                detail,
            } => write!(
                f,
                "the CA could not verify {domain}: {detail}. It fetches {} from outside, \
                 so the thing to check is that port 80 is open all the way in — the cloud \
                 security group as well as the host firewall — and that the name resolves \
                 to this server",
                looked_at.join(", ")
            ),
            AcmeError::Validation {
                domain,
                challenge: Challenge::Dns01,
                looked_at,
                detail,
            } => write!(
                f,
                "the CA could not verify {domain}: {detail}. It resolves {} itself, from \
                 its own side of the internet, so what to look at is DNS and not this \
                 machine: whether the zone anago wrote into is the one actually answering \
                 for that name (a delegated subzone answers for itself), whether something \
                 stale is still at it, and whether the token may edit the zone that \
                 matters.\n{}",
                looked_at.join(", "),
                no_automatic_switch()
            ),
            AcmeError::Finalize { domain, detail } => write!(
                f,
                "{domain} was verified and the certificate still did not arrive: {detail}. \
                 Nothing was saved; running this again re-uses the authorization the CA \
                 already granted"
            ),
            AcmeError::Unreadable { path, detail } => write!(
                f,
                "the ACME account key at {path} is not readable as account credentials: \
                 {detail}. Restore the file from a backup, or delete it — anago will \
                 register a new account, which costs nothing but the old account's history"
            ),
        }
    }
}

impl std::error::Error for AcmeError {}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str = "/etc/ssl/anago/fullchain.pem";
    const KEY: &str = "/etc/ssl/anago/privkey.pem";
    const EMAIL: &str = "jo@example.com";

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> TempDir {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("anago-acme-{}-{unique}", std::process::id()));
            std::fs::create_dir_all(&path).expect("temp dir");
            TempDir { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn nothing() -> Request<'static> {
        Request {
            tls_cert: None,
            tls_key: None,
            acme_email: None,
            staging: false,
            challenge: None,
            token: None,
        }
    }

    fn acme() -> Request<'static> {
        Request {
            acme_email: Some(EMAIL),
            ..nothing()
        }
    }

    fn token() -> Source {
        Source::Env
    }

    #[test]
    fn a_certificate_pair_is_the_manual_path() {
        let request = Request {
            tls_cert: Some(CERT),
            tls_key: Some(KEY),
            ..nothing()
        };
        assert_eq!(
            plan(&request),
            Ok(Plan::Manual {
                cert: CERT.to_string(),
                key: KEY.to_string(),
            })
        );
        assert!(plan(&request).unwrap().is_manual());
        assert!(!plan(&request).unwrap().needs_token());
    }

    #[test]
    fn half_a_pair_is_refused_rather_than_guessed_at() {
        let cert_only = Request {
            tls_cert: Some(CERT),
            ..nothing()
        };
        let error = plan(&cert_only).unwrap_err();
        assert_eq!(
            error,
            PlanError::HalfAPair {
                given: "--tls-cert",
                missing: "--tls-key",
            }
        );
        assert!(error.to_string().contains("--tls-key"), "{error}");

        let key_only = Request {
            tls_key: Some(KEY),
            ..nothing()
        };
        assert_eq!(
            plan(&key_only).unwrap_err(),
            PlanError::HalfAPair {
                given: "--tls-key",
                missing: "--tls-cert",
            }
        );
    }

    #[test]
    fn acme_flags_beside_a_certificate_are_an_error_not_a_thing_to_ignore() {
        // Ignored, they would leave a person believing automatic
        // renewal is on — and they would find out at expiry.
        let request = Request {
            tls_cert: Some(CERT),
            tls_key: Some(KEY),
            acme_email: Some(EMAIL),
            staging: true,
            challenge: Some(Challenge::Dns01),
            ..nothing()
        };
        let error = plan(&request).unwrap_err();
        assert_eq!(
            error,
            PlanError::AcmeFlagsWithCertificate(vec![
                "--acme-email",
                "--acme-staging",
                "--acme-challenge"
            ])
        );
        // The message names the flags that are in the way, and says
        // what each choice means.
        let message = error.to_string();
        assert!(
            message.contains("--acme-email and --acme-staging"),
            "{message}"
        );
        assert!(message.contains("nothing here would renew"), "{message}");
    }

    #[test]
    fn a_cloudflare_token_beside_a_certificate_is_fine() {
        // The token's other job — writing the A record — has nothing to
        // do with how the certificate was obtained (§6.1).
        let source = token();
        let request = Request {
            tls_cert: Some(CERT),
            tls_key: Some(KEY),
            token: Some(&source),
            ..nothing()
        };
        assert!(plan(&request).unwrap().is_manual());
    }

    #[test]
    fn ordering_a_certificate_needs_an_address_to_warn() {
        // The CA's expiry mail is the only alarm that reaches a person
        // when renewal has silently broken.
        assert_eq!(plan(&nothing()).unwrap_err(), PlanError::NoContact);
        // An empty or blank --acme-email is the same as none: it would
        // register an account nothing can be sent to.
        for blank in ["", "   "] {
            let request = Request {
                acme_email: Some(blank),
                ..nothing()
            };
            assert_eq!(plan(&request).unwrap_err(), PlanError::NoContact);
        }
        assert!(PlanError::NoContact.to_string().contains("about to expire"));
    }

    #[test]
    fn the_challenge_defaults_to_what_the_machine_can_do() {
        // No token: HTTP-01, which needs :80 rather than a credential.
        assert_eq!(
            plan(&acme()).unwrap(),
            Plan::Acme {
                directory: PRODUCTION,
                challenge: Challenge::Http01,
                contact: EMAIL.to_string(),
                staging: false,
            }
        );

        // A token: DNS-01, which needs no :80 at all (§11 M1).
        let source = token();
        let with_token = Request {
            token: Some(&source),
            ..acme()
        };
        let plan = plan(&with_token).unwrap();
        assert!(matches!(
            plan,
            Plan::Acme {
                challenge: Challenge::Dns01,
                ..
            }
        ));
        assert!(plan.needs_token());
    }

    #[test]
    fn http_01_can_be_asked_for_even_with_a_token() {
        // An escape hatch that exists so two unrelated things stay
        // unrelated: a zone delegated oddly may need HTTP-01, and
        // giving up the A record automation to get it would be an
        // absurd price (§8).
        let source = token();
        let request = Request {
            challenge: Some(Challenge::Http01),
            token: Some(&source),
            ..acme()
        };
        let chosen = plan(&request).unwrap();
        assert!(matches!(
            chosen,
            Plan::Acme {
                challenge: Challenge::Http01,
                ..
            }
        ));
        assert!(
            !chosen.needs_token(),
            "the token is still useful for the A record, just not required"
        );
    }

    #[test]
    fn dns_01_without_a_token_is_an_error_not_a_silent_fallback() {
        // Falling back to HTTP-01 would open a port the person may have
        // chosen DNS-01 precisely to avoid.
        let request = Request {
            challenge: Some(Challenge::Dns01),
            ..acme()
        };
        assert_eq!(plan(&request).unwrap_err(), PlanError::Dns01WithoutToken);
        let message = PlanError::Dns01WithoutToken.to_string();
        assert!(message.contains("--cf-token-file"), "{message}");
        assert!(message.contains("port 80"), "{message}");
    }

    #[test]
    fn staging_and_production_are_different_directories() {
        // The URL is what the state file keeps, so a renewal returns to
        // the same CA without the flag being repeated (§9.1).
        let staging = Request {
            staging: true,
            ..acme()
        };
        let Plan::Acme {
            directory: url,
            staging: recorded,
            ..
        } = plan(&staging).unwrap()
        else {
            panic!("ACME was asked for");
        };
        assert_eq!(url, STAGING);
        assert!(recorded);
        assert!(url.contains("staging"), "{url}");
        assert_ne!(STAGING, PRODUCTION);
        assert_eq!(directory(false), PRODUCTION);
    }

    // ----------------------------------------------------- account

    const ACCOUNT_KEY: &str = "/var/lib/anago/tls/account.key";
    const ACCOUNT_URL: &str = "https://acme-v02.api.letsencrypt.org/acme/acct/1234";

    fn recorded(directory: &str, contact: Option<&str>) -> Acme {
        Acme {
            directory: directory.to_string(),
            contact: contact.map(str::to_string),
            account_key_path: ACCOUNT_KEY.to_string(),
            account_url: ACCOUNT_URL.to_string(),
            challenge: Challenge::Http01,
            issued_at: 1_755_561_600,
            renew_after: 1_760_000_000,
        }
    }

    fn default_path() -> PathBuf {
        PathBuf::from(ACCOUNT_KEY)
    }

    fn issued(certificate: &str, private_key: &str) -> Issued {
        Issued {
            certificate: certificate.to_string(),
            private_key: private_key.to_string(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn a_contact_is_a_mailto_uri() {
        assert_eq!(contact_uri("jo@example.com"), "mailto:jo@example.com");
        assert_eq!(contact_uri("  jo@example.com "), "mailto:jo@example.com");
    }

    #[test]
    fn the_first_run_registers() {
        assert_eq!(
            registration(None, PRODUCTION, EMAIL, &default_path(), false),
            Registration::Register {
                credentials: default_path(),
                why: Fresh::FirstTime,
            }
        );
    }

    #[test]
    fn an_account_that_is_there_is_used_again() {
        // A CA counts new accounts. Registering one per renewal works
        // all year and then meets a rate limit on the day a certificate
        // expires (§13).
        let existing = recorded(PRODUCTION, Some(EMAIL));
        assert_eq!(
            registration(Some(&existing), PRODUCTION, EMAIL, &default_path(), true),
            Registration::Reuse {
                credentials: default_path(),
                account_url: ACCOUNT_URL.to_string(),
                update_contact: false,
            }
        );
    }

    #[test]
    fn a_new_address_updates_the_account_rather_than_replacing_it() {
        // Throwing an account away to change an email would spend a
        // rate limit on nothing — and leaving the CA with the old
        // address would point the expiry warning at a mailbox nobody
        // reads (§8).
        let existing = recorded(PRODUCTION, Some("old@example.com"));
        let plan = registration(Some(&existing), PRODUCTION, EMAIL, &default_path(), true);
        assert_eq!(
            plan,
            Registration::Reuse {
                credentials: default_path(),
                account_url: ACCOUNT_URL.to_string(),
                update_contact: true,
            }
        );

        // An account registered before anago recorded a contact at all
        // is the same case.
        let no_contact = recorded(PRODUCTION, None);
        assert!(matches!(
            registration(Some(&no_contact), PRODUCTION, EMAIL, &default_path(), true),
            Registration::Reuse {
                update_contact: true,
                ..
            }
        ));
    }

    #[test]
    fn moving_to_another_ca_means_another_account() {
        // An ACME account exists at one directory and nowhere else, so
        // `server renew --acme-production` on a staging hub cannot sign
        // in with what it has (§8).
        let staging = recorded(STAGING, Some(EMAIL));
        assert_eq!(
            registration(Some(&staging), PRODUCTION, EMAIL, &default_path(), true),
            Registration::Register {
                credentials: default_path(),
                why: Fresh::DifferentCa {
                    was: STAGING.to_string()
                },
            }
        );
    }

    #[test]
    fn a_missing_key_file_means_the_recorded_account_is_out_of_reach() {
        // The key is what proves the account is ours; without it the
        // recorded URL is a name we cannot answer to.
        let existing = recorded(PRODUCTION, Some(EMAIL));
        assert_eq!(
            registration(Some(&existing), PRODUCTION, EMAIL, &default_path(), false),
            Registration::Register {
                credentials: default_path(),
                why: Fresh::KeyGone {
                    path: ACCOUNT_KEY.to_string()
                },
            }
        );
    }

    #[test]
    fn the_recorded_path_is_the_one_that_gets_written() {
        // Not the default: the state points at a file, and registering
        // again has to replace that file rather than leave the state
        // naming a key nothing wrote.
        let elsewhere = Acme {
            account_key_path: "/srv/anago/tls/account.key".to_string(),
            ..recorded(STAGING, Some(EMAIL))
        };
        let plan = registration(Some(&elsewhere), PRODUCTION, EMAIL, &default_path(), true);
        assert_eq!(
            plan.credentials(),
            Path::new("/srv/anago/tls/account.key"),
            "{plan:?}"
        );
    }

    #[test]
    fn the_credentials_file_is_private_from_the_moment_it_exists() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new();
        let path = dir.path.join("tls").join("account.key");
        store_text(&path, r#"{"id":"x"}"#).expect("the account key is written");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the account key holds a private key");
        let parent = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode & 0o077, 0, "nobody else reads it");
        assert_eq!(parent, 0o700, "nor lists the directory it is in");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), r#"{"id":"x"}"#);

        // Replacing it keeps the mode — a second run must not widen it.
        store_text(&path, r#"{"id":"y"}"#).expect("replaced");
        let again = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(again, 0o600);
    }

    #[test]
    fn a_file_that_is_not_credentials_says_what_to_do_about_it() {
        // A file that exists and cannot be read is a different problem
        // from one that is missing, and the next move differs: restore
        // it, or delete it and let anago register again.
        let Err(detail) = parse_credentials("this is not json") else {
            panic!("that is not an account");
        };
        let error = AcmeError::Unreadable {
            path: ACCOUNT_KEY.to_string(),
            detail,
        };
        let message = error.to_string();
        assert!(message.contains(ACCOUNT_KEY), "{message}");
        assert!(message.contains("delete it"), "{message}");

        // Valid JSON that is not an account is refused too, rather than
        // half-loading into something that fails at signing time.
        assert!(parse_credentials(r#"{"id":"x"}"#).is_err());
        // And so is an empty file, which is what a run killed mid-write
        // would once have left behind (it cannot now — the write is
        // atomic — but the reader does not rely on that).
        assert!(parse_credentials("").is_err());
    }

    #[test]
    fn account_errors_say_which_step_failed_and_what_to_try() {
        let cases = [
            AcmeError::Register {
                directory: PRODUCTION.to_string(),
                detail: "connection refused".to_string(),
            },
            AcmeError::SignIn {
                directory: PRODUCTION.to_string(),
                detail: "account does not exist".to_string(),
            },
            AcmeError::Contact {
                contact: EMAIL.to_string(),
                detail: "invalid contact".to_string(),
            },
            AcmeError::Read {
                path: ACCOUNT_KEY.to_string(),
                detail: "permission denied".to_string(),
            },
            AcmeError::Write {
                path: ACCOUNT_KEY.to_string(),
                detail: "read-only file system".to_string(),
            },
            AcmeError::Client("no provider".to_string()),
        ];
        for error in &cases {
            let message = error.to_string();
            for line in message.lines() {
                assert!(
                    !line.trim_start().contains("  "),
                    "collapsed continuation in {line:?}"
                );
            }
        }
        assert!(cases[1].to_string().contains("register a new one"));
        // A failed contact update is not a failed certificate.
        assert!(cases[2].to_string().contains("certificate is unaffected"));
    }

    /// A credentials file as `instant-acme` serializes one, minus the
    /// key — [`belongs_to`] reads only these two fields, and a real
    /// key would need an encoder anago does not have.
    fn stored(directory: &str, id: &str) -> String {
        format!(r#"{{"id":"{id}","key_pkcs8":"...","directory":"{directory}"}}"#)
    }

    #[test]
    fn a_credentials_file_from_another_ca_is_refused() {
        // The file, not the argument, decides which CA gets talked to:
        // `from_credentials` reads the directory URL out of the JSON.
        // So this is the difference between `--acme-staging` meaning
        // staging and it meaning whatever the file says.
        let wrong = belongs_to(&stored(STAGING, ACCOUNT_URL), PRODUCTION, ACCOUNT_URL).unwrap_err();
        assert_eq!(
            wrong,
            Wrong::Ca {
                found: Some(STAGING.to_string())
            }
        );

        let error = AcmeError::WrongAccount {
            path: ACCOUNT_KEY.to_string(),
            wrong,
            directory: PRODUCTION.to_string(),
        };
        let message = error.to_string();
        assert!(message.contains(STAGING), "{message}");
        assert!(message.contains("did not ask for"), "{message}");
        // Refused, not repaired: registering over the top would destroy
        // whatever the file was, possibly another hub's account.
        assert!(message.contains("delete this one"), "{message}");
    }

    #[test]
    fn a_file_that_names_no_ca_is_refused_too() {
        // Older credentials embedded the URLs instead of the directory.
        // anago cannot tell which CA that is, and "cannot tell" is not
        // a reason to go ahead.
        let no_directory = format!(r#"{{"id":"{ACCOUNT_URL}","key_pkcs8":"..."}}"#);
        assert_eq!(
            belongs_to(&no_directory, PRODUCTION, ACCOUNT_URL).unwrap_err(),
            Wrong::Ca { found: None }
        );
    }

    #[test]
    fn a_credentials_file_for_another_account_is_refused() {
        // One CA holds many accounts; the state names one of them.
        let other = "https://acme-v02.api.letsencrypt.org/acme/acct/9999";
        assert_eq!(
            belongs_to(&stored(PRODUCTION, other), PRODUCTION, ACCOUNT_URL).unwrap_err(),
            Wrong::Account {
                found: Some(other.to_string()),
                expected: ACCOUNT_URL.to_string(),
            }
        );
    }

    #[test]
    fn the_file_this_hub_wrote_is_accepted() {
        assert_eq!(
            belongs_to(&stored(PRODUCTION, ACCOUNT_URL), PRODUCTION, ACCOUNT_URL),
            Ok(())
        );
        // A state that has no account URL yet has nothing to compare —
        // the key is what proves the account in any case.
        assert_eq!(
            belongs_to(&stored(PRODUCTION, "any"), PRODUCTION, ""),
            Ok(())
        );
    }

    #[test]
    fn a_file_that_is_not_json_is_unreadable_rather_than_wrong() {
        // Different problem, different fix: restore the file, or delete
        // it — not "you have the wrong account".
        assert_eq!(
            belongs_to("half a file", PRODUCTION, ACCOUNT_URL),
            Err(Wrong::Unreadable(
                "expected value at line 1 column 1".to_string()
            ))
        );
    }

    #[test]
    fn a_new_account_is_not_written_until_the_issuance_says_so() {
        // The failure this prevents: a staging → production switch that
        // registers, replaces the file, and then fails at the order.
        // The state stays at staging by design (§8, all-or-nothing) —
        // but the staging account's key is gone and nothing can put it
        // back.
        let dir = TempDir::new();
        let path = dir.path.join("tls").join("account.key");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, stored(STAGING, ACCOUNT_URL)).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();

        // What `sign_in` holds after registering with a new CA: the
        // account is usable, and the file is untouched.
        let url = "https://acme-v02.api.letsencrypt.org/acme/acct/2";
        let held = Pending {
            path: path.clone(),
            fresh: Some(stored(PRODUCTION, url)),
        };
        assert!(held.uncommitted());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            before,
            "the previous account survives an issuance that has not finished"
        );

        // …and only the commit replaces it.
        held.commit().unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert_ne!(after, before);
        assert!(belongs_to(&after, PRODUCTION, url).is_ok());
    }

    #[test]
    fn signing_in_to_an_existing_account_has_nothing_to_commit() {
        let dir = TempDir::new();
        let path = dir.path.join("account.key");
        std::fs::write(&path, stored(PRODUCTION, ACCOUNT_URL)).unwrap();

        let reused = Pending {
            path: path.clone(),
            fresh: None,
        };
        assert!(!reused.uncommitted());
        reused.commit().unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            stored(PRODUCTION, ACCOUNT_URL),
            "a reused account rewrites nothing"
        );
    }

    #[test]
    fn what_is_waiting_to_be_written_is_not_printed() {
        let held = Pending {
            path: PathBuf::from(ACCOUNT_KEY),
            fresh: Some(stored(PRODUCTION, ACCOUNT_URL) + "secret-key-material"),
        };
        let shown = format!("{held:?}");
        assert!(!shown.contains("secret-key-material"), "{shown}");
        assert!(shown.contains(ACCOUNT_KEY), "{shown}");
        assert!(shown.contains("uncommitted: true"), "{shown}");
    }

    // ----------------------------------------------------- HTTP-01

    const TOKEN: &str = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";
    const KEY_AUTH: &str =
        "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0.9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI";

    async fn fetch(path: &str, answers: &[(&str, &str)]) -> (StatusCode, String, String) {
        use tower::ServiceExt;

        let answers: HashMap<String, String> = answers
            .iter()
            .map(|(token, key)| (token.to_string(), key.to_string()))
            .collect();
        let request = axum::http::Request::builder()
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap();
        let response = router(Arc::new(answers)).oneshot(request).await.unwrap();
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|value| value.to_str().unwrap().to_string())
            .unwrap_or_default();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        (
            status,
            content_type,
            String::from_utf8(body.to_vec()).unwrap(),
        )
    }

    #[tokio::test]
    async fn the_listener_serves_the_key_authorization_and_nothing_else() {
        let (status, content_type, body) = fetch(
            &format!("/.well-known/acme-challenge/{TOKEN}"),
            &[(TOKEN, KEY_AUTH)],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body, KEY_AUTH,
            "the key authorization, and nothing around it"
        );
        // RFC 8555 §8.3.
        assert_eq!(content_type, "application/octet-stream");
    }

    #[tokio::test]
    async fn a_token_this_hub_is_not_waiting_for_is_not_answered() {
        // An empty 200 would be read by the CA as a wrong answer; 404
        // is the truth and reads as one in a log.
        let (status, _, body) = fetch(
            "/.well-known/acme-challenge/some-other-token",
            &[(TOKEN, KEY_AUTH)],
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty(), "{body}");
    }

    #[tokio::test]
    async fn nothing_but_the_challenge_path_is_served() {
        // A hub that is briefly on port 80 must not be a web server.
        for path in [
            "/",
            "/index.html",
            "/.well-known/acme-challenge/",
            "/api/v1/peers",
        ] {
            let (status, _, _) = fetch(path, &[(TOKEN, KEY_AUTH)]).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        }
    }

    #[test]
    fn a_privileged_port_is_named_as_that_and_not_as_a_mystery() {
        let error = AcmeError::Listen {
            port: CHALLENGE_PORT,
            problem: ListenProblem::Permission,
            detail: "Permission denied (os error 13)".to_string(),
        };
        let message = error.to_string();
        assert!(message.contains("without privilege"), "{message}");
        assert!(message.contains("CAP_NET_BIND_SERVICE"), "{message}");
        // The way out that needs no port at all.
        assert!(message.contains("dns-01"), "{message}");
    }

    #[test]
    fn a_busy_port_says_what_is_probably_holding_it() {
        let error = AcmeError::Listen {
            port: CHALLENGE_PORT,
            problem: ListenProblem::InUse,
            detail: "Address already in use (os error 48)".to_string(),
        };
        let message = error.to_string();
        assert!(message.contains("nginx"), "{message}");
        // And that it is only wanted for a moment — the alternative
        // reading is "anago wants port 80 forever", which is a reason
        // to give up on the whole thing.
        assert!(message.contains("seconds"), "{message}");
        assert!(message.contains("dns-01"), "{message}");
    }

    #[test]
    fn a_family_this_host_does_not_have_is_not_something_in_the_way() {
        // An IPv4-only VPS is an ordinary VPS: the missing family is a
        // fact about the machine, and carrying on with the other one is
        // right. Anything else — a web server, a privileged port — is
        // not, and stops the run.
        for raw in [
            libc::EAFNOSUPPORT,
            libc::EPROTONOSUPPORT,
            libc::EADDRNOTAVAIL,
        ] {
            assert!(
                family_unavailable(Some(raw), io::ErrorKind::Other),
                "raw {raw}"
            );
        }
        for kind in [io::ErrorKind::Unsupported, io::ErrorKind::AddrNotAvailable] {
            assert!(family_unavailable(None, kind), "{kind:?}");
        }
        for kind in [
            io::ErrorKind::AddrInUse,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::Other,
        ] {
            assert!(!family_unavailable(None, kind), "{kind:?}");
            assert!(
                !family_unavailable(Some(libc::EADDRINUSE), kind),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn a_family_held_by_somebody_else_stops_the_run() {
        // The quiet failure this prevents: another process holds one
        // family, anago binds the other and reports success — and the
        // CA, which picks, is answered by that other process.
        let error = accept_families(
            CHALLENGE_PORT,
            1,
            &[io::Error::from(io::ErrorKind::AddrInUse)],
        )
        .expect_err("one family is held by somebody else");
        assert!(
            matches!(
                error,
                AcmeError::Listen {
                    problem: ListenProblem::InUse,
                    ..
                }
            ),
            "{error:?}"
        );
        assert!(error.to_string().contains("already listening"), "{error}");

        // Privilege is the same shape of problem.
        assert!(matches!(
            accept_families(
                CHALLENGE_PORT,
                1,
                &[io::Error::from(io::ErrorKind::PermissionDenied)]
            ),
            Err(AcmeError::Listen {
                problem: ListenProblem::Permission,
                ..
            })
        ));
    }

    #[test]
    fn one_family_is_enough_when_the_other_does_not_exist_here() {
        let missing = io::Error::from_raw_os_error(libc::EAFNOSUPPORT);
        assert_eq!(accept_families(CHALLENGE_PORT, 1, &[missing]), Ok(()));
        assert_eq!(accept_families(CHALLENGE_PORT, 2, &[]), Ok(()));

        // Neither is not enough — a hub has to be reachable somehow.
        let error = accept_families(
            CHALLENGE_PORT,
            0,
            &[
                io::Error::from_raw_os_error(libc::EAFNOSUPPORT),
                io::Error::from_raw_os_error(libc::EADDRNOTAVAIL),
            ],
        )
        .expect_err("nothing bound");
        assert!(
            matches!(error, AcmeError::NoAddressFamily { .. }),
            "{error:?}"
        );
        assert!(error.to_string().contains("neither"), "{error}");
    }

    /// A task that reports having been cancelled, so the lifecycle can
    /// be checked without a socket — the review environment has no
    /// permission to bind one, and what is being tested is ownership,
    /// not networking.
    fn parked_task(cancelled: &Arc<std::sync::atomic::AtomicBool>) -> tokio::task::JoinHandle<()> {
        struct Guard(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let guard = Guard(cancelled.clone());
        tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        })
    }

    async fn wait_for(flag: &Arc<std::sync::atomic::AtomicBool>) -> bool {
        for _ in 0..100 {
            if flag.load(std::sync::atomic::Ordering::SeqCst) {
                return true;
            }
            tokio::task::yield_now().await;
        }
        false
    }

    #[tokio::test]
    async fn dropping_the_listener_cancels_what_holds_the_port() {
        // The issuance future can be cancelled — a timeout above, an
        // abort, a panic. A `JoinHandle` that is merely dropped
        // detaches, and the serve task would keep the port with nothing
        // referring to it.
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let listener = Http01 {
            tasks: vec![parked_task(&cancelled)],
        };
        drop(listener);
        assert!(
            wait_for(&cancelled).await,
            "the serving task outlived the listener"
        );
    }

    #[tokio::test]
    async fn stopping_waits_for_the_task_to_be_gone() {
        // The difference between `stop` and `Drop`: no waiting for the
        // runtime to get round to it, so the port is free the moment
        // this returns.
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let listener = Http01 {
            tasks: vec![parked_task(&cancelled)],
        };
        listener.stop().await;
        assert!(
            cancelled.load(std::sync::atomic::Ordering::SeqCst),
            "stop returned before the task was done"
        );
    }

    /// A port nothing else is using, or `None` where this process may
    /// not bind at all (a sandbox, a container without net access).
    fn spare_port() -> Option<u16> {
        match std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)) {
            Ok(probe) => probe.local_addr().ok().map(|addr| addr.port()),
            Err(_) => None,
        }
    }

    #[tokio::test]
    async fn a_real_listener_takes_the_port_and_gives_it_back() {
        // The end-to-end version of the two tests above. Skipped rather
        // than failed where binding is not allowed: what it adds is
        // that the socket really is closed, and a sandbox cannot answer
        // that either way.
        let Some(port) = spare_port() else {
            eprintln!("skipped: this environment does not allow binding a socket");
            return;
        };

        let listener = Http01::start(port, HashMap::new()).await.expect("bound");
        assert!(
            std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).is_err(),
            "the listener is not actually holding port {port}"
        );

        listener.stop().await;
        assert!(
            std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok(),
            "port {port} is still held"
        );
    }

    #[tokio::test]
    async fn a_real_family_held_by_somebody_else_is_refused() {
        let Some(port) = spare_port() else {
            eprintln!("skipped: this environment does not allow binding a socket");
            return;
        };
        // The whole address, not just loopback: with SO_REUSEADDR the
        // BSDs let a wildcard bind sit beside a specific one, so a
        // loopback listener would not be in the way at all.
        let Ok(taken) = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)) else {
            eprintln!("skipped: this environment does not allow binding a socket");
            return;
        };

        let error = Http01::start(port, HashMap::new())
            .await
            .expect_err("IPv4 is held by this test");
        assert!(
            matches!(
                error,
                AcmeError::Listen {
                    problem: ListenProblem::InUse,
                    ..
                }
            ),
            "{error:?}"
        );
        drop(taken);
    }

    #[test]
    fn a_failed_http_01_validation_says_which_url_the_ca_asked_for() {
        // The single most useful thing to print: a person can paste it
        // into curl from another machine and see the same failure.
        let error = AcmeError::Validation {
            domain: "net.example.com".to_string(),
            challenge: Challenge::Http01,
            looked_at: vec![format!(
                "http://net.example.com/.well-known/acme-challenge/{TOKEN}"
            )],
            detail: "the CA left the order Invalid".to_string(),
        };
        let message = error.to_string();
        assert!(message.contains(TOKEN), "{message}");
        assert!(message.contains("http://net.example.com/"), "{message}");
        // Where the port has to be open: not just on the host.
        assert!(message.contains("security group"), "{message}");
        // And no offer to switch: HTTP-01 is already the port-opening
        // one, so there is nothing to be careful about.
        assert!(!message.contains("--acme-challenge"), "{message}");
    }

    #[test]
    fn a_failed_dns_01_validation_never_tells_anyone_to_open_a_port() {
        // The failure this prevents is advice that is wrong twice: the
        // person chose DNS-01 to keep :80 shut, and opening it would
        // not fix a DNS problem anyway. The CA resolves the name from
        // its own side; nothing about this machine's firewall is
        // involved.
        let error = AcmeError::Validation {
            domain: "net.example.com".to_string(),
            challenge: Challenge::Dns01,
            looked_at: vec!["the TXT record at _acme-challenge.net.example.com".to_string()],
            detail: "the CA left the order Invalid".to_string(),
        };
        let message = error.to_string();
        let (diagnosis, offer) = message.split_once('\n').expect("two parts");

        // The diagnosis says nothing about ports or firewalls.
        assert!(
            diagnosis.contains("_acme-challenge.net.example.com"),
            "{diagnosis}"
        );
        for port_advice in ["port", "firewall", "security group"] {
            assert!(
                !diagnosis.contains(port_advice),
                "DNS-01 was diagnosed as a port problem: {diagnosis}"
            );
        }
        // What it does point at: which zone actually answers, what is
        // stale, and whether the token may edit it.
        assert!(diagnosis.contains("delegated subzone"), "{diagnosis}");
        assert!(diagnosis.contains("stale"), "{diagnosis}");
        assert!(diagnosis.contains("may edit"), "{diagnosis}");

        // Port 80 appears once, in the offer, as what http-01 would
        // cost — the person's choice to make, not a fix being
        // recommended for this failure.
        assert!(offer.contains("--acme-challenge http-01"), "{offer}");
        assert!(offer.contains("did not switch"), "{offer}");
        assert_eq!(message.matches("port 80").count(), 1, "{message}");
    }

    #[test]
    fn the_certificate_and_its_key_land_private() {
        let dir = TempDir::new();
        let paths = crate::paths::ServerPaths::new(dir.path.clone());
        let issued = issued(
            "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n",
            "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
        );
        save(&paths.certificate(), &paths.private_key(), &issued).expect("saved");

        use std::os::unix::fs::PermissionsExt;
        for path in [paths.certificate(), paths.private_key()] {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", path.display());
        }
        assert_eq!(
            std::fs::metadata(paths.tls_dir())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::read_to_string(paths.private_key()).unwrap(),
            issued.expose_key()
        );
        assert_eq!(
            std::fs::read_to_string(paths.certificate()).unwrap(),
            issued.certificate
        );
        // The names the state file records (§9).
        assert!(paths.certificate().ends_with("tls/fullchain.pem"));
        assert!(paths.private_key().ends_with("tls/privkey.pem"));
    }

    #[test]
    fn a_certificate_that_cannot_be_written_leaves_the_working_pair_alone() {
        // Not just the crash window: a full disk or an unwritable path
        // on the *second* file would otherwise leave the new key beside
        // the old certificate — a mismatched pair, and a hub that will
        // not start, reported as an error that says nothing happened.
        let dir = TempDir::new();
        let paths = crate::paths::ServerPaths::new(dir.path.clone());
        let working = issued("old chain", "old key");
        save(&paths.certificate(), &paths.private_key(), &working).expect("the first pair");

        // A directory where the certificate should go: the rename
        // cannot land, and it is the second of the two.
        std::fs::remove_file(paths.certificate()).unwrap();
        std::fs::create_dir(paths.certificate()).unwrap();

        let replacement = issued("new chain", "new key");
        let error = save(&paths.certificate(), &paths.private_key(), &replacement)
            .expect_err("the certificate cannot be written");
        assert!(matches!(error, AcmeError::Write { .. }), "{error:?}");

        assert_eq!(
            std::fs::read_to_string(paths.private_key()).unwrap(),
            "old key",
            "the key that goes with the certificate on disk is the one still there"
        );
        // And nothing is left lying around for the next run to trip on.
        assert!(!paths.private_key().with_extension("pem.tmp").exists());
    }

    #[test]
    fn a_first_issuance_that_fails_halfway_leaves_no_lone_key() {
        // There is nothing to restore on a first issuance, so the undo
        // is to take the new key away again. Leaving it beside no
        // certificate is the same mismatch in a different shape — and
        // the next run would find a key it did not write.
        let dir = TempDir::new();
        let paths = crate::paths::ServerPaths::new(dir.path.clone());
        std::fs::create_dir_all(paths.tls_dir()).unwrap();
        // A directory where the certificate should go: the rename
        // cannot land, and it is the second of the two.
        std::fs::create_dir(paths.certificate()).unwrap();

        let first = issued("chain", "key");
        assert!(save(&paths.certificate(), &paths.private_key(), &first).is_err());
        assert!(
            !paths.private_key().exists(),
            "a key with no certificate was left behind"
        );
        assert!(!paths.private_key().with_extension("pem.bak").exists());
    }

    #[test]
    fn a_previous_key_that_cannot_be_read_stops_before_anything_changes() {
        // Without a copy of what is there, a failed second rename could
        // not be undone. Finding that out after publishing is too late,
        // so it is found out before.
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new();
        let paths = crate::paths::ServerPaths::new(dir.path.clone());
        let working = issued("old chain", "old key");
        save(&paths.certificate(), &paths.private_key(), &working).expect("the first pair");

        // Unreadable — as a file whose mode says so. Root ignores that,
        // so this checks what it can and skips the rest.
        std::fs::set_permissions(paths.private_key(), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        if std::fs::read(paths.private_key()).is_ok() {
            eprintln!("skipped: this process reads files regardless of mode");
            return;
        }

        let replacement = issued("new chain", "new key");
        assert!(save(&paths.certificate(), &paths.private_key(), &replacement).is_err());
        assert_eq!(
            std::fs::read_to_string(paths.certificate()).unwrap(),
            "old chain",
            "the certificate was published even though the key could not be backed up"
        );
        std::fs::set_permissions(paths.private_key(), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(paths.private_key()).unwrap(),
            "old key"
        );
    }

    #[test]
    fn a_pair_that_cannot_be_prepared_publishes_neither_half() {
        // The first failure mode: the temp write itself fails, before
        // anything is published.
        let dir = TempDir::new();
        let paths = crate::paths::ServerPaths::new(dir.path.clone());
        let working = issued("old chain", "old key");
        save(&paths.certificate(), &paths.private_key(), &working).expect("the first pair");

        let nowhere = dir.path.join("gone").join("fullchain.pem");
        let replacement = issued("new chain", "new key");
        assert!(save(&nowhere, &paths.private_key(), &replacement).is_err());
        assert_eq!(
            std::fs::read_to_string(paths.private_key()).unwrap(),
            "old key"
        );
        assert_eq!(
            std::fs::read_to_string(paths.certificate()).unwrap(),
            "old chain"
        );
    }

    #[test]
    fn an_issued_certificate_never_prints_its_key() {
        let issued = issued("chain", "-----BEGIN PRIVATE KEY-----secret-----");
        let shown = format!("{issued:?}");
        assert!(!shown.contains("secret"), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
    }

    // ------------------------------------------------------ DNS-01

    #[test]
    fn a_dns_01_failure_does_not_quietly_open_port_80() {
        // The two challenges have different blast radii (§13), and
        // somebody who chose DNS-01 may have chosen it precisely so
        // that port 80 stays shut — on a host where opening it means
        // touching a firewall, a security group, or somebody else's web
        // server. Switching for them would undo that silently and then
        // report success.
        let refused = AcmeError::Dns01 {
            domain: "net.example.com".to_string(),
            detail: "the token is not allowed to edit this zone".to_string(),
        };
        let message = refused.to_string();
        assert!(message.contains("did not switch"), "{message}");
        assert!(message.contains("--acme-challenge http-01"), "{message}");
        // Named as a choice for a person, with what it costs attached.
        assert!(message.contains("port 80 open"), "{message}");
        // And the reason it failed travels with it.
        assert!(message.contains("not allowed to edit"), "{message}");

        let never_served = AcmeError::Propagation {
            detail: "the nameservers were still not serving it".to_string(),
        };
        assert!(never_served.to_string().contains("did not switch"));
    }

    #[test]
    fn the_a_record_falls_back_where_the_challenge_does_not() {
        // Not a contradiction, a difference in what the token is doing:
        // for the A record it does a job a person can do in a browser
        // in ten seconds, and M0's instructions are printed underneath
        // (§6.1). For the challenge it is the whole mechanism.
        let same_failure = CfError::Forbidden("no".to_string());
        assert!(cfapi::fallback_notice(&same_failure).contains("Nothing else is affected"));
        assert!(!no_automatic_switch().contains("Nothing else is affected"));
    }

    #[test]
    fn a_dns_01_wait_that_saw_nothing_is_reported_beside_the_success() {
        // Blind is not failure — the certificate is real — but it is
        // the difference between "verified it was served" and "hoped",
        // and only the person can judge that.
        let blind = dnsprobe::Outcome::Blind {
            waited: Duration::from_secs(10),
        };
        let mut certificate = issued("chain", "key");
        certificate.warnings.extend(blind.warning());
        assert_eq!(certificate.warnings.len(), 1);
        assert!(certificate.warnings[0].contains("could not check DNS"));

        // A wait that saw the record says nothing extra.
        let mut quiet = issued("chain", "key");
        quiet.warnings.extend(
            dnsprobe::Outcome::Served {
                waited: Duration::from_secs(4),
            }
            .warning(),
        );
        assert!(quiet.warnings.is_empty());
    }

    #[test]
    fn a_certificate_says_nothing_extra_by_default() {
        // HTTP-01 has nothing to warn about: the listener either
        // answered or the order failed.
        assert!(issued("chain", "key").warnings.is_empty());
    }

    #[test]
    fn the_wait_for_the_ca_is_bounded() {
        // `server init` must not hang forever on a hub whose port 80
        // never opens: it has to fail with something readable (§13).
        assert!(
            VALIDATION_TIMEOUT >= Duration::from_secs(30),
            "a CA under load"
        );
        assert!(
            VALIDATION_TIMEOUT <= Duration::from_secs(300),
            "a person is waiting"
        );
    }

    #[test]
    fn no_message_carries_a_collapsed_line_continuation() {
        for error in [
            PlanError::HalfAPair {
                given: "--tls-cert",
                missing: "--tls-key",
            },
            PlanError::AcmeFlagsWithCertificate(vec!["--acme-email"]),
            PlanError::NoContact,
            PlanError::Dns01WithoutToken,
        ] {
            for line in error.to_string().lines() {
                assert!(
                    !line.trim_start().contains("  "),
                    "collapsed continuation in {line:?}"
                );
            }
        }
    }
}
