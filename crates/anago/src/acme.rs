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

use std::fmt;
use std::path::{Path, PathBuf};

use anago_core::state::{Acme, Challenge};

use crate::cfapi::Source;
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
