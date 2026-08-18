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

use anago_core::state::Challenge;

use crate::cfapi::Source;

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

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str = "/etc/ssl/anago/fullchain.pem";
    const KEY: &str = "/etc/ssl/anago/privkey.pem";
    const EMAIL: &str = "jo@example.com";

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
