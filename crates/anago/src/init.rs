//! `anago server init` (DESIGN.md §6.1, §11).
//!
//! Keys, the state file, and the two things that used to be the
//! operator's alone: pointing DNS at this machine and getting a
//! certificate. With a Cloudflare token the A record is written here;
//! without one, M0's instruction to add it by hand is printed
//! unchanged. The certificate is either one the operator named or one
//! anago orders (§8).
//!
//! [`run`] is the only thing here that touches disk, the network, or
//! `wg`; the order it does them in is what makes a failed init leave
//! nothing behind, and its own doc comment is where that is written
//! down. Everything else — what to say, what to record, what to undo —
//! is a pure function of what was decided.

use std::fmt;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};

use anago_core::code::{IssuedCode, JoinCode, DEFAULT_TTL_SECS};
use anago_core::render;
use anago_core::state::{Acme, Challenge, Cloudflare, PrivateKey, ServerKeys, ServerState, Tls};
use anago_core::wgconf;

use crate::acme;
use crate::cfapi;
use crate::cli::ServerInit;
use crate::fsutil;
use crate::paths::{self, ServerPaths};
use crate::secret;
use crate::systemd;
use crate::wg::{self, WgError};

/// Builds the initial state. Pure — the keys, the clock, and the code
/// come from the caller.
///
/// This runs **before** the CA is called, because ordering a
/// certificate needs a state to order it against: the account key path,
/// the CA, the challenge and the contact all live here. What the CA
/// answers is written back by [`acme::record`] afterwards, which is why
/// `account_url` starts empty and `renew_after` starts at zero — a hub
/// with no certificate yet is a hub that is due for one.
pub fn build_state(
    args: &ServerInit,
    setup: &Setup,
    keys: (PrivateKey, String),
    code: JoinCode,
    now: i64,
) -> ServerState {
    let (private_key, public_key) = keys;
    let certificate = &setup.certificate;
    let tls = match &setup.decision.plan {
        acme::Plan::Manual { .. } => Tls::manual(&certificate.cert, &certificate.key),
        acme::Plan::Acme {
            directory,
            challenge,
            contact,
            ..
        } => Tls::acme(
            &certificate.cert,
            &certificate.key,
            Acme {
                directory: directory.to_string(),
                contact: Some(contact.clone()),
                account_key_path: certificate.account_key.clone(),
                // Filled in by `acme::record` once the CA has answered.
                account_url: String::new(),
                challenge: *challenge,
                issued_at: 0,
                renew_after: 0,
            },
        ),
    };
    ServerState {
        domain: args.domain.clone(),
        subnet: args.subnet,
        listen_port: args.listen_port,
        api_port: args.api_port,
        tls,
        cloudflare: setup.dns.recorded(setup.token_path.clone()),
        server: ServerKeys {
            private_key,
            public_key,
            // The hub is always the subnet's .1 (§5).
            address: args.subnet.server_address(),
        },
        peers: Vec::new(),
        // The first code is issued here so `server init` ends with a
        // line the operator can paste on their laptop (§6.1 step 5).
        codes: vec![IssuedCode::issue(code, now, DEFAULT_TTL_SECS)],
    }
}

/// What to print when the hub is up: what anago did, and what is still
/// the operator's to do.
///
/// **The two are kept apart on purpose.** M1 automates two of the
/// things M0 asked for by hand, and a list that mixes "this is done"
/// with "you must do this" is a list nobody reads to the end. So one
/// section reports — the A record, the certificate and when it runs
/// out — and the other asks, numbered, with nothing in it that has
/// already happened.
///
/// The reporting section disappears entirely when there is nothing in
/// it. A hub set up the M0 way — a certificate of the operator's, no
/// Cloudflare token — gets M0's output, because that is still exactly
/// what happened.
///
/// `public_ip` is best-effort. When the lookup failed, the A record
/// line keeps a placeholder instead of inventing an address — a wrong
/// IP in a copy-pasteable instruction is worse than an obvious blank.
pub fn instructions(
    state: &ServerState,
    dns: &Dns,
    public_ip: Option<Ipv4Addr>,
    ttl_secs: i64,
    now: i64,
) -> String {
    let domain = &state.domain;
    let mut out = format!("anago is set up for {domain}.\n");
    out.push_str(&done_for_you(state, dns, now));
    out.push_str(&still_yours(state, dns, public_ip, now));
    out.push_str(&join_line(state, ttl_secs));
    out
}

/// What anago did, and nothing else.
fn done_for_you(state: &ServerState, dns: &Dns, now: i64) -> String {
    let mut items = Vec::new();
    if let ARecord::Written(applied) = &dns.record {
        // `Applied` already reads as a sentence about what happened
        // ("created the A record…"), so a heading in front of it
        // would only repeat the word after the dash.
        items.push(format!("{applied}\n"));
    }
    if let Some(acme) = state.tls.renewable() {
        // The wording, the two dates and the staging warning are
        // core's (§8), so `server init` and `server renew` cannot
        // drift into saying the same thing differently.
        items.push(render::certificate_ready(
            &state.domain,
            acme.challenge,
            state.tls.not_after,
            acme.renew_after,
            now,
            acme.directory == acme::STAGING,
            false,
        ));
    }
    if items.is_empty() {
        return "\n".to_string();
    }

    let mut out = String::from("\nanago did these for you:\n\n");
    for item in items {
        for line in item.lines() {
            out.push_str(&format!("  {line}\n"));
        }
    }
    out.push('\n');
    out
}

/// What the operator still has to do, numbered from one.
fn still_yours(state: &ServerState, dns: &Dns, public_ip: Option<Ipv4Addr>, now: i64) -> String {
    let mut step = Steps::new();
    let mut out = String::from("Still yours to do:\n\n");

    if dns.is_by_hand() {
        out.push_str(&format!(
            "{}. DNS — point the domain at this machine:\n\n",
            step.next()
        ));
        out.push_str(&format!(
            "     {}.  A  {}\n\n",
            state.domain,
            address_line(public_ip)
        ));
        if public_ip.is_none() {
            out.push_str(
                "   (anago could not work out this machine's public address; use the one\n\
                 \x20   your provider shows.)\n\n",
            );
        } else {
            out.push_str(
                "   (that is the address this machine sends traffic from; if the server is\n\
                 \x20   behind NAT, use the public address your provider shows instead.)\n\n",
            );
        }
        if dns.zone_id.is_none() {
            // No token, so anago does not know the provider — but the
            // trap below is not Cloudflare's alone.
            out.push_str(
                "   (if your DNS provider puts a proxy or CDN in front of the record, leave\n\
                 \x20   it off: WireGuard's UDP port does not survive one.)\n\n",
            );
        }
    }

    out.push_str(&format!(
        "{}. Firewall — open these, or nothing can reach the hub:\n\n",
        step.next()
    ));
    out.push_str(&format!(
        "     {}/tcp   control API (HTTPS)\n",
        state.api_port
    ));
    out.push_str(&format!("     {}/udp WireGuard\n", state.listen_port));
    // A home hub sits behind a consumer router (often two — ISP box
    // plus your own): the same ports must be forwarded there to this
    // machine, on every layer (§11.1 결정 5).
    if cfg!(windows) {
        out.push_str(&format!(
            "\n     Windows Defender (elevated PowerShell):\n\
             \x20      netsh advfirewall firewall add rule name=\"anago api\" dir=in action=allow protocol=TCP localport={}\n\
             \x20      netsh advfirewall firewall add rule name=\"anago wg\" dir=in action=allow protocol=UDP localport={}\n\
             \x20    And IPv4 forwarding, so devices can reach each other through this hub:\n\
             \x20      Set-NetIPInterface -InterfaceAlias anago -Forwarding Enabled\n\
             \x20    Home network: forward the same ports on your router(s) to this PC.\n",
            state.api_port, state.listen_port
        ));
    } else {
        out.push_str(
            "\n     Home network: if this hub sits behind a router, forward the same\n\
             \x20    ports there to this machine (two routers = forward on both).\n",
        );
    }
    if wants_port_80(state) {
        // HTTP-01 answers the challenge on :80 again at every renewal.
        // A firewall that let the first issuance through and was then
        // tightened is a hub that stops renewing months later (§9.1).
        out.push_str("     80/tcp    certificate renewal, now and at every renewal\n");
    }
    out.push('\n');

    if dns.zone_id.is_some() {
        // §13's worst trap, and it gets worse the more anago
        // automates: a proxied record still passes HTTP-01 and its TXT
        // records are not proxied at all, so the certificate arrives,
        // HTTPS works, every line above is green — and the tunnel is
        // dead. Nothing anago can see says so, which is exactly why it
        // has to be asked of a person.
        out.push_str(&format!(
            "{}. Cloudflare — check the A record is DNS only:\n\n",
            step.next()
        ));
        out.push_str(
            "     The cloud beside it must be grey, not orange. A proxied record still\n\
             \x20    gets a certificate and still serves HTTPS, so nothing above would have\n\
             \x20    failed — but WireGuard's UDP port is not forwarded through the proxy,\n\
             \x20    and devices would join and then reach nothing.\n\n",
        );
    }

    if state.tls.renewable().is_none() {
        // A manual certificate has an owner and it is not anago
        // (§9.1). Saying when it runs out is the whole of what anago
        // can do about it.
        out.push_str(&format!(
            "{}. Certificate — keep it up to date yourself:\n\n",
            step.next()
        ));
        out.push_str(&format!(
            "     anago serves {} and never rewrites it. {}\n\n",
            state.tls.cert_path,
            match state.tls.not_after {
                Some(not_after) => format!(
                    "It expires {}.",
                    render::format_in(not_after.saturating_sub(now))
                ),
                None => "Its expiry could not be read.".to_string(),
            }
        ));
    }
    out
}

/// The line to paste on the first device.
fn join_line(state: &ServerState, ttl_secs: i64) -> String {
    let code = state
        .codes
        .last()
        .map(|issued| issued.code.to_string())
        .unwrap_or_default();
    format!(
        "Then add a device — run this on it:\n\n     anago join {} {code}\n\n\
         That code is single use and expires in {} minutes; `anago code` issues another.\n",
        state.domain,
        ttl_secs / 60
    )
}

/// Numbers the steps that are actually printed, so a list that loses
/// its DNS entry still reads "1." and not "2.".
struct Steps(usize);

impl Steps {
    fn new() -> Steps {
        Steps(0)
    }

    fn next(&mut self) -> usize {
        self.0 += 1;
        self.0
    }
}

fn address_line(public_ip: Option<Ipv4Addr>) -> String {
    match public_ip {
        Some(ip) => ip.to_string(),
        None => "<this server's public IP>".to_string(),
    }
}

/// Whether the firewall list should mention port 80.
///
/// Only an HTTP-01 hub needs it, and it needs it for ever — the
/// challenge is answered again at every renewal.
pub fn wants_port_80(state: &ServerState) -> bool {
    matches!(
        state.tls.renewable().map(|acme| acme.challenge),
        Some(Challenge::Http01)
    )
}

/// This machine's outbound address, when that address is one the world
/// could actually reach.
///
/// No packet is sent: connecting a UDP socket only fixes which local
/// address the kernel would use for that destination. On a plain VPS
/// that is the public address — but on AWS, GCP, and anything else that
/// 1:1 NATs a public address onto a private NIC, it is a `10.x` the
/// operator must not put in DNS. Those are filtered out by
/// [`routable_address`], so the instructions fall back to a placeholder
/// rather than printing a pasteable lie.
pub fn detect_public_ip() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    match socket.local_addr().ok()? {
        std::net::SocketAddr::V4(addr) => routable_address(*addr.ip()),
        std::net::SocketAddr::V6(_) => None,
    }
}

/// Keeps only addresses that can appear in a public A record.
///
/// Pure, so every range below is a test rather than a claim.
pub fn routable_address(ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let [a, b, ..] = ip.octets();
    let carrier_grade_nat = a == 100 && (64..=127).contains(&b);
    let reserved = ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || ip.is_unspecified()
        || carrier_grade_nat
        || a == 0
        || a >= 240;
    if reserved {
        None
    } else {
        Some(ip)
    }
}

/// What `server init` produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Initialized {
    pub instructions: String,
    /// Non-fatal notes about the certificate files, from [`tls::load`].
    pub warnings: Vec<String>,
}

/// The certificate files this hub will serve, and where the ACME
/// account that renews them lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub cert: String,
    pub key: String,
    /// Recorded even on the manual path, where nothing reads it: the
    /// field is what a later `server renew --acme-email` writes its
    /// account into, and a path is not a secret.
    pub account_key: String,
}

/// What `server init` settled before it touched anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// How this hub will have a certificate.
    pub plan: acme::Plan,
    /// Where a Cloudflare token was found, if anywhere.
    pub token: Option<cfapi::Source>,
}

impl Decision {
    /// The certificate and key this hub will serve.
    ///
    /// Known before either exists: the manual path names them, and the
    /// ACME path puts them where §9 fixes. That is what lets the state
    /// be built before the CA is called and recorded after.
    pub fn certificate(&self, paths: &ServerPaths) -> Certificate {
        let account_key = paths.account_key().display().to_string();
        match &self.plan {
            acme::Plan::Manual { cert, key } => Certificate {
                cert: cert.clone(),
                key: key.clone(),
                account_key,
            },
            acme::Plan::Acme { .. } => Certificate {
                cert: paths.certificate().display().to_string(),
                key: paths.private_key().display().to_string(),
                account_key,
            },
        }
    }
}

/// Settles which TLS path `server init` takes, and whether there is a
/// Cloudflare token to do DNS with (§8).
///
/// The environment is a parameter rather than something read here, so
/// the precedence between the three ways a token arrives is a unit test
/// — and the rules themselves belong to [`cfapi::choose`] and
/// [`acme::plan`], which own them. `cli` already ran the same two checks
/// over argv alone; this is the run that can also see
/// `CLOUDFLARE_API_TOKEN`, and so the one that decides.
pub fn decide(args: &ServerInit, env: Option<&str>) -> Result<Decision, InitError> {
    let token = cfapi::choose(
        args.cf_token_file.as_deref(),
        args.cf_token.as_ref().map(cfapi::Token::expose),
        env,
    )
    .map_err(InitError::Cloudflare)?;

    let plan = acme::plan(&acme::Request {
        tls_cert: args.tls_cert.as_deref(),
        tls_key: args.tls_key.as_deref(),
        acme_email: args.acme_email.as_deref(),
        staging: args.acme_staging,
        challenge: args.acme_challenge,
        token: token.as_ref(),
    })
    .map_err(InitError::Plan)?;

    Ok(Decision { plan, token })
}

/// Everything `server init` settled before it built the state.
///
/// One value rather than four arguments, because the four are one
/// decision: which certificate path follows from which plan, and
/// whether the token is kept follows from the plan **and** from whether
/// a record was written at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    pub decision: Decision,
    pub certificate: Certificate,
    pub dns: Dns,
    /// Where the token will be kept, and `None` when it is not kept —
    /// see [`Setup::new`].
    pub token_path: Option<String>,
}

impl Setup {
    /// Puts the four together, which is where the one rule that spans
    /// them is applied.
    ///
    /// **The token is written to disk only when DNS-01 renewal will
    /// need it again** (§9.1). A hub that used the token to write an A
    /// record and then took its certificate over HTTP-01 forgets it the
    /// moment `server init` ends: the secret that can be got rid of is
    /// got rid of (§7.1).
    /// The test for the token is the *plan*, not whether a record was
    /// written. A DNS-01 hub answers its challenge in TXT; the A record
    /// is a separate job the same token happens to do, and a hub that
    /// could not write one still has to renew.
    pub fn new(decision: Decision, dns: Dns, paths: &ServerPaths) -> Setup {
        let keeps_token = decision.plan.needs_token() && dns.zone_id.is_some();
        Setup {
            certificate: decision.certificate(paths),
            token_path: keeps_token.then(|| paths.cf_token().display().to_string()),
            decision,
            dns,
        }
    }

    /// Whether the token is one of the files [`publish`] writes.
    pub fn keeps_token(&self) -> bool {
        self.token_path.is_some()
    }
}

/// What `server init` found and did about DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dns {
    /// The zone the domain lives in — known whenever there was a token
    /// to look it up with, **whether or not a record was written**.
    ///
    /// The two are separate on purpose. A DNS-01 hub answers its
    /// challenge in TXT and needs no A record at all, so tying the zone
    /// to whether one was written is how a hub ends up issuing its
    /// first certificate and then being unable to renew it (§9.1).
    pub zone_id: Option<String>,
    pub record: ARecord,
}

/// What happened to the hub's A record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ARecord {
    /// Written through the Cloudflare API — or found already right.
    Written(cfapi::Applied),
    /// Nothing was written, and the operator has to add the record.
    /// M0's path, kept whenever there is no token — and whenever there
    /// is one but anago could not work out what address to point it at.
    ByHand(ByHand),
}

/// Why the A record is still the operator's to add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ByHand {
    /// No Cloudflare token anywhere (§8). The ordinary M0 case.
    NoToken,
    /// A token, but no address to point the record at. anago will not
    /// invent one: a wrong A record is worse than an absent one,
    /// because everything downstream then reports success against a
    /// hub nobody can reach.
    NoAddress,
}

impl Dns {
    /// Nothing looked up and nothing written — no token anywhere.
    fn none() -> Dns {
        Dns {
            zone_id: None,
            record: ARecord::ByHand(ByHand::NoToken),
        }
    }

    /// Whether the operator still has to add the record — which is
    /// what decides whether the output asks them to.
    pub fn is_by_hand(&self) -> bool {
        matches!(self.record, ARecord::ByHand(_))
    }

    /// What goes in the state file.
    ///
    /// `None` only when there is no zone: caching one anago never
    /// looked up would claim knowledge it does not have. **The record
    /// id is what goes missing when nothing was written**, not the
    /// whole of the Cloudflare settings — the zone and the token are
    /// what a DNS-01 renewal needs, and it needs them either way.
    pub fn recorded(&self, token_path: Option<String>) -> Option<Cloudflare> {
        Some(Cloudflare {
            zone_id: self.zone_id.clone()?,
            record_id: match &self.record {
                ARecord::Written(applied) => Some(applied.record_id().to_string()),
                ARecord::ByHand(_) => None,
            },
            token_path,
        })
    }
}

/// What [`point_dns`] came back with.
struct Pointed {
    dns: Dns,
    /// The token, once read. Kept even when no record was written: a
    /// DNS-01 challenge needs the token and no A record at all.
    token: Option<cfapi::Token>,
    /// The zone the domain lives in, when it was looked up.
    ///
    /// Carried whole rather than as an id, because a DNS-01 challenge
    /// is watched at the zone's **nameservers** and those are in here.
    /// Rebuilding a `Zone` from the id alone would leave every first
    /// issuance blind (§9.1).
    zone: Option<cfapi::Zone>,
}

/// Points the domain at this machine, when anago can (§6.1 step 2).
///
/// **Human verification needed**: this talks to a real Cloudflare zone.
fn point_dns(
    decision: &Decision,
    domain: &str,
    address: Option<Ipv4Addr>,
    flag: Option<&str>,
    env: Option<&str>,
    warnings: &mut Vec<String>,
) -> Result<Pointed, InitError> {
    let Some(source) = decision.token.clone() else {
        return Ok(Pointed {
            dns: Dns::none(),
            token: None,
            zone: None,
        });
    };

    let loaded = cfapi::load(source, flag, env).map_err(InitError::Cloudflare)?;
    if let Some(warning) = loaded.warning {
        warnings.push(warning);
    }
    let zone = cfapi::find_zone(&loaded.token, domain).map_err(InitError::Cloudflare)?;

    let Some(address) = address else {
        // The token is still worth having — a DNS-01 challenge answers
        // in TXT and needs no A record at all — so this is a warning
        // and M0's instruction, not a refusal.
        warnings.push(
            "anago could not work out this machine's public address, so it left DNS \
             alone — the A record below is still yours to add"
                .to_string(),
        );
        return Ok(Pointed {
            dns: Dns {
                zone_id: Some(zone.id.clone()),
                record: ARecord::ByHand(ByHand::NoAddress),
            },
            token: Some(loaded.token),
            zone: Some(zone),
        });
    };

    // No cached id on a first init: there is no state file to have
    // cached one in.
    let written = cfapi::apply_record(&loaded.token, &zone.id, domain, address, None)
        .map_err(InitError::Cloudflare)?;
    if let Some(warning) = written.warning {
        warnings.push(warning);
    }
    Ok(Pointed {
        dns: Dns {
            zone_id: Some(zone.id.clone()),
            record: ARecord::Written(written.applied),
        },
        token: Some(loaded.token),
        zone: Some(zone),
    })
}

/// Runs the command: refuse, decide, do, publish, explain (§6.1).
///
/// **The order is the point, and M1 does not weaken it.** Everything
/// that can refuse for free happens before anything is touched, and
/// before the lock file is even made: an existing hub, a combination of
/// flags that cannot work, missing WireGuard tools, a certificate the
/// operator named that will not load. Then the lock — held from before
/// the first outside change, so that two inits cannot both register an
/// ACME account over one `account.key` (§9.1). Then the two steps that
/// reach outside, the A record and the certificate. Then the files that
/// make this machine a hub, published together and last.
///
/// **A failed run leaves nothing behind.** The state file, the wg
/// config and the Cloudflare token go together or not at all
/// ([`publish`]), and the files an issuance writes before any of them
/// exist — `account.key` and the certificate pair — are removed by
/// [`Issuance`] if the run does not reach the end. In both cases only
/// what *this* run created: a file that was already there belongs to
/// somebody else and is never ours to remove. So a failure means this
/// machine is not a hub, and running the same command again works.
///
/// The one thing not undone is **the A record.** It is a change to the
/// world, it is the record the operator would have added by hand, and
/// it is right whether or not the rest of this command finished;
/// deleting it on the way out would break a domain that was working
/// before. A certificate that was issued and then discarded is
/// reported as such — the files are gone, but the CA counted it
/// against a weekly allowance a few retries can exhaust (§13).
///
/// **Human verification needed** for the parts that need a real
/// machine and real accounts: `wg genkey`, writing under `/var/lib` and
/// `/etc/wireguard`, the Cloudflare zone, the CA, and whether the
/// detected address is really this server's public one.
pub fn run(
    args: &ServerInit,
    root: &Path,
    wg_dir: &Path,
    now: i64,
) -> Result<Initialized, InitError> {
    let paths = ServerPaths::new(root);
    let mut warnings = Vec::new();

    // --- Everything that can refuse without touching anything.
    check_not_initialized(root, wg_dir)?;
    let env = std::env::var(cfapi::TOKEN_ENV).ok();
    // The full verdict on the flags, environment included — routing
    // settled everything argv could settle on its own (§8).
    let decision = decide(args, env.as_deref())?;
    wg::check_tools_from_env().map_err(InitError::Wg)?;
    // M0's refusal, and it stays where M0 put it: a certificate the
    // operator named is on disk *now*, so a wrong path or a mismatched
    // pair costs nothing to catch — and catching it later would mean a
    // typo in `--tls-cert` had already rewritten their DNS.
    let mut loaded = match &decision.plan {
        acme::Plan::Manual { cert, key } => {
            Some(crate::tls::load(Path::new(cert), Path::new(key)).map_err(InitError::Tls)?)
        }
        // Nothing to check yet: this pair does not exist until the CA
        // has answered.
        acme::Plan::Acme { .. } => None,
    };

    // --- One winner from here on.
    //
    // The lock goes on **before the first outside change**, not around
    // the publish at the end. Two inits racing past this point would
    // both register an ACME account and both write the same
    // `account.key` and certificate pair; the one that lost the publish
    // would have left the files, so the winner's state file would name
    // one account and the credentials on disk another — and every
    // renewal after that is refused as the wrong account (§9.1).
    let _init = lock(root)?;
    // Again, now that nothing else can get in: the check above is a
    // courtesy that fails before the lock file is even made.
    check_not_initialized(root, wg_dir)?;

    // --- The two steps that reach outside this machine.
    let address = detect_public_ip();
    let pointed = point_dns(
        &decision,
        &args.domain,
        address,
        args.cf_token.as_ref().map(cfapi::Token::expose),
        env.as_deref(),
        &mut warnings,
    )?;
    let dns = pointed.dns;

    let setup = Setup::new(decision, dns, &paths);
    let keys = wg::generate_keypair().map_err(InitError::Wg)?;
    let code = secret::new_join_code().map_err(|e| InitError::Io {
        what: "read /dev/urandom",
        kind: e.kind(),
        source: e.to_string(),
    })?;
    let mut state = build_state(args, &setup, keys, code, now);

    // Nothing to undo on the manual path: those files are the
    // operator's and this run never goes near them.
    let mut issuance = Issuance::nothing();
    if state.tls.renewable().is_some() {
        // **Armed before the call, not after it comes back.** An
        // issuance writes the account file first and the certificate
        // pair after it, so a failure in between returns nothing to
        // arm a guard with — and leaves an account this run made.
        issuance = Issuance::watching(&paths);
        let issued = obtain(&state, &paths, pointed.token.clone(), pointed.zone, now)?;
        warnings.extend(issued.warnings.iter().cloned());
        acme::record(&mut state, &issued, now);
    }

    // The other half of the same check: a pair anago has just written
    // and cannot serve. Still before anything of ours is published, so
    // either way a bad pair is a hub that was never made rather than
    // one that will not start.
    let loaded = match loaded.take() {
        Some(loaded) => loaded,
        None => crate::tls::load(
            Path::new(&state.tls.cert_path),
            Path::new(&state.tls.key_path),
        )
        .map_err(|e| finished_but_unpublished(InitError::Tls(e), &state))?,
    };
    // §9.1 fills `not_after` for a manual certificate too: anago does
    // not renew it, but it can say when it runs out — which is the
    // whole of what the output can do about a file it does not own.
    // For an ACME hub this is the same certificate `record` already
    // read, now confirmed from the file that will actually be served.
    state.tls.not_after = loaded.not_after;
    warnings.extend(loaded.warnings);

    // --- The point of no return: after this, the machine is a hub.
    publish(
        &state,
        root,
        wg_dir,
        setup
            .keeps_token()
            .then_some(pointed.token.as_ref())
            .flatten(),
    )
    .map_err(|e| finished_but_unpublished(e, &state))?;
    // The state file is there, so what the issuance wrote is now the
    // hub's and stays.
    issuance.keep();

    // No systemd on this host means no unit to install, whatever the
    // flag says — offering one would leave a file nothing reads.
    // The platform's service manager, behind one seam (§11.1 결정 3):
    // systemd, the Windows SCM, or launchd. No manager on this host
    // means nothing to install, whatever the flag says.
    let start = if args.systemd && crate::service::is_available() {
        match crate::service::install(
            &std::env::current_exe().unwrap_or_else(|_| PathBuf::from("anago")),
            root,
            wg_dir,
            Path::new(&state.tls.cert_path),
            Path::new(&state.tls.key_path),
        ) {
            Ok(note) => note,
            Err(e) => {
                // The hub is configured either way; only the babysitter
                // is missing, and the operator can still run it by hand.
                warnings.push(format!("could not install the hub service: {e}"));
                foreground_hint()
            }
        }
    } else {
        foreground_hint()
    };

    Ok(Initialized {
        instructions: assemble(
            &instructions(&state, &setup.dns, address, DEFAULT_TTL_SECS, now),
            &start,
        ),
        warnings,
    })
}

/// Orders the certificate (§6.1 step 3).
///
/// The token and zone go in rather than being looked up: `point_dns`
/// has just used them, and the token is not on disk yet — it is
/// published with the state file, not before it.
///
/// **Human verification needed**: this talks to a real CA.
fn obtain(
    state: &ServerState,
    paths: &ServerPaths,
    token: Option<cfapi::Token>,
    zone: Option<cfapi::Zone>,
    now: i64,
) -> Result<acme::Renewed, InitError> {
    let ready = token.zip(zone);
    acme::renew_blocking(state, paths, ready, now).map_err(InitError::Acme)
}

/// A failure after the certificate is in hand.
///
/// The distinction matters to whoever retries. The certificate is gone
/// with everything else this run wrote, but it was still **paid for**:
/// Let's Encrypt counts it against a weekly allowance for this domain
/// that a handful of retries can exhaust. Saying so is the difference
/// between a person retrying with their eyes open and one wondering
/// why the CA has started refusing them.
fn finished_but_unpublished(error: InitError, state: &ServerState) -> InitError {
    if state.tls.renewable().is_none() {
        return error;
    }
    InitError::AfterIssuance {
        source: Box::new(error),
    }
}

/// The finished output: what the operator must do, then how this hub
/// starts. Exactly one start note, so nothing can contradict it.
pub fn assemble(instructions: &str, start_note: &str) -> String {
    format!("{instructions}\n{start_note}")
}

/// What `server init` says when systemd took over.
pub fn systemd_note(unit_path: &Path) -> String {
    format!(
        "The hub is running under systemd ({}) and comes back on reboot.\n\
         `systemctl status anago` shows it, `journalctl -u anago` its log.\n",
        unit_path.display()
    )
}

/// What to run when nothing will run it for you — `--no-systemd`, a
/// container, or a failed unit install.
pub fn foreground_hint() -> String {
    "Start the hub with:\n\n     anago server run\n\n     It stays in the foreground; nothing keeps it alive across a reboot.\n"
        .to_string()
}

/// Refuses when either output is already there.
///
/// Checking the wg config too: overwriting a live `anago.conf` would
/// take down whatever interface it describes, and it may not even be
/// anago's.
pub fn check_not_initialized(root: &Path, wg_dir: &Path) -> Result<(), InitError> {
    let state_file = ServerPaths::new(root).state_file();
    if state_file.exists() {
        return Err(InitError::AlreadyInitialized(
            state_file.display().to_string(),
        ));
    }
    let config_path = paths::wg_config(wg_dir);
    if config_path.exists() {
        return Err(InitError::ConfigExists(config_path.display().to_string()));
    }
    Ok(())
}

/// Takes the lock that makes `server init` a one-winner command.
///
/// Held from before the first change outside this machine to after the
/// last file is written. The earlier [`check_not_initialized`] is a
/// courtesy — it fails fast, before even this lock file exists. This is
/// the one that decides.
///
/// It **waits** rather than giving up. An init that walked away because
/// another one held the lock for a moment would be worse than one that
/// queued; the renewal timer is the only caller in this codebase with a
/// reason to do otherwise (§9.1).
pub fn lock(root: &Path) -> Result<fsutil::FileLock, InitError> {
    // The lock lives beside the state file, so the directory has to
    // exist first. An empty directory is not a hub — the state file is.
    fsutil::ensure_private_dir(root).map_err(|e| InitError::Io {
        what: "create the state directory",
        kind: e.kind(),
        source: e.to_string(),
    })?;
    fsutil::FileLock::acquire(&ServerPaths::new(root).state_lock()).map_err(|e| InitError::Io {
        what: "take the initialization lock",
        kind: e.kind(),
        source: e.to_string(),
    })
}

/// Undoes an issuance that the rest of `server init` did not finish.
///
/// Ordering a certificate writes three files before there is a hub to
/// own them, and if the command fails after that they are a private key
/// and an account sitting on a machine that is not a hub. Nothing ever
/// comes back for them: a later `server init` orders a fresh
/// certificate whatever is on disk, so keeping them buys nothing and
/// leaves a secret behind — the same reasoning that keeps the
/// Cloudflare token out of the way until the state file is written
/// (§7.1).
///
/// **Only what this run created.** Which of the three were already
/// there is recorded before the CA is called, so a file that predates
/// this run — an operator's own, or one a previous attempt left — is
/// never removed by us.
///
/// It is **armed by being made**, and it is made just before the CA is
/// called. There is no "the issuance finished" flag to set, because
/// finishing is not what this guards against: an issuance writes the
/// account file first and the certificate pair after it (§9.1), so the
/// failure most in need of sweeping is the one that comes back with no
/// result to learn anything from.
struct Issuance {
    /// The files that did **not** exist when this run reached the CA.
    /// Empty on the manual path, where nothing is ordered and these
    /// paths are not this run's to touch.
    candidates: Vec<PathBuf>,
    keep: bool,
}

impl Issuance {
    /// A guard over the files an issuance may create, from now on.
    fn watching(paths: &ServerPaths) -> Issuance {
        let candidates = [
            paths.account_key(),
            paths.certificate(),
            paths.private_key(),
        ]
        .into_iter()
        .filter(|path| !path.exists())
        .collect();
        Issuance {
            candidates,
            keep: false,
        }
    }

    /// No issuance to undo.
    fn nothing() -> Issuance {
        Issuance {
            candidates: Vec::new(),
            keep: false,
        }
    }

    fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for Issuance {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        for path in &self.candidates {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Writes the files that make this machine a hub, state last, and
/// removes what it created if a later write fails.
///
/// The state file is the marker for "this machine is a hub", so it must
/// not exist unless everything beside it does. Every file here goes
/// through [`fsutil::create_new_private`], which refuses to replace an
/// existing one — so anything that appeared after the check belongs to
/// somebody else, is left alone, and **is never rolled back by us**.
/// That is why the rollback works off what this call actually created
/// rather than off the paths it might have.
///
/// The Cloudflare token, when it is kept at all (§9.1), is published
/// here rather than earlier for the same reason as the rest: a secret
/// written for a `server init` that then failed is a secret sitting on
/// a machine that is not a hub, and nothing would ever come back for
/// it.
pub fn publish(
    state: &ServerState,
    root: &Path,
    wg_dir: &Path,
    token: Option<&cfapi::Token>,
) -> Result<(), InitError> {
    let mut created = Vec::new();
    let published = write_all(state, root, wg_dir, token, &mut created);
    if published.is_err() {
        // Newest first, so the state file — if it somehow got there —
        // stops being the marker before anything under it goes.
        for path in created.iter().rev() {
            let _ = std::fs::remove_file(path);
        }
    }
    published
}

/// The writes themselves, recording each one as it lands.
///
/// Split out so that `created` is the record of what happened rather
/// than a guess: a file that failed with `AlreadyExists` is somebody
/// else's and never reaches this list.
fn write_all(
    state: &ServerState,
    root: &Path,
    wg_dir: &Path,
    token: Option<&cfapi::Token>,
    created: &mut Vec<PathBuf>,
) -> Result<(), InitError> {
    fsutil::ensure_private_dir(wg_dir).map_err(|e| InitError::Io {
        what: "create the WireGuard directory",
        kind: e.kind(),
        source: e.to_string(),
    })?;
    let config_path = paths::wg_config(wg_dir);
    fsutil::create_new_private(&config_path, wgconf::server_config(state).expose()).map_err(
        |e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                InitError::ConfigExists(config_path.display().to_string())
            } else {
                InitError::Io {
                    what: "write the WireGuard config",
                    kind: e.kind(),
                    source: e.to_string(),
                }
            }
        },
    )?;
    created.push(config_path);

    fsutil::ensure_private_dir(root).map_err(|e| InitError::Io {
        what: "create the state directory",
        kind: e.kind(),
        source: e.to_string(),
    })?;

    let server = ServerPaths::new(root);
    if let Some(token) = token {
        let token_file = server.cf_token();
        fsutil::create_new_private(&token_file, token.expose()).map_err(|e| InitError::Io {
            what: "write the Cloudflare token",
            kind: e.kind(),
            source: e.to_string(),
        })?;
        created.push(token_file);
    }

    let state_file = server.state_file();
    fsutil::create_new_private(&state_file, &state.to_json_string()).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            InitError::AlreadyInitialized(state_file.display().to_string())
        } else {
            InitError::Io {
                what: "write the state file",
                kind: e.kind(),
                source: e.to_string(),
            }
        }
    })?;
    created.push(state_file);
    Ok(())
}

/// Why `server init` could not finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitError {
    /// A state file is already there.
    AlreadyInitialized(String),
    /// A WireGuard config with anago's name is already there.
    ConfigExists(String),
    /// The certificate and key could not be loaded.
    Tls(crate::tls::TlsError),
    /// The flags do not describe a hub anago can set up.
    Plan(acme::PlanError),
    /// The Cloudflare token could not be settled on.
    Cloudflare(cfapi::CfError),
    /// The CA would not issue.
    Acme(acme::AcmeError),
    /// A failure that happened **after** the certificate was in hand.
    /// Carried separately because the retry advice differs: the
    /// account is reusable, the certificate is not free.
    AfterIssuance { source: Box<InitError> },
    /// The WireGuard tools are missing, or one of them failed.
    Wg(WgError),
    Io {
        what: &'static str,
        kind: std::io::ErrorKind,
        source: String,
    },
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InitError::AlreadyInitialized(path) => write!(
                f,
                "this machine is already a hub — {path} exists. \
                 Remove it to start over, but every registered device \
                 will have to join again"
            ),
            InitError::ConfigExists(path) => write!(
                f,
                "{path} already exists — anago will not overwrite a WireGuard \
                 config it did not write. Move it aside first"
            ),
            InitError::Tls(e) => write!(f, "{e}"),
            InitError::Plan(e) => write!(f, "{e}"),
            InitError::Cloudflare(e) => write!(f, "{e}"),
            // The way round a rate limit depends on what this hub
            // would be giving up, and `init` is the run where the
            // answer is "nothing" — it refuses to touch a hub that
            // already exists (`AlreadyInitialized`).
            InitError::Acme(e) => write!(
                f,
                "{e}{}",
                acme::rate_limit_advice(e, acme::Standing::NoCertificateYet)
            ),
            InitError::AfterIssuance { source } => write!(
                f,
                "{source}\n       A certificate had already been issued and was \
                 discarded with the rest of this attempt, so nothing is left \
                 half-made — but the CA still counted it. Only a handful fit in \
                 its weekly allowance for one domain, so fix the above before \
                 running `server init` again"
            ),
            InitError::Wg(e) => write!(f, "{e}"),
            InitError::Io { what, kind, source } => f.write_str(&crate::diagnostics::with_advice(
                format!("could not {what}: {source}"),
                *kind,
            )),
        }
    }
}

impl std::error::Error for InitError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use anago_core::state::Challenge;
    use anago_core::subnet::Subnet;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::Ordering;

    const NOW: i64 = 1_755_500_000;

    fn args() -> ServerInit {
        ServerInit {
            domain: "net.example.com".to_string(),
            tls_cert: Some("/etc/ssl/anago/fullchain.pem".to_string()),
            tls_key: Some("/etc/ssl/anago/privkey.pem".to_string()),
            acme_email: None,
            acme_staging: false,
            acme_challenge: None,
            cf_token: None,
            cf_token_file: None,
            subnet: Subnet::parse("10.100.0.0/24").unwrap(),
            listen_port: 51820,
            api_port: 443,
            systemd: true,
        }
    }

    const ROOT: &str = "/var/lib/anago";

    fn paths() -> ServerPaths {
        ServerPaths::new(ROOT)
    }

    fn certificate() -> Certificate {
        Certificate {
            cert: "/etc/ssl/anago/fullchain.pem".to_string(),
            key: "/etc/ssl/anago/privkey.pem".to_string(),
            account_key: paths().account_key().display().to_string(),
        }
    }

    fn keys() -> (PrivateKey, String) {
        (
            PrivateKey::new("c2VydmVyIHByaXZhdGU="),
            "c2VydmVyIHB1YmxpYw==".to_string(),
        )
    }

    /// No token at all: nothing looked up, nothing written.
    fn by_hand() -> Dns {
        Dns::none()
    }

    /// A token, a zone, and no address to point a record at.
    fn no_address() -> Dns {
        Dns {
            zone_id: Some("zone-1".to_string()),
            record: ARecord::ByHand(ByHand::NoAddress),
        }
    }

    fn written() -> Dns {
        Dns {
            zone_id: Some("zone-1".to_string()),
            record: ARecord::Written(cfapi::Applied::Created {
                record_id: "rec-1".to_string(),
            }),
        }
    }

    fn state_from(args: &ServerInit) -> ServerState {
        let decision = decide(args, None).expect("these flags are a plan");
        state_of(args, &decision, &by_hand())
    }

    fn state_of(args: &ServerInit, decision: &Decision, dns: &Dns) -> ServerState {
        build_state(
            args,
            &Setup::new(decision.clone(), dns.clone(), &paths()),
            keys(),
            JoinCode::parse("7QX4-M2KD").unwrap(),
            NOW,
        )
    }

    /// `server init` with no certificate pair — the ACME fork.
    fn ordering() -> ServerInit {
        ServerInit {
            tls_cert: None,
            tls_key: None,
            acme_email: Some("jo@example.com".to_string()),
            ..args()
        }
    }

    fn token() -> cfapi::Token {
        cfapi::Token::parse("cf-secret-value", cfapi::Source::Flag).unwrap()
    }

    #[test]
    fn the_certificate_pair_is_taken_as_given() {
        // The M0 path, unchanged: both flags, and the files named are
        // the files the hub will serve.
        let decision = decide(&args(), None).unwrap();
        assert_eq!(decision.certificate(&paths()), certificate());
        assert!(decision.plan.is_manual());
        assert_eq!(decision.token, None);

        // And an environment token does not change that — what it is
        // for is the A record, not the certificate (§8).
        let with_token = decide(&args(), Some("cf-secret-value")).unwrap();
        assert!(with_token.plan.is_manual());
        assert_eq!(with_token.token, Some(cfapi::Source::Env));
    }

    #[test]
    fn ordering_a_certificate_puts_it_where_9_fixes() {
        // Known before it exists, which is what lets the state be
        // built — and the CA called against it — before the
        // certificate is in hand.
        let decision = decide(&ordering(), None).unwrap();
        assert_eq!(
            decision.certificate(&paths()),
            Certificate {
                cert: "/var/lib/anago/tls/fullchain.pem".to_string(),
                key: "/var/lib/anago/tls/privkey.pem".to_string(),
                account_key: "/var/lib/anago/tls/account.key".to_string(),
            }
        );
    }

    #[test]
    fn a_token_in_the_environment_answers_what_routing_could_not() {
        // `cli` lets `--acme-challenge dns-01` through with no token
        // flag, because CLOUDFLARE_API_TOKEN is a documented third way
        // in and routing does not read the environment. This is where
        // that verdict is actually reached.
        let asked = ServerInit {
            acme_challenge: Some(Challenge::Dns01),
            ..ordering()
        };
        let e = decide(&asked, None).unwrap_err();
        assert_eq!(e, InitError::Plan(acme::PlanError::Dns01WithoutToken));
        assert!(e.to_string().contains("needs a Cloudflare token"), "{e}");

        // With the variable set, the same command line is a plan — and
        // an empty variable is how a shell spells "unset", so it is
        // not one.
        assert_eq!(
            decide(&asked, Some("cf-secret-value")).unwrap().token,
            Some(cfapi::Source::Env)
        );
        assert_eq!(
            decide(&asked, Some("   ")),
            Err(InitError::Plan(acme::PlanError::Dns01WithoutToken))
        );
    }

    #[test]
    fn the_two_token_flags_are_settled_before_anything_is_written() {
        let both = ServerInit {
            cf_token: Some(token()),
            cf_token_file: Some("/root/cf-token".to_string()),
            ..args()
        };
        assert_eq!(
            decide(&both, None),
            Err(InitError::Cloudflare(cfapi::CfError::BothFlags))
        );
    }

    #[test]
    #[cfg(unix)] // asserts unix path strings
    fn an_acme_hub_records_what_a_renewal_will_need() {
        // The state is built before the CA is called, so everything a
        // renewal reads has to be in it already — except what only the
        // CA can say, which `acme::record` writes back.
        let asked = ServerInit {
            acme_staging: true,
            ..ordering()
        };
        let decision = decide(&asked, None).unwrap();
        let state = state_of(&asked, &decision, &by_hand());

        let acme = state.tls.renewable().expect("this hub renews its own");
        assert_eq!(acme.directory, acme::STAGING);
        assert_eq!(acme.contact.as_deref(), Some("jo@example.com"));
        assert_eq!(acme.account_key_path, "/var/lib/anago/tls/account.key");
        assert_eq!(acme.challenge, Challenge::Http01);
        assert_eq!(state.tls.cert_path, "/var/lib/anago/tls/fullchain.pem");

        // Nothing has been issued yet, so the hub is due for a
        // certificate rather than holding one — which is what makes
        // the renewal loop's first tick a `Renew` if init is
        // interrupted between issuing and the state file.
        assert_eq!(acme.account_url, "");
        assert!(state.tls.needs_renewal(NOW, 0));

        // A manual hub records none of it.
        assert!(state_from(&args()).tls.renewable().is_none());
    }

    #[test]
    #[cfg(unix)] // asserts unix path strings
    fn the_token_is_only_kept_when_a_renewal_will_need_it() {
        // §9.1: the secret that can be got rid of is got rid of. A hub
        // that used the token for the A record and took its
        // certificate over HTTP-01 forgets it when init ends.
        let http01 = decide(
            &ServerInit {
                acme_challenge: Some(Challenge::Http01),
                cf_token: Some(token()),
                ..ordering()
            },
            None,
        )
        .unwrap();
        assert!(!Setup::new(http01, written(), &paths()).keeps_token());

        let dns01 = decide(
            &ServerInit {
                cf_token: Some(token()),
                ..ordering()
            },
            None,
        )
        .unwrap();
        assert!(dns01.plan.needs_token());
        assert!(Setup::new(dns01.clone(), written(), &paths()).keeps_token());
        // ...and only when a record was actually written: a hub whose
        // DNS is still the operator's has nowhere the token has been
        // used and nothing yet to renew against.
        assert!(!Setup::new(dns01.clone(), by_hand(), &paths()).keeps_token());

        // A manual hub keeps nothing either: the token wrote a record
        // and has no second job.
        let manual = decide(
            &ServerInit {
                cf_token: Some(token()),
                ..args()
            },
            None,
        )
        .unwrap();
        assert!(!Setup::new(manual, written(), &paths()).keeps_token());

        // And the state says where it went, or that it went nowhere.
        let state = state_of(
            &ServerInit {
                cf_token: Some(token()),
                ..ordering()
            },
            &dns01,
            &written(),
        );
        let cloudflare = state.cloudflare.expect("a record was written");
        assert_eq!(cloudflare.zone_id, "zone-1");
        assert_eq!(cloudflare.record_id.as_deref(), Some("rec-1"));
        assert_eq!(
            cloudflare.token_path.as_deref(),
            Some("/var/lib/anago/cf-token")
        );
    }

    #[test]
    fn a_dns01_hub_can_still_renew_when_the_a_record_was_not_written() {
        // Regression: a token with no detectable public address left
        // the A record for the operator — and the state then dropped
        // the zone and the token with it. The certificate was issued
        // (DNS-01 answers in TXT and needs no A record at all) and the
        // very first renewal failed for ever, because a renewal reads
        // the zone and the token path out of the state (§9.1).
        let asked = ServerInit {
            cf_token: Some(token()),
            ..ordering()
        };
        let decision = decide(&asked, None).unwrap();
        assert!(
            decision.plan.needs_token(),
            "a token makes dns-01 the default (§8)"
        );

        let setup = Setup::new(decision.clone(), no_address(), &paths());
        assert!(
            setup.keeps_token(),
            "the token a renewal needs was thrown away"
        );

        let state = state_of(&asked, &decision, &no_address());
        let cloudflare = state.cloudflare.clone().expect("the zone was looked up");
        assert_eq!(cloudflare.zone_id, "zone-1");
        assert_eq!(
            cloudflare.token_path.as_deref(),
            Some("/var/lib/anago/cf-token")
        );
        // Only the record id is missing, because only the record is.
        assert_eq!(cloudflare.record_id, None);

        // The operator is still told to add the record.
        let out = instructions(&state, &no_address(), None, DEFAULT_TTL_SECS, NOW);
        assert!(out.contains("1. DNS"), "{out}");
        assert!(out.contains("could not work out"), "{out}");
    }

    #[test]
    fn a_hub_that_wrote_no_record_caches_no_zone() {
        // Caching a zone anago never used would claim knowledge it does
        // not have — and the id would then be trusted by the next
        // upsert (§9.1).
        let decision = decide(&ordering(), None).unwrap();
        let state = state_of(&ordering(), &decision, &by_hand());
        assert_eq!(state.cloudflare, None);
    }

    #[test]
    fn the_initial_state_is_the_server_and_one_code() {
        let state = state_from(&args());
        assert_eq!(state.domain, "net.example.com");
        assert_eq!(
            state.server.address,
            "10.100.0.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(state.server.public_key, "c2VydmVyIHB1YmxpYw==");
        assert_eq!(state.tls.cert_path, "/etc/ssl/anago/fullchain.pem");
        assert!(state.peers.is_empty(), "a fresh hub has no devices");

        // One live code, so init can end with a join line (§6.1).
        assert_eq!(state.codes.len(), 1);
        assert_eq!(state.codes[0].issued_at, NOW);
        assert_eq!(state.codes[0].expires_at, NOW + DEFAULT_TTL_SECS);
        assert_eq!(state.codes[0].used_at, None);
        assert!(state.codes[0].is_usable(NOW));
    }

    #[test]
    fn the_server_address_follows_the_subnet() {
        let mut args = args();
        args.subnet = Subnet::parse("192.168.7.0/24").unwrap();
        let state = state_from(&args);
        assert_eq!(
            state.server.address,
            "192.168.7.1".parse::<Ipv4Addr>().unwrap()
        );
        // And the state round-trips, so init writes something readable.
        assert_eq!(ServerState::parse(&state.to_json_string()).unwrap(), state);
    }

    /// The renderer under test, with the two clock values fixed so
    /// every relative date below is a constant.
    fn text(state: &ServerState, dns: &Dns, public_ip: Option<Ipv4Addr>) -> String {
        instructions(state, dns, public_ip, DEFAULT_TTL_SECS, NOW)
    }

    /// An ACME hub as it stands when `run` prints: the certificate has
    /// arrived, so the state carries its expiry and the schedule that
    /// follows from it (§9.1).
    fn issued(asked: &ServerInit, dns: &Dns, lifetime_days: i64) -> ServerState {
        let decision = decide(asked, None).unwrap();
        let mut state = state_of(asked, &decision, dns);
        let not_after = NOW + lifetime_days * 86_400;
        state.tls.not_after = Some(not_after);
        state
            .tls
            .renewable_mut()
            .expect("this hub renews its own")
            .issued(NOW, Some(not_after));
        state
    }

    #[test]
    fn the_instructions_carry_the_dns_record_to_add() {
        let state = state_from(&args());
        let out = text(&state, &by_hand(), Some("203.0.113.7".parse().unwrap()));
        assert!(out.contains("net.example.com.  A  203.0.113.7"), "{out}");
        assert!(out.contains("behind NAT"), "the address is a guess: {out}");
    }

    #[test]
    fn a_failed_lookup_leaves_a_blank_rather_than_a_wrong_address() {
        let state = state_from(&args());
        let out = text(&state, &by_hand(), None);
        assert!(out.contains("A  <this server's public IP>"), "{out}");
        assert!(out.contains("could not work out"), "{out}");
        // Nothing that looks like an address it made up.
        assert!(!out.contains("0.0.0.0"), "{out}");
    }

    #[test]
    fn what_anago_did_and_what_is_left_are_two_lists() {
        // The point of the rewrite: a list that mixes "this is done"
        // with "you must do this" is one nobody reads to the end.
        let asked = ServerInit {
            cf_token: Some(token()),
            ..ordering()
        };
        let state = issued(&asked, &written(), 90);
        let out = text(&state, &written(), Some("203.0.113.7".parse().unwrap()));

        let did = out.find("anago did these for you").expect("{out}");
        let left = out.find("Still yours to do").expect("{out}");
        assert!(did < left, "{out}");

        // Reported, not asked for: the record and the certificate.
        let done = &out[did..left];
        assert!(done.contains("created the A record"), "{done}");
        assert!(done.contains("issued a certificate"), "{done}");
        assert!(done.contains("dns-01"), "{done}");

        // Asked for, and nothing that already happened: the firewall
        // and the one thing automation cannot check.
        let todo = &out[left..];
        assert!(todo.contains("1. Firewall"), "{todo}");
        assert!(todo.contains("2. Cloudflare"), "{todo}");
        assert!(
            !todo.contains("point the domain at this machine"),
            "the record anago just wrote is being asked for again: {todo}"
        );
    }

    #[test]
    fn the_certificate_line_says_when_it_runs_out_and_when_it_renews() {
        // §9.1 renews at two thirds of the lifetime, so a 90-day
        // certificate renews at 60 — and the numbers have to be the
        // ones the state actually holds, not a fixed "60 days".
        let state = issued(&ordering(), &by_hand(), 90);
        let out = text(&state, &by_hand(), None);
        assert!(out.contains("expires in 90d"), "{out}");
        assert!(out.contains("renewing in 60d"), "{out}");

        // The lifetimes Let's Encrypt is moving to say the same thing
        // in different numbers, which is the reason not to hard-code
        // one.
        let out = text(&issued(&ordering(), &by_hand(), 45), &by_hand(), None);
        assert!(out.contains("expires in 45d"), "{out}");
        assert!(out.contains("renewing in 30d"), "{out}");
    }

    #[test]
    fn an_expiry_that_could_not_be_read_is_said_rather_than_invented() {
        // The certificate still serves and the renewal still runs, on
        // §9.1's assumed lifetime — and a person is entitled to know
        // they are on the assumption.
        let decision = decide(&ordering(), None).unwrap();
        let mut state = state_of(&ordering(), &decision, &by_hand());
        state.tls.not_after = None;
        state.tls.renewable_mut().unwrap().issued(NOW, None);
        let out = text(&state, &by_hand(), None);
        assert!(out.contains("expiry could not be read"), "{out}");
        assert!(out.contains("assumed lifetime"), "{out}");
        // No invented date. ("expires in 15 minutes" further down is
        // the join code, which anago does know the life of.)
        let done = &out[..out.find("Still yours to do").expect("{out}")];
        assert!(!done.contains("expires"), "{done}");
    }

    #[test]
    fn a_manual_certificate_is_the_operators_to_renew_and_says_so() {
        // anago reads that file and never writes it (§9.1). The most
        // it can do is say when it runs out — which is exactly the
        // kind of thing that belongs in the second list, not the
        // first.
        let mut state = state_from(&args());
        state.tls.not_after = Some(NOW + 41 * 86_400);
        let out = text(&state, &by_hand(), None);

        assert!(
            !out.contains("anago did these for you"),
            "an M0 hub had a list of things anago did: {out}"
        );
        assert!(
            out.contains("Certificate — keep it up to date yourself"),
            "{out}"
        );
        assert!(out.contains("/etc/ssl/anago/fullchain.pem"), "{out}");
        assert!(out.contains("It expires in 41d"), "{out}");
        assert!(out.contains("never rewrites it"), "{out}");

        // And when the file's date could not be read, it says that
        // instead of leaving the sentence half-finished.
        let mut state = state_from(&args());
        state.tls.not_after = None;
        assert!(text(&state, &by_hand(), None).contains("expiry could not be read"));
    }

    #[test]
    fn an_m0_hub_still_gets_m0s_output() {
        // A certificate of the operator's and no Cloudflare token:
        // nothing was automated, so there is nothing to report and the
        // list of what is left is the one M0 printed.
        let state = state_from(&args());
        let out = text(&state, &by_hand(), Some("203.0.113.7".parse().unwrap()));
        assert!(!out.contains("anago did these for you"), "{out}");
        assert!(out.contains("1. DNS"), "{out}");
        assert!(out.contains("2. Firewall"), "{out}");
        assert!(!out.contains("Cloudflare —"), "{out}");
        assert!(
            out.contains("anago join net.example.com 7QX4-M2KD"),
            "{out}"
        );
    }

    #[test]
    fn run_refuses_before_it_touches_anything() {
        // The head of the order: an existing hub and a combination of
        // flags that cannot work are both settled before `wg` is even
        // looked for, let alone before anything reaches Cloudflare or
        // a CA. Both cases below are decided without reading the
        // environment, so the test does not depend on it.
        let dir = TempDir::new();
        let root = dir.path.join("var");
        let wg_dir = dir.path.join("wireguard");

        let contradictory = ServerInit {
            cf_token: Some(token()),
            cf_token_file: Some("/root/cf-token".to_string()),
            ..args()
        };
        assert_eq!(
            run(&contradictory, &root, &wg_dir, NOW),
            Err(InitError::Cloudflare(cfapi::CfError::BothFlags))
        );
        assert!(!root.exists(), "a refused init made the state directory");
        assert!(
            !wg_dir.exists(),
            "a refused init made the WireGuard directory"
        );

        // And a machine that is already a hub is refused before that
        // again — the courtesy check that keeps a second init from
        // generating keys it will throw away.
        fsutil::ensure_private_dir(&root).unwrap();
        let state_file = ServerPaths::new(&root).state_file();
        std::fs::write(&state_file, state_from(&args()).to_json_string()).unwrap();
        assert!(matches!(
            run(&contradictory, &root, &wg_dir, NOW),
            Err(InitError::AlreadyInitialized(_))
        ));
        assert!(!wg_dir.exists());
    }

    #[test]
    fn a_record_anago_wrote_is_not_also_asked_for() {
        // Telling somebody to add a record anago has just added is how
        // one name ends up with two A records — the round-robin §9.1
        // refuses to touch, and which makes half the answers point
        // somewhere else.
        let state = state_from(&args());
        let out = text(&state, &written(), Some("203.0.113.7".parse().unwrap()));
        assert!(!out.contains("point the domain at this machine"), "{out}");
        assert!(!out.contains("A  203.0.113.7"), "{out}");
        // It says what happened instead, and the firewall step is
        // renumbered rather than starting at two.
        assert!(out.contains("created the A record"), "{out}");
        assert!(out.contains("1. Firewall"), "{out}");
        assert!(out.contains("443/tcp"), "{out}");
    }

    #[test]
    fn no_token_keeps_m0s_instruction_word_for_word() {
        // The manual path is not a fallback that degrades — it is what
        // a hub without a Cloudflare token gets, and it has to stay
        // complete.
        let state = state_from(&args());
        for dns in [by_hand(), no_address()] {
            let out = text(&state, &dns, Some("203.0.113.7".parse().unwrap()));
            assert!(out.contains("1. DNS"), "{out}");
            assert!(out.contains("net.example.com.  A  203.0.113.7"), "{out}");
            assert!(out.contains("2. Firewall"), "{out}");
        }
    }

    #[test]
    fn the_proxy_is_the_one_thing_automation_cannot_check() {
        // §13's worst trap, and M1 makes it worse: a proxied record
        // still passes HTTP-01, its TXT records are not proxied at
        // all, HTTPS works — and the tunnel is dead. Every line above
        // it is green, so the only way it gets caught is by asking a
        // person to look.
        let asked = ServerInit {
            cf_token: Some(token()),
            ..ordering()
        };
        let state = issued(&asked, &written(), 90);
        let out = text(&state, &written(), None);
        assert!(out.contains("check the A record is DNS only"), "{out}");
        assert!(out.contains("grey, not orange"), "{out}");
        assert!(out.contains("gets a certificate"), "{out}");
        assert!(out.contains("UDP port is not forwarded"), "{out}");

        // It is asked whenever the name is in a zone anago looked up —
        // including the hub that could not write its record, because
        // the record it is told to add can be proxied just the same.
        assert!(text(&state, &no_address(), None).contains("DNS only"));

        // With no token anago does not know the provider, so it warns
        // in the DNS step instead of naming Cloudflare.
        let out = text(&state_from(&args()), &by_hand(), None);
        assert!(!out.contains("Cloudflare —"), "{out}");
        assert!(out.contains("proxy or CDN in front of the record"), "{out}");
        assert!(out.contains("UDP port does not survive"), "{out}");
    }

    #[test]
    fn the_instructions_list_the_ports_the_hub_actually_needs() {
        let state = state_from(&args());
        let out = text(&state, &by_hand(), None);
        assert!(out.contains("443/tcp"), "{out}");
        assert!(out.contains("51820/udp"), "{out}");
        assert!(out.contains("nothing can reach the hub"), "{out}");

        // And they follow the flags, not the defaults.
        let mut args = args();
        args.api_port = 8443;
        args.listen_port = 51999;
        let out = text(&state_from(&args), &by_hand(), None);
        assert!(out.contains("8443/tcp"), "{out}");
        assert!(out.contains("51999/udp"), "{out}");
    }

    #[test]
    fn an_http01_hub_is_told_to_keep_port_80_open() {
        // The renewal answers the challenge on :80 every couple of
        // months. A firewall opened for the first issuance and then
        // tightened is a hub that stops renewing months later, and the
        // only moment to say so is here.
        let state = issued(&ordering(), &by_hand(), 90);
        let out = text(&state, &by_hand(), None);
        assert!(out.contains("80/tcp"), "{out}");
        assert!(out.contains("at every renewal"), "{out}");

        // DNS-01 needs no :80 at all, which is the reason to prefer it.
        let asked = ServerInit {
            cf_token: Some(token()),
            ..ordering()
        };
        let state = issued(&asked, &written(), 90);
        assert!(!text(&state, &written(), None).contains("80/tcp"));

        // And a manual hub never mentions it either.
        assert!(!text(&state_from(&args()), &by_hand(), None).contains("80/tcp"));
    }

    #[test]
    fn a_staging_certificate_says_so_before_the_join_line() {
        // Nothing trusts staging, so `anago join` fails with an
        // unknown-issuer error. A person who typed --acme-staging to
        // check the wiring has to know that failure is the expected
        // one (§8).
        let asked = ServerInit {
            acme_staging: true,
            ..ordering()
        };
        let state = issued(&asked, &by_hand(), 90);
        let out = text(&state, &by_hand(), None);
        assert!(out.contains("staging"), "{out}");
        assert!(out.contains("UnknownIssuer"), "{out}");
        assert!(out.contains("--acme-production"), "{out}");
        assert!(
            out.find("staging") < out.find("anago join"),
            "the warning has to come before the line it is about: {out}"
        );

        // Production says nothing of the sort.
        let state = issued(&ordering(), &by_hand(), 90);
        assert!(!text(&state, &by_hand(), None).contains("staging"));
    }

    #[test]
    fn the_instructions_end_with_a_line_to_paste_on_the_device() {
        let state = state_from(&args());
        let out = text(&state, &by_hand(), None);
        assert!(
            out.contains("anago join net.example.com 7QX4-M2KD"),
            "{out}"
        );
        assert!(
            out.contains("single use and expires in 15 minutes"),
            "{out}"
        );
        assert!(out.contains("`anago code` issues another"), "{out}");
    }

    #[test]
    fn a_failure_at_the_last_write_takes_back_everything_before_it() {
        // M0's guarantee, and M1 does not weaken it: the state file is
        // what "this machine is a hub" means, so a run that did not
        // write it may not leave anything it published beside it —
        // least of all a token that can rewrite the zone.
        let dir = TempDir::new();
        let root = dir.path.join("var");
        let wg_dir = dir.path.join("wireguard");
        let state = state_from(&args());

        // The state file refuses to be written — here because another
        // init got there first, which is the case the lock narrows but
        // `create_new_private` is what actually decides.
        std::fs::create_dir_all(ServerPaths::new(&root).state_file()).unwrap();

        let e = publish(&state, &root, &wg_dir, Some(&token())).unwrap_err();
        assert!(matches!(e, InitError::AlreadyInitialized(_)), "{e:?}");
        assert!(
            !paths::wg_config(&wg_dir).exists(),
            "the WireGuard config survived a failed publish"
        );
        assert!(
            !ServerPaths::new(&root).cf_token().exists(),
            "a Cloudflare token was left on a machine that is not a hub"
        );
    }

    #[test]
    fn a_token_that_was_already_there_is_never_rolled_back() {
        // The rollback works off what this call created. A token file
        // that was already in place belongs to a hub anago did not
        // make, and deleting it would break that hub's renewals.
        let dir = TempDir::new();
        let root = dir.path.join("var");
        let wg_dir = dir.path.join("wireguard");
        fsutil::ensure_private_dir(&root).unwrap();
        let theirs = ServerPaths::new(&root).cf_token();
        std::fs::write(&theirs, "somebody else's token").unwrap();

        let e = publish(&state_from(&args()), &root, &wg_dir, Some(&token())).unwrap_err();
        assert!(matches!(e, InitError::Io { .. }), "{e:?}");
        assert_eq!(
            std::fs::read_to_string(&theirs).unwrap(),
            "somebody else's token"
        );
        assert!(!paths::wg_config(&wg_dir).exists());
    }

    #[test]
    #[cfg(unix)] // exercises unix modes/ownership/symlinks
    fn the_token_lands_beside_the_state_and_only_when_it_is_kept() {
        let dir = TempDir::new();
        let root = dir.path.join("var");
        let wg_dir = dir.path.join("wireguard");
        let state = state_from(&args());

        publish(&state, &root, &wg_dir, Some(&token())).unwrap();
        let token_file = ServerPaths::new(&root).cf_token();
        assert_eq!(
            std::fs::read_to_string(&token_file).unwrap(),
            "cf-secret-value"
        );
        // 0600: it can rewrite every record in the zone (§13).
        let mode = std::fs::metadata(&token_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:04o}");

        // And a hub that keeps no token has no file to leak.
        let other = TempDir::new();
        publish(
            &state,
            &other.path.join("var"),
            &other.path.join("wireguard"),
            None,
        )
        .unwrap();
        assert!(!ServerPaths::new(other.path.join("var")).cf_token().exists());
    }

    /// The three files an issuance writes, in the order `acme::renew`
    /// writes them: the account is committed once the certificate is
    /// in hand, and the pair is saved after that (§9.1).
    fn issuance_writes(paths: &ServerPaths, upto: usize) {
        for path in [
            paths.account_key(),
            paths.certificate(),
            paths.private_key(),
        ]
        .into_iter()
        .take(upto)
        {
            std::fs::write(&path, "issued").unwrap();
        }
    }

    fn tls_paths(dir: &TempDir) -> ServerPaths {
        let paths = ServerPaths::new(dir.path.join("var"));
        fsutil::ensure_private_dir(&paths.tls_dir()).unwrap();
        paths
    }

    #[test]
    fn an_issuance_that_is_never_published_leaves_nothing_behind() {
        // The requirement this slice was given: a failed `server init`
        // leaves no files. Ordering a certificate writes three of them
        // before there is a hub to own them, and nothing ever comes
        // back for them — a later init orders a fresh certificate
        // whatever is on disk — so keeping them would only leave a
        // private key on a machine that is not a hub (§7.1).
        let dir = TempDir::new();
        let paths = tls_paths(&dir);

        let issuance = Issuance::watching(&paths);
        issuance_writes(&paths, 3);
        drop(issuance);

        assert!(!paths.account_key().exists(), "the ACME account survived");
        assert!(!paths.certificate().exists(), "the certificate survived");
        assert!(!paths.private_key().exists(), "its private key survived");
    }

    #[test]
    fn an_issuance_that_failed_halfway_leaves_nothing_either() {
        // Regression: the guard used to be armed by the issuance
        // *succeeding*, which is the one case it is not needed for.
        // `acme::renew` commits the account file and only then saves
        // the certificate pair, so a failure between the two came back
        // as an error with nothing to arm anything with — and left a
        // fresh ACME account behind on a machine that is not a hub.
        let dir = TempDir::new();
        let paths = tls_paths(&dir);

        // Armed where `run` arms it: before the call, not after it.
        let issuance = Issuance::watching(&paths);
        // The account is committed, and saving the pair then fails.
        issuance_writes(&paths, 1);
        drop(issuance);

        assert!(
            !paths.account_key().exists(),
            "a failed init left an ACME account behind"
        );

        // And the other partial: the pair half-written.
        let dir = TempDir::new();
        let paths = tls_paths(&dir);
        let issuance = Issuance::watching(&paths);
        issuance_writes(&paths, 2);
        drop(issuance);
        assert!(!paths.account_key().exists());
        assert!(!paths.certificate().exists());
    }

    #[test]
    fn a_published_issuance_is_the_hubs_and_stays() {
        let dir = TempDir::new();
        let paths = tls_paths(&dir);

        let mut issuance = Issuance::watching(&paths);
        issuance_writes(&paths, 3);
        issuance.keep();
        drop(issuance);
        assert!(paths.account_key().exists());
        assert!(paths.certificate().exists());
        assert!(paths.private_key().exists());
    }

    #[test]
    fn a_file_this_run_did_not_create_is_not_removed() {
        // The same rule as the publish rollback: only what this call
        // made. An account key that was already there belongs to
        // whatever put it there, and a `server init` that failed is no
        // reason to destroy it.
        let dir = TempDir::new();
        let paths = tls_paths(&dir);
        std::fs::write(paths.account_key(), "theirs").unwrap();

        let issuance = Issuance::watching(&paths);
        issuance_writes(&paths, 3);
        drop(issuance);

        // The file is still there. Its *contents* are another matter —
        // an issuance that reuses an account rewrites the credentials
        // — but deleting somebody's account key is the damage this
        // rule exists to prevent.
        assert!(
            paths.account_key().exists(),
            "an account key this run did not create was removed"
        );
        assert!(!paths.certificate().exists());
        assert!(!paths.private_key().exists());
    }

    #[test]
    fn a_manual_hub_never_touches_the_issuance_paths() {
        // Nothing was ordered, so there is nothing of ours under
        // `tls/` — and a stray file there is not this run's to sweep.
        let dir = TempDir::new();
        let paths = tls_paths(&dir);

        let issuance = Issuance::nothing();
        issuance_writes(&paths, 3);
        drop(issuance);
        assert!(paths.account_key().exists());
        assert!(paths.certificate().exists());
    }

    #[test]
    fn a_failure_after_issuance_says_the_certificate_is_already_paid_for() {
        // The files are gone with the rest of the attempt, but the CA
        // still counted the certificate: only a handful fit in its
        // weekly allowance for one domain (§13). A person who is not
        // told that reads the next refusal as anago being broken.
        let asked = ordering();
        let decision = decide(&asked, None).unwrap();
        let issued = state_of(&asked, &decision, &by_hand());
        let e = finished_but_unpublished(
            InitError::Io {
                what: "write the state file",
                kind: std::io::ErrorKind::StorageFull,
                source: "No space left on device".to_string(),
            },
            &issued,
        );
        let message = e.to_string();
        assert!(message.contains("No space left on device"), "{message}");
        assert!(message.contains("discarded"), "{message}");
        assert!(message.contains("weekly allowance"), "{message}");

        // A manual hub paid nothing, so it is told nothing extra.
        let plain = finished_but_unpublished(
            InitError::ConfigExists("/etc/wireguard/anago.conf".to_string()),
            &state_from(&args()),
        );
        assert_eq!(
            plain,
            InitError::ConfigExists("/etc/wireguard/anago.conf".to_string())
        );
    }

    #[test]
    fn without_systemd_the_operator_is_told_what_to_run() {
        // `--no-systemd` is for containers and non-systemd hosts: the
        // hub is configured, but nothing will start it.
        let hint = foreground_hint();
        assert!(hint.contains("anago server run"), "{hint}");
        assert!(hint.contains("across a reboot"), "{hint}");
    }

    #[test]
    fn the_output_says_exactly_one_thing_about_starting() {
        // Regression: a fixed "not running yet" line used to follow the
        // real answer, contradicting the systemd case and denying the
        // command the foreground case had just recommended.
        let state = state_from(&args());
        let base = instructions(&state, &by_hand(), None, DEFAULT_TTL_SECS, NOW);

        let under_systemd = assemble(
            &base,
            &systemd_note(Path::new("/etc/systemd/system/anago.service")),
        );
        assert!(
            under_systemd.contains("running under systemd"),
            "{under_systemd}"
        );
        assert!(
            under_systemd.contains("systemctl status anago"),
            "{under_systemd}"
        );
        assert!(
            !under_systemd.contains("not running yet"),
            "{under_systemd}"
        );
        assert!(
            !under_systemd.contains("Start the hub with"),
            "one start note only: {under_systemd}"
        );

        let by_hand = assemble(&base, &foreground_hint());
        assert!(by_hand.contains("anago server run"), "{by_hand}");
        assert!(!by_hand.contains("running under systemd"), "{by_hand}");
        assert!(!by_hand.contains("next M0 slice"), "{by_hand}");

        // Both keep everything the operator still has to do.
        for text in [&under_systemd, &by_hand] {
            assert!(text.contains("A  <this server's public IP>"), "{text}");
            assert!(text.contains("51820/udp"), "{text}");
            assert!(
                text.contains("anago join net.example.com 7QX4-M2KD"),
                "{text}"
            );
        }
    }

    #[test]
    fn a_second_init_is_refused_before_anything_is_generated() {
        // Re-keying a live hub would strand every registered device.
        let e = InitError::AlreadyInitialized("/var/lib/anago/state.json".to_string());
        let message = e.to_string();
        assert!(message.contains("/var/lib/anago/state.json"), "{message}");
        assert!(message.contains("join again"), "{message}");
    }

    #[test]
    fn init_errors_say_which_step_failed() {
        let e = InitError::Io {
            what: "write the state file",
            kind: std::io::ErrorKind::PermissionDenied,
            source: "Permission denied (os error 13)".to_string(),
        };
        // The step, the cause, and — for this cause — what to do.
        assert!(
            e.to_string().starts_with("could not write the state file"),
            "{e}"
        );
        assert!(e.to_string().contains("run this as root"), "{e}");
    }

    // ------------------------------------------------ publishing

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> TempDir {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("anago-init-{}-{unique}", std::process::id()));
            std::fs::create_dir_all(&path).expect("temp dir");
            TempDir { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn publishing_writes_the_config_and_the_state() {
        let dir = TempDir::new();
        let root = dir.path.join("var");
        let wg_dir = dir.path.join("wireguard");
        let state = state_from(&args());

        publish(&state, &root, &wg_dir, None).unwrap();
        assert_eq!(
            std::fs::read_to_string(paths::wg_config(&wg_dir)).unwrap(),
            wgconf::server_config(&state).expose()
        );
        assert_eq!(
            Store::new(&root).read().unwrap(),
            state,
            "the state file is what a later run reads"
        );
        // A finished hub answers "already initialized" to a second run.
        assert!(check_not_initialized(&root, &wg_dir).is_err());
    }

    #[test]
    fn a_failed_state_write_leaves_nothing_behind() {
        // Regression: the state file used to be written first, so a
        // later failure left a marker that blocked every retry — while
        // a failure after it left a hub with no interface config.
        let dir = TempDir::new();
        let wg_dir = dir.path.join("wireguard");
        // A regular file where the state directory must go: creating it
        // fails, after the config has already been written.
        let blocker = dir.path.join("blocked");
        std::fs::write(&blocker, "not a directory").unwrap();
        let root = blocker.join("anago");

        let e = publish(&state_from(&args()), &root, &wg_dir, None).unwrap_err();
        assert!(matches!(e, InitError::Io { .. }), "{e:?}");
        assert!(
            !paths::wg_config(&wg_dir).exists(),
            "the config must be rolled back so the next run can retry"
        );
        assert!(
            check_not_initialized(&root, &wg_dir).is_ok(),
            "a retry is possible"
        );
    }

    #[test]
    fn an_existing_hub_or_config_stops_the_run_before_anything_happens() {
        let dir = TempDir::new();
        let root = dir.path.join("var");
        let wg_dir = dir.path.join("wireguard");
        assert!(check_not_initialized(&root, &wg_dir).is_ok());

        // Someone else's anago.conf is not ours to replace.
        std::fs::create_dir_all(&wg_dir).unwrap();
        std::fs::write(paths::wg_config(&wg_dir), "[Interface]\n").unwrap();
        let e = check_not_initialized(&root, &wg_dir).unwrap_err();
        assert!(matches!(e, InitError::ConfigExists(_)), "{e:?}");
        assert!(e.to_string().contains("did not write"), "{e}");

        // An existing state file wins, since it is the hub marker.
        std::fs::create_dir_all(&root).unwrap();
        Store::new(&root).write(&state_from(&args())).unwrap();
        let e = check_not_initialized(&root, &wg_dir).unwrap_err();
        assert!(matches!(e, InitError::AlreadyInitialized(_)), "{e:?}");
    }

    #[test]
    fn only_a_reachable_address_is_offered_for_dns() {
        // The common VPS shape this gets wrong: a public address 1:1
        // NATed onto a private NIC, where the local address is a lie.
        for private in [
            "10.0.0.5",
            "172.16.0.5",
            "172.31.255.254",
            "192.168.7.2",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
        ] {
            assert_eq!(
                routable_address(private.parse().unwrap()),
                None,
                "{private} must not reach an A record"
            );
        }
        for public in [
            "5.6.7.8",
            "1.1.1.1",
            "93.184.216.34",
            "172.32.0.1",
            "100.128.0.1",
        ] {
            let ip = public.parse().unwrap();
            assert_eq!(routable_address(ip), Some(ip), "{public} is routable");
        }
    }

    #[test]
    fn exactly_one_of_two_racing_inits_wins() {
        // Regression, twice over. Check and publish used to be separate
        // steps with nothing between them, so both runs passed the
        // check and the later writer re-keyed a hub the earlier one had
        // finished. Then the lock covered only the publish, so both
        // runs still registered an ACME account and wrote over the same
        // `account.key` and certificate pair — and the loser's files
        // stayed, leaving the winner's state file naming one account
        // and the credentials on disk another (§9.1).
        //
        // So what is raced here is what `run` does **under the lock**:
        // the outside work and the publish together.
        let dir = TempDir::new();
        let root = dir.path.join("var");
        let wg_dir = dir.path.join("wireguard");
        let inside = std::sync::atomic::AtomicUsize::new(0);
        let overlapped = std::sync::atomic::AtomicBool::new(false);

        let mut first = args();
        first.domain = "first.example.com".to_string();
        let mut second = args();
        second.domain = "second.example.com".to_string();

        let outcomes: Vec<Result<(), InitError>> = std::thread::scope(|scope| {
            let handles: Vec<_> = [state_from(&first), state_from(&second)]
                .into_iter()
                .map(|state| {
                    let root = root.clone();
                    let wg_dir = wg_dir.clone();
                    let inside = &inside;
                    let overlapped = &overlapped;
                    scope.spawn(move || {
                        let _init = lock(&root)?;
                        check_not_initialized(&root, &wg_dir)?;

                        // Where the A record and the certificate go.
                        // Nothing here may run twice at once: two ACME
                        // accounts registered against one hub is the
                        // failure this lock exists for.
                        if inside.fetch_add(1, Ordering::SeqCst) != 0 {
                            overlapped.store(true, Ordering::SeqCst);
                        }
                        std::thread::yield_now();
                        inside.fetch_sub(1, Ordering::SeqCst);

                        publish(&state, &root, &wg_dir, None)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        assert!(
            !overlapped.load(Ordering::SeqCst),
            "two inits reached the CA at the same time"
        );

        let winners = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
        assert_eq!(winners, 1, "{outcomes:?}");
        let loser = outcomes.iter().find(|outcome| outcome.is_err()).unwrap();
        assert!(
            matches!(
                loser,
                Err(InitError::AlreadyInitialized(_)) | Err(InitError::ConfigExists(_))
            ),
            "{loser:?}"
        );

        // The two files describe the same hub — the winner's.
        let stored = Store::new(&root).read().unwrap();
        let config = std::fs::read_to_string(paths::wg_config(&wg_dir)).unwrap();
        assert_eq!(config, wgconf::server_config(&stored).expose());
        assert!(
            ["first.example.com", "second.example.com"].contains(&stored.domain.as_str()),
            "{}",
            stored.domain
        );
    }

    #[test]
    fn a_config_that_appears_after_the_check_is_left_alone() {
        // Somebody else's anago.conf must survive, and must not be
        // swept up by our rollback.
        let dir = TempDir::new();
        let root = dir.path.join("var");
        let wg_dir = dir.path.join("wireguard");
        std::fs::create_dir_all(&wg_dir).unwrap();
        std::fs::write(paths::wg_config(&wg_dir), "not ours\n").unwrap();

        let e = publish(&state_from(&args()), &root, &wg_dir, None).unwrap_err();
        assert!(matches!(e, InitError::ConfigExists(_)), "{e:?}");
        assert_eq!(
            std::fs::read_to_string(paths::wg_config(&wg_dir)).unwrap(),
            "not ours\n"
        );
        assert!(
            !ServerPaths::new(&root).state_file().exists(),
            "no hub was published"
        );
    }
}
