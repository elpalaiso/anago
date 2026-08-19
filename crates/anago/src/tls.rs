//! TLS for the control plane (DESIGN.md §11: M0 takes an existing
//! certificate; ACME arrives in M1).
//!
//! The split here is the point: turning PEM bytes into a
//! [`rustls::ServerConfig`] is a pure function over byte slices, and so
//! is deciding what to say about a bad path or a loose key file. Only
//! [`load`] touches the filesystem, and all it adds is the path in the
//! message.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::Router;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

/// Certificate and key, ready to serve, plus anything worth telling the
/// operator about how they are stored.
#[derive(Debug)]
pub struct LoadedTls {
    pub config: ServerConfig,
    /// What this configuration presents, kept so a later look at the
    /// files can tell "the same certificate" from "a new one". A
    /// `ServerConfig` hands its chain to a resolver and does not give
    /// it back, so the only way to answer that question later is to
    /// have kept it.
    pub chain: Chain,
    /// When the certificate runs out, read from the certificate
    /// itself (§9.1). `None` when it could not be read, which is a
    /// display and a schedule going on an assumption rather than a
    /// reason to refuse the file.
    pub not_after: Option<i64>,
    /// Non-fatal complaints — a key file others can read, say. The
    /// certificate is still usable, so this is a warning and not a
    /// refusal: the file may belong to a certbot or Cloudflare layout
    /// anago does not own.
    pub warnings: Vec<String>,
}

/// Reads both files and builds the server config.
///
/// Each file is parsed on its own before the two are combined, so a
/// blame is never guessed: a malformed key is reported against
/// `--tls-key` even though the same [`PemError::Malformed`] can come
/// from either side. Only the pairing failure names both files, because
/// that is the one failure neither file owns alone.
pub fn load(cert_path: &Path, key_path: &Path) -> Result<LoadedTls, TlsError> {
    let cert_pem = read(cert_path)?;
    let key_pem = read(key_path)?;

    let certs = parse_certs(&cert_pem).map_err(|error| TlsError::Pem {
        path: cert_path.to_path_buf(),
        error,
    })?;
    let key = parse_key(&key_pem).map_err(|error| TlsError::Pem {
        path: key_path.to_path_buf(),
        error,
    })?;
    let chain = Chain(certs.clone());
    let config = build_from_parts(certs, key).map_err(|error| TlsError::Pair {
        cert_path: cert_path.to_path_buf(),
        key_path: key_path.to_path_buf(),
        error,
    })?;

    let mut warnings = Vec::new();
    if let Some(warning) = permission_warning(key_path, mode_of(key_path)) {
        warnings.push(warning);
    }
    Ok(LoadedTls {
        not_after: chain.expiry(),
        config,
        chain,
        warnings,
    })
}

/// Builds a server config from PEM bytes. Pure — every failure below is
/// reproducible from a byte slice in a unit test.
///
/// Only the tests call it: [`load`] runs the same three steps by hand
/// so that it can name the file each failure belongs to. This is that
/// sequence without the blame, which is what makes it usable on a byte
/// slice with no path behind it.
#[cfg(test)]
pub fn build_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<ServerConfig, PemError> {
    let certs = parse_certs(cert_pem)?;
    let key = parse_key(key_pem)?;
    build_from_parts(certs, key)
}

/// The pairing step alone: everything here is about the two halves
/// belonging together, which is why [`load`] reports it against both
/// files.
pub fn build_from_parts(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, PemError> {
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| PemError::Rejected(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| PemError::Rejected(e.to_string()))
}

/// Every `CERTIFICATE` block, leaf first — the chain a client needs.
pub fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, PemError> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut io::BufReader::new(pem))
        .collect::<Result<_, _>>()
        .map_err(|e| PemError::Malformed(e.to_string()))?;
    if certs.is_empty() {
        return Err(PemError::NoCertificates);
    }
    Ok(certs)
}

/// The one private key in the file, in any of the three encodings the
/// usual tools emit: PKCS#8 (`BEGIN PRIVATE KEY`), SEC1 (`BEGIN EC
/// PRIVATE KEY`), or PKCS#1 (`BEGIN RSA PRIVATE KEY`).
///
/// More than one is an error rather than a guess: picking the first
/// would silently serve with a key the operator did not mean.
pub fn parse_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, PemError> {
    let mut keys = Vec::new();
    for item in rustls_pemfile::read_all(&mut io::BufReader::new(pem)) {
        match item.map_err(|e| PemError::Malformed(e.to_string()))? {
            rustls_pemfile::Item::Pkcs8Key(key) => keys.push(PrivateKeyDer::Pkcs8(key)),
            rustls_pemfile::Item::Sec1Key(key) => keys.push(PrivateKeyDer::Sec1(key)),
            rustls_pemfile::Item::Pkcs1Key(key) => keys.push(PrivateKeyDer::Pkcs1(key)),
            _ => {}
        }
    }
    match keys.len() {
        0 => Err(PemError::NoPrivateKey),
        1 => Ok(keys.remove(0)),
        many => Err(PemError::ManyPrivateKeys(many)),
    }
}

/// Complains about a key file other users can read. Pure: the mode is
/// passed in, so every case is a test rather than a chmod.
pub fn permission_warning(path: &Path, mode: Option<u32>) -> Option<String> {
    let mode = mode?;
    if mode & 0o077 == 0 {
        return None;
    }
    Some(format!(
        "{} is readable by other users (mode {:04o}) — `chmod 600 {}`",
        path.display(),
        mode & 0o7777,
        path.display()
    ))
}

fn mode_of(path: &Path) -> Option<u32> {
    std::fs::metadata(path)
        .ok()
        .map(|meta| meta.permissions().mode())
}

fn read(path: &Path) -> Result<Vec<u8>, TlsError> {
    std::fs::read(path).map_err(|e| TlsError::Io {
        path: path.to_path_buf(),
        kind: e.kind(),
        hint: io_hint(e.kind()),
    })
}

/// What to suggest for a failed open. Pure, and the reason these
/// messages can be checked without arranging a broken filesystem.
pub fn io_hint(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::NotFound => {
            "check the path — M0 does not issue certificates, it takes one you already have"
        }
        io::ErrorKind::PermissionDenied => {
            "certificate keys are usually root-only; run `anago server init` as root"
        }
        io::ErrorKind::IsADirectory => "expected the PEM file itself, not the directory",
        _ => "check that the file exists and is readable",
    }
}

/// Serves `app` over TLS.
///
/// **Human verification needed**: binding a port and completing a
/// handshake needs a real machine and a real certificate; the parts
/// that can be decided from bytes are tested above.
pub async fn serve(addr: SocketAddr, tls: Reloadable, app: Router) -> io::Result<()> {
    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service())
        .await
}

/// The live TLS configuration, as a handle the listener reads on every
/// handshake.
///
/// This is what makes renewal worth doing while the hub runs: the
/// config is fetched per connection rather than captured once, so
/// [`reload`] changes what the next handshake presents without dropping
/// the connections already open, and without a restart nobody asked
/// for.
pub type Reloadable = axum_server::tls_rustls::RustlsConfig;

/// What the hub is presenting: the handle the listener reads, and the
/// chain that went into it.
///
/// **One value and not two.** The two have to move together — a handle
/// swapped without recording what went into it leaves the next look at
/// the files comparing against a certificate that is no longer being
/// served, and then the swap that would put the disk back in front of
/// the listener never happens. Keeping them behind one lock is the only
/// way to make that state unreachable rather than merely avoided.
#[derive(Debug)]
pub struct Listening {
    handle: Reloadable,
    /// Behind the same lock as the swap, so no look can land between
    /// the two halves of one change.
    serving: Mutex<Chain>,
}

impl Listening {
    pub fn new(loaded: LoadedTls) -> Listening {
        Listening {
            handle: Reloadable::from_config(Arc::new(loaded.config)),
            serving: Mutex::new(loaded.chain),
        }
    }

    /// The handle to hand the listener. Cloning it shares the same live
    /// configuration rather than copying it, which is what makes
    /// [`Listening::present`] visible to a listener already running.
    pub fn config(&self) -> Reloadable {
        self.handle.clone()
    }

    /// Puts an already-loaded certificate in front of the listener.
    ///
    /// **This cannot fail, and that is the point.** Reading and
    /// validating the new pair is [`load`]'s job and belongs *before*
    /// the state file is written; if the swap could fail after that, a
    /// hub would record a renewal it is not actually serving and then
    /// sit on the old certificate until it expired — the next check
    /// would see a fresh `renew_after` and do nothing (§9.1).
    pub fn present(&self, loaded: LoadedTls) {
        let mut serving = self.lock();
        self.handle.reload_from_config(Arc::new(loaded.config));
        *serving = loaded.chain;
    }

    /// Compares a read of the files against what is being presented and
    /// acts on the answer, both under the one lock.
    ///
    /// The decision itself is [`reload`] and is pure; this adds the
    /// swap, so that "decided to swap" and "swapped" cannot come apart.
    pub fn take(&self, found: Result<LoadedTls, TlsError>) -> Reload {
        let mut serving = self.lock();
        match reload(&serving, found.as_ref().map(|loaded| &loaded.chain)) {
            Reload::Swap => {
                let loaded = found.expect("Reload::Swap only comes from a pair that loaded");
                self.handle.reload_from_config(Arc::new(loaded.config));
                *serving = loaded.chain;
                Reload::Swap
            }
            decided => decided,
        }
    }

    /// A poisoned lock means a panic while a swap was half-made; the
    /// certificate the handle holds is still a whole one either way, so
    /// going on with it beats taking the hub down.
    fn lock(&self) -> std::sync::MutexGuard<'_, Chain> {
        self.serving.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The certificate chain a listener is presenting — leaf first, exactly
/// the bytes a client is handed.
///
/// The whole chain and not just the leaf: a CA that changes which
/// intermediate it cross-signs from reissues the same leaf under a
/// different chain, and a hub that called that "unchanged" would serve
/// the old intermediates until somebody restarted it. Order counts for
/// the same reason — it is what goes on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain(Vec<CertificateDer<'static>>);

impl Chain {
    /// When the leaf runs out (§9.1).
    ///
    /// The leaf and not the whole chain: the intermediates outlive it
    /// and expire on somebody else's schedule, so the earliest date in
    /// the file is not the one that matters to this hub.
    pub fn expiry(&self) -> Option<i64> {
        anago_core::x509::not_after(self.0.first()?.as_ref())
    }
}

/// When the certificate in a PEM file runs out.
///
/// For the caller that has the bytes rather than a loaded
/// configuration — an issuance, which has just been handed the chain
/// by the CA.
pub fn expiry(pem: &[u8]) -> Option<i64> {
    parse_certs(pem)
        .ok()
        .and_then(|certs| Chain(certs).expiry())
}

/// What the periodic look at the certificate files should do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reload {
    /// The files hold what the listener already presents. This is also
    /// the answer right after anago's own renewal, which presents the
    /// pair it has just validated rather than waiting for this check.
    Unchanged,
    /// A different chain, and it loads: put it in front of the listener.
    Swap,
    /// The files are not a usable pair *right now*. The certificate
    /// already in front of the listener keeps working, so this is a
    /// complaint and not a stop.
    Keep(String),
}

/// Decides whether what is on disk should replace what the listener is
/// presenting (DESIGN.md §9.1).
///
/// Pure, and it takes the outcome of the read rather than doing it, so
/// every case below is a test rather than a filesystem to arrange.
///
/// The comparison is on the chain and not on the files, because what a
/// client sees is the chain: a hub told to read a different path that
/// happens to hold the same certificate has nothing to swap, and a
/// certbot that rewrites the same path every 60 days has everything to.
///
/// [`Reload::Keep`] is the case worth being careful about. Tools that
/// renew certificates do not write both halves at once — certbot writes
/// `fullchain.pem` and `privkey.pem` as two files — so a check that
/// lands in that gap sees a certificate that does not match its key.
/// Tearing down a working listener for that would turn a renewal into
/// an outage; the old certificate is still valid, so the hub keeps it
/// and looks again at the next check.
pub fn reload(serving: &Chain, found: Result<&Chain, &TlsError>) -> Reload {
    match found {
        Ok(chain) if chain == serving => Reload::Unchanged,
        Ok(_) => Reload::Swap,
        Err(error) => Reload::Keep(format!(
            "{error} — the hub is still serving the certificate it already has, and \
             will look again at the next check"
        )),
    }
}

/// Why some PEM bytes are not a usable certificate and key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PemError {
    /// No `CERTIFICATE` block at all — a key file passed as the cert,
    /// or DER rather than PEM.
    NoCertificates,
    /// No private key block in any supported encoding.
    NoPrivateKey,
    /// Several keys; anago will not choose one.
    ManyPrivateKeys(usize),
    /// The file is not well-formed PEM.
    Malformed(String),
    /// Well-formed, but rustls refused the pair — most often a key that
    /// does not belong to the certificate.
    Rejected(String),
}

impl fmt::Display for PemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PemError::NoCertificates => write!(
                f,
                "no CERTIFICATE block found — is this the certificate file, in PEM form?"
            ),
            PemError::NoPrivateKey => write!(
                f,
                "no private key found — expected PKCS#8, SEC1, or PKCS#1 PEM"
            ),
            PemError::ManyPrivateKeys(count) => write!(
                f,
                "found {count} private keys; give a file with exactly one"
            ),
            PemError::Malformed(detail) => write!(f, "not valid PEM: {detail}"),
            PemError::Rejected(detail) => write!(
                f,
                "certificate and key were rejected: {detail} — do they belong together?"
            ),
        }
    }
}

/// A failure with the file it happened to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    Io {
        path: PathBuf,
        kind: io::ErrorKind,
        hint: &'static str,
    },
    Pem {
        path: PathBuf,
        error: PemError,
    },
    /// Both files parsed, but they do not go together — the failure
    /// neither of them owns alone.
    Pair {
        cert_path: PathBuf,
        key_path: PathBuf,
        error: PemError,
    },
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::Io { path, kind, hint } => {
                let what = match kind {
                    io::ErrorKind::NotFound => "not found".to_string(),
                    io::ErrorKind::PermissionDenied => "permission denied".to_string(),
                    other => format!("{other:?}").to_lowercase(),
                };
                write!(f, "{}: {what} — {hint}", path.display())
            }
            TlsError::Pem { path, error } => write!(f, "{}: {error}", path.display()),
            TlsError::Pair {
                cert_path,
                key_path,
                error,
            } => write!(
                f,
                "{} with {}: {error}",
                cert_path.display(),
                key_path.display()
            ),
        }
    }
}

impl std::error::Error for TlsError {}

/// Two throwaway self-signed pairs, so the tests here and in
/// [`crate::serve`] can swap one real certificate for another rather
/// than a stub for a stub. Generated for these tests; the keys are
/// public by construction and belong to nothing.
#[cfg(test)]
pub mod pairs {
    pub const CERT_A: &str = "-----BEGIN CERTIFICATE-----\nMIIBizCCATGgAwIBAgIUXys43iONJV3kteA847Y5xzoj17IwCgYIKoZIzj0EAwIw\nGjEYMBYGA1UEAwwPbmV0LmV4YW1wbGUuY29tMCAXDTI2MDgxOTAxMDMzMVoYDzIx\nMjYwNzI2MDEwMzMxWjAaMRgwFgYDVQQDDA9uZXQuZXhhbXBsZS5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAASIPDFfU6+LAbNbhiXtHYBvPGNb5Lp0tn3wCtNs\nCWrwvUKevnHcY3CpHbUPD9kvdFLf4iBc+1X1GrobIk/QuNyyo1MwUTAdBgNVHQ4E\nFgQUsKLJkykZ5Mf5ggjV7x7w60lfNB0wHwYDVR0jBBgwFoAUsKLJkykZ5Mf5ggjV\n7x7w60lfNB0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiAv3pv/\nBs1Xj/35QG7dLCSCdtW5I6IDtUczwK65XhZyLAIhAOtE22DgWemYIHCCivp6FbtW\n/g/Xq40tYP8VUqc3Fj3Q\n-----END CERTIFICATE-----\n";
    pub const KEY_A: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgp10L63N+7ARRCawO\n8pJL1eNELGVFFaLLNTSTOMxnDyehRANCAASIPDFfU6+LAbNbhiXtHYBvPGNb5Lp0\ntn3wCtNsCWrwvUKevnHcY3CpHbUPD9kvdFLf4iBc+1X1GrobIk/QuNyy\n-----END PRIVATE KEY-----\n";
    pub const CERT_B: &str = "-----BEGIN CERTIFICATE-----\nMIIBizCCATGgAwIBAgIUE6efSE+EQmY2ekTk7j/rS4NRFSwwCgYIKoZIzj0EAwIw\nGjEYMBYGA1UEAwwPaHViLmV4YW1wbGUuY29tMCAXDTI2MDgxOTAxMDMzMVoYDzIx\nMjYwNzI2MDEwMzMxWjAaMRgwFgYDVQQDDA9odWIuZXhhbXBsZS5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAATEhl6fe5R+QSX6ZKriCNz2c8SL6Wya5KzML+3r\nFRrvUhoVa5lxmlUrP4orq6b4+kenCMqRoz96ppNvzYxxgq0ro1MwUTAdBgNVHQ4E\nFgQU6+bq37P6bQZEe33mpuCwWKQxGt4wHwYDVR0jBBgwFoAU6+bq37P6bQZEe33m\npuCwWKQxGt4wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA0Ijg\nGiMB5fb4jBmzBBXwqBc5ZiMs133hw97eDNUvRnUCIC98UgP1FrpeMv0eIOnNC+i1\n6Fw/trHxdI/h+9TYS+AQ\n-----END CERTIFICATE-----\n";
    pub const KEY_B: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgX7aCvnsuEiXKyS/s\ntWHFaxT7bXCgzf2oEe+7ZBlLEDuhRANCAATEhl6fe5R+QSX6ZKriCNz2c8SL6Wya\n5KzML+3rFRrvUhoVa5lxmlUrP4orq6b4+kenCMqRoz96ppNvzYxxgq0r\n-----END PRIVATE KEY-----\n";
}

#[cfg(test)]
mod tests {

    use super::pairs::{CERT_A, CERT_B, KEY_A, KEY_B};
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Throwaway self-signed material; see tests/fixtures/README.txt.
    const CERT: &[u8] = include_bytes!("../tests/fixtures/cert.pem");
    const KEY_PKCS8: &[u8] = include_bytes!("../tests/fixtures/key-pkcs8.pem");
    const KEY_SEC1: &[u8] = include_bytes!("../tests/fixtures/key-sec1.pem");
    const KEY_PKCS1: &[u8] = include_bytes!("../tests/fixtures/key-pkcs1.pem");

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> TempDir {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("anago-tls-{}-{unique}", std::process::id()));
            fs::create_dir_all(&path).expect("temp dir");
            TempDir { path }
        }

        fn write(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
            let path = self.path.join(name);
            fs::write(&path, bytes).expect("write");
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn a_real_certificate_and_key_build_a_config() {
        assert!(build_config(CERT, KEY_PKCS8).is_ok());
    }

    #[test]
    fn every_encoding_the_usual_tools_emit_is_accepted() {
        // openssl writes PKCS#8 by default and SEC1 with `openssl ec`;
        // older tooling and `-traditional` write PKCS#1.
        assert!(matches!(parse_key(KEY_PKCS8), Ok(PrivateKeyDer::Pkcs8(_))));
        assert!(matches!(parse_key(KEY_SEC1), Ok(PrivateKeyDer::Sec1(_))));
        assert!(matches!(parse_key(KEY_PKCS1), Ok(PrivateKeyDer::Pkcs1(_))));
        // The SEC1 copy is the same key, so it serves the same cert.
        assert!(build_config(CERT, KEY_SEC1).is_ok());
    }

    #[test]
    fn a_key_that_does_not_match_the_certificate_is_refused() {
        // The RSA fixture is unrelated to the EC certificate.
        let e = build_config(CERT, KEY_PKCS1).unwrap_err();
        assert!(matches!(e, PemError::Rejected(_)), "{e:?}");
        assert!(e.to_string().contains("do they belong together?"), "{e}");
    }

    #[test]
    fn swapping_the_two_files_says_which_one_is_wrong() {
        // The most likely mistake: --tls-cert and --tls-key crossed.
        assert_eq!(parse_certs(KEY_PKCS8), Err(PemError::NoCertificates));
        assert_eq!(parse_key(CERT), Err(PemError::NoPrivateKey));
        assert_eq!(
            build_config(KEY_PKCS8, CERT).map(|_| ()),
            Err(PemError::NoCertificates)
        );
    }

    #[test]
    fn several_keys_in_one_file_are_not_guessed_between() {
        let mut both = KEY_PKCS8.to_vec();
        both.extend_from_slice(KEY_PKCS1);
        assert_eq!(parse_key(&both), Err(PemError::ManyPrivateKeys(2)));
        assert!(
            parse_key(&both)
                .unwrap_err()
                .to_string()
                .contains("exactly one"),
            "message should say what to do"
        );
    }

    #[test]
    fn a_full_chain_keeps_every_certificate_in_order() {
        // fullchain.pem is leaf + intermediates; all of them must go.
        let mut chain = CERT.to_vec();
        chain.extend_from_slice(CERT);
        let certs = parse_certs(&chain).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0], certs[1]);
    }

    #[test]
    fn garbage_is_reported_as_not_being_pem() {
        assert_eq!(parse_certs(b""), Err(PemError::NoCertificates));
        assert_eq!(parse_certs(b"hello"), Err(PemError::NoCertificates));
        assert_eq!(parse_key(b"hello"), Err(PemError::NoPrivateKey));
        // A PEM header with unusable content is malformed, not empty.
        let broken = b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
        assert!(matches!(parse_certs(broken), Err(PemError::Malformed(_))));
    }

    #[test]
    fn loading_from_disk_names_the_file_that_failed() {
        let dir = TempDir::new();
        let cert = dir.write("cert.pem", CERT, 0o644);
        let key = dir.write("key.pem", KEY_PKCS8, 0o600);
        let missing = dir.path.join("nope.pem");

        let e = load(&missing, &key).unwrap_err();
        assert!(
            e.to_string().starts_with(&missing.display().to_string()),
            "{e}"
        );
        assert!(e.to_string().contains("not found"), "{e}");
        assert!(
            e.to_string().contains("M0 does not issue certificates"),
            "{e}"
        );

        let e = load(&cert, &missing).unwrap_err();
        assert!(
            e.to_string().starts_with(&missing.display().to_string()),
            "{e}"
        );

        // A directory where a file belongs.
        let e = load(&dir.path, &key).unwrap_err();
        assert!(matches!(e, TlsError::Io { .. }), "{e:?}");
    }

    #[test]
    fn a_pem_problem_is_attributed_to_the_right_file() {
        let dir = TempDir::new();
        let cert = dir.write("cert.pem", CERT, 0o644);
        let key = dir.write("key.pem", KEY_PKCS8, 0o600);

        // Files crossed: the certificate slot holds a key.
        let e = load(&key, &cert).unwrap_err();
        assert_eq!(
            e,
            TlsError::Pem {
                path: key.clone(),
                error: PemError::NoCertificates,
            }
        );

        // A cert file in the key slot is the key file's problem.
        let e = load(&cert, &cert).unwrap_err();
        assert_eq!(
            e,
            TlsError::Pem {
                path: cert,
                error: PemError::NoPrivateKey,
            }
        );
    }

    #[test]
    fn a_malformed_file_is_blamed_on_the_file_that_is_malformed() {
        // Regression: both sides can produce PemError::Malformed, so
        // the blame has to come from which parse failed, not a guess.
        let dir = TempDir::new();
        let cert = dir.write("cert.pem", CERT, 0o644);
        let key = dir.write("key.pem", KEY_PKCS8, 0o600);
        let broken_key = dir.write(
            "broken-key.pem",
            b"-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n",
            0o600,
        );
        let broken_cert = dir.write(
            "broken-cert.pem",
            b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
            0o644,
        );

        match load(&cert, &broken_key).unwrap_err() {
            TlsError::Pem { path, error } => {
                assert_eq!(path, broken_key, "a broken key must point at --tls-key");
                assert!(matches!(error, PemError::Malformed(_)), "{error:?}");
            }
            other => panic!("{other:?}"),
        }

        match load(&broken_cert, &key).unwrap_err() {
            TlsError::Pem { path, error } => {
                assert_eq!(path, broken_cert);
                assert!(matches!(error, PemError::Malformed(_)), "{error:?}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_mismatched_pair_names_both_files() {
        // Neither file is wrong on its own; the message has to say so.
        let dir = TempDir::new();
        let cert = dir.write("cert.pem", CERT, 0o644);
        let key = dir.write("other-key.pem", KEY_PKCS1, 0o600);

        let e = load(&cert, &key).unwrap_err();
        match &e {
            TlsError::Pair {
                cert_path,
                key_path,
                error,
            } => {
                assert_eq!(cert_path, &cert);
                assert_eq!(key_path, &key);
                assert!(matches!(error, PemError::Rejected(_)), "{error:?}");
            }
            other => panic!("{other:?}"),
        }
        let message = e.to_string();
        assert!(message.contains(&cert.display().to_string()), "{message}");
        assert!(message.contains(&key.display().to_string()), "{message}");
        assert!(message.contains("do they belong together?"), "{message}");
    }

    #[test]
    fn a_world_readable_key_is_a_warning_not_a_refusal() {
        // The file may belong to certbot or a Cloudflare origin-cert
        // layout anago does not own, so it says so and serves anyway.
        let dir = TempDir::new();
        let cert = dir.write("cert.pem", CERT, 0o644);
        let key = dir.write("key.pem", KEY_PKCS8, 0o644);

        let loaded = load(&cert, &key).unwrap();
        assert_eq!(loaded.warnings.len(), 1, "{:?}", loaded.warnings);
        assert!(loaded.warnings[0].contains("readable by other users"));
        assert!(loaded.warnings[0].contains("chmod 600"));
    }

    #[test]
    fn a_private_key_file_draws_no_complaint() {
        let dir = TempDir::new();
        let cert = dir.write("cert.pem", CERT, 0o644);
        let key = dir.write("key.pem", KEY_PKCS8, 0o600);
        assert!(load(&cert, &key).unwrap().warnings.is_empty());
    }

    #[test]
    fn the_permission_rule_covers_group_and_other() {
        let path = Path::new("/etc/ssl/anago/privkey.pem");
        assert_eq!(permission_warning(path, Some(0o600)), None);
        assert_eq!(permission_warning(path, Some(0o400)), None);
        assert_eq!(permission_warning(path, None), None);
        for mode in [0o640, 0o604, 0o644, 0o660, 0o666, 0o777] {
            let warning = permission_warning(path, Some(mode))
                .unwrap_or_else(|| panic!("mode {mode:04o} should warn"));
            assert!(warning.contains(&format!("{mode:04o}")), "{warning}");
        }
    }

    #[test]
    fn hints_point_at_the_likely_cause() {
        assert!(io_hint(io::ErrorKind::NotFound).contains("M0 does not issue certificates"));
        assert!(io_hint(io::ErrorKind::PermissionDenied).contains("as root"));
        assert!(io_hint(io::ErrorKind::IsADirectory).contains("not the directory"));
        assert!(io_hint(io::ErrorKind::Other).contains("exists and is readable"));
    }

    #[test]
    fn a_renewed_certificate_reaches_the_listener_without_a_restart() {
        // Without this the renewal is pointless: the config is built
        // once at startup, so a hub would keep presenting the expired
        // certificate until somebody restarted it.
        let dir = std::env::temp_dir().join(format!("anago-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("fullchain.pem");
        let key = dir.join("privkey.pem");
        std::fs::write(&cert, CERT_A).unwrap();
        std::fs::write(&key, KEY_A).unwrap();

        let listening = Listening::new(load(&cert, &key).expect("the first pair"));
        // The handle the listener was given at startup, held on to for
        // the length of the run.
        let listener = listening.config();
        let before = listener.get_inner();

        // What a renewal does: replace both files, load the new pair,
        // and only then present it.
        std::fs::write(&cert, CERT_B).unwrap();
        std::fs::write(&key, KEY_B).unwrap();
        let renewed = load(&cert, &key).expect("the renewed pair");
        assert_eq!(reload(&listening.lock(), Ok(&renewed.chain)), Reload::Swap);
        listening.present(renewed);

        let after = listener.get_inner();
        assert!(
            !Arc::ptr_eq(&before, &after),
            "the listener is still holding the configuration it started with"
        );
        // And the handle the listener holds is the same one — the swap
        // happens underneath it, not beside it.
        assert!(Arc::ptr_eq(&after, &listener.get_inner()));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_half_written_pair_leaves_the_old_certificate_serving() {
        // The reload reads the files again rather than taking what the
        // issuance had in memory, so a pair that does not match is
        // caught here — while the hub is still serving the old one —
        // instead of at the next restart.
        let dir = std::env::temp_dir().join(format!("anago-tls-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("fullchain.pem");
        let key = dir.join("privkey.pem");
        std::fs::write(&cert, CERT_A).unwrap();
        std::fs::write(&key, KEY_A).unwrap();

        let listener = Listening::new(load(&cert, &key).expect("the first pair")).config();
        let before = listener.get_inner();

        // The certificate of one pair with the key of another. The
        // load fails, so there is nothing to swap — the failure lands
        // before the state file is written, not after.
        std::fs::write(&cert, CERT_B).unwrap();
        assert!(load(&cert, &key).is_err());
        assert!(
            Arc::ptr_eq(&before, &listener.get_inner()),
            "a mismatched pair was put in front of the listener"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_expiry_comes_out_of_the_certificate_itself() {
        // The renewal schedule is two thirds of the *actual* lifetime
        // (§9.1), so this is an input and not a display detail — and
        // Let's Encrypt is in the middle of moving from 90 days to 45.
        // CERT_A carries `notAfter` 2126-07-26T01:03:31Z, in the
        // GeneralizedTime form anything past 2049 has to use.
        let a = chain(CERT_A);
        assert_eq!(a.expiry(), Some(4_940_701_411));
        assert_eq!(expiry(CERT_A.as_bytes()), Some(4_940_701_411));

        // The leaf, not the whole chain: an intermediate outlives it
        // and expires on somebody else's schedule.
        let with_intermediate =
            Chain(parse_certs(format!("{CERT_A}{CERT_B}").as_bytes()).expect("two certificates"));
        assert_eq!(with_intermediate.expiry(), a.expiry());

        // And the fixture pair, which is what `load` sees.
        let dir = TempDir::new();
        let cert = dir.write("cert.pem", CERT, 0o644);
        let key = dir.write("key.pem", KEY_PKCS8, 0o600);
        assert!(
            load(&cert, &key).unwrap().not_after.is_some(),
            "a real certificate's expiry could not be read"
        );

        // Nothing readable is `None` rather than a refusal: the file
        // still serves, the schedule falls back, and the output says
        // it could not read the date.
        assert_eq!(expiry(b"not pem"), None);
    }

    #[test]
    fn a_certificate_that_has_not_changed_is_not_swapped_in_again() {
        // The check runs every hour and a certificate lasts ninety
        // days, so "nothing to do" is the answer almost every time.
        // It is also the answer right after anago's own renewal, which
        // has already put the pair it validated in front of the
        // listener — one swap, not two.
        let a = chain(CERT_A);
        assert_eq!(reload(&a, Ok(&a.clone())), Reload::Unchanged);
        assert_eq!(reload(&a, Ok(&chain(CERT_B))), Reload::Swap);
    }

    #[test]
    fn a_new_intermediate_is_a_new_chain_even_under_the_same_leaf() {
        // Regression: comparing only the leaf would call this
        // unchanged. A CA that starts cross-signing from a different
        // intermediate reissues the same leaf under a new chain, and a
        // hub that kept the old intermediates would hand clients a
        // chain they cannot build a path from — until somebody
        // restarted it.
        let leaf_only = chain(CERT_A);
        let with_intermediate =
            Chain(parse_certs(format!("{CERT_A}{CERT_B}").as_bytes()).expect("two certificates"));
        assert_eq!(reload(&leaf_only, Ok(&with_intermediate)), Reload::Swap);
        assert_eq!(reload(&with_intermediate, Ok(&leaf_only)), Reload::Swap);

        // And order is part of it: the chain is what goes on the wire,
        // leaf first.
        let reversed = Chain({
            let mut certs = with_intermediate.0.clone();
            certs.reverse();
            certs
        });
        assert_eq!(reload(&with_intermediate, Ok(&reversed)), Reload::Swap);
    }

    #[test]
    fn a_pair_caught_half_written_does_not_take_the_hub_down() {
        // certbot writes fullchain.pem and privkey.pem as two files. A
        // check that lands between them sees a certificate that does
        // not match its key — for a second, once every sixty days.
        // Refusing to serve over that would turn a renewal into an
        // outage; the certificate already in front of the listener is
        // still valid, so it stays.
        let serving = chain(CERT_A);
        let mid_write = TlsError::Pair {
            cert_path: PathBuf::from("/etc/letsencrypt/live/net.example.com/fullchain.pem"),
            key_path: PathBuf::from("/etc/letsencrypt/live/net.example.com/privkey.pem"),
            error: PemError::Rejected("key does not match certificate".to_string()),
        };
        let Reload::Keep(why) = reload(&serving, Err(&mid_write)) else {
            panic!("a half-written pair must not disturb the listener");
        };
        assert!(why.contains("still serving"), "{why}");
        assert!(why.contains("look again"), "{why}");
        // The message keeps the original diagnosis, so a file that is
        // broken for good rather than for a second can be told apart.
        assert!(why.contains("fullchain.pem"), "{why}");
        assert!(why.contains("do they belong together?"), "{why}");

        // A file that was deleted reads the same way: the hub goes on
        // serving, and says what it could not read.
        let gone = TlsError::Io {
            path: PathBuf::from("/etc/ssl/anago/fullchain.pem"),
            kind: io::ErrorKind::NotFound,
            hint: io_hint(io::ErrorKind::NotFound),
        };
        assert!(matches!(reload(&serving, Err(&gone)), Reload::Keep(_)));
    }

    #[test]
    fn a_certificate_replaced_by_another_process_reaches_the_listener() {
        // The gap this closes: a manual hub whose certbot renews the
        // file, or a `server renew` typed by hand while the hub runs.
        // Neither goes through the renewal that presents its own pair,
        // so without this look the listener presents the old
        // certificate until somebody restarts the process.
        let dir = std::env::temp_dir().join(format!("anago-tls-reload-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("fullchain.pem");
        let key = dir.join("privkey.pem");
        std::fs::write(&cert, CERT_A).unwrap();
        std::fs::write(&key, KEY_A).unwrap();

        let listening = Listening::new(load(&cert, &key).expect("the first pair"));
        let listener = listening.config();
        let started_with = listener.get_inner();

        // Nothing has changed yet.
        assert_eq!(listening.take(load(&cert, &key)), Reload::Unchanged);
        assert!(Arc::ptr_eq(&started_with, &listener.get_inner()));

        // Somebody else wrote the certificate half and not yet the key.
        std::fs::write(&cert, CERT_B).unwrap();
        assert!(matches!(listening.take(load(&cert, &key)), Reload::Keep(_)));
        assert!(
            Arc::ptr_eq(&started_with, &listener.get_inner()),
            "a mismatched pair was put in front of the listener"
        );

        // And now the key half.
        std::fs::write(&key, KEY_B).unwrap();
        assert_eq!(listening.take(load(&cert, &key)), Reload::Swap);
        let swapped = listener.get_inner();
        assert!(!Arc::ptr_eq(&started_with, &swapped));

        // The next look has nothing to do — which is how the hub knows
        // the renewal actually reached the listener.
        assert_eq!(listening.take(load(&cert, &key)), Reload::Unchanged);
        assert!(Arc::ptr_eq(&swapped, &listener.get_inner()));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn presenting_a_certificate_moves_the_handle_and_the_record_together() {
        // Regression: `present` used to change the handle and leave the
        // chain it compares against untouched, which is the state
        // anago's own renewal ends in. Two things went wrong from
        // there — the very next look called the certificate it had just
        // installed "different" and installed it again, and a file put
        // back to the *previous* certificate read as "unchanged", so
        // the listener went on serving one certificate while the disk
        // held another with nothing left to notice it.
        let dir = std::env::temp_dir().join(format!("anago-tls-present-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("fullchain.pem");
        let key = dir.join("privkey.pem");
        std::fs::write(&cert, CERT_A).unwrap();
        std::fs::write(&key, KEY_A).unwrap();

        let listening = Listening::new(load(&cert, &key).expect("the first pair"));
        let listener = listening.config();

        // What a renewal does: write the pair, load it, present it.
        std::fs::write(&cert, CERT_B).unwrap();
        std::fs::write(&key, KEY_B).unwrap();
        let renewed = load(&cert, &key).expect("the renewed pair");
        listening.present(renewed);
        let presented = listener.get_inner();

        // The look that follows a renewal finds it already done.
        assert_eq!(listening.take(load(&cert, &key)), Reload::Unchanged);
        assert!(
            Arc::ptr_eq(&presented, &listener.get_inner()),
            "the certificate anago had just installed was installed again"
        );

        // And a rollback on disk is seen for what it is, rather than
        // read as "the same as what I remember".
        std::fs::write(&cert, CERT_A).unwrap();
        std::fs::write(&key, KEY_A).unwrap();
        assert_eq!(listening.take(load(&cert, &key)), Reload::Swap);
        assert!(!Arc::ptr_eq(&presented, &listener.get_inner()));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The chain of a one-certificate PEM, for the comparisons above.
    fn chain(pem: &str) -> Chain {
        Chain(parse_certs(pem.as_bytes()).expect("a certificate"))
    }
}
