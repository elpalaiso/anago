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
use std::sync::Arc;

use axum::Router;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

/// Certificate and key, ready to serve, plus anything worth telling the
/// operator about how they are stored.
#[derive(Debug)]
pub struct LoadedTls {
    pub config: ServerConfig,
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
    let config = build_from_parts(certs, key).map_err(|error| TlsError::Pair {
        cert_path: cert_path.to_path_buf(),
        key_path: key_path.to_path_buf(),
        error,
    })?;

    let mut warnings = Vec::new();
    if let Some(warning) = permission_warning(key_path, mode_of(key_path)) {
        warnings.push(warning);
    }
    Ok(LoadedTls { config, warnings })
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

/// A handle the listener will read from.
pub fn reloadable(config: ServerConfig) -> Reloadable {
    Reloadable::from_config(Arc::new(config))
}

/// Puts an already-loaded certificate in front of the listener.
///
/// **This cannot fail, and that is the point.** Reading and validating
/// the new pair is [`load`]'s job and belongs *before* the state file
/// is written; if the swap could fail after that, a hub would record a
/// renewal it is not actually serving and then sit on the old
/// certificate until it expired — the next check would see a fresh
/// `renew_after` and do nothing (§9.1).
pub fn swap(handle: &Reloadable, config: ServerConfig) {
    handle.reload_from_config(Arc::new(config));
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

#[cfg(test)]
mod tests {

    /// A throwaway self-signed pair, so that the reload below swaps one
    /// real certificate for another rather than a stub for a stub.
    /// Generated for these tests; the key is public by construction and
    /// belongs to nothing.
    const CERT_A: &str = "-----BEGIN CERTIFICATE-----\nMIIBizCCATGgAwIBAgIUXys43iONJV3kteA847Y5xzoj17IwCgYIKoZIzj0EAwIw\nGjEYMBYGA1UEAwwPbmV0LmV4YW1wbGUuY29tMCAXDTI2MDgxOTAxMDMzMVoYDzIx\nMjYwNzI2MDEwMzMxWjAaMRgwFgYDVQQDDA9uZXQuZXhhbXBsZS5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAASIPDFfU6+LAbNbhiXtHYBvPGNb5Lp0tn3wCtNs\nCWrwvUKevnHcY3CpHbUPD9kvdFLf4iBc+1X1GrobIk/QuNyyo1MwUTAdBgNVHQ4E\nFgQUsKLJkykZ5Mf5ggjV7x7w60lfNB0wHwYDVR0jBBgwFoAUsKLJkykZ5Mf5ggjV\n7x7w60lfNB0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiAv3pv/\nBs1Xj/35QG7dLCSCdtW5I6IDtUczwK65XhZyLAIhAOtE22DgWemYIHCCivp6FbtW\n/g/Xq40tYP8VUqc3Fj3Q\n-----END CERTIFICATE-----\n";
    const KEY_A: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgp10L63N+7ARRCawO\n8pJL1eNELGVFFaLLNTSTOMxnDyehRANCAASIPDFfU6+LAbNbhiXtHYBvPGNb5Lp0\ntn3wCtNsCWrwvUKevnHcY3CpHbUPD9kvdFLf4iBc+1X1GrobIk/QuNyy\n-----END PRIVATE KEY-----\n";
    const CERT_B: &str = "-----BEGIN CERTIFICATE-----\nMIIBizCCATGgAwIBAgIUE6efSE+EQmY2ekTk7j/rS4NRFSwwCgYIKoZIzj0EAwIw\nGjEYMBYGA1UEAwwPaHViLmV4YW1wbGUuY29tMCAXDTI2MDgxOTAxMDMzMVoYDzIx\nMjYwNzI2MDEwMzMxWjAaMRgwFgYDVQQDDA9odWIuZXhhbXBsZS5jb20wWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAATEhl6fe5R+QSX6ZKriCNz2c8SL6Wya5KzML+3r\nFRrvUhoVa5lxmlUrP4orq6b4+kenCMqRoz96ppNvzYxxgq0ro1MwUTAdBgNVHQ4E\nFgQU6+bq37P6bQZEe33mpuCwWKQxGt4wHwYDVR0jBBgwFoAU6+bq37P6bQZEe33m\npuCwWKQxGt4wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA0Ijg\nGiMB5fb4jBmzBBXwqBc5ZiMs133hw97eDNUvRnUCIC98UgP1FrpeMv0eIOnNC+i1\n6Fw/trHxdI/h+9TYS+AQ\n-----END CERTIFICATE-----\n";
    const KEY_B: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgX7aCvnsuEiXKyS/s\ntWHFaxT7bXCgzf2oEe+7ZBlLEDuhRANCAATEhl6fe5R+QSX6ZKriCNz2c8SL6Wya\n5KzML+3rFRrvUhoVa5lxmlUrP4orq6b4+kenCMqRoz96ppNvzYxxgq0r\n-----END PRIVATE KEY-----\n";
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

        let loaded = load(&cert, &key).expect("the first pair");
        let handle = reloadable(loaded.config);
        let before = handle.get_inner();

        // What a renewal does: replace both files, load the new pair,
        // and only then swap it in.
        std::fs::write(&cert, CERT_B).unwrap();
        std::fs::write(&key, KEY_B).unwrap();
        let renewed = load(&cert, &key).expect("the renewed pair");
        swap(&handle, renewed.config);

        let after = handle.get_inner();
        assert!(
            !Arc::ptr_eq(&before, &after),
            "the listener is still holding the configuration it started with"
        );
        // And the handle the listener holds is the same one — the swap
        // happens underneath it, not beside it.
        assert!(Arc::ptr_eq(&after, &handle.get_inner()));

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

        let handle = reloadable(load(&cert, &key).expect("the first pair").config);
        let before = handle.get_inner();

        // The certificate of one pair with the key of another. The
        // load fails, so there is nothing to swap — the failure lands
        // before the state file is written, not after.
        std::fs::write(&cert, CERT_B).unwrap();
        assert!(load(&cert, &key).is_err());
        assert!(
            Arc::ptr_eq(&before, &handle.get_inner()),
            "a mismatched pair was put in front of the listener"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
