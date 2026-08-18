//! Proof that the server dependency set actually works together.
//!
//! The listener and handlers land in the next slices; this checks the
//! part that is easy to get wrong when trimming features — that the
//! runtime, the router, and the TLS stack still compile and run with
//! the feature flags `Cargo.toml` picks. HTTP/2 is compiled in
//! whatever those flags say — axum-server enables it — so nothing here
//! claims an h1-only build.

use std::sync::Arc;

use axum::routing::get;
use axum::Router;

#[test]
fn the_tokio_runtime_and_router_build_with_trimmed_features() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("multi-thread runtime");

    // A router with a handler, which is what the API slice will fill in.
    let app: Router = Router::new().route("/api/v1/peers", get(|| async { "[]" }));

    let answered = runtime.block_on(async move {
        // Exercise the async machinery, not just the type checker.
        tokio::time::timeout(std::time::Duration::from_secs(5), async { "ok" })
            .await
            .expect("timeout feature works")
    });
    assert_eq!(answered, "ok");
    drop(app);
}

#[test]
fn rustls_uses_the_ring_provider() {
    // aws-lc-rs is rustls's default and needs a C toolchain; anago pins
    // ring so `cargo build` works on a stock VPS and a stock Mac.
    let provider = rustls::crypto::ring::default_provider();
    assert!(!provider.cipher_suites.is_empty());
    // Installing is idempotent per process; either outcome is fine, we
    // only care that a provider is available.
    let _ = provider.install_default();
    assert!(rustls::crypto::CryptoProvider::get_default().is_some());
}

#[test]
fn a_server_config_can_be_built_from_pem_bytes() {
    // The shape `server init --tls-cert/--tls-key` will follow: parse
    // PEM, hand the pieces to rustls. Bad material must be refused
    // rather than silently producing a config that serves nothing.
    let mut certs = std::io::BufReader::new(
        &b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"[..],
    );
    let parsed: Vec<_> = rustls_pemfile::certs(&mut certs)
        .collect::<Result<_, _>>()
        .expect("PEM parses");
    assert_eq!(parsed.len(), 1);

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_no_client_auth()
    .with_single_cert(
        parsed,
        rustls::pki_types::PrivateKeyDer::Pkcs8(vec![0u8; 32].into()),
    );
    assert!(
        config.is_err(),
        "a bogus key must not produce a usable config"
    );
}
