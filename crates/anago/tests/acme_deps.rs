//! Proof that the ACME dependency set works with the flags
//! `Cargo.toml` picks (DESIGN.md §10.2).
//!
//! The issuance code lands in a later slice. What is checked here is
//! the part that is easy to get wrong while trimming features and
//! painful to discover later: that `instant-acme` builds without
//! `aws-lc-rs`, that its client can actually be constructed on the
//! crypto provider anago pins, and that the strings anago's CLI and
//! design refer to are the ones the library uses.

use instant_acme::{Account, ChallengeType, Identifier, LetsEncrypt, NewOrder};

#[test]
fn the_acme_client_lands_on_ring_because_nothing_else_is_compiled_in() {
    // instant-acme's own HTTP client reaches rustls's *implicit*
    // provider — anago's own call sites all pass one explicitly
    // (`builder_with_provider`), so this is the one place the choice is
    // made for it. rustls resolves that from the crate features: with
    // exactly one provider compiled in it installs that one, with both
    // or neither it panics. anago compiles in `ring` and only `ring`,
    // which is what makes the implicit path safe here — and what this
    // test is really pinning, since the failure it guards against is a
    // feature flag quietly putting aws-lc-rs (and a C toolchain
    // requirement) under the ACME client.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        Account::builder().expect("an ACME client on the trimmed feature set");
    });

    let installed =
        rustls::crypto::CryptoProvider::get_default().expect("building the client installs one");
    let ring = rustls::crypto::ring::default_provider();
    let installed_suites: Vec<_> = installed
        .cipher_suites
        .iter()
        .map(|suite| suite.suite())
        .collect();
    let ring_suites: Vec<_> = ring
        .cipher_suites
        .iter()
        .map(|suite| suite.suite())
        .collect();
    assert_eq!(installed_suites, ring_suites, "the ACME client is on ring");
}

#[test]
fn the_challenge_names_are_the_ones_the_cli_takes() {
    // `--acme-challenge http-01|dns-01` (§8) has to spell these the way
    // the protocol does, or the flag parses and nothing matches.
    assert_eq!(
        serde_json::from_str::<ChallengeType>(r#""http-01""#).unwrap(),
        ChallengeType::Http01
    );
    assert_eq!(
        serde_json::from_str::<ChallengeType>(r#""dns-01""#).unwrap(),
        ChallengeType::Dns01
    );
}

#[test]
fn staging_and_production_are_the_directories_the_design_names() {
    // `--acme-staging` exists so a first run cannot spend a week's
    // rate limit (§13); it is only worth having if it points somewhere
    // else than production.
    assert_eq!(
        LetsEncrypt::Staging.url(),
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    );
    assert_eq!(
        LetsEncrypt::Production.url(),
        "https://acme-v02.api.letsencrypt.org/directory"
    );
    assert_ne!(LetsEncrypt::Staging.url(), LetsEncrypt::Production.url());
}

#[test]
fn an_order_names_the_hub_domain_and_nothing_else() {
    // One hub, one name: no wildcard, no second identifier. The shape
    // the issuance slice will build.
    let identifiers = [Identifier::Dns("net.example.com".to_string())];
    let order = NewOrder::new(&identifiers);
    let body = serde_json::to_value(&order).expect("an order serializes");
    assert_eq!(
        body["identifiers"],
        serde_json::json!([{ "type": "dns", "value": "net.example.com" }])
    );
    assert!(body.get("replaces").is_none(), "ARI is not enabled (§10.2)");
}
