//! Both legs of the PQ/T combiner (draft-ietf-mls-combiner), end to end.
//!
//! APHONE-1267. The traditional leg is `MLS_256_DHKEMP521_AES256GCM_SHA512_P521`
//! (0x0005); the PQ leg is `MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65` (0x0051).
//! Both must work against the same provider, which is why `openmls_rust_crypto`
//! uses the libcrux HPKE backend: `hpke-rs-rust-crypto` has no `DhKemP521` arm.
//!
//!   cargo +1.91.0 test -p openmls \
//!     --features test-utils,draft-ietf-mls-pq-ciphersuites \
//!     --test pqt_combiner_legs -- --nocapture

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize, Serialize};

const TRADITIONAL: Ciphersuite = Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521;
const PQ: Ciphersuite = Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65;

fn is_advertised(cs: Ciphersuite) {
    let provider = OpenMlsRustCrypto::default();
    provider
        .crypto()
        .supports(cs)
        .unwrap_or_else(|e| panic!("{cs:?} not supported: {e:?}"));
    assert!(
        provider.crypto().supported_ciphersuites().contains(&cs),
        "{cs:?} missing from supported_ciphersuites()"
    );
}

/// Builds a KeyPackage, round-trips it through the wire format and re-validates
/// it — exactly what the backend does on upload — then exercises the KEM itself
/// by sealing to the init key and opening with the init private key.
fn key_package_and_hpke_roundtrip(cs: Ciphersuite, label: &str) {
    let provider = OpenMlsRustCrypto::default();

    let credential = BasicCredential::new(label.as_bytes().to_vec());
    let signer = SignatureKeyPair::new(cs.signature_algorithm())
        .unwrap_or_else(|e| panic!("{label}: signature keypair generation failed: {e:?}"));

    let bundle = KeyPackage::builder()
        .build(
            cs,
            &provider,
            &signer,
            CredentialWithKey {
                credential: credential.into(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .unwrap_or_else(|e| panic!("{label}: KeyPackage build failed: {e:?}"));

    let kp = bundle.key_package();
    assert_eq!(kp.ciphersuite(), cs);

    let bytes = kp.tls_serialize_detached().expect("serialize failed");
    let parsed = KeyPackageIn::tls_deserialize(&mut bytes.as_slice()).expect("deserialize failed");
    let validated = parsed
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap_or_else(|e| panic!("{label}: KeyPackage failed validation: {e:?}"));
    assert_eq!(validated.ciphersuite(), cs);

    let pt = b"pq/t combiner leg";
    let info = b"info";
    let aad = b"aad";

    let ct = provider
        .crypto()
        .hpke_seal(cs.hpke_config(), kp.hpke_init_key().as_slice(), info, aad, pt)
        .unwrap_or_else(|e| panic!("{label}: hpke_seal failed: {e:?}"));
    let opened = provider
        .crypto()
        .hpke_open(cs.hpke_config(), &ct, bundle.init_private_key(), info, aad)
        .unwrap_or_else(|e| panic!("{label}: hpke_open failed: {e:?}"));
    assert_eq!(opened, pt, "{label}: HPKE round-trip produced wrong plaintext");

    println!(
        "{label} OK: KeyPackage {} bytes, init_key {} bytes",
        bytes.len(),
        kp.hpke_init_key().as_slice().len()
    );
}

#[test]
fn traditional_leg_is_advertised() {
    is_advertised(TRADITIONAL);
}

#[test]
fn pq_leg_is_advertised() {
    is_advertised(PQ);
}

#[test]
fn traditional_leg_works_end_to_end() {
    key_package_and_hpke_roundtrip(TRADITIONAL, "P-521");
}

#[test]
fn pq_leg_works_end_to_end() {
    key_package_and_hpke_roundtrip(PQ, "ML-KEM-768/ML-DSA-65");
}
