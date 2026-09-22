use crate::crypto::agility::{verify_signature_by_algorithm, CaKeyPair, KeyAlgorithm};
use crate::pki::ca::CaDeclaration;
use crate::pki::cert::builder::{X509Certificate, X509CertificateBuilder};
use crate::pki::chain::{
    extract_certificate_signature_bytes, extract_spki_public_key_bytes,
    extract_tbs_certificate_bytes,
};

/// Builds a real X.509 DER mock capability certificate via standard X509CertificateBuilder (CA-05)
///
/// Uses the existing X509CertificateBuilder::build_domain_leaf_certificate to produce
/// a standard certificate with all RFC 5280 and randbotd extensions (WoT, AIA, CDP, SAN, Proof Binding)
/// embedding the challenge nonce in a protocol mock domain.
pub fn build_mock_capability_certificate(
    ca_decl: &CaDeclaration,
    algorithm: KeyAlgorithm,
    challenge_nonce: u64,
    ttl_seconds: u64,
    current_time: u64,
) -> Result<X509Certificate, String> {
    let mock_keypair = CaKeyPair::generate(algorithm)?;
    let domain = format!("mock-{}.randbotd.internal", challenge_nonce);
    let mock_uri = format!("randbotd://rand-mock-domain?nonce={}", challenge_nonce);
    let proof_binding = format!("challenge_nonce:{}", challenge_nonce);

    X509CertificateBuilder::build_domain_leaf_certificate(
        ca_decl,
        &mock_keypair,
        &domain,
        algorithm,
        &mock_keypair.public_key_bytes,
        vec![domain.clone(), mock_uri],
        ttl_seconds,
        current_time,
        Some(&proof_binding),
    )
}

/// Pure Rust validation for incoming mock capability certificates (Zero OpenSSL dependency)
///
/// Verifies:
/// 1. ASN.1 DER certificate framing and field extraction.
/// 2. Cryptographic signature validity under the advertised algorithm.
/// 3. Inherent binding to the expected challenge nonce in the TBS certificate payload.
pub fn verify_mock_capability_certificate(
    cert_der: &[u8],
    expected_algorithm: KeyAlgorithm,
    expected_nonce: u64,
) -> Result<(), String> {
    if cert_der.is_empty() {
        return Err("Empty certificate bytes".to_string());
    }

    // 1. Extract TBS, signature, and SPKI public key bytes
    let tbs_bytes = extract_tbs_certificate_bytes(cert_der)?;
    let sig_bytes = extract_certificate_signature_bytes(cert_der)?;
    let spki_pubkey = extract_spki_public_key_bytes(cert_der)?;

    // 2. Cryptographically verify signature under the expected algorithm
    verify_signature_by_algorithm(expected_algorithm, &spki_pubkey, &tbs_bytes, &sig_bytes)?;

    // 3. Confirm expected challenge nonce presence in TBS certificate payload
    let nonce_str = expected_nonce.to_string();
    let nonce_bytes = nonce_str.as_bytes();
    let nonce_found = tbs_bytes
        .windows(nonce_bytes.len())
        .any(|window| window == nonce_bytes);

    if !nonce_found {
        return Err(format!(
            "Certificate does not contain expected challenge nonce {}",
            expected_nonce
        ));
    }

    Ok(())
}
