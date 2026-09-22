use super::*;

#[test]
fn test_custodian_contract_flow_and_signature() {
    let worker_sk = SigningKey::from_bytes(&[0x11u8; 32]);
    let ca_id = [0x42u8; 32];
    let created_at = 1000;
    let valid_until = 2000;
    let tcp_endpoint = "127.0.0.1:43210".to_string();

    let contract = CustodianContract::new(
        ca_id,
        &worker_sk,
        25,
        created_at,
        valid_until,
        tcp_endpoint.clone(),
    )
    .expect("Contract creation should succeed");

    assert_eq!(contract.work_share_pct, 25);
    assert!(!contract.is_expired(1500));
    assert!(contract.is_expired(2001));
    assert!(contract.verify_signature().is_ok());

    // Tampered contract fails signature verification
    let mut tampered = contract.clone();
    tampered.work_share_pct = 50;
    assert!(tampered.verify_signature().is_err());
}

#[test]
fn test_custodian_contract_bounds_validation() {
    let worker_sk = SigningKey::from_bytes(&[0x11u8; 32]);
    let ca_id = [0x42u8; 32];

    // Invalid work_share_pct > 100
    assert!(CustodianContract::new(
        ca_id,
        &worker_sk,
        101,
        1000,
        2000,
        "127.0.0.1:43210".to_string(),
    )
    .is_err());

    // Invalid valid_until <= created_at
    assert!(CustodianContract::new(
        ca_id,
        &worker_sk,
        20,
        2000,
        2000,
        "127.0.0.1:43210".to_string(),
    )
    .is_err());
}

#[test]
fn test_custodian_delegation_request_and_proof() {
    let worker_sk = SigningKey::from_bytes(&[0x11u8; 32]);
    let ca_sk = SigningKey::from_bytes(&[0x22u8; 32]);
    let ca_pubkey = ca_sk.verifying_key().to_bytes();
    let ca_id = [0x11u8; 32];

    let contract = CustodianContract::new(
        ca_id,
        &worker_sk,
        20,
        1000,
        5000,
        "127.0.0.1:43210".to_string(),
    )
    .unwrap();
    let contract_hash = contract.contract_hash();

    // Step 2: CA issues delegation challenge
    let challenge = CustodianDelegationRequest::new(
        ca_id,
        contract.worker_pubkey,
        contract_hash,
        99999,
        1,
        &ca_sk,
    );
    assert!(challenge.verify_signature(&ca_pubkey).is_ok());

    // Step 3: Worker generates dummy cert hash and emits proof
    let mock_cert_hash = [0x99u8; 32];
    let proof = CACapabilitiesProof::new(
        ca_id,
        &worker_sk,
        contract_hash,
        mock_cert_hash,
        KeyAlgorithm::MlDsa44,
        4500,
    );
    assert!(proof.verify_signature().is_ok());

    // Step 4: CA confirms swarm activation
    let confirmation = SwarmActivationConfirmation::new(
        ca_id,
        contract.worker_pubkey,
        contract_hash,
        mock_cert_hash,
        3000, // activated_at < valid_until (5000)
        &ca_sk,
    );
    assert!(confirmation
        .verify_against_contract(&contract, &ca_pubkey)
        .is_ok());

    // Consensus rule: Expired contract rejection
    let expired_confirmation = SwarmActivationConfirmation::new(
        ca_id,
        contract.worker_pubkey,
        contract_hash,
        mock_cert_hash,
        5001, // activated_at > valid_until (5000)
        &ca_sk,
    );
    let err = expired_confirmation
        .verify_against_contract(&contract, &ca_pubkey)
        .unwrap_err();
    assert!(err.contains("Consensus violation: contract expired"));
}

use crate::pki::ca::{CaDeclaration, CaSubjectMetadata};
use crate::proof::DomainNetworkType;

#[test]
fn test_real_mock_capability_certificate_build_and_pure_rust_verify() {
    let challenge_nonce = 123456789u64;
    let ca_id = [0x55u8; 32];
    let ca_subject = CaSubjectMetadata {
        common_name: "Swarm Test CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: None,
        locality: None,
        state_or_province: None,
        country: Some("IS".to_string()),
        email: None,
    };
    let ca_decl = CaDeclaration::new(
        ca_id,
        ca_subject.clone(),
        ca_subject,
        false,
        None,
        Vec::new(),
        1000,
        false,
        vec![DomainNetworkType::Clearnet],
    )
    .unwrap();

    // 1. Build real DER mock cert with Ed25519
    let cert_ed25519 = build_mock_capability_certificate(
        &ca_decl,
        KeyAlgorithm::Ed25519,
        challenge_nonce,
        3600,
        1000,
    )
    .expect("Ed25519 mock cert build should succeed");

    assert!(cert_ed25519.pem_certificate.contains("BEGIN CERTIFICATE"));
    assert!(cert_ed25519.sans[0].contains(&challenge_nonce.to_string()));

    // Verify valid cert passes
    assert!(verify_mock_capability_certificate(
        &cert_ed25519.der_bytes,
        KeyAlgorithm::Ed25519,
        challenge_nonce,
    )
    .is_ok());

    // Wrong challenge nonce fails verification
    let wrong_nonce = 999999999u64;
    assert!(verify_mock_capability_certificate(
        &cert_ed25519.der_bytes,
        KeyAlgorithm::Ed25519,
        wrong_nonce,
    )
    .is_err());

    // Wrong algorithm fails verification
    assert!(verify_mock_capability_certificate(
        &cert_ed25519.der_bytes,
        KeyAlgorithm::EcdsaP384,
        challenge_nonce,
    )
    .is_err());

    // 2. Build real DER mock cert with Post-Quantum ML-DSA-44
    let cert_mldsa = build_mock_capability_certificate(
        &ca_decl,
        KeyAlgorithm::MlDsa44,
        challenge_nonce,
        3600,
        1000,
    )
    .expect("ML-DSA-44 mock cert build should succeed");

    assert!(
        cert_mldsa.der_bytes.len() > 1400,
        "PQC cert must exceed UDP MTU"
    );

    assert!(verify_mock_capability_certificate(
        &cert_mldsa.der_bytes,
        KeyAlgorithm::MlDsa44,
        challenge_nonce,
    )
    .is_ok());
}
