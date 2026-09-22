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
