use super::*;
use crate::crypto::agility::CaKeyPair;
use crate::pki::ca::{compute_ca_id, CaSubjectMetadata};
use crate::proof::DomainNetworkType;

fn generate_test_ed25519_key() -> SigningKey {
    let mut rng = rand::rngs::OsRng;
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut secret);
    SigningKey::from_bytes(&secret)
}

fn sample_ca() -> (CaDeclaration, SigningKey) {
    let node_signing_key = generate_test_ed25519_key();
    let node_pubkey = node_signing_key.verifying_key().to_bytes();

    let subject = CaSubjectMetadata {
        common_name: "The Random Consortium Test Root".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: None,
        locality: Some("Valencia".to_string()),
        state_or_province: Some("Valencia".to_string()),
        country: Some("ES".to_string()),
        email: None,
    };
    let ca_id = compute_ca_id(&subject.common_name, &node_pubkey);
    let decl = CaDeclaration::new(
        ca_id,
        subject.clone(),
        subject,
        false,
        None,
        Vec::new(),
        1700000000,
        false,
        vec![DomainNetworkType::Clearnet],
    )
    .expect("Valid CA declaration");

    (decl, node_signing_key)
}

#[test]
fn test_proof_of_possession_generation_and_verification() {
    let (ca, _) = sample_ca();
    let keypair = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
    let timestamp = 1700001000;

    let pop_payload =
        OfferKeyRotation::compute_pop_payload(&ca.ca_id, 0, &keypair.public_key_bytes, timestamp);
    let pop_sig = keypair.sign(&pop_payload).unwrap();

    let rot = OfferKeyRotation {
        offer_id: 0,
        old_public_key: vec![1, 2, 3],
        new_public_key: keypair.public_key_bytes.clone(),
        key_algorithm: KeyAlgorithm::Ed25519,
        proof_of_possession: pop_sig,
        old_key_revocation_signature: None,
    };

    assert!(rot.verify_proof_of_possession(&ca.ca_id, timestamp).is_ok());

    // Tampered timestamp
    assert!(rot
        .verify_proof_of_possession(&ca.ca_id, timestamp + 1)
        .is_err());

    // Tampered payload / signature
    let mut corrupted = rot.clone();
    corrupted.proof_of_possession[0] ^= 0xFF;
    assert!(corrupted
        .verify_proof_of_possession(&ca.ca_id, timestamp)
        .is_err());
}

#[test]
fn test_key_rotation_proof_chain_and_validation() {
    let (ca, node_key) = sample_ca();
    let node_pubkey = node_key.verifying_key().to_bytes();

    let kp0 = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
    let t1 = 1700001000;
    let pop0 = kp0
        .sign(&OfferKeyRotation::compute_pop_payload(
            &ca.ca_id,
            0,
            &kp0.public_key_bytes,
            t1,
        ))
        .unwrap();

    let rot0 = OfferKeyRotation {
        offer_id: 0,
        old_public_key: vec![0; 32],
        new_public_key: kp0.public_key_bytes.clone(),
        key_algorithm: KeyAlgorithm::Ed25519,
        proof_of_possession: pop0,
        old_key_revocation_signature: None,
    };

    // 1. Genesis Proof (seq 1)
    let proof1 = KeyRotationProof::new(
        ca.ca_id,
        1,
        [0u8; 32],
        t1,
        RotationReason::RoutineOperational,
        vec![rot0],
        &node_key,
    )
    .unwrap();

    assert!(proof1.validate(&ca, &node_pubkey, None).is_ok());

    // 2. Chained Proof (seq 2)
    let kp1 = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
    let t2 = 1700002000;
    let pop1 = kp1
        .sign(&OfferKeyRotation::compute_pop_payload(
            &ca.ca_id,
            0,
            &kp1.public_key_bytes,
            t2,
        ))
        .unwrap();

    let rot1 = OfferKeyRotation {
        offer_id: 0,
        old_public_key: kp0.public_key_bytes.clone(),
        new_public_key: kp1.public_key_bytes.clone(),
        key_algorithm: KeyAlgorithm::Ed25519,
        proof_of_possession: pop1,
        old_key_revocation_signature: None,
    };

    let proof2 = KeyRotationProof::new(
        ca.ca_id,
        2,
        proof1.proof_id,
        t2,
        RotationReason::SuspectedLeakage,
        vec![rot1],
        &node_key,
    )
    .unwrap();

    assert!(proof2.validate(&ca, &node_pubkey, Some(&proof1)).is_ok());

    // Broken chain rejection (mismatched prev_rotation_hash)
    let bad_chained_proof = KeyRotationProof::new(
        ca.ca_id,
        2,
        [99u8; 32],
        t2,
        RotationReason::SuspectedLeakage,
        proof2.rotations.clone(),
        &node_key,
    )
    .unwrap();
    assert!(bad_chained_proof
        .validate(&ca, &node_pubkey, Some(&proof1))
        .is_err());
}

#[test]
fn test_distrust_reset_offer_coverage_rules() {
    let (ca, node_key) = sample_ca();
    let active_offer_ids = vec![0, 1, 2];

    let kp0 = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
    let t = 1700001000;
    let pop0 = kp0
        .sign(&OfferKeyRotation::compute_pop_payload(
            &ca.ca_id,
            0,
            &kp0.public_key_bytes,
            t,
        ))
        .unwrap();
    let rot0 = OfferKeyRotation {
        offer_id: 0,
        old_public_key: vec![0; 32],
        new_public_key: kp0.public_key_bytes.clone(),
        key_algorithm: KeyAlgorithm::Ed25519,
        proof_of_possession: pop0,
        old_key_revocation_signature: None,
    };

    // Partial rotation: rotates only offer 0
    let partial_proof = KeyRotationProof::new(
        ca.ca_id,
        1,
        [0u8; 32],
        t,
        RotationReason::SuspectedLeakage,
        vec![rot0.clone()],
        &node_key,
    )
    .unwrap();

    // Partial rotation is valid for routine / leakage, but cannot reset distrust!
    assert!(!partial_proof.covers_all_offers(&active_offer_ids));
    assert!(!partial_proof.can_reset_distrust(&active_offer_ids));

    // Full rotation: rotates offers 0, 1, and 2
    let kp1 = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
    let pop1 = kp1
        .sign(&OfferKeyRotation::compute_pop_payload(
            &ca.ca_id,
            1,
            &kp1.public_key_bytes,
            t,
        ))
        .unwrap();
    let rot1 = OfferKeyRotation {
        offer_id: 1,
        old_public_key: vec![0; 32],
        new_public_key: kp1.public_key_bytes.clone(),
        key_algorithm: KeyAlgorithm::Ed25519,
        proof_of_possession: pop1,
        old_key_revocation_signature: None,
    };

    let kp2 = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
    let pop2 = kp2
        .sign(&OfferKeyRotation::compute_pop_payload(
            &ca.ca_id,
            2,
            &kp2.public_key_bytes,
            t,
        ))
        .unwrap();
    let rot2 = OfferKeyRotation {
        offer_id: 2,
        old_public_key: vec![0; 32],
        new_public_key: kp2.public_key_bytes.clone(),
        key_algorithm: KeyAlgorithm::Ed25519,
        proof_of_possession: pop2,
        old_key_revocation_signature: None,
    };

    let full_proof = KeyRotationProof::new(
        ca.ca_id,
        1,
        [0u8; 32],
        t,
        RotationReason::DistrustRemediation,
        vec![rot0, rot1, rot2],
        &node_key,
    )
    .unwrap();

    // Full rotation covers all offers and can reset distrust!
    assert!(full_proof.covers_all_offers(&active_offer_ids));
    assert!(full_proof.can_reset_distrust(&active_offer_ids));
}
