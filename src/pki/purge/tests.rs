use super::*;
use crate::pki::ca::{CaDeclaration, CaSubjectMetadata};

#[test]
fn test_domain_purge_pow_solve_and_verify() {
    let ca_id = [0x42u8; 32];
    let domain = "phishing-site.hns";
    let timestamp = 1700000000;
    let prev_hash = [0u8; 32];
    let seq = 1;

    let challenge = compute_purge_challenge(&ca_id, domain, timestamp, &prev_hash, seq);

    // Test with base difficulty (12 bits)
    let nonce = solve_purge_pow(&challenge, 12);
    assert!(verify_purge_pow(&challenge, nonce, 12));

    // Invalid nonce should fail
    assert!(!verify_purge_pow(&challenge, nonce.wrapping_add(1), 32));
}

#[test]
fn test_pow_logarithmic_difficulty_scaling() {
    // 0 active purges + strike evidence -> BASE (12)
    assert_eq!(calculate_required_difficulty(0, true), 12);

    // 0 active purges + NO strike evidence -> BASE (12) + 4 = 16
    assert_eq!(calculate_required_difficulty(0, false), 16);

    // 1 active purge (log2(2) = 1) -> 12 + 2*1 = 14 with strike evidence
    assert_eq!(calculate_required_difficulty(1, true), 14);
    assert_eq!(calculate_required_difficulty(1, false), 18);

    // 3 active purges (log2(4) = 2) -> 12 + 2*2 = 16 with strike evidence
    assert_eq!(calculate_required_difficulty(3, true), 16);
    assert_eq!(calculate_required_difficulty(3, false), 20);

    // 7 active purges (log2(8) = 3) -> 12 + 2*3 = 18 with strike evidence
    assert_eq!(calculate_required_difficulty(7, true), 18);
}

fn generate_test_ed25519_key() -> SigningKey {
    let mut rng = rand::rngs::OsRng;
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut secret);
    SigningKey::from_bytes(&secret)
}

#[test]
fn test_domain_purge_record_chain_build_and_validate() {
    let ca_key = generate_test_ed25519_key();
    let ca_pubkey = ca_key.verifying_key().to_bytes();

    let subject = CaSubjectMetadata {
        common_name: "Purge Test Root CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: None,
        locality: None,
        state_or_province: None,
        country: Some("ES".to_string()),
        email: None,
    };

    let ca_id = compute_ca_id(&subject.common_name, &ca_pubkey);
    let ca = CaDeclaration::new(
        ca_id,
        subject.clone(),
        subject,
        false,
        None,
        Vec::new(),
        1700000000,
        false,
        vec![crate::proof::DomainNetworkType::Clearnet],
    )
    .unwrap();

    // 1. Genesis purge (seq = 1, prev_hash = [0; 32])
    let t1 = 1700000100;
    let exp1 = t1 + 86400 * 30;
    let challenge1 = compute_purge_challenge(&ca_id, "malware1.com", t1, &[0u8; 32], 1);
    let diff1 = calculate_required_difficulty(0, true);
    let nonce1 = solve_purge_pow(&challenge1, diff1);

    let purge1 = DomainPurgeRecord::new(
        ca_id,
        "malware1.com".to_string(),
        None,
        1,
        [0u8; 32],
        t1,
        exp1,
        PurgeReason::MalwarePhishing,
        "Detected distributed malware payload".to_string(),
        Some("UTW strike report #124".to_string()),
        nonce1,
        &ca_key,
    )
    .unwrap();

    assert!(purge1
        .validate_against_ca_and_chain(&ca, &ca_pubkey, None, 0)
        .is_ok());

    // 2. Second chained purge (seq = 2, prev_hash = purge1.purge_id)
    let t2 = t1 + 3600;
    let exp2 = t2 + 86400 * 30;
    let challenge2 = compute_purge_challenge(&ca_id, "scam2.com", t2, &purge1.purge_id, 2);
    let diff2 = calculate_required_difficulty(1, true);
    let nonce2 = solve_purge_pow(&challenge2, diff2);

    let purge2 = DomainPurgeRecord::new(
        ca_id,
        "scam2.com".to_string(),
        None,
        2,
        purge1.purge_id,
        t2,
        exp2,
        PurgeReason::UntrustworthyBehavior,
        "Exit-scam fraud confirmed".to_string(),
        Some("UTW vote delta breach".to_string()),
        nonce2,
        &ca_key,
    )
    .unwrap();

    assert!(purge2
        .validate_against_ca_and_chain(&ca, &ca_pubkey, Some(&purge1), 1)
        .is_ok());

    // 3. Test Discontinuity Rejections
    // Bad sequence
    let mut bad_seq = purge2.clone();
    bad_seq.purge_seq = 99;
    assert!(bad_seq
        .validate_against_ca_and_chain(&ca, &ca_pubkey, Some(&purge1), 1)
        .is_err());

    // Broken hash link
    let mut bad_hash = purge2.clone();
    bad_hash.prev_purge_hash = [0xffu8; 32];
    assert!(bad_hash
        .validate_against_ca_and_chain(&ca, &ca_pubkey, Some(&purge1), 1)
        .is_err());

    // Non-monotonic timestamp (timestamp earlier than prev)
    let challenge_bad_time =
        compute_purge_challenge(&ca_id, "badtime.com", t1 - 10, &purge1.purge_id, 2);
    let nonce_bt = solve_purge_pow(&challenge_bad_time, diff2);
    let bad_time = DomainPurgeRecord::new(
        ca_id,
        "badtime.com".to_string(),
        None,
        2,
        purge1.purge_id,
        t1 - 10,
        exp2,
        PurgeReason::TermsViolation,
        "Policy violation".to_string(),
        Some("strike".to_string()),
        nonce_bt,
        &ca_key,
    )
    .unwrap();

    assert!(bad_time
        .validate_against_ca_and_chain(&ca, &ca_pubkey, Some(&purge1), 1)
        .is_err());
}

#[test]
fn test_non_owner_and_subtree_constraint_rejections() {
    let owner_key = generate_test_ed25519_key();
    let owner_pubkey = owner_key.verifying_key().to_bytes();

    let attacker_key = generate_test_ed25519_key();
    let attacker_pubkey = attacker_key.verifying_key().to_bytes();

    let subject = CaSubjectMetadata {
        common_name: "Scoped Intermediate CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: None,
        locality: None,
        state_or_province: None,
        country: Some("ES".to_string()),
        email: None,
    };

    let ca_id = compute_ca_id(&subject.common_name, &owner_pubkey);
    let intermediate_ca = CaDeclaration::new(
        ca_id,
        subject.clone(),
        subject,
        true,
        Some(0),
        vec!["safe.hns".to_string()], // only safe.hns subtree permitted
        1700000000,
        false,
        vec![crate::proof::DomainNetworkType::Clearnet],
    )
    .unwrap();

    let t = 1700000500;
    let exp = t + 86400;

    // Attacker attempts to sign a purge for owner's CA
    let challenge = compute_purge_challenge(&ca_id, "safe.hns", t, &[0u8; 32], 1);
    let nonce = solve_purge_pow(&challenge, 12);

    let attack_purge = DomainPurgeRecord::new(
        ca_id,
        "safe.hns".to_string(),
        None,
        1,
        [0u8; 32],
        t,
        exp,
        PurgeReason::Other("Rogue purge".to_string()),
        "Malicious purge".to_string(),
        Some("strike".to_string()),
        nonce,
        &attacker_key,
    )
    .unwrap();

    // Must fail because attacker is not owner
    let res =
        attack_purge.validate_against_ca_and_chain(&intermediate_ca, &attacker_pubkey, None, 0);
    assert!(res.is_err());
    assert!(res
        .unwrap_err()
        .contains("Emitting node public key does not match CA owner"));

    // Owner attempts to purge a domain outside permitted subtree (`evil.onion`)
    let challenge_out = compute_purge_challenge(&ca_id, "evil.onion", t, &[0u8; 32], 1);
    let nonce_out = solve_purge_pow(&challenge_out, 12);
    let out_of_scope = DomainPurgeRecord::new(
        ca_id,
        "evil.onion".to_string(),
        None,
        1,
        [0u8; 32],
        t,
        exp,
        PurgeReason::MalwarePhishing,
        "Malware".to_string(),
        Some("strike".to_string()),
        nonce_out,
        &owner_key,
    )
    .unwrap();

    let res_scope =
        out_of_scope.validate_against_ca_and_chain(&intermediate_ca, &owner_pubkey, None, 0);
    assert!(res_scope.is_err());
    assert!(res_scope
        .unwrap_err()
        .contains("violates CA subtree name constraints"));
}
