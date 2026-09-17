use super::*;
use crate::crypto::agility::{CaKeyPair, KeyAlgorithm};
use crate::crypto::identity::{NodeIdentity, NodeRole};
use crate::net::gossip::{
    DEFAULT_GOSSIP_TTL, PAYLOAD_TYPE_CA_DECLARATION, PAYLOAD_TYPE_CRL_BROADCAST,
};
use crate::pki::ca::{compute_ca_id, CaSubjectMetadata};
use crate::pki::cert::serial::CertificateSerialNumber;
use crate::pki::crl::{CRLReason, RevokedCertificateEntry, X509CrlBuilder};

#[test]
fn test_broadcast_ca_declaration_non_draft_accepted_and_draft_rejected() {
    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_broadcast_test_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let db = Arc::new(Database::open(&temp_dir).unwrap());

    let identity = NodeIdentity::from_seed_and_role(&[0x42u8; 32], NodeRole::Voter);
    let node_pubkey = identity.verifying_key().to_bytes();

    let subject = CaSubjectMetadata {
        common_name: "Swarm Broadcast CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: None,
        locality: Some("Valencia".to_string()),
        state_or_province: Some("Valencia".to_string()),
        country: Some("ES".to_string()),
        email: None,
    };
    let ca_id = compute_ca_id(&subject.common_name, &node_pubkey);

    // 1. Non-draft CA declaration packet
    let non_draft_decl = CaDeclaration::new(
        ca_id,
        subject.clone(),
        subject.clone(),
        false,
        None,
        Vec::new(),
        1700000000,
        false, // is_draft = false
        vec![crate::proof::DomainNetworkType::Clearnet],
    )
    .unwrap();

    let non_draft_bytes = serde_json::to_vec(&non_draft_decl).unwrap();
    let msg = GossipMessage::new(
        identity.signing_key(),
        1,
        DEFAULT_GOSSIP_TTL,
        PAYLOAD_TYPE_CA_DECLARATION,
        non_draft_bytes,
    );

    handle_ca_declaration_packet(&msg, &db);
    assert!(db.get_ca(&ca_id).is_some());

    // 2. Draft CA declaration packet
    let draft_subject = CaSubjectMetadata {
        common_name: "Draft Broadcast CA".to_string(),
        organization: None,
        organizational_unit: None,
        locality: None,
        state_or_province: None,
        country: None,
        email: None,
    };
    let draft_ca_id = compute_ca_id(&draft_subject.common_name, &node_pubkey);
    let draft_decl = CaDeclaration::new(
        draft_ca_id,
        draft_subject.clone(),
        draft_subject,
        false,
        None,
        Vec::new(),
        1700000000,
        true, // is_draft = true
        vec![crate::proof::DomainNetworkType::Clearnet],
    )
    .unwrap();

    let draft_bytes = serde_json::to_vec(&draft_decl).unwrap();
    let draft_msg = GossipMessage::new(
        identity.signing_key(),
        2,
        DEFAULT_GOSSIP_TTL,
        PAYLOAD_TYPE_CA_DECLARATION,
        draft_bytes,
    );

    handle_ca_declaration_packet(&draft_msg, &db);
    assert!(db.get_ca(&draft_ca_id).is_none());

    let (valid, bullshit) = db.get_originator_reputation(&node_pubkey);
    assert_eq!(valid, 1);
    assert_eq!(bullshit, 1);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_broadcast_crl_packet_ingestion() {
    let temp_dir = std::env::temp_dir().join(format!(
        "randbotd_broadcast_crl_test_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let db = Arc::new(Database::open(&temp_dir).unwrap());

    let identity = NodeIdentity::from_seed_and_role(&[0x55u8; 32], NodeRole::Voter);
    let node_pubkey = identity.verifying_key().to_bytes();

    let subject = CaSubjectMetadata {
        common_name: "Swarm CRL CA".to_string(),
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
        vec![crate::proof::DomainNetworkType::Clearnet],
    )
    .unwrap();
    db.insert_ca(decl.clone()).unwrap();

    let keypair = CaKeyPair {
        algorithm: KeyAlgorithm::Ed25519,
        public_key_bytes: node_pubkey.to_vec(),
        private_key_bytes: identity.signing_key().to_bytes().to_vec(),
    };
    let revoked_serial = CertificateSerialNumber::generate();
    let crl = X509CrlBuilder::build_crl(
        &decl,
        &keypair,
        vec![RevokedCertificateEntry {
            serial_number: revoked_serial.clone(),
            revocation_date: 1700000050,
            reason: Some(CRLReason::KeyCompromise),
        }],
        1700000000,
        1700086400,
        1,
    )
    .unwrap();

    let crl_bytes = serde_json::to_vec(&crl).unwrap();
    let crl_msg = GossipMessage::new(
        identity.signing_key(),
        1,
        DEFAULT_GOSSIP_TTL,
        PAYLOAD_TYPE_CRL_BROADCAST,
        crl_bytes,
    );

    handle_crl_broadcast_packet(&crl_msg, &db);

    assert!(db.get_crl(&ca_id).is_some());
    assert!(db.is_cert_revoked_any(&revoked_serial));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_broadcast_domain_purge_packet_ingestion() {
    use crate::net::gossip::PAYLOAD_TYPE_DOMAIN_PURGE;
    use crate::pki::purge::{
        calculate_required_difficulty, compute_purge_challenge, solve_purge_pow, DomainPurgeRecord,
        PurgeReason,
    };

    let temp_dir = std::env::temp_dir().join(format!(
        "randbotd_broadcast_purge_test_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let db = Arc::new(Database::open(&temp_dir).unwrap());

    let owner_identity = NodeIdentity::from_seed_and_role(&[0x77u8; 32], NodeRole::Voter);
    let owner_pubkey = owner_identity.verifying_key().to_bytes();

    let attacker_identity = NodeIdentity::from_seed_and_role(&[0x88u8; 32], NodeRole::Voter);

    let subject = CaSubjectMetadata {
        common_name: "Swarm Purge Target CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: None,
        locality: Some("Valencia".to_string()),
        state_or_province: Some("Valencia".to_string()),
        country: Some("ES".to_string()),
        email: None,
    };
    let ca_id = compute_ca_id(&subject.common_name, &owner_pubkey);

    let decl = crate::pki::ca::CaDeclaration::new(
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
    db.insert_ca(decl).unwrap();

    let t1 = 1700000100;
    let exp1 = t1 + 86400 * 7;
    let challenge = compute_purge_challenge(&ca_id, "malicious.com", t1, &[0u8; 32], 1);
    let diff = calculate_required_difficulty(0, true);
    let nonce = solve_purge_pow(&challenge, diff);

    let valid_purge = DomainPurgeRecord::new(
        ca_id,
        "malicious.com".to_string(),
        None,
        1,
        [0u8; 32],
        t1,
        exp1,
        PurgeReason::MalwarePhishing,
        "Confirmed malware host".to_string(),
        Some("P2P UTW strike #99".to_string()),
        nonce,
        owner_identity.signing_key(),
    )
    .unwrap();

    // 1. Ingest valid purge packet from owner
    let purge_bytes = serde_json::to_vec(&valid_purge).unwrap();
    let purge_msg = GossipMessage::new(
        owner_identity.signing_key(),
        1,
        DEFAULT_GOSSIP_TTL,
        PAYLOAD_TYPE_DOMAIN_PURGE,
        purge_bytes,
    );

    handle_domain_purge_packet(&purge_msg, &db);

    assert!(db.is_domain_purged("malicious.com", t1));
    assert_eq!(db.count_active_unexpired_purges_for_ca(&ca_id, t1), 1);

    // 2. Attacker attempts to forge purge with attacker key
    let attack_challenge =
        compute_purge_challenge(&ca_id, "safe-site.com", t1 + 10, &valid_purge.purge_id, 2);
    let attack_nonce = solve_purge_pow(&attack_challenge, calculate_required_difficulty(1, true));
    let forged_purge = DomainPurgeRecord::new(
        ca_id,
        "safe-site.com".to_string(),
        None,
        2,
        valid_purge.purge_id,
        t1 + 10,
        exp1,
        PurgeReason::Other("Smear campaign".to_string()),
        "False strike".to_string(),
        Some("Fake".to_string()),
        attack_nonce,
        attacker_identity.signing_key(),
    )
    .unwrap();

    let forged_bytes = serde_json::to_vec(&forged_purge).unwrap();
    let forged_msg = GossipMessage::new(
        attacker_identity.signing_key(),
        2,
        DEFAULT_GOSSIP_TTL,
        PAYLOAD_TYPE_DOMAIN_PURGE,
        forged_bytes,
    );

    handle_domain_purge_packet(&forged_msg, &db);

    // Forged purge must NOT be ingested into database
    assert!(!db.is_domain_purged("safe-site.com", t1 + 10));
    assert_eq!(db.count_active_unexpired_purges_for_ca(&ca_id, t1 + 10), 1);

    let _ = std::fs::remove_dir_all(&temp_dir);
}
