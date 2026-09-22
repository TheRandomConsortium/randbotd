use super::*;
use crate::crypto::identity::{NodeIdentity, NodeRole};
use crate::net::gossip::{
    GossipMessage, DEFAULT_GOSSIP_TTL, PAYLOAD_TYPE_CUSTODIAN_CONTRACT,
    PAYLOAD_TYPE_SWARM_ACTIVATION,
};
use crate::net::router::GossipRouter;
use crate::pki::ca::{compute_ca_id, CaDeclaration, CaSubjectMetadata};
use crate::pki::swarm::{CaCustodianPolicy, CustodianContract, SwarmActivationConfirmation};
use crate::storage::db::Database;
use std::sync::Arc;
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_broadcast_custodian_contract_silent_drop_when_not_seeking() {
    let temp_dir = std::env::temp_dir().join(format!(
        "randbotd_custodian_bcast_test_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let db = Arc::new(Database::open(&temp_dir).unwrap());

    let ca_identity = NodeIdentity::from_seed_and_role(&[0x11u8; 32], NodeRole::Voter);
    let ca_pubkey = ca_identity.verifying_key().to_bytes();

    let subject = CaSubjectMetadata {
        common_name: "Custodian Test CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: None,
        locality: Some("Reykjavik".to_string()),
        state_or_province: None,
        country: Some("IS".to_string()),
        email: None,
    };
    let ca_id = compute_ca_id(&subject.common_name, &ca_pubkey);

    // CA with seeking_custodians = false (default)
    let ca_decl = CaDeclaration::new(
        ca_id,
        subject.clone(),
        subject,
        false,
        None,
        Vec::new(),
        1000,
        false,
        vec![crate::proof::DomainNetworkType::Clearnet],
    )
    .unwrap();
    db.insert_ca(ca_decl).unwrap();

    let worker_identity = NodeIdentity::from_seed_and_role(&[0x22u8; 32], NodeRole::Voter);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let contract = CustodianContract::new(
        ca_id,
        worker_identity.signing_key(),
        20,
        now,
        now + 3600,
        "127.0.0.1:43210".to_string(),
    )
    .unwrap();

    let msg = GossipMessage::new(
        worker_identity.signing_key(),
        1,
        DEFAULT_GOSSIP_TTL,
        PAYLOAD_TYPE_CUSTODIAN_CONTRACT,
        serde_json::to_vec(&contract).unwrap(),
    );

    let phonebook = Arc::new(std::sync::RwLock::new(
        crate::net::phonebook::Phonebook::new(),
    ));
    let router = GossipRouter::with_database(phonebook, db.clone());
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Must be silently dropped (no pending contract registered)
    handle_custodian_contract_packet(&msg, &db, Some(&ca_identity), &socket, &router).await;
    assert!(router.pending_contracts.read().unwrap().is_empty());
}

#[tokio::test]
async fn test_broadcast_custodian_contract_silent_drop_when_workshare_exceeds_policy() {
    let temp_dir = std::env::temp_dir().join(format!(
        "randbotd_custodian_policy_test_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let db = Arc::new(Database::open(&temp_dir).unwrap());

    let ca_identity = NodeIdentity::from_seed_and_role(&[0x33u8; 32], NodeRole::Voter);
    let ca_pubkey = ca_identity.verifying_key().to_bytes();

    let subject = CaSubjectMetadata {
        common_name: "Policy Test CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: None,
        locality: Some("Reykjavik".to_string()),
        state_or_province: None,
        country: Some("IS".to_string()),
        email: None,
    };
    let ca_id = compute_ca_id(&subject.common_name, &ca_pubkey);

    let mut ca_decl = CaDeclaration::new(
        ca_id,
        subject.clone(),
        subject,
        false,
        None,
        Vec::new(),
        1000,
        false,
        vec![crate::proof::DomainNetworkType::Clearnet],
    )
    .unwrap();
    ca_decl.seeking_custodians = true;
    db.insert_ca(ca_decl).unwrap();

    // Set blind policy: max 25%
    let policy = CaCustodianPolicy {
        max_work_share_pct: 25,
        min_ttl_seconds: 100,
        target_swarm_size: 5,
        auto_accept: true,
    };
    db.set_ca_custodian_policy(ca_id, policy).unwrap();

    let worker_identity = NodeIdentity::from_seed_and_role(&[0x44u8; 32], NodeRole::Voter);
    let worker_pubkey = worker_identity.verifying_key().to_bytes();
    let worker_subject = CaSubjectMetadata {
        common_name: "Worker CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: None,
        locality: None,
        state_or_province: None,
        country: Some("IS".to_string()),
        email: None,
    };
    let worker_ca_id = compute_ca_id(&worker_subject.common_name, &worker_pubkey);
    let worker_ca_decl = CaDeclaration::new(
        worker_ca_id,
        worker_subject.clone(),
        worker_subject,
        false,
        None,
        Vec::new(),
        1000,
        false,
        vec![crate::proof::DomainNetworkType::Clearnet],
    )
    .unwrap();
    db.insert_ca(worker_ca_decl).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Worker asks for 30% (greedy, exceeds 25% policy ceiling)
    let contract = CustodianContract::new(
        ca_id,
        worker_identity.signing_key(),
        30,
        now,
        now + 3600,
        "127.0.0.1:43210".to_string(),
    )
    .unwrap();

    let msg = GossipMessage::new(
        worker_identity.signing_key(),
        1,
        DEFAULT_GOSSIP_TTL,
        PAYLOAD_TYPE_CUSTODIAN_CONTRACT,
        serde_json::to_vec(&contract).unwrap(),
    );

    let phonebook = Arc::new(std::sync::RwLock::new(
        crate::net::phonebook::Phonebook::new(),
    ));
    let router = GossipRouter::with_database(phonebook, db.clone());
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Must be silently dropped
    handle_custodian_contract_packet(&msg, &db, Some(&ca_identity), &socket, &router).await;
    assert!(router.pending_contracts.read().unwrap().is_empty());
}

#[tokio::test]
async fn test_broadcast_custodian_contract_silent_drop_when_worker_lacks_network_support() {
    let temp_dir = std::env::temp_dir().join(format!(
        "randbotd_custodian_net_test_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let db = Arc::new(Database::open(&temp_dir).unwrap());

    let ca_identity = NodeIdentity::from_seed_and_role(&[0x66u8; 32], NodeRole::Voter);
    let ca_pubkey = ca_identity.verifying_key().to_bytes();
    let ca_subject = CaSubjectMetadata {
        common_name: "Multi-Net CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: None,
        locality: None,
        state_or_province: None,
        country: Some("IS".to_string()),
        email: None,
    };
    let ca_id = compute_ca_id(&ca_subject.common_name, &ca_pubkey);

    // Main CA supports both Clearnet and Tor
    let mut ca_decl = CaDeclaration::new(
        ca_id,
        ca_subject.clone(),
        ca_subject,
        false,
        None,
        Vec::new(),
        1000,
        false,
        vec![
            crate::proof::DomainNetworkType::Clearnet,
            crate::proof::DomainNetworkType::Tor,
        ],
    )
    .unwrap();
    ca_decl.seeking_custodians = true;
    db.insert_ca(ca_decl).unwrap();

    let worker_identity = NodeIdentity::from_seed_and_role(&[0x77u8; 32], NodeRole::Voter);
    let worker_pubkey = worker_identity.verifying_key().to_bytes();
    let worker_subject = CaSubjectMetadata {
        common_name: "Clearnet Only Worker CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: None,
        locality: None,
        state_or_province: None,
        country: Some("IS".to_string()),
        email: None,
    };
    let worker_ca_id = compute_ca_id(&worker_subject.common_name, &worker_pubkey);

    // Worker CA only supports Clearnet (missing Tor)
    let worker_ca_decl = CaDeclaration::new(
        worker_ca_id,
        worker_subject.clone(),
        worker_subject,
        false,
        None,
        Vec::new(),
        1000,
        false,
        vec![crate::proof::DomainNetworkType::Clearnet],
    )
    .unwrap();
    db.insert_ca(worker_ca_decl).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let contract = CustodianContract::new(
        ca_id,
        worker_identity.signing_key(),
        20,
        now,
        now + 3600,
        "127.0.0.1:43210".to_string(),
    )
    .unwrap();

    let msg = GossipMessage::new(
        worker_identity.signing_key(),
        1,
        DEFAULT_GOSSIP_TTL,
        PAYLOAD_TYPE_CUSTODIAN_CONTRACT,
        serde_json::to_vec(&contract).unwrap(),
    );

    let phonebook = Arc::new(std::sync::RwLock::new(
        crate::net::phonebook::Phonebook::new(),
    ));
    let router = GossipRouter::with_database(phonebook, db.clone());
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Must be silently dropped because worker lacks Tor support
    handle_custodian_contract_packet(&msg, &db, Some(&ca_identity), &socket, &router).await;
    assert!(router.pending_contracts.read().unwrap().is_empty());
}

#[tokio::test]
async fn test_broadcast_swarm_activation_ingestion() {
    let temp_dir = std::env::temp_dir().join(format!(
        "randbotd_activation_bcast_test_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let db = Arc::new(Database::open(&temp_dir).unwrap());

    let ca_identity = NodeIdentity::from_seed_and_role(&[0x55u8; 32], NodeRole::Voter);
    let ca_pubkey = ca_identity.verifying_key().to_bytes();

    let subject = CaSubjectMetadata {
        common_name: "Activation Test CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: None,
        locality: Some("Reykjavik".to_string()),
        state_or_province: None,
        country: Some("IS".to_string()),
        email: None,
    };
    let ca_id = compute_ca_id(&subject.common_name, &ca_pubkey);

    let ca_decl = CaDeclaration::new(
        ca_id,
        subject.clone(),
        subject,
        false,
        None,
        Vec::new(),
        1000,
        false,
        vec![crate::proof::DomainNetworkType::Clearnet],
    )
    .unwrap();
    db.insert_ca(ca_decl).unwrap();

    let worker_pubkey = [0x77u8; 32];
    let confirmation = SwarmActivationConfirmation::new(
        ca_id,
        worker_pubkey,
        [0x11u8; 32],
        [0x22u8; 32],
        2000,
        ca_identity.signing_key(),
    );

    let msg = GossipMessage::new(
        ca_identity.signing_key(),
        1,
        DEFAULT_GOSSIP_TTL,
        PAYLOAD_TYPE_SWARM_ACTIVATION,
        serde_json::to_vec(&confirmation).unwrap(),
    );

    handle_swarm_activation_packet(&msg, &db);

    let custodians = db.get_custodians_for_ca(&ca_id);
    assert_eq!(custodians.len(), 1);
    assert_eq!(custodians[0].worker_pubkey, worker_pubkey);
}
