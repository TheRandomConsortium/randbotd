use std::sync::{Arc, RwLock};

use super::*;
use crate::crypto::identity::{NodeIdentity, NodeRole};
use crate::crypto::vote::{VoteAction, VoteRecord};
use crate::net::gossip::{GossipMessage, DEFAULT_GOSSIP_TTL, PAYLOAD_TYPE_VOTE};
use crate::net::phonebook::Phonebook;
use crate::storage::db::Database;

#[test]
fn test_broadcast_vote_packet_ingested_successfully() {
    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_bcast_vote_{}", rand::random::<u64>()));
    let db = Arc::new(Database::open(&temp_dir).unwrap());
    let phonebook = Arc::new(RwLock::new(Phonebook::new()));

    let voter_identity = NodeIdentity::from_seed_and_role(&[0x22u8; 32], NodeRole::Voter);
    let voter_pubkey = voter_identity.verifying_key().to_bytes();

    let vote = VoteRecord::new_signed(
        voter_identity.signing_key(),
        "awesome-service.rand",
        VoteAction::Tw,
        1,
        [0u8; 32],
        1000,
        0,
        0,
    )
    .unwrap();

    let payload = serde_json::to_vec(&vote).unwrap();
    let msg = GossipMessage::new(
        voter_identity.signing_key(),
        1,
        DEFAULT_GOSSIP_TTL,
        PAYLOAD_TYPE_VOTE,
        payload,
    );

    handle_vote_packet(&msg, &db, &phonebook);

    let status = db.get_domain_vote_status(Some(&voter_pubkey), "awesome-service.rand");
    assert!(status.has_voted);
    assert_eq!(status.total_active_votes, 1);
    assert_eq!(status.tw_count, 1);
    assert_eq!(status.utw_count, 0);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_broadcast_vote_packet_rejected_for_headless_peer() {
    let temp_dir = std::env::temp_dir().join(format!(
        "randbotd_bcast_vote_headless_{}",
        rand::random::<u64>()
    ));
    let db = Arc::new(Database::open(&temp_dir).unwrap());
    let phonebook = Arc::new(RwLock::new(Phonebook::new()));

    let headless_identity = NodeIdentity::from_seed_and_role(&[0x33u8; 32], NodeRole::Headless);
    let headless_pubkey = headless_identity.verifying_key().to_bytes();

    // Register peer in phonebook as headless
    phonebook.write().unwrap().upsert_peer_with_role(
        &headless_pubkey,
        "192.168.1.100:43210",
        false,
        true, // is_headless = true
    );

    let vote = VoteRecord::new_signed(
        headless_identity.signing_key(),
        "forbidden.rand",
        VoteAction::Tw,
        1,
        [0u8; 32],
        1000,
        0,
        0,
    )
    .unwrap();

    let payload = serde_json::to_vec(&vote).unwrap();
    let msg = GossipMessage::new(
        headless_identity.signing_key(),
        1,
        DEFAULT_GOSSIP_TTL,
        PAYLOAD_TYPE_VOTE,
        payload,
    );

    handle_vote_packet(&msg, &db, &phonebook);

    let status = db.get_domain_vote_status(Some(&headless_pubkey), "forbidden.rand");
    assert!(!status.has_voted);
    assert_eq!(status.total_active_votes, 0);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_broadcast_vote_packet_rejected_if_previous_monotonic_not_received_yet() {
    let temp_dir = std::env::temp_dir().join(format!(
        "randbotd_bcast_vote_disc_{}",
        rand::random::<u64>()
    ));
    let db = Arc::new(Database::open(&temp_dir).unwrap());
    let phonebook = Arc::new(RwLock::new(Phonebook::new()));

    let voter_identity = NodeIdentity::from_seed_and_role(&[0x44u8; 32], NodeRole::Voter);
    let voter_pubkey = voter_identity.verifying_key().to_bytes();

    // Attempt to broadcast seq = 2 directly without seq = 1 being in DB
    let vote_seq_2 = VoteRecord::new_signed(
        voter_identity.signing_key(),
        "skip-seq.rand",
        VoteAction::Tw,
        2,
        [0xaa; 32],
        1000,
        0,
        0,
    )
    .unwrap();

    let payload = serde_json::to_vec(&vote_seq_2).unwrap();
    let msg = GossipMessage::new(
        voter_identity.signing_key(),
        2,
        DEFAULT_GOSSIP_TTL,
        PAYLOAD_TYPE_VOTE,
        payload,
    );

    // If previous monotonic is not here yet, we don't listen to the new one!
    handle_vote_packet(&msg, &db, &phonebook);

    let status = db.get_domain_vote_status(Some(&voter_pubkey), "skip-seq.rand");
    assert!(!status.has_voted);
    assert_eq!(status.total_active_votes, 0);

    let _ = std::fs::remove_dir_all(&temp_dir);
}
