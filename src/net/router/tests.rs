use crate::crypto::identity::NodeIdentity;
use crate::net::gossip::{
    GossipMessage, RangeSyncRequest, DEFAULT_GOSSIP_TTL, PAYLOAD_TYPE_RANGE_SYNC_REQ,
    PAYLOAD_TYPE_VOTE,
};
use crate::net::phonebook::Phonebook;
use crate::net::router::GossipRouter;
use crate::storage::db::Database;
use ed25519_dalek::SigningKey;
use std::sync::{Arc, RwLock};

#[test]
fn test_router_seen_cache_deduplication() {
    let phonebook = Arc::new(RwLock::new(Phonebook::new()));
    let router = GossipRouter::new(phonebook);

    let identity =
        NodeIdentity::from_seed_and_role(&[0x44u8; 32], crate::crypto::identity::NodeRole::Voter);
    let msg = GossipMessage::new(
        identity.signing_key(),
        1,
        DEFAULT_GOSSIP_TTL,
        PAYLOAD_TYPE_VOTE,
        b"test_payload".to_vec(),
    );

    assert!(!router.is_seen(&msg.msg_id));
    router.mark_seen(msg.msg_id);
    assert!(router.is_seen(&msg.msg_id));
}

#[tokio::test]
async fn test_anti_entropy_range_sync_exchange() {
    use ed25519_dalek::Signer;

    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_sync_test_{}", rand::random::<u64>()));
    let db = Arc::new(Database::open(&temp_dir).expect("Failed to open DB"));

    let secret = [0x05u8; 32];
    let signing_key = SigningKey::from_bytes(&secret);
    let originator = signing_key.verifying_key().to_bytes();
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&1u64.to_be_bytes());
    signed_data.extend_from_slice(&[0u8; 32]);
    signed_data.push(0x02);
    signed_data.extend_from_slice(b"vote_sync_payload");
    let sig = signing_key.sign(&signed_data).to_bytes().to_vec();
    let entry = crate::net::history::EventLogEntry::new(
        1,
        [0u8; 32],
        originator,
        0x02,
        b"vote_sync_payload".to_vec(),
        sig,
    )
    .unwrap();
    db.append_event(entry).unwrap();

    let phonebook = Arc::new(RwLock::new(Phonebook::new()));
    let router = GossipRouter::with_database(phonebook, db);
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let node_id =
        NodeIdentity::from_seed_and_role(&secret, crate::crypto::identity::NodeRole::Voter);
    let sync_req = RangeSyncRequest { vector: Vec::new() };
    let req_bytes = serde_json::to_vec(&sync_req).unwrap();
    let msg = GossipMessage::new(
        node_id.signing_key(),
        1,
        1,
        PAYLOAD_TYPE_RANGE_SYNC_REQ,
        req_bytes,
    );
    let dummy_src = "127.0.0.1:43210".parse().unwrap();
    let result = router
        .process_incoming_packet(
            &msg.to_bytes(),
            dummy_src,
            &socket,
            Some(&node_id),
            false,
            false,
        )
        .await;
    assert!(result.is_ok());
    let _ = std::fs::remove_dir_all(temp_dir);
}

#[tokio::test]
async fn test_anti_entropy_merkle_drill_exchange() {
    use crate::net::gossip::PAYLOAD_TYPE_MERKLE_DRILL_REQ;
    use crate::net::history::{MerkleDrillRequest, SequenceRange};

    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_merkle_test_{}", rand::random::<u64>()));
    let db = Arc::new(Database::open(&temp_dir).expect("Failed to open DB"));
    let secret = [0x06u8; 32];
    let signing_key = SigningKey::from_bytes(&secret);
    let originator = signing_key.verifying_key().to_bytes();

    let phonebook = Arc::new(RwLock::new(Phonebook::new()));
    let router = GossipRouter::with_database(phonebook, db);
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let node_id =
        NodeIdentity::from_seed_and_role(&secret, crate::crypto::identity::NodeRole::Voter);

    let drill_req = MerkleDrillRequest {
        nonce: 100,
        originator,
        target_range: SequenceRange { start: 1, end: 10 },
    };
    let req_bytes = serde_json::to_vec(&drill_req).unwrap();
    let msg = GossipMessage::new(
        node_id.signing_key(),
        1,
        1,
        PAYLOAD_TYPE_MERKLE_DRILL_REQ,
        req_bytes,
    );

    let dummy_src = "127.0.0.1:43210".parse().unwrap();
    let result = router
        .process_incoming_packet(
            &msg.to_bytes(),
            dummy_src,
            &socket,
            Some(&node_id),
            false,
            false,
        )
        .await;
    assert!(result.is_ok());
    let _ = std::fs::remove_dir_all(temp_dir);
}
