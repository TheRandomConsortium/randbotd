use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::net::UdpSocket;

use crate::crypto::identity::NodeIdentity;
use crate::net::gossip::{
    AddressAnnouncementPayload, AddressReflectionResponse, GetPeersResponse, GossipMessage,
    PAYLOAD_TYPE_ADDRESS_ANNOUNCEMENT, PAYLOAD_TYPE_GET_PEERS_REQ, PAYLOAD_TYPE_GET_PEERS_RESP,
    PAYLOAD_TYPE_MERKLE_DRILL_REQ, PAYLOAD_TYPE_MERKLE_DRILL_RESP, PAYLOAD_TYPE_PING,
    PAYLOAD_TYPE_RANGE_SYNC_REQ, PAYLOAD_TYPE_RANGE_SYNC_RESP, PAYLOAD_TYPE_REFLECT_ADDR_REQ,
    PAYLOAD_TYPE_REFLECT_ADDR_RESP,
};
use crate::net::handshake::{HandshakeInit, HandshakeResponse};
use crate::net::phonebook::Phonebook;
use crate::storage::db::Database;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

pub mod sync;
use sync::*;

pub struct GossipRouter {
    seen_cache: Arc<RwLock<HashMap<[u8; 32], u64>>>,
    active_peers: Arc<RwLock<HashMap<SocketAddr, u64>>>,
    phonebook: Arc<RwLock<Phonebook>>,
    database: Option<Arc<Database>>,
}

impl GossipRouter {
    #[allow(dead_code)]
    pub fn new(phonebook: Arc<RwLock<Phonebook>>) -> Self {
        Self {
            seen_cache: Arc::new(RwLock::new(HashMap::new())),
            active_peers: Arc::new(RwLock::new(HashMap::new())),
            phonebook,
            database: None,
        }
    }

    pub fn with_database(phonebook: Arc<RwLock<Phonebook>>, database: Arc<Database>) -> Self {
        Self {
            seen_cache: Arc::new(RwLock::new(HashMap::new())),
            active_peers: Arc::new(RwLock::new(HashMap::new())),
            phonebook,
            database: Some(database),
        }
    }

    pub fn add_peer(&self, addr: SocketAddr) {
        if let Ok(mut peers) = self.active_peers.write() {
            peers.insert(
                addr,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
        }
    }

    pub fn active_peers(&self) -> Vec<SocketAddr> {
        if let Ok(peers) = self.active_peers.read() {
            peers.keys().copied().collect()
        } else {
            Vec::new()
        }
    }

    pub fn prune_inactive_peers(&self, timeout_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Ok(mut peers) = self.active_peers.write() {
            peers.retain(|addr, last_seen| {
                let active = (now - *last_seen) <= timeout_secs;
                if !active {
                    println!(
                        "  💀 [P2P Network] Pruned inactive peer {} (Inactive > {}s)",
                        addr, timeout_secs
                    );
                }
                active
            });
        }
    }

    pub fn prune_seen_cache(&self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Ok(mut cache) = self.seen_cache.write() {
            cache.retain(|_, seen_at| (now - *seen_at) <= max_age_secs);
        }
    }

    pub fn is_seen(&self, msg_id: &[u8; 32]) -> bool {
        if let Ok(cache) = self.seen_cache.read() {
            cache.contains_key(msg_id)
        } else {
            false
        }
    }

    pub fn mark_seen(&self, msg_id: [u8; 32]) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Ok(mut cache) = self.seen_cache.write() {
            cache.insert(msg_id, now);
        }
    }

    pub async fn process_incoming_packet(
        &self,
        buf: &[u8],
        src: SocketAddr,
        socket: &UdpSocket,
        identity: Option<&NodeIdentity>,
        is_seed: bool,
        is_headless: bool,
    ) -> Result<Option<GossipMessage>, &'static str> {
        let my_pubkey = identity.map(|id| id.verifying_key().to_bytes());

        // 1. Check if packet is HandshakeInit
        if let Ok(init) = HandshakeInit::from_bytes(buf) {
            if let Some(my_pk) = my_pubkey {
                if init.sender_pubkey == my_pk {
                    return Ok(None);
                }
            }

            self.add_peer(src);
            println!(
                "  🤝 [P2P Handshake] Received verified HandshakeInit from {} (Key: {:02x?}, Seed: {}, Headless: {}, Voter: {})",
                src, &init.sender_pubkey[..4], init.is_seed(), init.is_headless(), init.is_voter()
            );

            if let Ok(mut pb) = self.phonebook.write() {
                pb.upsert_peer(&init.sender_pubkey, &src.to_string(), init.is_seed());
            }

            if let Some(id) = identity {
                let response_frame = {
                    let rng = rand::rngs::OsRng;
                    let ephemeral_secret = EphemeralSecret::random_from_rng(rng);
                    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
                    HandshakeResponse::new(
                        id.signing_key(),
                        &ephemeral_public,
                        is_seed,
                        is_headless,
                    )
                };
                let _ = socket.send_to(&response_frame.to_bytes(), src).await;
            }

            return Ok(None);
        }

        // 2. Check if packet is HandshakeResponse
        if let Ok(res) = HandshakeResponse::from_bytes(buf) {
            if let Some(my_pk) = my_pubkey {
                if res.sender_pubkey == my_pk {
                    return Ok(None);
                }
            }

            self.add_peer(src);
            println!(
                "  🤝 [P2P Handshake] Received verified HandshakeResponse from {} (Key: {:02x?}, Seed: {}, Headless: {}, Voter: {})",
                src, &res.sender_pubkey[..4], res.is_seed(), res.is_headless(), res.is_voter()
            );

            if let Ok(mut pb) = self.phonebook.write() {
                pb.upsert_peer(&res.sender_pubkey, &src.to_string(), res.is_seed());
            }

            return Ok(None);
        }

        // 3. Process as GossipMessage
        let msg = GossipMessage::from_bytes(buf)?;

        if let Some(my_pk) = my_pubkey {
            if msg.originator_pubkey == my_pk {
                return Ok(None);
            }
        }

        self.add_peer(src);

        if self.is_seen(&msg.msg_id) {
            return Ok(None);
        }

        self.mark_seen(msg.msg_id);

        if msg.payload_type == PAYLOAD_TYPE_PING {
            println!(
                "  🏓 [P2P Keepalive] Received Ping keepalive from {} (Key: {:02x?})",
                src,
                &msg.originator_pubkey[..4]
            );
            return Ok(Some(msg));
        }

        println!(
            "  📩 [P2P Network] Received verified gossip message from {} (Msg ID: {:02x?}, Type: {}, TTL: {})",
            src,
            &msg.msg_id[..4],
            msg.payload_type,
            msg.ttl
        );

        if msg.payload_type == PAYLOAD_TYPE_ADDRESS_ANNOUNCEMENT {
            if let Ok(announcement) = AddressAnnouncementPayload::from_bytes(&msg.payload) {
                if let Ok(mut pb) = self.phonebook.write() {
                    pb.upsert_peer(
                        &msg.originator_pubkey,
                        &announcement.new_address,
                        announcement.is_seed,
                    );
                }
            }
        } else if msg.payload_type == PAYLOAD_TYPE_GET_PEERS_REQ {
            println!("  📖 [P2P Phonebook] Received GetPeersRequest from {}", src);
            let sampled_peers = {
                if let Ok(pb) = self.phonebook.read() {
                    pb.sample_random_peers(8, &src.to_string())
                } else {
                    Vec::new()
                }
            };
            let resp_payload = GetPeersResponse {
                peers: sampled_peers,
            };
            if let Ok(resp_bytes) = serde_json::to_vec(&resp_payload) {
                if let Some(id) = identity {
                    let resp_msg = GossipMessage::new(
                        id.signing_key(),
                        1,
                        1,
                        PAYLOAD_TYPE_GET_PEERS_RESP,
                        resp_bytes,
                    );
                    let _ = socket.send_to(&resp_msg.to_bytes(), src).await;
                }
            }
        } else if msg.payload_type == PAYLOAD_TYPE_GET_PEERS_RESP {
            if let Ok(resp) = serde_json::from_slice::<GetPeersResponse>(&msg.payload) {
                println!(
                    "  📖 [P2P Phonebook] Received GetPeersResponse from {} with {} peers",
                    src,
                    resp.peers.len()
                );
                if let Ok(mut pb) = self.phonebook.write() {
                    for peer_addr in resp.peers {
                        pb.add_peer(peer_addr);
                    }
                }
            }
        } else if msg.payload_type == PAYLOAD_TYPE_REFLECT_ADDR_REQ {
            println!(
                "  🔍 [P2P Reflection] Received AddressReflectionRequest from {}",
                src
            );
            let resp_payload = AddressReflectionResponse {
                reflected_addr: src.to_string(),
            };
            if let Ok(resp_bytes) = serde_json::to_vec(&resp_payload) {
                if let Some(id) = identity {
                    let resp_msg = GossipMessage::new(
                        id.signing_key(),
                        1,
                        1,
                        PAYLOAD_TYPE_REFLECT_ADDR_RESP,
                        resp_bytes,
                    );
                    let _ = socket.send_to(&resp_msg.to_bytes(), src).await;
                }
            }
        } else if msg.payload_type == PAYLOAD_TYPE_REFLECT_ADDR_RESP {
            if let Ok(resp) = serde_json::from_slice::<AddressReflectionResponse>(&msg.payload) {
                println!(
                    "  🔍 [P2P Reflection] Peer {} sees our socket connection coming from: {}",
                    src, resp.reflected_addr
                );
            }
        } else if msg.payload_type == PAYLOAD_TYPE_RANGE_SYNC_REQ {
            if let Some(db) = &self.database {
                handle_range_sync_request(&msg, src, socket, identity, db).await;
            }
        } else if msg.payload_type == PAYLOAD_TYPE_RANGE_SYNC_RESP {
            if let Some(db) = &self.database {
                handle_range_sync_response(&msg, src, socket, identity, db).await;
            }
        } else if msg.payload_type == PAYLOAD_TYPE_MERKLE_DRILL_REQ {
            if let Some(db) = &self.database {
                handle_merkle_drill_request(&msg, src, socket, identity, db).await;
            }
        } else if msg.payload_type == PAYLOAD_TYPE_MERKLE_DRILL_RESP {
            if let Some(db) = &self.database {
                handle_merkle_drill_response(&msg, src, socket, identity, db).await;
            }
        }

        if msg.ttl > 1 {
            let mut forwarded_msg = msg.clone();
            forwarded_msg.ttl -= 1;
            let packet_bytes = forwarded_msg.to_bytes();

            let peers = self.active_peers();
            for peer in peers {
                if peer != src {
                    let _ = socket.send_to(&packet_bytes, peer).await;
                }
            }
        }

        Ok(Some(msg))
    }

    pub async fn broadcast(&self, msg: &GossipMessage, socket: &UdpSocket) {
        self.mark_seen(msg.msg_id);
        let packet_bytes = msg.to_bytes();
        let peers = self.active_peers();
        for peer in peers {
            let _ = socket.send_to(&packet_bytes, peer).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::NodeIdentity;
    use crate::net::gossip::{DEFAULT_GOSSIP_TTL, PAYLOAD_TYPE_VOTE};

    #[test]
    fn test_router_seen_cache_deduplication() {
        let phonebook = Arc::new(RwLock::new(Phonebook::new()));
        let router = GossipRouter::new(phonebook);

        let identity = NodeIdentity::from_seed_and_role(
            &[0x44u8; 32],
            crate::crypto::identity::NodeRole::Voter,
        );
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
        use crate::net::gossip::{RangeSyncRequest, PAYLOAD_TYPE_RANGE_SYNC_REQ};
        use crate::storage::db::Database;
        use ed25519_dalek::{Signer, SigningKey};

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
        use crate::storage::db::Database;
        use ed25519_dalek::SigningKey;

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
}
