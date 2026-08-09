use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::net::UdpSocket;

use crate::crypto::identity::NodeIdentity;
use crate::net::gossip::{
    AddressAnnouncementPayload, GossipMessage, PAYLOAD_TYPE_ADDRESS_ANNOUNCEMENT, PAYLOAD_TYPE_PING,
};
use crate::net::handshake::{HandshakeInit, HandshakeResponse};
use crate::net::phonebook::Phonebook;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

pub struct GossipRouter {
    seen_cache: Arc<RwLock<HashMap<[u8; 32], u64>>>,
    active_peers: Arc<RwLock<HashMap<SocketAddr, u64>>>,
    phonebook: Arc<RwLock<Phonebook>>,
}

impl GossipRouter {
    pub fn new(phonebook: Arc<RwLock<Phonebook>>) -> Self {
        Self {
            seen_cache: Arc::new(RwLock::new(HashMap::new())),
            active_peers: Arc::new(RwLock::new(HashMap::new())),
            phonebook,
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
            // Ignore self-originating handshakes
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

            // Reply with HandshakeResponse if identity is present
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
            // Ignore self-originating responses
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

        // Ignore self-originating gossip
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
}
