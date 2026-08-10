use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

pub type SaturatedOriginatorMap = Arc<RwLock<HashMap<(SocketAddr, [u8; 32]), u64>>>;

pub struct PeerAntiSpamState {
    pub banned_peers: Arc<RwLock<HashMap<SocketAddr, u64>>>,
    pub pending_drill_nonces: Arc<RwLock<HashMap<u64, u64>>>,
    pub saturated_originators: SaturatedOriginatorMap,
}

impl PeerAntiSpamState {
    pub fn new() -> Self {
        Self {
            banned_peers: Arc::new(RwLock::new(HashMap::new())),
            pending_drill_nonces: Arc::new(RwLock::new(HashMap::new())),
            saturated_originators: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn ban_peer(&self, addr: SocketAddr, duration_secs: u64) {
        let until = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + duration_secs;
        if let Ok(mut map) = self.banned_peers.write() {
            map.insert(addr, until);
        }
        println!(
            "  🚫 [P2P Anti-Spam] Banned peer {} for {} seconds",
            addr, duration_secs
        );
    }

    pub fn is_banned(&self, addr: SocketAddr) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Ok(mut map) = self.banned_peers.write() {
            if let Some(&until) = map.get(&addr) {
                if now < until {
                    return true;
                } else {
                    map.remove(&addr);
                }
            }
        }
        false
    }

    pub fn register_drill_nonce(&self, nonce: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Ok(mut map) = self.pending_drill_nonces.write() {
            map.insert(nonce, now);
        }
    }

    pub fn validate_and_take_nonce(&self, nonce: u64) -> bool {
        if let Ok(mut map) = self.pending_drill_nonces.write() {
            map.remove(&nonce).is_some()
        } else {
            false
        }
    }

    pub fn is_originator_saturated(
        &self,
        peer: SocketAddr,
        originator: &[u8; 32],
        req_end: u64,
    ) -> bool {
        if let Ok(map) = self.saturated_originators.read() {
            if let Some(&highest_seq) = map.get(&(peer, *originator)) {
                return req_end <= highest_seq;
            }
        }
        false
    }

    pub fn mark_originator_saturated(
        &self,
        peer: SocketAddr,
        originator: [u8; 32],
        highest_seq: u64,
    ) {
        if let Ok(mut map) = self.saturated_originators.write() {
            map.insert((peer, originator), highest_seq);
        }
    }
}
