use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_SEED_DOMAIN: &str = "therandomconsortium.org:43210";

pub const ZERO_PUBKEY: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub pubkey_hex: String,
    pub address: String,
    pub last_seen: u64,
    /// Capability claim advertised by the remote node in its handshake / AddressAnnouncement
    pub self_declared_seed: bool,
    /// Verified seed status confirmed locally by the node.
    pub verified_seed: bool,
    /// Behavioral ponderation / Web-of-Trust score (0 to 100). Reserved for `REP-03`.
    pub ponderation_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Phonebook {
    pub peers: HashMap<String, PeerEntry>,
    #[serde(skip)]
    pub pending_dial_peers: Vec<String>,
    #[serde(skip)]
    pub file_path: Option<std::path::PathBuf>,
    #[serde(skip)]
    pub my_pubkey_hex: Option<String>,
    #[serde(skip)]
    pub my_pubkey: Option<[u8; 32]>,
}

impl Phonebook {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            pending_dial_peers: Vec::new(),
            file_path: None,
            my_pubkey_hex: None,
            my_pubkey: None,
        }
    }

    pub fn set_my_pubkey(&mut self, pubkey: &[u8; 32]) {
        self.my_pubkey = Some(*pubkey);
        self.my_pubkey_hex = Some(hex_encode(pubkey));
    }

    pub fn my_pubkey_bytes(&self) -> Option<[u8; 32]> {
        self.my_pubkey
    }

    pub fn load_from_file(path: &Path) -> io::Result<Self> {
        if !path.exists() {
            let mut pb = Self::new();
            pb.file_path = Some(path.to_path_buf());
            let _ = pb.save_to_file(path);
            return Ok(pb);
        }
        let data = fs::read_to_string(path)?;
        let mut pb: Phonebook = serde_json::from_str(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        pb.file_path = Some(path.to_path_buf());
        Ok(pb)
    }

    pub fn save_to_file(&self, path: &Path) -> io::Result<()> {
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, data)
    }

    pub fn auto_save(&self) {
        if let Some(ref path) = self.file_path {
            let _ = self.save_to_file(path);
        }
    }

    pub fn upsert_peer(&mut self, pubkey: &[u8; 32], address: &str, self_declared_seed: bool) {
        if pubkey == &[0u8; 32] {
            return;
        }
        let pubkey_hex = hex_encode(pubkey);
        if let Some(ref my_pk) = self.my_pubkey_hex {
            if &pubkey_hex == my_pk {
                return;
            }
        }
        let is_currently_verified = self
            .peers
            .get(address)
            .map(|existing| existing.verified_seed)
            .unwrap_or(false);

        let entry = PeerEntry {
            pubkey_hex,
            address: address.to_string(),
            last_seen: current_timestamp(),
            self_declared_seed,
            verified_seed: is_currently_verified,
            ponderation_score: 50,
        };
        self.peers.insert(address.to_string(), entry);
        self.auto_save();
    }

    pub fn resolve_peer_addresses(&self) -> Vec<std::net::SocketAddr> {
        let mut addrs = Vec::new();
        for entry in self.peers.values() {
            if let Ok(resolved) = entry.address.to_socket_addrs() {
                addrs.extend(resolved);
            }
        }
        addrs
    }

    pub fn verified_seed_addresses(&self) -> Vec<std::net::SocketAddr> {
        let mut addrs = Vec::new();
        for entry in self.peers.values() {
            if entry.verified_seed {
                if let Ok(resolved) = entry.address.to_socket_addrs() {
                    addrs.extend(resolved);
                }
            }
        }
        addrs
    }

    pub fn add_peer(&mut self, address: String) {
        let clean = address.trim().to_string();
        if !clean.is_empty() && !self.pending_dial_peers.contains(&clean) {
            self.pending_dial_peers.push(clean);
        }
    }

    pub fn all_peers(&self) -> Vec<String> {
        let mut list: Vec<String> = self.peers.keys().cloned().collect();
        for pending in &self.pending_dial_peers {
            if !list.contains(pending) {
                list.push(pending.clone());
            }
        }
        list
    }

    /// Randomly samples up to `max_count` (e.g. 8) active peer addresses from local phonebook map
    pub fn sample_random_peers(&self, max_count: usize, exclude_peer: &str) -> Vec<String> {
        use rand::seq::SliceRandom;

        let mut candidates: Vec<String> = self
            .peers
            .iter()
            .filter(|(addr, entry)| {
                addr.as_str() != exclude_peer
                    && entry.pubkey_hex != ZERO_PUBKEY
                    && !entry.pubkey_hex.is_empty()
            })
            .map(|(addr, _)| addr.clone())
            .collect();

        let mut rng = rand::thread_rng();
        candidates.shuffle(&mut rng);
        candidates.truncate(max_count);
        candidates
    }
}

pub fn bootstrap_seed_addresses() -> Vec<std::net::SocketAddr> {
    let mut addrs = Vec::new();
    if let Ok(resolved) = DEFAULT_SEED_DOMAIN.to_socket_addrs() {
        addrs.extend(resolved);
    }
    addrs
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phonebook_bootstrap_seed_addresses() {
        let addrs = bootstrap_seed_addresses();
        assert!(!addrs.is_empty());
    }

    #[test]
    fn test_phonebook_sample_random_peers() {
        let mut pb = Phonebook::new();
        for i in 1..=15 {
            let key = [(i % 255) as u8; 32];
            pb.upsert_peer(&key, &format!("192.168.1.{}:43210", i), false);
        }

        let sampled = pb.sample_random_peers(8, "192.168.1.1:43210");
        assert!(sampled.len() <= 8);
        assert!(!sampled.contains(&"192.168.1.1:43210".to_string()));
    }

    #[test]
    fn test_phonebook_add_peer_and_all_peers() {
        let mut pb = Phonebook::new();
        pb.add_peer("127.0.0.1:43210".to_string());
        assert!(pb.all_peers().contains(&"127.0.0.1:43210".to_string()));
    }
}
