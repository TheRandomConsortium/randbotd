use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_SEED_DOMAIN: &str = "therandomconsortium.org:43210";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub pubkey_hex: String,
    pub address: String,
    pub last_seen: u64,
    /// Capability claim advertised by the remote node in its handshake / AddressAnnouncement
    pub self_declared_seed: bool,
    /// Verified seed status confirmed locally by the node.
    /// NOTE: Web-of-Trust (WoT) seed promotion relies on behavioral score ponderation (`REP-03`).
    /// Until `REP-03` ponderation is fully implemented, newly discovered nodes remain `verified_seed = false`
    /// to prevent unverified self-declared seeds from polluting the bootstrap tier.
    pub verified_seed: bool,
    /// Behavioral ponderation / Web-of-Trust score (0 to 100). Reserved for `REP-03`.
    pub ponderation_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Phonebook {
    pub peers: HashMap<String, PeerEntry>,
}

impl Phonebook {
    pub fn new() -> Self {
        let mut pb = Self {
            peers: HashMap::new(),
        };
        pb.add_default_seed();
        pb
    }

    pub fn add_default_seed(&mut self) {
        let seed_entry = PeerEntry {
            pubkey_hex: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            address: DEFAULT_SEED_DOMAIN.to_string(),
            last_seen: current_timestamp(),
            self_declared_seed: true,
            verified_seed: true,
            ponderation_score: 50,
        };
        self.peers
            .insert(DEFAULT_SEED_DOMAIN.to_string(), seed_entry);
    }

    pub fn load_from_file(path: &Path) -> io::Result<Self> {
        if !path.exists() {
            let pb = Self::new();
            let _ = pb.save_to_file(path);
            return Ok(pb);
        }
        let data = fs::read_to_string(path)?;
        let mut pb: Phonebook = serde_json::from_str(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if pb.peers.is_empty() {
            pb.add_default_seed();
        }
        Ok(pb)
    }

    pub fn save_to_file(&self, path: &Path) -> io::Result<()> {
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, data)
    }

    pub fn upsert_peer(&mut self, pubkey: &[u8; 32], address: &str, self_declared_seed: bool) {
        let pubkey_hex = hex_encode(pubkey);
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
    fn test_phonebook_default_seed() {
        let pb = Phonebook::new();
        assert!(pb.peers.contains_key(DEFAULT_SEED_DOMAIN));
        let seed = pb.peers.get(DEFAULT_SEED_DOMAIN).unwrap();
        assert!(seed.verified_seed);
        assert!(seed.self_declared_seed);
    }
}
