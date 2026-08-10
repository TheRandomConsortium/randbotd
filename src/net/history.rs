use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// P2P Payload Types that are transient network traffic and MUST NOT enter the monotonic event log
pub const TRANSIENT_PAYLOAD_TYPES: &[u8] = &[
    0x00, // PING
    0x01, // ADDRESS_ANNOUNCEMENT
    0x05, // GET_PEERS_REQ
    0x06, // GET_PEERS_RESP
    0x07, // REFLECT_ADDR_REQ
    0x08, // REFLECT_ADDR_RESP
];

/// A raw, cryptographically signed monotonic event log item for P2P consensus anti-entropy sync
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventLogEntry {
    pub seq: u64,
    pub prev_hash: [u8; 32],
    pub originator: [u8; 32],
    pub payload_type: u8,
    pub payload: Vec<u8>,
    pub signature_bytes: Vec<u8>,
}

impl EventLogEntry {
    #[allow(dead_code)]
    pub fn new(
        seq: u64,
        prev_hash: [u8; 32],
        originator: [u8; 32],
        payload_type: u8,
        payload: Vec<u8>,
        signature_bytes: Vec<u8>,
    ) -> Result<Self, String> {
        if Self::is_transient(payload_type) {
            return Err(format!(
                "Payload type 0x{:02x} is transient and strictly prohibited from entering event log",
                payload_type
            ));
        }

        let entry = Self {
            seq,
            prev_hash,
            originator,
            payload_type,
            payload,
            signature_bytes,
        };

        entry.verify_signature()?;
        Ok(entry)
    }

    /// Checks if a payload type is transient network traffic (Ping, AddressAnnounce, GetPeers, ReflectAddr)
    pub fn is_transient(payload_type: u8) -> bool {
        TRANSIENT_PAYLOAD_TYPES.contains(&payload_type)
    }

    /// Computes the SHA-256 hash of this event entry
    #[allow(dead_code)]
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.seq.to_be_bytes());
        hasher.update(self.prev_hash);
        hasher.update(self.originator);
        hasher.update([self.payload_type]);
        hasher.update(&self.payload);
        hasher.update(&self.signature_bytes);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verifies the Ed25519 signature over (seq || prev_hash || payload_type || payload)
    pub fn verify_signature(&self) -> Result<(), String> {
        let vk = VerifyingKey::from_bytes(&self.originator)
            .map_err(|e| format!("Invalid originator verifying key: {}", e))?;

        if self.signature_bytes.len() != 64 {
            return Err(format!(
                "Invalid signature byte length: expected 64, got {}",
                self.signature_bytes.len()
            ));
        }

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&self.signature_bytes);
        let sig = Signature::from_bytes(&sig_arr);

        let mut signed_data = Vec::with_capacity(8 + 32 + 1 + self.payload.len());
        signed_data.extend_from_slice(&self.seq.to_be_bytes());
        signed_data.extend_from_slice(&self.prev_hash);
        signed_data.push(self.payload_type);
        signed_data.extend_from_slice(&self.payload);

        vk.verify(&signed_data, &sig)
            .map_err(|e| format!("Event signature verification failed: {}", e))
    }
}

/// Monotonic sequence range [start..=end] for a single originator
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SequenceRange {
    pub start: u64,
    pub end: u64,
}

impl SequenceRange {
    pub fn contains(&self, seq: u64) -> bool {
        seq >= self.start && seq <= self.end
    }
}

/// Node-scoped anti-entropy range vector tracking known sequence ranges & optional Merkle root per originator
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OriginatorRangeVector {
    pub originator: [u8; 32],
    pub known_ranges: Vec<SequenceRange>,
    pub merkle_root: Option<[u8; 32]>,
}

impl OriginatorRangeVector {
    pub fn new(originator: [u8; 32], known_ranges: Vec<SequenceRange>) -> Self {
        Self {
            originator,
            known_ranges,
            merkle_root: None,
        }
    }

    /// Checks if a sequence number is present in any known range
    pub fn has_sequence(&self, seq: u64) -> bool {
        self.known_ranges.iter().any(|r| r.contains(seq))
    }
}

/// Merkle tree node for iterative anti-entropy drill-down when range vectors are heavily fragmented
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(dead_code)]
pub struct MerkleNode {
    pub hash: [u8; 32],
    pub range: SequenceRange,
}

/// Request to drill down into a specific subtree range when Merkle roots diverge
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(dead_code)]
pub struct MerkleDrillRequest {
    pub originator: [u8; 32],
    pub target_range: SequenceRange,
}

/// Response containing left and right child Merkle nodes for subtree drill-down
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(dead_code)]
pub struct MerkleDrillResponse {
    pub originator: [u8; 32],
    pub left_child: Option<MerkleNode>,
    pub right_child: Option<MerkleNode>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn test_transient_payload_exclusion() {
        assert!(EventLogEntry::is_transient(0x00)); // PING
        assert!(EventLogEntry::is_transient(0x01)); // ADDRESS_ANNOUNCEMENT
        assert!(EventLogEntry::is_transient(0x05)); // GET_PEERS_REQ
        assert!(EventLogEntry::is_transient(0x06)); // GET_PEERS_RESP
        assert!(EventLogEntry::is_transient(0x07)); // REFLECT_ADDR_REQ
        assert!(EventLogEntry::is_transient(0x08)); // REFLECT_ADDR_RESP

        assert!(!EventLogEntry::is_transient(0x02)); // VOTE
        assert!(!EventLogEntry::is_transient(0x03)); // CA_DECLARATION
    }

    #[test]
    fn test_event_log_entry_signature_verification() {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let originator = signing_key.verifying_key().to_bytes();

        let seq = 1u64;
        let prev_hash = [0x00u8; 32];
        let payload_type = 0x02u8; // VOTE
        let payload = b"TW_vote_for_randbot.hns".to_vec();

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&seq.to_be_bytes());
        signed_data.extend_from_slice(&prev_hash);
        signed_data.push(payload_type);
        signed_data.extend_from_slice(&payload);

        let signature_bytes = signing_key.sign(&signed_data).to_bytes().to_vec();

        let entry = EventLogEntry::new(
            seq,
            prev_hash,
            originator,
            payload_type,
            payload.clone(),
            signature_bytes,
        )
        .expect("Failed to create valid EventLogEntry");

        assert_eq!(entry.seq, 1);
        assert_eq!(entry.compute_hash().len(), 32);
    }
}
