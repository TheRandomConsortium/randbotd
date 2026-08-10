use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::net::frame::MAGIC_BYTES;

pub const PAYLOAD_TYPE_PING: u8 = 0;
pub const PAYLOAD_TYPE_ADDRESS_ANNOUNCEMENT: u8 = 1;
pub const PAYLOAD_TYPE_VOTE: u8 = 2;
pub const PAYLOAD_TYPE_CA_DECLARATION: u8 = 3;
pub const PAYLOAD_TYPE_GET_PEERS_REQ: u8 = 5;
pub const PAYLOAD_TYPE_GET_PEERS_RESP: u8 = 6;
pub const PAYLOAD_TYPE_REFLECT_ADDR_REQ: u8 = 7;
pub const PAYLOAD_TYPE_REFLECT_ADDR_RESP: u8 = 8;
pub const PAYLOAD_TYPE_RANGE_SYNC_REQ: u8 = 9;
pub const PAYLOAD_TYPE_RANGE_SYNC_RESP: u8 = 10;
pub const PAYLOAD_TYPE_MERKLE_DRILL_REQ: u8 = 11;
pub const PAYLOAD_TYPE_MERKLE_DRILL_RESP: u8 = 12;
#[allow(dead_code)]
pub const PAYLOAD_TYPE_EQUIVOCATION_PROOF: u8 = 13;

pub const DEFAULT_GOSSIP_TTL: u8 = 8;

#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EquivocationProof {
    pub originator: [u8; 32],
    pub conflicting_event_a: crate::net::history::EventLogEntry,
    pub conflicting_event_b: crate::net::history::EventLogEntry,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GetPeersRequest;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GetPeersResponse {
    pub peers: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub struct AddressReflectionRequest;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AddressReflectionResponse {
    pub reflected_addr: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RangeSyncRequest {
    pub vector: Vec<crate::net::history::OriginatorRangeVector>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RangeSyncResponse {
    pub entries_for_peer: Vec<crate::net::history::EventLogEntry>,
    pub my_vector: Vec<crate::net::history::OriginatorRangeVector>,
}

#[derive(Debug, Clone)]
pub struct GossipMessage {
    pub msg_id: [u8; 32],
    pub originator_pubkey: [u8; 32],
    pub seq: u64,
    pub ttl: u8,
    pub payload_type: u8,
    pub payload: Vec<u8>,
    pub signature: [u8; 64],
}

impl GossipMessage {
    pub fn new(
        signing_key: &SigningKey,
        seq: u64,
        ttl: u8,
        payload_type: u8,
        payload: Vec<u8>,
    ) -> Self {
        let originator_pubkey = signing_key.verifying_key().to_bytes();

        let mut hasher = Sha256::new();
        hasher.update(originator_pubkey);
        hasher.update(seq.to_be_bytes());
        hasher.update([payload_type]);
        hasher.update(&payload);
        let msg_id: [u8; 32] = hasher.finalize().into();

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(MAGIC_BYTES);
        signed_data.extend_from_slice(&msg_id);
        signed_data.extend_from_slice(&originator_pubkey);
        signed_data.extend_from_slice(&seq.to_be_bytes());
        signed_data.extend_from_slice(&[ttl]);
        signed_data.extend_from_slice(&[payload_type]);
        signed_data.extend_from_slice(&payload);

        let signature = signing_key.sign(&signed_data).to_bytes();

        Self {
            msg_id,
            originator_pubkey,
            seq,
            ttl,
            payload_type,
            payload,
            signature,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC_BYTES);
        buf.extend_from_slice(&self.msg_id);
        buf.extend_from_slice(&self.originator_pubkey);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&[self.ttl]);
        buf.extend_from_slice(&[self.payload_type]);
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 4 + 32 + 32 + 8 + 1 + 1 + 4 + 64 {
            return Err("Packet too short for GossipMessage");
        }
        if &buf[..4] != MAGIC_BYTES {
            return Err("Invalid magic bytes");
        }

        let mut msg_id = [0u8; 32];
        msg_id.copy_from_slice(&buf[4..36]);

        let mut originator_pubkey = [0u8; 32];
        originator_pubkey.copy_from_slice(&buf[36..68]);

        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&buf[68..76]);
        let seq = u64::from_be_bytes(seq_bytes);

        let ttl = buf[76];
        let payload_type = buf[77];

        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&buf[78..82]);
        let payload_len = u32::from_be_bytes(len_bytes) as usize;

        if buf.len() < 82 + payload_len + 64 {
            return Err("Incomplete payload in GossipMessage");
        }

        let payload = buf[82..82 + payload_len].to_vec();

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&buf[82 + payload_len..82 + payload_len + 64]);

        let msg = Self {
            msg_id,
            originator_pubkey,
            seq,
            ttl,
            payload_type,
            payload,
            signature: sig_bytes,
        };

        msg.verify()?;
        Ok(msg)
    }

    pub fn verify(&self) -> Result<(), &'static str> {
        let verifying_key = VerifyingKey::from_bytes(&self.originator_pubkey)
            .map_err(|_| "Invalid Ed25519 public key")?;
        let signature = Signature::from_bytes(&self.signature);

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(MAGIC_BYTES);
        signed_data.extend_from_slice(&self.msg_id);
        signed_data.extend_from_slice(&self.originator_pubkey);
        signed_data.extend_from_slice(&self.seq.to_be_bytes());
        signed_data.extend_from_slice(&[self.ttl]);
        signed_data.extend_from_slice(&[self.payload_type]);
        signed_data.extend_from_slice(&self.payload);

        verifying_key
            .verify(&signed_data, &signature)
            .map_err(|_| "Gossip message signature verification failed")
    }
}

#[derive(Debug, Clone)]
pub struct AddressAnnouncementPayload {
    pub new_address: String,
    pub timestamp: u64,
    pub is_seed: bool,
}

impl AddressAnnouncementPayload {
    pub fn new(new_address: &str, is_seed: bool) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            new_address: new_address.to_string(),
            timestamp,
            is_seed,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.push(if self.is_seed { 1 } else { 0 });
        buf.extend_from_slice(self.new_address.as_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 9 {
            return Err("Payload too short for AddressAnnouncement");
        }
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&buf[..8]);
        let timestamp = u64::from_be_bytes(ts_bytes);
        let is_seed = buf[8] != 0;
        let new_address =
            String::from_utf8(buf[9..].to_vec()).map_err(|_| "Invalid UTF-8 address string")?;

        Ok(Self {
            new_address,
            timestamp,
            is_seed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::NodeIdentity;

    #[test]
    fn test_gossip_message_serialization_roundtrip() {
        let identity = NodeIdentity::from_seed_and_role(
            &[0x11u8; 32],
            crate::crypto::identity::NodeRole::Voter,
        );
        let payload = b"TW_vote_for_randbot.hns".to_vec();

        let msg = GossipMessage::new(
            identity.signing_key(),
            1,
            DEFAULT_GOSSIP_TTL,
            PAYLOAD_TYPE_VOTE,
            payload.clone(),
        );

        let encoded = msg.to_bytes();
        let decoded = GossipMessage::from_bytes(&encoded).expect("Decoding failed");

        assert_eq!(msg.msg_id, decoded.msg_id);
        assert_eq!(msg.originator_pubkey, decoded.originator_pubkey);
        assert_eq!(msg.seq, decoded.seq);
        assert_eq!(msg.ttl, decoded.ttl);
        assert_eq!(msg.payload, decoded.payload);
    }
}
