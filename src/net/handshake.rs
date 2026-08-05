use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, Verifier};
use x25519_dalek::PublicKey as X25519PublicKey;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::net::frame::MAGIC_BYTES;

#[derive(Debug, Clone)]
pub struct HandshakeInit {
    pub sender_pubkey: [u8; 32],
    pub ephemeral_x25519: [u8; 32],
    pub timestamp: u64,
    pub nonce: [u8; 24],
    pub signature: [u8; 64],
}

impl HandshakeInit {
    pub fn new(signing_key: &SigningKey, ephemeral_x25519_pub: &X25519PublicKey) -> Self {
        let sender_pubkey = signing_key.verifying_key().to_bytes();
        let ephemeral_bytes = ephemeral_x25519_pub.to_bytes();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let mut nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(MAGIC_BYTES);
        signed_data.extend_from_slice(&sender_pubkey);
        signed_data.extend_from_slice(&ephemeral_bytes);
        signed_data.extend_from_slice(&timestamp.to_be_bytes());
        signed_data.extend_from_slice(&nonce);

        let signature = signing_key.sign(&signed_data).to_bytes();

        Self {
            sender_pubkey,
            ephemeral_x25519: ephemeral_bytes,
            timestamp,
            nonce,
            signature,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC_BYTES);
        buf.extend_from_slice(&self.sender_pubkey);
        buf.extend_from_slice(&self.ephemeral_x25519);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 4 + 32 + 32 + 8 + 24 + 64 {
            return Err("Packet too short for HandshakeInit");
        }
        if &buf[..4] != MAGIC_BYTES {
            return Err("Invalid magic bytes");
        }

        let mut sender_pubkey = [0u8; 32];
        sender_pubkey.copy_from_slice(&buf[4..36]);

        let mut ephemeral_x25519 = [0u8; 32];
        ephemeral_x25519.copy_from_slice(&buf[36..68]);

        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&buf[68..76]);
        let timestamp = u64::from_be_bytes(ts_bytes);

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&buf[76..100]);

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&buf[100..164]);

        let init = Self {
            sender_pubkey,
            ephemeral_x25519,
            timestamp,
            nonce,
            signature: sig_bytes,
        };

        init.verify()?;
        Ok(init)
    }

    pub fn verify(&self) -> Result<(), &'static str> {
        let verifying_key = VerifyingKey::from_bytes(&self.sender_pubkey)
            .map_err(|_| "Invalid Ed25519 public key")?;
        let signature = Signature::from_bytes(&self.signature);

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(MAGIC_BYTES);
        signed_data.extend_from_slice(&self.sender_pubkey);
        signed_data.extend_from_slice(&self.ephemeral_x25519);
        signed_data.extend_from_slice(&self.timestamp.to_be_bytes());
        signed_data.extend_from_slice(&self.nonce);

        verifying_key
            .verify(&signed_data, &signature)
            .map_err(|_| "Handshake signature verification failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::NodeIdentity;
    use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

    #[test]
    fn test_handshake_init_roundtrip() {
        let identity = NodeIdentity::generate();
        let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rand::thread_rng());
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

        let init = HandshakeInit::new(identity.signing_key(), &ephemeral_public);
        let encoded = init.to_bytes();
        let decoded = HandshakeInit::from_bytes(&encoded).expect("Decoding failed");

        assert_eq!(init.sender_pubkey, decoded.sender_pubkey);
        assert_eq!(init.ephemeral_x25519, decoded.ephemeral_x25519);
    }
}
