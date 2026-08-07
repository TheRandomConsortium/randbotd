use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::net::frame::MAGIC_BYTES;

pub const MAGIC_BYTES_RESPONSE: &[u8; 4] = b"RBr1";
pub const CAPABILITY_FLAG_SEED: u32 = 1 << 0;
pub const CAPABILITY_FLAG_HEADLESS: u32 = 1 << 1;
pub const CAPABILITY_FLAG_VOTER: u32 = 1 << 2;

#[derive(Debug, Clone)]
pub struct HandshakeInit {
    pub sender_pubkey: [u8; 32],
    pub ephemeral_x25519: [u8; 32],
    pub timestamp: u64,
    pub capabilities: u32,
    pub nonce: [u8; 24],
    pub signature: [u8; 64],
}

impl HandshakeInit {
    pub fn new(
        signing_key: &SigningKey,
        ephemeral_x25519_pub: &X25519PublicKey,
        is_seed: bool,
        is_headless: bool,
    ) -> Self {
        let sender_pubkey = signing_key.verifying_key().to_bytes();
        let ephemeral_bytes = ephemeral_x25519_pub.to_bytes();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut capabilities = 0u32;
        if is_seed {
            capabilities |= CAPABILITY_FLAG_SEED;
        }
        if is_headless {
            capabilities |= CAPABILITY_FLAG_HEADLESS;
        } else {
            capabilities |= CAPABILITY_FLAG_VOTER;
        }

        let mut nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(MAGIC_BYTES);
        signed_data.extend_from_slice(&sender_pubkey);
        signed_data.extend_from_slice(&ephemeral_bytes);
        signed_data.extend_from_slice(&timestamp.to_be_bytes());
        signed_data.extend_from_slice(&capabilities.to_be_bytes());
        signed_data.extend_from_slice(&nonce);

        let signature = signing_key.sign(&signed_data).to_bytes();

        Self {
            sender_pubkey,
            ephemeral_x25519: ephemeral_bytes,
            timestamp,
            capabilities,
            nonce,
            signature,
        }
    }

    pub fn is_seed(&self) -> bool {
        (self.capabilities & CAPABILITY_FLAG_SEED) != 0
    }

    pub fn is_headless(&self) -> bool {
        (self.capabilities & CAPABILITY_FLAG_HEADLESS) != 0
    }

    pub fn is_voter(&self) -> bool {
        (self.capabilities & CAPABILITY_FLAG_VOTER) != 0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC_BYTES);
        buf.extend_from_slice(&self.sender_pubkey);
        buf.extend_from_slice(&self.ephemeral_x25519);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.capabilities.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 4 + 32 + 32 + 8 + 4 + 24 + 64 {
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

        let mut cap_bytes = [0u8; 4];
        cap_bytes.copy_from_slice(&buf[76..80]);
        let capabilities = u32::from_be_bytes(cap_bytes);

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&buf[80..104]);

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&buf[104..168]);

        let init = Self {
            sender_pubkey,
            ephemeral_x25519,
            timestamp,
            capabilities,
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
        signed_data.extend_from_slice(&self.capabilities.to_be_bytes());
        signed_data.extend_from_slice(&self.nonce);

        verifying_key
            .verify(&signed_data, &signature)
            .map_err(|_| "Handshake signature verification failed")
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeResponse {
    pub sender_pubkey: [u8; 32],
    pub ephemeral_x25519: [u8; 32],
    pub timestamp: u64,
    pub capabilities: u32,
    pub nonce: [u8; 24],
    pub signature: [u8; 64],
}

impl HandshakeResponse {
    pub fn new(
        signing_key: &SigningKey,
        ephemeral_x25519_pub: &X25519PublicKey,
        is_seed: bool,
        is_headless: bool,
    ) -> Self {
        let sender_pubkey = signing_key.verifying_key().to_bytes();
        let ephemeral_bytes = ephemeral_x25519_pub.to_bytes();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut capabilities = 0u32;
        if is_seed {
            capabilities |= CAPABILITY_FLAG_SEED;
        }
        if is_headless {
            capabilities |= CAPABILITY_FLAG_HEADLESS;
        } else {
            capabilities |= CAPABILITY_FLAG_VOTER;
        }

        let mut nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(MAGIC_BYTES_RESPONSE);
        signed_data.extend_from_slice(&sender_pubkey);
        signed_data.extend_from_slice(&ephemeral_bytes);
        signed_data.extend_from_slice(&timestamp.to_be_bytes());
        signed_data.extend_from_slice(&capabilities.to_be_bytes());
        signed_data.extend_from_slice(&nonce);

        let signature = signing_key.sign(&signed_data).to_bytes();

        Self {
            sender_pubkey,
            ephemeral_x25519: ephemeral_bytes,
            timestamp,
            capabilities,
            nonce,
            signature,
        }
    }

    pub fn is_seed(&self) -> bool {
        (self.capabilities & CAPABILITY_FLAG_SEED) != 0
    }

    pub fn is_headless(&self) -> bool {
        (self.capabilities & CAPABILITY_FLAG_HEADLESS) != 0
    }

    pub fn is_voter(&self) -> bool {
        (self.capabilities & CAPABILITY_FLAG_VOTER) != 0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC_BYTES_RESPONSE);
        buf.extend_from_slice(&self.sender_pubkey);
        buf.extend_from_slice(&self.ephemeral_x25519);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.capabilities.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 4 + 32 + 32 + 8 + 4 + 24 + 64 {
            return Err("Packet too short for HandshakeResponse");
        }
        if &buf[..4] != MAGIC_BYTES_RESPONSE {
            return Err("Invalid response magic bytes");
        }

        let mut sender_pubkey = [0u8; 32];
        sender_pubkey.copy_from_slice(&buf[4..36]);

        let mut ephemeral_x25519 = [0u8; 32];
        ephemeral_x25519.copy_from_slice(&buf[36..68]);

        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&buf[68..76]);
        let timestamp = u64::from_be_bytes(ts_bytes);

        let mut cap_bytes = [0u8; 4];
        cap_bytes.copy_from_slice(&buf[76..80]);
        let capabilities = u32::from_be_bytes(cap_bytes);

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&buf[80..104]);

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&buf[104..168]);

        let res = Self {
            sender_pubkey,
            ephemeral_x25519,
            timestamp,
            capabilities,
            nonce,
            signature: sig_bytes,
        };

        res.verify()?;
        Ok(res)
    }

    pub fn verify(&self) -> Result<(), &'static str> {
        let verifying_key = VerifyingKey::from_bytes(&self.sender_pubkey)
            .map_err(|_| "Invalid Ed25519 public key")?;
        let signature = Signature::from_bytes(&self.signature);

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(MAGIC_BYTES_RESPONSE);
        signed_data.extend_from_slice(&self.sender_pubkey);
        signed_data.extend_from_slice(&self.ephemeral_x25519);
        signed_data.extend_from_slice(&self.timestamp.to_be_bytes());
        signed_data.extend_from_slice(&self.capabilities.to_be_bytes());
        signed_data.extend_from_slice(&self.nonce);

        verifying_key
            .verify(&signed_data, &signature)
            .map_err(|_| "Handshake response signature verification failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::NodeIdentity;
    use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

    #[test]
    fn test_handshake_init_roundtrip() {
        let identity = NodeIdentity::generate(crate::crypto::identity::NodeRole::Voter);
        let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rand::thread_rng());
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

        let init = HandshakeInit::new(identity.signing_key(), &ephemeral_public, true, false);
        let encoded = init.to_bytes();
        let decoded = HandshakeInit::from_bytes(&encoded).expect("Decoding failed");

        assert_eq!(init.sender_pubkey, decoded.sender_pubkey);
        assert_eq!(init.ephemeral_x25519, decoded.ephemeral_x25519);
        assert!(decoded.is_seed());
        assert!(decoded.is_voter());
        assert!(!decoded.is_headless());
    }

    #[test]
    fn test_handshake_response_roundtrip() {
        let identity = NodeIdentity::generate(crate::crypto::identity::NodeRole::Voter);
        let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rand::thread_rng());
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

        let res = HandshakeResponse::new(identity.signing_key(), &ephemeral_public, true, true);
        let encoded = res.to_bytes();
        let decoded = HandshakeResponse::from_bytes(&encoded).expect("Decoding failed");

        assert_eq!(res.sender_pubkey, decoded.sender_pubkey);
        assert_eq!(res.ephemeral_x25519, decoded.ephemeral_x25519);
        assert!(decoded.is_seed());
        assert!(decoded.is_headless());
        assert!(!decoded.is_voter());
    }
}
