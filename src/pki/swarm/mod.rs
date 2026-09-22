use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::agility::KeyAlgorithm;

pub mod mock_cert;
pub use mock_cert::{build_mock_capability_certificate, verify_mock_capability_certificate};

/// Blind local CA custodian acceptance policy (kept private on CA node)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaCustodianPolicy {
    pub max_work_share_pct: u8,
    pub min_ttl_seconds: u64,
    pub target_swarm_size: usize,
    pub auto_accept: bool,
}

impl Default for CaCustodianPolicy {
    fn default() -> Self {
        Self {
            max_work_share_pct: 30,
            min_ttl_seconds: 86400,
            target_swarm_size: 5,
            auto_accept: true,
        }
    }
}

/// Step 1: Candidate Worker publishes signed delegation contract
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustodianContract {
    pub ca_id: [u8; 32],
    pub worker_pubkey: [u8; 32],
    pub work_share_pct: u8,
    pub created_at: u64,
    pub valid_until: u64,
    pub tcp_endpoint: String,
    pub signature: Vec<u8>,
}

impl CustodianContract {
    pub fn new(
        ca_id: [u8; 32],
        signing_key: &SigningKey,
        work_share_pct: u8,
        created_at: u64,
        valid_until: u64,
        tcp_endpoint: String,
    ) -> Result<Self, String> {
        if work_share_pct > 100 {
            return Err("work_share_pct cannot exceed 100%".to_string());
        }
        if valid_until <= created_at {
            return Err("valid_until must be strictly greater than created_at".to_string());
        }
        if tcp_endpoint.trim().is_empty() {
            return Err("tcp_endpoint cannot be empty".to_string());
        }

        let worker_pubkey = signing_key.verifying_key().to_bytes();
        let mut contract = Self {
            ca_id,
            worker_pubkey,
            work_share_pct,
            created_at,
            valid_until,
            tcp_endpoint,
            signature: Vec::new(),
        };

        let canon = contract.canonical_bytes();
        let sig = signing_key.sign(&canon);
        contract.signature = sig.to_bytes().to_vec();
        Ok(contract)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"randbotd_custodian_contract_v1:");
        buf.extend_from_slice(&self.ca_id);
        buf.extend_from_slice(&self.worker_pubkey);
        buf.push(self.work_share_pct);
        buf.extend_from_slice(&self.created_at.to_be_bytes());
        buf.extend_from_slice(&self.valid_until.to_be_bytes());
        buf.extend_from_slice(self.tcp_endpoint.as_bytes());
        buf
    }

    pub fn contract_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes());
        hasher.update(&self.signature);
        hasher.finalize().into()
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        let vk = VerifyingKey::from_bytes(&self.worker_pubkey)
            .map_err(|e| format!("Invalid worker public key: {}", e))?;
        let sig_arr: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "Signature must be 64 bytes".to_string())?;
        let sig = Signature::from_bytes(&sig_arr);
        let canon = self.canonical_bytes();
        vk.verify(&canon, &sig)
            .map_err(|e| format!("Invalid CustodianContract signature: {}", e))
    }

    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.valid_until
    }
}

/// Step 2: CA confirms terms and challenges worker with target catalog offer
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustodianDelegationRequest {
    pub ca_id: [u8; 32],
    pub worker_pubkey: [u8; 32],
    pub contract_hash: [u8; 32],
    pub challenge_nonce: u64,
    pub target_offer_id: u32,
    pub signature: Vec<u8>,
}

impl CustodianDelegationRequest {
    pub fn new(
        ca_id: [u8; 32],
        worker_pubkey: [u8; 32],
        contract_hash: [u8; 32],
        challenge_nonce: u64,
        target_offer_id: u32,
        ca_signing_key: &SigningKey,
    ) -> Self {
        let mut req = Self {
            ca_id,
            worker_pubkey,
            contract_hash,
            challenge_nonce,
            target_offer_id,
            signature: Vec::new(),
        };
        let canon = req.canonical_bytes();
        let sig = ca_signing_key.sign(&canon);
        req.signature = sig.to_bytes().to_vec();
        req
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"randbotd_custodian_delegation_req_v1:");
        buf.extend_from_slice(&self.ca_id);
        buf.extend_from_slice(&self.worker_pubkey);
        buf.extend_from_slice(&self.contract_hash);
        buf.extend_from_slice(&self.challenge_nonce.to_be_bytes());
        buf.extend_from_slice(&self.target_offer_id.to_be_bytes());
        buf
    }

    pub fn verify_signature(&self, ca_pubkey: &[u8; 32]) -> Result<(), String> {
        let vk = VerifyingKey::from_bytes(ca_pubkey)
            .map_err(|e| format!("Invalid CA public key: {}", e))?;
        let sig_arr: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "Signature must be 64 bytes".to_string())?;
        let sig = Signature::from_bytes(&sig_arr);
        let canon = self.canonical_bytes();
        vk.verify(&canon, &sig)
            .map_err(|e| format!("Invalid CustodianDelegationRequest signature: {}", e))
    }
}

/// Step 3: Worker proves capability by building dummy cert and publishing hash commitment on UDP
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CACapabilitiesProof {
    pub ca_id: [u8; 32],
    pub worker_pubkey: [u8; 32],
    pub contract_hash: [u8; 32],
    pub mock_cert_hash: [u8; 32],
    pub algorithm: KeyAlgorithm,
    pub cert_len: u32,
    pub signature: Vec<u8>,
}

impl CACapabilitiesProof {
    pub fn new(
        ca_id: [u8; 32],
        worker_signing_key: &SigningKey,
        contract_hash: [u8; 32],
        mock_cert_hash: [u8; 32],
        algorithm: KeyAlgorithm,
        cert_len: u32,
    ) -> Self {
        let worker_pubkey = worker_signing_key.verifying_key().to_bytes();
        let mut proof = Self {
            ca_id,
            worker_pubkey,
            contract_hash,
            mock_cert_hash,
            algorithm,
            cert_len,
            signature: Vec::new(),
        };
        let canon = proof.canonical_bytes();
        let sig = worker_signing_key.sign(&canon);
        proof.signature = sig.to_bytes().to_vec();
        proof
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"randbotd_ca_capabilities_proof_v1:");
        buf.extend_from_slice(&self.ca_id);
        buf.extend_from_slice(&self.worker_pubkey);
        buf.extend_from_slice(&self.contract_hash);
        buf.extend_from_slice(&self.mock_cert_hash);
        buf.extend_from_slice(self.algorithm.oid().as_bytes());
        buf.extend_from_slice(&self.cert_len.to_be_bytes());
        buf
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        let vk = VerifyingKey::from_bytes(&self.worker_pubkey)
            .map_err(|e| format!("Invalid worker public key: {}", e))?;
        let sig_arr: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "Signature must be 64 bytes".to_string())?;
        let sig = Signature::from_bytes(&sig_arr);
        let canon = self.canonical_bytes();
        vk.verify(&canon, &sig)
            .map_err(|e| format!("Invalid CACapabilitiesProof signature: {}", e))
    }
}

/// Step 4: CA emits final swarm activation confirmation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwarmActivationConfirmation {
    pub ca_id: [u8; 32],
    pub worker_pubkey: [u8; 32],
    pub contract_hash: [u8; 32],
    pub mock_cert_hash: [u8; 32],
    pub activated_at: u64,
    pub signature: Vec<u8>,
}

impl SwarmActivationConfirmation {
    pub fn new(
        ca_id: [u8; 32],
        worker_pubkey: [u8; 32],
        contract_hash: [u8; 32],
        mock_cert_hash: [u8; 32],
        activated_at: u64,
        ca_signing_key: &SigningKey,
    ) -> Self {
        let mut conf = Self {
            ca_id,
            worker_pubkey,
            contract_hash,
            mock_cert_hash,
            activated_at,
            signature: Vec::new(),
        };
        let canon = conf.canonical_bytes();
        let sig = ca_signing_key.sign(&canon);
        conf.signature = sig.to_bytes().to_vec();
        conf
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"randbotd_swarm_activation_v1:");
        buf.extend_from_slice(&self.ca_id);
        buf.extend_from_slice(&self.worker_pubkey);
        buf.extend_from_slice(&self.contract_hash);
        buf.extend_from_slice(&self.mock_cert_hash);
        buf.extend_from_slice(&self.activated_at.to_be_bytes());
        buf
    }

    pub fn verify_signature(&self, ca_pubkey: &[u8; 32]) -> Result<(), String> {
        let vk = VerifyingKey::from_bytes(ca_pubkey)
            .map_err(|e| format!("Invalid CA public key: {}", e))?;
        let sig_arr: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "Signature must be 64 bytes".to_string())?;
        let sig = Signature::from_bytes(&sig_arr);
        let canon = self.canonical_bytes();
        vk.verify(&canon, &sig)
            .map_err(|e| format!("Invalid SwarmActivationConfirmation signature: {}", e))
    }

    /// Enforces consensus validity: contract hash matching, signature validity,
    /// and that the activation timestamp did not exceed the worker's declared valid_until.
    pub fn verify_against_contract(
        &self,
        contract: &CustodianContract,
        ca_pubkey: &[u8; 32],
    ) -> Result<(), String> {
        if self.ca_id != contract.ca_id {
            return Err("Confirmation ca_id does not match contract ca_id".to_string());
        }
        if self.worker_pubkey != contract.worker_pubkey {
            return Err("Confirmation worker_pubkey does not match contract".to_string());
        }
        if self.contract_hash != contract.contract_hash() {
            return Err("Confirmation contract_hash does not match contract hash".to_string());
        }
        if self.activated_at > contract.valid_until {
            return Err(format!(
                "Consensus violation: contract expired at {} but activation occurred at {}",
                contract.valid_until, self.activated_at
            ));
        }
        self.verify_signature(ca_pubkey)
    }
}

/// Aggregated database representation of an active swarm custodian
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustodianSwarmRecord {
    pub ca_id: [u8; 32],
    pub worker_pubkey: [u8; 32],
    pub work_share_pct: u8,
    pub tcp_endpoint: String,
    pub activated_at: u64,
    pub contract_hash: [u8; 32],
    pub mock_cert_hash: [u8; 32],
}

#[cfg(test)]
mod tests;
