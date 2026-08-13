//! CA-03 Multi-Network Domain Proofs Engine
//! Exposes domain proof classification, challenges, Ed25519 signature verification,
//! DNS TXT / HTTP Nonce verifiers, and network capability routing for ACME integration.

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::DaemonConfig;
use crate::crypto::identity::NodeIdentity;

/// Supported domain network ecosystems in randbotd
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DomainNetworkType {
    Clearnet,
    Handshake,
    Tor,
    I2P,
}

impl DomainNetworkType {
    pub fn name(&self) -> &'static str {
        match self {
            DomainNetworkType::Clearnet => "Clearnet (ICANN DNS)",
            DomainNetworkType::Handshake => "Handshake (.hns / Custom HNS Root TLD)",
            DomainNetworkType::Tor => "Tor Hidden Service (.onion)",
            DomainNetworkType::I2P => "I2P Eepsite (.i2p)",
        }
    }

    /// Classifies domain network by TLD suffix
    pub fn classify_domain(domain: &str) -> Self {
        let clean = domain.trim().to_lowercase();
        if clean.ends_with(".onion") {
            DomainNetworkType::Tor
        } else if clean.ends_with(".i2p") {
            DomainNetworkType::I2P
        } else if clean.ends_with(".hns") {
            DomainNetworkType::Handshake
        } else {
            DomainNetworkType::Clearnet
        }
    }
}

impl fmt::Display for DomainNetworkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Verification proof methods for domain control
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DomainProofMethod {
    DnsTxt,
    HttpNonceFallback,
}

/// Domain proof verification errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    UnresolvableDomain(String),
    BackendUnreachable(String),
    InvalidSignature(String),
    ExpiredChallenge(String),
    ConfigMismatch(String),
    NetworkMismatch(String),
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofError::UnresolvableDomain(e) => write!(f, "Unresolvable domain error: {}", e),
            ProofError::BackendUnreachable(e) => write!(f, "Backend proxy unreachable: {}", e),
            ProofError::InvalidSignature(e) => write!(f, "Invalid proof signature: {}", e),
            ProofError::ExpiredChallenge(e) => write!(f, "Expired challenge: {}", e),
            ProofError::ConfigMismatch(e) => write!(f, "Configuration mismatch: {}", e),
            ProofError::NetworkMismatch(e) => write!(f, "Network capability mismatch: {}", e),
        }
    }
}

impl std::error::Error for ProofError {}

/// Domain verification challenge payload issued by CA or verification engine
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainProofChallenge {
    pub challenge_id: String,
    pub domain: String,
    pub network_type: DomainNetworkType,
    pub nonce: [u8; 32],
    pub timestamp: u64,
    pub expires_at: u64,
    pub retry_count: u32,
    pub max_retries: u32,
}

impl DomainProofChallenge {
    /// Creates a new domain proof challenge with custom TTL (seconds)
    pub fn new(domain: &str, network_type: DomainNetworkType, ttl_seconds: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut nonce = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(domain.as_bytes());
        hasher.update(now.to_le_bytes());
        hasher.update(rand::random::<[u8; 32]>());
        nonce.copy_from_slice(&hasher.finalize());

        let challenge_id = hex::encode(&nonce[..16]);

        Self {
            challenge_id,
            domain: domain.trim().to_lowercase(),
            network_type,
            nonce,
            timestamp: now,
            expires_at: now + ttl_seconds,
            retry_count: 0,
            max_retries: 5,
        }
    }

    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time >= self.expires_at
    }

    pub fn validate_active(&self, current_time: u64) -> Result<(), ProofError> {
        if self.is_expired(current_time) {
            Err(ProofError::ExpiredChallenge(format!(
                "Challenge `{}` for domain `{}` expired at timestamp {}",
                self.challenge_id, self.domain, self.expires_at
            )))
        } else {
            Ok(())
        }
    }

    pub fn next_retry_delay_seconds(&self) -> u64 {
        15 * 2u64.pow(self.retry_count.min(6))
    }

    pub fn construct_signing_bytes(&self) -> Vec<u8> {
        format!("randbotd-proof:{}:{}", self.domain, hex::encode(self.nonce)).into_bytes()
    }
}

/// Signed response payload proving domain control
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainProofResponse {
    pub challenge_id: String,
    pub domain: String,
    pub node_pubkey: [u8; 32],
    pub signature: Vec<u8>,
    pub proof_method: DomainProofMethod,
}

impl DomainProofResponse {
    pub fn create_signed(
        challenge: &DomainProofChallenge,
        node_identity: &NodeIdentity,
        proof_method: DomainProofMethod,
    ) -> Self {
        let message_bytes = challenge.construct_signing_bytes();
        let sig = node_identity.signing_key().sign(&message_bytes);

        Self {
            challenge_id: challenge.challenge_id.clone(),
            domain: challenge.domain.clone(),
            node_pubkey: node_identity.verifying_key().to_bytes(),
            signature: sig.to_bytes().to_vec(),
            proof_method,
        }
    }

    pub fn to_dns_txt_record(&self, nonce: &[u8; 32]) -> String {
        format!(
            "randbotd-proof={}:{}:{}",
            hex::encode(nonce),
            hex::encode(self.node_pubkey),
            hex::encode(&self.signature)
        )
    }

    pub fn verify_signature(&self, challenge: &DomainProofChallenge) -> Result<(), ProofError> {
        if self.domain.to_lowercase() != challenge.domain.to_lowercase() {
            return Err(ProofError::ConfigMismatch(format!(
                "Domain in response `{}` does not match challenge domain `{}`",
                self.domain, challenge.domain
            )));
        }

        if self.challenge_id != challenge.challenge_id {
            return Err(ProofError::ConfigMismatch(format!(
                "Challenge ID mismatch: `{}` vs `{}`",
                self.challenge_id, challenge.challenge_id
            )));
        }

        if self.signature.len() != 64 {
            return Err(ProofError::InvalidSignature(format!(
                "Signature length {} invalid (expected 64 bytes)",
                self.signature.len()
            )));
        }

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&self.signature);

        let message_bytes = challenge.construct_signing_bytes();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&self.node_pubkey)
            .map_err(|e| ProofError::InvalidSignature(format!("Invalid Ed25519 pubkey: {}", e)))?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

        verifying_key
            .verify_strict(&message_bytes, &signature)
            .map_err(|e| {
                ProofError::InvalidSignature(format!("Signature verification failed: {}", e))
            })
    }
}

/// Multi-network domain proof verifier & backend capability manager
pub struct DomainProofVerifier;

impl DomainProofVerifier {
    pub fn check_backend_capability(
        network_type: DomainNetworkType,
        config: &DaemonConfig,
    ) -> Result<(), ProofError> {
        match network_type {
            DomainNetworkType::Clearnet => Ok(()),
            DomainNetworkType::Handshake => {
                if config.has_hns_support() {
                    Ok(())
                } else {
                    Err(ProofError::NetworkMismatch(
                        "Handshake DNS resolution is not configured (hns_dns_mode = 'none')"
                            .to_string(),
                    ))
                }
            }
            DomainNetworkType::Tor => {
                if config.has_tor_support() {
                    Ok(())
                } else {
                    Err(ProofError::BackendUnreachable(
                        "Tor SOCKS proxy (127.0.0.1:9050) is not configured".to_string(),
                    ))
                }
            }
            DomainNetworkType::I2P => {
                if config.has_i2p_support() {
                    Ok(())
                } else {
                    Err(ProofError::BackendUnreachable(
                        "I2P proxy port (7656) is not configured".to_string(),
                    ))
                }
            }
        }
    }

    pub fn parse_dns_txt_record(
        txt_val: &str,
        challenge: &DomainProofChallenge,
    ) -> Result<DomainProofResponse, ProofError> {
        let clean = txt_val.trim();
        let payload = clean.strip_prefix("randbotd-proof=").ok_or_else(|| {
            ProofError::InvalidSignature(
                "DNS TXT record missing `randbotd-proof=` prefix".to_string(),
            )
        })?;

        let parts: Vec<&str> = payload.split(':').collect();
        if parts.len() != 3 {
            return Err(ProofError::InvalidSignature(
                "DNS TXT payload must contain 3 colon-separated fields".to_string(),
            ));
        }

        let nonce_bytes = hex::decode(parts[0])
            .map_err(|e| ProofError::InvalidSignature(format!("Invalid nonce hex: {}", e)))?;
        if nonce_bytes != challenge.nonce {
            return Err(ProofError::InvalidSignature(
                "Nonce does not match challenge".to_string(),
            ));
        }

        let pubkey_bytes = hex::decode(parts[1])
            .map_err(|e| ProofError::InvalidSignature(format!("Invalid pubkey hex: {}", e)))?;
        if pubkey_bytes.len() != 32 {
            return Err(ProofError::InvalidSignature(
                "Ed25519 pubkey length must be 32 bytes".to_string(),
            ));
        }

        let sig_bytes = hex::decode(parts[2])
            .map_err(|e| ProofError::InvalidSignature(format!("Invalid signature hex: {}", e)))?;
        if sig_bytes.len() != 64 {
            return Err(ProofError::InvalidSignature(
                "Ed25519 signature length must be 64 bytes".to_string(),
            ));
        }

        let mut node_pubkey = [0u8; 32];
        node_pubkey.copy_from_slice(&pubkey_bytes);

        let response = DomainProofResponse {
            challenge_id: challenge.challenge_id.clone(),
            domain: challenge.domain.clone(),
            node_pubkey,
            signature: sig_bytes,
            proof_method: DomainProofMethod::DnsTxt,
        };

        response.verify_signature(challenge)?;
        Ok(response)
    }

    pub fn parse_http_nonce_json(
        json_str: &str,
        challenge: &DomainProofChallenge,
    ) -> Result<DomainProofResponse, ProofError> {
        #[derive(Deserialize)]
        struct HttpProofPayload {
            challenge_id: String,
            domain: String,
            node_pubkey: String,
            signature: String,
        }

        let payload: HttpProofPayload = serde_json::from_str(json_str).map_err(|e| {
            ProofError::InvalidSignature(format!("Invalid HTTP Nonce JSON payload: {}", e))
        })?;

        let pubkey_bytes = hex::decode(&payload.node_pubkey)
            .map_err(|e| ProofError::InvalidSignature(format!("Invalid node_pubkey hex: {}", e)))?;
        if pubkey_bytes.len() != 32 {
            return Err(ProofError::InvalidSignature(
                "Ed25519 pubkey length must be 32 bytes".to_string(),
            ));
        }

        let sig_bytes = hex::decode(&payload.signature)
            .map_err(|e| ProofError::InvalidSignature(format!("Invalid signature hex: {}", e)))?;
        if sig_bytes.len() != 64 {
            return Err(ProofError::InvalidSignature(
                "Ed25519 signature length must be 64 bytes".to_string(),
            ));
        }

        let mut node_pubkey = [0u8; 32];
        node_pubkey.copy_from_slice(&pubkey_bytes);

        let response = DomainProofResponse {
            challenge_id: payload.challenge_id,
            domain: payload.domain,
            node_pubkey,
            signature: sig_bytes,
            proof_method: DomainProofMethod::HttpNonceFallback,
        };

        response.verify_signature(challenge)?;
        Ok(response)
    }

    pub fn fail_unresolvable_domain(domain: &str, details: &str) -> ProofError {
        ProofError::UnresolvableDomain(format!(
            "Failed to resolve domain `{}` across DNS, Handshake, and HTTP fallback: {}",
            domain, details
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::{NodeIdentity, NodeRole};

    #[test]
    fn test_domain_network_type_classification() {
        assert_eq!(
            DomainNetworkType::classify_domain("example.onion"),
            DomainNetworkType::Tor
        );
        assert_eq!(
            DomainNetworkType::classify_domain("site.i2p"),
            DomainNetworkType::I2P
        );
        assert_eq!(
            DomainNetworkType::classify_domain("crypto.hns"),
            DomainNetworkType::Handshake
        );
        assert_eq!(
            DomainNetworkType::classify_domain("therandomconsortium.org"),
            DomainNetworkType::Clearnet
        );
    }

    #[test]
    fn test_domain_proof_challenge_creation_and_signing() {
        let seed = [1u8; 32];
        let identity = NodeIdentity::from_seed_and_role(&seed, NodeRole::Voter);
        let challenge =
            DomainProofChallenge::new("therandomconsortium.org", DomainNetworkType::Clearnet, 900);

        assert!(!challenge.is_expired(challenge.timestamp + 100));
        assert!(challenge.is_expired(challenge.timestamp + 1000));
        assert!(challenge.validate_active(challenge.timestamp + 100).is_ok());

        let expired_err = challenge.validate_active(challenge.timestamp + 1000);
        assert!(expired_err.is_err());
        assert!(matches!(
            expired_err.unwrap_err(),
            ProofError::ExpiredChallenge(_)
        ));

        assert_eq!(challenge.next_retry_delay_seconds(), 15);

        let response =
            DomainProofResponse::create_signed(&challenge, &identity, DomainProofMethod::DnsTxt);
        assert!(response.verify_signature(&challenge).is_ok());

        let txt_record = response.to_dns_txt_record(&challenge.nonce);
        let parsed = DomainProofVerifier::parse_dns_txt_record(&txt_record, &challenge);
        assert!(parsed.is_ok());
        assert_eq!(
            parsed.unwrap().node_pubkey,
            identity.verifying_key().to_bytes()
        );
    }

    #[test]
    fn test_proof_error_unresolvable_domain_construction() {
        let err =
            DomainProofVerifier::fail_unresolvable_domain("nonexistent.hns", "NXDOMAIN from hnsd");
        assert!(matches!(err, ProofError::UnresolvableDomain(_)));
        assert!(err.to_string().contains("nonexistent.hns"));
    }

    #[test]
    fn test_http_nonce_json_parsing_and_verification() {
        let seed = [2u8; 32];
        let identity = NodeIdentity::from_seed_and_role(&seed, NodeRole::Voter);
        let challenge = DomainProofChallenge::new("myname.hns", DomainNetworkType::Handshake, 900);
        let response = DomainProofResponse::create_signed(
            &challenge,
            &identity,
            DomainProofMethod::HttpNonceFallback,
        );

        let json_payload = serde_json::json!({
            "challenge_id": response.challenge_id,
            "domain": response.domain,
            "node_pubkey": hex::encode(response.node_pubkey),
            "signature": hex::encode(&response.signature),
        })
        .to_string();

        let parsed = DomainProofVerifier::parse_http_nonce_json(&json_payload, &challenge);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_check_backend_capability() {
        let mut config = DaemonConfig::default();
        assert!(DomainProofVerifier::check_backend_capability(
            DomainNetworkType::Clearnet,
            &config
        )
        .is_ok());
        assert!(
            DomainProofVerifier::check_backend_capability(DomainNetworkType::Tor, &config).is_err()
        );
        assert!(
            DomainProofVerifier::check_backend_capability(DomainNetworkType::I2P, &config).is_err()
        );

        config.privacy.tor_socks_proxy = Some("127.0.0.1:9050".to_string());
        assert!(
            DomainProofVerifier::check_backend_capability(DomainNetworkType::Tor, &config).is_ok()
        );
    }
}
