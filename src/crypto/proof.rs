//! CA-03 Multi-Network Domain Proofs Engine
//! Exposes domain proof classification, challenges, Ed25519 signature verification,
//! active REAL DNS network resolution (Upstream Clearnet -> Handshake daemon -> Error),
//! HTTP Nonce fetching (Tor/I2P proxy), and network capability routing.

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::DaemonConfig;
use crate::crypto::identity::NodeIdentity;
use crate::crypto::proof_net::{
    check_dns_resolves, fetch_http_nonce, parse_dns_txt_record, parse_http_nonce_json,
    send_udp_dns_txt_query,
};

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
            DomainNetworkType::Clearnet => "Clearnet (ICANN Upstream DNS)",
            DomainNetworkType::Handshake => "Handshake (Arbitrary Root TLDs)",
            DomainNetworkType::Tor => "Tor Hidden Service (.onion)",
            DomainNetworkType::I2P => "I2P Eepsite (.i2p)",
        }
    }

    pub fn resolve_network_type(domain: &str, config: &DaemonConfig) -> Result<Self, ProofError> {
        let clean = domain.trim().to_lowercase();
        if clean.ends_with(".onion") {
            return Ok(DomainNetworkType::Tor);
        }
        if clean.ends_with(".i2p") {
            return Ok(DomainNetworkType::I2P);
        }

        let upstream_resolver = config
            .handshake
            .upstream_dns_resolver
            .as_deref()
            .unwrap_or("9.9.9.9:53");

        if check_dns_resolves(&clean, upstream_resolver) {
            return Ok(DomainNetworkType::Clearnet);
        }

        if config.has_hns_support() {
            let hns_port = config.handshake.hns_dns_port.unwrap_or(53493);
            let hns_addr = format!("127.0.0.1:{}", hns_port);
            if check_dns_resolves(&clean, &hns_addr) {
                return Ok(DomainNetworkType::Handshake);
            }
        }

        Err(ProofError::UnresolvableDomain(format!(
            "Domain `{}` could not be resolved on Upstream Clearnet DNS ({}) nor Handshake DNS daemon. Domain is unresolvable or unsupported.",
            clean, upstream_resolver
        )))
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

/// Multi-network domain proof verifier & active resolver manager
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
        parse_dns_txt_record(txt_val, challenge)
    }

    pub fn parse_http_nonce_json(
        json_str: &str,
        challenge: &DomainProofChallenge,
    ) -> Result<DomainProofResponse, ProofError> {
        parse_http_nonce_json(json_str, challenge)
    }

    /// Performs active live network resolution and domain proof verification:
    /// 1. `.onion` => Tor SOCKS proxy HTTP Nonce
    /// 2. `.i2p` => I2P HTTP proxy HTTP Nonce
    /// 3. Checks Upstream Clearnet DNS (Quad9 9.9.9.9:53) FOR REAL -> Clearnet
    /// 4. Checks Handshake DNS daemon (127.0.0.1:53493) FOR REAL -> Handshake
    /// 5. Tries HTTP Nonce Fallback
    /// 6. If all fail => Returns ProofError::UnresolvableDomain
    pub fn verify_active_domain_control(
        challenge: &DomainProofChallenge,
        config: &DaemonConfig,
    ) -> Result<DomainProofResponse, ProofError> {
        let domain = &challenge.domain;

        let detected_net = DomainNetworkType::resolve_network_type(domain, config)?;

        Self::check_backend_capability(detected_net, config)?;

        match detected_net {
            DomainNetworkType::Tor => fetch_http_nonce(domain, DomainNetworkType::Tor, config)
                .map_err(ProofError::UnresolvableDomain)
                .and_then(|json| Self::parse_http_nonce_json(&json, challenge)),
            DomainNetworkType::I2P => fetch_http_nonce(domain, DomainNetworkType::I2P, config)
                .map_err(ProofError::UnresolvableDomain)
                .and_then(|json| Self::parse_http_nonce_json(&json, challenge)),
            DomainNetworkType::Clearnet => {
                let upstream_resolver = config
                    .handshake
                    .upstream_dns_resolver
                    .as_deref()
                    .unwrap_or("9.9.9.9:53");
                if let Ok(records) = send_udp_dns_txt_query(domain, upstream_resolver) {
                    for rec in records {
                        if rec.contains("randbotd-proof=") {
                            if let Ok(resp) = Self::parse_dns_txt_record(&rec, challenge) {
                                return Ok(resp);
                            }
                        }
                    }
                }

                fetch_http_nonce(domain, DomainNetworkType::Clearnet, config)
                    .map_err(ProofError::UnresolvableDomain)
                    .and_then(|json| Self::parse_http_nonce_json(&json, challenge))
            }
            DomainNetworkType::Handshake => {
                let hns_port = config.handshake.hns_dns_port.unwrap_or(53493);
                let hns_addr = format!("127.0.0.1:{}", hns_port);
                if let Ok(records) = send_udp_dns_txt_query(domain, &hns_addr) {
                    for rec in records {
                        if rec.contains("randbotd-proof=") {
                            if let Ok(resp) = Self::parse_dns_txt_record(&rec, challenge) {
                                return Ok(resp);
                            }
                        }
                    }
                }

                fetch_http_nonce(domain, DomainNetworkType::Handshake, config)
                    .map_err(ProofError::UnresolvableDomain)
                    .and_then(|json| Self::parse_http_nonce_json(&json, challenge))
            }
        }
    }

    pub fn fail_unresolvable_domain(domain: &str, details: &str) -> ProofError {
        ProofError::UnresolvableDomain(format!(
            "Failed to resolve domain `{}` across Upstream Clearnet DNS, Handshake DNS, and HTTP fallback: {}",
            domain, details
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::{NodeIdentity, NodeRole};

    #[test]
    fn test_domain_network_type_resolution() {
        let cfg = DaemonConfig::default();
        assert_eq!(
            DomainNetworkType::resolve_network_type("example.onion", &cfg).unwrap(),
            DomainNetworkType::Tor
        );
        assert_eq!(
            DomainNetworkType::resolve_network_type("site.i2p", &cfg).unwrap(),
            DomainNetworkType::I2P
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
        let err = DomainProofVerifier::fail_unresolvable_domain("nonexistent.randºm", "NXDOMAIN");
        assert!(matches!(err, ProofError::UnresolvableDomain(_)));
        assert!(err.to_string().contains("nonexistent.randºm"));
    }

    #[test]
    fn test_http_nonce_json_parsing_and_verification() {
        let identity = NodeIdentity::from_seed_and_role(&[2u8; 32], NodeRole::Voter);
        let challenge =
            DomainProofChallenge::new("mreugenej7.randºm", DomainNetworkType::Clearnet, 900);
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

        assert!(DomainProofVerifier::parse_http_nonce_json(&json_payload, &challenge).is_ok());
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
