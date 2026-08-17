//! HTTP Nonce proofing, DNS TXT parsing, and proof response helper module

use crate::config::DaemonConfig;
use crate::crypto::identity::NodeIdentity;
use crate::proof::dns::resolve_hns_ip;
use crate::proof::engine::{
    DomainNetworkType, DomainProofChallenge, DomainProofMethod, ProofError,
};

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

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

/// Active HTTP GET Nonce fetcher (Tor SOCKS5 / I2P HTTP Proxy / Handshake IP resolution / Clearnet)
pub fn fetch_http_nonce(
    domain: &str,
    net_type: DomainNetworkType,
    config: &DaemonConfig,
) -> Result<String, String> {
    if net_type == DomainNetworkType::Handshake {
        if let Ok(ip) = resolve_hns_ip(domain, config) {
            let url = format!("http://{}/.well-known/randbotd-proof", ip);
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .map_err(|e| e.to_string())?;
            let resp = client
                .get(&url)
                .header("Host", domain)
                .send()
                .map_err(|e| format!("HTTP GET {} via HNS IP failed: {}", url, e))?;
            if resp.status().is_success() {
                return resp
                    .text()
                    .map_err(|e| format!("Failed to read HTTP body: {}", e));
            }
        }
    }

    let url = format!("http://{}/.well-known/randbotd-proof", domain);
    let mut builder =
        reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(5));

    match net_type {
        DomainNetworkType::Tor => {
            let proxy_addr = config
                .privacy
                .tor_socks_proxy
                .as_deref()
                .unwrap_or("127.0.0.1:9050");
            let proxy = reqwest::Proxy::all(format!("socks5h://{}", proxy_addr))
                .map_err(|e| format!("Tor proxy error: {}", e))?;
            builder = builder.proxy(proxy);
        }
        DomainNetworkType::I2P => {
            let proxy_port = config.privacy.i2p_proxy_port.unwrap_or(4444);
            let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{}", proxy_port))
                .map_err(|e| format!("I2P proxy error: {}", e))?;
            builder = builder.proxy(proxy);
        }
        _ => {}
    }

    let client = builder.build().map_err(|e| e.to_string())?;
    let resp = client
        .get(&url)
        .send()
        .map_err(|e| format!("HTTP GET {} failed: {}", url, e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "HTTP GET {} returned status {}",
            url,
            resp.status()
        ));
    }
    resp.text()
        .map_err(|e| format!("Failed to read HTTP body: {}", e))
}

pub fn parse_dns_txt_record(
    txt_val: &str,
    challenge: &DomainProofChallenge,
) -> Result<DomainProofResponse, ProofError> {
    let clean = txt_val.trim();
    let payload = clean.strip_prefix("randbotd-proof=").ok_or_else(|| {
        ProofError::InvalidSignature("DNS TXT record missing `randbotd-proof=` prefix".to_string())
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
    proof_method: DomainProofMethod,
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
        proof_method,
    };

    response.verify_signature(challenge)?;
    Ok(response)
}
