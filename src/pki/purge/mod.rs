use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::pki::ca::{compute_ca_id, CaDeclaration};
use crate::pki::cert::serial::CertificateSerialNumber;

/// Minimum and maximum allowable lengths for purged domain names
pub const MIN_DOMAIN_LENGTH: usize = 3;
pub const MAX_DOMAIN_LENGTH: usize = 253;

/// Baseline PoW difficulty in leading zero bits (fast for testing/CLI)
pub const BASE_POW_DIFFICULTY: u32 = 12;

/// Additional PoW difficulty in bits when purging unilaterally without external UTW strike evidence
pub const UNILATERAL_PURGE_PENALTY_BITS: u32 = 4;

/// Standard reason classification for issuing a bad-domain purge (CA-07)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PurgeReason {
    /// Domain exhibited verified untrustworthy / fraudulent behavior (UTW)
    UntrustworthyBehavior,
    /// Domain actively hosts malware, phishing, or malicious exploits
    MalwarePhishing,
    /// Private key material or hosting infrastructure for the domain was compromised
    KeyCompromise,
    /// Domain breached CA issuance terms or baseline cryptographic policies
    TermsViolation,
    /// Operator-specified custom justification
    Other(String),
}

/// Cryptographic and evidentiary payload supporting a domain purge
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainPurgeEvidence {
    pub reason: PurgeReason,
    pub description: String,
    pub strike_evidence: Option<String>,
    pub pow_nonce: u64,
}

/// Authoritative, cryptographically chained bad-domain purge record (CA-07)
///
/// Purges for a given CA form a tamper-evident linked chain:
/// - `purge_seq = 1` and `prev_purge_hash = [0; 32]` for genesis purge
/// - `purge_seq = N` and `prev_purge_hash = purge_{N-1}.purge_id` for subsequent purges
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainPurgeRecord {
    pub purge_id: [u8; 32],
    pub ca_id: [u8; 32],
    pub domain: String,
    pub serial_number: Option<CertificateSerialNumber>,
    pub purge_seq: u64,
    pub prev_purge_hash: [u8; 32],
    pub timestamp: u64,
    pub expires_at: u64,
    pub evidence: DomainPurgeEvidence,
    pub signature: Vec<u8>,
}

impl DomainPurgeRecord {
    /// Constructs, signs, and seals a new DomainPurgeRecord
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ca_id: [u8; 32],
        domain: String,
        serial_number: Option<CertificateSerialNumber>,
        purge_seq: u64,
        prev_purge_hash: [u8; 32],
        timestamp: u64,
        expires_at: u64,
        reason: PurgeReason,
        description: String,
        strike_evidence: Option<String>,
        pow_nonce: u64,
        signing_key: &SigningKey,
    ) -> Result<Self, String> {
        validate_domain_name(&domain)?;

        if timestamp >= expires_at {
            return Err(format!(
                "Invalid purge timestamp {}: must be strictly before expiration {}",
                timestamp, expires_at
            ));
        }

        if purge_seq == 0 {
            return Err("purge_seq must be >= 1 (1-based sequence)".to_string());
        }

        if purge_seq == 1 && prev_purge_hash != [0u8; 32] {
            return Err("Genesis purge (seq=1) must have prev_purge_hash = [0; 32]".to_string());
        }

        if description.trim().is_empty() {
            return Err("Purge description cannot be empty".to_string());
        }

        let evidence = DomainPurgeEvidence {
            reason,
            description,
            strike_evidence,
            pow_nonce,
        };

        // Data to sign: ca_id || domain || seq || prev_hash || timestamp || expires_at || nonce
        let sign_bytes = compute_sign_payload(
            &ca_id,
            &domain,
            purge_seq,
            &prev_purge_hash,
            timestamp,
            expires_at,
            evidence.pow_nonce,
        );

        let sig = signing_key.sign(&sign_bytes);
        let signature_bytes = sig.to_bytes().to_vec();

        let purge_id = compute_purge_id(
            &ca_id,
            &domain,
            purge_seq,
            &prev_purge_hash,
            timestamp,
            &signature_bytes,
        );

        Ok(Self {
            purge_id,
            ca_id,
            domain,
            serial_number,
            purge_seq,
            prev_purge_hash,
            timestamp,
            expires_at,
            evidence,
            signature: signature_bytes,
        })
    }

    /// Verifies the cryptographic signature of this purge record against a public key
    pub fn verify_signature(&self, pubkey_bytes: &[u8; 32]) -> Result<(), String> {
        let verifying_key = VerifyingKey::from_bytes(pubkey_bytes)
            .map_err(|e| format!("Invalid verifying key bytes: {}", e))?;

        if self.signature.len() != 64 {
            return Err(format!(
                "Invalid signature length: expected 64, got {}",
                self.signature.len()
            ));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&self.signature);
        let signature = Signature::from_bytes(&sig_arr);

        let sign_bytes = compute_sign_payload(
            &self.ca_id,
            &self.domain,
            self.purge_seq,
            &self.prev_purge_hash,
            self.timestamp,
            self.expires_at,
            self.evidence.pow_nonce,
        );

        verifying_key
            .verify(&sign_bytes, &signature)
            .map_err(|e| format!("Purge cryptographic signature verification failed: {}", e))?;

        let expected_id = compute_purge_id(
            &self.ca_id,
            &self.domain,
            self.purge_seq,
            &self.prev_purge_hash,
            self.timestamp,
            &self.signature,
        );

        if self.purge_id != expected_id {
            return Err("Purge ID does not match computed digest".to_string());
        }

        Ok(())
    }

    /// Validates this purge record against the issuing CA and the preceding purge in the CA's chain
    pub fn validate_against_ca_and_chain(
        &self,
        ca: &CaDeclaration,
        originator_pubkey: &[u8; 32],
        prev_purge: Option<&DomainPurgeRecord>,
        active_unexpired_purges_before: usize,
    ) -> Result<(), String> {
        if ca.is_draft {
            return Err(format!(
                "Cannot purge domain under draft CA `{}`",
                ca.subject.common_name
            ));
        }

        if self.ca_id != ca.ca_id {
            return Err(format!(
                "Purge record CA ID {:02x?} does not match target CA ID {:02x?}",
                &self.ca_id[..4],
                &ca.ca_id[..4]
            ));
        }

        // 1. Verify emitting node is the registered owner/custodian of the CA
        let expected_ca_id = compute_ca_id(&ca.subject.common_name, originator_pubkey);
        if ca.ca_id != expected_ca_id {
            return Err(
                "Emitting node public key does not match CA owner/custodian identity".to_string(),
            );
        }

        // 2. Validate domain format
        validate_domain_name(&self.domain)?;

        // 3. Subtree constraint check (CA-14)
        if !ca.is_domain_permitted(&self.domain) {
            return Err(format!(
                "Domain `{}` violates CA subtree name constraints (permitted_subtrees: {:?})",
                self.domain, ca.permitted_subtrees
            ));
        }

        // 4. Verify timestamp before expiry
        if self.timestamp >= self.expires_at {
            return Err(format!(
                "Purge timestamp {} is not strictly before expiration {}",
                self.timestamp, self.expires_at
            ));
        }

        // 5. Chain continuity verification
        match prev_purge {
            None => {
                if self.purge_seq != 1 {
                    return Err(format!(
                        "First purge for CA must have purge_seq = 1, found {}",
                        self.purge_seq
                    ));
                }
                if self.prev_purge_hash != [0u8; 32] {
                    return Err(
                        "First purge for CA must have prev_purge_hash = [0; 32]".to_string()
                    );
                }
            }
            Some(prev) => {
                if self.purge_seq != prev.purge_seq + 1 {
                    return Err(format!(
                        "Purge sequence discontinuity: expected seq {}, found {}",
                        prev.purge_seq + 1,
                        self.purge_seq
                    ));
                }
                if self.prev_purge_hash != prev.purge_id {
                    return Err(format!(
                        "Broken purge hash link: expected {:02x?}, found {:02x?}",
                        &prev.purge_id[..4],
                        &self.prev_purge_hash[..4]
                    ));
                }
                if self.timestamp < prev.timestamp {
                    return Err(format!(
                        "Non-monotonic timestamp: current {} < previous {}",
                        self.timestamp, prev.timestamp
                    ));
                }
            }
        }

        // 6. Verify cryptographic signature
        self.verify_signature(originator_pubkey)?;

        // 7. Verify dynamic logarithmic PoW difficulty
        let has_strike_evidence = self
            .evidence
            .strike_evidence
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        let required_difficulty =
            calculate_required_difficulty(active_unexpired_purges_before, has_strike_evidence);

        let challenge = compute_purge_challenge(
            &self.ca_id,
            &self.domain,
            self.timestamp,
            &self.prev_purge_hash,
            self.purge_seq,
        );

        if !verify_purge_pow(&challenge, self.evidence.pow_nonce, required_difficulty) {
            return Err(format!(
                "Insufficient PoW solution: required {} leading zero bits for challenge",
                required_difficulty
            ));
        }

        Ok(())
    }

    /// Returns true if this purge is currently active (unexpired) relative to `now`
    #[allow(dead_code)]
    pub fn is_active_at(&self, now: u64) -> bool {
        now < self.expires_at
    }
}

/// Validates RFC domain name syntax
pub fn validate_domain_name(domain: &str) -> Result<(), String> {
    let d = domain.trim();
    if d.len() < MIN_DOMAIN_LENGTH || d.len() > MAX_DOMAIN_LENGTH {
        return Err(format!(
            "Domain name length {} is outside valid range [{}, {}]",
            d.len(),
            MIN_DOMAIN_LENGTH,
            MAX_DOMAIN_LENGTH
        ));
    }

    if d.starts_with('.') || d.ends_with('.') {
        return Err("Domain name cannot start or end with a dot".to_string());
    }

    for label in d.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("Invalid domain label length: `{}`", label));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "Domain label cannot start or end with hyphen: `{}`",
                label
            ));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!("Domain contains invalid characters: `{}`", label));
        }
    }

    Ok(())
}

/// Computes the unique challenge hash for a purge request PoW puzzle
pub fn compute_purge_challenge(
    ca_id: &[u8; 32],
    domain: &str,
    timestamp: u64,
    prev_purge_hash: &[u8; 32],
    purge_seq: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"randbotd_v1_purge_challenge");
    hasher.update(ca_id);
    hasher.update(domain.as_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(prev_purge_hash);
    hasher.update(purge_seq.to_be_bytes());
    hasher.finalize().into()
}

/// Calculates required PoW difficulty in leading zero bits:
/// D = BASE_POW_DIFFICULTY + 2 * log2(active_unexpired_purges + 1) + (0 if strike_evidence else 4)
pub fn calculate_required_difficulty(
    active_unexpired_purges: usize,
    has_strike_evidence: bool,
) -> u32 {
    let n = (active_unexpired_purges + 1) as f64;
    let log2_n = n.log2().floor() as u32;
    let scaling = 2 * log2_n;
    let penalty = if has_strike_evidence {
        0
    } else {
        UNILATERAL_PURGE_PENALTY_BITS
    };

    BASE_POW_DIFFICULTY + scaling + penalty
}

/// Solves the PoW challenge by finding a nonce that achieves the required difficulty
pub fn solve_purge_pow(challenge: &[u8; 32], difficulty: u32) -> u64 {
    let mut nonce = 0u64;
    loop {
        if verify_purge_pow(challenge, nonce, difficulty) {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// Verifies whether `nonce` produces at least `difficulty` leading zero bits on `challenge`
pub fn verify_purge_pow(challenge: &[u8; 32], nonce: u64, difficulty: u32) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(nonce.to_be_bytes());
    let digest = hasher.finalize();

    leading_zero_bits(&digest) >= difficulty
}

/// Counts the number of leading zero bits in a 256-bit digest
fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in digest {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

fn compute_sign_payload(
    ca_id: &[u8; 32],
    domain: &str,
    purge_seq: u64,
    prev_purge_hash: &[u8; 32],
    timestamp: u64,
    expires_at: u64,
    pow_nonce: u64,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"randbotd_v1_domain_purge");
    bytes.extend_from_slice(ca_id);
    bytes.extend_from_slice(domain.as_bytes());
    bytes.extend_from_slice(&purge_seq.to_be_bytes());
    bytes.extend_from_slice(prev_purge_hash);
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&expires_at.to_be_bytes());
    bytes.extend_from_slice(&pow_nonce.to_be_bytes());
    bytes
}

fn compute_purge_id(
    ca_id: &[u8; 32],
    domain: &str,
    purge_seq: u64,
    prev_purge_hash: &[u8; 32],
    timestamp: u64,
    signature: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"randbotd_v1_purge_id");
    hasher.update(ca_id);
    hasher.update(domain.as_bytes());
    hasher.update(purge_seq.to_be_bytes());
    hasher.update(prev_purge_hash);
    hasher.update(timestamp.to_be_bytes());
    hasher.update(signature);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests;
