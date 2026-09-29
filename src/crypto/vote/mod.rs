//! Dynamic Domain Reputation Voting Engine (REP-02)
//!
//! Enforces 1 active vote per node per domain with real-time mind-changing support,
//! monotonic per-originator sequence chaining, and logarithmic Proof-of-Work difficulty scaling.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::pow::{PowEngine, DEFAULT_BASE_DIFFICULTY};
use crate::pki::purge::validate_domain_name;

/// Rolling window for active votes (1 year in seconds) anchored in previous resolved event
pub const ACTIVE_VOTES_ROLLING_WINDOW_SECS: u64 = 365 * 86_400;

/// Maximum computable difficulty for SHA-256 (256 bits)
pub const MAX_COMPUTABLE_DIFFICULTY: u32 = 255;

/// Reputation voting action: Trustworthy (TW) or Untrustworthy (UTW)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteAction {
    #[serde(rename = "TW")]
    Tw,
    #[serde(rename = "UTW")]
    Utw,
}

impl VoteAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            VoteAction::Tw => "TW",
            VoteAction::Utw => "UTW",
        }
    }

    pub fn from_str_loose(s: &str) -> Result<Self, String> {
        match s.trim().to_uppercase().as_str() {
            "TW" | "TRUSTWORTHY" => Ok(VoteAction::Tw),
            "UTW" | "UNTRUSTWORTHY" => Ok(VoteAction::Utw),
            other => Err(format!(
                "Invalid vote action `{}`: must be TW or UTW",
                other
            )),
        }
    }

    pub fn is_tw(&self) -> bool {
        matches!(self, VoteAction::Tw)
    }

    pub fn is_utw(&self) -> bool {
        matches!(self, VoteAction::Utw)
    }
}

impl std::fmt::Display for VoteAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Cryptographically signed, PoW-backed domain reputation vote record (REP-02)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoteRecord {
    /// Unique 32-byte identifier for this vote event (hash of canonical vote fields)
    pub vote_id: [u8; 32],
    /// Ed25519 public key of the voting node
    pub voter_pubkey: [u8; 32],
    /// Fully-qualified domain name (ASCII/punycode normalized)
    pub domain: String,
    /// Vote action (TW / UTW)
    pub action: VoteAction,
    /// Monotonic sequence number for this voter node (1, 2, 3...)
    pub vote_seq: u64,
    /// Hash of the previous vote record emitted by this voter ([0; 32] if vote_seq == 1)
    pub prev_vote_hash: [u8; 32],
    /// Unix timestamp in seconds
    pub timestamp: u64,
    /// Number of times this voter has revised/flipped their vote on this domain before this vote
    pub revisions_on_domain: u32,
    /// PoW challenge hash bound to (originator || prev_hash || domain || action || seq || extra_nonce)
    pub challenge: [u8; 32],
    /// PoW solution nonce
    pub nonce: u64,
    /// Extra nonce for changing fields when cycling through 32-bit nonce space
    pub extra_nonce: u64,
    /// PoW difficulty in leading zero bits
    pub difficulty: u32,
    /// Ed25519 cryptographic signature over the canonical vote digest
    pub signature: Vec<u8>,
}

impl VoteRecord {
    /// Constructs, solves PoW for, and signs a new VoteRecord
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed(
        signing_key: &SigningKey,
        domain: &str,
        action: VoteAction,
        vote_seq: u64,
        prev_vote_hash: [u8; 32],
        timestamp: u64,
        active_votes_count_before: usize,
        revisions_on_domain_before: usize,
    ) -> Result<Self, String> {
        let clean_domain = domain.trim().to_ascii_lowercase();
        validate_domain_name(&clean_domain)?;

        let voter_pubkey = signing_key.verifying_key().to_bytes();
        let revisions_on_domain = revisions_on_domain_before as u32;

        let difficulty =
            calculate_vote_difficulty(active_votes_count_before, revisions_on_domain_before);

        if difficulty > MAX_COMPUTABLE_DIFFICULTY {
            return Err(format!(
                "Required vote difficulty ({}) exceeds maximum computable limit ({}) for SHA-256. Please vote on other domains you haven't flipped so much to allow your active voting difficulty to cool down.",
                difficulty, MAX_COMPUTABLE_DIFFICULTY
            ));
        }

        let (nonce, extra_nonce, challenge) =
            PowEngine::solve_with_changing_field(difficulty, |extra| {
                compute_vote_challenge(
                    &voter_pubkey,
                    &prev_vote_hash,
                    &clean_domain,
                    action,
                    vote_seq,
                    extra,
                )
            });

        let vote_id = compute_vote_id(
            &voter_pubkey,
            &clean_domain,
            action,
            vote_seq,
            &prev_vote_hash,
            timestamp,
            nonce,
            extra_nonce,
            difficulty,
        );

        let sig = signing_key.sign(&vote_id);
        let signature = sig.to_bytes().to_vec();

        Ok(Self {
            vote_id,
            voter_pubkey,
            domain: clean_domain,
            action,
            vote_seq,
            prev_vote_hash,
            timestamp,
            revisions_on_domain,
            challenge,
            nonce,
            extra_nonce,
            difficulty,
            signature,
        })
    }

    /// Verifies the cryptographic signature of the vote record against the voter's public key
    pub fn verify_signature(&self, expected_pubkey: &[u8; 32]) -> Result<(), String> {
        if self.voter_pubkey != *expected_pubkey {
            return Err("Vote record voter_pubkey does not match expected public key".to_string());
        }

        let verifying_key = VerifyingKey::from_bytes(&self.voter_pubkey)
            .map_err(|e| format!("Invalid Ed25519 public key: {}", e))?;

        if self.signature.len() != 64 {
            return Err(format!(
                "Invalid signature length: expected 64, got {}",
                self.signature.len()
            ));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&self.signature);
        let sig = Signature::from_bytes(&sig_arr);
        verifying_key
            .verify_strict(&self.vote_id, &sig)
            .map_err(|e| format!("Cryptographic signature verification failed: {}", e))?;

        Ok(())
    }

    /// Verifies the Proof-of-Work solution
    pub fn verify_pow(&self) -> bool {
        PowEngine::verify(&self.challenge, self.nonce, self.difficulty)
    }

    /// Validates the vote record against sequence continuity, challenge binding, PoW, and chain rules
    pub fn validate_against_chain(
        &self,
        prev_vote: Option<&VoteRecord>,
        active_votes_count_before: usize,
        revisions_on_domain_before: usize,
    ) -> Result<(), String> {
        validate_domain_name(&self.domain)?;

        match prev_vote {
            None => {
                if self.vote_seq != 1 {
                    return Err(format!(
                        "First vote for originator must have vote_seq = 1, found {}",
                        self.vote_seq
                    ));
                }
                if self.prev_vote_hash != [0u8; 32] {
                    return Err(
                        "First vote for originator must have prev_vote_hash = [0; 32]".to_string(),
                    );
                }
            }
            Some(prev) => {
                if self.vote_seq != prev.vote_seq + 1 {
                    return Err(format!(
                        "Vote sequence discontinuity: expected seq {}, found {}",
                        prev.vote_seq + 1,
                        self.vote_seq
                    ));
                }
                if self.prev_vote_hash != prev.vote_id {
                    return Err(format!(
                        "Broken vote hash link: expected prev {:02x?}, found {:02x?}",
                        &prev.vote_id[..4],
                        &self.prev_vote_hash[..4]
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

        if self.revisions_on_domain as usize != revisions_on_domain_before {
            return Err(format!(
                "Mismatched revisions_on_domain: record says {}, chain state has {}",
                self.revisions_on_domain, revisions_on_domain_before
            ));
        }

        let expected_challenge = compute_vote_challenge(
            &self.voter_pubkey,
            &self.prev_vote_hash,
            &self.domain,
            self.action,
            self.vote_seq,
            self.extra_nonce,
        );
        if self.challenge != expected_challenge {
            return Err("Challenge does not match computed challenge digest".to_string());
        }

        let required_difficulty =
            calculate_vote_difficulty(active_votes_count_before, revisions_on_domain_before);
        if required_difficulty > MAX_COMPUTABLE_DIFFICULTY {
            return Err(format!(
                "Required vote difficulty ({}) exceeds maximum computable limit ({})",
                required_difficulty, MAX_COMPUTABLE_DIFFICULTY
            ));
        }
        if self.difficulty < required_difficulty {
            return Err(format!(
                "Insufficient vote difficulty: required {}, found {}",
                required_difficulty, self.difficulty
            ));
        }
        if self.difficulty > MAX_COMPUTABLE_DIFFICULTY {
            return Err(format!(
                "Vote difficulty ({}) exceeds maximum computable limit ({})",
                self.difficulty, MAX_COMPUTABLE_DIFFICULTY
            ));
        }

        if !self.verify_pow() {
            return Err("Invalid PoW nonce for vote challenge".to_string());
        }

        let expected_id = compute_vote_id(
            &self.voter_pubkey,
            &self.domain,
            self.action,
            self.vote_seq,
            &self.prev_vote_hash,
            self.timestamp,
            self.nonce,
            self.extra_nonce,
            self.difficulty,
        );
        if self.vote_id != expected_id {
            return Err("Vote ID does not match computed digest".to_string());
        }

        self.verify_signature(&self.voter_pubkey)?;

        Ok(())
    }
}

/// Computes the unique challenge hash bound to:
/// (originator || prev_hash || domain || vote_action || seq || extra_nonce)
pub fn compute_vote_challenge(
    voter_pubkey: &[u8; 32],
    prev_vote_hash: &[u8; 32],
    domain: &str,
    action: VoteAction,
    vote_seq: u64,
    extra_nonce: u64,
) -> [u8; 32] {
    PowEngine::compute_challenge(&[
        voter_pubkey,
        prev_vote_hash,
        domain.as_bytes(),
        action.as_str().as_bytes(),
        &vote_seq.to_be_bytes(),
        &extra_nonce.to_be_bytes(),
    ])
}

/// Computes canonical 32-byte digest identifying a vote record
#[allow(clippy::too_many_arguments)]
pub fn compute_vote_id(
    voter_pubkey: &[u8; 32],
    domain: &str,
    action: VoteAction,
    vote_seq: u64,
    prev_vote_hash: &[u8; 32],
    timestamp: u64,
    nonce: u64,
    extra_nonce: u64,
    difficulty: u32,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"randbotd_vote_v1:");
    hasher.update(voter_pubkey);
    hasher.update(domain.as_bytes());
    hasher.update(action.as_str().as_bytes());
    hasher.update(vote_seq.to_be_bytes());
    hasher.update(prev_vote_hash);
    hasher.update(timestamp.to_be_bytes());
    hasher.update(nonce.to_be_bytes());
    hasher.update(extra_nonce.to_be_bytes());
    hasher.update(difficulty.to_be_bytes());
    hasher.finalize().into()
}

/// Computes the logarithmic flip penalty (in leading zero bits) applied per mind-change flip on a domain:
/// P_flip(revisions) = 2 * floor(log2(revisions + 1))
pub fn calculate_flip_penalty(revisions_on_domain: usize) -> u32 {
    let n = (revisions_on_domain + 1) as f64;
    2 * (n.log2().floor() as u32)
}

/// Computes required dynamic logarithmic difficulty:
/// D_vote = D_base + 2 * floor(log2(N_active_votes + 1)) + P_flip(revisions_on_domain)
pub fn calculate_vote_difficulty(active_votes: usize, revisions_on_domain: usize) -> u32 {
    let penalty = calculate_flip_penalty(revisions_on_domain);
    PowEngine::calculate_logarithmic_difficulty(DEFAULT_BASE_DIFFICULTY, active_votes, 2, penalty)
}

#[cfg(test)]
mod tests;
