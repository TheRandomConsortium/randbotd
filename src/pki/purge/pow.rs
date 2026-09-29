//! Proof-of-Work Challenge and Difficulty Calculation for Domain Purges (CA-07)

use crate::crypto::pow::{calculate_logarithmic_difficulty, solve_pow, verify_pow, PowEngine};

/// Baseline PoW difficulty in leading zero bits (fast for testing/CLI)
pub const BASE_POW_DIFFICULTY: u32 = 12;

/// Additional PoW difficulty in bits when purging unilaterally without external UTW strike evidence
pub const UNILATERAL_PURGE_PENALTY_BITS: u32 = 4;

/// Computes the unique challenge hash for a purge request PoW puzzle (defaults extra_nonce to 0)
pub fn compute_purge_challenge(
    ca_id: &[u8; 32],
    domain: &str,
    timestamp: u64,
    prev_purge_hash: &[u8; 32],
    purge_seq: u64,
) -> [u8; 32] {
    compute_purge_challenge_with_extra_nonce(
        ca_id,
        domain,
        timestamp,
        prev_purge_hash,
        purge_seq,
        0,
    )
}

/// Computes the unique challenge hash for a purge request PoW puzzle with explicit extra_nonce
pub fn compute_purge_challenge_with_extra_nonce(
    ca_id: &[u8; 32],
    domain: &str,
    timestamp: u64,
    prev_purge_hash: &[u8; 32],
    purge_seq: u64,
    extra_nonce: u64,
) -> [u8; 32] {
    let ts_bytes = timestamp.to_be_bytes();
    let seq_bytes = purge_seq.to_be_bytes();
    if extra_nonce == 0 {
        PowEngine::compute_challenge(&[
            b"randbotd_v1_purge_challenge",
            ca_id,
            domain.as_bytes(),
            &ts_bytes,
            prev_purge_hash,
            &seq_bytes,
        ])
    } else {
        let extra_bytes = extra_nonce.to_be_bytes();
        PowEngine::compute_challenge(&[
            b"randbotd_v1_purge_challenge",
            ca_id,
            domain.as_bytes(),
            &ts_bytes,
            prev_purge_hash,
            &seq_bytes,
            &extra_bytes,
        ])
    }
}

/// Solves the purge PoW challenge, automatically re-seeding extra_nonce if u32 nonces cycle
pub fn solve_purge_pow_with_changing_field(
    ca_id: &[u8; 32],
    domain: &str,
    timestamp: u64,
    prev_purge_hash: &[u8; 32],
    purge_seq: u64,
    difficulty: u32,
) -> (u64, u64) {
    let (pow_nonce, extra_nonce, _) = PowEngine::solve_with_changing_field(difficulty, |extra| {
        compute_purge_challenge_with_extra_nonce(
            ca_id,
            domain,
            timestamp,
            prev_purge_hash,
            purge_seq,
            extra,
        )
    });
    (pow_nonce, extra_nonce)
}

/// Calculates required PoW difficulty in leading zero bits:
/// D = BASE_POW_DIFFICULTY + 2 * log2(active_unexpired_purges + 1) + (0 if strike_evidence else 4)
pub fn calculate_required_difficulty(
    active_unexpired_purges: usize,
    has_strike_evidence: bool,
) -> u32 {
    let penalty = if has_strike_evidence {
        0
    } else {
        UNILATERAL_PURGE_PENALTY_BITS
    };

    calculate_logarithmic_difficulty(BASE_POW_DIFFICULTY, active_unexpired_purges, 2, penalty)
}

/// Solves the PoW challenge by finding a nonce that achieves the required difficulty
pub fn solve_purge_pow(challenge: &[u8; 32], difficulty: u32) -> u64 {
    solve_pow(challenge, difficulty)
}

/// Verifies whether `nonce` produces at least `difficulty` leading zero bits on `challenge`
pub fn verify_purge_pow(challenge: &[u8; 32], nonce: u64, difficulty: u32) -> bool {
    verify_pow(challenge, nonce, difficulty)
}
