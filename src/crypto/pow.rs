//! Cryptographic Proof-of-Work (PoW) Engine
//!
//! Provides modular, algorithm-agile Proof-of-Work puzzle generation, verification,
//! solving, and dynamic difficulty scaling for domain purges (CA-07), reputation
//! voting (REP-01), and CA user flagging (REP-08).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Baseline PoW difficulty in leading zero bits (fast for testing/CLI)
pub const DEFAULT_BASE_DIFFICULTY: u32 = 12;

/// Supported Proof-of-Work algorithms (extensible for memory-hard schemes such as Equihash)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PowAlgorithm {
    #[default]
    Sha256,
}

/// Generic Proof-of-Work Challenge and Solver Engine
pub struct PowEngine;

impl PowEngine {
    /// Computes a 32-byte challenge hash by hashing an ordered sequence of byte slices
    pub fn compute_challenge(components: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for component in components {
            hasher.update(component);
        }
        hasher.finalize().into()
    }

    /// Computes the resulting digest for a given challenge and nonce
    pub fn compute_digest(challenge: &[u8; 32], nonce: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(challenge);
        hasher.update(nonce.to_be_bytes());
        hasher.finalize().into()
    }

    /// Verifies whether `nonce` produces at least `difficulty` leading zero bits on `challenge`
    pub fn verify(challenge: &[u8; 32], nonce: u64, difficulty: u32) -> bool {
        let digest = Self::compute_digest(challenge, nonce);
        leading_zero_bits(&digest) >= difficulty
    }

    /// Solves the PoW challenge by finding a nonce that achieves the required difficulty
    pub fn solve(challenge: &[u8; 32], difficulty: u32) -> u64 {
        let mut nonce = 0u64;
        loop {
            if Self::verify(challenge, nonce, difficulty) {
                return nonce;
            }
            nonce = nonce.wrapping_add(1);
        }
    }

    /// Solves a PoW challenge by searching nonces. If nonces cycle through u32::MAX,
    /// invokes `reseed_challenge(extra_nonce)` to change challenge entropy so unresolvable hashes are eliminated.
    pub fn solve_with_changing_field<F>(
        difficulty: u32,
        mut reseed_challenge: F,
    ) -> (u64, u64, [u8; 32])
    where
        F: FnMut(u64) -> [u8; 32],
    {
        let mut extra_nonce = 0u64;
        loop {
            let challenge = reseed_challenge(extra_nonce);
            let mut nonce = 0u64;
            while nonce <= u32::MAX as u64 {
                if Self::verify(&challenge, nonce, difficulty) {
                    return (nonce, extra_nonce, challenge);
                }
                nonce += 1;
            }
            extra_nonce = extra_nonce.wrapping_add(1);
        }
    }

    /// Calculates dynamic logarithmic difficulty:
    /// D = base_difficulty + step_bits * floor(log2(item_count + 1)) + penalty_bits
    pub fn calculate_logarithmic_difficulty(
        base_difficulty: u32,
        item_count: usize,
        step_bits: u32,
        penalty_bits: u32,
    ) -> u32 {
        let n = (item_count + 1) as f64;
        let log2_n = n.log2().floor() as u32;
        let scaling = step_bits * log2_n;
        base_difficulty + scaling + penalty_bits
    }
}

/// Solves the PoW challenge by finding a nonce that achieves the required difficulty (standalone helper)
pub fn solve_pow(challenge: &[u8; 32], difficulty: u32) -> u64 {
    PowEngine::solve(challenge, difficulty)
}

/// Verifies whether `nonce` produces at least `difficulty` leading zero bits on `challenge` (standalone helper)
pub fn verify_pow(challenge: &[u8; 32], nonce: u64, difficulty: u32) -> bool {
    PowEngine::verify(challenge, nonce, difficulty)
}

/// Computes the dynamic logarithmic difficulty in leading zero bits (standalone helper)
pub fn calculate_logarithmic_difficulty(
    base_difficulty: u32,
    item_count: usize,
    step_bits: u32,
    penalty_bits: u32,
) -> u32 {
    PowEngine::calculate_logarithmic_difficulty(
        base_difficulty,
        item_count,
        step_bits,
        penalty_bits,
    )
}

/// Counts the number of leading zero bits in a digest
pub fn leading_zero_bits(digest: &[u8]) -> u32 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leading_zero_bits_computation() {
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x01]), 23);
        assert_eq!(leading_zero_bits(&[0x00, 0x01]), 15);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0x40]), 1);
        assert_eq!(leading_zero_bits(&[0x20]), 2);
        assert_eq!(leading_zero_bits(&[0x10]), 3);
        assert_eq!(leading_zero_bits(&[0x08]), 4);
        assert_eq!(leading_zero_bits(&[0x00, 0x00]), 16);
    }

    #[test]
    fn test_solve_and_verify_pow_roundtrip() {
        let challenge = PowEngine::compute_challenge(&[b"test_challenge_data", b":extra_entropy"]);
        let difficulty = 8; // 8 bits is very fast for unit tests

        let nonce = solve_pow(&challenge, difficulty);
        assert!(verify_pow(&challenge, nonce, difficulty));

        // Tampered nonce fails
        assert!(!verify_pow(&challenge, nonce.wrapping_add(1), 32));
    }

    #[test]
    fn test_logarithmic_difficulty_scaling_math() {
        // Base 12, step 2, penalty 0
        assert_eq!(calculate_logarithmic_difficulty(12, 0, 2, 0), 12);
        assert_eq!(calculate_logarithmic_difficulty(12, 1, 2, 0), 14);
        assert_eq!(calculate_logarithmic_difficulty(12, 2, 2, 0), 14);
        assert_eq!(calculate_logarithmic_difficulty(12, 3, 2, 0), 16);
        assert_eq!(calculate_logarithmic_difficulty(12, 6, 2, 0), 16);
        assert_eq!(calculate_logarithmic_difficulty(12, 7, 2, 0), 18);

        // With penalty 4
        assert_eq!(calculate_logarithmic_difficulty(12, 0, 2, 4), 16);
        assert_eq!(calculate_logarithmic_difficulty(12, 1, 2, 4), 18);
        assert_eq!(calculate_logarithmic_difficulty(12, 3, 2, 4), 20);
    }

    #[test]
    fn test_pow_algorithm_default_and_serde() {
        let algo = PowAlgorithm::default();
        assert_eq!(algo, PowAlgorithm::Sha256);

        let json = serde_json::to_string(&algo).expect("serialize");
        let deserialized: PowAlgorithm = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized, algo);
    }
}
