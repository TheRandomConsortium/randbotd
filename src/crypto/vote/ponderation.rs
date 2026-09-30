//! Behavioral Score & Weight Ponderation Engine (REP-03)
//!
//! Provides the mathematical formulation, input vector definitions, and deterministic
//! game-theoretic scoring functions for node ponderation evaluation.

use serde::{Deserialize, Serialize};

/// Neutral baseline ponderation score for a fresh, well-behaved node (50 out of 100)
pub const PONDERATION_BASELINE_SCORE: f64 = 50.0;

/// Maximum volume maturity bonus applied to ponderation
pub const MAX_VOLUME_BONUS: f64 = 15.0;

/// Maximum consensus alignment adjustment (+/- 20 points)
pub const MAX_CONSENSUS_ALIGNMENT_ADJUSTMENT: f64 = 20.0;

/// Maximum rapid flip and burst penalty applied to ponderation
pub const MAX_BURST_PENALTY: f64 = 40.0;

/// Maximum high-ponderation peer affinity bonus
pub const MAX_HIGH_PONDERATION_AFFINITY_BONUS: f64 = 15.0;

/// Maximum low-ponderation peer agreement penalty
pub const MAX_LOW_PONDERATION_AGREEMENT_PENALTY: f64 = 15.0;

/// Maximum single-target domain concentration penalty
pub const MAX_TARGET_CONCENTRATION_PENALTY: f64 = 15.0;

/// Threshold score for classifying a node as high-ponderation
pub const HIGH_PONDERATION_THRESHOLD: f64 = 70.0;

/// Threshold score for classifying a node as low-ponderation
pub const LOW_PONDERATION_THRESHOLD: f64 = 30.0;

/// Comprehensive input metrics for computing a node's behavioral ponderation score (REP-03)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PonderationInputs {
    /// Ed25519 public key of the evaluated voter node in 32-byte representation
    pub voter_pubkey: [u8; 32],
    /// Whether this peer operates as an infrastructure / headless node (cannot vote per Manifesto §2.IV)
    pub is_headless: bool,
    /// Has the node committed proven Byzantine double-signing / equivocation (PAYLOAD_TYPE_EQUIVOCATION_PROOF)
    pub is_equivocator: bool,
    /// Active distinct domains voted on by this node within rolling 1-year window
    pub active_votes_count: usize,
    /// Total lifetime monotonic votes emitted by this node
    pub total_votes_emitted: u64,
    /// Total distinct active voting nodes in local network view
    pub network_active_voters: usize,
    /// Total distinct domains currently voted on across the network
    pub network_active_domains: usize,
    /// Number of ingested bullshit events emitted by this originator
    pub bullshit_events_count: usize,
    /// Number of valid consensus events emitted by this originator
    pub valid_events_count: usize,
    /// Consensus alignment metric in [-1.0, 1.0] across domains with established peer consensus
    pub consensus_alignment: f64,
    /// Number of anomalous rapid flips on the same domain (delta_t < 300s)
    pub rapid_flips_count: usize,
    /// Number of rapid multi-domain burst clusters emitted in short windows (< 60s)
    pub burst_clusters_count: usize,
    /// Correlation with high-ponderation peers (P0 >= 70) in [-1.0, 1.0]
    pub high_ponderation_affinity: f64,
    /// Agreement with low-ponderation peers (P0 <= 30) in [0.0, 1.0]
    pub low_ponderation_agreement: f64,
    /// Target domain voting concentration (Herfindahl-Hirschman Index in [0.0, 1.0])
    pub target_concentration_hhi: f64,
}

impl PonderationInputs {
    /// Constructs default inputs for a fresh, neutral node
    pub fn new_neutral(voter_pubkey: [u8; 32]) -> Self {
        Self {
            voter_pubkey,
            is_headless: false,
            is_equivocator: false,
            active_votes_count: 0,
            total_votes_emitted: 0,
            network_active_voters: 1,
            network_active_domains: 1,
            bullshit_events_count: 0,
            valid_events_count: 0,
            consensus_alignment: 0.0,
            rapid_flips_count: 0,
            burst_clusters_count: 0,
            high_ponderation_affinity: 0.0,
            low_ponderation_agreement: 0.0,
            target_concentration_hhi: 0.0,
        }
    }
}

/// Detailed, verifiable explanatory breakdown of a node's ponderation score calculation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PonderationBreakdown {
    /// Evaluated node public key in hexadecimal representation
    pub pubkey_hex: String,
    /// Neutral starting baseline (50.0)
    pub base_score: f64,
    /// Logarithmic vote volume & participation maturity bonus (0.0 to +15.0)
    pub volume_bonus: f64,
    /// Penalty for bullshit events on the anti-entropy ledger (0.0 to 100.0)
    pub bullshit_penalty: f64,
    /// Closeness to established network consensus adjustment (-20.0 to +20.0)
    pub consensus_alignment_adjustment: f64,
    /// Penalty for anomalous rapid flips and burst voting (0.0 to 40.0)
    pub burst_penalty: f64,
    /// Reinforcement bonus from positive correlation with high-ponderation peers (0.0 to +15.0)
    pub high_ponderation_affinity_bonus: f64,
    /// Degradation penalty from agreement with low-ponderation peers (0.0 to 15.0)
    pub low_ponderation_agreement_penalty: f64,
    /// Penalty for extreme single-target brigading concentration (0.0 to 15.0)
    pub target_concentration_penalty: f64,
    /// Whether node was disqualified as headless infrastructure
    pub is_headless: bool,
    /// Whether node was disqualified for Byzantine equivocation
    pub is_equivocator: bool,
    /// Final clamped integer score in [0, 100]
    pub final_score: u32,
}

/// Core mathematical engine implementing REP-03 ponderation formulas
pub struct PonderationEngine;

impl PonderationEngine {
    /// Computes the complete behavioral ponderation score and explanatory breakdown
    pub fn compute_score(inputs: &PonderationInputs) -> PonderationBreakdown {
        let pubkey_hex = hex::encode(inputs.voter_pubkey);

        // Invariant 1: Headless infrastructure nodes have 0 voting weight (Manifesto §2.IV)
        if inputs.is_headless {
            return PonderationBreakdown {
                pubkey_hex,
                base_score: PONDERATION_BASELINE_SCORE,
                volume_bonus: 0.0,
                bullshit_penalty: 0.0,
                consensus_alignment_adjustment: 0.0,
                burst_penalty: 0.0,
                high_ponderation_affinity_bonus: 0.0,
                low_ponderation_agreement_penalty: 0.0,
                target_concentration_penalty: 0.0,
                is_headless: true,
                is_equivocator: inputs.is_equivocator,
                final_score: 0,
            };
        }

        // Invariant 2: Byzantine Equivocation permanently zeros voting weight
        if inputs.is_equivocator {
            return PonderationBreakdown {
                pubkey_hex,
                base_score: PONDERATION_BASELINE_SCORE,
                volume_bonus: 0.0,
                bullshit_penalty: 100.0,
                consensus_alignment_adjustment: 0.0,
                burst_penalty: 0.0,
                high_ponderation_affinity_bonus: 0.0,
                low_ponderation_agreement_penalty: 0.0,
                target_concentration_penalty: 0.0,
                is_headless: false,
                is_equivocator: true,
                final_score: 0,
            };
        }

        let base_score = PONDERATION_BASELINE_SCORE;
        let volume_bonus =
            Self::calculate_volume_bonus(inputs.active_votes_count, inputs.network_active_domains);
        let bullshit_penalty = Self::calculate_bullshit_penalty(
            inputs.bullshit_events_count,
            inputs.valid_events_count,
        );
        let consensus_alignment_adjustment =
            Self::calculate_consensus_alignment_adjustment(inputs.consensus_alignment);
        let burst_penalty =
            Self::calculate_burst_penalty(inputs.rapid_flips_count, inputs.burst_clusters_count);
        let high_ponderation_affinity_bonus =
            Self::calculate_high_ponderation_affinity_bonus(inputs.high_ponderation_affinity);
        let low_ponderation_agreement_penalty =
            Self::calculate_low_ponderation_agreement_penalty(inputs.low_ponderation_agreement);
        let target_concentration_penalty = Self::calculate_target_concentration_penalty(
            inputs.total_votes_emitted,
            inputs.target_concentration_hhi,
        );

        let raw_score = base_score + volume_bonus - bullshit_penalty
            + consensus_alignment_adjustment
            - burst_penalty
            + high_ponderation_affinity_bonus
            - low_ponderation_agreement_penalty
            - target_concentration_penalty;

        let final_score = raw_score.round().clamp(0.0, 100.0) as u32;

        PonderationBreakdown {
            pubkey_hex,
            base_score,
            volume_bonus,
            bullshit_penalty,
            consensus_alignment_adjustment,
            burst_penalty,
            high_ponderation_affinity_bonus,
            low_ponderation_agreement_penalty,
            target_concentration_penalty,
            is_headless: false,
            is_equivocator: false,
            final_score,
        }
    }

    /// Logarithmic vote volume & participation maturity formula:
    /// Delta_vol = 15.0 * ln(1 + V_active) / ln(1 + V_target)
    pub fn calculate_volume_bonus(active_votes_count: usize, network_active_domains: usize) -> f64 {
        if active_votes_count == 0 {
            return 0.0;
        }

        let target_volume = (network_active_domains / 4).clamp(5, 20) as f64;
        let numerator = (1.0 + active_votes_count as f64).ln();
        let denominator = (1.0 + target_volume).ln();

        let ratio = (numerator / denominator).clamp(0.0, 1.0);
        (MAX_VOLUME_BONUS * ratio * 100.0).round() / 100.0
    }

    /// Bullshit event penalty formula:
    /// Delta_bs = min(100.0, 20.0 * B + 40.0 * (B / (B + V_valid + 1)))
    pub fn calculate_bullshit_penalty(
        bullshit_events_count: usize,
        valid_events_count: usize,
    ) -> f64 {
        if bullshit_events_count == 0 {
            return 0.0;
        }

        let b = bullshit_events_count as f64;
        let v = valid_events_count as f64;
        let ratio = b / (b + v + 1.0);

        let penalty = 20.0 * b + 40.0 * ratio;
        penalty.clamp(0.0, 100.0)
    }

    /// Closeness to consensus adjustment formula:
    /// Delta_cons = 20.0 * Alignment [-1.0, 1.0]
    pub fn calculate_consensus_alignment_adjustment(consensus_alignment: f64) -> f64 {
        let clamped = consensus_alignment.clamp(-1.0, 1.0);
        (MAX_CONSENSUS_ALIGNMENT_ADJUSTMENT * clamped * 100.0).round() / 100.0
    }

    /// Rapid flip and burst voting penalty formula:
    /// Delta_burst = min(40.0, 15.0 * N_flips + 10.0 * N_bursts)
    pub fn calculate_burst_penalty(rapid_flips_count: usize, burst_clusters_count: usize) -> f64 {
        let flips_cost = 15.0 * (rapid_flips_count as f64);
        let bursts_cost = 10.0 * (burst_clusters_count as f64);
        (flips_cost + bursts_cost).clamp(0.0, MAX_BURST_PENALTY)
    }

    /// High-ponderation peer affinity bonus formula:
    /// Delta_high = 15.0 * max(0.0, Affinity_high)
    pub fn calculate_high_ponderation_affinity_bonus(high_ponderation_affinity: f64) -> f64 {
        let affinity = high_ponderation_affinity.clamp(-1.0, 1.0);
        if affinity <= 0.0 {
            0.0
        } else {
            (MAX_HIGH_PONDERATION_AFFINITY_BONUS * affinity * 100.0).round() / 100.0
        }
    }

    /// Low-ponderation peer agreement penalty formula:
    /// Delta_low = 15.0 * Agreement_low
    pub fn calculate_low_ponderation_agreement_penalty(low_ponderation_agreement: f64) -> f64 {
        let agreement = low_ponderation_agreement.clamp(0.0, 1.0);
        (MAX_LOW_PONDERATION_AGREEMENT_PENALTY * agreement * 100.0).round() / 100.0
    }

    /// Single-target brigading concentration penalty (HHI > 0.6 with >= 5 votes)
    pub fn calculate_target_concentration_penalty(
        total_votes_emitted: u64,
        target_concentration_hhi: f64,
    ) -> f64 {
        if total_votes_emitted < 5 {
            return 0.0;
        }

        let hhi = target_concentration_hhi.clamp(0.0, 1.0);
        if hhi <= 0.6 {
            0.0
        } else {
            let excess = (hhi - 0.6) / 0.4;
            (MAX_TARGET_CONCENTRATION_PENALTY * excess * 100.0).round() / 100.0
        }
    }
}
