#[cfg(test)]
mod tests {
    use crate::crypto::vote::ponderation::*;

    #[test]
    fn test_neutral_fresh_node_baseline() {
        let pubkey = [0x42u8; 32];
        let inputs = PonderationInputs::new_neutral(pubkey);
        let breakdown = PonderationEngine::compute_score(&inputs);

        assert_eq!(breakdown.base_score, 50.0);
        assert_eq!(breakdown.volume_bonus, 0.0);
        assert_eq!(breakdown.bullshit_penalty, 0.0);
        assert_eq!(breakdown.consensus_alignment_adjustment, 0.0);
        assert_eq!(breakdown.burst_penalty, 0.0);
        assert_eq!(breakdown.high_ponderation_affinity_bonus, 0.0);
        assert_eq!(breakdown.low_ponderation_agreement_penalty, 0.0);
        assert_eq!(breakdown.target_concentration_penalty, 0.0);
        assert_eq!(breakdown.final_score, 50);
        assert!(!breakdown.is_headless);
        assert!(!breakdown.is_equivocator);
    }

    #[test]
    fn test_headless_node_zero_voting_weight() {
        let pubkey = [0x01u8; 32];
        let mut inputs = PonderationInputs::new_neutral(pubkey);
        inputs.is_headless = true;
        inputs.active_votes_count = 10;
        inputs.consensus_alignment = 1.0;

        let breakdown = PonderationEngine::compute_score(&inputs);
        assert_eq!(breakdown.final_score, 0);
        assert!(breakdown.is_headless);
    }

    #[test]
    fn test_equivocation_fatal_byzantine_penalty() {
        let pubkey = [0x02u8; 32];
        let mut inputs = PonderationInputs::new_neutral(pubkey);
        inputs.is_equivocator = true;
        inputs.active_votes_count = 20;
        inputs.consensus_alignment = 1.0;

        let breakdown = PonderationEngine::compute_score(&inputs);
        assert_eq!(breakdown.final_score, 0);
        assert!(breakdown.is_equivocator);
        assert_eq!(breakdown.bullshit_penalty, 100.0);
    }

    #[test]
    fn test_vote_volume_logarithmic_maturity() {
        // Zero votes = 0 bonus
        assert_eq!(PonderationEngine::calculate_volume_bonus(0, 40), 0.0);

        // Moderate votes = partial bonus
        let bonus5 = PonderationEngine::calculate_volume_bonus(5, 40);
        assert!(bonus5 > 0.0 && bonus5 < MAX_VOLUME_BONUS);

        // Large votes = caps at MAX_VOLUME_BONUS
        let bonus30 = PonderationEngine::calculate_volume_bonus(30, 40);
        assert_eq!(bonus30, MAX_VOLUME_BONUS);
    }

    #[test]
    fn test_bullshit_event_penalties() {
        // 0 bullshit = 0 penalty
        assert_eq!(PonderationEngine::calculate_bullshit_penalty(0, 10), 0.0);

        // 1 bullshit event with 1 valid event gives substantial penalty (> 30 pts)
        let penalty1 = PonderationEngine::calculate_bullshit_penalty(1, 1);
        assert!(penalty1 >= 30.0);

        // 4+ bullshit events caps at 100
        let penalty5 = PonderationEngine::calculate_bullshit_penalty(5, 0);
        assert_eq!(penalty5, 100.0);
    }

    #[test]
    fn test_consensus_alignment_scaling() {
        // Full positive agreement gives +20.0
        assert_eq!(
            PonderationEngine::calculate_consensus_alignment_adjustment(1.0),
            20.0
        );

        // Full contrarian disagreement gives -20.0
        assert_eq!(
            PonderationEngine::calculate_consensus_alignment_adjustment(-1.0),
            -20.0
        );

        // Neutral alignment gives 0.0
        assert_eq!(
            PonderationEngine::calculate_consensus_alignment_adjustment(0.0),
            0.0
        );
    }

    #[test]
    fn test_rapid_burst_and_flip_penalties() {
        // 0 rapid flips/bursts = 0 penalty
        assert_eq!(PonderationEngine::calculate_burst_penalty(0, 0), 0.0);

        // 1 rapid flip = 15.0 penalty
        assert_eq!(PonderationEngine::calculate_burst_penalty(1, 0), 15.0);

        // 1 burst cluster = 10.0 penalty
        assert_eq!(PonderationEngine::calculate_burst_penalty(0, 1), 10.0);

        // Extreme burst caps at MAX_BURST_PENALTY (40.0)
        assert_eq!(PonderationEngine::calculate_burst_penalty(5, 5), 40.0);
    }

    #[test]
    fn test_peer_affinity_high_and_low_ponderation() {
        // High affinity bonus
        assert_eq!(
            PonderationEngine::calculate_high_ponderation_affinity_bonus(1.0),
            15.0
        );
        assert_eq!(
            PonderationEngine::calculate_high_ponderation_affinity_bonus(-0.5),
            0.0
        );

        // Low agreement penalty
        assert_eq!(
            PonderationEngine::calculate_low_ponderation_agreement_penalty(1.0),
            15.0
        );
        assert_eq!(
            PonderationEngine::calculate_low_ponderation_agreement_penalty(0.0),
            0.0
        );
    }

    #[test]
    fn test_target_concentration_penalty() {
        // Low lifetime votes (< 5) is exempt
        assert_eq!(
            PonderationEngine::calculate_target_concentration_penalty(4, 1.0),
            0.0
        );

        // Diversified voting (HHI <= 0.6) has no penalty
        assert_eq!(
            PonderationEngine::calculate_target_concentration_penalty(10, 0.4),
            0.0
        );

        // Extreme brigading (HHI = 1.0) gets maximum concentration penalty (15.0)
        assert_eq!(
            PonderationEngine::calculate_target_concentration_penalty(10, 1.0),
            15.0
        );
    }

    #[test]
    fn test_sybil_and_collusion_ring_suppression() {
        // Node colluding with low-ponderation ring and contrarian to network consensus
        let mut inputs = PonderationInputs::new_neutral([0x99u8; 32]);
        inputs.active_votes_count = 2;
        inputs.consensus_alignment = -0.8; // contrarian to consensus
        inputs.low_ponderation_agreement = 1.0; // highly correlated with low nodes
        inputs.rapid_flips_count = 1; // 1 rapid flip

        let breakdown = PonderationEngine::compute_score(&inputs);
        // Base 50 - 16 (consensus) - 15 (low agreement) - 15 (flip) + ~2 (vol) = ~6
        assert!(breakdown.final_score < 15);
    }

    #[test]
    fn test_honest_mature_voter_reputation_growth() {
        // Honest community voter with mature volume, high consensus alignment, and peer affinity
        let mut inputs = PonderationInputs::new_neutral([0x10u8; 32]);
        inputs.active_votes_count = 25;
        inputs.network_active_domains = 50;
        inputs.consensus_alignment = 0.9;
        inputs.high_ponderation_affinity = 0.8;
        inputs.total_votes_emitted = 30;
        inputs.target_concentration_hhi = 0.2; // well diversified

        let breakdown = PonderationEngine::compute_score(&inputs);
        // Base 50 + 15 (vol) + 18 (cons) + 12 (high affinity) = ~95
        assert!(breakdown.final_score >= 90);
        assert!(breakdown.final_score <= 100);
    }
}
