#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use crate::crypto::vote::consensus::{
        ConsensusDirection, DomainConsensus, DomainConsensusCache,
    };
    use crate::crypto::vote::lazy::{calculate_dynamic_delta, evaluate_domain_trust_with_weights};
    use crate::crypto::vote::{VoteAction, VoteRecord};
    use crate::net::gossip::PAYLOAD_TYPE_EQUIVOCATION_PROOF;
    use crate::net::history::EventLogEntry;
    use crate::net::phonebook::Phonebook;
    use crate::storage::db::Database;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn test_dynamic_delta_zero_votes_and_monotonic_decay() {
        // Invariant 1: 0 votes always produces maximum baseline delta 50.0%
        let delta0 = calculate_dynamic_delta(0, 100);
        assert_eq!(delta0, 50.0);

        // Invariant 2: Delta narrows logarithmically as votes accumulate
        let delta5 = calculate_dynamic_delta(5, 100);
        let delta20 = calculate_dynamic_delta(20, 100);
        let delta50 = calculate_dynamic_delta(50, 100);
        let delta100 = calculate_dynamic_delta(100, 100);

        assert!(delta5 < delta0);
        assert!(delta20 < delta5);
        assert!(delta50 < delta20);
        assert!(delta100 < delta50);
        assert_eq!(delta100, 0.0); // when active votes match network size, delta converges to 0
    }

    #[test]
    fn test_dynamic_delta_automatic_network_expansion_rescaling() {
        // REP-04 Requirement: Delta automatically rescales (widens) when active network node count expands
        let votes = 10;
        let delta_small_net = calculate_dynamic_delta(votes, 20);
        let delta_medium_net = calculate_dynamic_delta(votes, 100);
        let delta_large_net = calculate_dynamic_delta(votes, 1000);

        assert!(delta_small_net < delta_medium_net);
        assert!(delta_medium_net < delta_large_net);
    }

    #[test]
    fn test_domain_consensus_weighted_and_alignment() {
        let signing_key1 = SigningKey::from_bytes(&[0x11u8; 32]);
        let signing_key2 = SigningKey::from_bytes(&[0x22u8; 32]);
        let signing_key3 = SigningKey::from_bytes(&[0x33u8; 32]);

        let v1 = VoteRecord::new_signed(
            &signing_key1,
            "example.hns",
            VoteAction::Tw,
            1,
            [0u8; 32],
            1000,
            0,
            0,
        )
        .unwrap();
        let v2 = VoteRecord::new_signed(
            &signing_key2,
            "example.hns",
            VoteAction::Tw,
            1,
            [0u8; 32],
            1000,
            0,
            0,
        )
        .unwrap();
        let v3 = VoteRecord::new_signed(
            &signing_key3,
            "example.hns",
            VoteAction::Utw,
            1,
            [0u8; 32],
            1000,
            0,
            0,
        )
        .unwrap();

        // Node 1 (w=80, TW), Node 2 (w=70, TW), Node 3 (w=30, UTW)
        let votes = vec![(&v1, 80u32), (&v2, 70u32), (&v3, 30u32)];
        let consensus = DomainConsensus::from_weighted_votes("example.hns", &votes, 1000);

        assert_eq!(consensus.domain, "example.hns");
        assert_eq!(consensus.tw_count, 2);
        assert_eq!(consensus.utw_count, 1);
        assert_eq!(consensus.total_active_votes, 3);
        assert_eq!(consensus.direction, ConsensusDirection::Tw);
        assert_eq!(consensus.tw_weight_sum, 150.0);
        assert_eq!(consensus.utw_weight_sum, 30.0);

        // Confidence = |150 - 30| / 180 = 120 / 180 = 0.667
        assert!((consensus.confidence - 0.667).abs() < 0.001);

        // Alignment check
        let align_tw = consensus.alignment_score(VoteAction::Tw);
        let align_utw = consensus.alignment_score(VoteAction::Utw);
        assert_eq!(align_tw, consensus.confidence);
        assert_eq!(align_utw, -consensus.confidence);
    }

    #[test]
    fn test_domain_consensus_cache_operations() {
        let mut cache = DomainConsensusCache::new();
        assert!(cache.is_empty());

        let consensus = DomainConsensus::new_empty("test.hns", 1000);
        cache.insert(consensus);
        assert_eq!(cache.len(), 1);
        assert!(cache.get("TEST.HNS").is_some());

        let removed = cache.remove("test.hns");
        assert!(removed.is_some());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_evaluate_domain_trust_empty_and_weighted_proportions() {
        // 1. Empty domain evaluation
        let empty_eval = evaluate_domain_trust_with_weights("empty.hns", &[], |_| 50, 10, 1000);
        assert_eq!(empty_eval.trust_score, 50.0);
        assert_eq!(empty_eval.delta, 50.0);
        assert_eq!(empty_eval.lower_bound, 0.0);
        assert_eq!(empty_eval.upper_bound, 100.0);
        assert_eq!(empty_eval.total_active_votes, 0);

        // 2. Unanimous TW with equal weights
        let sk1 = SigningKey::from_bytes(&[0x44u8; 32]);
        let sk2 = SigningKey::from_bytes(&[0x55u8; 32]);
        let v1 =
            VoteRecord::new_signed(&sk1, "secure.hns", VoteAction::Tw, 1, [0u8; 32], 1000, 0, 0)
                .unwrap();
        let v2 =
            VoteRecord::new_signed(&sk2, "secure.hns", VoteAction::Tw, 1, [0u8; 32], 1000, 0, 0)
                .unwrap();

        let votes = vec![v1.clone(), v2.clone()];
        let eval_tw = evaluate_domain_trust_with_weights("secure.hns", &votes, |_| 50, 10, 1000);
        assert_eq!(eval_tw.trust_score, 100.0);
        assert_eq!(eval_tw.tw_votes_count, 2);
        assert_eq!(eval_tw.utw_votes_count, 0);

        // 3. Mixed weighted votes: Node 1 has weight 90 (TW), Node 2 has weight 10 (UTW)
        let pk1 = sk1.verifying_key().to_bytes();
        let _pk2 = sk2.verifying_key().to_bytes();
        let v2_flip = VoteRecord::new_signed(
            &sk2,
            "secure.hns",
            VoteAction::Utw,
            2,
            v2.vote_id,
            1001,
            1,
            1,
        )
        .unwrap();
        let mixed_votes = vec![v1, v2_flip];

        let eval_mixed = evaluate_domain_trust_with_weights(
            "secure.hns",
            &mixed_votes,
            |pk| if *pk == pk1 { 90 } else { 10 },
            10,
            1002,
        );
        // Trust score = (90 / (90 + 10)) * 100 = 90.0%
        assert_eq!(eval_mixed.trust_score, 90.0);
        assert_eq!(eval_mixed.tw_votes_count, 1);
        assert_eq!(eval_mixed.utw_votes_count, 1);
        assert_eq!(eval_mixed.tw_voter_weight, 90.0);
        assert_eq!(eval_mixed.utw_voter_weight, 10.0);
    }

    #[test]
    fn test_database_evaluate_domain_trust_and_phonebook_profile_integration() {
        let temp_dir =
            std::env::temp_dir().join(format!("randbotd_lazy_eval_{}", rand::random::<u64>()));
        let db = Arc::new(Database::open(&temp_dir).expect("Open DB"));
        let phonebook = Arc::new(RwLock::new(Phonebook::new()));

        let sk1 = SigningKey::from_bytes(&[0x61u8; 32]);
        let sk2 = SigningKey::from_bytes(&[0x62u8; 32]);
        let pk1 = sk1.verifying_key().to_bytes();
        let pk2 = sk2.verifying_key().to_bytes();

        phonebook
            .write()
            .unwrap()
            .upsert_peer(&pk1, "127.0.0.1:43210", false);
        phonebook
            .write()
            .unwrap()
            .upsert_peer(&pk2, "127.0.0.1:43211", false);

        // Insert vote 1 (TW)
        let v1 =
            VoteRecord::new_signed(&sk1, "alpha.rand", VoteAction::Tw, 1, [0u8; 32], 1000, 0, 0)
                .unwrap();
        db.insert_vote(v1).unwrap();

        // Compute voter 1 ponderation in profile
        let breakdown1 = db.compute_and_update_voter_ponderation(&pk1, Some(&phonebook));
        assert!(breakdown1.is_some());
        let score1 = phonebook.read().unwrap().get_peer_ponderation(&pk1);
        assert!(score1 > 0);

        // Insert vote 2 (UTW)
        let v2 = VoteRecord::new_signed(
            &sk2,
            "alpha.rand",
            VoteAction::Utw,
            1,
            [0u8; 32],
            1000,
            0,
            0,
        )
        .unwrap();
        db.insert_vote(v2).unwrap();
        let breakdown2 = db.compute_and_update_voter_ponderation(&pk2, Some(&phonebook));
        assert!(breakdown2.is_some());

        // Read path: evaluate domain trust in O(n)
        let eval = db.evaluate_domain_trust("alpha.rand", Some(&phonebook));
        assert_eq!(eval.domain, "alpha.rand");
        assert_eq!(eval.total_active_votes, 2);
        assert_eq!(eval.tw_votes_count, 1);
        assert_eq!(eval.utw_votes_count, 1);
        assert!(eval.trust_score >= 0.0 && eval.trust_score <= 100.0);
        assert!(eval.lower_bound <= eval.trust_score);
        assert!(eval.upper_bound >= eval.trust_score);

        // Byzantine Equivocation penalty zeroes ponderation
        let mut data = Vec::new();
        data.extend_from_slice(&1u64.to_be_bytes());
        data.extend_from_slice(&[0u8; 32]);
        data.push(PAYLOAD_TYPE_EQUIVOCATION_PROOF);
        data.extend_from_slice(&[1, 2, 3]);
        let sig = sk1.sign(&data).to_bytes().to_vec();
        let equivocation_entry = EventLogEntry {
            seq: 1,
            prev_hash: [0u8; 32],
            originator: pk1,
            payload_type: PAYLOAD_TYPE_EQUIVOCATION_PROOF,
            payload: vec![1, 2, 3],
            signature_bytes: sig,
            is_bullshit: true,
        };
        db.append_event(equivocation_entry).unwrap();
        assert!(db.is_equivocator(&pk1));

        let equiv_breakdown = db
            .compute_and_update_voter_ponderation(&pk1, Some(&phonebook))
            .unwrap();
        assert_eq!(equiv_breakdown.final_score, 0);
        assert_eq!(phonebook.read().unwrap().get_peer_ponderation(&pk1), 0);

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
