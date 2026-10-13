//! Unit and integration tests for Heuristic Cluster Ponderation Penalties Engine (REP-07)

use super::*;
use crate::crypto::vote::VoteAction;
use crate::net::phonebook::Phonebook;
use std::sync::{Arc, RwLock};

fn mock_pubkey(byte: u8) -> [u8; 32] {
    let mut pk = [0u8; 32];
    pk[0] = byte;
    pk
}

#[test]
fn test_inverted_index_candidate_retrieval_and_omega_1() {
    let mut index = InvertedVoteIndex::new();
    let pk_a = mock_pubkey(1);
    let pk_b = mock_pubkey(2);
    let pk_c = mock_pubkey(3);

    // Ω(1) best-case: lone voter on a domain
    index.insert_or_update_vote(&pk_a, "alpha.example.org", VoteAction::Tw);
    let candidates_a = index.get_candidates_for_domain("alpha.example.org", &pk_a);
    assert!(
        candidates_a.is_empty(),
        "Expected 0 candidates when sole voter is excluded"
    );

    // Add peer B to alpha, and peer C to a completely different domain beta
    index.insert_or_update_vote(&pk_b, "alpha.example.org", VoteAction::Tw);
    index.insert_or_update_vote(&pk_c, "beta.example.org", VoteAction::Utw);

    let candidates = index.get_candidates_for_domain("alpha.example.org", &pk_a);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0], pk_b);

    // Peer C on beta must never appear as candidate for alpha
    assert!(!candidates.contains(&pk_c));
}

#[test]
fn test_significance_gate_and_bayesian_shrinkage() {
    let mut index = InvertedVoteIndex::new();
    let pk_a = mock_pubkey(1);
    let pk_b = mock_pubkey(2);

    // 1. Only 2 co-voted domains: below MIN_CO_VOTED_SIGNIFICANCE_GATE (3)
    index.insert_or_update_vote(&pk_a, "d1.org", VoteAction::Tw);
    index.insert_or_update_vote(&pk_b, "d1.org", VoteAction::Tw);
    index.insert_or_update_vote(&pk_a, "d2.org", VoteAction::Tw);
    index.insert_or_update_vote(&pk_b, "d2.org", VoteAction::Tw);

    let sim_2 = index.compute_pairwise_similarity(&pk_a, &pk_b, 64);
    assert!(
        sim_2.is_none(),
        "Overlap < 3 must be filtered out by the significance gate"
    );

    // 2. 3 co-voted domains: raw agreement = 1.0, but shrunk by 3 / (3 + 5) = 0.375
    index.insert_or_update_vote(&pk_a, "d3.org", VoteAction::Tw);
    index.insert_or_update_vote(&pk_b, "d3.org", VoteAction::Tw);

    let sim_3 = index
        .compute_pairwise_similarity(&pk_a, &pk_b, 64)
        .expect("Should compute similarity with 3 overlapping domains");
    assert_eq!(sim_3.raw_agreement, 1.0);
    assert!((sim_3.significance_weight - (3.0 / 8.0)).abs() < 1e-6);
    assert!((sim_3.final_similarity - 0.375).abs() < 1e-6);
    assert!(
        sim_3.final_similarity < DEFAULT_CLUSTER_SIMILARITY_THRESHOLD,
        "Small sample size must not meet 0.70 cluster threshold"
    );

    // 3. 20 co-voted domains: shrinkage = 20 / 25 = 0.80 -> final similarity = 0.80
    for i in 4..=20 {
        let domain = format!("d{}.org", i);
        index.insert_or_update_vote(&pk_a, &domain, VoteAction::Tw);
        index.insert_or_update_vote(&pk_b, &domain, VoteAction::Tw);
    }

    let sim_20 = index
        .compute_pairwise_similarity(&pk_a, &pk_b, 64)
        .expect("Should compute similarity with 20 overlapping domains");
    assert_eq!(sim_20.raw_agreement, 1.0);
    assert!((sim_20.significance_weight - 0.80).abs() < 1e-6);
    assert!((sim_20.final_similarity - 0.80).abs() < 1e-6);
    assert!(
        sim_20.final_similarity >= DEFAULT_CLUSTER_SIMILARITY_THRESHOLD,
        "20 identical votes must exceed 0.70 cluster threshold"
    );
}

#[test]
fn test_asymmetric_voter_activity_without_jaccard_penalty() {
    let mut index = InvertedVoteIndex::new();
    let puppet = mock_pubkey(10);
    let master = mock_pubkey(20);

    // Puppet voted only on 15 targeted domains
    for i in 1..=15 {
        let domain = format!("target{}.org", i);
        index.insert_or_update_vote(&puppet, &domain, VoteAction::Tw);
        index.insert_or_update_vote(&master, &domain, VoteAction::Tw);
    }

    // Master voted on 85 additional unrelated camouflage domains
    for i in 1..=85 {
        let domain = format!("camouflage{}.org", i);
        index.insert_or_update_vote(&master, &domain, VoteAction::Tw);
    }

    // Under Jaccard: 15 / (15 + 85) = 0.15 (false negative!).
    // Under our probabilistic co-occurrence model:
    let sim = index
        .compute_pairwise_similarity(&puppet, &master, 64)
        .expect("Must compute similarity on intersection");

    assert_eq!(sim.total_co_voted, 15);
    assert_eq!(sim.raw_agreement, 1.0);
    // Weight = 15 / (15 + 5) = 0.75 -> Final = 0.75 >= 0.70 threshold!
    assert!((sim.final_similarity - 0.75).abs() < 1e-6);
    assert!(
        sim.final_similarity >= DEFAULT_CLUSTER_SIMILARITY_THRESHOLD,
        "Asymmetric puppet/master collusion ring must be detected"
    );
}

#[test]
fn test_cluster_engine_penalty_propagation_and_damping() {
    let mut index = InvertedVoteIndex::new();
    let ringleader = mock_pubkey(100);
    let puppet_a = mock_pubkey(101);
    let honest_peer = mock_pubkey(102);

    let phonebook = Arc::new(RwLock::new(Phonebook::new()));
    {
        let mut pb = phonebook.write().unwrap();
        pb.upsert_peer(&ringleader, "10.0.0.1:43210", false);
        pb.upsert_peer(&puppet_a, "10.0.0.2:43210", false);
        pb.upsert_peer(&honest_peer, "10.0.0.3:43210", false);
        pb.update_peer_ponderation(&ringleader, 70);
        pb.update_peer_ponderation(&puppet_a, 70);
        pb.update_peer_ponderation(&honest_peer, 80);
    }

    // Ringleader and puppet_a agree 100% across 20 domains
    for i in 1..=20 {
        let domain = format!("review-bomb{}.org", i);
        index.insert_or_update_vote(&ringleader, &domain, VoteAction::Utw);
        index.insert_or_update_vote(&puppet_a, &domain, VoteAction::Utw);
    }

    // Honest peer voted contrarian on those domains
    for i in 1..=20 {
        let domain = format!("review-bomb{}.org", i);
        index.insert_or_update_vote(&honest_peer, &domain, VoteAction::Tw);
    }

    // Trigger job: Ringleader was demoted by 30 points (from 70 down to 40)
    let job = ClusterJob {
        trigger_voter: ringleader,
        domain: "review-bomb1.org".to_string(),
        old_ponderation: 70,
        new_ponderation: 40,
        timestamp: 1700000000,
    };

    let breakdowns = ClusterEngine::process_cluster_job(
        &job,
        &index,
        Some(phonebook.as_ref()),
        DEFAULT_CLUSTER_SIMILARITY_THRESHOLD,
        DEFAULT_CLUSTER_DAMPING_FACTOR,
    );

    assert_eq!(
        breakdowns.len(),
        1,
        "Only puppet_a must be penalized, honest peer must not"
    );

    let b = &breakdowns[0];
    assert_eq!(b.target_peer_hex, hex::encode(puppet_a));
    assert_eq!(b.trigger_demotion, 30);
    // sim = 1.0 * (20 / 25) = 0.80
    // penalty = round(0.50 * 0.80 * 30) = round(12.0) = 12
    assert_eq!(b.cluster_penalty_applied, 12);
    assert_eq!(b.prior_ponderation, 70);
    assert_eq!(b.post_ponderation, 58);

    // Verify phonebook was actually updated
    let pb_read = phonebook.read().unwrap();
    assert_eq!(pb_read.get_peer_ponderation(&puppet_a), 58);
    // Honest peer's ponderation must remain untouched
    assert_eq!(pb_read.get_peer_ponderation(&honest_peer), 80);
}

#[tokio::test]
async fn test_async_fifo_worker_execution() {
    let mut index = InvertedVoteIndex::new();
    let ringleader = mock_pubkey(200);
    let puppet = mock_pubkey(201);

    let phonebook = Arc::new(RwLock::new(Phonebook::new()));
    {
        let mut pb = phonebook.write().unwrap();
        pb.upsert_peer(&ringleader, "10.0.0.10:43210", false);
        pb.upsert_peer(&puppet, "10.0.0.11:43210", false);
        pb.update_peer_ponderation(&puppet, 80);
    }

    for i in 1..=20 {
        let domain = format!("shared{}.org", i);
        index.insert_or_update_vote(&ringleader, &domain, VoteAction::Tw);
        index.insert_or_update_vote(&puppet, &domain, VoteAction::Tw);
    }

    let shared_index = Arc::new(RwLock::new(index));
    let worker = ClusterWorkerHandle::spawn(shared_index.clone(), phonebook.clone(), 16);

    let submitted = worker.submit_job(ClusterJob {
        trigger_voter: ringleader,
        domain: "shared1.org".to_string(),
        old_ponderation: 75,
        new_ponderation: 55, // 20-point drop
        timestamp: 1700000001,
    });
    assert!(submitted, "Job submission must succeed");

    // Allow worker background task to process
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Penalty: sim = 0.80; delta = 20; 0.5 * 0.80 * 20 = 8 points drop -> 80 - 8 = 72
    let updated_score = phonebook.read().unwrap().get_peer_ponderation(&puppet);
    assert_eq!(updated_score, 72);
}
