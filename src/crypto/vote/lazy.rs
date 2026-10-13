//! Lazy Evaluation Engine & Dynamic Delta Rescaling (REP-04)
//!
//! Provides on-demand, O(n) domain trust score calculation, dynamic Delta window
//! rescaling, and decoupled voter ponderation updates from cached network metrics.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::vote::consensus::{ConsensusDirection, DomainConsensus};
use crate::crypto::vote::ponderation::{
    PonderationBreakdown, PonderationEngine, PonderationInputs,
};
use crate::crypto::vote::{VoteAction, VoteRecord};
use crate::net::phonebook::Phonebook;
use crate::storage::db::Database;

/// Comprehensive trust evaluation result for a domain (REP-04 / ACME-04)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomainTrustEvaluation {
    /// Fully-qualified domain name
    pub domain: String,
    /// Aggregated trust score in [0.0, 100.0] (50.0 is neutral baseline per ACME-02)
    pub trust_score: f64,
    /// Dynamic tolerance window (+/- Delta %) in [0.0, 50.0]
    pub delta: f64,
    /// Lower confidence bound: max(0.0, trust_score - delta)
    pub lower_bound: f64,
    /// Upper confidence bound: min(100.0, trust_score + delta)
    pub upper_bound: f64,
    /// Total active votes cast for this domain
    pub total_active_votes: usize,
    /// Number of active TW votes
    pub tw_votes_count: usize,
    /// Number of active UTW votes
    pub utw_votes_count: usize,
    /// Total weighted voter ponderation sum
    pub total_voter_weight: f64,
    /// Weighted TW voter ponderation sum
    pub tw_voter_weight: f64,
    /// Weighted UTW voter ponderation sum
    pub utw_voter_weight: f64,
    /// Active network nodes count used for dynamic Delta rescaling
    pub network_active_nodes: usize,
    /// Unix timestamp when this evaluation was computed
    pub evaluated_at: u64,
}

/// Dynamic tolerance window (+/- Delta %) formula (REP-04 / ACME-04):
/// Starts at 50.0% with 0 votes and narrows logarithmically as votes accumulate,
/// naturally widening when active network node count expands.
pub fn calculate_dynamic_delta(active_domain_votes: usize, network_active_nodes: usize) -> f64 {
    if active_domain_votes == 0 {
        return 50.0;
    }
    let n_nodes = network_active_nodes.max(1) as f64;
    let v_votes = active_domain_votes as f64;

    let denom = (1.0 + n_nodes).ln();
    if denom <= f64::EPSILON {
        return 50.0;
    }
    let ratio = ((1.0 + v_votes).ln() / denom).clamp(0.0, 1.0);
    let delta = 50.0 * (1.0 - ratio);
    (delta * 100.0).round() / 100.0
}

/// Evaluates domain trust in O(n) time using pre-cached voter ponderation weights
pub fn evaluate_domain_trust_with_weights<F>(
    domain: &str,
    active_votes: &[VoteRecord],
    get_voter_weight: F,
    network_active_nodes: usize,
    timestamp: u64,
) -> DomainTrustEvaluation
where
    F: Fn(&[u8; 32]) -> u32,
{
    let clean_domain = domain.trim().to_ascii_lowercase();
    let total_active_votes = active_votes.len();
    let delta = calculate_dynamic_delta(total_active_votes, network_active_nodes);

    if total_active_votes == 0 {
        let trust_score = 50.0;
        let lower_bound = (trust_score - delta).max(0.0);
        let upper_bound = (trust_score + delta).min(100.0);
        return DomainTrustEvaluation {
            domain: clean_domain,
            trust_score,
            delta,
            lower_bound,
            upper_bound,
            total_active_votes: 0,
            tw_votes_count: 0,
            utw_votes_count: 0,
            total_voter_weight: 0.0,
            tw_voter_weight: 0.0,
            utw_voter_weight: 0.0,
            network_active_nodes,
            evaluated_at: timestamp,
        };
    }

    let mut tw_votes_count = 0usize;
    let mut utw_votes_count = 0usize;
    let mut tw_voter_weight = 0.0f64;
    let mut utw_voter_weight = 0.0f64;

    for vote in active_votes {
        let weight = get_voter_weight(&vote.voter_pubkey) as f64;
        match vote.action {
            VoteAction::Tw => {
                tw_votes_count += 1;
                tw_voter_weight += weight;
            }
            VoteAction::Utw => {
                utw_votes_count += 1;
                utw_voter_weight += weight;
            }
        }
    }

    let total_voter_weight = tw_voter_weight + utw_voter_weight;
    let trust_score = if total_voter_weight > 0.0 {
        ((tw_voter_weight / total_voter_weight) * 100.0 * 100.0).round() / 100.0
    } else {
        50.0
    };

    let lower_bound = ((trust_score - delta).max(0.0) * 100.0).round() / 100.0;
    let upper_bound = ((trust_score + delta).min(100.0) * 100.0).round() / 100.0;

    DomainTrustEvaluation {
        domain: clean_domain,
        trust_score,
        delta,
        lower_bound,
        upper_bound,
        total_active_votes,
        tw_votes_count,
        utw_votes_count,
        total_voter_weight,
        tw_voter_weight,
        utw_voter_weight,
        network_active_nodes,
        evaluated_at: timestamp,
    }
}

impl Database {
    /// On-demand lazy evaluation of a domain's trust score and dynamic Delta window (REP-04)
    pub fn evaluate_domain_trust(
        &self,
        domain: &str,
        phonebook: Option<&RwLock<Phonebook>>,
    ) -> DomainTrustEvaluation {
        let clean_domain = domain.trim().to_ascii_lowercase();
        let active_votes = self.list_active_domain_votes(Some(&clean_domain), None);

        let (network_active_nodes, get_weight) = match phonebook {
            Some(pb_lock) => {
                let pb = pb_lock.read().ok();
                let nodes_count = pb.as_ref().map(|p| p.peers.len().max(1)).unwrap_or(1);
                (
                    nodes_count,
                    Box::new(move |pk: &[u8; 32]| {
                        pb_lock
                            .read()
                            .map(|p| p.get_peer_ponderation(pk))
                            .unwrap_or(50)
                    }) as Box<dyn Fn(&[u8; 32]) -> u32>,
                )
            }
            None => {
                let all_votes = self.list_all_votes();
                let mut voters = HashSet::new();
                for v in &all_votes {
                    voters.insert(v.voter_pubkey);
                }
                let nodes_count = voters.len().max(1);
                (
                    nodes_count,
                    Box::new(|_: &[u8; 32]| 50u32) as Box<dyn Fn(&[u8; 32]) -> u32>,
                )
            }
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        evaluate_domain_trust_with_weights(
            &clean_domain,
            &active_votes,
            get_weight,
            network_active_nodes,
            now,
        )
    }

    /// Evaluates cached domain consensus from active votes paired with phonebook voter ponderations
    pub fn compute_domain_consensus(
        &self,
        domain: &str,
        phonebook: Option<&RwLock<Phonebook>>,
    ) -> DomainConsensus {
        let clean_domain = domain.trim().to_ascii_lowercase();
        let active_votes = self.list_active_domain_votes(Some(&clean_domain), None);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let votes_with_weights: Vec<(&VoteRecord, u32)> = active_votes
            .iter()
            .map(|v| {
                let weight = phonebook
                    .and_then(|pb| pb.read().ok())
                    .map(|pb| pb.get_peer_ponderation(&v.voter_pubkey))
                    .unwrap_or(50);
                (v, weight)
            })
            .collect();

        DomainConsensus::from_weighted_votes(&clean_domain, &votes_with_weights, now)
    }

    /// Extracts voter metrics from local database and updates peer ponderation in profile (REP-04 Write Path)
    pub fn compute_and_update_voter_ponderation(
        &self,
        voter_pubkey: &[u8; 32],
        phonebook: Option<&RwLock<Phonebook>>,
    ) -> Option<PonderationBreakdown> {
        let all_votes = self.get_votes_for_originator(voter_pubkey);
        if all_votes.is_empty() {
            return None;
        }

        let is_headless = phonebook
            .and_then(|pb| pb.read().ok())
            .map(|pb| pb.is_peer_headless(voter_pubkey))
            .unwrap_or(false);

        let is_equivocator = self.is_equivocator(voter_pubkey);

        let active_votes = self.list_active_domain_votes(None, Some(voter_pubkey));
        let active_votes_count = active_votes.len();
        let total_votes_emitted = all_votes.last().map(|v| v.vote_seq).unwrap_or(0);

        let network_all_votes = self.list_all_votes();
        let mut network_voters = HashSet::new();
        let mut network_domains = HashSet::new();
        for v in &network_all_votes {
            network_voters.insert(v.voter_pubkey);
            network_domains.insert(v.domain.clone());
        }
        let network_active_voters = network_voters.len().max(1);
        let network_active_domains = network_domains.len().max(1);

        let (valid_events_count, bullshit_events_count) =
            self.get_originator_reputation(voter_pubkey);

        // Compute consensus alignment using cached consensus on voted domains
        let mut alignment_sum = 0.0f64;
        let mut consensus_domains_count = 0usize;
        for active_v in &active_votes {
            let consensus = self.compute_domain_consensus(&active_v.domain, phonebook);
            if consensus.direction != ConsensusDirection::Undecided && consensus.confidence > 0.0 {
                alignment_sum += consensus.alignment_score(active_v.action);
                consensus_domains_count += 1;
            }
        }
        let consensus_alignment = if consensus_domains_count > 0 {
            (alignment_sum / consensus_domains_count as f64).clamp(-1.0, 1.0)
        } else {
            0.0
        };

        // Compute rapid flips (delta_t < 300s on same domain)
        let mut rapid_flips_count = 0usize;
        for i in 1..all_votes.len() {
            let prev = &all_votes[i - 1];
            let curr = &all_votes[i];
            if prev.domain == curr.domain
                && curr.action != prev.action
                && curr.timestamp.saturating_sub(prev.timestamp) < 300
            {
                rapid_flips_count += 1;
            }
        }

        // Compute burst clusters (> 5 votes in 60s)
        let mut burst_clusters_count = 0usize;
        if all_votes.len() >= 5 {
            for i in 4..all_votes.len() {
                if all_votes[i]
                    .timestamp
                    .saturating_sub(all_votes[i - 4].timestamp)
                    < 60
                {
                    burst_clusters_count += 1;
                }
            }
        }

        // High / Low ponderation peer affinity
        let (high_peers, low_peers) = match phonebook {
            Some(pb_lock) => {
                let pb = pb_lock.read().ok();
                let high = pb
                    .as_ref()
                    .map(|p| p.high_ponderation_peers())
                    .unwrap_or_default();
                let low = pb
                    .as_ref()
                    .map(|p| p.low_ponderation_peers())
                    .unwrap_or_default();
                (high, low)
            }
            None => (Vec::new(), Vec::new()),
        };

        let high_ponderation_affinity =
            Self::compute_peer_affinity(&active_votes, &high_peers, self);
        let low_ponderation_agreement =
            Self::compute_peer_agreement(&active_votes, &low_peers, self);

        // Herfindahl-Hirschman Index (HHI) for target concentration
        let mut domain_vote_counts: HashMap<String, usize> = HashMap::new();
        for v in &all_votes {
            *domain_vote_counts.entry(v.domain.clone()).or_insert(0) += 1;
        }
        let total_v = all_votes.len() as f64;
        let mut hhi = 0.0f64;
        for count in domain_vote_counts.values() {
            let share = *count as f64 / total_v;
            hhi += share * share;
        }

        let inputs = PonderationInputs {
            voter_pubkey: *voter_pubkey,
            is_headless,
            is_equivocator,
            active_votes_count,
            total_votes_emitted,
            network_active_voters,
            network_active_domains,
            bullshit_events_count,
            valid_events_count,
            consensus_alignment,
            rapid_flips_count,
            burst_clusters_count,
            high_ponderation_affinity,
            low_ponderation_agreement,
            target_concentration_hhi: hhi.clamp(0.0, 1.0),
        };

        let prior_score = phonebook
            .and_then(|pb| pb.read().ok())
            .map(|pb| pb.get_peer_ponderation(voter_pubkey))
            .unwrap_or(50);

        let breakdown = PonderationEngine::compute_score(&inputs);

        if let Some(pb_lock) = phonebook {
            if let Ok(mut pb) = pb_lock.write() {
                pb.update_peer_ponderation(voter_pubkey, breakdown.final_score);
            }
        }

        // REP-07: Heuristic Cluster Propagation upon significant demotion
        if breakdown.final_score < prior_score
            && (prior_score - breakdown.final_score)
                >= crate::crypto::vote::cluster::MIN_DEMOTION_TRIGGER_DELTA
        {
            if let Some(latest_v) = all_votes.last() {
                let job = crate::crypto::vote::cluster::ClusterJob {
                    trigger_voter: *voter_pubkey,
                    domain: latest_v.domain.clone(),
                    old_ponderation: prior_score,
                    new_ponderation: breakdown.final_score,
                    timestamp: latest_v.timestamp,
                };
                self.dispatch_cluster_job(job, phonebook);
            }
        }

        Some(breakdown)
    }

    fn compute_peer_affinity(my_votes: &[VoteRecord], peers: &[[u8; 32]], db: &Database) -> f64 {
        if peers.is_empty() || my_votes.is_empty() {
            return 0.0;
        }
        let mut matches = 0isize;
        let mut total = 0usize;

        for peer in peers {
            for v in my_votes {
                if let Some(peer_vote) =
                    db.get_active_vote_for_originator_and_domain(peer, &v.domain)
                {
                    total += 1;
                    if peer_vote.action == v.action {
                        matches += 1;
                    } else {
                        matches -= 1;
                    }
                }
            }
        }

        if total == 0 {
            0.0
        } else {
            (matches as f64 / total as f64).clamp(-1.0, 1.0)
        }
    }

    fn compute_peer_agreement(my_votes: &[VoteRecord], peers: &[[u8; 32]], db: &Database) -> f64 {
        if peers.is_empty() || my_votes.is_empty() {
            return 0.0;
        }
        let mut agreements = 0usize;
        let mut total = 0usize;

        for peer in peers {
            for v in my_votes {
                if let Some(peer_vote) =
                    db.get_active_vote_for_originator_and_domain(peer, &v.domain)
                {
                    total += 1;
                    if peer_vote.action == v.action {
                        agreements += 1;
                    }
                }
            }
        }

        if total == 0 {
            0.0
        } else {
            (agreements as f64 / total as f64).clamp(0.0, 1.0)
        }
    }
}
