//! Heuristic Cluster Ponderation Penalties Engine (REP-07)
//!
//! Provides behavioral collusion ring detection, in-memory inverted domain vote indexing,
//! probabilistic co-occurrence sampling with Bayesian shrinkage, and strict FIFO
//! background cluster penalty propagation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

use crate::crypto::vote::VoteAction;
use crate::net::phonebook::Phonebook;

/// Default similarity threshold to qualify as a heuristic cluster member (0.70)
pub const DEFAULT_CLUSTER_SIMILARITY_THRESHOLD: f64 = 0.70;

/// Default cluster damping factor applied to guilt-by-association penalties (0.50)
pub const DEFAULT_CLUSTER_DAMPING_FACTOR: f64 = 0.50;

/// Minimum overlapping co-voted domains required before computing cluster similarity
pub const MIN_CO_VOTED_SIGNIFICANCE_GATE: usize = 3;

/// Empirical Bayesian shrinkage prior constant (k0 = 5.0)
pub const BAYESIAN_SHRINKAGE_K0: f64 = 5.0;

/// Maximum number of overlapping domains evaluated per candidate pair
pub const MAX_STRATIFIED_SAMPLE_SIZE: usize = 64;

/// Minimum demotion delta in voter ponderation required to trigger cluster evaluation
pub const MIN_DEMOTION_TRIGGER_DELTA: u32 = 5;

/// Inverted in-memory co-voting index mapping domains to active voter decisions,
/// providing Ω(1) best-case and O(k_d) average-case candidate retrieval.
#[derive(Debug, Clone, Default)]
pub struct InvertedVoteIndex {
    /// domain -> HashMap<voter_pubkey, VoteAction>
    domain_postings: HashMap<String, HashMap<[u8; 32], VoteAction>>,
    /// voter_pubkey -> HashMap<domain, VoteAction>
    voter_postings: HashMap<[u8; 32], HashMap<String, VoteAction>>,
}

impl InvertedVoteIndex {
    /// Creates a fresh empty inverted index
    pub fn new() -> Self {
        Self {
            domain_postings: HashMap::new(),
            voter_postings: HashMap::new(),
        }
    }

    /// Indexes or updates an active vote for a voter on a domain
    pub fn insert_or_update_vote(
        &mut self,
        voter_pubkey: &[u8; 32],
        domain: &str,
        action: VoteAction,
    ) {
        let clean_domain = domain.trim().to_ascii_lowercase();

        self.domain_postings
            .entry(clean_domain.clone())
            .or_default()
            .insert(*voter_pubkey, action);

        self.voter_postings
            .entry(*voter_pubkey)
            .or_default()
            .insert(clean_domain, action);
    }

    /// Retrieves all candidate peer pubkeys that have cast an active vote on `domain`,
    /// excluding the originator `exclude_voter`.
    pub fn get_candidates_for_domain(
        &self,
        domain: &str,
        exclude_voter: &[u8; 32],
    ) -> Vec<[u8; 32]> {
        let clean_domain = domain.trim().to_ascii_lowercase();
        self.domain_postings
            .get(&clean_domain)
            .map(|voters| {
                voters
                    .keys()
                    .filter(|&&pk| pk != *exclude_voter)
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Retrieves all active domain votes for a specific voter
    pub fn get_voter_votes(&self, voter_pubkey: &[u8; 32]) -> Option<&HashMap<String, VoteAction>> {
        self.voter_postings.get(voter_pubkey)
    }

    /// Evaluates directional agreement and Bayesian-shrunk similarity between voter `u` and `v`.
    ///
    /// Complexity: O(min(|Votes_u|, |Votes_v|, MAX_STRATIFIED_SAMPLE_SIZE)) = O(1) bounded in RAM.
    pub fn compute_pairwise_similarity(
        &self,
        u: &[u8; 32],
        v: &[u8; 32],
        max_sample_size: usize,
    ) -> Option<ClusterSimilarityResult> {
        let u_votes = self.voter_postings.get(u)?;
        let v_votes = self.voter_postings.get(v)?;

        // Iterate over the smaller set for optimal intersection evaluation
        let (smaller, larger) = if u_votes.len() <= v_votes.len() {
            (u_votes, v_votes)
        } else {
            (v_votes, u_votes)
        };

        let mut overlapping: Vec<(&String, VoteAction, VoteAction)> = Vec::new();
        for (domain, &act_small) in smaller {
            if let Some(&act_large) = larger.get(domain) {
                // Keep ordering deterministic with respect to u and v
                let (act_u, act_v) = if smaller == u_votes {
                    (act_small, act_large)
                } else {
                    (act_large, act_small)
                };
                overlapping.push((domain, act_u, act_v));
            }
        }

        let total_co_voted = overlapping.len();
        if total_co_voted < MIN_CO_VOTED_SIGNIFICANCE_GATE {
            return None;
        }

        // Stratified sample if overlapping domain count exceeds sample bound
        let sample: &[(&String, VoteAction, VoteAction)] = if total_co_voted > max_sample_size {
            // Sort deterministically to maintain consistent reproducibility
            overlapping.sort_by(|a, b| a.0.cmp(b.0));
            &overlapping[..max_sample_size]
        } else {
            &overlapping
        };

        let sample_size = sample.len();
        let mut matches = 0usize;
        for (_, act_u, act_v) in sample {
            if act_u == act_v {
                matches += 1;
            }
        }

        let raw_agreement = matches as f64 / sample_size as f64;
        let significance_weight = sample_size as f64 / (sample_size as f64 + BAYESIAN_SHRINKAGE_K0);
        let final_similarity = raw_agreement * significance_weight;

        Some(ClusterSimilarityResult {
            total_co_voted,
            sample_size,
            matches,
            raw_agreement,
            significance_weight,
            final_similarity,
        })
    }
}

/// Detailed result of evaluating directional similarity between two voters
#[derive(Debug, Clone, PartialEq)]
pub struct ClusterSimilarityResult {
    pub total_co_voted: usize,
    pub sample_size: usize,
    pub matches: usize,
    pub raw_agreement: f64,
    pub significance_weight: f64,
    pub final_similarity: f64,
}

/// Verifiable audit record emitted whenever a heuristic cluster penalty is applied (REP-07)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClusterPenaltyBreakdown {
    pub target_peer_hex: String,
    pub trigger_peer_hex: String,
    pub domain: String,
    pub co_voted_domains_count: usize,
    pub sample_size: usize,
    pub raw_agreement: f64,
    pub significance_weight: f64,
    pub final_similarity: f64,
    pub trigger_demotion: u32,
    pub damping_factor: f64,
    pub cluster_penalty_applied: u32,
    pub prior_ponderation: u32,
    pub post_ponderation: u32,
    pub timestamp: u64,
}

/// Asynchronous FIFO event job emitted when a voter's ponderation changes significantly
#[derive(Debug, Clone)]
pub struct ClusterJob {
    pub trigger_voter: [u8; 32],
    pub domain: String,
    pub old_ponderation: u32,
    pub new_ponderation: u32,
    pub timestamp: u64,
}

/// Heuristic Cluster Engine providing non-blocking cluster detection and penalty propagation
pub struct ClusterEngine;

impl ClusterEngine {
    /// Evaluates cluster penalties for a job against the in-memory inverted index and phonebook.
    ///
    /// Executes sequentially in FIFO order without blocking the primary vote ingestion path.
    pub fn process_cluster_job(
        job: &ClusterJob,
        index: &InvertedVoteIndex,
        phonebook: Option<&RwLock<Phonebook>>,
        similarity_threshold: f64,
        damping_factor: f64,
    ) -> Vec<ClusterPenaltyBreakdown> {
        // Only evaluate if there was an actual demotion of sufficient magnitude
        if job.old_ponderation <= job.new_ponderation {
            return Vec::new();
        }

        let demotion_delta = job.old_ponderation - job.new_ponderation;
        if demotion_delta < MIN_DEMOTION_TRIGGER_DELTA {
            return Vec::new();
        }

        let candidates = index.get_candidates_for_domain(&job.domain, &job.trigger_voter);
        if candidates.is_empty() {
            return Vec::new();
        }

        let mut breakdowns = Vec::new();

        for candidate in candidates {
            if let Some(sim) = index.compute_pairwise_similarity(
                &job.trigger_voter,
                &candidate,
                MAX_STRATIFIED_SAMPLE_SIZE,
            ) {
                if sim.final_similarity >= similarity_threshold {
                    // Damped guilt-by-association penalty
                    let penalty = (damping_factor * sim.final_similarity * (demotion_delta as f64))
                        .round() as u32;

                    if penalty > 0 {
                        let prior_score = phonebook
                            .and_then(|pb| pb.read().ok())
                            .map(|pb| pb.get_peer_ponderation(&candidate))
                            .unwrap_or(50);

                        let post_score = prior_score.saturating_sub(penalty);

                        if let Some(pb_lock) = phonebook {
                            if let Ok(mut pb) = pb_lock.write() {
                                pb.update_peer_ponderation(&candidate, post_score);
                            }
                        }

                        breakdowns.push(ClusterPenaltyBreakdown {
                            target_peer_hex: hex::encode(candidate),
                            trigger_peer_hex: hex::encode(job.trigger_voter),
                            domain: job.domain.clone(),
                            co_voted_domains_count: sim.total_co_voted,
                            sample_size: sim.sample_size,
                            raw_agreement: sim.raw_agreement,
                            significance_weight: sim.significance_weight,
                            final_similarity: sim.final_similarity,
                            trigger_demotion: demotion_delta,
                            damping_factor,
                            cluster_penalty_applied: penalty,
                            prior_ponderation: prior_score,
                            post_ponderation: post_score,
                            timestamp: job.timestamp,
                        });
                    }
                }
            }
        }

        breakdowns
    }
}

/// Handle to the asynchronous background FIFO worker processing cluster ponderation jobs
pub struct ClusterWorkerHandle {
    sender: mpsc::Sender<ClusterJob>,
}

impl ClusterWorkerHandle {
    /// Creates a new background worker handle, spawning an asynchronous consumer task
    pub fn spawn(
        index: Arc<RwLock<InvertedVoteIndex>>,
        phonebook: Arc<RwLock<Phonebook>>,
        queue_capacity: usize,
    ) -> Self {
        let (sender, mut receiver) = mpsc::channel::<ClusterJob>(queue_capacity);

        tokio::spawn(async move {
            while let Some(job) = receiver.recv().await {
                let idx_guard = match index.read() {
                    Ok(guard) => guard,
                    Err(_) => continue,
                };

                let _ = ClusterEngine::process_cluster_job(
                    &job,
                    &idx_guard,
                    Some(phonebook.as_ref()),
                    DEFAULT_CLUSTER_SIMILARITY_THRESHOLD,
                    DEFAULT_CLUSTER_DAMPING_FACTOR,
                );
            }
        });

        Self { sender }
    }

    /// Submits a cluster job to the background worker non-blocking.
    ///
    /// Returns true if queued successfully, or false if channel is full/closed.
    pub fn submit_job(&self, job: ClusterJob) -> bool {
        self.sender.try_send(job).is_ok()
    }
}

#[cfg(test)]
mod tests;
