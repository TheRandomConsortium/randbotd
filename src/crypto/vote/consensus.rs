//! Domain Consensus Engine & Caching Layer (REP-04)
//!
//! Tracks and caches network-wide consensus direction and confidence per domain,
//! decoupling voter alignment calculations from recursive peer queries.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::crypto::vote::{VoteAction, VoteRecord};

/// Consensus outcome direction for a domain
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusDirection {
    #[serde(rename = "TW")]
    Tw,
    #[serde(rename = "UTW")]
    Utw,
    #[serde(rename = "UNDECIDED")]
    Undecided,
}

impl ConsensusDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConsensusDirection::Tw => "TW",
            ConsensusDirection::Utw => "UTW",
            ConsensusDirection::Undecided => "UNDECIDED",
        }
    }
}

impl std::fmt::Display for ConsensusDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Cached consensus state for a specific domain across all active peer votes
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomainConsensus {
    /// Domain name
    pub domain: String,
    /// Number of active TW votes
    pub tw_count: usize,
    /// Number of active UTW votes
    pub utw_count: usize,
    /// Sum of weighted TW voter ponderations
    pub tw_weight_sum: f64,
    /// Sum of weighted UTW voter ponderations
    pub utw_weight_sum: f64,
    /// Total active votes on this domain
    pub total_active_votes: usize,
    /// Majority direction
    pub direction: ConsensusDirection,
    /// Statistical confidence metric in [0.0, 1.0]: |TW - UTW| / (TW + UTW)
    pub confidence: f64,
    /// Unix timestamp when this consensus was computed
    pub last_updated_timestamp: u64,
}

impl DomainConsensus {
    /// Creates a neutral, undecided consensus record for a domain with no votes
    pub fn new_empty(domain: &str, timestamp: u64) -> Self {
        Self {
            domain: domain.trim().to_ascii_lowercase(),
            tw_count: 0,
            utw_count: 0,
            tw_weight_sum: 0.0,
            utw_weight_sum: 0.0,
            total_active_votes: 0,
            direction: ConsensusDirection::Undecided,
            confidence: 0.0,
            last_updated_timestamp: timestamp,
        }
    }

    /// Computes domain consensus from active votes paired with their voter ponderation weights
    pub fn from_weighted_votes(
        domain: &str,
        votes_with_weights: &[(&VoteRecord, u32)],
        timestamp: u64,
    ) -> Self {
        let clean_domain = domain.trim().to_ascii_lowercase();
        let mut tw_count = 0usize;
        let mut utw_count = 0usize;
        let mut tw_weight_sum = 0.0f64;
        let mut utw_weight_sum = 0.0f64;

        for (vote, weight) in votes_with_weights {
            let w = *weight as f64;
            match vote.action {
                VoteAction::Tw => {
                    tw_count += 1;
                    tw_weight_sum += w;
                }
                VoteAction::Utw => {
                    utw_count += 1;
                    utw_weight_sum += w;
                }
            }
        }

        let total_active_votes = tw_count + utw_count;
        let total_weight = tw_weight_sum + utw_weight_sum;

        let (direction, confidence) = if total_weight > 0.0 {
            let diff = (tw_weight_sum - utw_weight_sum).abs();
            let conf = (diff / total_weight).clamp(0.0, 1.0);
            let dir = if (tw_weight_sum - utw_weight_sum).abs() < f64::EPSILON {
                ConsensusDirection::Undecided
            } else if tw_weight_sum > utw_weight_sum {
                ConsensusDirection::Tw
            } else {
                ConsensusDirection::Utw
            };
            (dir, conf)
        } else if total_active_votes > 0 {
            // Fallback unweighted count if weights happen to be 0
            let diff = (tw_count as f64 - utw_count as f64).abs();
            let conf = (diff / total_active_votes as f64).clamp(0.0, 1.0);
            let dir = if tw_count > utw_count {
                ConsensusDirection::Tw
            } else if utw_count > tw_count {
                ConsensusDirection::Utw
            } else {
                ConsensusDirection::Undecided
            };
            (dir, conf)
        } else {
            (ConsensusDirection::Undecided, 0.0)
        };

        Self {
            domain: clean_domain,
            tw_count,
            utw_count,
            tw_weight_sum,
            utw_weight_sum,
            total_active_votes,
            direction,
            confidence: (confidence * 1000.0).round() / 1000.0,
            last_updated_timestamp: timestamp,
        }
    }

    /// Evaluates how aligned a given vote action is with this cached consensus:
    /// Returns value in [-1.0, 1.0] scaled by the consensus confidence sigma.
    pub fn alignment_score(&self, action: VoteAction) -> f64 {
        match self.direction {
            ConsensusDirection::Tw => {
                if action.is_tw() {
                    self.confidence
                } else {
                    -self.confidence
                }
            }
            ConsensusDirection::Utw => {
                if action.is_utw() {
                    self.confidence
                } else {
                    -self.confidence
                }
            }
            ConsensusDirection::Undecided => 0.0,
        }
    }
}

/// In-memory cache of domain consensus records to accelerate lazy evaluation
#[derive(Debug, Clone, Default)]
pub struct DomainConsensusCache {
    entries: HashMap<String, DomainConsensus>,
}

impl DomainConsensusCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn get(&self, domain: &str) -> Option<&DomainConsensus> {
        let clean = domain.trim().to_ascii_lowercase();
        self.entries.get(&clean)
    }

    pub fn insert(&mut self, consensus: DomainConsensus) {
        self.entries.insert(consensus.domain.clone(), consensus);
    }

    pub fn remove(&mut self, domain: &str) -> Option<DomainConsensus> {
        let clean = domain.trim().to_ascii_lowercase();
        self.entries.remove(&clean)
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
