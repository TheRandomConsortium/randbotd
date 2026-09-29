use std::collections::{HashMap, HashSet};

use crate::crypto::vote::{VoteRecord, ACTIVE_VOTES_ROLLING_WINDOW_SECS};
use crate::storage::db::ca_subtable::bytes32_to_hex;
use crate::storage::db::Database;
use serde::{Deserialize, Serialize};

/// Summary of domain reputation votes across the network and local voter node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainVoteStatus {
    pub domain: String,
    pub has_voted: bool,
    pub my_vote: Option<VoteRecord>,
    pub revisions_on_domain: usize,
    pub total_active_votes: usize,
    pub tw_count: usize,
    pub utw_count: usize,
}

impl Database {
    /// Inserts and validates a VoteRecord into the vote subtable and persists to disk.
    ///
    /// Enforces monotonic sequence continuity, strict hash linking, and logarithmic difficulty consensus.
    pub fn insert_vote(&self, vote: VoteRecord) -> Result<[u8; 32], String> {
        let vote_id = vote.vote_id;

        let export_map: HashMap<String, VoteRecord> = {
            let mut store = self
                .vote_store
                .write()
                .map_err(|e| format!("Lock poison error on vote_store: {}", e))?;

            if store.contains_key(&vote_id) {
                return Ok(vote_id);
            }

            // 1. Gather all prior votes for this originator sorted by vote_seq
            let mut originator_votes: Vec<VoteRecord> = store
                .values()
                .filter(|v| v.voter_pubkey == vote.voter_pubkey)
                .cloned()
                .collect();
            originator_votes.sort_by_key(|v| v.vote_seq);

            let latest_opt = originator_votes.last();

            // 2. Validate sequence continuity against latest vote in database
            match latest_opt {
                None => {
                    if vote.vote_seq != 1 {
                        return Err(format!(
                            "Discontinuous vote sequence: first vote for voter {:02x?} must have vote_seq = 1, found {}",
                            &vote.voter_pubkey[..4],
                            vote.vote_seq
                        ));
                    }
                    if vote.prev_vote_hash != [0u8; 32] {
                        return Err(
                            "First vote for voter must have prev_vote_hash = [0; 32]".to_string()
                        );
                    }
                }
                Some(latest) => {
                    if vote.vote_seq != latest.vote_seq + 1 {
                        return Err(format!(
                            "Discontinuous vote sequence: expected seq {}, found {} (previous monotonic vote not received yet)",
                            latest.vote_seq + 1,
                            vote.vote_seq
                        ));
                    }
                    if vote.prev_vote_hash != latest.vote_id {
                        return Err(format!(
                            "Broken vote hash link: expected prev {:02x?}, found {:02x?}",
                            &latest.vote_id[..4],
                            &vote.prev_vote_hash[..4]
                        ));
                    }
                    if vote.timestamp < latest.timestamp {
                        return Err(format!(
                            "Non-monotonic vote timestamp: current {} < previous {}",
                            vote.timestamp, latest.timestamp
                        ));
                    }
                }
            }

            // 3. Compute active distinct domains count and revisions on this domain before this vote,
            // filtered by the rolling window anchored in latest.timestamp (if any).
            let window_cutoff = latest_opt
                .map(|latest| {
                    latest
                        .timestamp
                        .saturating_sub(ACTIVE_VOTES_ROLLING_WINDOW_SECS)
                })
                .unwrap_or(0);

            let mut active_domains = HashSet::new();
            let mut revisions_on_domain = 0usize;
            for prior in &originator_votes {
                if prior.timestamp >= window_cutoff {
                    active_domains.insert(prior.domain.clone());
                    if prior.domain == vote.domain {
                        revisions_on_domain += 1;
                    }
                }
            }
            let active_votes_count_before = active_domains.len();

            // 4. Validate against chain rules (challenge binding, PoW difficulty, and signature)
            vote.validate_against_chain(
                latest_opt,
                active_votes_count_before,
                revisions_on_domain,
            )?;

            store.insert(vote_id, vote);

            store
                .iter()
                .map(|(k, v)| (bytes32_to_hex(k), v.clone()))
                .collect()
        };

        let json_data = serde_json::to_string_pretty(&export_map)
            .map_err(|e| format!("Failed to serialize vote_store: {}", e))?;
        std::fs::write(&self.vote_file_path, json_data)
            .map_err(|e| format!("Failed to write domain_votes file: {}", e))?;

        Ok(vote_id)
    }

    /// Retrieves a VoteRecord by its vote_id
    pub fn get_vote(&self, vote_id: &[u8; 32]) -> Option<VoteRecord> {
        self.vote_store
            .read()
            .ok()
            .and_then(|store| store.get(vote_id).cloned())
    }

    /// Retrieves all historical votes cast by a specific voter, sorted sequentially (seq 1, 2, 3...)
    pub fn get_votes_for_originator(&self, originator: &[u8; 32]) -> Vec<VoteRecord> {
        let mut votes: Vec<VoteRecord> = self
            .vote_store
            .read()
            .map(|store| {
                store
                    .values()
                    .filter(|v| &v.voter_pubkey == originator)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        votes.sort_by_key(|v| v.vote_seq);
        votes
    }

    /// Retrieves the most recent vote (highest vote_seq) cast by a specific voter
    pub fn get_latest_vote_for_originator(&self, originator: &[u8; 32]) -> Option<VoteRecord> {
        self.get_votes_for_originator(originator).pop()
    }

    /// Retrieves vote context for an originator and domain:
    /// Returns (latest_vote, active_votes_count, revisions_on_domain)
    pub fn get_vote_context(
        &self,
        originator: &[u8; 32],
        domain: &str,
    ) -> (Option<VoteRecord>, usize, usize) {
        let clean_domain = domain.trim().to_ascii_lowercase();
        let votes = self.get_votes_for_originator(originator);
        let latest = votes.last().cloned();

        let window_cutoff = latest
            .as_ref()
            .map(|l| l.timestamp.saturating_sub(ACTIVE_VOTES_ROLLING_WINDOW_SECS))
            .unwrap_or(0);

        let mut active_domains = HashSet::new();
        let mut revisions = 0usize;
        for v in &votes {
            if v.timestamp >= window_cutoff {
                active_domains.insert(v.domain.clone());
                if v.domain == clean_domain {
                    revisions += 1;
                }
            }
        }

        (latest, active_domains.len(), revisions)
    }

    /// Retrieves the single active vote for a specific (originator, domain) pair (REP-02 1-vote-per-node)
    pub fn get_active_vote_for_originator_and_domain(
        &self,
        originator: &[u8; 32],
        domain: &str,
    ) -> Option<VoteRecord> {
        let clean_domain = domain.trim().to_ascii_lowercase();
        let votes = self.get_votes_for_originator(originator);
        votes.into_iter().rev().find(|v| v.domain == clean_domain)
    }

    /// Retrieves the comprehensive vote status for a domain, answering if local node has voted
    pub fn get_domain_vote_status(
        &self,
        my_pubkey: Option<&[u8; 32]>,
        domain: &str,
    ) -> DomainVoteStatus {
        let clean_domain = domain.trim().to_ascii_lowercase();

        // 1. Determine local node's active vote and revision count
        let (my_vote, revisions_on_domain) = match my_pubkey {
            Some(pk) => {
                let active = self.get_active_vote_for_originator_and_domain(pk, &clean_domain);
                let votes = self.get_votes_for_originator(pk);
                let window_cutoff = votes
                    .last()
                    .map(|l| l.timestamp.saturating_sub(ACTIVE_VOTES_ROLLING_WINDOW_SECS))
                    .unwrap_or(0);
                let revs = votes
                    .iter()
                    .filter(|v| v.domain == clean_domain && v.timestamp >= window_cutoff)
                    .count();
                (active, revs)
            }
            None => (None, 0),
        };

        let has_voted = my_vote.is_some();

        // 2. Aggregate active votes across all network voters for this domain
        let active_votes = self.list_active_domain_votes(Some(&clean_domain), None);
        let total_active_votes = active_votes.len();
        let tw_count = active_votes.iter().filter(|v| v.action.is_tw()).count();
        let utw_count = active_votes.iter().filter(|v| v.action.is_utw()).count();

        DomainVoteStatus {
            domain: clean_domain,
            has_voted,
            my_vote,
            revisions_on_domain,
            total_active_votes,
            tw_count,
            utw_count,
        }
    }

    /// Lists active votes matching optional domain and/or voter filters
    pub fn list_active_domain_votes(
        &self,
        domain_filter: Option<&str>,
        voter_filter: Option<&[u8; 32]>,
    ) -> Vec<VoteRecord> {
        let store = match self.vote_store.read() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let clean_domain_opt = domain_filter.map(|d| d.trim().to_ascii_lowercase());

        // Group votes by (originator, domain) and keep the highest vote_seq (the active vote)
        let mut active_map: HashMap<([u8; 32], String), VoteRecord> = HashMap::new();
        for vote in store.values() {
            if let Some(ref d) = clean_domain_opt {
                if &vote.domain != d {
                    continue;
                }
            }
            if let Some(v) = voter_filter {
                if &vote.voter_pubkey != v {
                    continue;
                }
            }

            let key = (vote.voter_pubkey, vote.domain.clone());
            match active_map.get(&key) {
                Some(existing) if existing.vote_seq < vote.vote_seq => {
                    active_map.insert(key, vote.clone());
                }
                None => {
                    active_map.insert(key, vote.clone());
                }
                _ => {}
            }
        }

        let mut results: Vec<VoteRecord> = active_map.into_values().collect();
        results.sort_by(|a, b| a.domain.cmp(&b.domain).then(a.vote_seq.cmp(&b.vote_seq)));
        results
    }

    /// Lists all raw vote records in the store
    pub fn list_all_votes(&self) -> Vec<VoteRecord> {
        self.vote_store
            .read()
            .map(|store| store.values().cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::vote::VoteAction;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_vote_subtable_insert_and_mind_change_active_state() {
        let temp_dir =
            std::env::temp_dir().join(format!("randbotd_vote_test_{}", rand::random::<u64>()));
        let db = Database::open(&temp_dir).expect("Database should open");

        let signing_key = SigningKey::from_bytes(&[0x12u8; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();

        // 1. Initial status: has not voted
        let status0 = db.get_domain_vote_status(Some(&pubkey), "wiki.hns");
        assert!(!status0.has_voted);
        assert_eq!(status0.total_active_votes, 0);

        // 2. Cast vote 1: TW for wiki.hns
        let vote1 = VoteRecord::new_signed(
            &signing_key,
            "wiki.hns",
            VoteAction::Tw,
            1,
            [0u8; 32],
            1000,
            0,
            0,
        )
        .unwrap();

        db.insert_vote(vote1.clone()).expect("Insert vote 1");

        let status1 = db.get_domain_vote_status(Some(&pubkey), "wiki.hns");
        assert!(status1.has_voted);
        assert_eq!(status1.my_vote.as_ref().unwrap().action, VoteAction::Tw);
        assert_eq!(status1.revisions_on_domain, 1);
        assert_eq!(status1.total_active_votes, 1);
        assert_eq!(status1.tw_count, 1);
        assert_eq!(status1.utw_count, 0);

        // 3. Flip vote (mind-change) to UTW (seq 2, chained from vote 1)
        let (prev, active_count, revs) = db.get_vote_context(&pubkey, "wiki.hns");
        assert_eq!(prev.as_ref().unwrap().vote_id, vote1.vote_id);
        assert_eq!(active_count, 1);
        assert_eq!(revs, 1);

        let vote2 = VoteRecord::new_signed(
            &signing_key,
            "wiki.hns",
            VoteAction::Utw,
            2,
            vote1.vote_id,
            1020,
            active_count,
            revs,
        )
        .unwrap();

        db.insert_vote(vote2.clone())
            .expect("Insert flipped vote 2");

        let status2 = db.get_domain_vote_status(Some(&pubkey), "wiki.hns");
        assert!(status2.has_voted);
        assert_eq!(status2.my_vote.as_ref().unwrap().action, VoteAction::Utw);
        assert_eq!(status2.revisions_on_domain, 2);
        // Crucial invariant: total active votes is still 1! (1 vote per node)
        assert_eq!(status2.total_active_votes, 1);
        assert_eq!(status2.tw_count, 0);
        assert_eq!(status2.utw_count, 1);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_vote_subtable_discontinuous_sequence_rejection() {
        let temp_dir =
            std::env::temp_dir().join(format!("randbotd_vote_disc_test_{}", rand::random::<u64>()));
        let db = Database::open(&temp_dir).expect("Database should open");

        let signing_key = SigningKey::from_bytes(&[0x34u8; 32]);

        // Attempt to insert seq 2 directly without seq 1
        let vote2 = VoteRecord::new_signed(
            &signing_key,
            "test.rand",
            VoteAction::Tw,
            2,
            [0x88u8; 32],
            1000,
            0,
            0,
        )
        .unwrap();

        let err = db.insert_vote(vote2).unwrap_err();
        assert!(err.contains("Discontinuous vote sequence"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_vote_subtable_rolling_window_cooldown() {
        let temp_dir =
            std::env::temp_dir().join(format!("randbotd_vote_cooldown_{}", rand::random::<u64>()));
        let db = Database::open(&temp_dir).expect("Database should open");
        let signing_key = SigningKey::from_bytes(&[0x45u8; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();

        let t0 = 1_000_000u64;
        let vote1 = VoteRecord::new_signed(
            &signing_key,
            "old-domain.rand",
            VoteAction::Tw,
            1,
            [0u8; 32],
            t0,
            0,
            0,
        )
        .unwrap();
        db.insert_vote(vote1.clone()).unwrap();

        // Vote 2 cast 366 days later (> ACTIVE_VOTES_ROLLING_WINDOW_SECS)
        let t1 = t0 + ACTIVE_VOTES_ROLLING_WINDOW_SECS + 100;
        let (prev, active_count, revs) = db.get_vote_context(&pubkey, "intermediate.rand");
        assert_eq!(prev.as_ref().unwrap().vote_id, vote1.vote_id);
        assert_eq!(active_count, 1);
        assert_eq!(revs, 0);

        let vote2 = VoteRecord::new_signed(
            &signing_key,
            "intermediate.rand",
            VoteAction::Tw,
            2,
            vote1.vote_id,
            t1,
            active_count,
            revs,
        )
        .unwrap();
        db.insert_vote(vote2.clone()).unwrap();

        // Now context for old-domain.rand is evaluated with latest = vote2 (timestamp = t1).
        // Since vote1 timestamp (t0) is < t1 - 1_year, vote1 has rolled out!
        let (latest, active_count3, revs3) = db.get_vote_context(&pubkey, "old-domain.rand");
        assert_eq!(latest.as_ref().unwrap().vote_id, vote2.vote_id);
        // Only intermediate.rand is in the 1-year window
        assert_eq!(active_count3, 1);
        // Revisions for old-domain.rand cooled down to 0
        assert_eq!(revs3, 0);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
