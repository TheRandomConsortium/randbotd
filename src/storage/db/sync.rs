use super::Database;
use crate::net::history::EventLogEntry;
use std::collections::HashMap;
use std::sync::atomic::Ordering;

impl Database {
    /// Builds local range vectors with round-robin originator offset pagination
    pub fn get_originator_range_vectors(
        &self,
        max_originators: usize,
    ) -> Vec<crate::net::history::OriginatorRangeVector> {
        let log = match self.event_log.read() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };

        let mut originator_seqs: HashMap<[u8; 32], Vec<u64>> = HashMap::new();
        for entry in log.iter() {
            originator_seqs
                .entry(entry.originator)
                .or_default()
                .push(entry.seq);
        }

        let mut originators: Vec<[u8; 32]> = originator_seqs.keys().copied().collect();
        originators.sort_unstable();

        if originators.is_empty() {
            return Vec::new();
        }

        let current_offset = self
            .sync_offset
            .fetch_add(max_originators, Ordering::Relaxed);
        let next_offset = (current_offset + max_originators) % originators.len();
        let _ = std::fs::write(&self.sync_offset_file_path, next_offset.to_string());

        let effective_offset = current_offset % originators.len();
        let target_originators = originators
            .into_iter()
            .cycle()
            .skip(effective_offset)
            .take(max_originators);

        let mut result = Vec::new();
        for originator in target_originators {
            if let Some(mut seqs) = originator_seqs.get(&originator).cloned() {
                seqs.sort_unstable();
                seqs.dedup();

                let mut ranges = Vec::new();
                if let Some(&first) = seqs.first() {
                    let mut start = first;
                    let mut prev = first;

                    for &seq in seqs.iter().skip(1) {
                        if seq == prev + 1 {
                            prev = seq;
                        } else {
                            ranges.push(crate::net::history::SequenceRange { start, end: prev });
                            start = seq;
                            prev = seq;
                        }
                    }
                    ranges.push(crate::net::history::SequenceRange { start, end: prev });
                }

                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                for entry in log.iter().filter(|e| e.originator == originator) {
                    hasher.update(entry.compute_hash());
                }
                let mut merkle_root = [0u8; 32];
                merkle_root.copy_from_slice(&hasher.finalize());

                let mut range_vec =
                    crate::net::history::OriginatorRangeVector::new(originator, ranges);
                range_vec.merkle_root = Some(merkle_root);
                result.push(range_vec);
            }
        }

        result
    }

    #[allow(dead_code)]
    pub fn compute_originator_merkle_root(&self, originator: &[u8; 32]) -> Option<[u8; 32]> {
        if let Ok(log) = self.event_log.read() {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            let mut count = 0;
            for entry in log.iter().filter(|e| &e.originator == originator) {
                hasher.update(entry.compute_hash());
                count += 1;
            }
            if count == 0 {
                return None;
            }
            let mut root = [0u8; 32];
            root.copy_from_slice(&hasher.finalize());
            Some(root)
        } else {
            None
        }
    }

    /// Evaluates peer range vectors against local DB to find local entries the peer is missing (bounded by max_entries)
    pub fn find_missing_entries_for_peer(
        &self,
        peer_vectors: &[crate::net::history::OriginatorRangeVector],
        max_entries: usize,
    ) -> Vec<EventLogEntry> {
        use sha2::{Digest, Sha256};
        let log = match self.event_log.read() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };

        let peer_map: HashMap<[u8; 32], &crate::net::history::OriginatorRangeVector> =
            peer_vectors.iter().map(|v| (v.originator, v)).collect();

        // Single linear O(N) pass to precalculate per-originator local Merkle roots
        let mut hasher_map: HashMap<[u8; 32], Sha256> = HashMap::new();
        for entry in log.iter() {
            hasher_map
                .entry(entry.originator)
                .or_default()
                .update(entry.compute_hash());
        }
        let local_roots: HashMap<[u8; 32], [u8; 32]> = hasher_map
            .into_iter()
            .map(|(orig, hasher)| {
                let mut root = [0u8; 32];
                root.copy_from_slice(&hasher.finalize());
                (orig, root)
            })
            .collect();

        let mut missing = Vec::new();
        for entry in log.iter() {
            if missing.len() >= max_entries {
                break;
            }
            if let Some(peer_vec) = peer_map.get(&entry.originator) {
                let local_root = local_roots.get(&entry.originator).copied();
                let merkle_mismatch =
                    peer_vec.merkle_root.is_some() && peer_vec.merkle_root != local_root;

                if !peer_vec.has_sequence(entry.seq)
                    || (merkle_mismatch
                        && (entry.payload_type
                            == crate::net::gossip::PAYLOAD_TYPE_EQUIVOCATION_PROOF
                            || entry.is_bullshit))
                {
                    missing.push(entry.clone());
                }
            } else {
                missing.push(entry.clone());
            }
        }

        missing
    }
}
