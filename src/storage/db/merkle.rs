use crate::net::history::{MerkleNode, SequenceRange};
use crate::storage::db::Database;
use sha2::{Digest, Sha256};

impl Database {
    /// Returns the left and right child Merkle nodes for a given subtree sequence range
    pub fn get_merkle_children(
        &self,
        originator: &[u8; 32],
        target_range: &SequenceRange,
    ) -> (Option<MerkleNode>, Option<MerkleNode>) {
        if target_range.start >= target_range.end {
            return (None, None);
        }

        let mid = target_range.start + (target_range.end - target_range.start) / 2;
        let left_range = SequenceRange {
            start: target_range.start,
            end: mid,
        };
        let right_range = SequenceRange {
            start: mid + 1,
            end: target_range.end,
        };

        let log = match self.event_log.read() {
            Ok(guard) => guard,
            Err(_) => return (None, None),
        };

        let compute_sub_root = |r: &SequenceRange| {
            let mut hasher = Sha256::new();
            let mut count = 0;
            for entry in log
                .iter()
                .filter(|e| &e.originator == originator && r.contains(e.seq))
            {
                hasher.update(entry.compute_hash());
                count += 1;
            }
            if count > 0 {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&hasher.finalize());
                Some(MerkleNode {
                    hash,
                    range: r.clone(),
                })
            } else {
                None
            }
        };

        (
            compute_sub_root(&left_range),
            compute_sub_root(&right_range),
        )
    }

    /// Computes the SHA-256 Merkle hash across all stored events for an originator in range [start..=end] (with LRU caching)
    pub fn compute_merkle_hash_for_range(
        &self,
        originator: &[u8; 32],
        range: &SequenceRange,
    ) -> Option<[u8; 32]> {
        if let Ok(cache) = self.merkle_cache.read() {
            if let Some(cached_res) = cache.get(&(*originator, range.clone())) {
                return *cached_res;
            }
        }

        let log = match self.event_log.read() {
            Ok(guard) => guard,
            Err(_) => return None,
        };

        let mut hasher = Sha256::new();
        let mut count = 0;
        for entry in log
            .iter()
            .filter(|e| &e.originator == originator && range.contains(e.seq))
        {
            hasher.update(entry.compute_hash());
            count += 1;
        }

        let res = if count > 0 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hasher.finalize());
            Some(hash)
        } else {
            None
        };

        if let Ok(mut cache) = self.merkle_cache.write() {
            cache.insert((*originator, range.clone()), res);
        }

        res
    }
}
