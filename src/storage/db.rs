use crate::net::history::EventLogEntry;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

/// Transactional embedded storage engine for randbotd
#[allow(dead_code)]
pub struct Database {
    db_file_path: PathBuf,
    sync_offset_file_path: PathBuf,
    event_log: RwLock<Vec<EventLogEntry>>,
    sync_offset: AtomicUsize,
}

#[allow(dead_code)]
impl Database {
    /// Opens or initializes the embedded database in `state_dir`
    pub fn open(state_dir: &Path) -> Result<Self, String> {
        if !state_dir.exists() {
            std::fs::create_dir_all(state_dir)
                .map_err(|e| format!("Failed to create state directory: {}", e))?;
        }

        let db_file_path = state_dir.join("event_log.jsonl");
        let sync_offset_file_path = state_dir.join("sync_offset.state");
        let mut entries = Vec::new();

        if db_file_path.exists() {
            let file = File::open(&db_file_path)
                .map_err(|e| format!("Failed to open event_log file: {}", e))?;
            let reader = BufReader::new(file);

            for (line_num, line) in reader.lines().enumerate() {
                let line_str =
                    line.map_err(|e| format!("Error reading line {}: {}", line_num, e))?;
                if line_str.trim().is_empty() {
                    continue;
                }

                let entry: EventLogEntry = serde_json::from_str(&line_str)
                    .map_err(|e| format!("Invalid JSON on line {}: {}", line_num, e))?;

                // Validate signature and transient payload rule
                if EventLogEntry::is_transient(entry.payload_type) {
                    return Err(format!(
                        "Corruption error: Line {} contains transient payload type 0x{:02x}",
                        line_num, entry.payload_type
                    ));
                }

                entry
                    .verify_signature()
                    .map_err(|e| format!("Signature corruption on line {}: {}", line_num, e))?;

                entries.push(entry);
            }
        }

        let initial_offset = if sync_offset_file_path.exists() {
            std::fs::read_to_string(&sync_offset_file_path)
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok())
                .unwrap_or(0)
        } else {
            0
        };

        Ok(Self {
            db_file_path,
            sync_offset_file_path,
            event_log: RwLock::new(entries),
            sync_offset: AtomicUsize::new(initial_offset),
        })
    }

    /// Appends a verified consensus EventLogEntry to the database
    pub fn append_event(&self, entry: EventLogEntry) -> Result<(), String> {
        if EventLogEntry::is_transient(entry.payload_type) {
            return Err(format!(
                "Payload type 0x{:02x} is transient and cannot be saved to database",
                entry.payload_type
            ));
        }

        entry
            .verify_signature()
            .map_err(|e| format!("Invalid event signature: {}", e))?;

        let mut log = self
            .event_log
            .write()
            .map_err(|_| "Database rwlock poisoned".to_string())?;

        // Per-originator monotonic sequence and prev_hash verification
        let (expected_seq, expected_prev_hash) = log
            .iter()
            .rev()
            .find(|e| e.originator == entry.originator)
            .map(|e| (e.seq + 1, e.compute_hash()))
            .unwrap_or((1, [0u8; 32]));

        if entry.seq != expected_seq {
            return Err(format!(
                "Per-originator sequence mismatch for node {:02x?}: expected {}, got {}",
                &entry.originator[..4],
                expected_seq,
                entry.seq
            ));
        }

        if entry.prev_hash != expected_prev_hash {
            return Err(format!(
                "Per-originator prev_hash link mismatch for node {:02x?}",
                &entry.originator[..4]
            ));
        }

        // Persist to disk
        let json_line = serde_json::to_string(&entry)
            .map_err(|e| format!("Failed to serialize EventLogEntry: {}", e))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.db_file_path)
            .map_err(|e| format!("Failed to open DB file for writing: {}", e))?;

        writeln!(file, "{}", json_line)
            .map_err(|e| format!("Failed to write event line to DB: {}", e))?;
        file.sync_all()
            .map_err(|e| format!("Failed to sync DB file to disk: {}", e))?;

        log.push(entry);
        Ok(())
    }

    /// Fetches a sequential range of EventLogEntry items [start_seq..=end_seq] for anti-entropy sync
    pub fn get_event_range(&self, start_seq: u64, end_seq: u64) -> Vec<EventLogEntry> {
        let log = match self.event_log.read() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };

        log.iter()
            .filter(|e| e.seq >= start_seq && e.seq <= end_seq)
            .cloned()
            .collect()
    }

    /// Gets the current latest sequence number (0 if empty)
    pub fn latest_seq(&self) -> u64 {
        self.event_log
            .read()
            .map(|log| log.last().map(|e| e.seq).unwrap_or(0))
            .unwrap_or(0)
    }

    /// Gets the current head hash of the event log chain
    pub fn head_hash(&self) -> [u8; 32] {
        self.event_log
            .read()
            .map(|log| log.last().map(|e| e.compute_hash()).unwrap_or([0u8; 32]))
            .unwrap_or([0u8; 32])
    }

    /// Builds per-originator range vectors with persistent round-robin offset pagination for UDP safety & 100% swarm convergence
    pub fn get_originator_range_vectors(
        &self,
        max_originators: usize,
    ) -> Vec<crate::net::history::OriginatorRangeVector> {
        use std::collections::HashMap;
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
        originators.sort_unstable(); // Deterministic ordering across sync cycles!

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

                // Compute Merkle Root across events for this originator
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

    /// Evaluates peer range vectors against local DB to find local entries the peer is missing
    pub fn find_missing_entries_for_peer(
        &self,
        peer_vectors: &[crate::net::history::OriginatorRangeVector],
    ) -> Vec<EventLogEntry> {
        use std::collections::HashMap;
        let log = match self.event_log.read() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };

        let peer_map: HashMap<[u8; 32], &crate::net::history::OriginatorRangeVector> =
            peer_vectors.iter().map(|v| (v.originator, v)).collect();

        let mut missing = Vec::new();
        for entry in log.iter() {
            if let Some(peer_vec) = peer_map.get(&entry.originator) {
                if !peer_vec.has_sequence(entry.seq) {
                    missing.push(entry.clone());
                }
            } else {
                missing.push(entry.clone());
            }
        }

        missing
    }

    /// Returns the left and right child Merkle nodes for a given subtree sequence range
    pub fn get_merkle_children(
        &self,
        originator: &[u8; 32],
        target_range: &crate::net::history::SequenceRange,
    ) -> (
        Option<crate::net::history::MerkleNode>,
        Option<crate::net::history::MerkleNode>,
    ) {
        use sha2::{Digest, Sha256};
        if target_range.start >= target_range.end {
            return (None, None);
        }

        let mid = target_range.start + (target_range.end - target_range.start) / 2;
        let left_range = crate::net::history::SequenceRange {
            start: target_range.start,
            end: mid,
        };
        let right_range = crate::net::history::SequenceRange {
            start: mid + 1,
            end: target_range.end,
        };

        let log = match self.event_log.read() {
            Ok(guard) => guard,
            Err(_) => return (None, None),
        };

        let compute_sub_root = |r: &crate::net::history::SequenceRange| {
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
                Some(crate::net::history::MerkleNode {
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

    /// Computes the SHA-256 Merkle hash across all stored events for an originator in range [start..=end]
    pub fn compute_merkle_hash_for_range(
        &self,
        originator: &[u8; 32],
        range: &crate::net::history::SequenceRange,
    ) -> Option<[u8; 32]> {
        use sha2::{Digest, Sha256};
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

        if count > 0 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hasher.finalize());
            Some(hash)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn test_database_event_log_roundtrip() {
        use rand::RngCore;
        let temp_dir =
            std::env::temp_dir().join(format!("randbotd_db_test_{}", rand::random::<u64>()));
        let db = Database::open(&temp_dir).expect("Failed to open database");

        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let originator = signing_key.verifying_key().to_bytes();

        let seq = 1u64;
        let prev_hash = [0u8; 32];
        let payload_type = 0x02u8; // VOTE
        let payload = b"TW_vote_domain.hns".to_vec();

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&seq.to_be_bytes());
        signed_data.extend_from_slice(&prev_hash);
        signed_data.push(payload_type);
        signed_data.extend_from_slice(&payload);

        let signature_bytes = signing_key.sign(&signed_data).to_bytes().to_vec();

        let entry = EventLogEntry::new(
            seq,
            prev_hash,
            originator,
            payload_type,
            payload,
            signature_bytes,
        )
        .expect("Failed to construct entry");

        db.append_event(entry.clone())
            .expect("Failed to append event");

        assert_eq!(db.latest_seq(), 1);
        let range = db.get_event_range(1, 1);
        assert_eq!(range.len(), 1);
        assert_eq!(range[0].seq, 1);

        // Re-open DB to test disk persistence
        let db_reopened = Database::open(&temp_dir).expect("Failed to re-open database");
        assert_eq!(db_reopened.latest_seq(), 1);
        let range_reopened = db_reopened.get_event_range(1, 1);
        assert_eq!(range_reopened.len(), 1);
        assert_eq!(range_reopened[0], entry);

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_database_per_originator_interleaved_events() {
        let temp_dir = std::env::temp_dir().join(format!(
            "randbotd_db_interleaved_test_{}",
            rand::random::<u64>()
        ));
        let db = Database::open(&temp_dir).expect("Failed to open database");

        // Node A
        let secret_a = [0x01u8; 32];
        let signing_key_a = SigningKey::from_bytes(&secret_a);
        let originator_a = signing_key_a.verifying_key().to_bytes();

        // Node B
        let secret_b = [0x02u8; 32];
        let signing_key_b = SigningKey::from_bytes(&secret_b);
        let originator_b = signing_key_b.verifying_key().to_bytes();

        // Entry A1 (seq=1, prev_hash=0)
        let mut data_a1 = Vec::new();
        data_a1.extend_from_slice(&1u64.to_be_bytes());
        data_a1.extend_from_slice(&[0u8; 32]);
        data_a1.push(0x02); // VOTE
        data_a1.extend_from_slice(b"vote_a1");
        let sig_a1 = signing_key_a.sign(&data_a1).to_bytes().to_vec();
        let entry_a1 = EventLogEntry::new(
            1,
            [0u8; 32],
            originator_a,
            0x02,
            b"vote_a1".to_vec(),
            sig_a1,
        )
        .unwrap();
        db.append_event(entry_a1.clone()).unwrap();

        // Entry B1 (seq=1, prev_hash=0) - Interleaved from Node B!
        let mut data_b1 = Vec::new();
        data_b1.extend_from_slice(&1u64.to_be_bytes());
        data_b1.extend_from_slice(&[0u8; 32]);
        data_b1.push(0x02);
        data_b1.extend_from_slice(b"vote_b1");
        let sig_b1 = signing_key_b.sign(&data_b1).to_bytes().to_vec();
        let entry_b1 = EventLogEntry::new(
            1,
            [0u8; 32],
            originator_b,
            0x02,
            b"vote_b1".to_vec(),
            sig_b1,
        )
        .unwrap();
        db.append_event(entry_b1).unwrap();

        // Entry A2 (seq=2, prev_hash=entry_a1.compute_hash())
        let prev_hash_a1 = entry_a1.compute_hash();
        let mut data_a2 = Vec::new();
        data_a2.extend_from_slice(&2u64.to_be_bytes());
        data_a2.extend_from_slice(&prev_hash_a1);
        data_a2.push(0x02);
        data_a2.extend_from_slice(b"vote_a2");
        let sig_a2 = signing_key_a.sign(&data_a2).to_bytes().to_vec();
        let entry_a2 = EventLogEntry::new(
            2,
            prev_hash_a1,
            originator_a,
            0x02,
            b"vote_a2".to_vec(),
            sig_a2,
        )
        .unwrap();

        // This MUST succeed because seq=2 and prev_hash match Node A's chain!
        db.append_event(entry_a2).unwrap();

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
