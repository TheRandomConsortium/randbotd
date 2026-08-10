use crate::net::history::EventLogEntry;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

pub mod merkle;

pub const MAX_STAGED_EVENTS: usize = 50;

type MerkleCacheMap = RwLock<
    std::collections::HashMap<([u8; 32], crate::net::history::SequenceRange), Option<[u8; 32]>>,
>;

type PendingStagingMap = RwLock<std::collections::HashMap<[u8; 32], Vec<EventLogEntry>>>;

/// Transactional embedded storage engine for randbotd
#[allow(dead_code)]
pub struct Database {
    db_file_path: PathBuf,
    sync_offset_file_path: PathBuf,
    event_log: RwLock<Vec<EventLogEntry>>,
    pending_unverified: PendingStagingMap,
    sync_offset: AtomicUsize,
    merkle_cache: MerkleCacheMap,
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
            pending_unverified: RwLock::new(std::collections::HashMap::new()),
            sync_offset: AtomicUsize::new(initial_offset),
            merkle_cache: RwLock::new(std::collections::HashMap::new()),
        })
    }

    fn persist_and_append_entry(
        &self,
        log: &mut Vec<EventLogEntry>,
        entry: EventLogEntry,
    ) -> Result<(), String> {
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

    pub fn get_originator_reputation(&self, originator: &[u8; 32]) -> (usize, usize) {
        if let Ok(log) = self.event_log.read() {
            let mut valid = 0;
            let mut bullshit = 0;
            for e in log.iter().filter(|e| &e.originator == originator) {
                if e.is_bullshit {
                    bullshit += 1;
                } else {
                    valid += 1;
                }
            }
            (valid, bullshit)
        } else {
            (0, 0)
        }
    }

    /// Appends a verified consensus EventLogEntry to the database (with out-of-order staging & bullshit event marking)
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

        let (expected_seq, expected_prev_hash) = log
            .iter()
            .rev()
            .find(|e| e.originator == entry.originator)
            .map(|e| (e.seq + 1, e.compute_hash()))
            .unwrap_or((1, [0u8; 32]));

        if entry.seq > expected_seq {
            if let Ok(mut pending) = self.pending_unverified.write() {
                let staged_list = pending.entry(entry.originator).or_default();
                if staged_list.len() >= MAX_STAGED_EVENTS {
                    eprintln!(
                        "  ⚠️ [Anti-Entropy DB] Staging buffer full ({}) for node {:02x?}, dropping seq {}",
                        MAX_STAGED_EVENTS,
                        &entry.originator[..4],
                        entry.seq
                    );
                    return Ok(());
                }
                if !staged_list.iter().any(|e| e.seq == entry.seq) {
                    staged_list.push(entry.clone());
                    staged_list.sort_by_key(|e| e.seq);
                    println!(
                        "  📦 [Anti-Entropy DB] Staged out-of-order event seq {} for node {:02x?} (Expected seq {})",
                        entry.seq,
                        &entry.originator[..4],
                        expected_seq
                    );
                }
            }
            return Ok(());
        }

        if entry.seq < expected_seq {
            return Ok(());
        }

        let mut final_entry = entry;
        if final_entry.prev_hash != expected_prev_hash {
            final_entry.is_bullshit = true;
            println!(
                "  💩 [Anti-Entropy DB] Ingesting bullshit event seq {} for originator {:02x?} (prev_hash link mismatch!)",
                final_entry.seq,
                &final_entry.originator[..4]
            );
        }

        self.persist_and_append_entry(&mut log, final_entry.clone())?;

        // DRAIN & AUTO-PROMOTE STAGED ITEMS for this originator!
        if let Ok(mut pending) = self.pending_unverified.write() {
            if let Some(staged_list) = pending.get_mut(&final_entry.originator) {
                let mut current_expected_seq = final_entry.seq + 1;
                let mut current_prev_hash = final_entry.compute_hash();

                while !staged_list.is_empty() && staged_list[0].seq == current_expected_seq {
                    let mut next_item = staged_list.remove(0);
                    if next_item.prev_hash != current_prev_hash {
                        next_item.is_bullshit = true;
                        println!(
                            "  💩 [Anti-Entropy DB] Auto-promoting bullshit staged event seq {} for originator {:02x?} (link mismatch!)",
                            next_item.seq,
                            &next_item.originator[..4]
                        );
                    } else {
                        println!(
                            "  ⚡ [Anti-Entropy DB] Auto-promoted valid staged event seq {} for node {:02x?}",
                            next_item.seq,
                            &next_item.originator[..4]
                        );
                    }
                    if let Ok(()) = self.persist_and_append_entry(&mut log, next_item.clone()) {
                        current_expected_seq = next_item.seq + 1;
                        current_prev_hash = next_item.compute_hash();
                    } else {
                        break;
                    }
                }
            }
        }

        if let Ok(mut cache) = self.merkle_cache.write() {
            cache.clear();
        }
        Ok(())
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

    /// Evaluates peer range vectors against local DB to find local entries the peer is missing (bounded by max_entries)
    pub fn find_missing_entries_for_peer(
        &self,
        peer_vectors: &[crate::net::history::OriginatorRangeVector],
        max_entries: usize,
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
            if missing.len() >= max_entries {
                break;
            }
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
}

#[cfg(test)]
mod tests;
