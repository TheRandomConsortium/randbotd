use std::collections::HashMap;

use crate::pki::purge::DomainPurgeRecord;
use crate::storage::db::ca_subtable::bytes32_to_hex;
use crate::storage::db::Database;

impl Database {
    /// Inserts and validates a DomainPurgeRecord into the purge subtable and persists to disk
    pub fn insert_purge(&self, purge: DomainPurgeRecord) -> Result<[u8; 32], String> {
        let purge_id = purge.purge_id;

        let export_map: HashMap<String, DomainPurgeRecord> = {
            let mut store = self
                .purge_store
                .write()
                .map_err(|e| format!("Lock poison error on purge_store: {}", e))?;

            // 1. Verify sequence continuity and chain hash against existing chain for this CA
            let mut ca_purges: Vec<DomainPurgeRecord> = store
                .values()
                .filter(|p| p.ca_id == purge.ca_id)
                .cloned()
                .collect();
            ca_purges.sort_by_key(|p| p.purge_seq);

            let latest_opt = ca_purges.last();
            match latest_opt {
                None => {
                    if purge.purge_seq != 1 {
                        return Err(format!(
                            "First purge for CA {:02x?} must have purge_seq = 1, got {}",
                            &purge.ca_id[..4],
                            purge.purge_seq
                        ));
                    }
                    if purge.prev_purge_hash != [0u8; 32] {
                        return Err(
                            "First purge for CA must have prev_purge_hash = [0; 32]".to_string()
                        );
                    }
                }
                Some(latest) => {
                    if purge.purge_seq != latest.purge_seq + 1 {
                        return Err(format!(
                            "Discontinuous purge_seq: expected {}, got {}",
                            latest.purge_seq + 1,
                            purge.purge_seq
                        ));
                    }
                    if purge.prev_purge_hash != latest.purge_id {
                        return Err(format!(
                            "Broken purge chain link: expected prev {:02x?}, got {:02x?}",
                            &latest.purge_id[..4],
                            &purge.prev_purge_hash[..4]
                        ));
                    }
                    if purge.timestamp < latest.timestamp {
                        return Err(format!(
                            "Non-monotonic purge timestamp: current {} < previous {}",
                            purge.timestamp, latest.timestamp
                        ));
                    }
                }
            }

            // 2. Validate expiration invariant
            if purge.timestamp >= purge.expires_at {
                return Err(format!(
                    "Purge timestamp {} must be strictly before expiration {}",
                    purge.timestamp, purge.expires_at
                ));
            }

            store.insert(purge_id, purge);

            store
                .iter()
                .map(|(k, v)| (bytes32_to_hex(k), v.clone()))
                .collect()
        };

        let json_data = serde_json::to_string_pretty(&export_map)
            .map_err(|e| format!("Failed to serialize purge_store: {}", e))?;
        std::fs::write(&self.purge_file_path, json_data)
            .map_err(|e| format!("Failed to write domain_purges file: {}", e))?;

        Ok(purge_id)
    }

    /// Retrieves a DomainPurgeRecord by its purge_id
    #[allow(dead_code)]
    pub fn get_purge(&self, purge_id: &[u8; 32]) -> Option<DomainPurgeRecord> {
        self.purge_store
            .read()
            .ok()
            .and_then(|store| store.get(purge_id).cloned())
    }

    /// Retrieves all purges issued by a specific CA, sorted in sequential order (seq 1, 2, 3...)
    pub fn get_purges_for_ca(&self, ca_id: &[u8; 32]) -> Vec<DomainPurgeRecord> {
        self.purge_store
            .read()
            .map(|store| {
                let mut list: Vec<DomainPurgeRecord> = store
                    .values()
                    .filter(|p| &p.ca_id == ca_id)
                    .cloned()
                    .collect();
                list.sort_by_key(|p| p.purge_seq);
                list
            })
            .unwrap_or_default()
    }

    /// Retrieves the latest purge record issued by a specific CA
    pub fn get_latest_purge_for_ca(&self, ca_id: &[u8; 32]) -> Option<DomainPurgeRecord> {
        let purges = self.get_purges_for_ca(ca_id);
        purges.into_iter().last()
    }

    /// Counts active (unexpired relative to `now`) purges issued by a specific CA
    pub fn count_active_unexpired_purges_for_ca(&self, ca_id: &[u8; 32], now: u64) -> usize {
        self.purge_store
            .read()
            .map(|store| {
                store
                    .values()
                    .filter(|p| &p.ca_id == ca_id && p.expires_at > now)
                    .count()
            })
            .unwrap_or(0)
    }

    /// Retrieves an active (unexpired relative to `now`) purge for a given domain
    pub fn get_active_purge_for_domain(&self, domain: &str, now: u64) -> Option<DomainPurgeRecord> {
        self.purge_store.read().ok().and_then(|store| {
            store
                .values()
                .find(|p| p.domain.eq_ignore_ascii_case(domain) && p.expires_at > now)
                .cloned()
        })
    }

    /// Checks if a domain is currently purged (active unexpired purge exists)
    pub fn is_domain_purged(&self, domain: &str, now: u64) -> bool {
        self.get_active_purge_for_domain(domain, now).is_some()
    }

    /// Checks if a domain has an active unexpired purge issued specifically by `ca_id`
    pub fn is_domain_purged_by_ca(&self, ca_id: &[u8; 32], domain: &str, now: u64) -> bool {
        self.purge_store
            .read()
            .map(|store| {
                store.values().any(|p| {
                    &p.ca_id == ca_id && p.domain.eq_ignore_ascii_case(domain) && p.expires_at > now
                })
            })
            .unwrap_or(false)
    }

    /// Returns a list of all registered domain purges
    pub fn list_purges(&self) -> Vec<DomainPurgeRecord> {
        self.purge_store
            .read()
            .map(|store| store.values().cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::pki::purge::{
        calculate_required_difficulty, compute_purge_challenge, solve_purge_pow, PurgeReason,
    };
    use ed25519_dalek::SigningKey;
    use rand::RngCore;

    fn test_key() -> SigningKey {
        let mut rng = rand::rngs::OsRng;
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        SigningKey::from_bytes(&secret)
    }

    #[test]
    fn test_purge_subtable_persistence_and_chain_validation() {
        let temp_dir = std::env::temp_dir().join(format!(
            "randbotd_purge_subtable_test_{}",
            rand::random::<u64>()
        ));
        let _ = std::fs::create_dir_all(&temp_dir);

        let key = test_key();
        let ca_id = [0x55u8; 32];
        let t1 = 1700000000;
        let exp1 = t1 + 86400 * 10;

        let diff1 = calculate_required_difficulty(0, true);
        let ch1 = compute_purge_challenge(&ca_id, "malware.hns", t1, &[0u8; 32], 1);
        let n1 = solve_purge_pow(&ch1, diff1);

        let p1 = DomainPurgeRecord::new(
            ca_id,
            "malware.hns".to_string(),
            None,
            1,
            [0u8; 32],
            t1,
            exp1,
            PurgeReason::MalwarePhishing,
            "Malware host".to_string(),
            Some("UTW alert".to_string()),
            n1,
            &key,
        )
        .unwrap();

        // 1. Insert into database
        {
            let db = Database::open(&temp_dir).unwrap();
            assert_eq!(db.count_active_unexpired_purges_for_ca(&ca_id, t1), 0);
            assert!(!db.is_domain_purged("malware.hns", t1));

            let id1 = db.insert_purge(p1.clone()).unwrap();
            assert_eq!(id1, p1.purge_id);

            assert!(db.is_domain_purged("malware.hns", t1));
            assert_eq!(db.count_active_unexpired_purges_for_ca(&ca_id, t1), 1);

            // After expiration, active count decrements to 0
            assert!(!db.is_domain_purged("malware.hns", exp1 + 1));
            assert_eq!(db.count_active_unexpired_purges_for_ca(&ca_id, exp1 + 1), 0);

            // 2. Chain second purge
            let t2 = t1 + 1000;
            let exp2 = t2 + 86400 * 5;
            let diff2 = calculate_required_difficulty(1, true);
            let ch2 = compute_purge_challenge(&ca_id, "scam.onion", t2, &p1.purge_id, 2);
            let n2 = solve_purge_pow(&ch2, diff2);

            let p2 = DomainPurgeRecord::new(
                ca_id,
                "scam.onion".to_string(),
                None,
                2,
                p1.purge_id,
                t2,
                exp2,
                PurgeReason::UntrustworthyBehavior,
                "Scam site".to_string(),
                Some("Community strikes".to_string()),
                n2,
                &key,
            )
            .unwrap();

            db.insert_purge(p2).unwrap();

            let ca_purges = db.get_purges_for_ca(&ca_id);
            assert_eq!(ca_purges.len(), 2);
            assert_eq!(ca_purges[0].purge_seq, 1);
            assert_eq!(ca_purges[1].purge_seq, 2);

            let latest = db.get_latest_purge_for_ca(&ca_id).unwrap();
            assert_eq!(latest.purge_seq, 2);
        }

        // 3. Re-open database and verify persistence from domain_purges.json
        {
            let db = Database::open(&temp_dir).unwrap();
            let ca_purges = db.get_purges_for_ca(&ca_id);
            assert_eq!(ca_purges.len(), 2);
            assert!(db.is_domain_purged("scam.onion", t1 + 1500));
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_db_ca_retrocompatibility_with_purge_subtable() {
        let temp_dir = std::env::temp_dir().join(format!(
            "randbotd_retrocompat_test_{}",
            rand::random::<u64>()
        ));
        let _ = std::fs::create_dir_all(&temp_dir);

        // Simulate an existing deployed ca_declarations.json from a prior release
        let legacy_ca_json = r#"{
            "1111111111111111111111111111111111111111111111111111111111111111": {
                "ca_id": [17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17],
                "subject": {
                    "common_name": "Legacy Deployed Root CA",
                    "organization": "Legacy Corp",
                    "organizational_unit": null,
                    "locality": null,
                    "state_or_province": null,
                    "country": "ES",
                    "email": null
                },
                "issuer": {
                    "common_name": "Legacy Deployed Root CA",
                    "organization": "Legacy Corp",
                    "organizational_unit": null,
                    "locality": null,
                    "state_or_province": null,
                    "country": "ES",
                    "email": null
                },
                "is_intermediate": false,
                "path_len_constraint": null,
                "created_at": 1690000000,
                "is_draft": false,
                "supported_domain_networks": ["Clearnet"],
                "permitted_subtrees": []
            }
        }"#;
        std::fs::write(temp_dir.join("ca_declarations.json"), legacy_ca_json).unwrap();

        // 1. Open Database on legacy directory (no domain_purges.json exists yet)
        let db =
            Database::open(&temp_dir).expect("Database must open legacy CA data without error");
        let legacy_ca_id = [17u8; 32];
        let loaded_ca = db
            .get_ca(&legacy_ca_id)
            .expect("Legacy CA must be successfully loaded");
        assert_eq!(loaded_ca.subject.common_name, "Legacy Deployed Root CA");
        assert_eq!(db.list_purges().len(), 0);

        // 2. Database can record domain purges alongside legacy CAs without desync
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
        let challenge = crate::pki::purge::compute_purge_challenge(
            &legacy_ca_id,
            "legacy-bad.com",
            1700000000,
            &[0u8; 32],
            1,
        );
        let nonce = crate::pki::purge::solve_purge_pow(&challenge, 12);
        let purge = crate::pki::purge::DomainPurgeRecord::new(
            legacy_ca_id,
            "legacy-bad.com".to_string(),
            None,
            1,
            [0u8; 32],
            1700000000,
            1700086400,
            crate::pki::purge::PurgeReason::MalwarePhishing,
            "Legacy bad domain purge".to_string(),
            None,
            nonce,
            &key,
        )
        .unwrap();

        db.insert_purge(purge).unwrap();
        assert!(db.is_domain_purged("legacy-bad.com", 1700000000));

        // 3. Re-open DB and verify both legacy CA and new purge persist cleanly
        drop(db);
        let db_reopened = Database::open(&temp_dir).expect("Database must reopen cleanly");
        assert!(db_reopened.get_ca(&legacy_ca_id).is_some());
        assert!(db_reopened.is_domain_purged("legacy-bad.com", 1700000000));
        assert!(db_reopened.is_domain_purged_by_ca(&legacy_ca_id, "legacy-bad.com", 1700000000));
        assert!(!db_reopened.is_domain_purged_by_ca(&[0x99u8; 32], "legacy-bad.com", 1700000000));

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
