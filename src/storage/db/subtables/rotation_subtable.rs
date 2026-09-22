use std::collections::HashMap;

use crate::pki::offer::CaOfferCatalog;
use crate::pki::rotation::KeyRotationProof;
use crate::storage::db::ca_subtable::bytes32_to_hex;
use crate::storage::db::Database;

impl Database {
    /// Inserts and validates a KeyRotationProof into the rotation subtable and persists to disk (CA-09)
    pub fn insert_key_rotation(&self, proof: KeyRotationProof) -> Result<[u8; 32], String> {
        let proof_id = proof.proof_id;
        let ca_id = proof.ca_id;

        let export_map: HashMap<String, Vec<KeyRotationProof>> = {
            let mut store = self
                .rotation_store
                .write()
                .map_err(|e| format!("Lock poison error on rotation_store: {}", e))?;

            let ca_history = store.entry(ca_id).or_default();

            // 1. Verify sequence continuity and chain hash against existing chain for this CA
            let latest_opt = ca_history.last();
            match latest_opt {
                None => {
                    if proof.rotation_seq != 1 {
                        return Err(format!(
                            "First rotation for CA {:02x?} must have rotation_seq = 1, got {}",
                            &ca_id[..4],
                            proof.rotation_seq
                        ));
                    }
                    if proof.prev_rotation_hash != [0u8; 32] {
                        return Err(
                            "First rotation for CA must have prev_rotation_hash = [0; 32]"
                                .to_string(),
                        );
                    }
                }
                Some(latest) => {
                    if proof.rotation_seq != latest.rotation_seq + 1 {
                        return Err(format!(
                            "Discontinuous rotation_seq: expected {}, got {}",
                            latest.rotation_seq + 1,
                            proof.rotation_seq
                        ));
                    }
                    if proof.prev_rotation_hash != latest.proof_id {
                        return Err(format!(
                            "Broken rotation chain link: expected prev {:02x?}, got {:02x?}",
                            &latest.proof_id[..4],
                            &proof.prev_rotation_hash[..4]
                        ));
                    }
                    if proof.timestamp < latest.timestamp {
                        return Err(format!(
                            "Non-monotonic rotation timestamp: current {} < previous {}",
                            proof.timestamp, latest.timestamp
                        ));
                    }
                }
            }

            // 2. Validate Proof-of-Possession for each rotated offer key
            for rot in &proof.rotations {
                rot.verify_proof_of_possession(&ca_id, proof.timestamp)?;
            }

            ca_history.push(proof.clone());

            store
                .iter()
                .map(|(k, v)| (bytes32_to_hex(k), v.clone()))
                .collect()
        };

        // 3. Update rotated offer keys in offer_store and recompute catalog hash
        let active_offer_ids = {
            let mut offer_store = self
                .offer_store
                .write()
                .map_err(|e| format!("Lock poison error on offer_store: {}", e))?;

            let offers = offer_store.entry(ca_id).or_default();

            for rot in &proof.rotations {
                if let Some(offer) = offers.iter_mut().find(|o| o.offer_id == rot.offer_id) {
                    offer.public_key = rot.new_public_key.clone();
                }
            }

            let mut catalog =
                CaOfferCatalog::new(ca_id, proof.rotation_seq as u32 + 1, proof.timestamp);
            catalog.offers = offers.clone();
            let new_catalog_hash = catalog.compute_hash();

            // Update parent CA declaration in ca_store with new catalog hash
            if let Ok(mut ca_store) = self.ca_store.write() {
                if let Some(ca) = ca_store.get_mut(&ca_id) {
                    ca.current_catalog_hash = Some(new_catalog_hash);
                }
            }

            offers
                .iter()
                .filter(|o| !o.is_draft)
                .map(|o| o.offer_id)
                .collect::<Vec<u32>>()
        };

        // Persist updated offers to disk
        self.persist_offers()?;

        // 4. Distrust Reset Enforcement:
        // A KeyRotationProof resets distrust if and only if it proves rotation of ALL active offer keys!
        if proof.can_reset_distrust(&active_offer_ids) {
            if let Ok(mut distrust_store) = self.distrust_store.write() {
                distrust_store.insert(ca_id, 0);
            }
            eprintln!(
                "  ✨ [CA-09 Remediation] Successfully reset standing distrust strikes for CA {:02x?} (Rotated all {} offers)",
                &ca_id[..4],
                active_offer_ids.len()
            );
        }

        // 5. Persist rotation_store to disk
        let json_data = serde_json::to_string_pretty(&export_map)
            .map_err(|e| format!("Failed to serialize rotation_store: {}", e))?;
        std::fs::write(&self.rotation_file_path, json_data)
            .map_err(|e| format!("Failed to write key_rotations file: {}", e))?;

        Ok(proof_id)
    }

    /// Retrieves full key rotation audit trail for a CA
    pub fn get_key_rotations_for_ca(&self, ca_id: &[u8; 32]) -> Vec<KeyRotationProof> {
        self.rotation_store
            .read()
            .ok()
            .and_then(|store| store.get(ca_id).cloned())
            .unwrap_or_default()
    }

    /// Retrieves the latest key rotation proof for a CA
    pub fn get_latest_key_rotation(&self, ca_id: &[u8; 32]) -> Option<KeyRotationProof> {
        self.rotation_store
            .read()
            .ok()
            .and_then(|store| store.get(ca_id).and_then(|v| v.last().cloned()))
    }

    /// Records a market distrust strike against a CA (wireframe / testing for REP-09)
    pub fn record_distrust_strike(&self, ca_id: &[u8; 32], _reason: &str) -> u32 {
        if let Ok(mut store) = self.distrust_store.write() {
            let count = store.entry(*ca_id).or_insert(0);
            *count += 1;
            *count
        } else {
            0
        }
    }

    /// Retrieves count of standing distrust strikes against a CA
    pub fn get_standing_distrust_strikes(&self, ca_id: &[u8; 32]) -> u32 {
        self.distrust_store
            .read()
            .ok()
            .and_then(|store| store.get(ca_id).copied())
            .unwrap_or(0)
    }

    /// Returns true if a CA has standing distrust strikes
    pub fn has_standing_distrust(&self, ca_id: &[u8; 32]) -> bool {
        self.get_standing_distrust_strikes(ca_id) > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::agility::{CaKeyPair, KeyAlgorithm};
    use crate::pki::ca::{compute_ca_id, CaDeclaration, CaSubjectMetadata};
    use crate::pki::offer::{CertificateOffer, DEFAULT_OFFER_TTL_SECONDS};
    use crate::pki::rotation::{OfferKeyRotation, RotationReason};
    use crate::pki::scope::CertificateCoverageScope;
    use crate::proof::DomainNetworkType;
    use ed25519_dalek::SigningKey;

    fn test_node_key() -> SigningKey {
        let mut rng = rand::rngs::OsRng;
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut secret);
        SigningKey::from_bytes(&secret)
    }

    #[test]
    fn test_rotation_subtable_persistence_and_distrust_reset() {
        let temp_dir = std::env::temp_dir().join(format!(
            "randbotd_db_rotation_test_{}",
            rand::random::<u64>()
        ));
        let _ = std::fs::create_dir_all(&temp_dir);
        let db = Database::open(&temp_dir).unwrap();

        let node_key = test_node_key();
        let node_pubkey = node_key.verifying_key().to_bytes();

        let subject = CaSubjectMetadata {
            common_name: "Rotation Test CA".to_string(),
            organization: None,
            organizational_unit: None,
            locality: None,
            state_or_province: None,
            country: Some("ES".to_string()),
            email: None,
        };
        let ca_id = compute_ca_id(&subject.common_name, &node_pubkey);
        let decl = CaDeclaration::new(
            ca_id,
            subject.clone(),
            subject,
            false,
            None,
            Vec::new(),
            1700000000,
            false,
            vec![DomainNetworkType::Clearnet],
        )
        .unwrap();

        db.insert_ca(decl).unwrap();

        // Register 2 offers under this CA
        let offer0 = CertificateOffer::new(
            0,
            ca_id,
            "Offer 0".to_string(),
            KeyAlgorithm::Ed25519,
            vec![DomainNetworkType::Clearnet],
            DEFAULT_OFFER_TTL_SECONDS,
            CertificateCoverageScope::SingleFqdn,
            false,
            1700000000,
        )
        .unwrap();

        let offer1 = CertificateOffer::new(
            1,
            ca_id,
            "Offer 1".to_string(),
            KeyAlgorithm::Ed25519,
            vec![DomainNetworkType::Clearnet],
            DEFAULT_OFFER_TTL_SECONDS,
            CertificateCoverageScope::SingleFqdn,
            false,
            1700000000,
        )
        .unwrap();

        db.insert_offer(offer0).unwrap();
        db.insert_offer(offer1).unwrap();

        // 1. Simulate market distrust strike against this CA
        assert_eq!(db.record_distrust_strike(&ca_id, "Reported compromise"), 1);
        assert!(db.has_standing_distrust(&ca_id));

        // 2. Perform partial rotation (only offer 0 rotated)
        let kp0 = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let t1 = 1700001000;
        let pop0 = kp0
            .sign(&OfferKeyRotation::compute_pop_payload(
                &ca_id,
                0,
                &kp0.public_key_bytes,
                t1,
            ))
            .unwrap();
        let rot0 = OfferKeyRotation {
            offer_id: 0,
            old_public_key: vec![0; 32],
            new_public_key: kp0.public_key_bytes.clone(),
            key_algorithm: KeyAlgorithm::Ed25519,
            proof_of_possession: pop0,
            old_key_revocation_signature: None,
        };

        let partial_proof = KeyRotationProof::new(
            ca_id,
            1,
            [0u8; 32],
            t1,
            RotationReason::SuspectedLeakage,
            vec![rot0],
            &node_key,
        )
        .unwrap();

        db.insert_key_rotation(partial_proof).unwrap();

        // Distrust must STILL be standing because offer 1 was NOT rotated!
        assert!(db.has_standing_distrust(&ca_id));
        assert_eq!(db.get_standing_distrust_strikes(&ca_id), 1);

        // 3. Perform full remediation rotation (rotating BOTH offer 0 and offer 1)
        let kp0_new = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let kp1_new = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let t2 = 1700002000;

        let pop0_new = kp0_new
            .sign(&OfferKeyRotation::compute_pop_payload(
                &ca_id,
                0,
                &kp0_new.public_key_bytes,
                t2,
            ))
            .unwrap();
        let pop1_new = kp1_new
            .sign(&OfferKeyRotation::compute_pop_payload(
                &ca_id,
                1,
                &kp1_new.public_key_bytes,
                t2,
            ))
            .unwrap();

        let rot0_new = OfferKeyRotation {
            offer_id: 0,
            old_public_key: kp0.public_key_bytes.clone(),
            new_public_key: kp0_new.public_key_bytes.clone(),
            key_algorithm: KeyAlgorithm::Ed25519,
            proof_of_possession: pop0_new,
            old_key_revocation_signature: None,
        };
        let rot1_new = OfferKeyRotation {
            offer_id: 1,
            old_public_key: vec![0; 32],
            new_public_key: kp1_new.public_key_bytes.clone(),
            key_algorithm: KeyAlgorithm::Ed25519,
            proof_of_possession: pop1_new,
            old_key_revocation_signature: None,
        };

        let prev_proof = db.get_latest_key_rotation(&ca_id).unwrap();
        let full_proof = KeyRotationProof::new(
            ca_id,
            2,
            prev_proof.proof_id,
            t2,
            RotationReason::DistrustRemediation,
            vec![rot0_new, rot1_new],
            &node_key,
        )
        .unwrap();

        db.insert_key_rotation(full_proof).unwrap();

        // Distrust MUST be reset because all offers were rotated!
        assert!(!db.has_standing_distrust(&ca_id));
        assert_eq!(db.get_standing_distrust_strikes(&ca_id), 0);

        // Verify offer keys were updated in store
        let updated_offer0 = db.get_offer(&ca_id, 0).unwrap();
        let updated_offer1 = db.get_offer(&ca_id, 1).unwrap();
        assert_eq!(updated_offer0.public_key, kp0_new.public_key_bytes);
        assert_eq!(updated_offer1.public_key, kp1_new.public_key_bytes);

        // Reopen database from disk and verify persistence
        let reopened_db = Database::open(&temp_dir).unwrap();
        assert_eq!(reopened_db.get_key_rotations_for_ca(&ca_id).len(), 2);
        assert_eq!(
            reopened_db.get_offer(&ca_id, 0).unwrap().public_key,
            kp0_new.public_key_bytes
        );
        assert_eq!(
            reopened_db.get_offer(&ca_id, 1).unwrap().public_key,
            kp1_new.public_key_bytes
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
