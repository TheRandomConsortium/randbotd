use std::collections::HashMap;

use super::ca_subtable::bytes32_to_hex;
use super::Database;
use crate::pki::cert::serial::CertificateSerialNumber;
use crate::pki::chain::CertificateChain;
use crate::pki::crl::CertificateRevocationList;

impl Database {
    /// Inserts a validated CertificateChain into the database and persists to disk
    pub fn insert_cert_chain(&self, chain: CertificateChain) -> Result<[u8; 32], String> {
        let chain_id = chain.chain_id();

        let export_map: HashMap<String, CertificateChain> = {
            let mut store = self
                .chain_store
                .write()
                .map_err(|e| format!("Lock poison error on chain_store: {}", e))?;

            store.insert(chain_id, chain);

            store
                .iter()
                .map(|(k, v)| (bytes32_to_hex(k), v.clone()))
                .collect()
        };

        let json_data = serde_json::to_string_pretty(&export_map)
            .map_err(|e| format!("Failed to serialize chain_store: {}", e))?;
        std::fs::write(&self.chain_file_path, json_data)
            .map_err(|e| format!("Failed to write cert_chains file: {}", e))?;

        Ok(chain_id)
    }

    /// Retrieves a CertificateChain by its chain_id
    /// Note: Dead code permitted until CA-11 (Distributed Custodian Swarm)
    #[allow(dead_code)]
    pub fn get_cert_chain(&self, chain_id: &[u8; 32]) -> Option<CertificateChain> {
        self.chain_store
            .read()
            .ok()
            .and_then(|store| store.get(chain_id).cloned())
    }

    /// Retrieves a CertificateChain by the target leaf certificate serial number
    pub fn get_cert_chain_by_serial(
        &self,
        serial: &CertificateSerialNumber,
    ) -> Option<CertificateChain> {
        self.chain_store.read().ok().and_then(|store| {
            store
                .values()
                .find(|chain| &chain.target_certificate.serial_number == serial)
                .cloned()
        })
    }

    /// Lists all registered certificate chains
    pub fn list_cert_chains(&self) -> Vec<CertificateChain> {
        self.chain_store
            .read()
            .map(|store| store.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Inserts a validated CertificateRevocationList into the database and persists to disk
    pub fn insert_crl(&self, crl: CertificateRevocationList) -> Result<[u8; 32], String> {
        let ca_id = crl.issuer_ca_id;
        let export_map: HashMap<String, CertificateRevocationList> = {
            let mut store = self
                .crl_store
                .write()
                .map_err(|e| format!("Lock poison error on crl_store: {}", e))?;

            if let Some(existing) = store.get(&ca_id) {
                if crl.crl_number < existing.crl_number {
                    return Err(format!(
                        "Incoming CRL number {} is older than existing CRL number {}",
                        crl.crl_number, existing.crl_number
                    ));
                }
            }

            store.insert(ca_id, crl);

            store
                .iter()
                .map(|(k, v)| (bytes32_to_hex(k), v.clone()))
                .collect()
        };

        let json_data = serde_json::to_string_pretty(&export_map)
            .map_err(|e| format!("Failed to serialize crl_store: {}", e))?;
        std::fs::write(&self.crl_file_path, json_data)
            .map_err(|e| format!("Failed to write crls file: {}", e))?;

        Ok(ca_id)
    }

    /// Retrieves a CertificateRevocationList by issuing CA ID
    pub fn get_crl(&self, issuer_ca_id: &[u8; 32]) -> Option<CertificateRevocationList> {
        self.crl_store
            .read()
            .ok()
            .and_then(|store| store.get(issuer_ca_id).cloned())
    }

    /// Lists all registered CRLs
    pub fn list_crls(&self) -> Vec<CertificateRevocationList> {
        self.crl_store
            .read()
            .map(|store| store.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Checks if a certificate serial number is revoked by its issuing CA
    /// Note: Dead code permitted until CA-11 (Distributed Custodian Swarm) / CA-06 Dashboard
    #[allow(dead_code)]
    pub fn is_serial_revoked(
        &self,
        issuer_ca_id: &[u8; 32],
        serial: &CertificateSerialNumber,
    ) -> bool {
        self.get_crl(issuer_ca_id)
            .map(|crl| crl.is_serial_revoked(serial))
            .unwrap_or(false)
    }

    /// Checks if a certificate serial number is marked revoked in any known CRL
    pub fn is_cert_revoked_any(&self, serial: &CertificateSerialNumber) -> bool {
        if let Ok(store) = self.crl_store.read() {
            store.values().any(|crl| crl.is_serial_revoked(serial))
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::agility::{CaKeyPair, KeyAlgorithm};
    use crate::pki::ca::{compute_ca_id, CaDeclaration, CaSubjectMetadata};
    use crate::pki::cert::builder::X509CertificateBuilder;
    use crate::pki::crl::{CRLReason, RevokedCertificateEntry, X509CrlBuilder};

    #[test]
    fn test_cert_subtable_chain_and_crl_persistence_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!(
            "randbotd_db_cert_subtable_test_{}",
            rand::random::<u64>()
        ));
        let _ = std::fs::create_dir_all(&temp_dir);
        let db = Database::open(&temp_dir).unwrap();

        let root_subject = CaSubjectMetadata {
            common_name: "The Random Consortium Subtable CA".to_string(),
            organization: Some("The Random Consortium".to_string()),
            organizational_unit: None,
            locality: Some("Valencia".to_string()),
            state_or_province: Some("Valencia".to_string()),
            country: Some("ES".to_string()),
            email: None,
        };
        let root_ca_id = compute_ca_id(&root_subject.common_name, b"test_root_subtable_key");
        let root_decl = CaDeclaration::new(
            root_ca_id,
            root_subject.clone(),
            root_subject,
            false,
            None,
            Vec::new(),
            1700000000,
            false,
            vec![crate::proof::DomainNetworkType::Clearnet],
        )
        .unwrap();

        let root_keypair = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let root_cert = X509CertificateBuilder::build_root_ca_certificate(
            &root_decl,
            &root_keypair,
            864000,
            1700000000,
        )
        .unwrap();

        let leaf_keypair = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let leaf_cert = X509CertificateBuilder::build_domain_leaf_certificate(
            &root_decl,
            &root_keypair,
            "subtable.randbot.hns",
            KeyAlgorithm::Ed25519,
            &leaf_keypair.public_key_bytes,
            vec!["subtable.randbot.hns".to_string()],
            86400,
            1700000000,
            None,
        )
        .unwrap();

        let target_serial = leaf_cert.serial_number.clone();
        let chain = CertificateChain::new(leaf_cert, Vec::new(), Some(root_cert));

        // Insert chain
        let chain_id = db.insert_cert_chain(chain.clone()).unwrap();

        // Query by chain_id and target serial
        assert_eq!(db.get_cert_chain(&chain_id).unwrap(), chain);
        assert_eq!(db.get_cert_chain_by_serial(&target_serial).unwrap(), chain);
        assert_eq!(db.list_cert_chains().len(), 1);

        // CRL test
        let revoked_entry = RevokedCertificateEntry {
            serial_number: target_serial.clone(),
            revocation_date: 1700000050,
            reason: Some(CRLReason::KeyCompromise),
        };
        let crl = X509CrlBuilder::build_crl(
            &root_decl,
            &root_keypair,
            vec![revoked_entry],
            1700000000,
            1700086400,
            1,
        )
        .unwrap();

        let crl_id = db.insert_crl(crl.clone()).unwrap();
        assert_eq!(crl_id, root_ca_id);
        assert!(db.is_serial_revoked(&root_ca_id, &target_serial));
        assert!(db.is_cert_revoked_any(&target_serial));

        let non_revoked_serial = CertificateSerialNumber::generate();
        assert!(!db.is_serial_revoked(&root_ca_id, &non_revoked_serial));
        assert!(!db.is_cert_revoked_any(&non_revoked_serial));

        // Reopen database from disk and verify persistence
        let reopened_db = Database::open(&temp_dir).unwrap();
        assert_eq!(reopened_db.get_cert_chain(&chain_id).unwrap(), chain);
        assert_eq!(reopened_db.get_crl(&root_ca_id).unwrap().crl_number, 1);
        assert!(reopened_db.is_cert_revoked_any(&target_serial));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
