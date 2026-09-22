use std::collections::HashMap;

use crate::pki::swarm::{CaCustodianPolicy, CustodianSwarmRecord};
use crate::storage::db::ca_subtable::bytes32_to_hex;
use crate::storage::db::Database;

impl Database {
    /// Inserts or updates an active swarm custodian record for a CA
    pub fn insert_custodian_record(&self, record: CustodianSwarmRecord) -> Result<(), String> {
        let ca_id = record.ca_id;
        let export_map: HashMap<String, Vec<CustodianSwarmRecord>> = {
            let mut store = self
                .custodian_store
                .write()
                .map_err(|e| format!("Lock poison error: {}", e))?;

            let list = store.entry(ca_id).or_default();
            // Remove any existing entry for this worker pubkey
            list.retain(|c| c.worker_pubkey != record.worker_pubkey);
            list.push(record);

            store
                .iter()
                .map(|(k, v)| (bytes32_to_hex(k), v.clone()))
                .collect()
        };

        let json_data = serde_json::to_string_pretty(&export_map)
            .map_err(|e| format!("Failed to serialize custodian_store: {}", e))?;
        std::fs::write(&self.custodians_file_path, json_data)
            .map_err(|e| format!("Failed to write custodians file: {}", e))?;

        Ok(())
    }

    /// Retrieves all active swarm custodians for a given CA
    pub fn get_custodians_for_ca(&self, ca_id: &[u8; 32]) -> Vec<CustodianSwarmRecord> {
        self.custodian_store
            .read()
            .ok()
            .and_then(|store| store.get(ca_id).cloned())
            .unwrap_or_default()
    }

    /// Removes a custodian worker node from a CA's active swarm
    pub fn remove_custodian(
        &self,
        ca_id: &[u8; 32],
        worker_pubkey: &[u8; 32],
    ) -> Result<bool, String> {
        let (removed, export_map) = {
            let mut store = self
                .custodian_store
                .write()
                .map_err(|e| format!("Lock poison error: {}", e))?;

            let mut was_removed = false;
            if let Some(list) = store.get_mut(ca_id) {
                let initial_len = list.len();
                list.retain(|c| &c.worker_pubkey != worker_pubkey);
                was_removed = list.len() < initial_len;
            }

            let export: HashMap<String, Vec<CustodianSwarmRecord>> = store
                .iter()
                .map(|(k, v)| (bytes32_to_hex(k), v.clone()))
                .collect();
            (was_removed, export)
        };

        if removed {
            let json_data = serde_json::to_string_pretty(&export_map)
                .map_err(|e| format!("Failed to serialize custodian_store: {}", e))?;
            std::fs::write(&self.custodians_file_path, json_data)
                .map_err(|e| format!("Failed to write custodians file: {}", e))?;
        }

        Ok(removed)
    }

    /// Retrieves private blind custodian acceptance policy for a CA
    pub fn get_ca_custodian_policy(&self, ca_id: &[u8; 32]) -> Option<CaCustodianPolicy> {
        self.policy_store
            .read()
            .ok()
            .and_then(|store| store.get(ca_id).cloned())
    }

    /// Sets or updates private blind custodian acceptance policy for a CA
    pub fn set_ca_custodian_policy(
        &self,
        ca_id: [u8; 32],
        policy: CaCustodianPolicy,
    ) -> Result<(), String> {
        let export_map: HashMap<String, CaCustodianPolicy> = {
            let mut store = self
                .policy_store
                .write()
                .map_err(|e| format!("Lock poison error: {}", e))?;

            store.insert(ca_id, policy);

            store
                .iter()
                .map(|(k, v)| (bytes32_to_hex(k), v.clone()))
                .collect()
        };

        let json_data = serde_json::to_string_pretty(&export_map)
            .map_err(|e| format!("Failed to serialize policy_store: {}", e))?;
        std::fs::write(&self.policies_file_path, json_data)
            .map_err(|e| format!("Failed to write policies file: {}", e))?;

        Ok(())
    }
}
