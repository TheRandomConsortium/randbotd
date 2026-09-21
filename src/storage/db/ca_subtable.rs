use super::Database;

impl Database {
    /// Inserts a validated CA declaration into the CA subtable and persists to disk
    pub fn insert_ca(
        &self,
        declaration: crate::pki::ca::CaDeclaration,
    ) -> Result<[u8; 32], String> {
        declaration.subject.validate()?;
        declaration.issuer.validate()?;

        let ca_id = declaration.ca_id;
        let export_map: std::collections::HashMap<String, crate::pki::ca::CaDeclaration> = {
            let mut store = self
                .ca_store
                .write()
                .map_err(|e| format!("Lock poison error: {}", e))?;

            let mut decl_to_insert = declaration;
            if let Some(existing) = store.get(&ca_id) {
                if !existing.is_draft && decl_to_insert.is_draft {
                    return Err("Cannot demote published CA to draft".to_string());
                }
                if decl_to_insert.current_catalog_hash.is_none() {
                    decl_to_insert.current_catalog_hash = existing.current_catalog_hash;
                }
                if decl_to_insert.offer_ids.is_empty() {
                    decl_to_insert.offer_ids = existing.offer_ids.clone();
                }
            }
            store.insert(ca_id, decl_to_insert);

            store
                .iter()
                .map(|(k, v)| (bytes32_to_hex(k), v.clone()))
                .collect()
        };

        let json_data = serde_json::to_string_pretty(&export_map)
            .map_err(|e| format!("Failed to serialize ca_store: {}", e))?;
        std::fs::write(&self.ca_file_path, json_data)
            .map_err(|e| format!("Failed to write ca_declarations file: {}", e))?;

        Ok(ca_id)
    }

    /// Retrieves a CA declaration by its ca_id
    pub fn get_ca(&self, ca_id: &[u8; 32]) -> Option<crate::pki::ca::CaDeclaration> {
        self.ca_store
            .read()
            .ok()
            .and_then(|store| store.get(ca_id).cloned())
    }

    /// Returns a list of all registered CA declarations
    pub fn list_cas(&self) -> Vec<crate::pki::ca::CaDeclaration> {
        self.ca_store
            .read()
            .map(|store| store.values().cloned().collect())
            .unwrap_or_default()
    }
}

pub(crate) fn bytes32_to_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub(crate) fn hex_to_bytes32(hex_str: &str) -> Result<[u8; 32], String> {
    if hex_str.len() != 64 {
        return Err("Invalid hex string length for [u8; 32]".to_string());
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("Invalid hex byte: {}", e))?;
    }
    Ok(bytes)
}

pub(crate) fn load_hex_map_from_disk<T: serde::de::DeserializeOwned>(
    path: &std::path::Path,
) -> Result<std::collections::HashMap<[u8; 32], T>, String> {
    if !path.exists() {
        return Ok(std::collections::HashMap::new());
    }
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read {:?}: {}", path, e))?;
    let hex_map: std::collections::HashMap<String, T> =
        serde_json::from_str(&content).unwrap_or_default();
    let mut map = std::collections::HashMap::new();
    for (hex_key, val) in hex_map {
        if let Ok(bytes) = hex_to_bytes32(&hex_key) {
            map.insert(bytes, val);
        }
    }
    Ok(map)
}
