use super::Database;

impl Database {
    /// Inserts a validated CA declaration into the CA subtable and persists to disk
    pub fn insert_ca(
        &self,
        declaration: crate::crypto::ca::CaDeclaration,
    ) -> Result<[u8; 32], String> {
        declaration.subject.validate()?;
        declaration.issuer.validate()?;

        let ca_id = declaration.ca_id;
        let mut store = self
            .ca_store
            .write()
            .map_err(|e| format!("Lock poison error: {}", e))?;
        store.insert(ca_id, declaration);

        let export_map: std::collections::HashMap<String, crate::crypto::ca::CaDeclaration> = store
            .iter()
            .map(|(k, v)| (bytes32_to_hex(k), v.clone()))
            .collect();

        let json_data = serde_json::to_string_pretty(&export_map)
            .map_err(|e| format!("Failed to serialize ca_store: {}", e))?;
        std::fs::write(&self.ca_file_path, json_data)
            .map_err(|e| format!("Failed to write ca_declarations file: {}", e))?;

        Ok(ca_id)
    }

    /// Retrieves a CA declaration by its ca_id
    #[allow(dead_code)]
    pub fn get_ca(&self, ca_id: &[u8; 32]) -> Option<crate::crypto::ca::CaDeclaration> {
        self.ca_store
            .read()
            .ok()
            .and_then(|store| store.get(ca_id).cloned())
    }

    /// Returns a list of all registered CA declarations
    #[allow(dead_code)]
    pub fn list_cas(&self) -> Vec<crate::crypto::ca::CaDeclaration> {
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
