use super::ca_subtable::bytes32_to_hex;
use super::Database;
use crate::pki::offer::{CaOfferCatalog, CertificateOffer};

impl Database {
    /// Inserts or updates a certificate offer, links it to its CA declaration, and updates catalog hash
    pub fn insert_offer(&self, offer: CertificateOffer) -> Result<(u32, [u8; 32]), String> {
        let ca_id = offer.ca_id;
        let offer_id = offer.offer_id;

        // Verify parent CA exists
        let ca_exists = {
            let ca_store = self
                .ca_store
                .read()
                .map_err(|e| format!("Lock poison error: {}", e))?;
            ca_store.contains_key(&ca_id)
        };

        if !ca_exists {
            return Err(format!(
                "Parent CA `{}` does not exist in database",
                bytes32_to_hex(&ca_id)
            ));
        }

        // Insert / Update in offer_store
        let (catalog_hash, all_offers_for_ca) = {
            let mut store = self
                .offer_store
                .write()
                .map_err(|e| format!("Lock poison error: {}", e))?;

            let ca_offers = store.entry(ca_id).or_default();
            if let Some(pos) = ca_offers.iter().position(|o| o.offer_id == offer_id) {
                ca_offers[pos] = offer.clone();
            } else {
                ca_offers.push(offer.clone());
                ca_offers.sort_by_key(|o| o.offer_id);
            }

            let mut catalog = CaOfferCatalog::new(ca_id, 1, offer.created_at);
            catalog.offers = ca_offers.clone();
            let hash = catalog.compute_hash();
            (hash, ca_offers.clone())
        };

        // Update parent CA declaration in ca_store with new catalog hash & offer IDs
        {
            let mut ca_store = self
                .ca_store
                .write()
                .map_err(|e| format!("Lock poison error: {}", e))?;

            if let Some(ca) = ca_store.get_mut(&ca_id) {
                ca.current_catalog_hash = Some(catalog_hash);
                ca.offer_ids = all_offers_for_ca.iter().map(|o| o.offer_id).collect();
            }

            let export_map: std::collections::HashMap<String, crate::pki::ca::CaDeclaration> =
                ca_store
                    .iter()
                    .map(|(k, v)| (bytes32_to_hex(k), v.clone()))
                    .collect();

            let json_data = serde_json::to_string_pretty(&export_map)
                .map_err(|e| format!("Failed to serialize ca_store: {}", e))?;
            std::fs::write(&self.ca_file_path, json_data)
                .map_err(|e| format!("Failed to write ca_declarations file: {}", e))?;
        }

        // Persist offer_store to disk
        self.persist_offers()?;

        Ok((offer_id, catalog_hash))
    }

    /// Retrieves an offer for a specific CA and offer ID
    pub fn get_offer(&self, ca_id: &[u8; 32], offer_id: u32) -> Option<CertificateOffer> {
        self.offer_store.read().ok().and_then(|store| {
            store
                .get(ca_id)
                .and_then(|offers| offers.iter().find(|o| o.offer_id == offer_id).cloned())
        })
    }

    /// Lists all offers defined for a given CA ID
    pub fn list_offers_for_ca(&self, ca_id: &[u8; 32]) -> Vec<CertificateOffer> {
        self.offer_store
            .read()
            .ok()
            .and_then(|store| store.get(ca_id).cloned())
            .unwrap_or_default()
    }

    /// Reconstructs and returns the full CaOfferCatalog for a given CA ID
    pub fn get_catalog_for_ca(&self, ca_id: &[u8; 32]) -> Option<CaOfferCatalog> {
        let offers = self.list_offers_for_ca(ca_id);
        if offers.is_empty() {
            None
        } else {
            let created_at = offers.first().map(|o| o.created_at).unwrap_or_default();
            let mut catalog = CaOfferCatalog::new(*ca_id, 1, created_at);
            catalog.offers = offers;
            Some(catalog)
        }
    }

    fn persist_offers(&self) -> Result<(), String> {
        let store = self
            .offer_store
            .read()
            .map_err(|e| format!("Lock poison error: {}", e))?;

        let export_map: std::collections::HashMap<String, Vec<CertificateOffer>> = store
            .iter()
            .map(|(k, v)| (bytes32_to_hex(k), v.clone()))
            .collect();

        let json_data = serde_json::to_string_pretty(&export_map)
            .map_err(|e| format!("Failed to serialize offer_store: {}", e))?;
        std::fs::write(&self.offer_file_path, json_data)
            .map_err(|e| format!("Failed to write ca_offers file: {}", e))?;

        Ok(())
    }
}
