use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::DaemonConfig;
use crate::crypto::agility::KeyAlgorithm;
use crate::net::ipc::{IpcCommand, IpcResponse};
use crate::net::phonebook::Phonebook;
use crate::pki::offer::CertificateOffer;
use crate::proof::DomainNetworkType;
use crate::storage::db::ca_subtable::{bytes32_to_hex, hex_to_bytes32};
use crate::storage::db::Database;

use super::IpcHandler;

fn get_masterpass() -> Vec<u8> {
    std::env::var("RANDBOTD_MASTERPASS")
        .map(|p| p.into_bytes())
        .or_else(|_| std::fs::read("/etc/randbotd/masterpass.cred"))
        .unwrap_or_else(|_| b"randbotd_masterpass_default_key".to_vec())
}

/// IPC Handler responsible for certificate offer publishing, catalog queries, and profile inspection
pub struct OfferHandler;

impl IpcHandler for OfferHandler {
    fn handle(
        &self,
        command: &IpcCommand,
        _phonebook: &Arc<std::sync::RwLock<Phonebook>>,
        db: Option<&Arc<Database>>,
    ) -> Option<IpcResponse> {
        match command {
            IpcCommand::PublishOffer {
                ca_id_hex,
                offer_id,
                name,
                key_algorithm,
                supported_domain_networks,
                ttl_seconds,
                is_draft,
            } => Some(Self::handle_publish_offer(
                ca_id_hex,
                *offer_id,
                name,
                *key_algorithm,
                supported_domain_networks.clone(),
                *ttl_seconds,
                *is_draft,
                db,
            )),
            IpcCommand::GetOffer {
                ca_id_hex,
                offer_id,
            } => Some(Self::handle_get_offer(ca_id_hex, *offer_id, db)),
            IpcCommand::ListOffers { ca_id_hex } => {
                Some(Self::handle_list_offers(ca_id_hex.as_deref(), db))
            }
            _ => None,
        }
    }
}

impl OfferHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn handle_publish_offer(
        ca_id_hex: &str,
        offer_id: Option<u32>,
        name: &str,
        key_algorithm: Option<KeyAlgorithm>,
        supported_domain_networks: Option<Vec<DomainNetworkType>>,
        ttl_seconds: Option<u64>,
        is_draft: Option<bool>,
        db: Option<&Arc<Database>>,
    ) -> IpcResponse {
        let database = match db {
            Some(d) => d,
            None => {
                return IpcResponse::Error {
                    reason: "Database is unavailable".to_string(),
                }
            }
        };

        let ca_id = match hex_to_bytes32(ca_id_hex) {
            Ok(b) => b,
            Err(e) => return IpcResponse::Error { reason: e },
        };

        let ca = match database.get_ca(&ca_id) {
            Some(c) => c,
            None => {
                return IpcResponse::Error {
                    reason: format!("CA `{}` does not exist in database", ca_id_hex),
                }
            }
        };

        let existing_offers = database.list_offers_for_ca(&ca_id);
        let resolved_offer_id = offer_id.unwrap_or_else(|| {
            existing_offers
                .iter()
                .map(|o| o.offer_id)
                .max()
                .map(|m| m + 1)
                .unwrap_or(0)
        });

        let algo = key_algorithm.unwrap_or(KeyAlgorithm::Ed25519);
        let keypair = match crate::crypto::agility::CaKeyPair::generate(algo) {
            Ok(kp) => kp,
            Err(e) => return IpcResponse::Error { reason: e },
        };

        if let Ok(sig) = keypair.sign(ca_id.as_slice()) {
            let _ = keypair.verify(ca_id.as_slice(), &sig);
        }

        let key_file = std::env::temp_dir().join(format!(
            "ca_{:02x?}_offer_{}.enc",
            &ca_id[..4],
            resolved_offer_id
        ));
        let masterpass = get_masterpass();
        if keypair
            .save_encrypted_key_file(&key_file, &masterpass)
            .is_ok()
        {
            let _ =
                crate::crypto::agility::CaKeyPair::load_encrypted_key_file(&key_file, &masterpass);
            let _ = std::fs::remove_file(key_file);
        }

        let networks =
            supported_domain_networks.unwrap_or_else(|| vec![DomainNetworkType::Clearnet]);
        let ttl = ttl_seconds.unwrap_or(crate::pki::offer::DEFAULT_OFFER_TTL_SECONDS);
        let is_draft_val = is_draft.unwrap_or(false);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let offer = match CertificateOffer::new(
            resolved_offer_id,
            ca_id,
            name.to_string(),
            algo,
            networks,
            ttl,
            is_draft_val,
            now,
        ) {
            Ok(o) => o,
            Err(e) => return IpcResponse::Error { reason: e },
        };

        let (not_before, not_after) = offer.validity_window(now);
        eprintln!(
            "  ℹ️ [Offer] TTL {}s validity window: {} -> {}",
            offer.ttl_seconds, not_before, not_after
        );

        let daemon_cfg = DaemonConfig::load_default_or_create(None);
        if let Err(e) = offer.validate_against_ca_and_config(&ca, &daemon_cfg) {
            return IpcResponse::Error { reason: e };
        }

        let _ = database.get_catalog_for_ca(&ca_id);

        match database.insert_offer(offer.clone()) {
            Ok((oid, cat_hash)) => IpcResponse::Ok {
                message: format!(
                    "Offer `{}` (ID {}) successfully published for CA `{}` (Algorithm: {}, Catalog Hash: {})",
                    offer.name, oid, ca_id_hex, offer.key_algorithm.name(), bytes32_to_hex(&cat_hash)
                ),
            },
            Err(e) => IpcResponse::Error { reason: e },
        }
    }

    pub fn handle_get_offer(
        ca_id_hex: &str,
        offer_id: u32,
        db: Option<&Arc<Database>>,
    ) -> IpcResponse {
        let database = match db {
            Some(d) => d,
            None => {
                return IpcResponse::Error {
                    reason: "Database is unavailable".to_string(),
                }
            }
        };
        let ca_id = match hex_to_bytes32(ca_id_hex) {
            Ok(b) => b,
            Err(e) => return IpcResponse::Error { reason: e },
        };
        match database.get_offer(&ca_id, offer_id) {
            Some(offer) => match serde_json::to_string(&offer) {
                Ok(json_str) => IpcResponse::Ok { message: json_str },
                Err(e) => IpcResponse::Error {
                    reason: format!("Failed to serialize offer: {}", e),
                },
            },
            None => IpcResponse::Error {
                reason: format!("Offer ID {} not found for CA `{}`", offer_id, ca_id_hex),
            },
        }
    }

    pub fn handle_list_offers(ca_id_hex: Option<&str>, db: Option<&Arc<Database>>) -> IpcResponse {
        let database = match db {
            Some(d) => d,
            None => {
                return IpcResponse::Error {
                    reason: "Database is unavailable".to_string(),
                }
            }
        };
        let offers = if let Some(hex_str) = ca_id_hex {
            match hex_to_bytes32(hex_str) {
                Ok(ca_id) => database.list_offers_for_ca(&ca_id),
                Err(e) => return IpcResponse::Error { reason: e },
            }
        } else {
            let mut all_offers = Vec::new();
            for ca in database.list_cas() {
                all_offers.extend(database.list_offers_for_ca(&ca.ca_id));
            }
            all_offers
        };
        match serde_json::to_string(&offers) {
            Ok(json_str) => IpcResponse::Ok { message: json_str },
            Err(e) => IpcResponse::Error {
                reason: format!("Failed to serialize offers: {}", e),
            },
        }
    }
}
