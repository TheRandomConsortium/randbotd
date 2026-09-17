use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::DaemonConfig;
use crate::crypto::agility::KeyAlgorithm;
use crate::net::ipc::{IpcCommand, IpcResponse};
use crate::pki::cert::{X509Certificate, X509CertificateBuilder};
use crate::pki::offer::CertificateOffer;
use crate::proof::DomainNetworkType;
use crate::storage::db::ca_subtable::{bytes32_to_hex, hex_to_bytes32};
use crate::storage::db::Database;

use super::{IpcContext, IpcHandler};

fn get_masterpass() -> Vec<u8> {
    std::env::var("RANDBOTD_MASTERPASS")
        .map(|p| p.into_bytes())
        .or_else(|_| std::fs::read("/etc/randbotd/masterpass.cred"))
        .unwrap_or_else(|_| b"randbotd_masterpass_default_key".to_vec())
}

/// IPC Handler responsible for certificate offer publishing, catalog queries, and profile inspection
pub struct OfferHandler;

impl IpcHandler for OfferHandler {
    fn handle(&self, command: &IpcCommand, ctx: &IpcContext) -> Option<IpcResponse> {
        match command {
            IpcCommand::PublishOffer {
                ca_id_hex,
                offer_id,
                name,
                key_algorithm,
                supported_domain_networks,
                ttl_seconds,
                coverage_scope,
                is_draft,
            } => Some(Self::handle_publish_offer(
                ca_id_hex,
                *offer_id,
                name,
                *key_algorithm,
                supported_domain_networks.clone(),
                *ttl_seconds,
                coverage_scope.clone(),
                *is_draft,
                ctx.db,
            )),
            IpcCommand::GetOffer {
                ca_id_hex,
                offer_id,
            } => Some(Self::handle_get_offer(ca_id_hex, *offer_id, ctx.db)),
            IpcCommand::ListOffers { ca_id_hex } => {
                Some(Self::handle_list_offers(ca_id_hex.as_deref(), ctx.db))
            }
            IpcCommand::GenerateDomainCert {
                ca_id_hex,
                offer_id,
                domain,
                subject_pubkey_hex,
                sans,
                proof_binding,
            } => Some(Self::handle_generate_domain_cert(
                ca_id_hex,
                *offer_id,
                domain,
                subject_pubkey_hex.as_deref(),
                sans.as_ref(),
                proof_binding.as_deref(),
                ctx.db,
            )),
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
        coverage_scope: Option<crate::pki::scope::CertificateCoverageScope>,
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
        let scope = coverage_scope.unwrap_or_default();
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
            scope,
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

        let root_cert_res: Result<X509Certificate, String> =
            X509CertificateBuilder::build_root_ca_certificate(
                &ca,
                &keypair,
                offer.ttl_seconds,
                now,
            );

        match database.insert_offer(offer.clone()) {
            Ok((oid, cat_hash)) => {
                let root_cert_notice = match root_cert_res {
                    Ok(rc) => {
                        format!(
                            " | Root CA Cert Generated (Serial: {})",
                            rc.serial_number.to_colon_hex()
                        )
                    }
                    Err(e) => format!(" | Root CA Cert Error: {}", e),
                };
                IpcResponse::Ok {
                    message: format!(
                        "Offer `{}` (ID {}) successfully published for CA `{}` (Algorithm: {}, Catalog Hash: {}){}",
                        offer.name, oid, ca_id_hex, offer.key_algorithm.name(), bytes32_to_hex(&cat_hash), root_cert_notice
                    ),
                }
            }
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

    /// Policy evaluation for domain purges prior to certificate issuance.
    ///
    /// NOTE(CA-07 / Phase 7 - Review Purge Scope):
    /// Purging is NOT intended to be a permanent, network-wide veto across all CAs:
    /// - A domain with low fairban / UTW votes may renew earlier and match with a different CA.
    /// - Purges are primarily CA-scoped unless a federated CA trust network is established
    ///   where CAs explicitly opt into honoring foreign purges.
    ///
    /// We isolate this check here for Phase 7 review when cert emission & matchmaking are live.
    pub fn is_domain_blocked_by_purge_policy(
        db: &Database,
        ca_id: &[u8; 32],
        domain: &str,
        now: u64,
    ) -> bool {
        // Enforce CA-scoped purge check: this CA will never issue a cert for domains it has purged.
        // Also checks global wireframe purge state until CA trust networks / fairban matching are active in Phase 7.
        db.is_domain_purged_by_ca(ca_id, domain, now) || db.is_domain_purged(domain, now)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn handle_generate_domain_cert(
        ca_id_hex: &str,
        offer_id: u32,
        domain: &str,
        subject_pubkey_hex: Option<&str>,
        sans: Option<&Vec<String>>,
        proof_binding: Option<&str>,
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
        let offer = match database.get_offer(&ca_id, offer_id) {
            Some(o) => o,
            None => {
                return IpcResponse::Error {
                    reason: format!("Offer ID {} not found for CA `{}`", offer_id, ca_id_hex),
                }
            }
        };

        // Validate domain against intermediate CA subtree constraints (CA-14)
        if ca.is_intermediate
            && !ca.permitted_subtrees.is_empty()
            && !ca.is_domain_permitted(domain)
        {
            return IpcResponse::Error {
                reason: format!(
                    "Domain `{}` violates permitted subtrees ({:?}) of intermediate CA",
                    domain, ca.permitted_subtrees
                ),
            };
        }

        // Validate domain against bad-domain purge policy (CA-07 wireframe)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if Self::is_domain_blocked_by_purge_policy(database, &ca_id, domain, now) {
            return IpcResponse::Error {
                reason: format!(
                    "Domain `{}` has been purged and cannot be issued a certificate under current policy",
                    domain
                ),
            };
        }

        // Validate or autogenerate SANs
        let resolved_sans = if let Some(custom_sans) = sans {
            if custom_sans.len() as u32 > offer.coverage_scope.max_sans() {
                return IpcResponse::Error {
                    reason: format!(
                        "Number of SANs ({}) exceeds maximum allowed ({}) under coverage scope {:?}",
                        custom_sans.len(),
                        offer.coverage_scope.max_sans(),
                        offer.coverage_scope
                    ),
                };
            }
            for s in custom_sans {
                if s.starts_with("*.") && !offer.coverage_scope.allows_wildcard() {
                    return IpcResponse::Error {
                        reason: format!(
                            "Wildcard SAN `{}` not permitted under coverage scope {:?}",
                            s, offer.coverage_scope
                        ),
                    };
                }
                if ca.is_intermediate
                    && !ca.permitted_subtrees.is_empty()
                    && !ca.is_domain_permitted(s)
                {
                    return IpcResponse::Error {
                        reason: format!(
                            "SAN `{}` violates permitted subtrees ({:?}) of intermediate CA",
                            s, ca.permitted_subtrees
                        ),
                    };
                }
            }
            custom_sans.clone()
        } else {
            offer.coverage_scope.autogenerate_sans(domain)
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Subject public key bytes
        let subject_pubkey = match subject_pubkey_hex {
            Some(hex_str) => match hex::decode(hex_str.trim().trim_start_matches("0x")) {
                Ok(b) => b,
                Err(e) => {
                    return IpcResponse::Error {
                        reason: format!("Invalid subject_pubkey_hex: {}", e),
                    }
                }
            },
            None => match crate::crypto::agility::CaKeyPair::generate(offer.key_algorithm) {
                Ok(kp) => kp.public_key_bytes.clone(),
                Err(e) => return IpcResponse::Error { reason: e },
            },
        };

        // Generate issuing CA keypair (for signing leaf cert)
        let ca_keypair = match crate::crypto::agility::CaKeyPair::generate(offer.key_algorithm) {
            Ok(kp) => kp,
            Err(e) => return IpcResponse::Error { reason: e },
        };

        match X509CertificateBuilder::build_domain_leaf_certificate(
            &ca,
            &ca_keypair,
            domain,
            offer.key_algorithm,
            &subject_pubkey,
            resolved_sans,
            offer.ttl_seconds,
            now,
            proof_binding,
        ) {
            Ok(cert) => match serde_json::to_string(&cert) {
                Ok(json_str) => IpcResponse::Ok { message: json_str },
                Err(e) => IpcResponse::Error {
                    reason: format!("Failed to serialize issued certificate: {}", e),
                },
            },
            Err(e) => IpcResponse::Error { reason: e },
        }
    }
}
