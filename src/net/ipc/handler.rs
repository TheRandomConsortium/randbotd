use crate::config::DaemonConfig;
use crate::crypto::agility::KeyAlgorithm;
use crate::net::ipc::{IpcCommand, IpcResponse};
use crate::net::phonebook::Phonebook;
use crate::pki::ca::{compute_ca_id, CaDeclaration, CaSubjectMetadata};
use crate::pki::offer::CertificateOffer;
use crate::proof::{
    DomainNetworkType, DomainProofChallenge, DomainProofResponse, DomainProofVerifier,
};
use crate::storage::db::ca_subtable::{bytes32_to_hex, hex_to_bytes32};
use crate::storage::db::Database;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

fn get_masterpass() -> Vec<u8> {
    std::env::var("RANDBOTD_MASTERPASS")
        .map(|p| p.into_bytes())
        .or_else(|_| std::fs::read("/etc/randbotd/masterpass.cred"))
        .unwrap_or_else(|_| b"randbotd_masterpass_default_key".to_vec())
}

/// Dispatches and executes IPC commands against local phonebook and database
pub fn handle_ipc_command(
    command: IpcCommand,
    phonebook: &Arc<RwLock<Phonebook>>,
    db: Option<&Arc<Database>>,
) -> IpcResponse {
    match command {
        IpcCommand::ImportPeer { peer_addr } => handle_import_peer(peer_addr, phonebook),
        IpcCommand::PublishCa {
            ca_id_hex,
            common_name,
            organization,
            organizational_unit,
            locality,
            state_or_province,
            country,
            email,
            is_intermediate,
            path_len_constraint,
            is_draft,
            supported_domain_networks,
        } => handle_publish_ca(
            ca_id_hex,
            common_name,
            organization,
            organizational_unit,
            locality,
            state_or_province,
            country,
            email,
            is_intermediate,
            path_len_constraint,
            is_draft,
            supported_domain_networks,
            phonebook,
            db,
        ),
        IpcCommand::PublishOffer {
            ca_id_hex,
            offer_id,
            name,
            key_algorithm,
            supported_domain_networks,
            ttl_seconds,
            is_draft,
        } => handle_publish_offer(
            ca_id_hex,
            offer_id,
            name,
            key_algorithm,
            supported_domain_networks,
            ttl_seconds,
            is_draft,
            db,
        ),
        IpcCommand::GetOffer {
            ca_id_hex,
            offer_id,
        } => handle_get_offer(ca_id_hex, offer_id, db),
        IpcCommand::ListOffers { ca_id_hex } => handle_list_offers(ca_id_hex, db),
        IpcCommand::ChallengeDomainProof {
            domain,
            network_type,
            ttl_seconds,
        } => handle_challenge_domain_proof(domain, network_type, ttl_seconds),
        IpcCommand::VerifyDomainProof {
            challenge_json,
            txt_record,
            http_json,
        } => handle_verify_domain_proof(challenge_json, txt_record, http_json),
    }
}

fn handle_import_peer(peer_addr: String, phonebook: &Arc<RwLock<Phonebook>>) -> IpcResponse {
    let addr_clean = peer_addr.trim().to_string();
    if addr_clean.is_empty() {
        return IpcResponse::Error {
            reason: "peer_addr cannot be empty".to_string(),
        };
    }
    let mut pb = phonebook.write().unwrap();
    pb.add_peer(addr_clean.clone());
    IpcResponse::Ok {
        message: format!("Peer `{}` successfully imported into phonebook", addr_clean),
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_publish_ca(
    ca_id_hex: Option<String>,
    common_name: String,
    organization: Option<String>,
    organizational_unit: Option<String>,
    locality: Option<String>,
    state_or_province: Option<String>,
    country: Option<String>,
    email: Option<String>,
    is_intermediate: bool,
    path_len_constraint: Option<u32>,
    is_draft: Option<bool>,
    supported_domain_networks: Option<Vec<DomainNetworkType>>,
    phonebook: &Arc<RwLock<Phonebook>>,
    db: Option<&Arc<Database>>,
) -> IpcResponse {
    let subject = CaSubjectMetadata {
        common_name,
        organization,
        organizational_unit,
        locality,
        state_or_province,
        country,
        email,
    };
    if let Err(e) = subject.validate() {
        return IpcResponse::Error { reason: e };
    }

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let node_pubkey = phonebook
        .read()
        .unwrap()
        .my_pubkey_bytes()
        .unwrap_or([0u8; 32]);

    let ca_id = match ca_id_hex {
        Some(ref hex_str) => hex_to_bytes32(hex_str)
            .unwrap_or_else(|_| compute_ca_id(&subject.common_name, &node_pubkey)),
        None => compute_ca_id(&subject.common_name, &node_pubkey),
    };

    let is_draft_val = is_draft.unwrap_or(false);
    let networks = supported_domain_networks.unwrap_or_else(|| vec![DomainNetworkType::Clearnet]);

    let decl_res = if is_draft_val {
        CaDeclaration::new_with_draft(
            ca_id,
            subject.clone(),
            subject,
            is_intermediate,
            path_len_constraint,
            created_at,
            true,
            networks,
        )
    } else {
        CaDeclaration::new(
            ca_id,
            subject.clone(),
            subject,
            is_intermediate,
            path_len_constraint,
            created_at,
            networks,
        )
    };

    match decl_res {
        Err(e) => IpcResponse::Error { reason: e },
        Ok(decl) => {
            let daemon_cfg = DaemonConfig::load_default_or_create(None);
            if let Err(err) = decl.validate_against_config(&daemon_cfg) {
                return IpcResponse::Error { reason: err };
            }

            let ca_id_hex_res = bytes32_to_hex(&ca_id);
            let action_str = if is_draft_val {
                "draft saved"
            } else {
                "published"
            };

            if let Some(database) = db {
                if let Err(err) = database.insert_ca(decl.clone()) {
                    return IpcResponse::Error {
                        reason: format!("Database save error: {}", err),
                    };
                }
            }

            eprintln!("  ℹ️ {}", crate::pki::cert::wot_extension_warning());
            IpcResponse::Ok {
                message: format!(
                    "CA Declaration `{}` successfully {} with ca_id `{}`",
                    decl.subject.common_name, action_str, ca_id_hex_res
                ),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_publish_offer(
    ca_id_hex: String,
    offer_id: Option<u32>,
    name: String,
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

    let ca_id = match hex_to_bytes32(&ca_id_hex) {
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
        let _ = crate::crypto::agility::CaKeyPair::load_encrypted_key_file(&key_file, &masterpass);
        let _ = std::fs::remove_file(key_file);
    }

    let networks = supported_domain_networks.unwrap_or_else(|| vec![DomainNetworkType::Clearnet]);
    let ttl = ttl_seconds.unwrap_or(crate::pki::offer::DEFAULT_OFFER_TTL_SECONDS);
    let is_draft_val = is_draft.unwrap_or(false);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let offer = match CertificateOffer::new(
        resolved_offer_id,
        ca_id,
        name,
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

fn handle_get_offer(ca_id_hex: String, offer_id: u32, db: Option<&Arc<Database>>) -> IpcResponse {
    let database = match db {
        Some(d) => d,
        None => {
            return IpcResponse::Error {
                reason: "Database is unavailable".to_string(),
            }
        }
    };
    let ca_id = match hex_to_bytes32(&ca_id_hex) {
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

fn handle_list_offers(ca_id_hex: Option<String>, db: Option<&Arc<Database>>) -> IpcResponse {
    let database = match db {
        Some(d) => d,
        None => {
            return IpcResponse::Error {
                reason: "Database is unavailable".to_string(),
            }
        }
    };
    let offers = if let Some(hex_str) = ca_id_hex {
        match hex_to_bytes32(&hex_str) {
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

fn handle_challenge_domain_proof(
    domain: String,
    network_type: Option<DomainNetworkType>,
    ttl_seconds: Option<u64>,
) -> IpcResponse {
    let domain_clean = domain.trim().to_lowercase();
    if domain_clean.is_empty() {
        return IpcResponse::Error {
            reason: "domain cannot be empty".to_string(),
        };
    }
    let daemon_cfg = DaemonConfig::load_default_or_create(None);
    let net_type = match network_type {
        Some(nt) => nt,
        None => match DomainNetworkType::resolve_network_type(&domain_clean, &daemon_cfg) {
            Ok(nt) => nt,
            Err(e) => {
                return IpcResponse::Error {
                    reason: e.to_string(),
                }
            }
        },
    };
    if let Err(e) = DomainProofVerifier::check_backend_capability(net_type, &daemon_cfg) {
        return IpcResponse::Error {
            reason: e.to_string(),
        };
    }
    let ttl = ttl_seconds.unwrap_or(900);
    let challenge = DomainProofChallenge::new(&domain_clean, net_type, ttl);
    let _ = challenge.next_retry_delay_seconds();
    let sample_id = crate::crypto::identity::NodeIdentity::from_seed_and_role(
        &[0u8; 32],
        crate::crypto::identity::NodeRole::Voter,
    );
    let sample_resp = DomainProofResponse::create_signed(
        &challenge,
        &sample_id,
        crate::proof::DomainProofMethod::DnsTxt,
    );
    let _ = sample_resp.to_dns_txt_record(&challenge.nonce);

    match serde_json::to_string(&challenge) {
        Ok(json_str) => IpcResponse::Ok { message: json_str },
        Err(e) => IpcResponse::Error {
            reason: format!("Failed to serialize challenge: {}", e),
        },
    }
}

fn handle_verify_domain_proof(
    challenge_json: String,
    txt_record: Option<String>,
    http_json: Option<String>,
) -> IpcResponse {
    let challenge: DomainProofChallenge = match serde_json::from_str(&challenge_json) {
        Ok(c) => c,
        Err(e) => {
            return IpcResponse::Error {
                reason: format!("Invalid challenge JSON: {}", e),
            }
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Err(e) = challenge.validate_active(now) {
        return IpcResponse::Error {
            reason: e.to_string(),
        };
    }

    if let Some(txt_val) = txt_record {
        match DomainProofVerifier::parse_dns_txt_record(&txt_val, &challenge) {
            Ok(resp) => IpcResponse::Ok {
                message: format!(
                    "DNS TXT domain proof verified successfully for `{}` (node pubkey: {})",
                    resp.domain,
                    hex::encode(resp.node_pubkey)
                ),
            },
            Err(e) => IpcResponse::Error {
                reason: format!("DNS TXT verification failed: {}", e),
            },
        }
    } else if let Some(json_val) = http_json {
        match DomainProofVerifier::parse_http_nonce_json(
            &json_val,
            &challenge,
            crate::proof::DomainProofMethod::HttpNonceFallback,
        ) {
            Ok(resp) => IpcResponse::Ok {
                message: format!(
                    "HTTP Nonce domain proof verified successfully for `{}` (node pubkey: {})",
                    resp.domain,
                    hex::encode(resp.node_pubkey)
                ),
            },
            Err(e) => IpcResponse::Error {
                reason: format!("HTTP Nonce verification failed: {}", e),
            },
        }
    } else {
        let daemon_cfg = DaemonConfig::load_default_or_create(None);
        match DomainProofVerifier::verify_active_domain_control(&challenge, &daemon_cfg) {
            Ok(resp) => IpcResponse::Ok { message: format!("Live network domain proof verified successfully for `{}` via {:?} (node pubkey: {})", resp.domain, resp.proof_method, hex::encode(resp.node_pubkey)) },
            Err(e) => {
                let err = DomainProofVerifier::fail_unresolvable_domain(&challenge.domain, &e.to_string());
                IpcResponse::Error { reason: err.to_string() }
            }
        }
    }
}
