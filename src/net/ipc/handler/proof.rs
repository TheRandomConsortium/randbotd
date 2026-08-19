use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::DaemonConfig;
use crate::net::ipc::{IpcCommand, IpcResponse};
use crate::net::phonebook::Phonebook;
use crate::proof::{
    DomainNetworkType, DomainProofChallenge, DomainProofResponse, DomainProofVerifier,
};
use crate::storage::db::Database;

use super::IpcHandler;

/// IPC Handler responsible for domain ownership proof challenge creation and multi-network verification
pub struct ProofHandler;

impl IpcHandler for ProofHandler {
    fn handle(
        &self,
        command: &IpcCommand,
        _phonebook: &Arc<std::sync::RwLock<Phonebook>>,
        _db: Option<&Arc<Database>>,
    ) -> Option<IpcResponse> {
        match command {
            IpcCommand::ChallengeDomainProof {
                domain,
                network_type,
                ttl_seconds,
            } => Some(Self::handle_challenge_domain_proof(
                domain,
                *network_type,
                *ttl_seconds,
            )),
            IpcCommand::VerifyDomainProof {
                challenge_json,
                txt_record,
                http_json,
            } => Some(Self::handle_verify_domain_proof(
                challenge_json,
                txt_record.as_deref(),
                http_json.as_deref(),
            )),
            _ => None,
        }
    }
}

impl ProofHandler {
    pub fn handle_challenge_domain_proof(
        domain: &str,
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

    pub fn handle_verify_domain_proof(
        challenge_json: &str,
        txt_record: Option<&str>,
        http_json: Option<&str>,
    ) -> IpcResponse {
        let challenge: DomainProofChallenge = match serde_json::from_str(challenge_json) {
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
            match DomainProofVerifier::parse_dns_txt_record(txt_val, &challenge) {
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
                json_val,
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
                Ok(resp) => IpcResponse::Ok {
                    message: format!(
                        "Live network domain proof verified successfully for `{}` via {:?} (node pubkey: {})",
                        resp.domain,
                        resp.proof_method,
                        hex::encode(resp.node_pubkey)
                    ),
                },
                Err(e) => {
                    let err = DomainProofVerifier::fail_unresolvable_domain(
                        &challenge.domain,
                        &e.to_string(),
                    );
                    IpcResponse::Error {
                        reason: err.to_string(),
                    }
                }
            }
        }
    }
}
