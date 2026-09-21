use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::agility::CaKeyPair;
use crate::crypto::identity::NodeIdentity;
use crate::net::ipc::{IpcCommand, IpcResponse};
use crate::pki::rotation::{KeyRotationProof, OfferKeyRotation, RotationReason};
use crate::storage::db::ca_subtable::{bytes32_to_hex, hex_to_bytes32};
use crate::storage::db::Database;

use super::{IpcContext, IpcHandler};

/// IPC Handler responsible for Key Rotation publishing, audit querying, and distrust status inspection (CA-09)
pub struct RotationHandler;

impl IpcHandler for RotationHandler {
    fn handle(&self, command: &IpcCommand, ctx: &IpcContext) -> Option<IpcResponse> {
        match command {
            IpcCommand::PublishKeyRotation {
                ca_id_hex,
                reason,
                offer_id,
                proof_json,
            } => Some(Self::handle_publish_key_rotation(
                ca_id_hex,
                reason.as_deref(),
                *offer_id,
                proof_json.as_deref(),
                ctx.db,
                ctx.identity,
            )),
            IpcCommand::GetKeyRotations { ca_id_hex } => {
                Some(Self::handle_get_key_rotations(ca_id_hex, ctx.db))
            }
            IpcCommand::GetCaDistrustStatus { ca_id_hex } => {
                Some(Self::handle_get_distrust_status(ca_id_hex, ctx.db))
            }
            IpcCommand::RecordDistrustStrike { ca_id_hex, reason } => Some(
                Self::handle_record_distrust_strike(ca_id_hex, reason.as_deref(), ctx.db),
            ),
            _ => None,
        }
    }
}

impl RotationHandler {
    pub fn handle_publish_key_rotation(
        ca_id_hex: &str,
        reason_str: Option<&str>,
        offer_id: Option<u32>,
        proof_json: Option<&str>,
        db: Option<&Arc<Database>>,
        identity: Option<&NodeIdentity>,
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

        if ca.is_draft {
            return IpcResponse::Error {
                reason: format!("Cannot rotate keys for draft CA `{}`", ca_id_hex),
            };
        }

        // Case A: Pre-formed KeyRotationProof payload provided
        if let Some(json) = proof_json {
            let proof: KeyRotationProof = match serde_json::from_str(json) {
                Ok(p) => p,
                Err(e) => {
                    return IpcResponse::Error {
                        reason: format!("Failed to parse KeyRotationProof JSON: {}", e),
                    }
                }
            };
            return match database.insert_key_rotation(proof) {
                Ok(proof_id) => IpcResponse::Ok {
                    message: format!(
                        "KeyRotationProof successfully ingested (Proof ID: {})",
                        bytes32_to_hex(&proof_id)
                    ),
                },
                Err(e) => IpcResponse::Error { reason: e },
            };
        }

        // Case B: Local signing & automatic generation
        let node_id = match identity {
            Some(id) => id,
            None => {
                return IpcResponse::Error {
                    reason: "Node identity is unavailable for local signing".to_string(),
                }
            }
        };

        let all_offers = database.list_offers_for_ca(&ca_id);
        let target_offers: Vec<crate::pki::offer::CertificateOffer> = match offer_id {
            Some(id) => {
                let found = all_offers
                    .iter()
                    .filter(|o| o.offer_id == id)
                    .cloned()
                    .collect::<Vec<_>>();
                if found.is_empty() {
                    return IpcResponse::Error {
                        reason: format!("Offer ID {} not found under CA `{}`", id, ca_id_hex),
                    };
                }
                found
            }
            None => all_offers.iter().filter(|o| !o.is_draft).cloned().collect(),
        };

        if target_offers.is_empty() {
            return IpcResponse::Error {
                reason: format!("No active offers found to rotate for CA `{}`", ca_id_hex),
            };
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let reason = match reason_str {
            Some(s)
                if s.eq_ignore_ascii_case("remediation") || s.eq_ignore_ascii_case("distrust") =>
            {
                RotationReason::DistrustRemediation
            }
            Some(s) if s.eq_ignore_ascii_case("leakage") || s.eq_ignore_ascii_case("leak") => {
                RotationReason::SuspectedLeakage
            }
            Some(s)
                if s.eq_ignore_ascii_case("compromised")
                    || s.eq_ignore_ascii_case("compromise") =>
            {
                RotationReason::CompromisedKey
            }
            Some(s) if s.eq_ignore_ascii_case("routine") || s.eq_ignore_ascii_case("hygiene") => {
                RotationReason::RoutineOperational
            }
            Some(s) => RotationReason::Other(s.to_string()),
            None => {
                if offer_id.is_none() && database.has_standing_distrust(&ca_id) {
                    RotationReason::DistrustRemediation
                } else {
                    RotationReason::RoutineOperational
                }
            }
        };

        let mut rotations = Vec::new();
        for offer in &target_offers {
            let new_keypair = match CaKeyPair::generate(offer.key_algorithm) {
                Ok(kp) => kp,
                Err(e) => {
                    return IpcResponse::Error {
                        reason: format!(
                            "Failed to generate new key for offer {}: {}",
                            offer.offer_id, e
                        ),
                    }
                }
            };
            let pop_payload = OfferKeyRotation::compute_pop_payload(
                &ca_id,
                offer.offer_id,
                &new_keypair.public_key_bytes,
                now,
            );
            let pop_sig = match new_keypair.sign(&pop_payload) {
                Ok(sig) => sig,
                Err(e) => {
                    return IpcResponse::Error {
                        reason: format!("Failed to sign PoP for offer {}: {}", offer.offer_id, e),
                    }
                }
            };

            rotations.push(OfferKeyRotation {
                offer_id: offer.offer_id,
                old_public_key: offer.public_key.clone(),
                new_public_key: new_keypair.public_key_bytes.clone(),
                key_algorithm: offer.key_algorithm,
                proof_of_possession: pop_sig,
                old_key_revocation_signature: None,
            });
        }

        let prev_opt = database.get_latest_key_rotation(&ca_id);
        let (rotation_seq, prev_rotation_hash) = match prev_opt {
            Some(ref prev) => (prev.rotation_seq + 1, prev.proof_id),
            None => (1, [0u8; 32]),
        };

        let proof = match KeyRotationProof::new(
            ca_id,
            rotation_seq,
            prev_rotation_hash,
            now,
            reason,
            rotations,
            node_id.signing_key(),
        ) {
            Ok(p) => p,
            Err(e) => return IpcResponse::Error { reason: e },
        };

        let proof_id = proof.proof_id;
        let count = proof.rotations.len();
        let was_distrusted = database.has_standing_distrust(&ca_id);

        match database.insert_key_rotation(proof) {
            Ok(_) => {
                let now_distrusted = database.has_standing_distrust(&ca_id);
                let remediation_status = if was_distrusted && !now_distrusted {
                    " | Distrust remediated and strikes reset to 0"
                } else if now_distrusted {
                    " | Standing distrust strikes remain active (partial rotation)"
                } else {
                    " | Trust standing: Clean"
                };

                IpcResponse::Ok {
                    message: format!(
                        "Key rotation #{} published for CA `{}` (Rotated {} offers, Proof ID: {}){}",
                        rotation_seq, ca_id_hex, count, bytes32_to_hex(&proof_id), remediation_status
                    ),
                }
            }
            Err(e) => IpcResponse::Error { reason: e },
        }
    }

    pub fn handle_get_key_rotations(ca_id_hex: &str, db: Option<&Arc<Database>>) -> IpcResponse {
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
        let rotations = database.get_key_rotations_for_ca(&ca_id);
        match serde_json::to_string(&rotations) {
            Ok(json_str) => IpcResponse::Ok { message: json_str },
            Err(e) => IpcResponse::Error {
                reason: format!("Failed to serialize key rotations: {}", e),
            },
        }
    }

    pub fn handle_get_distrust_status(ca_id_hex: &str, db: Option<&Arc<Database>>) -> IpcResponse {
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
        let strikes = database.get_standing_distrust_strikes(&ca_id);
        let has_distrust = database.has_standing_distrust(&ca_id);
        let history_len = database.get_key_rotations_for_ca(&ca_id).len();

        let status_json = serde_json::json!({
            "ca_id": ca_id_hex,
            "standing_distrust_strikes": strikes,
            "has_standing_distrust": has_distrust,
            "key_rotations_count": history_len,
        });

        IpcResponse::Ok {
            message: status_json.to_string(),
        }
    }

    pub fn handle_record_distrust_strike(
        ca_id_hex: &str,
        reason: Option<&str>,
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
        let strike_count = database.record_distrust_strike(&ca_id, reason.unwrap_or("Unspecified"));
        IpcResponse::Ok {
            message: format!(
                "Recorded distrust strike for CA `{}` (Total standing strikes: {})",
                ca_id_hex, strike_count
            ),
        }
    }
}
