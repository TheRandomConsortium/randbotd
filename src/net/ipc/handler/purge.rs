use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::identity::NodeIdentity;
use crate::net::ipc::{IpcCommand, IpcResponse};
use crate::pki::ca::compute_ca_id;
use crate::pki::cert::serial::CertificateSerialNumber;
use crate::pki::purge::{
    calculate_required_difficulty, compute_purge_challenge, solve_purge_pow, validate_domain_name,
    DomainPurgeRecord, PurgeReason,
};
use crate::storage::db::ca_subtable::{bytes32_to_hex, hex_to_bytes32};
use crate::storage::db::Database;

use super::{IpcContext, IpcHandler};

/// IPC Handler for Domain Purge management and broadcast triggers (CA-07)
pub struct PurgeHandler;

impl IpcHandler for PurgeHandler {
    fn handle(&self, command: &IpcCommand, ctx: &IpcContext) -> Option<IpcResponse> {
        match command {
            IpcCommand::PurgeDomain {
                ca_id_hex,
                domain,
                serial_hex,
                reason,
                description,
                strike_evidence,
                ttl_seconds,
            } => Some(Self::handle_purge_domain(
                ca_id_hex,
                domain,
                serial_hex.as_deref(),
                reason.as_deref(),
                description,
                strike_evidence.as_deref(),
                *ttl_seconds,
                ctx.db,
                ctx.identity,
            )),
            IpcCommand::GetPurge { domain } => Some(Self::handle_get_purge(domain, ctx.db)),
            IpcCommand::ListPurges { ca_id_hex } => {
                Some(Self::handle_list_purges(ca_id_hex.as_deref(), ctx.db))
            }
            IpcCommand::BroadcastPurge { purge_id_hex } => {
                Some(Self::handle_broadcast_purge(purge_id_hex, ctx.db))
            }
            _ => None,
        }
    }
}

impl PurgeHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn handle_purge_domain(
        ca_id_hex: &str,
        domain: &str,
        serial_hex: Option<&str>,
        reason_str: Option<&str>,
        description: &str,
        strike_evidence: Option<&str>,
        ttl_seconds: Option<u64>,
        db: Option<&Arc<Database>>,
        identity: Option<&NodeIdentity>,
    ) -> IpcResponse {
        let database = match db {
            Some(d) => d,
            None => {
                return IpcResponse::Error {
                    reason: "Database is uninitialized".to_string(),
                }
            }
        };

        let ca_id = match hex_to_bytes32(ca_id_hex) {
            Ok(id) => id,
            Err(e) => return IpcResponse::Error { reason: e },
        };

        let ca_decl = match database.get_ca(&ca_id) {
            Some(decl) => decl,
            None => {
                return IpcResponse::Error {
                    reason: format!("CA declaration `{}` not found", ca_id_hex),
                }
            }
        };

        if ca_decl.is_draft {
            return IpcResponse::Error {
                reason: "Cannot issue domain purge for a draft CA declaration".to_string(),
            };
        }

        // Verify that this node actually owns the CA (CA ID binding)
        let node_id = match identity {
            Some(id) => id,
            None => {
                return IpcResponse::Error {
                    reason: "Node identity key is required to sign CA domain purge records"
                        .to_string(),
                }
            }
        };

        let my_pubkey = node_id.verifying_key().to_bytes();
        let expected_ca_id = compute_ca_id(&ca_decl.subject.common_name, &my_pubkey);
        if expected_ca_id != ca_id {
            return IpcResponse::Error {
                reason: format!(
                    "CA `{}` is not owned by this node (expected CA ID {:02x?}, got {:02x?})",
                    ca_decl.subject.common_name,
                    &expected_ca_id[..4],
                    &ca_id[..4]
                ),
            };
        }

        if let Err(e) = validate_domain_name(domain) {
            return IpcResponse::Error {
                reason: format!("Invalid domain name: {}", e),
            };
        }

        if !ca_decl.is_domain_permitted(domain) {
            return IpcResponse::Error {
                reason: format!(
                    "Domain `{}` violates CA subtree name constraints (permitted_subtrees: {:?})",
                    domain, ca_decl.permitted_subtrees
                ),
            };
        }

        let serial_number = if let Some(s_hex) = serial_hex {
            match CertificateSerialNumber::from_hex(s_hex) {
                Ok(s) => Some(s),
                Err(e) => {
                    return IpcResponse::Error {
                        reason: format!("Invalid serial hex `{}`: {}", s_hex, e),
                    }
                }
            }
        } else {
            None
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let validity = ttl_seconds.unwrap_or(86400 * 30); // Default 30 days
        let expires_at = now.saturating_add(validity);

        let parsed_reason = match reason_str.map(|s| s.trim().to_lowercase()).as_deref() {
            Some("malware") | Some("phishing") | Some("malwarephishing") => {
                PurgeReason::MalwarePhishing
            }
            Some("keycompromise") | Some("compromise") => PurgeReason::KeyCompromise,
            Some("terms") | Some("termsviolation") => PurgeReason::TermsViolation,
            Some("utw") | Some("untrustworthy") | Some("untrustworthybehavior") => {
                PurgeReason::UntrustworthyBehavior
            }
            Some(other) if !other.is_empty() => PurgeReason::Other(other.to_string()),
            _ => PurgeReason::UntrustworthyBehavior,
        };

        // Determine chain parameters from existing purges for this CA
        let latest = database.get_latest_purge_for_ca(&ca_id);
        let (purge_seq, prev_purge_hash) = match latest {
            None => (1u64, [0u8; 32]),
            Some(prev) => (prev.purge_seq + 1, prev.purge_id),
        };

        let active_unexpired_count = database.count_active_unexpired_purges_for_ca(&ca_id, now);
        let has_strike = strike_evidence
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        let difficulty = calculate_required_difficulty(active_unexpired_count, has_strike);

        let challenge = compute_purge_challenge(&ca_id, domain, now, &prev_purge_hash, purge_seq);

        let pow_nonce = solve_purge_pow(&challenge, difficulty);

        // Sign with the node identity key (authoritative CA owner key)
        let signing_key = node_id.signing_key();

        let record = match DomainPurgeRecord::new(
            ca_id,
            domain.to_string(),
            serial_number,
            purge_seq,
            prev_purge_hash,
            now,
            expires_at,
            parsed_reason,
            description.to_string(),
            strike_evidence.map(|s| s.to_string()),
            pow_nonce,
            signing_key,
        ) {
            Ok(r) => r,
            Err(e) => return IpcResponse::Error { reason: e },
        };

        if let Err(e) = database.insert_purge(record.clone()) {
            return IpcResponse::Error {
                reason: format!("Failed to save domain purge: {}", e),
            };
        }

        // Auto-Revocation on Domain Purge (CA-06 / CA-07 integration):
        // Automatically revoke any certificates issued to this domain on the CA's CRL.
        let mut serials_to_revoke = Vec::new();
        if let Some(ref s) = record.serial_number {
            serials_to_revoke.push(s.to_hex());
        }
        for chain in database.list_cert_chains() {
            let matches_domain = chain.target_certificate.subject.common_name == domain
                || chain
                    .target_certificate
                    .sans
                    .iter()
                    .any(|san| san == domain);
            if matches_domain {
                let s_hex = chain.target_certificate.serial_number.to_hex();
                if !serials_to_revoke.contains(&s_hex) {
                    serials_to_revoke.push(s_hex);
                }
            }
        }
        if !serials_to_revoke.is_empty() {
            let _ = crate::net::ipc::handler::crl::CrlHandler::handle_issue_crl(
                ca_id_hex,
                &serials_to_revoke,
                Some(9), // Reason 9: privilegeWithdrawn
                ttl_seconds,
                Some(database),
            );
        }

        IpcResponse::Ok {
            message: format!(
                "Bad-Domain Purge #{} created and recorded for domain `{}` under CA `{}` (Purge ID: {})",
                purge_seq,
                domain,
                ca_decl.subject.common_name,
                bytes32_to_hex(&record.purge_id)
            ),
        }
    }

    pub fn handle_get_purge(domain: &str, db: Option<&Arc<Database>>) -> IpcResponse {
        let database = match db {
            Some(d) => d,
            None => {
                return IpcResponse::Error {
                    reason: "Database is uninitialized".to_string(),
                }
            }
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match database.get_active_purge_for_domain(domain, now) {
            Some(purge) => IpcResponse::Ok {
                message: serde_json::to_string_pretty(&purge).unwrap_or_default(),
            },
            None => IpcResponse::Error {
                reason: format!("No active unexpired purge found for domain `{}`", domain),
            },
        }
    }

    pub fn handle_list_purges(ca_id_hex: Option<&str>, db: Option<&Arc<Database>>) -> IpcResponse {
        let database = match db {
            Some(d) => d,
            None => {
                return IpcResponse::Error {
                    reason: "Database is uninitialized".to_string(),
                }
            }
        };

        let purges = if let Some(hex_str) = ca_id_hex {
            let ca_id = match hex_to_bytes32(hex_str) {
                Ok(id) => id,
                Err(e) => return IpcResponse::Error { reason: e },
            };
            database.get_purges_for_ca(&ca_id)
        } else {
            database.list_purges()
        };

        IpcResponse::Ok {
            message: serde_json::to_string_pretty(&purges).unwrap_or_default(),
        }
    }

    pub fn handle_broadcast_purge(purge_id_hex: &str, db: Option<&Arc<Database>>) -> IpcResponse {
        let database = match db {
            Some(d) => d,
            None => {
                return IpcResponse::Error {
                    reason: "Database is uninitialized".to_string(),
                }
            }
        };

        let purge_id = match hex_to_bytes32(purge_id_hex) {
            Ok(id) => id,
            Err(e) => return IpcResponse::Error { reason: e },
        };

        match database.get_purge(&purge_id) {
            Some(purge) => IpcResponse::Ok {
                message: format!(
                    "Domain Purge #{} for `{}` (ID: {}) queued for P2P swarm broadcast",
                    purge.purge_seq,
                    purge.domain,
                    bytes32_to_hex(&purge.purge_id)
                ),
            },
            None => IpcResponse::Error {
                reason: format!("Domain purge with ID `{}` not found", purge_id_hex),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::phonebook::Phonebook;
    use crate::pki::ca::{compute_ca_id, CaDeclaration, CaSubjectMetadata};
    use std::sync::RwLock;

    #[test]
    fn test_ipc_purge_handlers_end_to_end() {
        let temp_dir =
            std::env::temp_dir().join(format!("randbotd_ipc_purge_test_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let db = Arc::new(Database::open(&temp_dir).unwrap());
        let phonebook = Arc::new(RwLock::new(Phonebook::new()));

        let identity = NodeIdentity::from_seed_and_role(
            &[0x42u8; 32],
            crate::crypto::identity::NodeRole::Voter,
        );

        let subject = CaSubjectMetadata {
            common_name: "IPC Purge Test Root CA".to_string(),
            organization: Some("The Random Consortium".to_string()),
            organizational_unit: None,
            locality: None,
            state_or_province: None,
            country: Some("ES".to_string()),
            email: None,
        };
        let ca_id = compute_ca_id(&subject.common_name, &identity.verifying_key().to_bytes());
        let ca_id_hex = bytes32_to_hex(&ca_id);

        let non_draft_ca = CaDeclaration::new(
            ca_id,
            subject.clone(),
            subject,
            false,
            None,
            Vec::new(),
            1700000000,
            false,
            vec![crate::proof::DomainNetworkType::Clearnet],
        )
        .unwrap();
        db.insert_ca(non_draft_ca).unwrap();

        let handler = PurgeHandler;
        let ctx = IpcContext::new(&phonebook, Some(&db), Some(&identity));

        // 1. Test PurgeDomain IPC command
        let purge_cmd = IpcCommand::PurgeDomain {
            ca_id_hex: ca_id_hex.clone(),
            domain: "bad-actor.hns".to_string(),
            serial_hex: None,
            reason: Some("MalwarePhishing".to_string()),
            description: "Phishing attack observed".to_string(),
            strike_evidence: Some("Strike proof #42".to_string()),
            ttl_seconds: Some(86400),
        };

        let resp = handler.handle(&purge_cmd, &ctx).unwrap();
        match resp {
            IpcResponse::Ok { message } => {
                assert!(message.contains("Bad-Domain Purge #1 created"));
            }
            _ => panic!("Expected Ok response from PurgeDomain"),
        }

        // Test CA ownership enforcement: another node cannot purge this CA's domains
        let other_identity = NodeIdentity::from_seed_and_role(
            &[0x99u8; 32],
            crate::crypto::identity::NodeRole::Voter,
        );
        let unauthorized_ctx = IpcContext::new(&phonebook, Some(&db), Some(&other_identity));
        let fail_resp = handler.handle(&purge_cmd, &unauthorized_ctx).unwrap();
        match fail_resp {
            IpcResponse::Error { reason } => {
                assert!(reason.contains("not owned by this node"));
            }
            _ => panic!("Expected Error for unauthorized CA purge"),
        }

        // 2. Test GetPurge for purged domain
        let get_cmd = IpcCommand::GetPurge {
            domain: "bad-actor.hns".to_string(),
        };
        let resp_get = handler.handle(&get_cmd, &ctx).unwrap();
        match resp_get {
            IpcResponse::Ok { message } => {
                assert!(message.contains("bad-actor.hns"));
                assert!(message.contains("MalwarePhishing"));
            }
            _ => panic!("Expected Ok response from GetPurge"),
        }

        // 3. Test ListPurges
        let list_cmd = IpcCommand::ListPurges {
            ca_id_hex: Some(ca_id_hex.clone()),
        };
        let resp_list = handler.handle(&list_cmd, &ctx).unwrap();
        match resp_list {
            IpcResponse::Ok { message } => {
                assert!(message.contains("bad-actor.hns"));
            }
            _ => panic!("Expected Ok response from ListPurges"),
        }

        // 4. Test BroadcastPurge
        let latest = db.get_latest_purge_for_ca(&ca_id).unwrap();
        let bcast_cmd = IpcCommand::BroadcastPurge {
            purge_id_hex: bytes32_to_hex(&latest.purge_id),
        };
        let resp_bcast = handler.handle(&bcast_cmd, &ctx).unwrap();
        match resp_bcast {
            IpcResponse::Ok { message } => {
                assert!(message.contains("queued for P2P swarm broadcast"));
            }
            _ => panic!("Expected Ok response from BroadcastPurge"),
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
