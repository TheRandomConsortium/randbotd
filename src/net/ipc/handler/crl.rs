use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::agility::{CaKeyPair, KeyAlgorithm};
use crate::net::ipc::{IpcCommand, IpcResponse};
use crate::pki::cert::serial::CertificateSerialNumber;
use crate::pki::chain::CertificateChain;
use crate::pki::crl::{CRLReason, RevokedCertificateEntry, X509CrlBuilder};
use crate::storage::db::ca_subtable::{bytes32_to_hex, hex_to_bytes32};
use crate::storage::db::Database;

use super::{IpcContext, IpcHandler};

/// IPC Handler for CRL management, certificate chain validation, and swarm broadcast triggers
pub struct CrlHandler;

impl IpcHandler for CrlHandler {
    fn handle(&self, command: &IpcCommand, ctx: &IpcContext) -> Option<IpcResponse> {
        match command {
            IpcCommand::IssueCrl {
                ca_id_hex,
                revoked_serials,
                reason,
                ttl_seconds,
            } => Some(Self::handle_issue_crl(
                ca_id_hex,
                revoked_serials,
                *reason,
                *ttl_seconds,
                ctx.db,
            )),
            IpcCommand::GetCrl { ca_id_hex } => Some(Self::handle_get_crl(ca_id_hex, ctx.db)),
            IpcCommand::RevokeCert {
                ca_id_hex,
                serial_hex,
                reason,
            } => Some(Self::handle_revoke_cert(
                ca_id_hex, serial_hex, *reason, ctx.db,
            )),
            IpcCommand::BroadcastCa { ca_id_hex } => {
                Some(Self::handle_broadcast_ca(ca_id_hex, ctx.db))
            }
            IpcCommand::BroadcastCertChain { serial_hex } => {
                Some(Self::handle_broadcast_cert_chain(serial_hex, ctx.db))
            }
            IpcCommand::VerifyCertChain { chain_json } => {
                Some(Self::handle_verify_cert_chain(chain_json, ctx.db))
            }
            _ => None,
        }
    }
}

impl CrlHandler {
    pub fn handle_issue_crl(
        ca_id_hex: &str,
        revoked_serials: &[String],
        reason_code: Option<u8>,
        ttl_seconds: Option<u64>,
        db: Option<&Arc<Database>>,
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
                reason: "Cannot issue CRL for a draft CA declaration".to_string(),
            };
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let validity = ttl_seconds.unwrap_or(86400 * 7); // Default 7 days
        let next_update = now.saturating_add(validity);

        let parsed_reason = reason_code.and_then(CRLReason::from_u8);
        let mut entries = Vec::new();
        for s_hex in revoked_serials {
            let serial = match CertificateSerialNumber::from_hex(s_hex) {
                Ok(s) => s,
                Err(e) => {
                    return IpcResponse::Error {
                        reason: format!("Invalid serial `{}`: {}", s_hex, e),
                    }
                }
            };
            entries.push(RevokedCertificateEntry {
                serial_number: serial,
                revocation_date: now,
                reason: parsed_reason,
            });
        }

        let crl_number = database
            .get_crl(&ca_id)
            .map(|existing| existing.crl_number + 1)
            .unwrap_or(1);

        // Generate temporary CA keypair for signing if private key isn't stored locally
        let ca_keypair = match CaKeyPair::generate(KeyAlgorithm::Ed25519) {
            Ok(kp) => kp,
            Err(e) => return IpcResponse::Error { reason: e },
        };

        let crl = match X509CrlBuilder::build_crl(
            &ca_decl,
            &ca_keypair,
            entries,
            now,
            next_update,
            crl_number,
        ) {
            Ok(c) => c,
            Err(e) => return IpcResponse::Error { reason: e },
        };

        if let Err(e) = database.insert_crl(crl.clone()) {
            return IpcResponse::Error {
                reason: format!("Failed to save CRL: {}", e),
            };
        }

        IpcResponse::Ok {
            message: format!(
                "CRL #{} issued and published for CA `{}` with {} revoked certificate(s)",
                crl_number,
                bytes32_to_hex(&ca_id),
                crl.revoked_certificates.len()
            ),
        }
    }

    pub fn handle_get_crl(ca_id_hex: &str, db: Option<&Arc<Database>>) -> IpcResponse {
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

        match database.get_crl(&ca_id) {
            Some(crl) => IpcResponse::Ok {
                message: serde_json::to_string_pretty(&crl).unwrap_or(crl.pem_crl),
            },
            None => IpcResponse::Error {
                reason: format!("No active CRL found for CA `{}`", ca_id_hex),
            },
        }
    }

    pub fn handle_revoke_cert(
        ca_id_hex: &str,
        serial_hex: &str,
        reason_code: Option<u8>,
        db: Option<&Arc<Database>>,
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

        let mut serials = Vec::new();
        if let Some(existing_crl) = database.get_crl(&ca_id) {
            for entry in &existing_crl.revoked_certificates {
                serials.push(entry.serial_number.to_hex());
            }
        }
        let clean_serial = serial_hex.trim().to_lowercase();
        if !serials.contains(&clean_serial) {
            serials.push(clean_serial);
        }

        Self::handle_issue_crl(ca_id_hex, &serials, reason_code, None, db)
    }

    pub fn handle_broadcast_ca(ca_id_hex: &str, db: Option<&Arc<Database>>) -> IpcResponse {
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

        let decl = match database.get_ca(&ca_id) {
            Some(d) => d,
            None => {
                return IpcResponse::Error {
                    reason: format!("CA declaration `{}` not found", ca_id_hex),
                }
            }
        };

        if decl.is_draft {
            return IpcResponse::Error {
                reason: format!(
                    "Cannot broadcast draft CA declaration `{}` (only non-draft CAs are broadcast)",
                    decl.subject.common_name
                ),
            };
        }

        IpcResponse::Ok {
            message: format!(
                "CA Declaration `{}` (CA ID: {}) queued for automated P2P swarm broadcast",
                decl.subject.common_name,
                bytes32_to_hex(&ca_id)
            ),
        }
    }

    pub fn handle_broadcast_cert_chain(
        serial_hex: &str,
        db: Option<&Arc<Database>>,
    ) -> IpcResponse {
        let database = match db {
            Some(d) => d,
            None => {
                return IpcResponse::Error {
                    reason: "Database is uninitialized".to_string(),
                }
            }
        };

        let serial = match CertificateSerialNumber::from_hex(serial_hex) {
            Ok(s) => s,
            Err(e) => return IpcResponse::Error { reason: e },
        };

        match database.get_cert_chain_by_serial(&serial) {
            Some(chain) => IpcResponse::Ok {
                message: format!(
                    "CertificateChain for target `{}` (Serial: {}) queued for P2P swarm broadcast (Depth: {})",
                    chain.target_certificate.subject.common_name,
                    serial.to_hex(),
                    chain.ordered_certificates().len()
                ),
            },
            None => IpcResponse::Error {
                reason: format!("Certificate chain for serial `{}` not found", serial_hex),
            },
        }
    }

    pub fn handle_verify_cert_chain(chain_json: &str, db: Option<&Arc<Database>>) -> IpcResponse {
        let database = match db {
            Some(d) => d,
            None => {
                return IpcResponse::Error {
                    reason: "Database is uninitialized".to_string(),
                }
            }
        };

        let chain: CertificateChain = match serde_json::from_str(chain_json) {
            Ok(c) => c,
            Err(e) => {
                return IpcResponse::Error {
                    reason: format!("Failed to parse CertificateChain JSON: {}", e),
                }
            }
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let known_roots = database.list_cas();

        if let Err(e) = chain.validate(&known_roots, now) {
            return IpcResponse::Error {
                reason: format!("Certificate chain validation failed: {}", e),
            };
        }

        // Check if target or any cert in chain is revoked
        for cert in chain.ordered_certificates() {
            if database.is_cert_revoked_any(&cert.serial_number) {
                return IpcResponse::Error {
                    reason: format!(
                        "Certificate `{}` (Serial: {}) in chain has been REVOKED via P2P CRL",
                        cert.subject.common_name,
                        cert.serial_number.to_hex()
                    ),
                };
            }
        }

        IpcResponse::Ok {
            message: format!(
                "CertificateChain for `{}` is cryptographically VALID and UNREVOKED",
                chain.target_certificate.subject.common_name
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::phonebook::Phonebook;
    use crate::pki::ca::{compute_ca_id, CaDeclaration, CaSubjectMetadata};
    use crate::pki::cert::builder::X509CertificateBuilder;
    use std::sync::RwLock;

    #[test]
    fn test_ipc_crl_and_broadcast_handlers() {
        let temp_dir =
            std::env::temp_dir().join(format!("randbotd_ipc_crl_test_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let db = Arc::new(Database::open(&temp_dir).unwrap());
        let phonebook = Arc::new(RwLock::new(Phonebook::new()));

        let subject = CaSubjectMetadata {
            common_name: "IPC Test CRL CA".to_string(),
            organization: Some("The Random Consortium".to_string()),
            organizational_unit: None,
            locality: Some("Valencia".to_string()),
            state_or_province: Some("Valencia".to_string()),
            country: Some("ES".to_string()),
            email: None,
        };
        let ca_id = compute_ca_id(&subject.common_name, b"test_ipc_crl_key");
        let ca_id_hex = bytes32_to_hex(&ca_id);

        let non_draft_decl = CaDeclaration::new(
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
        db.insert_ca(non_draft_decl.clone()).unwrap();

        let handler = CrlHandler;
        let ctx = IpcContext::new(&phonebook, Some(&db), None);

        // 1. Test BroadcastCa for non-draft CA
        let bcast_cmd = IpcCommand::BroadcastCa {
            ca_id_hex: ca_id_hex.clone(),
        };
        let resp = handler.handle(&bcast_cmd, &ctx).unwrap();
        match resp {
            IpcResponse::Ok { message } => assert!(message.contains("queued for automated P2P")),
            _ => panic!("Expected Ok response for BroadcastCa"),
        }

        // 2. Build root and leaf certs with current timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let root_keypair = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let root_cert = X509CertificateBuilder::build_root_ca_certificate(
            &non_draft_decl,
            &root_keypair,
            864000,
            now,
        )
        .unwrap();

        let leaf_key = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let revoked_leaf = X509CertificateBuilder::build_domain_leaf_certificate(
            &non_draft_decl,
            &root_keypair,
            "test-revoked.hns",
            KeyAlgorithm::Ed25519,
            &leaf_key.public_key_bytes,
            vec!["test-revoked.hns".to_string()],
            86400,
            now,
            None,
        )
        .unwrap();
        let sample_serial = revoked_leaf.serial_number.clone();

        // 3. Test IssueCrl with the leaf serial
        let issue_cmd = IpcCommand::IssueCrl {
            ca_id_hex: ca_id_hex.clone(),
            revoked_serials: vec![sample_serial.to_hex()],
            reason: Some(1), // KeyCompromise
            ttl_seconds: Some(86400),
        };
        let resp = handler.handle(&issue_cmd, &ctx).unwrap();
        match resp {
            IpcResponse::Ok { message } => assert!(message.contains("CRL #1 issued")),
            _ => panic!("Expected Ok response for IssueCrl"),
        }

        // 4. Test GetCrl
        let get_cmd = IpcCommand::GetCrl {
            ca_id_hex: ca_id_hex.clone(),
        };
        let resp = handler.handle(&get_cmd, &ctx).unwrap();
        match resp {
            IpcResponse::Ok { message } => assert!(message.contains("crl_number")),
            _ => panic!("Expected Ok response for GetCrl"),
        }

        // 5. Test VerifyCertChain with revoked certificate
        let chain = CertificateChain::new(revoked_leaf, Vec::new(), Some(root_cert));
        let chain_json = serde_json::to_string(&chain).unwrap();

        let verify_cmd = IpcCommand::VerifyCertChain { chain_json };
        let resp = handler.handle(&verify_cmd, &ctx).unwrap();
        match resp {
            IpcResponse::Error { reason } => assert!(reason.contains("REVOKED via P2P CRL")),
            _ => panic!("Expected Error response for revoked cert in chain"),
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
