use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::DaemonConfig;
use crate::net::ipc::{IpcCommand, IpcResponse};
use crate::net::phonebook::Phonebook;
use crate::pki::ca::{compute_ca_id, CaDeclaration, CaSubjectMetadata};
use crate::proof::DomainNetworkType;
use crate::storage::db::ca_subtable::{bytes32_to_hex, hex_to_bytes32};
use crate::storage::db::Database;

use super::IpcHandler;

/// IPC Handler responsible for CA publication, drafting, metadata validation, and entropy initialization
pub struct CaHandler;

impl IpcHandler for CaHandler {
    fn handle(
        &self,
        command: &IpcCommand,
        phonebook: &Arc<RwLock<Phonebook>>,
        db: Option<&Arc<Database>>,
    ) -> Option<IpcResponse> {
        match command {
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
            } => Some(Self::handle_publish_ca(
                ca_id_hex.as_deref(),
                common_name,
                organization.as_deref(),
                organizational_unit.as_deref(),
                locality.as_deref(),
                state_or_province.as_deref(),
                country.as_deref(),
                email.as_deref(),
                *is_intermediate,
                *path_len_constraint,
                *is_draft,
                supported_domain_networks.as_ref(),
                phonebook,
                db,
            )),
            _ => None,
        }
    }
}

impl CaHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn handle_publish_ca(
        ca_id_hex: Option<&str>,
        common_name: &str,
        organization: Option<&str>,
        organizational_unit: Option<&str>,
        locality: Option<&str>,
        state_or_province: Option<&str>,
        country: Option<&str>,
        email: Option<&str>,
        is_intermediate: bool,
        path_len_constraint: Option<u32>,
        is_draft: Option<bool>,
        supported_domain_networks: Option<&Vec<DomainNetworkType>>,
        phonebook: &Arc<RwLock<Phonebook>>,
        db: Option<&Arc<Database>>,
    ) -> IpcResponse {
        let subject = CaSubjectMetadata {
            common_name: common_name.to_string(),
            organization: organization.map(|s| s.to_string()),
            organizational_unit: organizational_unit.map(|s| s.to_string()),
            locality: locality.map(|s| s.to_string()),
            state_or_province: state_or_province.map(|s| s.to_string()),
            country: country.map(|s| s.to_string()),
            email: email.map(|s| s.to_string()),
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
            Some(hex_str) => hex_to_bytes32(hex_str)
                .unwrap_or_else(|_| compute_ca_id(&subject.common_name, &node_pubkey)),
            None => compute_ca_id(&subject.common_name, &node_pubkey),
        };

        let is_draft_val = is_draft.unwrap_or(false);
        let networks = supported_domain_networks
            .cloned()
            .unwrap_or_else(|| vec![DomainNetworkType::Clearnet]);

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
                let sample_serial = crate::pki::cert::CertificateSerialNumber::generate();
                eprintln!(
                    "  ℹ️ [CA-13] Future cert serial entropy initialized (Entropy: {} bits, Sample: {})",
                    sample_serial.entropy_bits(),
                    sample_serial.to_hex()
                );
                IpcResponse::Ok {
                    message: format!(
                        "CA Declaration `{}` successfully {} with ca_id `{}`",
                        decl.subject.common_name, action_str, ca_id_hex_res
                    ),
                }
            }
        }
    }
}
