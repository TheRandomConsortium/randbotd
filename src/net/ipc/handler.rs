use crate::crypto::agility::KeyAlgorithm;
use crate::crypto::ca::{compute_ca_id, CaDeclaration, CaSubjectMetadata};
use crate::net::ipc::{IpcCommand, IpcResponse};
use crate::net::phonebook::Phonebook;
use crate::storage::db::Database;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
fn get_masterpass() -> Vec<u8> {
    if let Ok(pass) = std::env::var("RANDBOTD_MASTERPASS") {
        pass.into_bytes()
    } else if let Ok(data) = std::fs::read("/etc/randbotd/masterpass.cred") {
        data
    } else {
        b"randbotd_masterpass_default_key".to_vec()
    }
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
            key_algorithm,
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
            key_algorithm,
            db,
        ),
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
    key_algorithm: Option<KeyAlgorithm>,
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

    let ca_id = if let Some(ref hex_str) = ca_id_hex {
        match crate::storage::db::ca_subtable::hex_to_bytes32(hex_str) {
            Ok(bytes) => bytes,
            Err(_) => compute_ca_id(subject.common_name.as_bytes()),
        }
    } else {
        compute_ca_id(subject.common_name.as_bytes())
    };

    let is_draft_val = is_draft.unwrap_or(false);
    let algo = key_algorithm.unwrap_or(KeyAlgorithm::Ed25519);

    let keypair = match crate::crypto::agility::CaKeyPair::generate(algo) {
        Ok(kp) => kp,
        Err(e) => return IpcResponse::Error { reason: e },
    };

    if let Ok(sig) = keypair.sign(ca_id.as_slice()) {
        let _ = keypair.verify(ca_id.as_slice(), &sig);
    }

    let key_file = std::env::temp_dir().join(format!("ca_key_{:02x?}.enc", &ca_id[..4]));
    let masterpass = get_masterpass();
    if keypair
        .save_encrypted_key_file(&key_file, &masterpass)
        .is_ok()
    {
        let _ = crate::crypto::agility::CaKeyPair::load_encrypted_key_file(&key_file, &masterpass);
        let _ = std::fs::remove_file(key_file);
    }

    let decl_res = if key_algorithm.is_none() {
        if is_draft_val {
            CaDeclaration::new_with_draft(
                ca_id,
                subject.clone(),
                subject,
                is_intermediate,
                path_len_constraint,
                created_at,
                true,
            )
        } else {
            CaDeclaration::new(
                ca_id,
                subject.clone(),
                subject,
                is_intermediate,
                path_len_constraint,
                created_at,
            )
        }
    } else {
        CaDeclaration::new_with_draft_and_algorithm(
            ca_id,
            subject.clone(),
            subject,
            is_intermediate,
            path_len_constraint,
            created_at,
            is_draft_val,
            keypair.algorithm,
        )
    };

    match decl_res {
        Err(e) => IpcResponse::Error { reason: e },
        Ok(decl) => {
            let ca_id_hex_res = ca_id
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            let action_str = if is_draft_val {
                "draft saved"
            } else {
                "published"
            };

            if let Some(database) = db {
                match database.insert_ca(decl) {
                    Ok(_) => IpcResponse::Ok {
                        message: format!(
                            "CA {} successfully with ID `{}` [Algorithm: {} (OID: {})]",
                            action_str,
                            ca_id_hex_res,
                            algo.name(),
                            algo.oid()
                        ),
                    },
                    Err(e) => IpcResponse::Error { reason: e },
                }
            } else {
                IpcResponse::Ok {
                    message: format!(
                        "CA declaration {} with ID `{}` [Algorithm: {} (OID: {})]",
                        action_str,
                        ca_id_hex_res,
                        algo.name(),
                        algo.oid()
                    ),
                }
            }
        }
    }
}
