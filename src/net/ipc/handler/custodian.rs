use crate::net::ipc::handler::{IpcContext, IpcHandler};
use crate::net::ipc::{IpcCommand, IpcResponse};
use crate::pki::swarm::{CaCustodianPolicy, CustodianContract};
use crate::storage::db::ca_subtable::hex_to_bytes32;

pub struct CustodianHandler;

impl IpcHandler for CustodianHandler {
    fn handle(&self, command: &IpcCommand, ctx: &IpcContext) -> Option<IpcResponse> {
        match command {
            IpcCommand::PublishCustodianContract {
                ca_id_hex,
                work_share_pct,
                valid_until,
                tcp_endpoint,
            } => {
                let db = match ctx.db {
                    Some(d) => d,
                    None => {
                        return Some(IpcResponse::Error {
                            reason: "Database not initialized".to_string(),
                        })
                    }
                };

                let identity = match ctx.identity {
                    Some(id) => id,
                    None => {
                        return Some(IpcResponse::Error {
                            reason: "Node identity unavailable to sign contract".to_string(),
                        })
                    }
                };

                let ca_id = match hex_to_bytes32(ca_id_hex) {
                    Ok(id) => id,
                    Err(e) => return Some(IpcResponse::Error { reason: e }),
                };

                if db.get_ca(&ca_id).is_none() {
                    return Some(IpcResponse::Error {
                        reason: format!("Target CA `{}` not found in database", ca_id_hex),
                    });
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let contract = match CustodianContract::new(
                    ca_id,
                    identity.signing_key(),
                    *work_share_pct,
                    now,
                    *valid_until,
                    tcp_endpoint.clone(),
                ) {
                    Ok(c) => c,
                    Err(e) => return Some(IpcResponse::Error { reason: e }),
                };

                let contract_hash = contract.contract_hash();
                let hash_hex: String = contract_hash.iter().map(|b| format!("{:02x}", b)).collect();

                let payload_json = serde_json::to_string_pretty(&contract).unwrap_or_default();
                Some(IpcResponse::Ok {
                    message: format!(
                        "Published CustodianContract for CA `{}` (Hash: {}):\n{}",
                        ca_id_hex, hash_hex, payload_json
                    ),
                })
            }

            IpcCommand::ListCustodians { ca_id_hex } => {
                let db = match ctx.db {
                    Some(d) => d,
                    None => {
                        return Some(IpcResponse::Error {
                            reason: "Database not initialized".to_string(),
                        })
                    }
                };

                let ca_id = match hex_to_bytes32(ca_id_hex) {
                    Ok(id) => id,
                    Err(e) => return Some(IpcResponse::Error { reason: e }),
                };

                let custodians = db.get_custodians_for_ca(&ca_id);
                let json = serde_json::to_string_pretty(&custodians).unwrap_or_default();
                Some(IpcResponse::Ok { message: json })
            }

            IpcCommand::SetSeekingCustodians { ca_id_hex, seeking } => {
                let db = match ctx.db {
                    Some(d) => d,
                    None => {
                        return Some(IpcResponse::Error {
                            reason: "Database not initialized".to_string(),
                        })
                    }
                };

                let ca_id = match hex_to_bytes32(ca_id_hex) {
                    Ok(id) => id,
                    Err(e) => return Some(IpcResponse::Error { reason: e }),
                };

                let mut ca = match db.get_ca(&ca_id) {
                    Some(c) => c,
                    None => {
                        return Some(IpcResponse::Error {
                            reason: format!("CA `{}` not found", ca_id_hex),
                        })
                    }
                };

                ca.seeking_custodians = *seeking;
                if let Err(e) = db.insert_ca(ca) {
                    return Some(IpcResponse::Error {
                        reason: format!("Failed to update CA seeking_custodians: {}", e),
                    });
                }

                Some(IpcResponse::Ok {
                    message: format!(
                        "Successfully updated CA `{}` seeking_custodians = {}",
                        ca_id_hex, seeking
                    ),
                })
            }

            IpcCommand::ConfigureCustodianPolicy {
                ca_id_hex,
                max_work_share_pct,
                min_ttl_seconds,
                target_swarm_size,
                auto_accept,
            } => {
                let db = match ctx.db {
                    Some(d) => d,
                    None => {
                        return Some(IpcResponse::Error {
                            reason: "Database not initialized".to_string(),
                        })
                    }
                };

                let ca_id = match hex_to_bytes32(ca_id_hex) {
                    Ok(id) => id,
                    Err(e) => return Some(IpcResponse::Error { reason: e }),
                };

                let policy = CaCustodianPolicy {
                    max_work_share_pct: *max_work_share_pct,
                    min_ttl_seconds: *min_ttl_seconds,
                    target_swarm_size: *target_swarm_size,
                    auto_accept: *auto_accept,
                };

                if let Err(e) = db.set_ca_custodian_policy(ca_id, policy) {
                    return Some(IpcResponse::Error {
                        reason: format!("Failed to persist custodian policy: {}", e),
                    });
                }

                Some(IpcResponse::Ok {
                    message: format!(
                        "Configured blind custodian policy for CA `{}`: max {}%, min {}s TTL, target {} nodes, auto_accept = {}",
                        ca_id_hex, max_work_share_pct, min_ttl_seconds, target_swarm_size, auto_accept
                    ),
                })
            }

            IpcCommand::RemoveCustodian {
                ca_id_hex,
                worker_pubkey_hex,
            } => {
                let db = match ctx.db {
                    Some(d) => d,
                    None => {
                        return Some(IpcResponse::Error {
                            reason: "Database not initialized".to_string(),
                        })
                    }
                };

                let ca_id = match hex_to_bytes32(ca_id_hex) {
                    Ok(id) => id,
                    Err(e) => return Some(IpcResponse::Error { reason: e }),
                };
                let worker_pubkey = match hex_to_bytes32(worker_pubkey_hex) {
                    Ok(k) => k,
                    Err(e) => return Some(IpcResponse::Error { reason: e }),
                };

                match db.remove_custodian(&ca_id, &worker_pubkey) {
                    Ok(true) => Some(IpcResponse::Ok {
                        message: format!(
                            "Successfully removed custodian `{}` from CA `{}`",
                            worker_pubkey_hex, ca_id_hex
                        ),
                    }),
                    Ok(false) => Some(IpcResponse::Error {
                        reason: format!(
                            "Custodian `{}` not found in swarm for CA `{}`",
                            worker_pubkey_hex, ca_id_hex
                        ),
                    }),
                    Err(e) => Some(IpcResponse::Error {
                        reason: format!("Failed to remove custodian: {}", e),
                    }),
                }
            }

            _ => None,
        }
    }
}
