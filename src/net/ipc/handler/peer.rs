use std::sync::{Arc, RwLock};

use crate::net::ipc::{IpcCommand, IpcResponse};
use crate::net::phonebook::Phonebook;

use super::{IpcContext, IpcHandler};

/// IPC Handler responsible for peer network management and phonebook operations
pub struct PeerHandler;

impl IpcHandler for PeerHandler {
    fn handle(&self, command: &IpcCommand, ctx: &IpcContext) -> Option<IpcResponse> {
        match command {
            IpcCommand::ImportPeer { peer_addr } => {
                Some(Self::handle_import_peer(peer_addr, ctx.phonebook))
            }
            IpcCommand::GetNodeStatus => Some(Self::handle_get_node_status(ctx)),
            IpcCommand::ListPeers => Some(Self::handle_list_peers(ctx.phonebook)),
            _ => None,
        }
    }
}

impl PeerHandler {
    pub fn handle_import_peer(peer_addr: &str, phonebook: &Arc<RwLock<Phonebook>>) -> IpcResponse {
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

    pub fn handle_get_node_status(ctx: &IpcContext) -> IpcResponse {
        let pb = ctx.phonebook.read().unwrap();
        let node_pubkey_hex = ctx
            .identity
            .map(|id| hex::encode(id.verifying_key().to_bytes()))
            .or_else(|| pb.my_pubkey_hex.clone())
            .unwrap_or_else(|| {
                "0000000000000000000000000000000000000000000000000000000000000000".to_string()
            });

        let peer_count = pb.peers.len();

        let (total_cas, total_offers, total_certs, total_crls, total_purges) =
            if let Some(db) = ctx.db {
                let cas = db.list_cas();
                let offers_count = cas
                    .iter()
                    .map(|ca| db.list_offers_for_ca(&ca.ca_id).len())
                    .sum::<usize>();
                (
                    cas.len(),
                    offers_count,
                    db.list_cert_chains().len(),
                    db.list_crls().len(),
                    db.list_purges().len(),
                )
            } else {
                (0, 0, 0, 0, 0)
            };

        let status_obj = serde_json::json!({
            "node_pubkey_hex": node_pubkey_hex,
            "peer_count": peer_count,
            "total_cas": total_cas,
            "total_offers": total_offers,
            "total_certs": total_certs,
            "total_crls": total_crls,
            "total_purges": total_purges,
            "status": "online",
        });

        match serde_json::to_string_pretty(&status_obj) {
            Ok(json_str) => IpcResponse::Ok { message: json_str },
            Err(e) => IpcResponse::Error {
                reason: format!("Failed to serialize status: {}", e),
            },
        }
    }

    pub fn handle_list_peers(phonebook: &Arc<RwLock<Phonebook>>) -> IpcResponse {
        let pb = phonebook.read().unwrap();
        let peers: Vec<_> = pb.peers.values().cloned().collect();
        match serde_json::to_string_pretty(&peers) {
            Ok(json_str) => IpcResponse::Ok { message: json_str },
            Err(e) => IpcResponse::Error {
                reason: format!("Failed to serialize peers: {}", e),
            },
        }
    }
}
