use std::sync::{Arc, RwLock};

use crate::net::ipc::{IpcCommand, IpcResponse};
use crate::net::phonebook::Phonebook;
use crate::storage::db::Database;

use super::IpcHandler;

/// IPC Handler responsible for peer network management and phonebook operations
pub struct PeerHandler;

impl IpcHandler for PeerHandler {
    fn handle(
        &self,
        command: &IpcCommand,
        phonebook: &Arc<RwLock<Phonebook>>,
        _db: Option<&Arc<Database>>,
    ) -> Option<IpcResponse> {
        match command {
            IpcCommand::ImportPeer { peer_addr } => {
                Some(Self::handle_import_peer(peer_addr, phonebook))
            }
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
}
