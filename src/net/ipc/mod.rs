pub mod handler;

#[cfg(test)]
mod tests;

use crate::net::phonebook::Phonebook;
use crate::storage::db::Database;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcCommand {
    ImportPeer {
        peer_addr: String,
    },
    PublishCa {
        #[serde(default)]
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
        #[serde(default)]
        is_draft: Option<bool>,
        #[serde(default)]
        supported_domain_networks: Option<Vec<crate::proof::DomainNetworkType>>,
    },
    PublishOffer {
        ca_id_hex: String,
        #[serde(default)]
        offer_id: Option<u32>,
        name: String,
        #[serde(default)]
        key_algorithm: Option<crate::crypto::agility::KeyAlgorithm>,
        #[serde(default)]
        supported_domain_networks: Option<Vec<crate::proof::DomainNetworkType>>,
        #[serde(default)]
        ttl_seconds: Option<u64>,
        #[serde(default)]
        is_draft: Option<bool>,
    },
    GetOffer {
        ca_id_hex: String,
        offer_id: u32,
    },
    ListOffers {
        #[serde(default)]
        ca_id_hex: Option<String>,
    },
    ChallengeDomainProof {
        domain: String,
        #[serde(default)]
        network_type: Option<crate::proof::DomainNetworkType>,
        #[serde(default)]
        ttl_seconds: Option<u64>,
    },
    VerifyDomainProof {
        challenge_json: String,
        #[serde(default)]
        txt_record: Option<String>,
        #[serde(default)]
        http_json: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcResponse {
    Ok { message: String },
    Error { reason: String },
}

pub struct IpcServer {
    socket_path: PathBuf,
    phonebook: Arc<RwLock<Phonebook>>,
    db: Option<Arc<Database>>,
}

impl IpcServer {
    pub fn new(socket_path: PathBuf, phonebook: Arc<RwLock<Phonebook>>) -> Self {
        Self {
            socket_path,
            phonebook,
            db: None,
        }
    }

    pub fn with_db(
        socket_path: PathBuf,
        phonebook: Arc<RwLock<Phonebook>>,
        db: Arc<Database>,
    ) -> Self {
        let mut server = Self::new(socket_path, phonebook);
        server.db = Some(db);
        server
    }

    /// Spawns the Unix Domain Socket IPC listener loop in a background tokio task
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if self.socket_path.exists() {
                let _ = std::fs::remove_file(&self.socket_path);
            }

            if let Some(parent) = self.socket_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            let listener = match UnixListener::bind(&self.socket_path) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!(
                        "  -> IPC SERVER ERROR: Failed to bind socket {}: {}",
                        self.socket_path.display(),
                        e
                    );
                    return;
                }
            };

            println!(
                "  -> Local Daemon IPC Control Server ACTIVE on {}",
                self.socket_path.display()
            );

            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let phonebook = Arc::clone(&self.phonebook);
                        let db = self.db.clone();
                        tokio::spawn(async move {
                            let (reader, mut writer) = stream.into_split();
                            let mut buf_reader = BufReader::new(reader);
                            let mut line = String::new();

                            if buf_reader.read_line(&mut line).await.is_ok() {
                                let response = match serde_json::from_str::<IpcCommand>(&line) {
                                    Ok(cmd) => {
                                        handler::handle_ipc_command(cmd, &phonebook, db.as_ref())
                                    }
                                    Err(err) => IpcResponse::Error {
                                        reason: format!("Invalid IPC command JSON: {}", err),
                                    },
                                };

                                if let Ok(json_resp) = serde_json::to_string(&response) {
                                    let _ = writer.write_all(json_resp.as_bytes()).await;
                                    let _ = writer.write_all(b"\n").await;
                                }
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("  -> IPC Accept error: {}", e);
                    }
                }
            }
        })
    }
}
