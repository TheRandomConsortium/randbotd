pub mod handler;

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
        key_algorithm: Option<crate::crypto::agility::KeyAlgorithm>,
        #[serde(default)]
        supported_domain_networks: Option<Vec<crate::crypto::proof::DomainNetworkType>>,
        #[serde(default)]
        ttl_seconds: Option<u64>,
    },
    ChallengeDomainProof {
        domain: String,
        #[serde(default)]
        network_type: Option<crate::crypto::proof::DomainNetworkType>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn test_ipc_command_import_peer_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("randbotd_ipc_test_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let socket_path = temp_dir.join("randbotd.sock");

        let phonebook = Arc::new(RwLock::new(Phonebook::new()));
        let server = IpcServer::new(socket_path.clone(), Arc::clone(&phonebook));
        let handle = server.spawn();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let stream = UnixStream::connect(&socket_path)
            .await
            .expect("Failed to connect to IPC socket");
        let (reader, mut writer) = stream.into_split();

        let cmd = IpcCommand::ImportPeer {
            peer_addr: "127.0.0.1:43210".to_string(),
        };
        let cmd_line = serde_json::to_string(&cmd).unwrap() + "\n";
        writer.write_all(cmd_line.as_bytes()).await.unwrap();

        let mut buf_reader = BufReader::new(reader);
        let mut resp_line = String::new();
        buf_reader.read_line(&mut resp_line).await.unwrap();

        let resp: IpcResponse = serde_json::from_str(&resp_line).unwrap();
        match resp {
            IpcResponse::Ok { message } => {
                assert!(message.contains("127.0.0.1:43210"));
            }
            _ => panic!("Expected IpcResponse::Ok"),
        }

        let pb = phonebook.read().unwrap();
        assert!(pb.all_peers().contains(&"127.0.0.1:43210".to_string()));

        handle.abort();
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[tokio::test]
    async fn test_ipc_publish_ca_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("randbotd_ipc_ca_test_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let socket_path = temp_dir.join("randbotd.sock");

        let phonebook = Arc::new(RwLock::new(Phonebook::new()));
        let db = Arc::new(Database::open(&temp_dir).unwrap());
        let server =
            IpcServer::with_db(socket_path.clone(), Arc::clone(&phonebook), Arc::clone(&db));
        let handle = server.spawn();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let stream = UnixStream::connect(&socket_path)
            .await
            .expect("Failed to connect to IPC socket");
        let (reader, mut writer) = stream.into_split();

        let cmd = IpcCommand::PublishCa {
            ca_id_hex: None,
            common_name: "The Random Consortium Root CA".to_string(),
            organization: Some("The Random Consortium".to_string()),
            organizational_unit: Some("PKI".to_string()),
            locality: Some("Valencia".to_string()),
            state_or_province: Some("Valencia".to_string()),
            country: Some("ES".to_string()),
            email: Some("root@consortium.rand".to_string()),
            is_intermediate: false,
            path_len_constraint: None,
            is_draft: None,
            key_algorithm: None,
            supported_domain_networks: Some(vec![
                crate::crypto::proof::DomainNetworkType::Clearnet,
            ]),
            ttl_seconds: None,
        };
        let cmd_line = serde_json::to_string(&cmd).unwrap() + "\n";
        writer.write_all(cmd_line.as_bytes()).await.unwrap();

        let mut buf_reader = BufReader::new(reader);
        let mut resp_line = String::new();
        buf_reader.read_line(&mut resp_line).await.unwrap();

        let resp: IpcResponse = serde_json::from_str(&resp_line).unwrap();
        match resp {
            IpcResponse::Ok { message } => {
                assert!(message.contains(
                    "CA Declaration `The Random Consortium Root CA` successfully published"
                ));
            }
            _ => panic!("Expected IpcResponse::Ok, got {:?}", resp),
        }

        let cas = db.list_cas();
        assert_eq!(cas.len(), 1);
        assert_eq!(cas[0].subject.common_name, "The Random Consortium Root CA");
        assert!(!cas[0].is_draft);

        handle.abort();
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[tokio::test]
    async fn test_ipc_ca_draft_and_edit_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("randbotd_ipc_draft_test_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let socket_path = temp_dir.join("randbotd.sock");

        let phonebook = Arc::new(RwLock::new(Phonebook::new()));
        let db = Arc::new(Database::open(&temp_dir).unwrap());
        let server =
            IpcServer::with_db(socket_path.clone(), Arc::clone(&phonebook), Arc::clone(&db));
        let handle = server.spawn();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();

        // 1. Create a draft CA
        let draft_cmd = IpcCommand::PublishCa {
            ca_id_hex: None,
            common_name: "Consortium Draft CA".to_string(),
            organization: Some("The Random Consortium".to_string()),
            organizational_unit: None,
            locality: None,
            state_or_province: None,
            country: Some("ES".to_string()),
            email: None,
            is_intermediate: false,
            path_len_constraint: None,
            is_draft: Some(true),
            key_algorithm: None,
            supported_domain_networks: Some(vec![
                crate::crypto::proof::DomainNetworkType::Clearnet,
            ]),
            ttl_seconds: None,
        };
        let cmd_line = serde_json::to_string(&draft_cmd).unwrap() + "\n";
        writer.write_all(cmd_line.as_bytes()).await.unwrap();

        let mut buf_reader = BufReader::new(reader);
        let mut resp_line = String::new();
        buf_reader.read_line(&mut resp_line).await.unwrap();

        let resp: IpcResponse = serde_json::from_str(&resp_line).unwrap();
        let ca_id_hex = match resp {
            IpcResponse::Ok { message } => {
                assert!(message.contains("draft saved"));
                message.split('`').nth(3).unwrap().to_string()
            }
            _ => panic!("Expected Ok response"),
        };

        let cas = db.list_cas();
        assert_eq!(cas.len(), 1);
        assert!(cas[0].is_draft);

        // 2. Edit existing draft CA and finalize publish (is_draft = false)
        let stream2 = UnixStream::connect(&socket_path).await.unwrap();
        let (reader2, mut writer2) = stream2.into_split();

        let edit_cmd = IpcCommand::PublishCa {
            ca_id_hex: Some(ca_id_hex.clone()),
            common_name: "Consortium Final CA".to_string(),
            organization: Some("The Random Consortium".to_string()),
            organizational_unit: Some("PKI Operations".to_string()),
            locality: Some("Valencia".to_string()),
            state_or_province: Some("Valencia".to_string()),
            country: Some("ES".to_string()),
            email: Some("ca@therandomconsortium.org".to_string()),
            is_intermediate: false,
            path_len_constraint: None,
            is_draft: Some(false),
            key_algorithm: None,
            supported_domain_networks: Some(vec![
                crate::crypto::proof::DomainNetworkType::Clearnet,
            ]),
            ttl_seconds: None,
        };
        let edit_line = serde_json::to_string(&edit_cmd).unwrap() + "\n";
        writer2.write_all(edit_line.as_bytes()).await.unwrap();

        let mut buf_reader2 = BufReader::new(reader2);
        let mut resp_line2 = String::new();
        buf_reader2.read_line(&mut resp_line2).await.unwrap();

        let resp2: IpcResponse = serde_json::from_str(&resp_line2).unwrap();
        match resp2 {
            IpcResponse::Ok { message } => {
                assert!(message.contains("successfully published"));
            }
            _ => panic!("Expected Ok response for edit"),
        }

        let cas_updated = db.list_cas();
        assert_eq!(cas_updated.len(), 1);
        assert_eq!(cas_updated[0].subject.common_name, "Consortium Final CA");
        assert!(!cas_updated[0].is_draft);

        handle.abort();
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[tokio::test]
    async fn test_ipc_publish_ca_with_key_algorithms() {
        let temp_dir =
            std::env::temp_dir().join(format!("randbotd_ipc_algo_test_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let socket_path = temp_dir.join("randbotd.sock");

        let phonebook = Arc::new(RwLock::new(Phonebook::new()));
        let db = Arc::new(Database::open(&temp_dir).unwrap());
        let server =
            IpcServer::with_db(socket_path.clone(), Arc::clone(&phonebook), Arc::clone(&db));
        let handle = server.spawn();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();

        let cmd = IpcCommand::PublishCa {
            ca_id_hex: None,
            common_name: "Consortium ML-DSA-44 PQC Root CA".to_string(),
            organization: Some("The Random Consortium".to_string()),
            organizational_unit: Some("PKI PQC".to_string()),
            locality: None,
            state_or_province: None,
            country: Some("ES".to_string()),
            email: None,
            is_intermediate: false,
            path_len_constraint: None,
            is_draft: None,
            key_algorithm: Some(crate::crypto::agility::KeyAlgorithm::MlDsa44),
            supported_domain_networks: Some(vec![
                crate::crypto::proof::DomainNetworkType::Clearnet,
            ]),
            ttl_seconds: None,
        };
        let cmd_line = serde_json::to_string(&cmd).unwrap() + "\n";
        writer.write_all(cmd_line.as_bytes()).await.unwrap();

        let mut buf_reader = BufReader::new(reader);
        let mut resp_line = String::new();
        buf_reader.read_line(&mut resp_line).await.unwrap();

        let resp: IpcResponse = serde_json::from_str(&resp_line).unwrap();
        match resp {
            IpcResponse::Ok { message } => {
                assert!(message.contains("ML-DSA-44"));
            }
            _ => panic!("Expected Ok response, got {:?}", resp),
        }

        let cas = db.list_cas();
        assert_eq!(cas.len(), 1);
        assert_eq!(
            cas[0].key_algorithm,
            crate::crypto::agility::KeyAlgorithm::MlDsa44
        );

        handle.abort();
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[tokio::test]
    async fn test_ipc_publish_ca_with_custom_ttl() {
        let temp_dir =
            std::env::temp_dir().join(format!("randbotd_ipc_ttl_test_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let socket_path = temp_dir.join("randbotd.sock");

        let phonebook = Arc::new(RwLock::new(Phonebook::new()));
        let db = Arc::new(Database::open(&temp_dir).unwrap());
        let server =
            IpcServer::with_db(socket_path.clone(), Arc::clone(&phonebook), Arc::clone(&db));
        let handle = server.spawn();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();

        let cmd = IpcCommand::PublishCa {
            ca_id_hex: None,
            common_name: "Ephemeral Micro-TTL CA".to_string(),
            organization: Some("The Random Consortium".to_string()),
            organizational_unit: None,
            locality: None,
            state_or_province: None,
            country: Some("ES".to_string()),
            email: None,
            is_intermediate: false,
            path_len_constraint: None,
            is_draft: None,
            key_algorithm: None,
            supported_domain_networks: Some(vec![
                crate::crypto::proof::DomainNetworkType::Clearnet,
            ]),
            ttl_seconds: Some(1800), // 30 minutes
        };
        let cmd_line = serde_json::to_string(&cmd).unwrap() + "\n";
        writer.write_all(cmd_line.as_bytes()).await.unwrap();

        let mut buf_reader = BufReader::new(reader);
        let mut resp_line = String::new();
        buf_reader.read_line(&mut resp_line).await.unwrap();

        let resp: IpcResponse = serde_json::from_str(&resp_line).unwrap();
        match resp {
            IpcResponse::Ok { message } => {
                assert!(message.contains("successfully published"));
            }
            _ => panic!("Expected Ok response, got {:?}", resp),
        }

        let cas = db.list_cas();
        assert_eq!(cas.len(), 1);
        assert_eq!(cas[0].ttl_seconds, 1800);

        handle.abort();
        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
