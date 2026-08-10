use crate::net::phonebook::Phonebook;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcCommand {
    ImportPeer { peer_addr: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcResponse {
    Ok { message: String },
    Error { reason: String },
}

pub struct IpcServer {
    socket_path: PathBuf,
    phonebook: Arc<RwLock<Phonebook>>,
}

impl IpcServer {
    pub fn new(socket_path: PathBuf, phonebook: Arc<RwLock<Phonebook>>) -> Self {
        Self {
            socket_path,
            phonebook,
        }
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
                        "  -> Warning: Could not bind IPC Unix socket at {}: {}",
                        self.socket_path.display(),
                        e
                    );
                    return;
                }
            };

            println!(
                "  -> IPC Daemon Control Listener active at {}",
                self.socket_path.display()
            );

            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let phonebook = Arc::clone(&self.phonebook);
                        tokio::spawn(async move {
                            let (reader, mut writer) = stream.into_split();
                            let mut buf_reader = BufReader::new(reader);
                            let mut line = String::new();

                            if buf_reader.read_line(&mut line).await.is_ok() {
                                let response = match serde_json::from_str::<IpcCommand>(&line) {
                                    Ok(IpcCommand::ImportPeer { peer_addr }) => {
                                        let addr_clean = peer_addr.trim().to_string();
                                        if addr_clean.is_empty() {
                                            IpcResponse::Error {
                                                reason: "Empty peer address provided".to_string(),
                                            }
                                        } else {
                                            let mut pb = phonebook.write().unwrap();
                                            pb.add_peer(addr_clean.clone());
                                            IpcResponse::Ok {
                                                message: format!("Peer `{}` successfully imported into phonebook", addr_clean),
                                            }
                                        }
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
}
