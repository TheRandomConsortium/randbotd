use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::net::frame::MAGIC_BYTES;

pub const CMD_GET_MOCK_CERT: u8 = 0x20;
pub const STATUS_OK: u8 = 0x00;
pub const STATUS_NOT_FOUND: u8 = 0x01;
pub const STATUS_ERR: u8 = 0x02;

pub const CONNECT_TIMEOUT: Duration = Duration::from_millis(2500);
pub const TRANSFER_TIMEOUT: Duration = Duration::from_millis(3000);
pub const MAX_RETRIES: usize = 3;
pub const MAX_CERT_SIZE: usize = 1024 * 1024; // 1 MB safety ceiling

/// In-memory staged mock certificate store indexed by SHA-256 cert hash
pub type MockCertStore = Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>;

pub fn new_mock_cert_store() -> MockCertStore {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Lightweight TCP streaming server for bulk certificate artifacts
pub struct CertificateTcpServer {
    listener: TcpListener,
    store: MockCertStore,
}

impl CertificateTcpServer {
    pub async fn bind(addr: &str, store: MockCertStore) -> Result<Self, String> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("Failed to bind TCP server on {}: {}", addr, e))?;
        Ok(Self { listener, store })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, String> {
        self.listener
            .local_addr()
            .map_err(|e| format!("Failed to query local addr: {}", e))
    }

    /// Spawns the TCP acceptance loop in the background
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let store = self.store;
            while let Ok((mut stream, _peer_addr)) = self.listener.accept().await {
                let store = store.clone();
                tokio::spawn(async move {
                    let _ = handle_tcp_client(&mut stream, store).await;
                });
            }
        })
    }
}

async fn handle_tcp_client(
    stream: &mut TcpStream,
    store: MockCertStore,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::time::timeout(TRANSFER_TIMEOUT, async {
        let mut req_header = [0u8; 37]; // 4 bytes MAGIC + 1 byte CMD + 32 bytes HASH
        stream.read_exact(&mut req_header).await?;

        if &req_header[0..4] != MAGIC_BYTES {
            let err_resp = [
                MAGIC_BYTES[0],
                MAGIC_BYTES[1],
                MAGIC_BYTES[2],
                MAGIC_BYTES[3],
                STATUS_ERR,
                0,
                0,
                0,
                0,
            ];
            stream.write_all(&err_resp).await?;
            return Ok(());
        }

        if req_header[4] != CMD_GET_MOCK_CERT {
            let err_resp = [
                MAGIC_BYTES[0],
                MAGIC_BYTES[1],
                MAGIC_BYTES[2],
                MAGIC_BYTES[3],
                STATUS_ERR,
                0,
                0,
                0,
                0,
            ];
            stream.write_all(&err_resp).await?;
            return Ok(());
        }

        let mut cert_hash = [0u8; 32];
        cert_hash.copy_from_slice(&req_header[5..37]);

        let maybe_cert = {
            let lock = store.read().map_err(|_| "Poisoned lock")?;
            lock.get(&cert_hash).cloned()
        };

        match maybe_cert {
            Some(cert_bytes) => {
                let len = cert_bytes.len() as u32;
                let mut resp_header = Vec::with_capacity(9);
                resp_header.extend_from_slice(MAGIC_BYTES);
                resp_header.push(STATUS_OK);
                resp_header.extend_from_slice(&len.to_be_bytes());

                stream.write_all(&resp_header).await?;
                stream.write_all(&cert_bytes).await?;
            }
            None => {
                let not_found_resp = [
                    MAGIC_BYTES[0],
                    MAGIC_BYTES[1],
                    MAGIC_BYTES[2],
                    MAGIC_BYTES[3],
                    STATUS_NOT_FOUND,
                    0,
                    0,
                    0,
                    0,
                ];
                stream.write_all(&not_found_resp).await?;
            }
        }
        stream.flush().await?;
        Ok(())
    })
    .await?
}

/// Hardened TCP client with anti-Slowloris transfer limits, retries, and exponential backoff
pub struct CertificateTcpClient;

impl CertificateTcpClient {
    /// Attempts to fetch a certificate matching `mock_cert_hash` from `peer_addr`.
    /// Retries up to `MAX_RETRIES` times with exponential backoff on transient errors.
    pub async fn fetch_mock_cert(
        peer_addr: &str,
        mock_cert_hash: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let mut last_err = String::from("No attempts made");

        for attempt in 0..MAX_RETRIES {
            match Self::single_fetch_attempt(peer_addr, mock_cert_hash).await {
                Ok(bytes) => return Ok(bytes),
                Err(err) => {
                    last_err = err;
                    if attempt + 1 < MAX_RETRIES {
                        let backoff_ms = 500u64 * (1u64 << attempt);
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    }
                }
            }
        }

        Err(format!(
            "Failed to fetch mock cert from `{}` after {} attempts: {}",
            peer_addr, MAX_RETRIES, last_err
        ))
    }

    async fn single_fetch_attempt(
        peer_addr: &str,
        mock_cert_hash: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let connect_fut = TcpStream::connect(peer_addr);
        let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, connect_fut)
            .await
            .map_err(|_| {
                format!(
                    "Connection timeout ({}ms) to {}",
                    CONNECT_TIMEOUT.as_millis(),
                    peer_addr
                )
            })?
            .map_err(|e| format!("Connect error to {}: {}", peer_addr, e))?;

        let transfer_fut = async {
            // Write request frame
            let mut req = Vec::with_capacity(37);
            req.extend_from_slice(MAGIC_BYTES);
            req.push(CMD_GET_MOCK_CERT);
            req.extend_from_slice(mock_cert_hash);

            stream
                .write_all(&req)
                .await
                .map_err(|e| format!("Write request error: {}", e))?;
            stream
                .flush()
                .await
                .map_err(|e| format!("Flush error: {}", e))?;

            // Read response header (9 bytes)
            let mut resp_header = [0u8; 9];
            stream
                .read_exact(&mut resp_header)
                .await
                .map_err(|e| format!("Read header error: {}", e))?;

            if &resp_header[0..4] != MAGIC_BYTES {
                return Err("Invalid magic bytes in TCP response".to_string());
            }

            let status = resp_header[4];
            if status != STATUS_OK {
                return Err(format!("Server returned non-OK status: 0x{:02x}", status));
            }

            let len = u32::from_be_bytes(resp_header[5..9].try_into().unwrap()) as usize;
            if len > MAX_CERT_SIZE {
                return Err(format!(
                    "Payload length {} exceeds maximum safety ceiling {}",
                    len, MAX_CERT_SIZE
                ));
            }

            // Read body
            let mut payload = vec![0u8; len];
            stream
                .read_exact(&mut payload)
                .await
                .map_err(|e| format!("Read payload error: {}", e))?;

            // Verify SHA-256 hash
            let mut hasher = Sha256::new();
            hasher.update(&payload);
            let calculated_hash: [u8; 32] = hasher.finalize().into();

            if &calculated_hash != mock_cert_hash {
                return Err("Integrity check failed: mock_cert_hash mismatch".to_string());
            }

            Ok(payload)
        };

        tokio::time::timeout(TRANSFER_TIMEOUT, transfer_fut)
            .await
            .map_err(|_| {
                format!(
                    "Transfer timeout / slowloris detected ({}ms)",
                    TRANSFER_TIMEOUT.as_millis()
                )
            })?
    }
}

#[cfg(test)]
mod tests;
