use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::client::send_command;
use super::web_assets::DASHBOARD_HTML;
use crate::net::ipc::IpcCommand;

pub async fn run_dashboard_server(
    port: u16,
    socket_path: PathBuf,
    auto_open: bool,
) -> Result<(), String> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("Failed to bind dashboard server to {}: {}", addr, e))?;

    let url = format!("http://{}", addr);
    println!("\n🚀 CA Command Center Dashboard active at: {}", url);
    println!(
        "   Proxying commands to daemon at: {}\n",
        socket_path.display()
    );

    if auto_open {
        let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
    }

    let socket_arc = Arc::new(socket_path);

    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };

        let sock_clone = Arc::clone(&socket_arc);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let n = match stream.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };

            let req_str = String::from_utf8_lossy(&buf[..n]);
            let first_line = req_str.lines().next().unwrap_or("");
            let parts: Vec<&str> = first_line.split_whitespace().collect();

            if parts.len() < 2 {
                return;
            }

            let method = parts[0];
            let path = parts[1];

            let (status, content_type, body) = match (method, path) {
                ("GET", "/") | ("GET", "/index.html") => (
                    "200 OK",
                    "text/html; charset=utf-8",
                    DASHBOARD_HTML.to_string(),
                ),
                ("GET", "/api/status") => {
                    match send_command(&sock_clone, IpcCommand::GetNodeStatus).await {
                        Ok(data) => ("200 OK", "application/json", data),
                        Err(e) => (
                            "500 Internal Server Error",
                            "application/json",
                            serde_json::json!({ "error": e }).to_string(),
                        ),
                    }
                }
                ("GET", "/api/cas") => match send_command(&sock_clone, IpcCommand::ListCas).await {
                    Ok(data) => ("200 OK", "application/json", data),
                    Err(e) => (
                        "500 Internal Server Error",
                        "application/json",
                        serde_json::json!({ "error": e }).to_string(),
                    ),
                },
                ("GET", "/api/offers") => {
                    match send_command(&sock_clone, IpcCommand::ListOffers { ca_id_hex: None })
                        .await
                    {
                        Ok(data) => ("200 OK", "application/json", data),
                        Err(e) => (
                            "500 Internal Server Error",
                            "application/json",
                            serde_json::json!({ "error": e }).to_string(),
                        ),
                    }
                }
                ("POST", "/api/revoke") => {
                    let req_body = req_str.split("\r\n\r\n").nth(1).unwrap_or("");
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(req_body) {
                        let ca_id_hex = v["ca_id_hex"].as_str().unwrap_or("").to_string();
                        let serial_hex = v["serial_hex"].as_str().unwrap_or("").to_string();
                        let reason = v["reason"].as_u64().map(|r| r as u8);
                        let cmd = IpcCommand::RevokeCert {
                            ca_id_hex,
                            serial_hex,
                            reason,
                        };
                        match send_command(&sock_clone, cmd).await {
                            Ok(msg) => (
                                "200 OK",
                                "application/json",
                                serde_json::json!({ "message": msg }).to_string(),
                            ),
                            Err(e) => (
                                "400 Bad Request",
                                "application/json",
                                serde_json::json!({ "error": e }).to_string(),
                            ),
                        }
                    } else {
                        (
                            "400 Bad Request",
                            "application/json",
                            "{\"error\":\"Invalid JSON\"}".to_string(),
                        )
                    }
                }
                ("POST", "/api/purge") => {
                    let req_body = req_str.split("\r\n\r\n").nth(1).unwrap_or("");
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(req_body) {
                        let ca_id_hex = v["ca_id_hex"].as_str().unwrap_or("").to_string();
                        let domain = v["domain"].as_str().unwrap_or("").to_string();
                        let description = v["description"].as_str().unwrap_or("").to_string();
                        let cmd = IpcCommand::PurgeDomain {
                            ca_id_hex,
                            domain,
                            serial_hex: None,
                            reason: Some("utw".to_string()),
                            description,
                            strike_evidence: None,
                            ttl_seconds: None,
                        };
                        match send_command(&sock_clone, cmd).await {
                            Ok(msg) => (
                                "200 OK",
                                "application/json",
                                serde_json::json!({ "message": msg }).to_string(),
                            ),
                            Err(e) => (
                                "400 Bad Request",
                                "application/json",
                                serde_json::json!({ "error": e }).to_string(),
                            ),
                        }
                    } else {
                        (
                            "400 Bad Request",
                            "application/json",
                            "{\"error\":\"Invalid JSON\"}".to_string(),
                        )
                    }
                }
                _ => ("404 Not Found", "text/plain", "Not Found".to_string()),
            };

            let resp = format!(
                "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                content_type,
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes()).await;
        });
    }
}
