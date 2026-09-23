use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::net::ipc::{IpcCommand, IpcResponse};

/// Resolves the default IPC socket path from environment or common locations
pub fn resolve_socket_path(custom: Option<&str>) -> PathBuf {
    if let Some(c) = custom {
        return PathBuf::from(c);
    }
    if let Ok(state_dir) = std::env::var("STATE_DIRECTORY") {
        let p = Path::new(&state_dir).join("randbotd.sock");
        if p.exists() {
            return p;
        }
    }
    let local = PathBuf::from("./randbotd.sock");
    if local.exists() {
        return local;
    }
    let var_run = PathBuf::from("/var/run/randbotd/randbotd.sock");
    if var_run.exists() {
        return var_run;
    }
    let tmp = PathBuf::from("/tmp/randbotd/randbotd.sock");
    if tmp.exists() {
        return tmp;
    }
    local
}

/// Sends an IPC command to the randbotd daemon over Unix domain socket
pub async fn send_command(socket_path: &Path, cmd: IpcCommand) -> Result<String, String> {
    let stream = UnixStream::connect(socket_path).await.map_err(|e| {
        format!(
            "Failed to connect to randbotd at {}: {}",
            socket_path.display(),
            e
        )
    })?;

    let (reader, mut writer) = stream.into_split();
    let mut payload =
        serde_json::to_string(&cmd).map_err(|e| format!("Serialization error: {}", e))?;
    payload.push('\n');

    writer
        .write_all(payload.as_bytes())
        .await
        .map_err(|e| format!("Failed to write to socket: {}", e))?;

    let mut buf_reader = BufReader::new(reader);
    let mut resp_line = String::new();
    buf_reader
        .read_line(&mut resp_line)
        .await
        .map_err(|e| format!("Failed to read from socket: {}", e))?;

    let resp: IpcResponse = serde_json::from_str(&resp_line).map_err(|e| {
        format!(
            "Failed to parse response: {} (raw: {})",
            e,
            resp_line.trim()
        )
    })?;

    match resp {
        IpcResponse::Ok { message } => Ok(message),
        IpcResponse::Error { reason } => Err(reason),
    }
}
