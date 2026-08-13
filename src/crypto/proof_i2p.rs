//! I2P SAM v3.0 Bridge STREAM session transport helpers

use crate::config::DaemonConfig;
use std::io::{Read, Write};

/// Active I2P SAM v3.0 Bridge STREAM session fetcher (default port 7656)
pub fn fetch_i2p_sam_nonce(domain: &str, config: &DaemonConfig) -> Result<String, String> {
    let sam_port = config.privacy.i2p_sam_port.unwrap_or(7656);
    let sam_addr = format!("127.0.0.1:{}", sam_port);
    let mut stream = std::net::TcpStream::connect(&sam_addr)
        .map_err(|e| format!("Failed to connect to I2P SAM bridge at {}: {}", sam_addr, e))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

    stream
        .write_all(b"HELLO VERSION MIN=3.0 MAX=3.1\n")
        .map_err(|e| e.to_string())?;
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
    let reply = std::str::from_utf8(&buf[..n]).unwrap_or_default();
    if !reply.contains("RESULT=OK") {
        return Err(format!("I2P SAM HELLO failed: {}", reply.trim()));
    }

    let connect_cmd = format!(
        "STREAM CONNECT ID=randbotd_verify DESTINATION={} PORT=80\n",
        domain
    );
    stream
        .write_all(connect_cmd.as_bytes())
        .map_err(|e| e.to_string())?;
    let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
    let conn_reply = std::str::from_utf8(&buf[..n]).unwrap_or_default();
    if !conn_reply.contains("RESULT=OK") {
        return Err(format!(
            "I2P SAM STREAM CONNECT failed: {}",
            conn_reply.trim()
        ));
    }

    let http_req = format!(
        "GET /.well-known/randbotd-proof HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        domain
    );
    stream
        .write_all(http_req.as_bytes())
        .map_err(|e| e.to_string())?;

    let mut body = String::new();
    stream
        .read_to_string(&mut body)
        .map_err(|e| format!("Failed to read HTTP body over I2P SAM: {}", e))?;

    if let Some(pos) = body.find("\r\n\r\n") {
        Ok(body[pos + 4..].to_string())
    } else {
        Ok(body)
    }
}
