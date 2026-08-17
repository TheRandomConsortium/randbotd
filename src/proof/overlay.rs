//! Tor Hidden Service TLS ALPN and I2P SAM v3.0 Bridge overlay network transport helpers

use crate::config::DaemonConfig;
use crate::proof::engine::DomainNetworkType;
use rustls::client::ServerCertVerifier;
use rustls::{Certificate, ClientConfig, ClientConnection, OwnedTrustAnchor, ServerName, Stream};
use std::io::{Read, Write};
use std::sync::Arc;

struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

/// Establishes SOCKS5 proxy TCP connection
pub fn connect_socks5_proxy(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
) -> Result<std::net::TcpStream, String> {
    let mut stream = std::net::TcpStream::connect(proxy_addr)
        .map_err(|e| format!("SOCKS5 connect to {} failed: {}", proxy_addr, e))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

    stream
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| e.to_string())?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).map_err(|e| e.to_string())?;
    if resp != [0x05, 0x00] {
        return Err("SOCKS5 auth negotiation failed".to_string());
    }

    let host_bytes = target_host.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&target_port.to_be_bytes());

    stream.write_all(&req).map_err(|e| e.to_string())?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).map_err(|e| e.to_string())?;
    if reply[1] != 0x00 {
        return Err(format!("SOCKS5 connect status error {}", reply[1]));
    }

    match reply[3] {
        0x01 => {
            let mut b = [0u8; 6];
            stream.read_exact(&mut b).map_err(|e| e.to_string())?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).map_err(|e| e.to_string())?;
            let mut b = vec![0u8; l[0] as usize + 2];
            stream.read_exact(&mut b[..]).map_err(|e| e.to_string())?;
        }
        0x06 => {
            let mut b = [0u8; 18];
            stream.read_exact(&mut b).map_err(|e| e.to_string())?;
        }
        _ => return Err("Invalid SOCKS5 ATYP in reply".to_string()),
    }

    Ok(stream)
}

/// Active TLS ALPN proof fetcher using rustls ClientConfig with real ALPN protocols ("randbotd-alpn/1", "acme-tls/1")
pub fn fetch_tls_alpn_nonce(
    domain: &str,
    net_type: DomainNetworkType,
    config: &DaemonConfig,
) -> Result<String, String> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let mut client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();

    client_config.alpn_protocols = vec![b"randbotd-alpn/1".to_vec(), b"acme-tls/1".to_vec()];

    let server_name: ServerName = domain
        .try_into()
        .map_err(|_| format!("Invalid domain name `{}` for TLS ServerName", domain))?;

    let mut tls_session = ClientConnection::new(Arc::new(client_config), server_name)
        .map_err(|e| format!("Failed to create TLS ClientConnection: {}", e))?;

    let mut tcp_stream = match net_type {
        DomainNetworkType::Tor => {
            let proxy_addr = config
                .privacy
                .tor_socks_proxy
                .as_deref()
                .unwrap_or("127.0.0.1:9050");
            connect_socks5_proxy(proxy_addr, domain, 443)?
        }
        _ => std::net::TcpStream::connect(format!("{}:443", domain))
            .map_err(|e| format!("Failed to connect to {}:443: {}", domain, e))?,
    };

    tcp_stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

    let mut tls_stream = Stream::new(&mut tls_session, &mut tcp_stream);
    let http_req = format!(
        "GET /.well-known/randbotd-proof HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        domain
    );
    tls_stream
        .write_all(http_req.as_bytes())
        .map_err(|e| format!("TLS ALPN write failed: {}", e))?;

    let mut response_body = String::new();
    tls_stream
        .read_to_string(&mut response_body)
        .map_err(|e| format!("TLS ALPN read failed: {}", e))?;

    if let Some(pos) = response_body.find("\r\n\r\n") {
        Ok(response_body[pos + 4..].to_string())
    } else {
        Ok(response_body)
    }
}

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
