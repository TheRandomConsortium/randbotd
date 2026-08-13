//! Active UDP DNS resolution and HTTP proxy network helpers for domain proof verification

use crate::config::DaemonConfig;
use crate::crypto::proof::{
    DomainNetworkType, DomainProofChallenge, DomainProofMethod, DomainProofResponse, ProofError,
};
use serde::Deserialize;

/// Sends a real UDP DNS query to check if a domain resolves (returns answer records with NOERROR RCODE)
pub fn check_dns_resolves(domain: &str, resolver_addr: &str) -> bool {
    let socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return false,
    };
    if socket
        .set_read_timeout(Some(std::time::Duration::from_millis(1500)))
        .is_err()
    {
        return false;
    }

    let qname = domain.trim_matches('.');
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in qname.split('.') {
        if label.is_empty() || label.len() > 63 {
            continue;
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    if socket.send_to(&query, resolver_addr).is_err() {
        return false;
    }

    let mut buf = [0u8; 512];
    let amt = match socket.recv_from(&mut buf) {
        Ok((a, _)) => a,
        Err(_) => return false,
    };

    if amt < 12 {
        return false;
    }
    let resp = &buf[..amt];
    let rcode = resp[3] & 0x0F;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);

    rcode == 0 && ancount > 0
}

/// Active UDP DNS TXT query helper
pub fn send_udp_dns_txt_query(domain: &str, resolver_addr: &str) -> Result<Vec<String>, String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(1500)))
        .map_err(|e| e.to_string())?;

    let qname = format!("_randbotd-challenge.{}", domain.trim_matches('.'));
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in qname.split('.') {
        if label.is_empty() || label.len() > 63 {
            continue;
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);
    query.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]);

    socket
        .send_to(&query, resolver_addr)
        .map_err(|e| format!("UDP send to {} failed: {}", resolver_addr, e))?;

    let mut buf = [0u8; 1024];
    let (amt, _) = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("UDP recv from {} failed: {}", resolver_addr, e))?;

    let resp = &buf[..amt];
    let mut txt_records = Vec::new();
    let mut idx = 12;
    while idx < resp.len() {
        let len = resp[idx] as usize;
        if len == 0 {
            idx += 5;
            break;
        }
        if (len & 0xC0) == 0xC0 {
            idx += 6;
            break;
        }
        idx += len + 1;
    }
    while idx < resp.len() {
        if (resp[idx] & 0xC0) == 0xC0 {
            idx += 2;
        } else {
            while idx < resp.len() && resp[idx] != 0 {
                idx += (resp[idx] as usize) + 1;
            }
            idx += 1;
        }
        if idx + 10 > resp.len() {
            break;
        }
        let rtype = u16::from_be_bytes([resp[idx], resp[idx + 1]]);
        let rdlen = u16::from_be_bytes([resp[idx + 8], resp[idx + 9]]) as usize;
        idx += 10;
        if idx + rdlen > resp.len() {
            break;
        }
        if rtype == 16 {
            let mut rdata_idx = idx;
            while rdata_idx < idx + rdlen {
                let txt_len = resp[rdata_idx] as usize;
                rdata_idx += 1;
                if rdata_idx + txt_len <= idx + rdlen {
                    if let Ok(s) = std::str::from_utf8(&resp[rdata_idx..rdata_idx + txt_len]) {
                        txt_records.push(s.to_string());
                    }
                    rdata_idx += txt_len;
                } else {
                    break;
                }
            }
        }
        idx += rdlen;
    }

    Ok(txt_records)
}

/// Active HTTP GET Nonce fetcher (Tor SOCKS5 / I2P HTTP Proxy / Clearnet)
pub fn fetch_http_nonce(
    domain: &str,
    net_type: DomainNetworkType,
    config: &DaemonConfig,
) -> Result<String, String> {
    let url = format!("http://{}/.well-known/randbotd-proof", domain);
    let mut builder =
        reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(5));

    match net_type {
        DomainNetworkType::Tor => {
            let proxy_addr = config
                .privacy
                .tor_socks_proxy
                .as_deref()
                .unwrap_or("127.0.0.1:9050");
            let proxy = reqwest::Proxy::all(format!("socks5h://{}", proxy_addr))
                .map_err(|e| format!("Tor proxy error: {}", e))?;
            builder = builder.proxy(proxy);
        }
        DomainNetworkType::I2P => {
            let proxy_port = config.privacy.i2p_proxy_port.unwrap_or(4444);
            let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{}", proxy_port))
                .map_err(|e| format!("I2P proxy error: {}", e))?;
            builder = builder.proxy(proxy);
        }
        _ => {}
    }

    let client = builder.build().map_err(|e| e.to_string())?;
    let resp = client
        .get(&url)
        .send()
        .map_err(|e| format!("HTTP GET {} failed: {}", url, e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "HTTP GET {} returned status {}",
            url,
            resp.status()
        ));
    }
    resp.text()
        .map_err(|e| format!("Failed to read HTTP body: {}", e))
}

pub fn parse_dns_txt_record(
    txt_val: &str,
    challenge: &DomainProofChallenge,
) -> Result<DomainProofResponse, ProofError> {
    let clean = txt_val.trim();
    let payload = clean.strip_prefix("randbotd-proof=").ok_or_else(|| {
        ProofError::InvalidSignature("DNS TXT record missing `randbotd-proof=` prefix".to_string())
    })?;

    let parts: Vec<&str> = payload.split(':').collect();
    if parts.len() != 3 {
        return Err(ProofError::InvalidSignature(
            "DNS TXT payload must contain 3 colon-separated fields".to_string(),
        ));
    }

    let nonce_bytes = hex::decode(parts[0])
        .map_err(|e| ProofError::InvalidSignature(format!("Invalid nonce hex: {}", e)))?;
    if nonce_bytes != challenge.nonce {
        return Err(ProofError::InvalidSignature(
            "Nonce does not match challenge".to_string(),
        ));
    }

    let pubkey_bytes = hex::decode(parts[1])
        .map_err(|e| ProofError::InvalidSignature(format!("Invalid pubkey hex: {}", e)))?;
    if pubkey_bytes.len() != 32 {
        return Err(ProofError::InvalidSignature(
            "Ed25519 pubkey length must be 32 bytes".to_string(),
        ));
    }

    let sig_bytes = hex::decode(parts[2])
        .map_err(|e| ProofError::InvalidSignature(format!("Invalid signature hex: {}", e)))?;
    if sig_bytes.len() != 64 {
        return Err(ProofError::InvalidSignature(
            "Ed25519 signature length must be 64 bytes".to_string(),
        ));
    }

    let mut node_pubkey = [0u8; 32];
    node_pubkey.copy_from_slice(&pubkey_bytes);

    let response = DomainProofResponse {
        challenge_id: challenge.challenge_id.clone(),
        domain: challenge.domain.clone(),
        node_pubkey,
        signature: sig_bytes,
        proof_method: DomainProofMethod::DnsTxt,
    };

    response.verify_signature(challenge)?;
    Ok(response)
}

pub fn parse_http_nonce_json(
    json_str: &str,
    challenge: &DomainProofChallenge,
) -> Result<DomainProofResponse, ProofError> {
    #[derive(Deserialize)]
    struct HttpProofPayload {
        challenge_id: String,
        domain: String,
        node_pubkey: String,
        signature: String,
    }

    let payload: HttpProofPayload = serde_json::from_str(json_str).map_err(|e| {
        ProofError::InvalidSignature(format!("Invalid HTTP Nonce JSON payload: {}", e))
    })?;

    let pubkey_bytes = hex::decode(&payload.node_pubkey)
        .map_err(|e| ProofError::InvalidSignature(format!("Invalid node_pubkey hex: {}", e)))?;
    if pubkey_bytes.len() != 32 {
        return Err(ProofError::InvalidSignature(
            "Ed25519 pubkey length must be 32 bytes".to_string(),
        ));
    }

    let sig_bytes = hex::decode(&payload.signature)
        .map_err(|e| ProofError::InvalidSignature(format!("Invalid signature hex: {}", e)))?;
    if sig_bytes.len() != 64 {
        return Err(ProofError::InvalidSignature(
            "Ed25519 signature length must be 64 bytes".to_string(),
        ));
    }

    let mut node_pubkey = [0u8; 32];
    node_pubkey.copy_from_slice(&pubkey_bytes);

    let response = DomainProofResponse {
        challenge_id: payload.challenge_id,
        domain: payload.domain,
        node_pubkey,
        signature: sig_bytes,
        proof_method: DomainProofMethod::HttpNonceFallback,
    };

    response.verify_signature(challenge)?;
    Ok(response)
}
