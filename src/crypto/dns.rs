//! Active UDP & DoH DNS Wire-Format Resolver Helpers for Clearnet and Handshake Daemon/System/Custom Targets

use crate::config::DaemonConfig;

/// Normalizes a single DNS label to ASCII Punycode (RFC 3492 / RFC 5891) if it contains non-ASCII characters.
pub fn normalize_dns_label_to_ascii(label: &str) -> String {
    if label.is_ascii() {
        label.to_string()
    } else if let Some(encoded) = idna::punycode::encode_str(label) {
        format!("xn--{}", encoded)
    } else {
        label.to_string()
    }
}

/// Builds binary wire-format DNS query packet payload with Punycode IDN normalization
pub fn build_dns_query_packet(qname: &str, qtype: u16) -> Vec<u8> {
    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in qname.trim_matches('.').split('.') {
        let ascii_label = normalize_dns_label_to_ascii(label);
        if !ascii_label.is_empty() && ascii_label.len() <= 63 {
            query.push(ascii_label.len() as u8);
            query.extend_from_slice(ascii_label.as_bytes());
        }
    }
    query.push(0x00);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&[0x00, 0x01]);
    query
}

/// Dispatches raw DNS wire-format query vector via UDP or DoH depending on target/mode parameters
pub fn send_dns_query_payload(
    query: &[u8],
    resolver_addr: &str,
    is_doh: bool,
) -> Result<Vec<u8>, String> {
    if is_doh {
        let url = if resolver_addr.starts_with("http://") || resolver_addr.starts_with("https://") {
            format!("{}/dns-query", resolver_addr.trim_end_matches('/'))
        } else {
            format!("https://{}/dns-query", resolver_addr)
        };
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| format!("DoH client build error: {}", e))?;

        let resp = client
            .post(&url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(query.to_vec())
            .send()
            .map_err(|e| format!("DoH POST to {} failed: {}", url, e))?;

        if !resp.status().is_success() {
            return Err(format!(
                "DoH server {} returned status {}",
                url,
                resp.status()
            ));
        }
        let bytes = resp
            .bytes()
            .map_err(|e| format!("Failed to read DoH body: {}", e))?;
        Ok(bytes.to_vec())
    } else {
        let target = if resolver_addr == "system" {
            "127.0.0.53:53"
        } else {
            resolver_addr
        };
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(1500)))
            .map_err(|e| e.to_string())?;
        socket
            .send_to(query, target)
            .map_err(|e| format!("UDP send to {} failed: {}", target, e))?;
        let mut buf = [0u8; 1024];
        let (amt, _) = socket
            .recv_from(&mut buf)
            .map_err(|e| format!("UDP recv from {} failed: {}", target, e))?;
        Ok(buf[..amt].to_vec())
    }
}

/// Queries Handshake DNS target (Daemon / System / Custom IP / DoH) for A record IP address of Handshake domain
pub fn resolve_hns_ip(domain: &str, config: &DaemonConfig) -> Result<String, String> {
    let resolver_addr = config.handshake.resolve_target_addr();
    let is_doh = config.handshake.is_doh_mode();
    let query = build_dns_query_packet(domain, 1);

    let resp = send_dns_query_payload(&query, &resolver_addr, is_doh)?;
    if resp.len() < 12 {
        return Err("DNS response buffer too short".to_string());
    }

    let rcode = resp[3] & 0x0F;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    if rcode != 0 || ancount == 0 {
        return Err(format!(
            "HNS DNS target {} returned RCODE {} with {} answers",
            resolver_addr, rcode, ancount
        ));
    }

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
        if rtype == 1 && rdlen == 4 {
            return Ok(format!(
                "{}.{}.{}.{}",
                resp[idx],
                resp[idx + 1],
                resp[idx + 2],
                resp[idx + 3]
            ));
        }
        idx += rdlen;
    }

    Err(format!(
        "No A record found in HNS DNS response for {}",
        domain
    ))
}

/// Sends a real UDP or DoH DNS query to check if a domain resolves (returns answer records with NOERROR RCODE)
pub fn check_dns_resolves_config(domain: &str, resolver_addr: &str, is_doh: bool) -> bool {
    let query = build_dns_query_packet(domain, 1);

    let resp = match send_dns_query_payload(&query, resolver_addr, is_doh) {
        Ok(r) => r,
        Err(_) => return false,
    };

    if resp.len() < 12 {
        return false;
    }
    let rcode = resp[3] & 0x0F;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);

    rcode == 0 && ancount > 0
}

pub fn check_dns_resolves(domain: &str, resolver_addr: &str) -> bool {
    check_dns_resolves_config(domain, resolver_addr, false)
}

/// Active UDP or DoH DNS TXT query helper
pub fn send_dns_txt_query_config(
    domain: &str,
    resolver_addr: &str,
    is_doh: bool,
) -> Result<Vec<String>, String> {
    let qname = format!("_randbotd-challenge.{}", domain.trim_matches('.'));
    let query = build_dns_query_packet(&qname, 16);

    let resp = send_dns_query_payload(&query, resolver_addr, is_doh)?;
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

pub fn send_udp_dns_txt_query(domain: &str, resolver_addr: &str) -> Result<Vec<String>, String> {
    send_dns_txt_query_config(domain, resolver_addr, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_dns_label_to_ascii_punycode() {
        assert_eq!(normalize_dns_label_to_ascii("example"), "example");
        assert_eq!(
            normalize_dns_label_to_ascii("_randbotd-challenge"),
            "_randbotd-challenge"
        );
        // IDN label "randºm" containing 'º' (U+00BA) normalized to "xn--randm-cka"
        assert_eq!(normalize_dns_label_to_ascii("randºm"), "xn--randm-cka");
    }

    #[test]
    fn test_build_dns_query_packet_with_idn() {
        let packet = build_dns_query_packet("randºm", 1);
        // Label len should be 13 for "xn--randm-cka"
        assert_eq!(packet[12], 13);
        assert_eq!(&packet[13..26], b"xn--randm-cka");

        let challenge_packet = build_dns_query_packet("_randbotd-challenge.randºm", 16);
        let challenge_label_len = "_randbotd-challenge".len() as u8;
        assert_eq!(challenge_packet[12], challenge_label_len);
    }
}
