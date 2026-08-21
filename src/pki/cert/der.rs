/// Computes ASN.1 DER length octets
pub fn der_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else if len < 65536 {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else if len < 16777216 {
        vec![
            0x83,
            (len >> 16) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    } else {
        vec![
            0x84,
            (len >> 24) as u8,
            ((len >> 16) & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

/// Encodes Tag-Length-Value (TLV)
pub fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + value.len());
    out.push(tag);
    out.extend_from_slice(&der_length(value.len()));
    out.extend_from_slice(value);
    out
}

/// Encodes ASN.1 SEQUENCE (tag 0x30)
pub fn der_sequence(contents: &[u8]) -> Vec<u8> {
    der_tlv(0x30, contents)
}

/// Encodes ASN.1 SET (tag 0x31)
pub fn der_set(contents: &[u8]) -> Vec<u8> {
    der_tlv(0x31, contents)
}

/// Encodes ASN.1 INTEGER (tag 0x02) with two's complement sign preservation
pub fn der_integer(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        return der_tlv(0x02, &[0x00]);
    }
    let mut val = bytes;
    while val.len() > 1 && val[0] == 0 && (val[1] & 0x80) == 0 {
        val = &val[1..];
    }
    let mut content = Vec::with_capacity(val.len() + 1);
    if (val[0] & 0x80) != 0 {
        content.push(0x00);
    }
    content.extend_from_slice(val);
    der_tlv(0x02, &content)
}

/// Encodes ASN.1 BOOLEAN (tag 0x01)
pub fn der_boolean(val: bool) -> Vec<u8> {
    der_tlv(0x01, &[if val { 0xFF } else { 0x00 }])
}

/// Encodes ASN.1 BIT STRING (tag 0x03) with unused bits prefix
pub fn der_bit_string(bytes: &[u8], unused_bits: u8) -> Vec<u8> {
    let mut content = Vec::with_capacity(1 + bytes.len());
    content.push(unused_bits);
    content.extend_from_slice(bytes);
    der_tlv(0x03, &content)
}

/// Encodes ASN.1 OCTET STRING (tag 0x04)
pub fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
    der_tlv(0x04, bytes)
}

/// Encodes ASN.1 NULL (tag 0x05)
pub fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// Encodes ASN.1 OBJECT IDENTIFIER (tag 0x06) per ITU-T X.690 §8.19
pub fn der_oid(oid_str: &str) -> Result<Vec<u8>, String> {
    let parts: Result<Vec<u128>, _> = oid_str.split('.').map(|p| p.parse::<u128>()).collect();
    let parts = parts.map_err(|e| format!("Invalid OID string `{}`: {}", oid_str, e))?;
    if parts.len() < 2 {
        return Err(format!("OID `{}` must have at least 2 components", oid_str));
    }
    if parts[0] > 2 || (parts[0] < 2 && parts[1] >= 40) {
        return Err(format!("Invalid initial OID arcs in `{}`", oid_str));
    }
    let first_byte = (parts[0] * 40 + parts[1]) as u8;
    let mut body = vec![first_byte];

    for &arc in &parts[2..] {
        if arc == 0 {
            body.push(0);
        } else {
            let mut temp = Vec::new();
            let mut val = arc;
            while val > 0 {
                temp.push((val & 0x7F) as u8);
                val >>= 7;
            }
            temp.reverse();
            for i in 0..temp.len() - 1 {
                temp[i] |= 0x80;
            }
            body.extend_from_slice(&temp);
        }
    }
    Ok(der_tlv(0x06, &body))
}

/// Formats a Unix timestamp into an ASN.1 UTCTime string (`YYMMDDHHMMSSZ`)
pub fn unix_secs_to_utc_time_string(secs: u64) -> String {
    let mut days = secs / 86400;
    let rem_secs = secs % 86400;
    let hours = rem_secs / 3600;
    let mins = (rem_secs % 3600) / 60;
    let s = rem_secs % 60;

    let mut year = 1970;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let days_in_months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1;
    for &dim in &days_in_months {
        if days < dim {
            break;
        }
        days -= dim;
        month += 1;
    }
    let day = days + 1;

    let yy = year % 100;
    format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        yy, month, day, hours, mins, s
    )
}

/// Encodes ASN.1 UTCTime (tag 0x17)
pub fn der_utctime(secs: u64) -> Vec<u8> {
    let s = unix_secs_to_utc_time_string(secs);
    der_tlv(0x17, s.as_bytes())
}

/// Encodes Base64 data to RFC 7468 PEM block
pub fn to_pem(der: &[u8], label: &str) -> String {
    let b64 = base64_encode(der);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}

/// Lightweight standard Base64 encoder (RFC 4648)
pub fn base64_encode(data: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        out.push(CHARSET[(b0 >> 2) as usize] as char);
        out.push(CHARSET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARSET[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARSET[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}
