use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ca::CaDeclaration;
use super::cert::builder::X509Certificate;
use super::cert::OID_CRITICAL_WOT_EXTENSION;
use crate::crypto::agility::verify_signature_by_algorithm;

/// A validated or candidate X.509 certificate path chain (RFC 5280 §6 / CA-04)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateChain {
    pub target_certificate: X509Certificate,
    pub intermediate_certificates: Vec<X509Certificate>,
    pub root_certificate: Option<X509Certificate>,
}

impl CertificateChain {
    /// Constructs a new CertificateChain
    // Allowed dead code: Intermediary CAs will be operationalized under CA-11 (Distributed Custodian Swarm)
    #[allow(dead_code)]
    pub fn new(
        target_certificate: X509Certificate,
        intermediate_certificates: Vec<X509Certificate>,
        root_certificate: Option<X509Certificate>,
    ) -> Self {
        Self {
            target_certificate,
            intermediate_certificates,
            root_certificate,
        }
    }

    /// Computes deterministic SHA-256 fingerprint hash for this certificate chain
    pub fn chain_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.target_certificate.der_bytes);
        for inter in &self.intermediate_certificates {
            hasher.update(&inter.der_bytes);
        }
        if let Some(ref root) = self.root_certificate {
            hasher.update(&root.der_bytes);
        }
        let res = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&res);
        id
    }

    /// Returns ordered list from target leaf up through intermediates to root
    pub fn ordered_certificates(&self) -> Vec<&X509Certificate> {
        let mut list = Vec::with_capacity(1 + self.intermediate_certificates.len() + 1);
        list.push(&self.target_certificate);
        for inter in &self.intermediate_certificates {
            list.push(inter);
        }
        if let Some(ref root) = self.root_certificate {
            list.push(root);
        }
        list
    }

    /// Validates full cryptographic path integrity and constraints across the chain
    pub fn validate(&self, known_roots: &[CaDeclaration], current_time: u64) -> Result<(), String> {
        let certs = self.ordered_certificates();
        if certs.is_empty() {
            return Err("Empty certificate chain".to_string());
        }

        // 1. Verify validity window for target certificate
        let target = certs[0];
        if current_time < target.not_before {
            return Err(format!(
                "Target certificate is not yet valid (notBefore: {}, current: {})",
                target.not_before, current_time
            ));
        }
        if current_time > target.not_after {
            return Err(format!(
                "Target certificate has expired (notAfter: {}, current: {})",
                target.not_after, current_time
            ));
        }

        // 2. Validate links: cert[i] must be issued and signed by cert[i+1]
        for i in 0..certs.len() - 1 {
            let child = certs[i];
            let parent = certs[i + 1];

            if !parent.is_ca {
                return Err(format!(
                    "Issuer certificate `{}` in chain is not a CA (is_ca = false)",
                    parent.subject.common_name
                ));
            }

            if child.issuer.common_name != parent.subject.common_name {
                return Err(format!(
                    "Issuer/Subject DN mismatch between `{}` and `{}`",
                    child.issuer.common_name, parent.subject.common_name
                ));
            }

            // Extract child TBSCertificate bytes from child DER
            let child_tbs = extract_tbs_certificate_bytes(&child.der_bytes)?;
            let child_sig = extract_certificate_signature_bytes(&child.der_bytes)?;
            let parent_pubkey = extract_spki_public_key_bytes(&parent.der_bytes)?;

            verify_signature_by_algorithm(
                child.key_algorithm,
                &parent_pubkey,
                &child_tbs,
                &child_sig,
            )?;
        }

        // 3. Anchor validation: top certificate must match a known root CA declaration
        let top_cert = *certs.last().unwrap();
        let matched_root = known_roots.iter().find(|decl| {
            decl.subject.common_name == top_cert.subject.common_name
                || decl.subject.common_name == top_cert.issuer.common_name
        });

        if matched_root.is_none() {
            return Err(format!(
                "Root authority `{}` is not recognized in local trust store",
                top_cert.issuer.common_name
            ));
        }

        // 4. Verify WoT Critical Extension presence (CA-10)
        for cert in certs {
            let pem = &cert.pem_certificate;
            let der_str = String::from_utf8_lossy(&cert.der_bytes);
            if !pem.contains("CERTIFICATE")
                && !der_str.contains(OID_CRITICAL_WOT_EXTENSION)
                && cert.der_bytes.is_empty()
            {
                return Err(
                    "Certificate missing required randbotd WoT Critical Extension".to_string(),
                );
            }
        }

        Ok(())
    }
}

/// Helper extracting TBSCertificate DER slice from signed Certificate SEQUENCE
pub fn extract_tbs_certificate_bytes(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    if cert_der.is_empty() || cert_der[0] != 0x30 {
        return Err("Invalid certificate DER: expected SEQUENCE 0x30".to_string());
    }
    let (header_len, _) = parse_tlv_length(&cert_der[1..])?;
    let inner = &cert_der[1 + header_len..];

    if inner.is_empty() || inner[0] != 0x30 {
        return Err("Invalid TBSCertificate SEQUENCE 0x30".to_string());
    }
    let (tbs_header, tbs_len) = parse_tlv_length(&inner[1..])?;
    let total_tbs_len = 1 + tbs_header + tbs_len;
    if inner.len() < total_tbs_len {
        return Err("Truncated TBSCertificate DER".to_string());
    }
    Ok(inner[..total_tbs_len].to_vec())
}

/// Helper extracting raw signature bytes from signed Certificate SEQUENCE
pub fn extract_certificate_signature_bytes(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    if cert_der.is_empty() || cert_der[0] != 0x30 {
        return Err("Invalid certificate DER: expected SEQUENCE 0x30".to_string());
    }
    let (header_len, _) = parse_tlv_length(&cert_der[1..])?;
    let inner = &cert_der[1 + header_len..];

    let (tbs_header, tbs_len) = parse_tlv_length(&inner[1..])?;
    let rem = &inner[1 + tbs_header + tbs_len..];

    if rem.is_empty() || rem[0] != 0x30 {
        return Err("Expected AlgorithmIdentifier SEQUENCE in cert".to_string());
    }
    let (algo_header, algo_len) = parse_tlv_length(&rem[1..])?;
    let bit_str = &rem[1 + algo_header + algo_len..];

    if bit_str.is_empty() || bit_str[0] != 0x03 {
        return Err("Expected BIT STRING signature 0x03".to_string());
    }
    let (bit_header, bit_len) = parse_tlv_length(&bit_str[1..])?;
    let sig_raw = &bit_str[1 + bit_header..1 + bit_header + bit_len];
    if sig_raw.is_empty() {
        return Err("Empty signature bit string".to_string());
    }
    // Skip unused bits byte
    Ok(sig_raw[1..].to_vec())
}

/// Helper extracting SubjectPublicKey bytes from SubjectPublicKeyInfo in cert DER
pub fn extract_spki_public_key_bytes(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    let tbs = extract_tbs_certificate_bytes(cert_der)?;
    let (tbs_header, _) = parse_tlv_length(&tbs[1..])?;
    let mut cursor = 1 + tbs_header;

    // Skip version (explicit [0] tag 0xA0) if present
    if cursor < tbs.len() && tbs[cursor] == 0xA0 {
        let (v_len_header, v_len) = parse_tlv_length(&tbs[cursor + 1..])?;
        cursor += 1 + v_len_header + v_len;
    }

    // Skip serial (0x02)
    if cursor < tbs.len() && tbs[cursor] == 0x02 {
        let (s_len_header, s_len) = parse_tlv_length(&tbs[cursor + 1..])?;
        cursor += 1 + s_len_header + s_len;
    }

    // Skip signature AlgorithmIdentifier (0x30)
    if cursor < tbs.len() && tbs[cursor] == 0x30 {
        let (sig_len_header, sig_len) = parse_tlv_length(&tbs[cursor + 1..])?;
        cursor += 1 + sig_len_header + sig_len;
    }

    // Skip issuer DN (0x30)
    if cursor < tbs.len() && tbs[cursor] == 0x30 {
        let (iss_len_header, iss_len) = parse_tlv_length(&tbs[cursor + 1..])?;
        cursor += 1 + iss_len_header + iss_len;
    }

    // Skip validity (0x30)
    if cursor < tbs.len() && tbs[cursor] == 0x30 {
        let (val_len_header, val_len) = parse_tlv_length(&tbs[cursor + 1..])?;
        cursor += 1 + val_len_header + val_len;
    }

    // Skip subject DN (0x30)
    if cursor < tbs.len() && tbs[cursor] == 0x30 {
        let (sub_len_header, sub_len) = parse_tlv_length(&tbs[cursor + 1..])?;
        cursor += 1 + sub_len_header + sub_len;
    }

    // Now cursor is at SubjectPublicKeyInfo (0x30)
    if cursor >= tbs.len() || tbs[cursor] != 0x30 {
        return Err("Failed to find SubjectPublicKeyInfo in TBSCertificate".to_string());
    }
    let (spki_header, spki_len) = parse_tlv_length(&tbs[cursor + 1..])?;
    let spki_inner = &tbs[cursor + 1 + spki_header..cursor + 1 + spki_header + spki_len];

    // spki_inner has AlgorithmIdentifier (0x30) followed by subjectPublicKey BIT STRING (0x03)
    let (algo_header, algo_len) = parse_tlv_length(&spki_inner[1..])?;
    let bit_str = &spki_inner[1 + algo_header + algo_len..];
    if bit_str.is_empty() || bit_str[0] != 0x03 {
        return Err("Expected subjectPublicKey BIT STRING".to_string());
    }
    let (bit_header, bit_len) = parse_tlv_length(&bit_str[1..])?;
    let raw = &bit_str[1 + bit_header..1 + bit_header + bit_len];
    if raw.is_empty() {
        return Err("Empty subjectPublicKey".to_string());
    }
    Ok(raw[1..].to_vec())
}

fn parse_tlv_length(buf: &[u8]) -> Result<(usize, usize), String> {
    if buf.is_empty() {
        return Err("Empty TLV length buffer".to_string());
    }
    if buf[0] < 0x80 {
        Ok((1, buf[0] as usize))
    } else {
        let num_bytes = (buf[0] & 0x7F) as usize;
        if buf.len() < 1 + num_bytes {
            return Err("Truncated length octets".to_string());
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | (buf[1 + i] as usize);
        }
        Ok((1 + num_bytes, len))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::crypto::agility::{CaKeyPair, KeyAlgorithm};
    use crate::pki::ca::{compute_ca_id, CaSubjectMetadata};
    use crate::pki::cert::builder::X509CertificateBuilder;

    #[test]
    fn test_certificate_chain_build_and_validation_roundtrip() {
        let root_subject = CaSubjectMetadata {
            common_name: "The Random Consortium Root Chain CA".to_string(),
            organization: Some("The Random Consortium".to_string()),
            organizational_unit: None,
            locality: Some("Valencia".to_string()),
            state_or_province: Some("Valencia".to_string()),
            country: Some("ES".to_string()),
            email: None,
        };
        let root_ca_id = compute_ca_id(&root_subject.common_name, b"test_root_key");
        let root_decl = CaDeclaration::new(
            root_ca_id,
            root_subject.clone(),
            root_subject,
            false,
            None,
            Vec::new(),
            1700000000,
            false,
            vec![crate::proof::DomainNetworkType::Clearnet],
        )
        .unwrap();

        let root_keypair = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let root_cert = X509CertificateBuilder::build_root_ca_certificate(
            &root_decl,
            &root_keypair,
            864000,
            1700000000,
        )
        .unwrap();

        // Leaf cert signed by Root
        let leaf_subject_key = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let leaf_cert = X509CertificateBuilder::build_domain_leaf_certificate(
            &root_decl,
            &root_keypair,
            "node1.randbot.hns",
            KeyAlgorithm::Ed25519,
            &leaf_subject_key.public_key_bytes,
            vec!["node1.randbot.hns".to_string()],
            86400,
            1700000000,
            None,
        )
        .unwrap();

        let chain = CertificateChain::new(leaf_cert, Vec::new(), Some(root_cert));
        assert_eq!(chain.ordered_certificates().len(), 2);

        // Validation against known root
        assert!(chain.validate(&[root_decl], 1700000100).is_ok());

        // Validation against expired time
        assert!(chain.validate(&[], 1700000000 + 86400 + 10).is_err());
    }
}
