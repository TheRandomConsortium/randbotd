use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ca::{CaDeclaration, CaSubjectMetadata};
use super::cert::der::*;
use super::cert::extensions::*;
use super::cert::serial::CertificateSerialNumber;
use crate::crypto::agility::{CaKeyPair, KeyAlgorithm};

/// RFC 5280 §5.3.1 CRLReason enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CRLReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CACompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    PrivilegeWithdrawn = 9,
    AACompromise = 10,
}

impl CRLReason {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Unspecified),
            1 => Some(Self::KeyCompromise),
            2 => Some(Self::CACompromise),
            3 => Some(Self::AffiliationChanged),
            4 => Some(Self::Superseded),
            5 => Some(Self::CessationOfOperation),
            6 => Some(Self::CertificateHold),
            9 => Some(Self::PrivilegeWithdrawn),
            10 => Some(Self::AACompromise),
            _ => None,
        }
    }
}

/// Standard X.509 v2 CRL entry for a revoked certificate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokedCertificateEntry {
    pub serial_number: CertificateSerialNumber,
    pub revocation_date: u64,
    pub reason: Option<CRLReason>,
}

/// Standard X.509 v2 Certificate Revocation List (RFC 5280 §5)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateRevocationList {
    pub crl_number: u64,
    pub issuer_ca_id: [u8; 32],
    pub issuer: CaSubjectMetadata,
    pub this_update: u64,
    pub next_update: u64,
    pub revoked_certificates: Vec<RevokedCertificateEntry>,
    pub signature_algorithm: KeyAlgorithm,
    pub signature_bytes: Vec<u8>,
    pub der_bytes: Vec<u8>,
    pub pem_crl: String,
}

impl CertificateRevocationList {
    /// Checks whether a given serial number is marked revoked in this CRL
    pub fn is_serial_revoked(&self, serial: &CertificateSerialNumber) -> bool {
        self.revoked_certificates
            .iter()
            .any(|entry| &entry.serial_number == serial)
    }

    /// Computes deterministic SHA-256 fingerprint hash of this CRL
    #[allow(dead_code)]
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.der_bytes);
        let res = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&res);
        hash
    }

    /// Cryptographically verifies the signature on this CRL against a public key
    pub fn verify_signature(&self, pubkey_bytes: &[u8]) -> Result<(), String> {
        if self.der_bytes.is_empty() {
            return Err("CRL has empty DER representation".to_string());
        }

        // Unpack outer SEQUENCE: [tbsCertList, sigAlgo, signature]
        let outer = der_unwrap_sequence(&self.der_bytes)?;
        let tbs_end = find_tbs_cert_list_end(outer)?;
        let tbs_der = &outer[..tbs_end];

        crate::crypto::agility::verify_signature_by_algorithm(
            self.signature_algorithm,
            pubkey_bytes,
            tbs_der,
            &self.signature_bytes,
        )
    }
}

/// Builder for RFC 5280 compliant X.509 v2 CRLs
pub struct X509CrlBuilder;

impl X509CrlBuilder {
    /// Builds and signs an RFC 5280 X.509 v2 Certificate Revocation List
    pub fn build_crl(
        ca_decl: &CaDeclaration,
        ca_keypair: &CaKeyPair,
        revoked_certificates: Vec<RevokedCertificateEntry>,
        this_update: u64,
        next_update: u64,
        crl_number: u64,
    ) -> Result<CertificateRevocationList, String> {
        if next_update <= this_update {
            return Err("next_update must be greater than this_update".to_string());
        }

        let mut tbs = Vec::new();

        // 1. Version v2 (INTEGER 1)
        tbs.extend_from_slice(&der_integer(&[0x01]));

        // 2. Signature AlgorithmIdentifier
        tbs.extend_from_slice(&encode_algorithm_identifier(ca_keypair.algorithm));

        // 3. Issuer Distinguished Name
        let issuer_dn = encode_distinguished_name(&ca_decl.subject);
        tbs.extend_from_slice(&issuer_dn);

        // 4. thisUpdate & nextUpdate (UTCTime)
        tbs.extend_from_slice(&der_utctime(this_update));
        tbs.extend_from_slice(&der_utctime(next_update));

        // 5. revokedCertificates (SEQUENCE OF RevokedEntry)
        if !revoked_certificates.is_empty() {
            let mut entries_der = Vec::new();
            for entry in &revoked_certificates {
                let mut single_entry = Vec::new();
                single_entry
                    .extend_from_slice(&der_integer(&entry.serial_number.to_der_integer_bytes()));
                single_entry.extend_from_slice(&der_utctime(entry.revocation_date));

                if let Some(reason) = entry.reason {
                    // crlEntryExtensions: SEQUENCE OF Extension
                    let reason_oid = der_oid("2.5.29.21").unwrap(); // id-ce-cRLReason
                    let enum_val = der_tlv(0x0A, &[reason as u8]);
                    let ext_val = der_octet_string(&enum_val);
                    let ext_seq = der_sequence(&[reason_oid, ext_val].concat());
                    single_entry.extend_from_slice(&der_sequence(&ext_seq));
                }

                entries_der.extend_from_slice(&der_sequence(&single_entry));
            }
            tbs.extend_from_slice(&der_sequence(&entries_der));
        }

        // 6. crlExtensions: [0] EXPLICIT SEQUENCE
        let mut exts = Vec::new();
        // AuthorityKeyIdentifier (2.5.29.35)
        exts.extend_from_slice(&encode_aki(&ca_keypair.public_key_bytes));
        // CRLNumber (2.5.29.20)
        let crl_num_oid = der_oid("2.5.29.20").unwrap();
        let crl_num_val = der_octet_string(&der_integer(&crl_number.to_be_bytes()));
        exts.extend_from_slice(&der_sequence(&[crl_num_oid, crl_num_val].concat()));

        let crl_exts_seq = der_sequence(&exts);
        tbs.extend_from_slice(&der_tlv(0xA0, &crl_exts_seq));

        let tbs_der = der_sequence(&tbs);
        let signature_bytes = ca_keypair.sign(&tbs_der)?;

        let mut crl_der_inner = Vec::new();
        crl_der_inner.extend_from_slice(&tbs_der);
        crl_der_inner.extend_from_slice(&encode_algorithm_identifier(ca_keypair.algorithm));
        crl_der_inner.extend_from_slice(&der_bit_string(&signature_bytes, 0));

        let der_bytes = der_sequence(&crl_der_inner);
        let pem_crl = to_pem(&der_bytes, "X509 CRL");

        Ok(CertificateRevocationList {
            crl_number,
            issuer_ca_id: ca_decl.ca_id,
            issuer: ca_decl.subject.clone(),
            this_update,
            next_update,
            revoked_certificates,
            signature_algorithm: ca_keypair.algorithm,
            signature_bytes,
            der_bytes,
            pem_crl,
        })
    }
}

fn der_unwrap_sequence(buf: &[u8]) -> Result<&[u8], String> {
    if buf.is_empty() || buf[0] != 0x30 {
        return Err("Expected SEQUENCE tag 0x30".to_string());
    }
    let (header_len, payload_len) = parse_tlv_length(&buf[1..])?;
    let total_header = 1 + header_len;
    if buf.len() < total_header + payload_len {
        return Err("Truncated sequence buffer".to_string());
    }
    Ok(&buf[total_header..total_header + payload_len])
}

fn parse_tlv_length(buf: &[u8]) -> Result<(usize, usize), String> {
    if buf.is_empty() {
        return Err("Empty length buffer".to_string());
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

fn find_tbs_cert_list_end(inner: &[u8]) -> Result<usize, String> {
    if inner.is_empty() || inner[0] != 0x30 {
        return Err("Expected TBSCertList SEQUENCE".to_string());
    }
    let (header_len, payload_len) = parse_tlv_length(&inner[1..])?;
    Ok(1 + header_len + payload_len)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::pki::ca::compute_ca_id;

    #[test]
    fn test_crl_build_and_verify_signature_roundtrip() {
        let subject = CaSubjectMetadata {
            common_name: "The Random Consortium CRL Authority".to_string(),
            organization: Some("The Random Consortium".to_string()),
            organizational_unit: Some("PKI Revocation Operations".to_string()),
            locality: Some("Valencia".to_string()),
            state_or_province: Some("Valencia".to_string()),
            country: Some("ES".to_string()),
            email: Some("crl@therandomconsortium.org".to_string()),
        };
        let ca_id = compute_ca_id(&subject.common_name, b"test_crl_node_pubkey");
        let decl = CaDeclaration::new(
            ca_id,
            subject.clone(),
            subject,
            false,
            None,
            Vec::new(),
            1700000000,
            false,
            vec![crate::proof::DomainNetworkType::Clearnet],
        )
        .unwrap();

        let keypair = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        let revoked_serial = CertificateSerialNumber::generate();
        let revoked_entry = RevokedCertificateEntry {
            serial_number: revoked_serial.clone(),
            revocation_date: 1700000050,
            reason: Some(CRLReason::KeyCompromise),
        };

        let crl = X509CrlBuilder::build_crl(
            &decl,
            &keypair,
            vec![revoked_entry],
            1700000000,
            1700086400,
            1,
        )
        .unwrap();

        assert_eq!(crl.crl_number, 1);
        assert!(crl.is_serial_revoked(&revoked_serial));
        assert!(!crl.is_serial_revoked(&CertificateSerialNumber::generate()));
        assert!(crl.pem_crl.contains("BEGIN X509 CRL"));

        // Verify cryptographic signature
        assert!(crl.verify_signature(&keypair.public_key_bytes).is_ok());

        // Tamper verification
        let invalid_key = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        assert!(crl.verify_signature(&invalid_key.public_key_bytes).is_err());
    }
}
