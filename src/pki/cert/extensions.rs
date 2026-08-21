use sha2::{Digest, Sha256};

use super::der::*;
use super::*;
use crate::crypto::agility::KeyAlgorithm;
use crate::pki::ca::CaSubjectMetadata;

/// Encodes an X.509 Distinguished Name (DN) sequence
pub fn encode_distinguished_name(meta: &CaSubjectMetadata) -> Vec<u8> {
    let mut rdns = Vec::new();

    // Country: 2.5.4.6 (PrintableString tag 0x13)
    if let Some(ref c) = meta.country {
        let mut seq = Vec::new();
        seq.extend_from_slice(&der_oid("2.5.4.6").unwrap());
        seq.extend_from_slice(&der_tlv(0x13, c.as_bytes()));
        rdns.extend_from_slice(&der_set(&der_sequence(&seq)));
    }
    // State/Province: 2.5.4.8 (UTF8String tag 0x0C)
    if let Some(ref st) = meta.state_or_province {
        let mut seq = Vec::new();
        seq.extend_from_slice(&der_oid("2.5.4.8").unwrap());
        seq.extend_from_slice(&der_tlv(0x0C, st.as_bytes()));
        rdns.extend_from_slice(&der_set(&der_sequence(&seq)));
    }
    // Locality: 2.5.4.7 (UTF8String tag 0x0C)
    if let Some(ref l) = meta.locality {
        let mut seq = Vec::new();
        seq.extend_from_slice(&der_oid("2.5.4.7").unwrap());
        seq.extend_from_slice(&der_tlv(0x0C, l.as_bytes()));
        rdns.extend_from_slice(&der_set(&der_sequence(&seq)));
    }
    // Organization: 2.5.4.10 (UTF8String tag 0x0C)
    if let Some(ref o) = meta.organization {
        let mut seq = Vec::new();
        seq.extend_from_slice(&der_oid("2.5.4.10").unwrap());
        seq.extend_from_slice(&der_tlv(0x0C, o.as_bytes()));
        rdns.extend_from_slice(&der_set(&der_sequence(&seq)));
    }
    // Organizational Unit: 2.5.4.11 (UTF8String tag 0x0C)
    if let Some(ref ou) = meta.organizational_unit {
        let mut seq = Vec::new();
        seq.extend_from_slice(&der_oid("2.5.4.11").unwrap());
        seq.extend_from_slice(&der_tlv(0x0C, ou.as_bytes()));
        rdns.extend_from_slice(&der_set(&der_sequence(&seq)));
    }
    // Common Name: 2.5.4.3 (UTF8String tag 0x0C)
    {
        let mut seq = Vec::new();
        seq.extend_from_slice(&der_oid("2.5.4.3").unwrap());
        seq.extend_from_slice(&der_tlv(0x0C, meta.common_name.as_bytes()));
        rdns.extend_from_slice(&der_set(&der_sequence(&seq)));
    }
    // Email: 1.2.840.113549.1.9.1 (IA5String tag 0x16)
    if let Some(ref email) = meta.email {
        let mut seq = Vec::new();
        seq.extend_from_slice(&der_oid("1.2.840.113549.1.9.1").unwrap());
        seq.extend_from_slice(&der_tlv(0x16, email.as_bytes()));
        rdns.extend_from_slice(&der_set(&der_sequence(&seq)));
    }

    der_sequence(&rdns)
}

/// Encodes AlgorithmIdentifier for signing and key encapsulation
pub fn encode_algorithm_identifier(algo: KeyAlgorithm) -> Vec<u8> {
    let mut seq = Vec::new();
    match algo {
        KeyAlgorithm::Ed25519 | KeyAlgorithm::EcdsaP384 | KeyAlgorithm::MlDsa44 => {
            seq.extend_from_slice(&der_oid(algo.oid()).unwrap());
        }
        KeyAlgorithm::Rsa4096 => {
            seq.extend_from_slice(&der_oid(algo.oid()).unwrap());
            seq.extend_from_slice(&der_null());
        }
    }
    der_sequence(&seq)
}

/// Encodes SubjectPublicKeyInfo (RFC 5280 §4.1.2.7)
pub fn encode_subject_public_key_info(algo: KeyAlgorithm, public_key_bytes: &[u8]) -> Vec<u8> {
    let mut seq = Vec::new();
    match algo {
        KeyAlgorithm::Ed25519 => {
            let mut alg_id = Vec::new();
            alg_id.extend_from_slice(&der_oid(algo.oid()).unwrap());
            seq.extend_from_slice(&der_sequence(&alg_id));
            seq.extend_from_slice(&der_bit_string(public_key_bytes, 0));
        }
        KeyAlgorithm::EcdsaP384 => {
            let mut alg_id = Vec::new();
            alg_id.extend_from_slice(&der_oid("1.2.840.10045.2.1").unwrap());
            alg_id.extend_from_slice(&der_oid("1.3.132.0.34").unwrap());
            seq.extend_from_slice(&der_sequence(&alg_id));
            seq.extend_from_slice(&der_bit_string(public_key_bytes, 0));
        }
        KeyAlgorithm::Rsa4096 => {
            let mut alg_id = Vec::new();
            alg_id.extend_from_slice(&der_oid("1.2.840.113549.1.1.1").unwrap());
            alg_id.extend_from_slice(&der_null());
            seq.extend_from_slice(&der_sequence(&alg_id));
            seq.extend_from_slice(&der_bit_string(public_key_bytes, 0));
        }
        KeyAlgorithm::MlDsa44 => {
            let mut alg_id = Vec::new();
            alg_id.extend_from_slice(&der_oid(algo.oid()).unwrap());
            seq.extend_from_slice(&der_sequence(&alg_id));
            seq.extend_from_slice(&der_bit_string(public_key_bytes, 0));
        }
    }
    der_sequence(&seq)
}

/// Encodes a generic X.509 v3 Extension (RFC 5280 §4.1.2.9)
pub fn encode_extension(oid: &str, critical: bool, extn_value: &[u8]) -> Vec<u8> {
    let mut seq = Vec::new();
    seq.extend_from_slice(&der_oid(oid).unwrap());
    if critical {
        seq.extend_from_slice(&der_boolean(true));
    }
    seq.extend_from_slice(&der_octet_string(extn_value));
    der_sequence(&seq)
}

/// Encodes Basic Constraints extension (2.5.29.19)
pub fn encode_basic_constraints(is_ca: bool, path_len_constraint: Option<u32>) -> Vec<u8> {
    let mut seq = Vec::new();
    if is_ca {
        seq.extend_from_slice(&der_boolean(true));
    }
    if let Some(len) = path_len_constraint {
        seq.extend_from_slice(&der_integer(&len.to_be_bytes()));
    }
    let ext_val = der_sequence(&seq);
    encode_extension(OID_BASIC_CONSTRAINTS, true, &ext_val)
}

/// Encodes Key Usage extension (2.5.29.15)
pub fn encode_key_usage(is_ca: bool) -> Vec<u8> {
    let (byte_val, unused) = if is_ca {
        (vec![0x86], 1)
    } else {
        (vec![0xA0], 5)
    };
    let ext_val = der_bit_string(&byte_val, unused);
    encode_extension(OID_KEY_USAGE, true, &ext_val)
}

/// Encodes Extended Key Usage (EKU) extension (2.5.29.37)
pub fn encode_extended_key_usage(server_auth: bool, client_auth: bool) -> Vec<u8> {
    let mut seq = Vec::new();
    if server_auth {
        seq.extend_from_slice(&der_oid(OID_EKU_SERVER_AUTH).unwrap());
    }
    if client_auth {
        seq.extend_from_slice(&der_oid(OID_EKU_CLIENT_AUTH).unwrap());
    }
    let ext_val = der_sequence(&seq);
    encode_extension(OID_EXTENDED_KEY_USAGE, false, &ext_val)
}

/// Encodes Subject Alternative Name (SAN) extension (2.5.29.17)
pub fn encode_san(dns_names: &[String]) -> Vec<u8> {
    let mut seq = Vec::new();
    for name in dns_names {
        seq.extend_from_slice(&der_tlv(0x82, name.as_bytes()));
    }
    let ext_val = der_sequence(&seq);
    encode_extension(OID_SUBJECT_ALT_NAME, false, &ext_val)
}

/// Encodes Authority Key Identifier (AKI) extension (2.5.29.35)
pub fn encode_aki(ca_pubkey_bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(ca_pubkey_bytes);
    let hash = hasher.finalize();
    let key_id = der_tlv(0x80, &hash);
    let ext_val = der_sequence(&key_id);
    encode_extension(OID_AUTHORITY_KEY_IDENTIFIER, false, &ext_val)
}

/// Encodes Subject Key Identifier (SKI) extension (2.5.29.14)
pub fn encode_ski(subject_pubkey_bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(subject_pubkey_bytes);
    let hash = hasher.finalize();
    let ext_val = der_octet_string(&hash);
    encode_extension(OID_SUBJECT_KEY_IDENTIFIER, false, &ext_val)
}

/// Encodes Name Constraints extension (2.5.29.30) for Intermediate CAs (CA-14)
pub fn encode_name_constraints(permitted_subtrees: &[String]) -> Vec<u8> {
    let mut subtrees_seq = Vec::new();
    for sub in permitted_subtrees {
        let mut subtree = Vec::new();
        subtree.extend_from_slice(&der_tlv(0x82, sub.as_bytes()));
        subtrees_seq.extend_from_slice(&der_sequence(&subtree));
    }
    let permitted = der_tlv(0xA0, &subtrees_seq);
    let ext_val = der_sequence(&permitted);
    encode_extension(OID_NAME_CONSTRAINTS, NAME_CONSTRAINTS_CRITICAL, &ext_val)
}

/// Encodes Critical Web-of-Trust extension (CA-10)
pub fn encode_wot_extension(uuid_or_metadata: &str) -> Vec<u8> {
    let ext_val = der_octet_string(uuid_or_metadata.as_bytes());
    encode_extension(OID_CRITICAL_WOT_EXTENSION, WOT_EXTENSION_CRITICAL, &ext_val)
}

/// Encodes Domain Proof Binding extension (CA-03)
pub fn encode_domain_proof_extension(proof_data: &str) -> Vec<u8> {
    let ext_val = der_octet_string(proof_data.as_bytes());
    encode_extension(OID_DOMAIN_PROOF_BINDING, false, &ext_val)
}

/// Encodes TBSCertificate structure (RFC 5280 §4.1)
#[allow(clippy::too_many_arguments)]
pub fn encode_tbs_certificate(
    serial: &CertificateSerialNumber,
    sig_algo: KeyAlgorithm,
    issuer_dn_der: &[u8],
    not_before: u64,
    not_after: u64,
    subject_dn_der: &[u8],
    spki_der: &[u8],
    extensions_der: &[u8],
) -> Result<Vec<u8>, String> {
    let mut tbs = Vec::new();

    let version_int = der_integer(&[0x02]);
    let version_explicit = der_tlv(0xA0, &version_int);
    tbs.extend_from_slice(&version_explicit);

    tbs.extend_from_slice(&der_integer(&serial.to_der_integer_bytes()));
    tbs.extend_from_slice(&encode_algorithm_identifier(sig_algo));
    tbs.extend_from_slice(issuer_dn_der);

    let mut val_seq = Vec::new();
    val_seq.extend_from_slice(&der_utctime(not_before));
    val_seq.extend_from_slice(&der_utctime(not_after));
    tbs.extend_from_slice(&der_sequence(&val_seq));

    tbs.extend_from_slice(subject_dn_der);
    tbs.extend_from_slice(spki_der);

    if !extensions_der.is_empty() {
        let ext_seq = der_sequence(extensions_der);
        let ext_explicit = der_tlv(0xA3, &ext_seq);
        tbs.extend_from_slice(&ext_explicit);
    }

    Ok(der_sequence(&tbs))
}

/// Encodes signed Certificate SEQUENCE (RFC 5280 §4.1)
pub fn encode_signed_certificate(
    tbs_der: &[u8],
    sig_algo: KeyAlgorithm,
    signature_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let mut cert = Vec::new();
    cert.extend_from_slice(tbs_der);
    cert.extend_from_slice(&encode_algorithm_identifier(sig_algo));
    cert.extend_from_slice(&der_bit_string(signature_bytes, 0));
    Ok(der_sequence(&cert))
}
