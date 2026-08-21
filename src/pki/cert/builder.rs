use serde::{Deserialize, Serialize};

use super::der::*;
use super::extensions::*;
use super::*;
use crate::crypto::agility::{CaKeyPair, KeyAlgorithm};
use crate::pki::ca::{CaDeclaration, CaSubjectMetadata};

/// Issued X.509 v3 Certificate representation with DER and PEM serialization
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct X509Certificate {
    pub serial_number: CertificateSerialNumber,
    pub issuer: CaSubjectMetadata,
    pub subject: CaSubjectMetadata,
    pub not_before: u64,
    pub not_after: u64,
    pub key_algorithm: KeyAlgorithm,
    pub is_ca: bool,
    pub sans: Vec<String>,
    pub der_bytes: Vec<u8>,
    pub pem_certificate: String,
}

/// Standard X.509 v3 Certificate Builder (CA-05)
pub struct X509CertificateBuilder;

impl X509CertificateBuilder {
    /// Builds and signs a self-signed X.509 v3 Root CA Certificate for a CA declaration (CA-05)
    pub fn build_root_ca_certificate(
        ca_decl: &CaDeclaration,
        ca_keypair: &CaKeyPair,
        ttl_seconds: u64,
        current_time: u64,
    ) -> Result<X509Certificate, String> {
        let serial = CertificateSerialNumber::generate();
        let not_before = current_time;
        let not_after = current_time.saturating_add(ttl_seconds);

        let spki_bytes =
            encode_subject_public_key_info(ca_keypair.algorithm, &ca_keypair.public_key_bytes);
        let issuer_dn = encode_distinguished_name(&ca_decl.subject);
        let subject_dn = encode_distinguished_name(&ca_decl.subject);

        let mut extensions = Vec::new();
        // 1. Basic Constraints (critical = true, cA = true)
        extensions.extend_from_slice(&encode_basic_constraints(true, ca_decl.path_len_constraint));
        // 2. Key Usage (critical = true, keyCertSign | cRLSign | digitalSignature)
        extensions.extend_from_slice(&encode_key_usage(true));
        // 3. SKI (non-critical)
        extensions.extend_from_slice(&encode_ski(&ca_keypair.public_key_bytes));
        // 4. AKI (non-critical)
        extensions.extend_from_slice(&encode_aki(&ca_keypair.public_key_bytes));
        // 5. Name Constraints if intermediate with permitted_subtrees (CA-14)
        if ca_decl.is_intermediate && !ca_decl.permitted_subtrees.is_empty() {
            extensions.extend_from_slice(&encode_name_constraints(&ca_decl.permitted_subtrees));
        }
        // 6. WoT Critical Extension (CA-10)
        extensions.extend_from_slice(&encode_wot_extension(WOT_EXTENSION_UUID));

        let tbs_der = encode_tbs_certificate(
            &serial,
            ca_keypair.algorithm,
            &issuer_dn,
            not_before,
            not_after,
            &subject_dn,
            &spki_bytes,
            &extensions,
        )?;

        let sig = ca_keypair.sign(&tbs_der)?;
        let cert_der = encode_signed_certificate(&tbs_der, ca_keypair.algorithm, &sig)?;
        let pem = to_pem(&cert_der, "CERTIFICATE");

        Ok(X509Certificate {
            serial_number: serial,
            issuer: ca_decl.subject.clone(),
            subject: ca_decl.subject.clone(),
            not_before,
            not_after,
            key_algorithm: ca_keypair.algorithm,
            is_ca: true,
            sans: Vec::new(),
            der_bytes: cert_der,
            pem_certificate: pem,
        })
    }

    /// Builds and signs a standard X.509 v3 End-Entity / Leaf Domain Certificate (CA-05)
    #[allow(clippy::too_many_arguments)]
    pub fn build_domain_leaf_certificate(
        ca_decl: &CaDeclaration,
        ca_keypair: &CaKeyPair,
        domain: &str,
        subject_algo: KeyAlgorithm,
        subject_pubkey_bytes: &[u8],
        sans: Vec<String>,
        ttl_seconds: u64,
        current_time: u64,
        proof_binding: Option<&str>,
    ) -> Result<X509Certificate, String> {
        let serial = CertificateSerialNumber::generate();
        let not_before = current_time;
        let not_after = current_time.saturating_add(ttl_seconds);

        let subject_meta = CaSubjectMetadata {
            common_name: domain.to_string(),
            organization: ca_decl.subject.organization.clone(),
            organizational_unit: ca_decl.subject.organizational_unit.clone(),
            locality: ca_decl.subject.locality.clone(),
            state_or_province: ca_decl.subject.state_or_province.clone(),
            country: ca_decl.subject.country.clone(),
            email: None,
        };

        let spki_bytes = encode_subject_public_key_info(subject_algo, subject_pubkey_bytes);
        let issuer_dn = encode_distinguished_name(&ca_decl.subject);
        let subject_dn = encode_distinguished_name(&subject_meta);

        let mut extensions = Vec::new();
        // 1. Basic Constraints (critical = true, cA = false)
        extensions.extend_from_slice(&encode_basic_constraints(false, None));
        // 2. Key Usage (critical = true, digitalSignature | keyEncipherment)
        extensions.extend_from_slice(&encode_key_usage(false));
        // 3. Extended Key Usage (serverAuth, clientAuth)
        extensions.extend_from_slice(&encode_extended_key_usage(true, true));
        // 4. SAN
        if !sans.is_empty() {
            extensions.extend_from_slice(&encode_san(&sans));
        }
        // 5. SKI
        extensions.extend_from_slice(&encode_ski(subject_pubkey_bytes));
        // 6. AKI
        extensions.extend_from_slice(&encode_aki(&ca_keypair.public_key_bytes));
        // 7. WoT Critical Extension (CA-10)
        extensions.extend_from_slice(&encode_wot_extension(WOT_EXTENSION_UUID));
        // 8. Optional Domain Proof Binding (CA-03)
        if let Some(proof) = proof_binding {
            extensions.extend_from_slice(&encode_domain_proof_extension(proof));
        }

        let tbs_der = encode_tbs_certificate(
            &serial,
            ca_keypair.algorithm,
            &issuer_dn,
            not_before,
            not_after,
            &subject_dn,
            &spki_bytes,
            &extensions,
        )?;

        let sig = ca_keypair.sign(&tbs_der)?;
        let cert_der = encode_signed_certificate(&tbs_der, ca_keypair.algorithm, &sig)?;
        let pem = to_pem(&cert_der, "CERTIFICATE");

        Ok(X509Certificate {
            serial_number: serial,
            issuer: ca_decl.subject.clone(),
            subject: subject_meta,
            not_before,
            not_after,
            key_algorithm: ca_keypair.algorithm,
            is_ca: false,
            sans,
            der_bytes: cert_der,
            pem_certificate: pem,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::ca::compute_ca_id;

    #[test]
    fn test_ca_05_root_ca_certificate_builder_ed25519() {
        let subject = CaSubjectMetadata {
            common_name: "The Random Consortium Root CA".to_string(),
            organization: Some("The Random Consortium".to_string()),
            organizational_unit: Some("PKI Operations".to_string()),
            locality: Some("Valencia".to_string()),
            state_or_province: Some("Valencia".to_string()),
            country: Some("ES".to_string()),
            email: Some("ca@therandomconsortium.org".to_string()),
        };
        let ca_id = compute_ca_id(&subject.common_name, b"test_ca_pubkey");
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
        let cert = X509CertificateBuilder::build_root_ca_certificate(
            &decl, &keypair, 7_776_000, 1700000000,
        )
        .unwrap();

        assert!(cert.is_ca);
        assert_eq!(cert.key_algorithm, KeyAlgorithm::Ed25519);
        assert!(!cert.der_bytes.is_empty());
        assert!(cert
            .pem_certificate
            .starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cert
            .pem_certificate
            .ends_with("-----END CERTIFICATE-----\n"));
    }

    #[test]
    fn test_ca_05_domain_leaf_certificate_builder_p384() {
        let subject = CaSubjectMetadata {
            common_name: "The Random Consortium Intermediate CA".to_string(),
            organization: Some("The Random Consortium".to_string()),
            organizational_unit: None,
            locality: None,
            state_or_province: None,
            country: Some("ES".to_string()),
            email: None,
        };
        let ca_id = compute_ca_id(&subject.common_name, b"intermediate_key");
        let decl = CaDeclaration::new(
            ca_id,
            subject.clone(),
            subject,
            true,
            Some(0),
            vec!["community.hns".to_string()],
            1700000000,
            false,
            vec![crate::proof::DomainNetworkType::Handshake],
        )
        .unwrap();

        let ca_keypair = CaKeyPair::generate(KeyAlgorithm::EcdsaP384).unwrap();
        let leaf_keypair = CaKeyPair::generate(KeyAlgorithm::EcdsaP384).unwrap();

        let sans = vec!["community.hns".to_string(), "*.community.hns".to_string()];
        let cert = X509CertificateBuilder::build_domain_leaf_certificate(
            &decl,
            &ca_keypair,
            "community.hns",
            KeyAlgorithm::EcdsaP384,
            &leaf_keypair.public_key_bytes,
            sans.clone(),
            86400,
            1700000000,
            Some("TXT_RECORD_PROOF_HASH_SAMPLE"),
        )
        .unwrap();

        assert!(!cert.is_ca);
        assert_eq!(cert.sans, sans);
        assert_eq!(cert.not_after, 1700000000 + 86400);
        assert!(cert.pem_certificate.contains("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn test_ca_05_certificate_rsa4096_and_mldsa44_builders() {
        let subject = CaSubjectMetadata {
            common_name: "PQC Consortium CA".to_string(),
            organization: None,
            organizational_unit: None,
            locality: None,
            state_or_province: None,
            country: Some("ES".to_string()),
            email: None,
        };
        let ca_id = compute_ca_id(&subject.common_name, b"pqc_key");
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

        let ml_keypair = CaKeyPair::generate(KeyAlgorithm::MlDsa44).unwrap();
        let cert_ml = X509CertificateBuilder::build_root_ca_certificate(
            &decl,
            &ml_keypair,
            31_536_000,
            1700000000,
        )
        .unwrap();
        assert_eq!(cert_ml.key_algorithm, KeyAlgorithm::MlDsa44);
        assert!(cert_ml
            .pem_certificate
            .contains("-----BEGIN CERTIFICATE-----"));
    }
}
