use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::DaemonConfig;
use crate::crypto::agility::KeyAlgorithm;
use crate::proof::DomainNetworkType;

/// Maximum field length constraints per RFC 5280 / ITU-T X.520
pub const MAX_CN_LENGTH: usize = 64;
pub const MAX_O_LENGTH: usize = 64;
pub const MAX_OU_LENGTH: usize = 64;
pub const MAX_LOCALITY_LENGTH: usize = 128;
pub const MAX_STATE_LENGTH: usize = 128;

pub const DEFAULT_CA_TTL_SECONDS: u64 = 7_776_000; // 90 days

fn default_key_algorithm() -> KeyAlgorithm {
    KeyAlgorithm::Ed25519
}

fn default_supported_domain_networks() -> Vec<DomainNetworkType> {
    vec![DomainNetworkType::Clearnet]
}

fn default_ttl_seconds() -> u64 {
    DEFAULT_CA_TTL_SECONDS
}

/// Standard X.509 Distinguished Name (DN) subject and issuer metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaSubjectMetadata {
    pub common_name: String,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub locality: Option<String>,
    pub state_or_province: Option<String>,
    pub country: Option<String>,
    pub email: Option<String>,
}

impl CaSubjectMetadata {
    /// Validates metadata against RFC 5280 and ISO 3166-1 alpha-2 standards
    pub fn validate(&self) -> Result<(), String> {
        let cn_clean = self.common_name.trim();
        if cn_clean.is_empty() {
            return Err("Common Name (CN) cannot be empty".to_string());
        }
        if cn_clean.len() > MAX_CN_LENGTH {
            return Err(format!(
                "Common Name (CN) length {} exceeds maximum allowed {}",
                cn_clean.len(),
                MAX_CN_LENGTH
            ));
        }

        if let Some(ref o) = self.organization {
            if o.trim().len() > MAX_O_LENGTH {
                return Err(format!(
                    "Organization (O) length {} exceeds maximum allowed {}",
                    o.trim().len(),
                    MAX_O_LENGTH
                ));
            }
        }

        if let Some(ref ou) = self.organizational_unit {
            if ou.trim().len() > MAX_OU_LENGTH {
                return Err(format!(
                    "Organizational Unit (OU) length {} exceeds maximum allowed {}",
                    ou.trim().len(),
                    MAX_OU_LENGTH
                ));
            }
        }

        if let Some(ref l) = self.locality {
            if l.trim().len() > MAX_LOCALITY_LENGTH {
                return Err(format!(
                    "Locality (L) length {} exceeds maximum allowed {}",
                    l.trim().len(),
                    MAX_LOCALITY_LENGTH
                ));
            }
        }

        if let Some(ref st) = self.state_or_province {
            if st.trim().len() > MAX_STATE_LENGTH {
                return Err(format!(
                    "State/Province (ST) length {} exceeds maximum allowed {}",
                    st.trim().len(),
                    MAX_STATE_LENGTH
                ));
            }
        }

        if let Some(ref c) = self.country {
            let c_clean = c.trim();
            if c_clean.len() != 2 || !c_clean.chars().all(|ch| ch.is_ascii_alphabetic()) {
                return Err(format!(
                    "Country code `{}` must be a valid 2-letter ISO 3166-1 alpha-2 code",
                    c_clean
                ));
            }
        }

        if let Some(ref email) = self.email {
            let email_clean = email.trim();
            if !email_clean.contains('@')
                || email_clean.starts_with('@')
                || email_clean.ends_with('@')
            {
                return Err(format!("Invalid email address format: `{}`", email_clean));
            }
        }

        Ok(())
    }
}

/// Declaration payload for a Root or Intermediate Certificate Authority (CA)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaDeclaration {
    pub ca_id: [u8; 32],
    pub subject: CaSubjectMetadata,
    pub issuer: CaSubjectMetadata,
    pub is_intermediate: bool,
    pub path_len_constraint: Option<u32>,
    pub created_at: u64,
    #[serde(default)]
    pub is_draft: bool,
    #[serde(default = "default_key_algorithm")]
    pub key_algorithm: KeyAlgorithm,
    #[serde(default = "default_supported_domain_networks")]
    pub supported_domain_networks: Vec<DomainNetworkType>,
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
}

impl CaDeclaration {
    /// Constructs and validates a new CaDeclaration with default Clearnet capabilities and default 90-day TTL
    pub fn new(
        ca_id: [u8; 32],
        subject: CaSubjectMetadata,
        issuer: CaSubjectMetadata,
        is_intermediate: bool,
        path_len_constraint: Option<u32>,
        created_at: u64,
    ) -> Result<Self, String> {
        Self::new_with_draft_and_algorithm_and_networks(
            ca_id,
            subject,
            issuer,
            is_intermediate,
            path_len_constraint,
            created_at,
            false,
            KeyAlgorithm::Ed25519,
            vec![DomainNetworkType::Clearnet],
            DEFAULT_CA_TTL_SECONDS,
        )
    }

    /// Constructs and validates a new CaDeclaration with full parameters including domain network capabilities and custom certificate TTL
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_draft_and_algorithm_and_networks(
        ca_id: [u8; 32],
        subject: CaSubjectMetadata,
        issuer: CaSubjectMetadata,
        is_intermediate: bool,
        path_len_constraint: Option<u32>,
        created_at: u64,
        is_draft: bool,
        key_algorithm: KeyAlgorithm,
        supported_domain_networks: Vec<DomainNetworkType>,
        ttl_seconds: u64,
    ) -> Result<Self, String> {
        subject.validate()?;
        issuer.validate()?;

        if !is_intermediate && path_len_constraint.is_some() {
            return Err(
                "path_len_constraint is only valid for Intermediate CAs (is_intermediate = true)"
                    .to_string(),
            );
        }

        if supported_domain_networks.is_empty() {
            return Err("CA must support at least one domain network type".to_string());
        }

        if ttl_seconds == 0 {
            return Err("TTL / validity period must be greater than 0 seconds".to_string());
        }

        Ok(Self {
            ca_id,
            subject,
            issuer,
            is_intermediate,
            path_len_constraint,
            created_at,
            is_draft,
            key_algorithm,
            supported_domain_networks,
            ttl_seconds,
        })
    }

    /// Calculates the certificate validity window (notBefore, notAfter) starting from `current_time`
    pub fn validity_window(&self, current_time: u64) -> (u64, u64) {
        (current_time, current_time.saturating_add(self.ttl_seconds))
    }

    /// Validates advertised CA capabilities against active node DaemonConfig
    pub fn validate_against_config(&self, config: &DaemonConfig) -> Result<(), String> {
        for net_type in &self.supported_domain_networks {
            match net_type {
                DomainNetworkType::Clearnet => {}
                DomainNetworkType::Handshake => {
                    if !config.has_hns_support() {
                        return Err(
                            "CA advertises Handshake support, but node has hns_dns_mode = 'none'"
                                .to_string(),
                        );
                    }
                }
                DomainNetworkType::Tor => {
                    if !config.has_tor_support() {
                        return Err(
                            "CA advertises Tor (.onion) support, but tor_socks_proxy is unconfigured"
                                .to_string(),
                        );
                    }
                }
                DomainNetworkType::I2P => {
                    if !config.has_i2p_support() {
                        return Err(
                            "CA advertises I2P (.i2p) support, but i2p_proxy_port is unconfigured"
                                .to_string(),
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

/// Computes the deterministic 32-byte CA identifier from common_name and owner node public key bytes
pub fn compute_ca_id(common_name: &str, node_pubkey_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"randbotd_v1_ca_identity_domain:");
    hasher.update(common_name.as_bytes());
    hasher.update(b":");
    hasher.update(node_pubkey_bytes);
    let result = hasher.finalize();
    let mut ca_id = [0u8; 32];
    ca_id.copy_from_slice(&result);
    ca_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ca_subject_metadata_validation() {
        let valid = CaSubjectMetadata {
            common_name: "The Random Consortium Root CA".to_string(),
            organization: Some("The Random Consortium".to_string()),
            organizational_unit: Some("PKI Operations".to_string()),
            locality: Some("Cyberspace".to_string()),
            state_or_province: Some("Decentralized".to_string()),
            country: Some("US".to_string()),
            email: Some("ca@therandomconsortium.org".to_string()),
        };
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn test_invalid_country_code_rejection() {
        let invalid_c = CaSubjectMetadata {
            common_name: "Test CA".to_string(),
            organization: None,
            organizational_unit: None,
            locality: None,
            state_or_province: None,
            country: Some("USA".to_string()),
            email: None,
        };
        assert!(invalid_c.validate().is_err());
        assert!(invalid_c.validate().unwrap_err().contains("ISO 3166-1"));
    }

    #[test]
    fn test_empty_common_name_rejection() {
        let invalid_cn = CaSubjectMetadata {
            common_name: "   ".to_string(),
            organization: None,
            organizational_unit: None,
            locality: None,
            state_or_province: None,
            country: None,
            email: None,
        };
        assert!(invalid_cn.validate().is_err());
    }

    #[test]
    fn test_path_len_constraint_validation() {
        let subject = CaSubjectMetadata {
            common_name: "Root CA".to_string(),
            organization: None,
            organizational_unit: None,
            locality: None,
            state_or_province: None,
            country: Some("ES".to_string()),
            email: None,
        };
        let ca_id = compute_ca_id(&subject.common_name, b"fake_pubkey");

        // Non-intermediate with path_len_constraint should fail
        let decl_err = CaDeclaration::new(
            ca_id,
            subject.clone(),
            subject.clone(),
            false,
            Some(2),
            1700000000,
        );
        assert!(decl_err.is_err());

        // Intermediate with path_len_constraint should pass
        let decl_ok = CaDeclaration::new(
            ca_id,
            subject.clone(),
            subject.clone(),
            true,
            Some(2),
            1700000000,
        );
        assert!(decl_ok.is_ok());

        // Draft mode constructor test
        let draft_ok = CaDeclaration::new_with_draft_and_algorithm_and_networks(
            ca_id,
            subject.clone(),
            subject.clone(),
            true,
            Some(1),
            1700000000,
            true,
            KeyAlgorithm::Ed25519,
            vec![DomainNetworkType::Clearnet],
            DEFAULT_CA_TTL_SECONDS,
        );
        assert!(draft_ok.is_ok());
        assert!(draft_ok.unwrap().is_draft);

        // Algorithm constructor test
        let algo_ok = CaDeclaration::new_with_draft_and_algorithm_and_networks(
            ca_id,
            subject.clone(),
            subject,
            true,
            Some(1),
            1700000000,
            true,
            KeyAlgorithm::Ed25519,
            vec![DomainNetworkType::Clearnet],
            DEFAULT_CA_TTL_SECONDS,
        );
        assert!(algo_ok.is_ok());
        assert_eq!(algo_ok.unwrap().key_algorithm, KeyAlgorithm::Ed25519);
    }

    #[test]
    fn test_ca_declaration_network_capability_validation() {
        let subject = CaSubjectMetadata {
            common_name: "Multi-Net CA".to_string(),
            organization: None,
            organizational_unit: None,
            locality: None,
            state_or_province: None,
            country: Some("ES".to_string()),
            email: None,
        };
        let ca_id = compute_ca_id(&subject.common_name, b"test_net_pubkey");

        let decl = CaDeclaration::new_with_draft_and_algorithm_and_networks(
            ca_id,
            subject.clone(),
            subject,
            false,
            None,
            1700000000,
            false,
            KeyAlgorithm::Ed25519,
            vec![DomainNetworkType::Clearnet, DomainNetworkType::Tor],
            DEFAULT_CA_TTL_SECONDS,
        )
        .expect("Failed to create CA declaration");

        let mut config = DaemonConfig::default();
        // Default config has no Tor support -> should fail validation
        assert!(decl.validate_against_config(&config).is_err());

        // Add Tor support -> should pass validation
        config.privacy.tor_socks_proxy = Some("127.0.0.1:9050".to_string());
        assert!(decl.validate_against_config(&config).is_ok());
    }

    #[test]
    fn test_ca_declaration_custom_ttl_and_validity_window() {
        let subject = CaSubjectMetadata {
            common_name: "Micro-TTL CA".to_string(),
            organization: None,
            organizational_unit: None,
            locality: None,
            state_or_province: None,
            country: Some("ES".to_string()),
            email: None,
        };
        let ca_id = compute_ca_id(&subject.common_name, b"micro_key");

        // Micro-TTL (300 seconds = 5 minutes)
        let micro_decl = CaDeclaration::new_with_draft_and_algorithm_and_networks(
            ca_id,
            subject.clone(),
            subject.clone(),
            false,
            None,
            1700000000,
            false,
            KeyAlgorithm::Ed25519,
            vec![DomainNetworkType::Clearnet],
            300,
        )
        .expect("Failed to create micro-TTL CA");
        assert_eq!(micro_decl.ttl_seconds, 300);
        let (nb, na) = micro_decl.validity_window(1700000000);
        assert_eq!(nb, 1700000000);
        assert_eq!(na, 1700000300);

        // 0 TTL should fail
        let zero_ttl_err = CaDeclaration::new_with_draft_and_algorithm_and_networks(
            ca_id,
            subject.clone(),
            subject,
            false,
            None,
            1700000000,
            false,
            KeyAlgorithm::Ed25519,
            vec![DomainNetworkType::Clearnet],
            0,
        );
        assert!(zero_ttl_err.is_err());
    }

    #[test]
    fn test_ca_id_composite_derivation() {
        let pk1 = [1u8; 32];
        let pk2 = [2u8; 32];
        let id1 = compute_ca_id("My CA", &pk1);
        let id2 = compute_ca_id("My CA", &pk2);
        let id3 = compute_ca_id("Other CA", &pk1);

        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
    }
}
