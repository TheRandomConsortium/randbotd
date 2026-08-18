use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::DaemonConfig;
use crate::crypto::agility::KeyAlgorithm;
use crate::pki::ca::CaDeclaration;
use crate::proof::DomainNetworkType;

pub const DEFAULT_OFFER_TTL_SECONDS: u64 = 7_776_000; // 90 days
pub const MAX_OFFER_NAME_LENGTH: usize = 64;

fn default_offer_key_algorithm() -> KeyAlgorithm {
    KeyAlgorithm::Ed25519
}

fn default_offer_supported_domain_networks() -> Vec<DomainNetworkType> {
    vec![DomainNetworkType::Clearnet]
}

fn default_offer_ttl_seconds() -> u64 {
    DEFAULT_OFFER_TTL_SECONDS
}

/// Certificate Offer (or Certificate Profile) defining issuance terms under a specific CA
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateOffer {
    pub offer_id: u32,
    pub ca_id: [u8; 32],
    pub name: String,
    #[serde(default = "default_offer_key_algorithm")]
    pub key_algorithm: KeyAlgorithm,
    #[serde(default = "default_offer_supported_domain_networks")]
    pub supported_domain_networks: Vec<DomainNetworkType>,
    #[serde(default = "default_offer_ttl_seconds")]
    pub ttl_seconds: u64,
    #[serde(default)]
    pub is_draft: bool,
    pub created_at: u64,
}

impl CertificateOffer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        offer_id: u32,
        ca_id: [u8; 32],
        name: String,
        key_algorithm: KeyAlgorithm,
        supported_domain_networks: Vec<DomainNetworkType>,
        ttl_seconds: u64,
        is_draft: bool,
        created_at: u64,
    ) -> Result<Self, String> {
        let name_clean = name.trim().to_string();
        if name_clean.is_empty() {
            return Err("Offer name cannot be empty".to_string());
        }
        if name_clean.len() > MAX_OFFER_NAME_LENGTH {
            return Err(format!(
                "Offer name length {} exceeds maximum allowed {}",
                name_clean.len(),
                MAX_OFFER_NAME_LENGTH
            ));
        }
        if supported_domain_networks.is_empty() {
            return Err(
                "Certificate offer must support at least one domain network type".to_string(),
            );
        }
        if ttl_seconds == 0 {
            return Err("TTL / validity period must be greater than 0 seconds".to_string());
        }

        Ok(Self {
            offer_id,
            ca_id,
            name: name_clean,
            key_algorithm,
            supported_domain_networks,
            ttl_seconds,
            is_draft,
            created_at,
        })
    }

    /// Calculates the validity window (notBefore, notAfter) starting from `current_time`
    pub fn validity_window(&self, current_time: u64) -> (u64, u64) {
        (current_time, current_time.saturating_add(self.ttl_seconds))
    }

    /// Validates offer parameters against issuing CA declaration and node configuration
    pub fn validate_against_ca_and_config(
        &self,
        ca: &CaDeclaration,
        config: &DaemonConfig,
    ) -> Result<(), String> {
        if self.ca_id != ca.ca_id {
            return Err("Offer ca_id does not match parent CA ca_id".to_string());
        }

        for net_type in &self.supported_domain_networks {
            if !ca.supported_domain_networks.contains(net_type) {
                return Err(format!(
                    "Offer advertises {:?} support, but parent CA does not include this capability",
                    net_type
                ));
            }
            match net_type {
                DomainNetworkType::Clearnet => {}
                DomainNetworkType::Handshake => {
                    if !config.has_hns_support() {
                        return Err(
                            "Offer advertises Handshake support, but node has hns_dns_mode = 'none'"
                                .to_string(),
                        );
                    }
                }
                DomainNetworkType::Tor => {
                    if !config.has_tor_support() {
                        return Err(
                            "Offer advertises Tor (.onion) support, but tor_socks_proxy is unconfigured"
                                .to_string(),
                        );
                    }
                }
                DomainNetworkType::I2P => {
                    if !config.has_i2p_support() {
                        return Err(
                            "Offer advertises I2P (.i2p) support, but i2p_proxy_port is unconfigured"
                                .to_string(),
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

/// CA Certificate Offer Catalog structure grouping active offers under a sovereign CA (CA-12)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaOfferCatalog {
    pub ca_id: [u8; 32],
    pub catalog_version: u32,
    pub created_at: u64,
    pub offers: Vec<CertificateOffer>,
}

impl CaOfferCatalog {
    pub fn new(ca_id: [u8; 32], catalog_version: u32, created_at: u64) -> Self {
        Self {
            ca_id,
            catalog_version,
            created_at,
            offers: Vec::new(),
        }
    }

    /// Deterministically computes the 32-byte catalog hash (CA-12 section 6.1)
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"randbotd_v1_ca_offer_catalog:");
        hasher.update(self.ca_id);
        hasher.update(self.catalog_version.to_le_bytes());
        for offer in &self.offers {
            hasher.update(offer.offer_id.to_le_bytes());
            hasher.update(offer.name.as_bytes());
            hasher.update(offer.key_algorithm.oid().as_bytes());
            hasher.update(offer.ttl_seconds.to_le_bytes());
            for net in &offer.supported_domain_networks {
                hasher.update([*net as u8]);
            }
        }
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::ca::{compute_ca_id, CaSubjectMetadata};

    fn sample_ca() -> CaDeclaration {
        let subject = CaSubjectMetadata {
            common_name: "Root CA".to_string(),
            organization: None,
            organizational_unit: None,
            locality: None,
            state_or_province: None,
            country: Some("ES".to_string()),
            email: None,
        };
        let ca_id = compute_ca_id(&subject.common_name, b"test_node_pubkey");
        CaDeclaration::new(
            ca_id,
            subject.clone(),
            subject,
            false,
            None,
            1700000000,
            vec![DomainNetworkType::Clearnet, DomainNetworkType::Tor],
        )
        .expect("Valid sample CA")
    }

    #[test]
    fn test_certificate_offer_creation_and_validity_window() {
        let ca = sample_ca();
        let offer = CertificateOffer::new(
            0,
            ca.ca_id,
            "Standard Clearnet 90-day".to_string(),
            KeyAlgorithm::Ed25519,
            vec![DomainNetworkType::Clearnet],
            DEFAULT_OFFER_TTL_SECONDS,
            false,
            1700000000,
        )
        .expect("Valid offer");

        let (nb, na) = offer.validity_window(1700000000);
        assert_eq!(nb, 1700000000);
        assert_eq!(na, 1700000000 + DEFAULT_OFFER_TTL_SECONDS);
    }

    #[test]
    fn test_certificate_offer_validation_against_ca_capabilities() {
        let ca = sample_ca(); // supports Clearnet and Tor
        let mut config = DaemonConfig::default();
        config.privacy.tor_socks_proxy = Some("127.0.0.1:9050".to_string());

        // Offer within CA capabilities
        let valid_offer = CertificateOffer::new(
            1,
            ca.ca_id,
            "Tor Onion Tier".to_string(),
            KeyAlgorithm::Ed25519,
            vec![DomainNetworkType::Tor],
            86400,
            false,
            1700000000,
        )
        .unwrap();
        assert!(valid_offer
            .validate_against_ca_and_config(&ca, &config)
            .is_ok());

        // Offer with unsupported network (I2P not in sample CA)
        let invalid_offer = CertificateOffer::new(
            2,
            ca.ca_id,
            "I2P Tier".to_string(),
            KeyAlgorithm::Ed25519,
            vec![DomainNetworkType::I2P],
            86400,
            false,
            1700000000,
        )
        .unwrap();
        assert!(invalid_offer
            .validate_against_ca_and_config(&ca, &config)
            .is_err());
    }

    #[test]
    fn test_ca_offer_catalog_hash_computation() {
        let ca = sample_ca();
        let mut catalog = CaOfferCatalog::new(ca.ca_id, 1, 1700000000);
        let hash_empty = catalog.compute_hash();

        let offer = CertificateOffer::new(
            0,
            ca.ca_id,
            "Profile 0".to_string(),
            KeyAlgorithm::Ed25519,
            vec![DomainNetworkType::Clearnet],
            3600,
            false,
            1700000000,
        )
        .unwrap();
        catalog.offers.push(offer);

        let hash_with_offer = catalog.compute_hash();
        assert_ne!(hash_empty, hash_with_offer);
    }
}
