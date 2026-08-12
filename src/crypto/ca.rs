use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum field length constraints per RFC 5280 / ITU-T X.520
pub const MAX_CN_LENGTH: usize = 64;
pub const MAX_O_LENGTH: usize = 64;
pub const MAX_OU_LENGTH: usize = 64;
pub const MAX_LOCALITY_LENGTH: usize = 128;
pub const MAX_STATE_LENGTH: usize = 128;

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

use crate::crypto::agility::KeyAlgorithm;

fn default_key_algorithm() -> KeyAlgorithm {
    KeyAlgorithm::Ed25519
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
}

impl CaDeclaration {
    /// Constructs and validates a new CaDeclaration
    pub fn new(
        ca_id: [u8; 32],
        subject: CaSubjectMetadata,
        issuer: CaSubjectMetadata,
        is_intermediate: bool,
        path_len_constraint: Option<u32>,
        created_at: u64,
    ) -> Result<Self, String> {
        Self::new_with_draft_and_algorithm(
            ca_id,
            subject,
            issuer,
            is_intermediate,
            path_len_constraint,
            created_at,
            false,
            KeyAlgorithm::Ed25519,
        )
    }

    /// Constructs and validates a new CaDeclaration with explicit draft status
    pub fn new_with_draft(
        ca_id: [u8; 32],
        subject: CaSubjectMetadata,
        issuer: CaSubjectMetadata,
        is_intermediate: bool,
        path_len_constraint: Option<u32>,
        created_at: u64,
        is_draft: bool,
    ) -> Result<Self, String> {
        Self::new_with_draft_and_algorithm(
            ca_id,
            subject,
            issuer,
            is_intermediate,
            path_len_constraint,
            created_at,
            is_draft,
            KeyAlgorithm::Ed25519,
        )
    }

    /// Constructs and validates a new CaDeclaration with explicit draft status and key algorithm
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_draft_and_algorithm(
        ca_id: [u8; 32],
        subject: CaSubjectMetadata,
        issuer: CaSubjectMetadata,
        is_intermediate: bool,
        path_len_constraint: Option<u32>,
        created_at: u64,
        is_draft: bool,
        key_algorithm: KeyAlgorithm,
    ) -> Result<Self, String> {
        subject.validate()?;
        issuer.validate()?;

        if !is_intermediate && path_len_constraint.is_some() {
            return Err(
                "path_len_constraint is only valid for Intermediate CAs (is_intermediate = true)"
                    .to_string(),
            );
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
        })
    }
}

/// Computes the deterministic 32-byte CA identifier from root public key bytes
pub fn compute_ca_id(root_pubkey_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"randbotd_v1_ca_identity_domain:");
    hasher.update(root_pubkey_bytes);
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
        let ca_id = compute_ca_id(b"fake_pubkey");

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
        let draft_ok = CaDeclaration::new_with_draft(
            ca_id,
            subject.clone(),
            subject,
            true,
            Some(1),
            1700000000,
            true,
        );
        assert!(draft_ok.is_ok());
        assert!(draft_ok.unwrap().is_draft);
    }
}
