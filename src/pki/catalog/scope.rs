use serde::{Deserialize, Serialize};

/// Declares the domain coverage scope of a Certificate Offer or issued certificate (CA-14)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum CertificateCoverageScope {
    /// 1. Exact Single FQDN (e.g., "pepito.has.a.blog" -> 1 exact SAN)
    #[default]
    SingleFqdn,

    /// 2. Apex + 1-level Wildcard (e.g., "pepito.has.a.blog" -> ["pepito.has.a.blog", "*.pepito.has.a.blog"])
    WildcardApex,

    /// 3. Multi-Domain SAN (Up to `max_sans` distinct domains, with optional wildcards)
    MultiSan {
        max_sans: u32,
        allow_wildcards: bool,
    },

    /// 4. Subtree Delegation (Intermediate CA: Autogenerates permittedSubtrees = [proven_domain])
    SubtreeDelegation { max_path_len: Option<u32> },
}

impl CertificateCoverageScope {
    /// Autogenerates the permitted subtrees for X.509 Name Constraints (RFC 5280 §4.2.1.10) from the proven domain
    pub fn autogenerate_permitted_subtrees(&self, proven_domain: &str) -> Vec<String> {
        let domain_clean = proven_domain.trim().trim_start_matches("*.").to_lowercase();
        if domain_clean.is_empty() {
            return Vec::new();
        }
        vec![domain_clean]
    }

    /// Autogenerates the default SAN list for Leaf certificates from the proven domain
    pub fn autogenerate_sans(&self, proven_domain: &str) -> Vec<String> {
        let domain_clean = proven_domain.trim().trim_start_matches("*.").to_lowercase();
        if domain_clean.is_empty() {
            return Vec::new();
        }

        match self {
            CertificateCoverageScope::SingleFqdn => vec![domain_clean],
            CertificateCoverageScope::WildcardApex => {
                vec![domain_clean.clone(), format!("*.{}", domain_clean)]
            }
            CertificateCoverageScope::MultiSan { .. } => vec![domain_clean],
            CertificateCoverageScope::SubtreeDelegation { .. } => Vec::new(),
        }
    }

    /// Returns whether this coverage scope allows wildcard SANs (*.domain.tld)
    pub fn allows_wildcard(&self) -> bool {
        match self {
            CertificateCoverageScope::SingleFqdn => false,
            CertificateCoverageScope::WildcardApex => true,
            CertificateCoverageScope::MultiSan {
                allow_wildcards, ..
            } => *allow_wildcards,
            CertificateCoverageScope::SubtreeDelegation { .. } => true,
        }
    }

    /// Returns the maximum number of SAN domains allowed under this scope
    pub fn max_sans(&self) -> u32 {
        match self {
            CertificateCoverageScope::SingleFqdn => 1,
            CertificateCoverageScope::WildcardApex => 2,
            CertificateCoverageScope::MultiSan { max_sans, .. } => *max_sans,
            CertificateCoverageScope::SubtreeDelegation { .. } => u32::MAX,
        }
    }

    /// Checks if a candidate domain (e.g. "sub.example.com" or "*.example.com") is permitted
    /// under a given set of permitted subtrees according to RFC 5280 §4.2.1.10 matching rules.
    pub fn is_domain_in_permitted_subtrees(domain: &str, permitted_subtrees: &[String]) -> bool {
        if permitted_subtrees.is_empty() {
            return true;
        }

        let cand_clean = domain.trim().trim_start_matches("*.").to_lowercase();
        if cand_clean.is_empty() {
            return false;
        }

        for subtree in permitted_subtrees {
            let sub_clean = subtree.trim().to_lowercase();
            if sub_clean.is_empty() {
                continue;
            }

            if let Some(suffix) = sub_clean.strip_prefix('.') {
                if cand_clean.ends_with(sub_clean.as_str())
                    || (cand_clean == suffix && cand_clean.len() > suffix.len())
                {
                    return true;
                }
            } else if cand_clean == sub_clean
                || (cand_clean.ends_with(format!(".{}", sub_clean).as_str()))
            {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_coverage_scope_single_fqdn() {
        let scope = CertificateCoverageScope::SingleFqdn;
        assert!(!scope.allows_wildcard());
        assert_eq!(scope.max_sans(), 1);
        assert_eq!(
            scope.autogenerate_sans("pepito.has.a.blog"),
            vec!["pepito.has.a.blog".to_string()]
        );
        assert_eq!(
            scope.autogenerate_permitted_subtrees("pepito.has.a.blog"),
            vec!["pepito.has.a.blog".to_string()]
        );
    }

    #[test]
    fn test_certificate_coverage_scope_wildcard_apex() {
        let scope = CertificateCoverageScope::WildcardApex;
        assert!(scope.allows_wildcard());
        assert_eq!(scope.max_sans(), 2);
        assert_eq!(
            scope.autogenerate_sans("pepito.has.a.blog"),
            vec![
                "pepito.has.a.blog".to_string(),
                "*.pepito.has.a.blog".to_string()
            ]
        );
    }

    #[test]
    fn test_certificate_coverage_scope_multi_san() {
        let scope = CertificateCoverageScope::MultiSan {
            max_sans: 50,
            allow_wildcards: true,
        };
        assert!(scope.allows_wildcard());
        assert_eq!(scope.max_sans(), 50);
        assert_eq!(
            scope.autogenerate_sans("example.hns"),
            vec!["example.hns".to_string()]
        );
    }

    #[test]
    fn test_certificate_coverage_scope_subtree_delegation() {
        let scope = CertificateCoverageScope::SubtreeDelegation {
            max_path_len: Some(0),
        };
        assert!(scope.allows_wildcard());
        assert_eq!(scope.max_sans(), u32::MAX);
        assert!(scope.autogenerate_sans("example.com").is_empty());
        assert_eq!(
            scope.autogenerate_permitted_subtrees("example.com"),
            vec!["example.com".to_string()]
        );
    }

    #[test]
    fn test_is_domain_in_permitted_subtrees() {
        let permitted = vec![
            "therandomconsortium.org".to_string(),
            "community.hns".to_string(),
        ];

        // Exact matches
        assert!(CertificateCoverageScope::is_domain_in_permitted_subtrees(
            "therandomconsortium.org",
            &permitted
        ));
        assert!(CertificateCoverageScope::is_domain_in_permitted_subtrees(
            "community.hns",
            &permitted
        ));

        // Subdomains
        assert!(CertificateCoverageScope::is_domain_in_permitted_subtrees(
            "api.therandomconsortium.org",
            &permitted
        ));
        assert!(CertificateCoverageScope::is_domain_in_permitted_subtrees(
            "deep.sub.community.hns",
            &permitted
        ));

        // Wildcards
        assert!(CertificateCoverageScope::is_domain_in_permitted_subtrees(
            "*.therandomconsortium.org",
            &permitted
        ));

        // Outside subtrees
        assert!(!CertificateCoverageScope::is_domain_in_permitted_subtrees(
            "otherdomain.org",
            &permitted
        ));
        assert!(!CertificateCoverageScope::is_domain_in_permitted_subtrees(
            "fakecommunity.hns",
            &permitted
        ));
    }
}
