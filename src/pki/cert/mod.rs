pub mod builder;
pub mod der;
pub mod extensions;
pub mod serial;

pub use builder::{X509Certificate, X509CertificateBuilder};
pub use serial::CertificateSerialNumber;

/// Official randbotd Critical Web-of-Trust X.509 Extension OID (ITU-T X.667 derived from UUID f9c616c7-8e4d-4f84-a32e-596b5ada63d2)
pub const OID_CRITICAL_WOT_EXTENSION: &str = "2.25.332006307751889903095271628869501346770.1.1";

/// ITU-T X.667 UUID root for randbotd custom extensions
pub const WOT_EXTENSION_UUID: &str = "f9c616c7-8e4d-4f84-a32e-596b5ada63d2";

/// Criticality flag for randbotd WoT validation extension per RFC 5280 / CA-10
pub const WOT_EXTENSION_CRITICAL: bool = true;

/// Official randbotd Domain Proof Binding Extension OID (CA-03)
pub const OID_DOMAIN_PROOF_BINDING: &str = "2.25.332006307751889903095271628869501346770.1.2";

/// Standard X.509 v3 Extension OIDs per RFC 5280
pub const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
pub const OID_KEY_USAGE: &str = "2.5.29.15";
pub const OID_EXTENDED_KEY_USAGE: &str = "2.5.29.37";
pub const OID_SUBJECT_ALT_NAME: &str = "2.5.29.17";
pub const OID_NAME_CONSTRAINTS: &str = "2.5.29.30";
pub const OID_AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
pub const OID_SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";

/// Standard Extended Key Usage (EKU) Purpose OIDs per RFC 5280 §4.2.1.12
pub const OID_EKU_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
pub const OID_EKU_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

/// Standard criticality flag for RFC 5280 Name Constraints extension in Intermediate CAs (CA-14)
pub const NAME_CONSTRAINTS_CRITICAL: bool = true;

/// Minimum certificate serial number entropy bits per CA/Browser Forum BR §7.1.4.2.1
pub const MIN_SERIAL_ENTROPY_BITS: usize = 64;

/// Maximum certificate serial number entropy bits per RFC 5280 §4.1.2.2 (20 octets)
pub const MAX_SERIAL_ENTROPY_BITS: usize = 160;

/// Minimum certificate serial number entropy in bytes (64 bits = 8 bytes)
pub const MIN_SERIAL_ENTROPY_BYTES: usize = MIN_SERIAL_ENTROPY_BITS / 8;

/// Maximum certificate serial number entropy in bytes (160 bits = 20 bytes)
pub const MAX_SERIAL_ENTROPY_BYTES: usize = MAX_SERIAL_ENTROPY_BITS / 8;

/// Default certificate serial number entropy in bytes (160 bits = 20 bytes)
pub const DEFAULT_SERIAL_ENTROPY_BYTES: usize = MAX_SERIAL_ENTROPY_BYTES;

/// Advisory warning regarding CA-10 critical custom extension behavior in standard browsers
pub fn wot_extension_warning() -> String {
    let criticality_str = if WOT_EXTENSION_CRITICAL {
        "critical"
    } else {
        "non-critical"
    };
    format!(
        "Warning: Every certificate emitted under randbotd PKI includes {} WoT extension `{}` (UUID: {}) and will not work in standard browsers without the randbotd extension or proxy daemon.",
        criticality_str,
        OID_CRITICAL_WOT_EXTENSION,
        WOT_EXTENSION_UUID
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_10_critical_wot_extension_constants_and_warning() {
        assert_eq!(
            OID_CRITICAL_WOT_EXTENSION,
            "2.25.332006307751889903095271628869501346770.1.1"
        );
        assert_eq!(WOT_EXTENSION_UUID, "f9c616c7-8e4d-4f84-a32e-596b5ada63d2");
        const { assert!(WOT_EXTENSION_CRITICAL) };

        let warning = wot_extension_warning();
        assert!(warning.contains(OID_CRITICAL_WOT_EXTENSION));
        assert!(warning.contains(WOT_EXTENSION_UUID));
        assert!(warning.contains("critical WoT extension"));
        assert!(warning.contains("will not work in standard browsers"));
    }

    #[test]
    fn test_ca_14_name_constraints_constants() {
        assert_eq!(OID_NAME_CONSTRAINTS, "2.5.29.30");
        const { assert!(NAME_CONSTRAINTS_CRITICAL) };
    }
}
