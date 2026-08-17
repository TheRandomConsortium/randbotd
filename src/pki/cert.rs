/// Official randbotd Critical Web-of-Trust X.509 Extension OID (ITU-T X.667 derived from UUID f9c616c7-8e4d-4f84-a32e-596b5ada63d2)
pub const OID_CRITICAL_WOT_EXTENSION: &str = "2.25.332006307751889903095271628869501346770.1.1";

/// ITU-T X.667 UUID root for randbotd custom extensions
pub const WOT_EXTENSION_UUID: &str = "f9c616c7-8e4d-4f84-a32e-596b5ada63d2";

/// Criticality flag for randbotd WoT validation extension per RFC 5280 / CA-10
pub const WOT_EXTENSION_CRITICAL: bool = true;

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
}
