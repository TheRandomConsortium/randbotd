use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::{DEFAULT_SERIAL_ENTROPY_BYTES, MAX_SERIAL_ENTROPY_BYTES, MIN_SERIAL_ENTROPY_BYTES};

/// Cryptographic Certificate Serial Number (CA-13) conforming to RFC 5280 §4.1.2.2 & CABF BR §7.1.4.2.1
///
/// Holds 64 to 160 bits (8 to 20 octets) of CSPRNG entropy to prevent hash collision and serial prediction attacks.
/// In X.509 ASN.1 DER encoding (`CertificateSerialNumber ::= INTEGER`), serial numbers MUST be positive integers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CertificateSerialNumber {
    pub bytes: Vec<u8>,
}

impl CertificateSerialNumber {
    /// Generates a standard-compliant 160-bit (20 octets) CSPRNG serial number (CA-13)
    pub fn generate() -> Self {
        Self::generate_with_entropy_bytes(DEFAULT_SERIAL_ENTROPY_BYTES)
            .expect("default entropy byte length 20 is valid")
    }

    /// Generates a CSPRNG serial number with specified entropy length in bytes (8 to 20 bytes, 64 to 160 bits)
    pub fn generate_with_entropy_bytes(byte_len: usize) -> Result<Self, String> {
        if !(MIN_SERIAL_ENTROPY_BYTES..=MAX_SERIAL_ENTROPY_BYTES).contains(&byte_len) {
            return Err(format!(
                "Serial entropy byte length {} out of allowed range [{}..={}] (64-160 bits)",
                byte_len, MIN_SERIAL_ENTROPY_BYTES, MAX_SERIAL_ENTROPY_BYTES
            ));
        }

        let mut rng = rand::thread_rng();
        let mut raw = vec![0u8; byte_len];
        rng.fill_bytes(&mut raw);

        // RFC 5280 §4.1.2.2: Serial number MUST be a positive integer.
        // Clear MSB of first byte so the integer is non-negative.
        raw[0] &= 0x7F;

        // Ensure the serial number is not zero (at least one non-zero byte).
        if raw.iter().all(|&b| b == 0) {
            raw[0] = 0x01;
        }

        Self::from_bytes(raw)
    }

    /// Constructs a `CertificateSerialNumber` from raw byte octets after validation
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let serial = Self { bytes };
        serial.validate()?;
        Ok(serial)
    }

    /// Constructs a `CertificateSerialNumber` from a byte slice
    pub fn from_slice(slice: &[u8]) -> Result<Self, String> {
        Self::from_bytes(slice.to_vec())
    }

    /// Parses a hexadecimal string (with or without colons, spaces, or 0x prefix) into a `CertificateSerialNumber`
    pub fn from_hex(hex_str: &str) -> Result<Self, String> {
        let cleaned: String = hex_str
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();
        if cleaned.is_empty() {
            return Err("Serial number hex string cannot be empty".to_string());
        }
        let bytes =
            hex::decode(&cleaned).map_err(|e| format!("Invalid hex serial string: {}", e))?;
        Self::from_bytes(bytes)
    }

    /// Validates the serial number against RFC 5280 §4.1.2.2 and CABF BR §7.1.4.2.1
    pub fn validate(&self) -> Result<(), String> {
        if self.bytes.len() < MIN_SERIAL_ENTROPY_BYTES {
            return Err(format!(
                "Certificate serial number length ({} bytes) is less than minimum required 64 bits (8 bytes) per CABF BR §7.1.4.2.1",
                self.bytes.len()
            ));
        }
        if self.bytes.len() > MAX_SERIAL_ENTROPY_BYTES {
            return Err(format!(
                "Certificate serial number length ({} bytes) exceeds maximum allowed 20 octets (160 bits) per RFC 5280 §4.1.2.2",
                self.bytes.len()
            ));
        }
        if self.bytes.iter().all(|&b| b == 0) {
            return Err("Certificate serial number cannot be zero".to_string());
        }
        Ok(())
    }

    /// Returns the entropy size in bits
    pub fn entropy_bits(&self) -> usize {
        self.bytes.len() * 8
    }

    /// Formats the serial number as lowercase hexadecimal string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Formats the serial number as uppercase hexadecimal string with colon delimiters (standard OpenSSL format)
    pub fn to_colon_hex(&self) -> String {
        self.bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(":")
    }

    /// Computes ASN.1 DER signed INTEGER content octets.
    pub fn to_der_integer_bytes(&self) -> Vec<u8> {
        let mut der = Vec::with_capacity(self.bytes.len() + 1);
        if let Some(&first) = self.bytes.first() {
            if first & 0x80 != 0 {
                der.push(0x00);
            }
        }
        der.extend_from_slice(&self.bytes);
        der
    }
}

impl std::str::FromStr for CertificateSerialNumber {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl TryFrom<&[u8]> for CertificateSerialNumber {
    type Error = String;
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(slice)
    }
}

impl TryFrom<Vec<u8>> for CertificateSerialNumber {
    type Error = String;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl std::fmt::Display for CertificateSerialNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::cert::{
        MAX_SERIAL_ENTROPY_BITS, MAX_SERIAL_ENTROPY_BYTES, MIN_SERIAL_ENTROPY_BITS,
        MIN_SERIAL_ENTROPY_BYTES,
    };

    #[test]
    fn test_ca_13_serial_entropy_generation_default() {
        assert_eq!(MIN_SERIAL_ENTROPY_BITS, 64);
        assert_eq!(MAX_SERIAL_ENTROPY_BITS, 160);
        assert_eq!(MIN_SERIAL_ENTROPY_BYTES, 8);
        assert_eq!(MAX_SERIAL_ENTROPY_BYTES, 20);

        let serial = CertificateSerialNumber::generate();
        assert_eq!(serial.bytes.len(), 20);
        assert_eq!(serial.entropy_bits(), 160);
        assert!(serial.validate().is_ok());
        assert_eq!(serial.bytes[0] & 0x80, 0);

        let serial2 = CertificateSerialNumber::generate();
        assert_ne!(serial.bytes, serial2.bytes);
    }

    #[test]
    fn test_ca_13_serial_entropy_custom_lengths() {
        let serial_min = CertificateSerialNumber::generate_with_entropy_bytes(8).unwrap();
        assert_eq!(serial_min.bytes.len(), 8);
        assert_eq!(serial_min.entropy_bits(), 64);
        assert!(serial_min.validate().is_ok());

        let serial_max = CertificateSerialNumber::generate_with_entropy_bytes(20).unwrap();
        assert_eq!(serial_max.bytes.len(), 20);
        assert_eq!(serial_max.entropy_bits(), 160);
        assert!(serial_max.validate().is_ok());

        assert!(CertificateSerialNumber::generate_with_entropy_bytes(7).is_err());
        assert!(CertificateSerialNumber::generate_with_entropy_bytes(21).is_err());
    }

    #[test]
    fn test_ca_13_serial_der_integer_bytes_positivity() {
        let raw_positive = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let serial_pos = CertificateSerialNumber::from_slice(&raw_positive).unwrap();
        assert_eq!(serial_pos.to_der_integer_bytes(), raw_positive);

        let raw_high_bit = vec![0x8F, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let serial_high = CertificateSerialNumber::from_slice(&raw_high_bit).unwrap();
        let der = serial_high.to_der_integer_bytes();
        assert_eq!(der.len(), 9);
        assert_eq!(der[0], 0x00);
        assert_eq!(&der[1..], &raw_high_bit[..]);
    }

    #[test]
    fn test_ca_13_serial_hex_parsing_and_formatting() {
        let hex_str = "0102030405060708090a0b0c0d0e0f1011121314";
        let serial = CertificateSerialNumber::from_hex(hex_str).unwrap();
        assert_eq!(serial.to_hex(), hex_str);
        assert_eq!(
            serial.to_colon_hex(),
            "01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14"
        );
        assert_eq!(format!("{}", serial), hex_str);

        let formatted = "0x01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14";
        let parsed = CertificateSerialNumber::from_hex(formatted).unwrap();
        assert_eq!(parsed, serial);
    }

    #[test]
    fn test_ca_13_serial_validation_rejections() {
        let zero_serial = vec![0u8; 16];
        assert!(CertificateSerialNumber::from_bytes(zero_serial).is_err());

        let too_short = vec![1u8; 7];
        assert!(CertificateSerialNumber::from_bytes(too_short).is_err());

        let too_long = vec![1u8; 21];
        assert!(CertificateSerialNumber::from_bytes(too_long).is_err());
    }

    #[test]
    fn test_ca_13_serial_json_serialization_roundtrip() {
        let serial = CertificateSerialNumber::generate();
        let json = serde_json::to_string(&serial).unwrap();
        let deserialized: CertificateSerialNumber = serde_json::from_str(&json).unwrap();
        assert_eq!(serial, deserialized);
    }
}
