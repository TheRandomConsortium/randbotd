pub const MAGIC_BYTES: &[u8; 4] = b"RBd1";

/// Validates whether an incoming UDP packet buffer starts with the `RBd1` magic bytes.
/// Packets failing this check are dropped immediately at the socket boundary.
pub fn validate_magic_bytes(buf: &[u8]) -> bool {
    if buf.len() < MAGIC_BYTES.len() {
        return false;
    }
    &buf[..4] == MAGIC_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_bytes_valid() {
        let valid_packet = b"RBd1hello_world_payload";
        assert!(validate_magic_bytes(valid_packet));
    }

    #[test]
    fn test_magic_bytes_invalid() {
        let invalid_packet = b"HTTP/1.1 200 OK";
        assert!(!validate_magic_bytes(invalid_packet));

        let short_packet = b"RBd";
        assert!(!validate_magic_bytes(short_packet));
    }
}
