use ed25519_dalek::{SigningKey, VerifyingKey};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use argon2::{Argon2, Algorithm, Version, Params};
use zeroize::{Zeroize, Zeroizing};
use rand::RngCore;
use std::fs;
use std::path::Path;

pub struct NodeIdentity {
    signing_key: SigningKey,
}

impl NodeIdentity {
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        secret.zeroize();
        Self { signing_key }
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn save_encrypted(&self, file_path: &Path, master_pass: Option<&str>) -> Result<(), String> {
        let secret_bytes = self.signing_key.to_bytes();
        let passphrase = resolve_master_secret(master_pass);
        
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);

        let derived_key = derive_key(&passphrase, &salt)?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(&derived_key)
            .map_err(|e| format!("Cipher init error: {}", e))?;

        let ciphertext = cipher
            .encrypt(nonce, secret_bytes.as_slice())
            .map_err(|e| format!("Encryption error: {}", e))?;

        let mut file_payload = Vec::new();
        file_payload.extend_from_slice(&salt);
        file_payload.extend_from_slice(&nonce_bytes);
        file_payload.extend_from_slice(&ciphertext);

        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        fs::write(file_path, file_payload).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load_encrypted(file_path: &Path, master_pass: Option<&str>) -> Result<Self, String> {
        let data = fs::read(file_path).map_err(|e| e.to_string())?;
        if data.len() < 16 + 12 + 16 {
            return Err("Encrypted key file is corrupt or too short".into());
        }

        let salt = &data[..16];
        let nonce_bytes = &data[16..28];
        let ciphertext = &data[28..];

        let passphrase = resolve_master_secret(master_pass);
        let derived_key = derive_key(&passphrase, salt)?;

        let cipher = ChaCha20Poly1305::new_from_slice(&derived_key)
            .map_err(|e| format!("Cipher init error: {}", e))?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let decrypted_bytes = Zeroizing::new(
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| "Failed to decrypt node key: Invalid passphrase or corrupted key file")?
        );

        if decrypted_bytes.len() != 32 {
            return Err("Decrypted secret key invalid length".into());
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&decrypted_bytes);
        let signing_key = SigningKey::from_bytes(&key_arr);
        key_arr.zeroize();

        Ok(Self { signing_key })
    }
}

fn resolve_master_secret(user_pass: Option<&str>) -> Zeroizing<Vec<u8>> {
    // 1. Explicit user passphrase via CLI (--masterpass)
    if let Some(pass) = user_pass {
        if !pass.trim().is_empty() {
            return Zeroizing::new(pass.as_bytes().to_vec());
        }
    }

    // 2. Linux Kernel Keyring / Systemd Credentials lookup
    if let Some(kernel_pass) = fetch_kernel_keyring_secret() {
        if !kernel_pass.is_empty() {
            return Zeroizing::new(kernel_pass);
        }
    }

    // 3. Fallback: /etc/machine-id for unattended systemd mode when kernel keyring is unconfigured
    if let Ok(machine_id) = fs::read_to_string("/etc/machine-id") {
        let trimmed = machine_id.trim();
        if !trimmed.is_empty() {
            return Zeroizing::new(trimmed.as_bytes().to_vec());
        }
    }

    Zeroizing::new(b"randbotd_default_secure_kernel_fallback_key".to_vec())
}

/// Attempts to read master passphrase from Linux Kernel Keyring or systemd credentials
fn fetch_kernel_keyring_secret() -> Option<Vec<u8>> {
    // Check systemd credentials first (/run/credentials/randbotd.service/masterpass)
    if let Ok(cred) = fs::read("/run/credentials/randbotd.service/masterpass") {
        if !cred.is_empty() {
            return Some(cred);
        }
    }

    // Try querying keyctl from Linux Kernel Keyring
    let output = std::process::Command::new("keyctl")
        .args(["search", "@u", "user", "randbotd_masterpass"])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let key_id = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !key_id.is_empty() {
                let read_out = std::process::Command::new("keyctl")
                    .args(["read", &key_id])
                    .output();
                if let Ok(r) = read_out {
                    if r.status.success() && !r.stdout.is_empty() {
                        return Some(r.stdout);
                    }
                }
            }
        }
    }

    None
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut key = vec![0u8; 32];
    let params = Params::new(19456, 2, 1, Some(32)).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| e.to_string())?;

    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_encrypted_roundtrip() {
        let mut path = std::env::temp_dir();
        path.push("randbotd_test_node_key.enc");

        let identity = NodeIdentity::generate();
        let pass = "test_cypherpunk_masterpass_123";

        identity.save_encrypted(&path, Some(pass)).unwrap();
        let loaded = NodeIdentity::load_encrypted(&path, Some(pass)).unwrap();

        assert_eq!(identity.verifying_key(), loaded.verifying_key());
        let _ = fs::remove_file(path);
    }
}
