use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use std::fs;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone)]
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

    pub fn save_encrypted(
        &self,
        file_path: &Path,
        master_pass: Option<&str>,
        allow_insecure_fallback: bool,
    ) -> Result<(), String> {
        let secret_bytes = self.signing_key.to_bytes();
        let passphrase = resolve_master_secret(master_pass, allow_insecure_fallback)?;

        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);

        let derived_key = derive_key(&passphrase, &salt)?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(derived_key.as_slice())
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

    pub fn load_encrypted(
        file_path: &Path,
        master_pass: Option<&str>,
        allow_insecure_fallback: bool,
    ) -> Result<Self, String> {
        let data = fs::read(file_path).map_err(|e| e.to_string())?;
        if data.len() < 16 + 12 + 16 {
            return Err("Encrypted key file is corrupt or too short".into());
        }

        let salt = &data[..16];
        let nonce_bytes = &data[16..28];
        let ciphertext = &data[28..];

        let passphrase = resolve_master_secret(master_pass, allow_insecure_fallback)?;
        let derived_key = derive_key(&passphrase, salt)?;

        let cipher = ChaCha20Poly1305::new_from_slice(derived_key.as_slice())
            .map_err(|e| format!("Cipher init error: {}", e))?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let decrypted_bytes =
            Zeroizing::new(cipher.decrypt(nonce, ciphertext).map_err(|_| {
                "Failed to decrypt node key: Invalid passphrase or corrupted key file"
            })?);

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

pub fn resolve_master_secret(
    user_pass: Option<&str>,
    allow_insecure_fallback: bool,
) -> Result<Zeroizing<Vec<u8>>, String> {
    // 1. Explicit user passphrase via CLI (--masterpass)
    if let Some(pass) = user_pass {
        if !pass.trim().is_empty() {
            return Ok(Zeroizing::new(pass.as_bytes().to_vec()));
        }
    }

    // 2. Linux Kernel Keyring / Systemd Credentials lookup
    if let Some(kernel_pass) = fetch_kernel_keyring_secret() {
        if !kernel_pass.is_empty() {
            return Ok(Zeroizing::new(kernel_pass));
        }
    }

    // 3. Machine-ID Fallback (only allowed if explicitly permitted via --allow-insecure-machine-id-fallback)
    if allow_insecure_fallback {
        if let Ok(machine_id) = fs::read_to_string("/etc/machine-id") {
            let trimmed = machine_id.trim();
            if !trimmed.is_empty() {
                return Ok(Zeroizing::new(trimmed.as_bytes().to_vec()));
            }
        }
        return Ok(Zeroizing::new(b"randbotd_default_secure_kernel_fallback_key".to_vec()));
    }

    Err(
        "⚠️ SECURITY WARNING: No master passphrase found in Linux Kernel Keyring or systemd encrypted credentials.\n\
         To set a master passphrase in the Linux Kernel Keyring:\n\
           keyctl add user randbotd:masterpass \"your_secret_passphrase\" @s\n\
         Or encrypt your master passphrase using systemd-creds:\n\
           echo -n \"your_secret_passphrase\" | sudo systemd-creds encrypt --name=masterpass - /etc/randbotd/masterpass.cred\n\
         Alternatively, to allow using /etc/machine-id fallback (insecure), start with:\n\
           randbotd --mode=headless --allow-insecure-machine-id-fallback".to_string()
    )
}

/// Attempts to read master passphrase from Linux Kernel Keyring or systemd credentials
fn fetch_kernel_keyring_secret() -> Option<Vec<u8>> {
    // 1. Check systemd CREDENTIALS_DIRECTORY environment variable first
    if let Ok(creds_dir) = std::env::var("CREDENTIALS_DIRECTORY") {
        let cred_path = Path::new(&creds_dir).join("masterpass");
        if let Ok(cred) = fs::read(&cred_path) {
            if !cred.is_empty() {
                return Some(cred);
            }
        }
    }

    // 2. Check fallback /run/credentials/randbotd.service/masterpass path
    if let Ok(cred) = fs::read("/run/credentials/randbotd.service/masterpass") {
        if !cred.is_empty() {
            return Some(cred);
        }
    }

    // 2. Check Linux Kernel Keyring via keyctl CLI
    if let Ok(output) = std::process::Command::new("keyctl")
        .args(["pipe", "randbotd:masterpass"])
        .output()
    {
        if output.status.success() && !output.stdout.is_empty() {
            return Some(output.stdout);
        }
    }

    None
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let params = Params::new(65536, 3, 1, Some(32))
        .map_err(|e| format!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut derived_key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase, salt, derived_key.as_mut_slice())
        .map_err(|e| format!("Argon2 key derivation error: {}", e))?;

    Ok(derived_key)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_identity_encrypted_roundtrip() {
        let identity = NodeIdentity::generate();
        let path = std::env::temp_dir().join("randbotd_test_key.enc");

        identity
            .save_encrypted(&path, Some("super_secret_passphrase"), true)
            .expect("Failed to save encrypted key");

        let loaded = NodeIdentity::load_encrypted(&path, Some("super_secret_passphrase"), true)
            .expect("Failed to load encrypted key");

        assert_eq!(
            identity.verifying_key().to_bytes(),
            loaded.verifying_key().to_bytes()
        );

        let _ = std::fs::remove_file(path);
    }
}
