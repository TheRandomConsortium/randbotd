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

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NodeRole {
    Voter = 1,
    Headless = 2,
}

impl NodeRole {
    pub fn from_u8(val: u8) -> Self {
        match val {
            2 => NodeRole::Headless,
            _ => NodeRole::Voter,
        }
    }

    pub fn domain_prefix(&self) -> &'static [u8] {
        match self {
            NodeRole::Voter => b"randbotd_v1_identity_domain_voter",
            NodeRole::Headless => b"randbotd_v1_identity_domain_headless",
        }
    }
}

#[derive(Clone)]
pub struct NodeIdentity {
    signing_key: SigningKey,
    role: NodeRole,
}

impl NodeIdentity {
    pub fn from_seed_and_role(seed: &[u8; 32], role: NodeRole) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(role.domain_prefix());
        hasher.update(seed);
        let derived_hash = hasher.finalize();

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&derived_hash[..32]);

        let signing_key = SigningKey::from_bytes(&key_bytes);
        key_bytes.zeroize();
        Self { signing_key, role }
    }

    pub fn role(&self) -> NodeRole {
        self.role
    }

    pub fn is_headless(&self) -> bool {
        self.role == NodeRole::Headless
    }

    pub fn is_voter(&self) -> bool {
        self.role == NodeRole::Voter
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

        let mut plain_payload = Vec::new();
        plain_payload.push(self.role as u8);
        plain_payload.extend_from_slice(secret_bytes.as_slice());

        let ciphertext = cipher
            .encrypt(nonce, plain_payload.as_slice())
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

        if decrypted_bytes.len() < 33 {
            return Err("Decrypted payload invalid length".into());
        }

        let role = NodeRole::from_u8(decrypted_bytes[0]);
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&decrypted_bytes[1..33]);
        let signing_key = SigningKey::from_bytes(&key_arr);
        key_arr.zeroize();

        Ok(Self { signing_key, role })
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
        return Ok(Zeroizing::new(
            b"randbotd_default_secure_kernel_fallback_key".to_vec(),
        ));
    }

    Err(
        "⚠️ SECURITY WARNING: No master passphrase found in Linux Kernel Keyring or systemd encrypted credentials.\n\
         To set a master passphrase in the Linux Kernel Keyring (disable shell history first: `set +o history`):\n\
           set +o history\n\
           keyctl add user randbotd:masterpass \"your_secret_passphrase\" @s\n\
         Or encrypt your master passphrase using systemd-creds:\n\
           set +o history\n\
           echo -n \"your_secret_passphrase\" | sudo systemd-creds encrypt --name=masterpass - /etc/randbotd/masterpass.cred\n\
         Alternatively, to allow using /etc/machine-id fallback (insecure), start with:\n\
           randbotd --allow-insecure-machine-id-fallback".to_string()
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
    let params =
        Params::new(65536, 3, 1, Some(32)).map_err(|e| format!("Argon2 params error: {}", e))?;
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
        let identity = NodeIdentity::from_seed_and_role(&[0x77u8; 32], NodeRole::Headless);
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
        assert_eq!(loaded.role(), NodeRole::Headless);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_role_domain_separation_different_keys() {
        let seed = [0x42u8; 32];
        let voter_id = NodeIdentity::from_seed_and_role(&seed, NodeRole::Voter);
        let headless_id = NodeIdentity::from_seed_and_role(&seed, NodeRole::Headless);

        assert_ne!(
            voter_id.verifying_key().to_bytes(),
            headless_id.verifying_key().to_bytes(),
            "Voter and Headless keys MUST be cryptographically distinct!"
        );
        assert!(voter_id.is_voter());
        assert!(headless_id.is_headless());
    }

    #[test]
    fn test_mnemonic_seed_identity_recovery_roundtrip() {
        use crate::crypto::gutenberg::GutenbergMnemonic;

        let fake_gutenberg_phrase =
            "cypherpunk decentralized web web-of-trust encryption sovereign consensus";
        let raw_seed = GutenbergMnemonic::phrase_to_seed(fake_gutenberg_phrase);
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&raw_seed[..32]);

        let original_id = NodeIdentity::from_seed_and_role(&seed_arr, NodeRole::Voter);

        // Simulate recovery from phrase
        let recovered_seed = GutenbergMnemonic::phrase_to_seed(fake_gutenberg_phrase);
        let mut recovered_seed_arr = [0u8; 32];
        recovered_seed_arr.copy_from_slice(&recovered_seed[..32]);
        let recovered_id = NodeIdentity::from_seed_and_role(&recovered_seed_arr, NodeRole::Voter);

        assert_eq!(
            original_id.verifying_key().to_bytes(),
            recovered_id.verifying_key().to_bytes(),
            "Derived NodeIdentity key MUST match recovered Gutenberg phrase key!"
        );
    }
}
