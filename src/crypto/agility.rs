use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature as EdSignature, Signer, Verifier, VerifyingKey};
use p384::ecdsa::{Signature as P384Signature, SigningKey, VerifyingKey as P384VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use rsa::{
    pkcs1v15::SigningKey as RsaSigningKey, pkcs1v15::VerifyingKey as RsaVerifyingKey,
    signature::SignatureEncoding, RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

use pqcrypto_dilithium::dilithium2::{
    detached_sign, keypair as dilithium_keypair, verify_detached_signature,
    DetachedSignature as DilithiumSignature, PublicKey as DilithiumPublicKey,
    SecretKey as DilithiumSecretKey,
};
use pqcrypto_traits::sign::{
    DetachedSignature as PqDetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};

/// Official RFC / NIST Standard Object Identifiers (OIDs)
pub const OID_ED25519: &str = "1.3.101.112";
pub const OID_ECDSA_P384: &str = "1.2.840.10045.4.3.3";
pub const OID_RSA_4096: &str = "1.2.840.113549.1.1.11";
pub const OID_ML_DSA_44: &str = "2.16.840.1.101.3.4.3.17";

/// Supported cryptographic key algorithm suites in randbotd CA engine
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP384,
    Rsa4096,
    MlDsa44,
}

impl KeyAlgorithm {
    /// Returns the official standard OID string for the algorithm
    pub fn oid(&self) -> &'static str {
        match self {
            KeyAlgorithm::Ed25519 => OID_ED25519,
            KeyAlgorithm::EcdsaP384 => OID_ECDSA_P384,
            KeyAlgorithm::Rsa4096 => OID_RSA_4096,
            KeyAlgorithm::MlDsa44 => OID_ML_DSA_44,
        }
    }

    /// Returns human-readable display name
    pub fn name(&self) -> &'static str {
        match self {
            KeyAlgorithm::Ed25519 => "Ed25519 (Pure Ed25519 / RFC 8032)",
            KeyAlgorithm::EcdsaP384 => "ECDSA P-384 (secp384r1 + SHA-384 / RFC 5480)",
            KeyAlgorithm::Rsa4096 => "RSA 4096-bit (PKCS#1 v1.5 + SHA-256)",
            KeyAlgorithm::MlDsa44 => "ML-DSA-44 (NIST FIPS 204 Dilithium2 PQC Digital Signature)",
        }
    }
}

/// Managed Cryptographic Key Pair holding public and zeroizable private key bytes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaKeyPair {
    pub algorithm: KeyAlgorithm,
    pub public_key_bytes: Vec<u8>,
    pub private_key_bytes: Vec<u8>,
}

impl Drop for CaKeyPair {
    fn drop(&mut self) {
        self.private_key_bytes.zeroize();
    }
}

impl CaKeyPair {
    /// Generates a new cryptographic keypair for the specified algorithm
    pub fn generate(algorithm: KeyAlgorithm) -> Result<Self, String> {
        let mut rng = OsRng;
        match algorithm {
            KeyAlgorithm::Ed25519 => {
                let mut secret_bytes = [0u8; 32];
                rng.fill_bytes(&mut secret_bytes);
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
                let public_bytes = signing_key.verifying_key().to_bytes().to_vec();
                let secret_vec = secret_bytes.to_vec();
                secret_bytes.zeroize();
                Ok(Self {
                    algorithm,
                    public_key_bytes: public_bytes,
                    private_key_bytes: secret_vec,
                })
            }
            KeyAlgorithm::EcdsaP384 => {
                let signing_key = SigningKey::random(&mut rng);
                let verifying_key = P384VerifyingKey::from(&signing_key);
                let secret_bytes = signing_key.to_bytes().to_vec();
                let public_bytes = verifying_key.to_sec1_bytes().to_vec();
                Ok(Self {
                    algorithm,
                    public_key_bytes: public_bytes,
                    private_key_bytes: secret_bytes,
                })
            }
            KeyAlgorithm::Rsa4096 => {
                let private_key = RsaPrivateKey::new(&mut rng, 4096)
                    .map_err(|e| format!("Failed to generate RSA-4096 key: {}", e))?;
                let public_key = RsaPublicKey::from(&private_key);

                use rsa::pkcs1::EncodeRsaPrivateKey;
                use rsa::pkcs1::EncodeRsaPublicKey;
                let secret_bytes = private_key
                    .to_pkcs1_der()
                    .map_err(|e| format!("Failed to encode RSA private key: {}", e))?
                    .as_bytes()
                    .to_vec();
                let public_bytes = public_key
                    .to_pkcs1_der()
                    .map_err(|e| format!("Failed to encode RSA public key: {}", e))?
                    .as_bytes()
                    .to_vec();

                Ok(Self {
                    algorithm,
                    public_key_bytes: public_bytes,
                    private_key_bytes: secret_bytes,
                })
            }
            KeyAlgorithm::MlDsa44 => {
                let (pk, sk) = dilithium_keypair();
                Ok(Self {
                    algorithm,
                    public_key_bytes: pk.as_bytes().to_vec(),
                    private_key_bytes: sk.as_bytes().to_vec(),
                })
            }
        }
    }

    /// Signs data using private key (Ed25519, ECDSA P-384, RSA-4096, ML-DSA-44)
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        match self.algorithm {
            KeyAlgorithm::Ed25519 => {
                let secret_arr: [u8; 32] = self
                    .private_key_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Invalid Ed25519 secret key length".to_string())?;
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_arr);
                let sig = signing_key.sign(message);
                Ok(sig.to_bytes().to_vec())
            }
            KeyAlgorithm::EcdsaP384 => {
                let signing_key = SigningKey::from_slice(&self.private_key_bytes)
                    .map_err(|e| format!("Invalid P-384 signing key: {}", e))?;
                let signature: P384Signature = signing_key.sign(message);
                Ok(signature.to_der().as_bytes().to_vec())
            }
            KeyAlgorithm::Rsa4096 => {
                use rsa::pkcs1::DecodeRsaPrivateKey;
                let private_key = RsaPrivateKey::from_pkcs1_der(&self.private_key_bytes)
                    .map_err(|e| format!("Invalid RSA private key: {}", e))?;
                let signing_key = RsaSigningKey::<Sha256>::new(private_key);
                let signature = signing_key.sign(message);
                Ok(signature.to_bytes().to_vec())
            }
            KeyAlgorithm::MlDsa44 => {
                let sk = DilithiumSecretKey::from_bytes(&self.private_key_bytes)
                    .map_err(|e| format!("Invalid ML-DSA-44 secret key: {:?}", e))?;
                let sig = detached_sign(message, &sk);
                Ok(sig.as_bytes().to_vec())
            }
        }
    }

    /// Verifies digital signature against data and public key
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, String> {
        match self.algorithm {
            KeyAlgorithm::Ed25519 => {
                let pub_arr: [u8; 32] = self
                    .public_key_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Invalid Ed25519 public key length".to_string())?;
                let verifying_key = VerifyingKey::from_bytes(&pub_arr)
                    .map_err(|e| format!("Invalid Ed25519 public key: {}", e))?;
                let sig_arr: [u8; 64] = signature
                    .try_into()
                    .map_err(|_| "Invalid Ed25519 signature length".to_string())?;
                let ed_sig = EdSignature::from_bytes(&sig_arr);
                Ok(verifying_key.verify(message, &ed_sig).is_ok())
            }
            KeyAlgorithm::EcdsaP384 => {
                let verifying_key = P384VerifyingKey::from_sec1_bytes(&self.public_key_bytes)
                    .map_err(|e| format!("Invalid P-384 public key: {}", e))?;
                let sig = P384Signature::from_der(signature)
                    .map_err(|e| format!("Invalid P-384 DER signature: {}", e))?;
                Ok(verifying_key.verify(message, &sig).is_ok())
            }
            KeyAlgorithm::Rsa4096 => {
                use rsa::pkcs1::DecodeRsaPublicKey;
                let public_key = RsaPublicKey::from_pkcs1_der(&self.public_key_bytes)
                    .map_err(|e| format!("Invalid RSA public key: {}", e))?;
                let verifying_key = RsaVerifyingKey::<Sha256>::new(public_key);
                let sig = rsa::pkcs1v15::Signature::try_from(signature)
                    .map_err(|e| format!("Invalid RSA signature: {}", e))?;
                Ok(verifying_key.verify(message, &sig).is_ok())
            }
            KeyAlgorithm::MlDsa44 => {
                let pk = DilithiumPublicKey::from_bytes(&self.public_key_bytes)
                    .map_err(|e| format!("Invalid ML-DSA-44 public key: {:?}", e))?;
                let sig = DilithiumSignature::from_bytes(signature)
                    .map_err(|e| format!("Invalid ML-DSA-44 signature: {:?}", e))?;
                Ok(verify_detached_signature(&sig, message, &pk).is_ok())
            }
        }
    }

    /// Encrypts and persists keypair to disk using Argon2id KDF + ChaCha20-Poly1305 AEAD bound to masterpass
    pub fn save_encrypted_key_file(
        &self,
        file_path: &Path,
        masterpass: &[u8],
    ) -> Result<(), String> {
        let salt = b"randbotd_ca_key_salt_v1_domain_sep:";
        let mut key = [0u8; 32];
        let argon2 = Argon2::default();
        argon2
            .hash_password_into(masterpass, salt, &mut key)
            .map_err(|e| format!("Argon2 KDF failed: {}", e))?;

        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| format!("Cipher init failed: {}", e))?;
        let nonce = Nonce::from_slice(b"ca_key_nonce");

        let plaintext =
            serde_json::to_vec(self).map_err(|e| format!("Serialization failed: {}", e))?;
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| format!("Encryption failed: {}", e))?;

        fs::write(file_path, ciphertext)
            .map_err(|e| format!("Failed to write encrypted key file: {}", e))?;
        key.zeroize();
        Ok(())
    }

    /// Loads and decrypts keypair from disk using Argon2id KDF + ChaCha20-Poly1305 AEAD bound to masterpass
    pub fn load_encrypted_key_file(file_path: &Path, masterpass: &[u8]) -> Result<Self, String> {
        let ciphertext =
            fs::read(file_path).map_err(|e| format!("Failed to read encrypted key file: {}", e))?;

        let salt = b"randbotd_ca_key_salt_v1_domain_sep:";
        let mut key = [0u8; 32];
        let argon2 = Argon2::default();
        argon2
            .hash_password_into(masterpass, salt, &mut key)
            .map_err(|e| format!("Argon2 KDF failed: {}", e))?;

        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| format!("Cipher init failed: {}", e))?;
        let nonce = Nonce::from_slice(b"ca_key_nonce");

        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
            "Failed to decrypt CA key file (invalid masterpass credential or corrupted file)"
                .to_string()
        })?;

        let keypair: Self = serde_json::from_slice(&plaintext)
            .map_err(|e| format!("Deserialization failed: {}", e))?;
        key.zeroize();
        Ok(keypair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify_roundtrip() {
        let keypair = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
        assert_eq!(keypair.algorithm.oid(), OID_ED25519);
        let msg = b"The Random Consortium Cryptographic Signature";
        let sig = keypair.sign(msg).unwrap();
        assert!(keypair.verify(msg, &sig).unwrap());
        assert!(!keypair.verify(b"tampered message", &sig).unwrap());
    }

    #[test]
    fn test_ecdsa_p384_sign_verify_roundtrip() {
        let keypair = CaKeyPair::generate(KeyAlgorithm::EcdsaP384).unwrap();
        assert_eq!(keypair.algorithm.oid(), OID_ECDSA_P384);
        let msg = b"ECDSA P-384 Test Message";
        let sig = keypair.sign(msg).unwrap();
        assert!(keypair.verify(msg, &sig).unwrap());
        assert!(!keypair.verify(b"tampered message", &sig).unwrap());
    }

    #[test]
    fn test_rsa_4096_sign_verify_roundtrip() {
        let keypair = CaKeyPair::generate(KeyAlgorithm::Rsa4096).unwrap();
        assert_eq!(keypair.algorithm.oid(), OID_RSA_4096);
        let msg = b"RSA 4096-bit Test Message";
        let sig = keypair.sign(msg).unwrap();
        assert!(keypair.verify(msg, &sig).unwrap());
        assert!(!keypair.verify(b"tampered message", &sig).unwrap());
    }

    #[test]
    fn test_ca_keypair_encrypted_masterpass_persistence_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("randbotd_key_test_{}", rand::random::<u64>()));
        let _ = fs::create_dir_all(&temp_dir);
        let file_path = temp_dir.join("ca_key_test.enc");
        let masterpass = b"super_secret_masterpass_credential";

        let keypair = CaKeyPair::generate(KeyAlgorithm::EcdsaP384).unwrap();
        keypair
            .save_encrypted_key_file(&file_path, masterpass)
            .unwrap();

        let loaded = CaKeyPair::load_encrypted_key_file(&file_path, masterpass).unwrap();
        assert_eq!(keypair.public_key_bytes, loaded.public_key_bytes);
        assert_eq!(keypair.algorithm, loaded.algorithm);

        let bad_pass = b"invalid_password";
        assert!(CaKeyPair::load_encrypted_key_file(&file_path, bad_pass).is_err());
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_ml_dsa_44_sign_verify_roundtrip() {
        let keypair = CaKeyPair::generate(KeyAlgorithm::MlDsa44).unwrap();
        assert_eq!(keypair.algorithm.oid(), OID_ML_DSA_44);
        let msg = b"ML-DSA-44 Post-Quantum Signature Test Message";
        let sig = keypair.sign(msg).unwrap();
        assert!(keypair.verify(msg, &sig).unwrap());
        assert!(!keypair.verify(b"tampered message", &sig).unwrap());
    }

    #[test]
    fn test_key_algorithm_oid_and_name() {
        assert_eq!(KeyAlgorithm::Ed25519.oid(), OID_ED25519);
        assert_eq!(KeyAlgorithm::EcdsaP384.oid(), OID_ECDSA_P384);
        assert_eq!(KeyAlgorithm::Rsa4096.oid(), OID_RSA_4096);
        assert_eq!(KeyAlgorithm::MlDsa44.oid(), OID_ML_DSA_44);

        assert!(KeyAlgorithm::Ed25519.name().contains("Ed25519"));
        assert!(KeyAlgorithm::EcdsaP384.name().contains("P-384"));
        assert!(KeyAlgorithm::Rsa4096.name().contains("RSA"));
        assert!(KeyAlgorithm::MlDsa44.name().contains("ML-DSA"));
    }
}
