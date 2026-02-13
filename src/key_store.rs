//! B4AE Key Store
//!
//! Persistent storage for Master Identity Key (MIK) encrypted with passphrase.
//! Uses HKDF + AES-256-GCM.

use crate::crypto::aes_gcm::{self, AesKey};
use crate::crypto::hkdf;
use crate::error::{B4aeError, B4aeResult};
use crate::key_hierarchy::MasterIdentityKey;
use std::collections::HashMap;

/// Backend for key persistence.
pub trait KeyStoreBackend: Send + Sync {
    fn put(&mut self, key: &str, value: &[u8]) -> B4aeResult<()>;
    fn get(&self, key: &str) -> B4aeResult<Option<Vec<u8>>>;
}

/// In-memory key store backend.
#[derive(Default)]
pub struct MemoryKeyStoreBackend {
    data: HashMap<String, Vec<u8>>,
}

impl MemoryKeyStoreBackend {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
}

impl KeyStoreBackend for MemoryKeyStoreBackend {
    fn put(&mut self, key: &str, value: &[u8]) -> B4aeResult<()> {
        self.data.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn get(&self, key: &str) -> B4aeResult<Option<Vec<u8>>> {
        Ok(self.data.get(key).cloned())
    }
}

/// Key store for MIK persistence. Encrypts with passphrase-derived key.
pub struct KeyStore {
    backend: Box<dyn KeyStoreBackend>,
}

impl KeyStore {
    pub fn new(backend: Box<dyn KeyStoreBackend>) -> Self {
        Self { backend }
    }

    /// Derive encryption key from passphrase.
    fn derive_key(passphrase: &[u8], salt: &[u8]) -> B4aeResult<AesKey> {
        let key = hkdf::derive_key_with_salt(salt, &[passphrase], b"B4AE-v1-keystore", 32)?;
        Ok(AesKey::from_bytes(&key)?)
    }

    /// Store MIK encrypted with passphrase.
    pub fn store_mik(&mut self, passphrase: &[u8], mik: &MasterIdentityKey) -> B4aeResult<()> {
        let mut salt = [0u8; 16];
        crate::crypto::random::fill_random(&mut salt).map_err(|e| B4aeError::CryptoError(e.to_string()))?;
        let key = Self::derive_key(passphrase, &salt)?;
        let plaintext = mik.to_bytes();
        let (nonce, ciphertext) = aes_gcm::encrypt(&key, &plaintext, b"B4AE-MIK")?;
        let mut blob = salt.to_vec();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        self.backend.put("mik", &blob)
    }

    /// Load MIK with passphrase.
    pub fn load_mik(&self, passphrase: &[u8]) -> B4aeResult<Option<MasterIdentityKey>> {
        let blob = match self.backend.get("mik")? {
            Some(b) => b,
            None => return Ok(None),
        };
        if blob.len() < 16 + 12 + 32 + 16 {
            return Err(B4aeError::CryptoError("KeyStore blob too short".to_string()));
        }
        let salt = &blob[0..16];
        let nonce = &blob[16..28];
        let ciphertext = &blob[28..];
        let key = Self::derive_key(passphrase, salt)?;
        let plaintext = aes_gcm::decrypt(&key, nonce, ciphertext, b"B4AE-MIK")?;
        Ok(Some(MasterIdentityKey::from_bytes(&plaintext)?))
    }
}
