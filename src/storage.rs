//! B4AE Encrypted Storage
//!
//! Secure storage using Storage Key (STK) from key hierarchy.
//! Data encrypted with AES-256-GCM; context used as AAD.

use crate::crypto::aes_gcm::{self, AesKey};
use crate::error::{B4aeError, B4aeResult};
use crate::key_hierarchy::StorageKey;
use std::collections::HashMap;

/// Backend for persistent storage (caller provides implementation).
pub trait StorageBackend: Send + Sync {
    /// Write encrypted blob
    fn write(&mut self, id: &[u8], data: &[u8]) -> B4aeResult<()>;
    /// Read encrypted blob
    fn read(&self, id: &[u8]) -> B4aeResult<Option<Vec<u8>>>;
    /// Delete
    fn delete(&mut self, id: &[u8]) -> B4aeResult<bool>;
}

/// In-memory storage backend (for testing or session-scoped data).
#[derive(Default)]
pub struct MemoryStorageBackend {
    data: HashMap<Vec<u8>, Vec<u8>>,
}

impl MemoryStorageBackend {
    /// Create new in-memory storage backend.
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
}

impl StorageBackend for MemoryStorageBackend {
    fn write(&mut self, id: &[u8], data: &[u8]) -> B4aeResult<()> {
        self.data.insert(id.to_vec(), data.to_vec());
        Ok(())
    }

    fn read(&self, id: &[u8]) -> B4aeResult<Option<Vec<u8>>> {
        Ok(self.data.get(id).cloned())
    }

    fn delete(&mut self, id: &[u8]) -> B4aeResult<bool> {
        Ok(self.data.remove(id).is_some())
    }
}

/// Encrypted storage using STK. Encrypts data with AES-256-GCM; context = AAD.
pub struct EncryptedStorage {
    key: StorageKey,
    backend: Box<dyn StorageBackend>,
}

impl EncryptedStorage {
    /// Create from StorageKey and backend.
    pub fn new(key: StorageKey, backend: Box<dyn StorageBackend>) -> Self {
        Self { key, backend }
    }

    /// Store data encrypted. `context` (e.g. "vault:profile") used as AAD.
    pub fn store(&mut self, context: &[u8], id: &[u8], plaintext: &[u8]) -> B4aeResult<()> {
        let aes_key = AesKey::from_bytes(self.key.as_slice())?;
        let (nonce, ciphertext) = aes_gcm::encrypt(&aes_key, plaintext, context)?;
        let mut blob = nonce;
        blob.extend_from_slice(&ciphertext);
        let storage_id = storage_id(context, id);
        self.backend.write(&storage_id, &blob)
    }

    /// Retrieve and decrypt.
    pub fn retrieve(&self, context: &[u8], id: &[u8]) -> B4aeResult<Option<Vec<u8>>> {
        let storage_id = storage_id(context, id);
        let blob = match self.backend.read(&storage_id)? {
            Some(b) => b,
            None => return Ok(None),
        };
        if blob.len() < 12 + 16 {
            return Err(B4aeError::CryptoError("Storage blob too short".to_string()));
        }
        let (nonce, ct) = blob.split_at(12);
        let aes_key = AesKey::from_bytes(self.key.as_slice())?;
        let plaintext = aes_gcm::decrypt(&aes_key, nonce, ct, context)?;
        Ok(Some(plaintext))
    }

    /// Delete stored entry.
    pub fn delete(&mut self, context: &[u8], id: &[u8]) -> B4aeResult<bool> {
        let storage_id = storage_id(context, id);
        self.backend.delete(&storage_id)
    }
}

fn storage_id(context: &[u8], id: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(context.len() as u32).to_be_bytes());
    out.extend_from_slice(context);
    out.extend_from_slice(id);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_hierarchy::{DeviceMasterKey, MasterIdentityKey};

    #[test]
    fn test_encrypted_storage_roundtrip() {
        let mik = MasterIdentityKey::generate().unwrap();
        let dmk = mik.derive_dmk(b"device-1").unwrap();
        let stk = dmk.derive_stk(b"vault").unwrap();
        let backend = Box::new(MemoryStorageBackend::new());
        let mut storage = EncryptedStorage::new(stk, backend);

        storage
            .store(b"vault:profiles", b"alice", b"secret data")
            .unwrap();
        let retrieved = storage.retrieve(b"vault:profiles", b"alice").unwrap().unwrap();
        assert_eq!(retrieved, b"secret data");
    }
}
