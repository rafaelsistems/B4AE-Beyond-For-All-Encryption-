// B4AE AES-256-GCM Implementation
// Authenticated Encryption with Associated Data (AEAD)

use crate::crypto::{CryptoError, CryptoResult};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

/// AES-256 key size in bytes (256 bits).
pub const KEY_SIZE: usize = 32;
/// GCM nonce size in bytes (96 bits, NIST recommended).
pub const NONCE_SIZE: usize = 12;
/// GCM authentication tag size in bytes (128 bits).
pub const TAG_SIZE: usize = 16;

/// AES-256-GCM Key
pub struct AesKey {
    key: [u8; KEY_SIZE],
}

impl AesKey {
    /// Create key from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeySize(
                format!("Expected {} bytes, got {}", KEY_SIZE, bytes.len())
            ));
        }
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(AesKey { key })
    }

    /// Generate random key
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        AesKey { key }
    }

    /// Get key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

/// Generate random nonce
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Encrypt data with AES-256-GCM
/// Returns: (nonce, ciphertext_with_tag)
pub fn encrypt(
    key: &AesKey,
    plaintext: &[u8],
    associated_data: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new_from_slice(&key.key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Decrypt data with AES-256-GCM
pub fn decrypt(
    key: &AesKey,
    nonce: &[u8],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> CryptoResult<Vec<u8>> {
    if nonce.len() != NONCE_SIZE {
        return Err(CryptoError::DecryptionFailed(
            format!("Invalid nonce size: expected {}, got {}", NONCE_SIZE, nonce.len())
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(&key.key)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext,
        aad: associated_data,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed("Authentication failed".to_string()))?;

    Ok(plaintext)
}

/// Encrypt with automatic nonce prepending
/// Format: [nonce || ciphertext_with_tag]
pub fn encrypt_combined(
    key: &AesKey,
    plaintext: &[u8],
    associated_data: &[u8],
) -> CryptoResult<Vec<u8>> {
    let (nonce, ciphertext) = encrypt(key, plaintext, associated_data)?;
    
    let mut combined = Vec::with_capacity(nonce.len() + ciphertext.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ciphertext);
    
    Ok(combined)
}

/// Decrypt with automatic nonce extraction
/// Format: [nonce || ciphertext_with_tag]
pub fn decrypt_combined(
    key: &AesKey,
    combined: &[u8],
    associated_data: &[u8],
) -> CryptoResult<Vec<u8>> {
    if combined.len() < NONCE_SIZE {
        return Err(CryptoError::DecryptionFailed(
            "Data too short to contain nonce".to_string()
        ));
    }

    let (nonce, ciphertext) = combined.split_at(NONCE_SIZE);
    decrypt(key, nonce, ciphertext, associated_data)
}

// Secure drop implementation
impl Drop for AesKey {
    fn drop(&mut self) {
        // Zero out key memory
        for byte in &mut self.key {
            *byte = 0;
        }
    }
}

impl std::fmt::Debug for AesKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AesKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = AesKey::generate();
        let plaintext = b"Hello, B4AE!";
        let aad = b"metadata";

        let (nonce, ciphertext) = encrypt(&key, plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_combined() {
        let key = AesKey::generate();
        let plaintext = b"Hello, B4AE!";
        let aad = b"metadata";

        let combined = encrypt_combined(&key, plaintext, aad).unwrap();
        let decrypted = decrypt_combined(&key, &combined, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_authentication_failure() {
        let key = AesKey::generate();
        let plaintext = b"Hello, B4AE!";
        let aad = b"metadata";

        let (nonce, mut ciphertext) = encrypt(&key, plaintext, aad).unwrap();
        
        // Tamper with ciphertext
        ciphertext[0] ^= 1;

        let result = decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad() {
        let key = AesKey::generate();
        let plaintext = b"Hello, B4AE!";
        let aad = b"metadata";

        let (nonce, ciphertext) = encrypt(&key, plaintext, aad).unwrap();
        
        // Use wrong AAD
        let wrong_aad = b"wrong";
        let result = decrypt(&key, &nonce, &ciphertext, wrong_aad);
        assert!(result.is_err());
    }
}
