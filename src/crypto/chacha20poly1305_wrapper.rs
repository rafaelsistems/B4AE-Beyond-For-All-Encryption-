//! ChaCha20-Poly1305 AEAD Wrapper
//!
//! Provides a simple interface for ChaCha20-Poly1305 authenticated encryption
//! with deterministic nonce derivation to prevent nonce reuse vulnerabilities.

use crate::crypto::{CryptoResult, CryptoError};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce, Key,
};
use crate::crypto::hkdf::derive_key;

/// Encrypt data using ChaCha20-Poly1305 with deterministic nonce
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `counter` - Message counter for deterministic nonce derivation
/// * `plaintext` - Data to encrypt
/// * `aad` - Optional additional authenticated data
///
/// # Returns
/// * `Ok((ciphertext, tag, nonce))` - Encrypted data with authentication tag and nonce
/// * `Err(CryptoError)` - If encryption fails
///
/// # Security
/// - Nonce is derived deterministically from key and counter
/// - This prevents catastrophic nonce reuse failures
/// - Each (key, counter) pair produces a unique nonce
pub fn encrypt_chacha20poly1305(
    key: &[u8; 32],
    counter: u64,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> CryptoResult<(Vec<u8>, [u8; 16], [u8; 12])> {
    // Derive deterministic nonce from key and counter
    let counter_bytes = counter.to_be_bytes();
    let nonce_vec = derive_key(
        &[key, &counter_bytes],
        b"B4AE-v2-nonce",
        12,
    )?;

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&nonce_vec);

    // Create cipher
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Prepare payload
    let payload = Payload {
        msg: plaintext,
        aad: aad.unwrap_or(&[]),
    };

    // Encrypt
    let ciphertext_with_tag = cipher.encrypt(nonce, payload)
        .map_err(|e| CryptoError::EncryptionFailed(format!("ChaCha20-Poly1305 encryption failed: {}", e)))?;

    // Split ciphertext and tag
    let tag_start = ciphertext_with_tag.len().saturating_sub(16);
    let ciphertext = ciphertext_with_tag[..tag_start].to_vec();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext_with_tag[tag_start..]);

    Ok((ciphertext, tag, nonce_bytes))
}

/// Decrypt data using ChaCha20-Poly1305
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce
/// * `ciphertext` - Encrypted data
/// * `tag` - 16-byte authentication tag
/// * `aad` - Optional additional authenticated data
///
/// # Returns
/// * `Ok(plaintext)` - Decrypted data
/// * `Err(CryptoError)` - If decryption or authentication fails
///
/// # Security Note
/// The `chacha20poly1305` crate performs constant-time MAC verification internally
/// using `subtle::ConstantTimeEq`. The early return on authentication failure occurs
/// AFTER the constant-time MAC check completes, so there is no timing side-channel
/// that leaks information about the MAC validity during the comparison itself.
/// The timing difference between success and failure is limited to the plaintext
/// copy operation, which is negligible and does not leak secret information.
pub fn decrypt_chacha20poly1305(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    tag: &[u8; 16],
    aad: Option<&[u8]>,
) -> CryptoResult<Vec<u8>> {
    // Create cipher
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_obj = Nonce::from_slice(nonce);

    // Reconstruct ciphertext with tag
    let mut ciphertext_with_tag = ciphertext.to_vec();
    ciphertext_with_tag.extend_from_slice(tag);

    // Prepare payload
    let payload = Payload {
        msg: &ciphertext_with_tag,
        aad: aad.unwrap_or(&[]),
    };

    // Decrypt
    let plaintext = cipher.decrypt(nonce_obj, payload)
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0x42; 32];
        let counter = 0;
        let plaintext = b"Hello, ChaCha20-Poly1305!";
        let aad = b"additional data";

        let (ciphertext, tag, nonce) = encrypt_chacha20poly1305(
            &key,
            counter,
            plaintext,
            Some(aad),
        ).unwrap();

        let decrypted = decrypt_chacha20poly1305(
            &key,
            &nonce,
            &ciphertext,
            &tag,
            Some(aad),
        ).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_deterministic_nonce() {
        let key = [0x42; 32];
        let counter = 5;
        let plaintext = b"Test message";

        let (_, _, nonce1) = encrypt_chacha20poly1305(&key, counter, plaintext, None).unwrap();
        let (_, _, nonce2) = encrypt_chacha20poly1305(&key, counter, plaintext, None).unwrap();

        // Same key and counter should produce same nonce
        assert_eq!(nonce1, nonce2);
    }

    #[test]
    fn test_different_counters_different_nonces() {
        let key = [0x42; 32];
        let plaintext = b"Test message";

        let (_, _, nonce1) = encrypt_chacha20poly1305(&key, 0, plaintext, None).unwrap();
        let (_, _, nonce2) = encrypt_chacha20poly1305(&key, 1, plaintext, None).unwrap();

        // Different counters should produce different nonces
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_authentication_failure() {
        let key = [0x42; 32];
        let counter = 0;
        let plaintext = b"Hello, ChaCha20-Poly1305!";

        let (ciphertext, mut tag, nonce) = encrypt_chacha20poly1305(
            &key,
            counter,
            plaintext,
            None,
        ).unwrap();

        // Tamper with tag
        tag[0] ^= 0xFF;

        let result = decrypt_chacha20poly1305(
            &key,
            &nonce,
            &ciphertext,
            &tag,
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_aad_mismatch() {
        let key = [0x42; 32];
        let counter = 0;
        let plaintext = b"Hello, ChaCha20-Poly1305!";
        let aad1 = b"aad1";
        let aad2 = b"aad2";

        let (ciphertext, tag, nonce) = encrypt_chacha20poly1305(
            &key,
            counter,
            plaintext,
            Some(aad1),
        ).unwrap();

        // Try to decrypt with different AAD
        let result = decrypt_chacha20poly1305(
            &key,
            &nonce,
            &ciphertext,
            &tag,
            Some(aad2),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42; 32];
        let counter = 0;
        let plaintext = b"";

        let (ciphertext, tag, nonce) = encrypt_chacha20poly1305(
            &key,
            counter,
            plaintext,
            None,
        ).unwrap();

        let decrypted = decrypt_chacha20poly1305(
            &key,
            &nonce,
            &ciphertext,
            &tag,
            None,
        ).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }
}
