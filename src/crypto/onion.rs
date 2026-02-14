//! B4AE Onion Routing Crypto Primitive
//!
//! Layered encryption for relay paths. Each hop decrypts one layer,
//! sees next-hop address, forwards remainder.

use crate::crypto::aes_gcm::{self, AesKey};
use crate::crypto::{CryptoError, CryptoResult};
use crate::crypto::random;

/// Maximum next-hop ID length.
pub const MAX_HOP_ID_LEN: usize = 256;

/// Encrypted onion layer. Format: nonce(12) || ciphertext || tag(16)
#[derive(Clone)]
pub struct OnionLayer {
    data: Vec<u8>,
}

impl OnionLayer {
    /// Returns the raw layer bytes (nonce || ciphertext || tag).
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Build onion-encrypted payload. Path: [(next_hop_id, layer_key)] from exit to entry.
/// Innermost payload is the final message. Keys must be 32 bytes each.
pub fn onion_encrypt(
    path: &[(Vec<u8>, [u8; 32])],
    payload: &[u8],
) -> CryptoResult<OnionLayer> {
    let mut inner = payload.to_vec();
    for (next_hop, key) in path.iter() {
        if next_hop.len() > MAX_HOP_ID_LEN {
            return Err(CryptoError::InvalidInput(
                "Next hop ID too long".to_string(),
            ));
        }
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&(next_hop.len() as u16).to_be_bytes());
        plaintext.extend_from_slice(next_hop);
        plaintext.append(&mut inner);

        let aes_key = AesKey::from_bytes(key)?;
        let (nonce, ct) = aes_gcm::encrypt(&aes_key, &plaintext, b"B4AE-onion")?;
        inner = nonce;
        inner.extend_from_slice(&ct);
    }
    Ok(OnionLayer { data: inner })
}

/// Decrypt one layer. Returns (next_hop_id, rest) or (empty, payload) if final.
pub fn onion_decrypt_layer(
    layer_key: &[u8; 32],
    onion: &[u8],
) -> CryptoResult<(Option<Vec<u8>>, Vec<u8>)> {
    if onion.len() < 12 + 16 + 2 {
        return Err(CryptoError::DecryptionFailed("Onion too short".to_string()));
    }
    let (nonce, ct) = onion.split_at(12);
    let aes_key = AesKey::from_bytes(layer_key)?;
    let plaintext = aes_gcm::decrypt(&aes_key, nonce, ct, b"B4AE-onion")?;
    if plaintext.len() < 2 {
        return Err(CryptoError::DecryptionFailed("Invalid layer plaintext".to_string()));
    }
    let len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
    if len == 0 {
        return Ok((None, plaintext[2..].to_vec()));
    }
    if len > MAX_HOP_ID_LEN {
        return Err(CryptoError::DecryptionFailed("Next hop ID exceeds limit".to_string()));
    }
    if plaintext.len() < 2 + len {
        return Err(CryptoError::DecryptionFailed("Truncated next hop".to_string()));
    }
    let next_hop = plaintext[2..2 + len].to_vec();
    let rest = plaintext[2 + len..].to_vec();
    Ok((Some(next_hop), rest))
}

/// Generate random layer key for testing or key exchange.
pub fn generate_layer_key() -> CryptoResult<[u8; 32]> {
    let mut key = [0u8; 32];
    random::fill_random(&mut key)?;
    Ok(key)
}
