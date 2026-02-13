//! B4AE WebAssembly bindings
//!
//! Subset API untuk browser: symmetric encrypt/decrypt dengan AES-GCM.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm,
};
use getrandom::getrandom;
use wasm_bindgen::prelude::*;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

fn fill_random(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom(buf)
}

/// Generate random key untuk AES-256-GCM
#[wasm_bindgen]
pub fn generate_key() -> Vec<u8> {
    let mut key = [0u8; KEY_SIZE];
    fill_random(&mut key).expect("getrandom");
    key.to_vec()
}

/// Encrypt plaintext dengan AES-256-GCM
/// Returns [nonce (12) || ciphertext] as single Vec
#[wasm_bindgen]
pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
    if key.len() != KEY_SIZE {
        return Err(JsValue::from_str("Key must be 32 bytes"));
    }

    let mut nonce = [0u8; NONCE_SIZE];
    fill_random(&mut nonce).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let payload = Payload { msg: plaintext, aad: &[] };
    let ciphertext = cipher
        .encrypt((&nonce).into(), payload)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut result = nonce.to_vec();
    result.extend(ciphertext);
    Ok(result)
}

/// Decrypt [nonce (12) || ciphertext] dengan AES-256-GCM
#[wasm_bindgen]
pub fn decrypt(key: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, JsValue> {
    if key.len() != KEY_SIZE {
        return Err(JsValue::from_str("Key must be 32 bytes"));
    }
    if encrypted.len() < NONCE_SIZE {
        return Err(JsValue::from_str("Encrypted data too short"));
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let payload = Payload {
        msg: ciphertext,
        aad: &[],
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
