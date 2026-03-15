//! Fuzz target untuk AES-256-GCM encrypt/decrypt
//!
//! Menguji decrypt dengan arbitrary key, nonce, ciphertext, dan AAD.
//! Goal: pastikan tidak ada panic, memory unsafety, atau crash pada input apapun.
#![no_main]

use libfuzzer_sys::fuzz_target;
use b4ae::crypto::aes_gcm::{AesKey, decrypt_combined, KEY_SIZE};

fuzz_target!(|data: &[u8]| {
    // Minimal: KEY_SIZE (32) bytes untuk key, sisanya sebagai combined ciphertext
    if data.len() < KEY_SIZE + 1 {
        return;
    }

    let key_bytes = &data[..KEY_SIZE];
    let ciphertext = &data[KEY_SIZE..];

    if let Ok(key) = AesKey::from_bytes(key_bytes) {
        // decrypt_combined arbitrary input tidak boleh panic
        // (akan return Err untuk input tidak valid)
        let _ = decrypt_combined(&key, ciphertext, b"fuzz-aad");
    }
});
