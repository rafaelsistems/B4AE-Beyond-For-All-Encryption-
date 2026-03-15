//! Fuzz target untuk HKDF key derivation
//!
//! Menguji derive_key dengan arbitrary IKM, info, dan output length.
//! Goal: pastikan tidak ada panic, memory unsafety, atau crash pada input apapun.
#![no_main]

use libfuzzer_sys::fuzz_target;
use b4ae::crypto::hkdf::derive_key;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Split data: pertama 1 byte sebagai output_length hint, sisanya IKM + info
    let output_len = (data[0] as usize % 64) + 1; // 1–64 bytes
    let rest = &data[1..];

    // Split rest menjadi IKM dan info (50/50)
    let mid = rest.len() / 2;
    let ikm = &rest[..mid];
    let info = &rest[mid..];

    // derive_key arbitrary input tidak boleh panic
    let _ = derive_key(&[ikm], info, output_len);
});
