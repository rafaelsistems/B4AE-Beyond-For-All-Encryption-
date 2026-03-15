//! Fuzz target untuk ML-DSA-87 (FIPS 204) signature verification
//!
//! Menguji verify dengan arbitrary public key, message, dan signature bytes.
//! Goal: pastikan tidak ada panic, memory unsafety, atau crash pada input apapun.
#![no_main]

use libfuzzer_sys::fuzz_target;
use b4ae::crypto::dilithium::{DilithiumPublicKey, DilithiumSignature, verify};

fuzz_target!(|data: &[u8]| {
    // DilithiumPublicKey::SIZE = 2592, DilithiumSignature min ~4627 bytes
    const PK_SIZE: usize = 2592;
    const SIG_SIZE: usize = 4627;
    const MIN_SIZE: usize = PK_SIZE + SIG_SIZE;

    if data.len() < MIN_SIZE {
        return;
    }

    let pk_bytes = &data[..PK_SIZE];
    let sig_bytes = &data[PK_SIZE..PK_SIZE + SIG_SIZE];
    let message = &data[PK_SIZE + SIG_SIZE..];

    if let (Ok(pk), Ok(sig)) = (
        DilithiumPublicKey::from_bytes(pk_bytes),
        DilithiumSignature::from_bytes(sig_bytes),
    ) {
        // Hasil boleh Err atau Ok(false), tapi TIDAK BOLEH panic
        let _ = verify(&pk, message, &sig);
    }
});
