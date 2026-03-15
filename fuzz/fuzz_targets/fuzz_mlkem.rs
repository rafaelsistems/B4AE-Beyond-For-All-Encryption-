//! Fuzz target untuk ML-KEM-1024 (FIPS 203) key encapsulation/decapsulation
//!
//! Menguji decapsulate dengan arbitrary ciphertext dan arbitrary key bytes.
//! Goal: pastikan tidak ada panic, memory unsafety, atau crash pada input apapun.
#![no_main]

use libfuzzer_sys::fuzz_target;
use b4ae::crypto::kyber::{KyberSecretKey, KyberCiphertext, decapsulate};

fuzz_target!(|data: &[u8]| {
    // KyberSecretKey::SIZE = 3168, KyberCiphertext::SIZE = 1568
    const SK_SIZE: usize = 3168;
    const CT_SIZE: usize = 1568;

    if data.len() < SK_SIZE + CT_SIZE {
        return;
    }

    let sk_bytes = &data[..SK_SIZE];
    let ct_bytes = &data[SK_SIZE..SK_SIZE + CT_SIZE];

    // Wrap ke tipe — decapsulate arbitrary input tidak boleh panic
    if let (Ok(sk), Ok(ct)) = (
        KyberSecretKey::from_bytes(sk_bytes),
        KyberCiphertext::from_bytes(ct_bytes),
    ) {
        // Hasil boleh Err (invalid), tapi TIDAK BOLEH panic
        let _ = decapsulate(&sk, &ct);
    }
});
