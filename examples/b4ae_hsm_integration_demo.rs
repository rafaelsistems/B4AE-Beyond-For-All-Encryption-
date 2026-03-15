//! B4AE HSM Integration Demo
//!
//! Menunjukkan cara menggunakan B4AE dengan Hardware Security Module (HSM)
//! melalui NoOpHsm (development) dan antarmuka HsmBackend.
//!
//! Usage:
//!   cargo run --example b4ae_hsm_integration_demo --features hsm

#[cfg(feature = "hsm")]
use b4ae::hsm::{HsmBackend, NoOpHsm};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== B4AE HSM Integration Demo ===\n");

    // --- 1. Menggunakan NoOpHsm (development/testing) ---
    println!("1. Inisialisasi NoOpHsm (fallback untuk development)...");

    #[cfg(feature = "hsm")]
    {
        let hsm = NoOpHsm::new();
        println!("   HSM tersedia: {}", hsm.is_available());
        match hsm.generate_keypair("test-key") {
            Ok(_) => println!("   Keypair dibuat (tidak diharapkan pada NoOpHsm)"),
            Err(e) => println!("   Expected error dari NoOpHsm: {}", e),
        }
    }

    #[cfg(not(feature = "hsm"))]
    println!("   (Jalankan dengan --features hsm untuk demo NoOpHsm)");

    // --- 2. Demonstrasi interface HsmBackend ---
    println!("\n2. Interface HsmBackend:");
    println!("   Untuk produksi, implementasikan HsmBackend untuk:");
    println!("   - SoftHSM2 (testing): libsofthsm2.so");
    println!("   - Nitrokey HSM 2");
    println!("   - Thales Luna HSM");
    println!("   - AWS CloudHSM");
    println!("   - Azure Dedicated HSM");

    // --- 3. Contoh konfigurasi PKCS#11 (production) ---
    println!("\n3. Contoh konfigurasi PKCS#11 untuk produksi:");
    println!(
        r#"
   // Aktifkan feature hsm-pkcs11 di Cargo.toml:
   // b4ae = {{ version = "2.1", features = ["hsm-pkcs11"] }}

   #[cfg(feature = "hsm-pkcs11")]
   {{
       use b4ae::hsm::pkcs11_enhanced::Pkcs11HsmEnhanced;

       // Inisialisasi dengan library path dan slot
       let hsm = Pkcs11HsmEnhanced::new(
           "/usr/lib/softhsm/libsofthsm2.so",  // Library path
           slot_id,                              // PKCS#11 slot
           Some("your-pin"),                     // PIN (opsional)
       )?;

       // Generate keypair di HSM (key tidak pernah keluar dari HSM)
       let public_key = hsm.generate_keypair("b4ae-master-key")?;

       // Sign data dengan private key yang aman di HSM
       let signature = hsm.sign("b4ae-master-key", &data)?;

       // Verify signature
       let valid = hsm.verify("b4ae-master-key", &data, &signature)?;
   }}
"#
    );

    // --- 4. Best practices HSM ---
    println!("4. Best Practices HSM untuk Produksi:");
    println!("   ✅ Gunakan Pkcs11HsmEnhanced untuk enterprise deployment");
    println!("   ✅ Master Identity Key (MIK) harus tersimpan di HSM");
    println!("   ✅ Session keys boleh di-derive di software (HKDF)");
    println!("   ✅ Aktifkan CKF_OS_LOCKING_OK untuk multi-thread safety");
    println!("   ✅ Session per-operasi (tidak di-cache) untuk thread safety");
    println!("   ✅ PIN harus di-load dari env var atau secrets manager");
    println!("   ❌ Jangan hardcode PIN di kode");
    println!("   ❌ Jangan simpan private key di filesystem");

    println!("\n=== Demo selesai ===");
    Ok(())
}
