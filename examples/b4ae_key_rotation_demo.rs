//! B4AE Key Rotation Demo
//!
//! Menunjukkan cara melakukan key rotation yang aman:
//! - Export key state
//! - Generate key baru
//! - Re-encrypt dengan key baru
//! - Verifikasi integritas setelah rotasi
//!
//! Usage:
//!   cargo run --example b4ae_key_rotation_demo

use b4ae::client::B4aeClient;
use b4ae::protocol::SecurityProfile;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== B4AE Key Rotation Demo ===\n");

    // --- 1. Setup dua klien (simulasi Alice dan Bob) ---
    println!("1. Setup Alice dan Bob...");
    let mut alice = B4aeClient::new(SecurityProfile::Standard)?;
    let mut bob = B4aeClient::new(SecurityProfile::Standard)?;

    let alice_id = b"alice";
    let bob_id = b"bob";

    // --- 2. Lakukan handshake awal ---
    println!("2. Handshake awal (session pertama)...");
    let init = alice.initiate_handshake(alice_id)?;
    let response = bob.respond_to_handshake(bob_id, init)?;
    let complete = alice.process_response(alice_id, response)?;
    bob.complete_handshake(bob_id, complete)?;
    alice.finalize_initiator(alice_id)?;
    println!("   ✅ Handshake selesai");

    // --- 3. Kirim beberapa pesan ---
    println!("\n3. Komunikasi sebelum key rotation...");
    let msgs1 = alice.encrypt_message(alice_id, b"Pesan pertama sebelum rotasi")?;
    for m in &msgs1 {
        let dec = bob.decrypt_message(bob_id, m)?;
        println!("   Alice → Bob: {}", String::from_utf8_lossy(&dec));
    }

    let msgs2 = bob.encrypt_message(bob_id, b"Balasan sebelum rotasi")?;
    for m in &msgs2 {
        let dec = alice.decrypt_message(alice_id, m)?;
        println!("   Bob → Alice: {}", String::from_utf8_lossy(&dec));
    }

    // --- 4. Simulasi key rotation ---
    println!("\n4. Key Rotation...");
    println!("   Alasan rotasi: jadwal berkala (misalnya setiap 24 jam)");

    // Tutup session lama
    println!("   � Tutup session lama Alice...");
    alice.close_session(alice_id);

    // Buat client baru dengan identitas baru (key baru)
    println!("   🔄 Generate keypair baru untuk Alice...");
    let mut alice_new = B4aeClient::new(SecurityProfile::Standard)?;

    // Lakukan re-handshake dengan key baru
    println!("   🤝 Re-handshake dengan key baru...");
    let new_init = alice_new.initiate_handshake(alice_id)?;
    let new_response = bob.respond_to_handshake(bob_id, new_init)?;
    let new_complete = alice_new.process_response(alice_id, new_response)?;
    bob.complete_handshake(bob_id, new_complete)?;
    alice_new.finalize_initiator(alice_id)?;
    println!("   ✅ Re-handshake berhasil");

    // --- 5. Verifikasi komunikasi setelah rotasi ---
    println!("\n5. Verifikasi komunikasi setelah key rotation...");
    let msgs3 = alice_new.encrypt_message(alice_id, b"Pesan pertama SETELAH rotasi")?;
    for m in &msgs3 {
        let dec = bob.decrypt_message(bob_id, m)?;
        println!("   Alice(baru) → Bob: {}", String::from_utf8_lossy(&dec));
    }

    let msgs4 = bob.encrypt_message(bob_id, b"Bob menerima pesan setelah rotasi")?;
    for m in &msgs4 {
        let dec = alice_new.decrypt_message(alice_id, m)?;
        println!("   Bob → Alice(baru): {}", String::from_utf8_lossy(&dec));
    }

    // --- 6. Kebijakan key rotation ---
    println!("\n6. Best Practices Key Rotation:");
    println!("   ✅ Rotasi Identity Key (MIK): setiap 1 tahun");
    println!("   ✅ Rotasi Session Key: otomatis via Double Ratchet setiap pesan");
    println!("   ✅ Rotasi Device Key (DMK): setiap device re-registration");
    println!("   ✅ Simpan audit log setiap rotasi");
    println!("   ✅ Overlap period: izinkan key lama terima pesan selama 24 jam");
    println!("   ✅ Notifikasi peer sebelum rotasi via re-handshake");
    println!("   ❌ Jangan rotasi di tengah sesi aktif tanpa re-handshake");
    println!("   ❌ Jangan hapus key lama sebelum semua pesan in-flight diterima");

    println!("\n=== Demo selesai ===");
    Ok(())
}
