//! B4AE Audit Logging Demo
//!
//! Menunjukkan cara menggunakan sistem audit logging B4AE:
//! - Konfigurasi AuditSink
//! - Capture dan inspect AuditEvent
//! - Implementasi custom AuditSink untuk SIEM integration
//!
//! Usage:
//!   cargo run --example b4ae_audit_logging_demo

use b4ae::audit::{AuditEvent, AuditSink, MemoryAuditSink};
use b4ae::client::{B4aeClient, B4aeConfig};
use b4ae::protocol::SecurityProfile;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== B4AE Audit Logging Demo ===\n");

    // --- 1. Setup MemoryAuditSink ---
    println!("1. Setup MemoryAuditSink...");
    let audit_sink = Arc::new(MemoryAuditSink::new());

    // --- 2. Buat klien dengan AuditSink via B4aeConfig ---
    println!("2. Buat B4aeClient dengan audit logging...");
    let alice_config = B4aeConfig {
        audit_sink: Some(audit_sink.clone() as Arc<dyn AuditSink>),
        ..B4aeConfig::default()
    };
    let mut alice = B4aeClient::with_config(alice_config)?;
    let mut bob = B4aeClient::new(SecurityProfile::Standard)?;

    let alice_id = b"alice";
    let bob_id = b"bob";

    // --- 3. Lakukan handshake dan kirim pesan ---
    println!("3. Handshake dan komunikasi...");
    let init = alice.initiate_handshake(alice_id)?;
    let response = bob.respond_to_handshake(bob_id, init)?;
    let complete = alice.process_response(alice_id, response)?;
    bob.complete_handshake(bob_id, complete)?;
    alice.finalize_initiator(alice_id)?;

    let msgs = alice.encrypt_message(alice_id, b"Pesan yang di-audit")?;
    for m in &msgs { let _ = bob.decrypt_message(bob_id, m)?; }

    let msgs2 = alice.encrypt_message(alice_id, b"Pesan kedua")?;
    for m in &msgs2 { let _ = bob.decrypt_message(bob_id, m)?; }

    // --- 4. Inspect audit log ---
    let entries = audit_sink.entries();
    println!("\n4. Audit Log ({} events):", entries.len());
    println!("   {:<50} {}", "Event", "Context");
    println!("   {}", "-".repeat(70));

    for entry in &entries {
        let event_name = format!("{:?}", entry.event);
        let ctx = entry.context.as_deref().unwrap_or("-");
        println!("   {:<50} {}", event_name, ctx);
    }

    // --- 5. Filter events berdasarkan tipe ---
    println!("\n5. Filter: hanya HandshakeCompleted events...");
    let handshake_events: Vec<_> = entries.iter()
        .filter(|e| matches!(e.event, AuditEvent::HandshakeCompleted { .. }))
        .collect();
    println!("   Ditemukan {} HandshakeCompleted events", handshake_events.len());

    // --- 6. Contoh integrasi SIEM produksi ---
    println!("\n6. Contoh Custom AuditSink untuk SIEM produksi:");
    println!(
        r#"
   // Forward ke Elasticsearch / Splunk / syslog:
   struct SiemAuditSink {{
       endpoint: String,
       client: reqwest::Client,
   }}

   impl AuditSink for SiemAuditSink {{
       fn log(&self, entry: AuditEntry) {{
           let json = serde_json::json!({{
               "timestamp": entry.timestamp,
               "event": format!("{{:?}}", entry.event),
               "session_id": entry.session_id,
               "severity": entry.severity,
               "detail": entry.detail,
           }});
           // Non-blocking send ke SIEM
           let _ = self.client.post(&self.endpoint).json(&json).send();
       }}
   }}
"#
    );

    // --- 7. Best practices audit logging ---
    println!("7. Best Practices Audit Logging:");
    println!("   ✅ Log semua handshake events (init, response, complete)");
    println!("   ✅ Log semua key rotation events");
    println!("   ✅ Log authentication failures dengan reason");
    println!("   ✅ Log session termination");
    println!("   ✅ Sertakan timestamp, session_id, peer_id di setiap entry");
    println!("   ✅ Forward ke immutable storage (SIEM, append-only DB)");
    println!("   ✅ Aktifkan alerting untuk HIGH severity events");
    println!("   ❌ Jangan log plaintext message content");
    println!("   ❌ Jangan log private keys atau shared secrets");
    println!("   ❌ Jangan simpan audit log di storage yang sama dengan data");

    println!("\n=== Demo selesai ===");
    Ok(())
}
