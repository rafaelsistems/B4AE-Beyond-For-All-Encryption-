# B4AE Audit: Ketidaksesuaian Implementasi vs Dokumentasi

**Tanggal:** 13 Februari 2026  
**Scope:** Auditing komprehensif codebase dan dokumen untuk menemukan ketidaksesuaian implementasi.  
**Perbaikan:** 13 Februari 2026 — Semua item kritis dan tinggi telah diperbaiki (merujuk implementasi X25519/Ed25519).

---

## Ringkasan Eksekutif

Audit menemukan **15 ketidaksesuaian** dalam kategori kritis, tinggi, dan medium. **Semua telah diperbaiki per 13 Feb 2026** (kode + spesifikasi + dokumentasi).

---

## 1. Kritis (Critical)

### 1.1 Classical Cryptography: P-521 vs X25519/Ed25519

| Lokasi | Klaim | Implementasi Aktual |
|--------|-------|---------------------|
| README.md (Security) | "ECDH P-521", "ECDSA P-521" | X25519, Ed25519 |
| specs/B4AE_Protocol_Specification_v1.0.md §3.2 | ECDH P-521 (133 bytes), ECDSA P-521 (133 bytes) | X25519 (32 bytes), Ed25519 (32 bytes) |
| src/crypto/hybrid.rs | — | `x25519-dalek`, `ring` Ed25519 |

**Dampak:** Spesifikasi dan dokumentasi publik salah. Implementasi menggunakan kurva berbeda (Curve25519 vs NIST P-521).

**Rekomendasi:**
- **Opsi A:** Perbarui semua dokumen untuk mencerminkan X25519/Ed25519 (lebih umum di ecosystem modern).
- **Opsi B:** Implementasikan P-521 sesuai spesifikasi (perlu dependency tambahan, mis. `p256` crate).

---

### 1.2 Key Derivation: Master Secret vs Spec

| Spec (B4AE_Protocol_Specification §6.4) | Implementasi (handshake.rs) |
|---------------------------------------|----------------------------|
| `master_secret = HKDF(ikm=kyber_ss\|\|ecdh_ss, salt=client_random\|\|server_random, info="B4AE-v1-master-secret")` | `shared_secret` dari hybrid encapsulate digunakan **langsung** sebagai master_secret tanpa langkah HKDF dengan salt |
| Session keys dari master_secret | Session keys di-derive dari `shared_secret + key_material` |

**Dampak:** Alur key derivation tidak sesuai spesifikasi. Potensi incompatibility jika ada implementasi lain mengikuti spec.

**Rekomendasi:** Implementasikan tahap HKDF untuk master_secret sesuai spec:
```rust
master_secret = HKDF(ikm=shared_secret, salt=client_random||server_random, info="B4AE-v1-master-secret", length=32)
```

---

### 1.3 HKDF Info String: Handshake vs Spec

| Spec §6.4 | handshake.rs (Initiator & Responder) |
|-----------|--------------------------------------|
| `B4AE-v1-encryption-key` | `B4AE-v1-encryption` |
| `B4AE-v1-authentication-key` | `B4AE-v1-authentication` |
| `B4AE-v1-metadata-key` | `B4AE-v1-metadata` |

**Catatan:** `hkdf.rs` B4aeKeyDerivation menggunakan string yang benar; handshake memiliki `derive_session_keys` sendiri dengan string yang salah.

**Rekomendasi:** Seragamkan ke `B4AE-v1-encryption-key`, `B4AE-v1-authentication-key`, `B4AE-v1-metadata-key` di `handshake.rs`.

---

## 2. Tinggi (High)

### 2.1 Handshake State Naming: Initial vs Initiation

| Sumber | Nama State Awal |
|--------|------------------|
| Rust `handshake.rs` | `HandshakeState::Initial` |
| TLA+ `B4AE_Handshake.tla` | `Initiation == 1` |
| Coq `B4AE_Handshake.v` | `Initiation` (comment: "matches Rust HandshakeState") |

**Dampak:** Ketidakkonsistenan semantik; Coq comment tidak akurat.

**Rekomendasi:** Rename `Initial` → `Initiation` di Rust agar selaras dengan spec formal.

---

### 2.2 HybridPublicKey Size: Spec vs Implementation

| Spec §6.2 | Implementasi |
|-----------|--------------|
| `ecdh_public: [u8; 133]` (P-521) | Variable length (X25519 = 32 bytes) |
| `ecdsa_public: [u8; 133]` (P-521) | Variable length (Ed25519 = 32 bytes) |

**Dampak:** Format serialisasi tidak cocok dengan spesifikasi.

**Rekomendasi:** Sesuaikan dengan pilihan di 1.1—update spec jika tetap memakai X25519/Ed25519.

---

### 2.3 Dilithium Signature Size

| Spec §3.1.2 | Implementation (dilithium.rs) |
|-------------|------------------------------|
| Signature: 4595 bytes | `SIZE = 4627` (pqcrypto-dilithium5); accept 4595–4700 |

**Dampak:** Perbedaan kecil; pqcrypto mungkin menggunakan encoding berbeda dari NIST FIPS 204.

**Rekomendasi:** Verifikasi ukuran output pqcrypto-dilithium5. Jika 4627 benar, perbarui spec. Jika 4595 benar, perbaiki konstanta di code.

---

### 2.4 API Design vs Implementasi

| B4AE_API_Design_v1.0 | B4aeClient (client.rs) |
|----------------------|-------------------------|
| `client.generate_identity().await?` | ❌ Tidak ada |
| `client.connect(&peer_id).await?` | ❌ Tidak ada (pakai handshake manual) |
| `session.send_text()`, `session.receive()` | ❌ API berbeda: `encrypt_message()`, `decrypt_message()` |
| `B4aeConfig { metadata_protection, enable_dummy_traffic, storage_path }` | `B4aeConfig { security_profile, crypto_config, protocol_config, handshake_config }` |
| `session.send_file()`, `session.receive_file()` | ❌ Tidak ada |
| `client.create_group()`, group messaging | ❌ Tidak ada |

**Dampak:** Dokumen API menggambarkan API yang lebih lengkap dan async daripada yang diimplementasikan.

**Rekomendasi:** Tambah catatan di API Design bahwa v1.0 mendeskripsikan API target; implementasi saat ini adalah subset. Atau sesuaikan dokumen dengan API aktual.

---

## 3. Medium

### 3.1 Key Hierarchy (MIK, DMK, SK)

| Spec §4.1 | Implementasi |
|-----------|--------------|
| Master Identity Key (MIK) → Device Master Key (DMK) → Session Key (SK) → Message Key (MK) | ❌ Hierarchy tidak diimplementasikan |
| Key lifetimes & rotation policy | PFS+ dan Session ada, tapi tanpa MIK/DMK |

**Rekomendasi:** Entah implementasikan hierarchy sesuai spec, atau tandai di spec bahwa ini roadmap/fase lanjut.

---

### 3.2 Message Format Header Size

| Spec §5.1 | EncryptedMessage (message.rs) |
|-----------|-------------------------------|
| Total Header: 40 bytes (Version 2 + Type 1 + Flags 1 + Seq 8 + Timestamp 8 + PayloadLen 4 + ...) | Layout berbeda: version, message_type, flags, sequence, timestamp, payload, nonce—tidak ada `Payload Length` terpisah di header |

**Rekomendasi:** Verifikasi layout serialisasi aktual; perbarui spec jika format berubah.

---

### 3.3 PLUGIN_ARCHITECTURE: Curve25519

| PLUGIN_ARCHITECTURE.md | README/Protocol Spec |
|------------------------|----------------------|
| "x25519-dalek (B4AE hybrid)" | "ECDH-P521 / ECDSA-P521" |

PLUGIN_ARCHITECTURE konsisten dengan implementasi; README/spec tidak.

---

### 3.4 README Duplikasi & Status

- README memiliki dua blok Quick Start dan Project Status yang overlap.
- "Current Phase: Phase 2" vs "Phase 4: Production & Deployment ✅"—bertentangan.

**Rekomendasi:** Deduplikasi dan rapikan status project.

---

### 3.5 Platform SDK: API Scope

| README Platform SDK table | PLATFORM_SDK.md |
|---------------------------|-----------------|
| "generateKey, encrypt, decrypt" | "Subset API AES-256-GCM (generateKey, encrypt, decrypt)" |

Sesuai—Platform SDK memang subset, tidak full handshake. ✅ Tidak ada ketidaksesuaian.

---

## 4. Daftar Perbaikan Prioritas

| Prioritas | Item | Usaha | Impact |
|-----------|------|-------|--------|
| P0 | Perbaiki dokumen Classical Crypto (P-521 vs X25519) | Dokumen | Klarifikasi publik |
| P0 | Align key derivation (master_secret + HKDF info) | Code | Security consistency |
| P1 | Rename Initial → Initiation | Code | Formal spec alignment |
| P1 | Update API Design doc vs actual API | Dokumen | Developer experience |
| P2 | Key hierarchy (MIK/DMK) status di spec | Dokumen | Clarify roadmap |
| P2 | Consolidate README status/duplicates | Dokumen | Maintenance |

---

## 5. Yang Sudah Sesuai ✅

- Message types (0x01–0x10, 0x20, 0x30, 0xFF) sesuai spec
- Message flags (Encrypted, Compressed, Dummy, RequiresAck)
- HKDF menggunakan SHA3-256 sesuai spec
- Kyber-1024, Dilithium5 key sizes (public/secret)
- TLA+ dan Coq state machine merepresentasikan alur handshake yang benar
- Platform SDK scope (generateKey, encrypt, decrypt) terdokumentasi dengan benar

---

**Disusun oleh:** B4AE Codebase Audit  
**Untuk pertanyaan:** Lihat CONTRIBUTING.md
