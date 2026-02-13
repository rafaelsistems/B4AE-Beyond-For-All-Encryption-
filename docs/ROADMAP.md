# B4AE Roadmap

Peta jalan pengembangan B4AE (Beyond For All Encryption).

---

## Phase 1: Foundation ✅ (Selesai)

- [x] Research & specification
- [x] Cryptographic core implementation
- [x] Performance benchmarking framework
- [x] Technical documentation

---

## Phase 2: Core Development ✅ (85% Selesai)

### Selesai
- [x] Cryptographic core (Kyber, Dilithium, Hybrid, PFS+, ZKAuth)
- [x] Protocol (Handshake, Message, Session)
- [x] Metadata protection (Padding, Timing, Obfuscation)
- [x] ELARA transport integration
- [x] B4aeElaraNode
- [x] CI/CD, Dependabot
- [x] Basic integration & security tests

### Sisa
- [ ] Platform SDK (iOS, Android, Web) — in progress

---

## Selanjutnya (1–3 Bulan)

### Security
- [ ] Security audit (internal + external)
- [ ] `cargo audit` integration
- [ ] Lihat [SECURITY_AUDIT_CHECKLIST.md](SECURITY_AUDIT_CHECKLIST.md)

### Testing
- [ ] Integrasi testing lebih lengkap
- [ ] ELARA end-to-end tests
- [ ] Lihat [INTEGRATION_TESTING_PLAN.md](INTEGRATION_TESTING_PLAN.md)

### Publish
- [ ] Persiapan crates.io
- [ ] elara-transport sebagai dependency (bukan path)
- [ ] Lihat [CRATES_IO_PUBLISH_PREP.md](CRATES_IO_PUBLISH_PREP.md)

---

## Jangka Panjang (6–24 Bulan)

### Platform SDK
- [ ] **iOS**: Swift/ObjC bindings, XCFramework — Lihat [PLATFORM_SDK.md](PLATFORM_SDK.md)
- [ ] **Android**: Kotlin/Java JNI atau Rust via jni-rs
- [ ] **Web**: WebAssembly (wasm-bindgen), target `wasm32-unknown-unknown`
- [ ] Contoh aplikasi (chat, file transfer)

### Production-Ready
- [x] **Audit logging** — modul `audit` (AuditEvent, AuditSink)
- [x] **Proptest invariants** — AES roundtrip, handshake completeness (lihat [FORMAL_VERIFICATION.md](FORMAL_VERIFICATION.md))
- [x] **Fuzzing CI** — job Proptest Invariants di GitHub Actions
- [x] **HSM trait** — `HsmBackend` + `NoOpHsm` (feature `hsm`)
- [ ] Formal verification (TLA+/Coq)
- [ ] OSS-Fuzz / libfuzzer integration
- [ ] Performance tuning (AES-NI, SIMD)

### Ekosistem
- [ ] Plugin/extension untuk Signal, Matrix, dll
- [ ] Gateway/proxy untuk legacy protocol
- [ ] Enterprise deployment guide

---

## Ringkasan Timeline

| Periode | Fokus |
|---------|-------|
| **Sekarang** | Tutup PR Dependabot rand, bersihkan warnings, perbaiki tests |
| **1–3 bln** | Security audit, integration testing, crates.io prep |
| **6–12 bln** | Platform SDK (iOS, Android, Web) |
| **12–24 bln** | Production-ready, HSM, formal verification |

---

## Referensi

- [Phase 2 Completion Report](../PHASE2_COMPLETION_REPORT.md)
- [Implementation Audit](../IMPLEMENTATION_AUDIT.md)
- [CHANGELOG](../CHANGELOG.md)
