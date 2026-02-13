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
- [x] Platform SDK (iOS Swift, Android Kotlin, Web WASM) — bindings implemented

---

## Phase 3: Integration & Testing ✅

- [x] Security Testing & Audits — `scripts/security_audit.sh`, cargo audit di CI
- [x] Performance Optimization — `docs/PERFORMANCE.md`, release profile
- [x] Integration Testing — ELARA tests expanded (concurrent, bidirectional)

## Phase 4: Production & Deployment ✅

- [x] Production Infrastructure — Dockerfile, docker-compose
- [x] Pilot Deployment — `docs/PILOT_DEPLOYMENT_GUIDE.md`
- [x] General Availability — `docs/RELEASE_CHECKLIST.md`

## Selanjutnya (1–3 Bulan)

### Security
- [ ] External security audit
- [ ] Lihat [SECURITY_AUDIT_CHECKLIST.md](SECURITY_AUDIT_CHECKLIST.md)

### Publish
- [ ] Persiapan crates.io
- [ ] elara-transport sebagai dependency (bukan path)
- [ ] Lihat [CRATES_IO_PUBLISH_PREP.md](CRATES_IO_PUBLISH_PREP.md)

---

## Jangka Panjang (6–24 Bulan)

### Platform SDK
- [x] **iOS**: Swift bindings (b4ae-ffi C API + bindings/swift)
- [x] **Android**: Kotlin JNI (b4ae-android crate)
- [x] **Web**: WebAssembly (b4ae-wasm + wasm-demo)
- [ ] Contoh aplikasi (chat, file transfer)

### Production-Ready
- [x] **Audit logging** — modul `audit` (AuditEvent, AuditSink)
- [x] **Proptest invariants** — AES roundtrip, handshake completeness (lihat [FORMAL_VERIFICATION.md](FORMAL_VERIFICATION.md))
- [x] **Fuzzing CI** — job Proptest Invariants di GitHub Actions
- [x] **HSM trait** — `HsmBackend` + `NoOpHsm` + `Pkcs11Hsm` (feature `hsm-pkcs11`)
- [x] Formal verification (TLA+ spec + TLC CI, Coq safety theorem)
- [x] cargo-fuzz / libfuzzer (fuzz targets + CI)
- [ ] Performance tuning (AES-NI, SIMD)

### Ekosistem
- [ ] Plugin/extension untuk Signal, Matrix, dll
- [ ] Gateway/proxy untuk legacy protocol
- [ ] Enterprise deployment guide

---

## Ringkasan Timeline

| Periode | Fokus |
|---------|-------|
| **Sekarang** | Security audit, integration testing, crates.io prep |
| **1–3 bln** | Contoh aplikasi (chat, file transfer) |
| **6–12 bln** | Production-ready, enterprise deployment |
| **12–24 bln** | Ekosistem (plugin, gateway) |

---

## Referensi

- [Platform SDK](PLATFORM_SDK.md)
- [Formal Verification](FORMAL_VERIFICATION.md)
- [CHANGELOG](../CHANGELOG.md)
