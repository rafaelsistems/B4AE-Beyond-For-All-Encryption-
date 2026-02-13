# B4AE Roadmap

Peta jalan pengembangan B4AE (Beyond For All Encryption).

---

## Phase 1: Foundation ✅ (Selesai)

- [x] Research & specification
- [x] Cryptographic core implementation
- [x] Performance benchmarking framework
- [x] Technical documentation

---

## Phase 2: Core Development ✅ (100% Selesai)

### Selesai
- [x] Cryptographic core (Kyber, Dilithium, Hybrid, PFS+, ZKAuth)
- [x] Protocol (Handshake, Message, Session)
- [x] Metadata protection (Padding, Timing, Dummy, metadata_key MAC) — lengkap di `encrypt_message`/`decrypt_message`
- [x] Key hierarchy (MIK, DMK, STK, BKS, export/import) — `src/key_hierarchy.rs`
- [x] Encrypted storage — `src/storage.rs` (EncryptedStorage, STK + AES-GCM)
- [x] Key store — `src/key_store.rs` (persistent MIK dengan passphrase)
- [x] Onion routing — `src/crypto/onion.rs` (layered encryption)
- [x] IP anonymization — `ProtocolConfig::anonymization` (proxy_url, use_tor)
- [x] ELARA transport integration
- [x] B4aeElaraNode
- [x] CI/CD, Dependabot
- [x] Basic integration & security tests
- [x] Platform SDK (iOS Swift, Android Kotlin, Web WASM) — 100%

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
- [x] Persiapan crates.io (metadata, exclude, CRATES_IO_PUBLISH_PREP.md)
- [x] elara-transport: elara-core, elara-wire, elara-transport v0.1.0 dipublish ke crates.io; B4AE memakai `version = "0.1"`
- [x] Lihat [CRATES_IO_PUBLISH_PREP.md](CRATES_IO_PUBLISH_PREP.md)

---

## Jangka Panjang (6–24 Bulan)

### Platform SDK
- [x] **iOS**: Swift bindings (b4ae-ffi + bindings/swift) + build_ios.sh/.ps1
- [x] **Android**: Kotlin JNI (b4ae-android + b4ae-android-app) + build_android.sh/.ps1
- [x] **Web**: WebAssembly (b4ae-wasm + wasm-demo) + build_wasm.ps1, package.json
- [x] **Full protocol**: b4ae-ffi feature `full-protocol` (handshake + encrypt/decrypt C API)
- [x] **Contoh aplikasi**: b4ae_chat_demo, b4ae_file_transfer_demo, b4ae_gateway_demo

### Production-Ready
- [x] **Audit logging** — modul `audit` (AuditEvent, AuditSink) + terhubung ke B4aeClient (audit_sink)
- [x] **Codebase audit & hardening** — fill_random error propagation; SessionManager poison recovery; remove_padding PKCS#7; BKS 2-of-2 HMAC; Message/sequence validation; elara_node bincode limit; B4aeClient cleanup_inactive_sessions
- [x] **Proptest invariants** — AES roundtrip, handshake completeness (lihat [FORMAL_VERIFICATION.md](FORMAL_VERIFICATION.md))
- [x] **Fuzzing CI** — job Proptest Invariants di GitHub Actions
- [x] **HSM trait** — `HsmBackend` + `NoOpHsm` + `Pkcs11Hsm` (feature `hsm-pkcs11`)
- [x] Formal verification (TLA+ spec + TLC CI, Coq safety theorem)
- [x] cargo-fuzz / libfuzzer (fuzz targets + CI)
- [x] **Performance tuning** — `crypto::perf` (AES-NI, AVX2 detection), [PERFORMANCE.md](PERFORMANCE.md)

### Ekosistem
- [x] **Plugin architecture** — [PLUGIN_ARCHITECTURE.md](PLUGIN_ARCHITECTURE.md) (Signal, Matrix)
- [x] **Gateway/proxy** — [GATEWAY_PROXY.md](GATEWAY_PROXY.md) + b4ae_gateway_demo
- [x] **Enterprise guide** — [ENTERPRISE_DEPLOYMENT_GUIDE.md](ENTERPRISE_DEPLOYMENT_GUIDE.md)

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
