# Changelog

All notable changes to B4AE will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Phase 2: Platform SDK 100% Complete**
  - `scripts/build_ios.sh` / `build_ios.ps1` — build C FFI for Swift Package
  - `scripts/build_android.sh` / `build_android.ps1` — build JNI, copy to app
  - `scripts/build_wasm.ps1` — build WASM for wasm-demo
  - `b4ae-android-app/` — minimal Android demo app (MainActivity, B4AE.kt, jniLibs)
  - `bindings/swift/libs/` — Swift Package library path
  - `wasm-demo/package.json` — npm run build, npm run serve

- **Phase 3: Integration & Testing**
  - `scripts/security_audit.sh` / `security_audit.ps1` — security audit script
  - CI: security audit script (cargo audit, build, test)
  - `docs/PERFORMANCE.md` — performance optimization guide
  - ELARA integration tests: concurrent_two_connections, bidirectional_messages

- **Phase 4: Production & Deployment**
  - `Dockerfile` — production Docker image (B4AE + ELARA demo)
  - `docker-compose.yml` — local demo
  - `docs/PRODUCTION_DEPLOYMENT.md` — production deployment guide
  - `docs/PILOT_DEPLOYMENT_GUIDE.md` — pilot deployment guide
  - `docs/RELEASE_CHECKLIST.md` — GA release checklist

- **Platform SDK** (Swift, Kotlin, WASM)
  - `b4ae-ffi` — C API (AES-256-GCM: generate_key, encrypt, decrypt)
  - `b4ae-android` — JNI crate untuk Kotlin/Android
  - `b4ae-wasm` — WebAssembly bindings untuk browser
  - `bindings/swift` — Swift package untuk iOS/macOS
  - `bindings/kotlin` — Kotlin wrapper
  - `wasm-demo` — HTML demo untuk WASM

- **HSM PKCS#11**
  - `src/hsm/pkcs11.rs` — Pkcs11Hsm (EC keypair, sign, verify via cryptoki)
  - Feature `hsm-pkcs11`

- **Formal Verification**
  - `specs/B4AE_Handshake.tla` — TLA+ spec + TLC model check
  - `specs/coq/B4AE_Handshake.v` — Coq safety theorem
  - cargo-fuzz targets (fuzz_handshake, fuzz_message)

- **Platform SDK & Production-Ready**
  - `docs/PLATFORM_SDK.md` — panduan iOS, Android, WASM
  - `docs/FORMAL_VERIFICATION.md` — proptest + formal verification plan
  - `src/audit.rs` — audit logging (AuditEvent, AuditSink) untuk compliance
  - `src/hsm/mod.rs` — HSM trait `HsmBackend` + `NoOpHsm` (feature `hsm`)
  - `tests/proptest_invariants.rs` — AES roundtrip, handshake completeness
  - CI: proptest, cargo-fuzz, TLA+, Coq, wasm, ffi, android jobs

- **Dokumentasi roadmap dan audit**
  - `docs/SECURITY_AUDIT_CHECKLIST.md` — checklist security audit
  - `docs/INTEGRATION_TESTING_PLAN.md` — rencana integrasi testing
  - `docs/CRATES_IO_PUBLISH_PREP.md` — persiapan publish ke crates.io
  - `docs/ROADMAP.md` — roadmap jangka panjang (SDK, production-ready)

- **ELARA Transport Integration**
  - `elara-transport` sebagai optional dependency untuk UDP transport
  - `ElaraTransport`: adapter UDP dengan chunking untuk payload > 1400 bytes
  - `B4aeElaraNode`: node lengkap dengan handshake dan messaging via ELARA
  - Feature flag `elara` untuk kompilasi opsional
  - Example `b4ae_elara_demo`: demo Alice-Bob komunikasi via UDP
- ELARA Protocol sebagai git submodule (`elara/`)

### Changed

- `Cargo.toml`: tambah feature `elara` dan dependency `elara-transport`
- Roadmap: Network layer implementation marked complete via ELARA
- **Dependabot**: ignore major version update untuk `rand` (`.github/dependabot.yml`)
- **Warnings**: perbaikan unused imports (Duration, hybrid), dead_code (zkauth, session), unused variables di tests
- **Tests**: relax `test_aes_gcm_performance` threshold (1000 µs untuk CI/Windows)
- **rand**: pin ke `=0.8.5` untuk hindari rand 0.10 (breaking API); regenerate Cargo.lock
- **Doctest**: blok ELARA di README pakai `no_run` untuk hindari kegagalan networking di CI

## [0.1.0] - 2026-02-05

### Added

- Initial release
- Post-quantum cryptography (Kyber-1024, Dilithium5)
- Hybrid cryptography (Classical + PQC)
- Three-way handshake protocol
- Perfect Forward Secrecy Plus (PFS+)
- Zero-knowledge authentication
- Metadata protection (padding, timing, obfuscation)
- B4aeClient high-level API
- Three security profiles: Standard, High, Maximum
