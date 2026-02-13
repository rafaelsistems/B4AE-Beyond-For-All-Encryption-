# Changelog

All notable changes to B4AE will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Platform SDK & Production-Ready**
  - `docs/PLATFORM_SDK.md` — panduan iOS, Android, WASM
  - `docs/FORMAL_VERIFICATION.md` — proptest + formal verification plan
  - `src/audit.rs` — audit logging (AuditEvent, AuditSink) untuk compliance
  - `src/hsm.rs` — HSM trait `HsmBackend` + `NoOpHsm` (feature `hsm`)
  - `tests/proptest_invariants.rs` — AES roundtrip, handshake completeness
  - CI: job Proptest Invariants

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
