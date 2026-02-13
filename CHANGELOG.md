# Changelog

All notable changes to B4AE will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
