# B4AE v0.1.0 - Initial Production Release

## Overview

B4AE (Beyond For All Encryption) is a quantum-resistant secure communication protocol that provides comprehensive protection against current and future threats, including quantum computing attacks.

## Features

### Cryptographic Implementation
- **Post-Quantum Key Exchange**: Kyber-1024 (NIST standardized)
- **Post-Quantum Signatures**: Dilithium5 (NIST standardized)
- **Classical Key Exchange**: X25519 (Curve25519)
- **Classical Signatures**: Ed25519
- **Symmetric Encryption**: AES-256-GCM
- **Key Derivation**: HKDF-SHA3-256
- **Hybrid Cryptography**: Combines classical and PQ algorithms for defense-in-depth

### Protocol Features
- Three-way handshake with mutual authentication
- Perfect Forward Secrecy Plus (PFS+) with key ratcheting
- Automatic key rotation (time-based, message-based, data-based)
- Zero-Knowledge Authentication support
- Constant-time operations for timing attack resistance

### Metadata Protection
- Traffic padding
- Timing obfuscation
- Dummy traffic generation

### High-Level API
- `B4aeClient` for simplified usage
- `prelude` module for convenient imports
- Three security profiles: Standard, High, Maximum

## Test Results

All **135 tests passing**:
- Library tests: 79 passed
- Fuzzing tests: 11 passed
- Integration tests: 4 passed
- Penetration tests: 10 passed
- Performance tests: 14 passed
- Security tests: 14 passed
- Doc-tests: 3 passed

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
b4ae = "0.1.0"
```

## Quick Start

```rust
use b4ae::{B4aeClient, SecurityProfile};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut alice = B4aeClient::new(SecurityProfile::Standard)?;
    let mut bob = B4aeClient::new(SecurityProfile::Standard)?;

    let alice_id = b"alice".to_vec();
    let bob_id = b"bob".to_vec();

    // Handshake
    let init = alice.initiate_handshake(&bob_id)?;
    let response = bob.respond_to_handshake(&alice_id, init)?;
    let complete = alice.process_response(&bob_id, response)?;
    bob.complete_handshake(&alice_id, complete)?;
    alice.finalize_initiator(&bob_id)?;

    // Secure messaging
    let encrypted = alice.encrypt_message(&bob_id, b"Hello, B4AE!")?;
    let decrypted = bob.decrypt_message(&alice_id, &encrypted)?;

    Ok(())
}
```

## Requirements

- Rust 1.70 or later
- Supported platforms: Windows, Linux, macOS

## License

Dual licensed under MIT and Apache-2.0.

## Links

- [Repository](https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-)
- [Documentation](https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-/blob/main/README.md)
- [Technical Architecture](https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-/blob/main/B4AE_Technical_Architecture.md)
