# B4AE v1.0.0 — Protocol Specification v1.0 Release

**Release Date:** 2026-02-13  
**Protocol Specification:** [B4AE Protocol Specification v1.0](specs/B4AE_Protocol_Specification_v1.0.md)

## Overview

B4AE v1.0.0 implements **Protocol Specification v1.0** end-to-end. All code, specs, and docs are aligned.

### Implementasi Sesuai Spec v1.0

- **Classical Crypto:** X25519 (key exchange), Ed25519 (signatures)
- **Post-Quantum:** Kyber-1024, Dilithium5 (4627-byte signature)
- **Key Derivation:** HKDF-SHA3-256, master_secret with salt, B4AE-v1-* info strings
- **Handshake:** Three-way handshake, state Initiation→WaitingResponse→WaitingComplete→Completed
- **Formal Verification:** TLA+ model check, Coq safety theorem

## Installation

```toml
[dependencies]
b4ae = "1.0"
```

## Quick Start

```rust
use b4ae::{B4aeClient, SecurityProfile};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut alice = B4aeClient::new(SecurityProfile::Standard)?;
    let mut bob = B4aeClient::new(SecurityProfile::Standard)?;
    let alice_id = b"alice".to_vec();
    let bob_id = b"bob".to_vec();

    let init = alice.initiate_handshake(&bob_id)?;
    let response = bob.respond_to_handshake(&alice_id, init)?;
    let complete = alice.process_response(&bob_id, response)?;
    bob.complete_handshake(&alice_id, complete)?;
    alice.finalize_initiator(&bob_id)?;

    let encrypted_list = alice.encrypt_message(&bob_id, b"Hello, B4AE!")?;
    let mut decrypted = vec![];
    for enc in &encrypted_list {
        let d = bob.decrypt_message(&alice_id, enc)?;
        if !d.is_empty() { decrypted = d; }
    }
    Ok(())
}
```

## What's New Since v0.1.0

- Protocol Specification v1.0 implemented and documented
- Master secret derivation per spec (HKDF with salt)
- HKDF info strings aligned (B4AE-v1-encryption-key, etc.)
- Handshake state `Initiation` (was `Initial`)
- Specs: X25519/Ed25519, key sizes
- Key hierarchy (MIK, DMK, STK, BKS, export/import) implemented
- Metadata protection full: padding, timing, dummy, metadata_key MAC
- ZKAuth integrated in handshake
- All docs reference Protocol Spec v1.0

## Links

- [Protocol Specification v1.0](specs/B4AE_Protocol_Specification_v1.0.md)
- [API Design v1.0](specs/B4AE_API_Design_v1.0.md)
- [Audit Report](docs/AUDIT_IMPLEMENTATION_MISMATCHES.md)
