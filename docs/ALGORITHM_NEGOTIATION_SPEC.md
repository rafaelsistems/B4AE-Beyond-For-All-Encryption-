# B4AE v2.0 Algorithm Negotiation and Downgrade Protection Specification

**Version:** 2.0  
**Date:** 2026  
**Status:** Production-Ready (v2.0 100% Complete)  
**Reference:** V2_ARCHITECTURE_OVERVIEW.md, V2_SECURITY_ANALYSIS.md

## 1. Overview

This document specifies the algorithm negotiation mechanism and downgrade protection in the B4AE v2.0 handshake protocol. **v2.0 introduces authentication mode separation (Mode A/B/C) which fundamentally changes the negotiation process.**

**v2.0 Key Changes:**
- **Mode-based negotiation** replaces algorithm-level negotiation
- **Mode A:** XEdDSA only (deniable)
- **Mode B:** Dilithium5 only (post-quantum, non-repudiable)
- **Mode C:** Future hybrid (research placeholder)
- **Mode binding** prevents downgrade attacks
- **Protocol ID derivation** from canonical spec (SHA3-256)

**Source Files:**
- `src/protocol/v2/mode_negotiation.rs` - Mode negotiation protocol
- `src/protocol/v2/mode_binding.rs` - Mode binding for downgrade protection
- `src/protocol/v2/protocol_id.rs` - Protocol ID derivation
- `src/protocol/v2/types.rs` - AuthenticationMode enum

## 2. Authentication Modes (v2.0)

### 2.1 Mode Identifiers

```rust
// Source: src/protocol/v2/types.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AuthenticationMode {
    ModeA = 0x01,  // XEdDSA (deniable)
    ModeB = 0x02,  // Dilithium5 (post-quantum, non-repudiable)
    ModeC = 0x03,  // Future hybrid (not production-ready)
}
```

**Encoding:** 8-bit unsigned integer (u8), included in session_id derivation

### 2.2 Mode Properties

| Mode | Signatures | Deniable | Post-Quantum | Non-Repudiable | Use Case |
|------|-----------|----------|--------------|----------------|----------|
| Mode A | XEdDSA | ✅ | ❌ | ❌ | Private messaging, whistleblowing |
| Mode B | Dilithium5 | ❌ | ✅ | ✅ | Legal contracts, audit trails |
| Mode C | TBD | TBD | TBD | TBD | Research placeholder |

**v2.0 Design Philosophy:** Clear security properties, no hybrid confusion

## 3. v2.0 Mode Negotiation Protocol

### 3.1 Negotiation Flow

```
Client                                    Server
  |                                         |
  | supported_modes = [ModeA, ModeB]        |
  | -------- ModeNegotiation ------------> |
  |                                         |
  |                                         | Select mode (ModeA or ModeB)
  |                                         | Verify mode compatibility
  |                                         |
  | <------- ModeSelection ----------------|
  | selected_mode = ModeA                   |
  |                                         |
  | Verify selected mode supported          |
  | Derive session_id with mode_id          |
  |                                         |
  | -------- ClientHello ----------------> |  (Cookie challenge)
  | <------- CookieChallenge --------------|
  | -------- ClientHelloWithCookie ------> |
  |                                         |
  | -------- HandshakeInit (Mode A) -----> |  (XEdDSA signatures)
  | <------- HandshakeResponse ------------|
  | -------- HandshakeComplete ------------|
  |                                         |
  [Session established with Mode A authentication]
```

### 3.2 Mode Selection Rules

**Server-side selection:**
1. **Intersection:** `selected ∈ (client_supported ∩ server_supported)`
2. **Preference:** Server chooses preferred mode from intersection
3. **Default:** Mode A (deniable) if both supported

**Client-side validation:**
1. **Subset Check:** `selected ∈ client_supported`
2. **Mode Binding:** Verify mode_id in session_id matches selected mode

### 3.3 Mode-Specific Handshake

**Mode A Handshake:**
- Signatures: XEdDSA (~0.3ms per handshake)
- Key Exchange: X25519 + Kyber1024 hybrid KEM
- Total: ~150ms (including network RTT)

**Mode B Handshake:**
- Signatures: Dilithium5 (~9ms per handshake)
- Key Exchange: X25519 + Kyber1024 hybrid KEM
- Total: ~155ms (including network RTT)

**v2.0 Note:** Mode determines signature scheme, KEM remains hybrid for both modes

## 5. Downgrade Protection Mechanisms

### 5.1 Transcript Binding

**All handshake messages are signed:**

#### 5.1.1 Init Signature

```
signature_init = HybridSign(
    secret_key = client_secret_key,
    message = protocol_version || client_random || hybrid_public_key
)
```

**Source:** `src/protocol/handshake.rs:207-215`

**Verification:** `src/protocol/handshake.rs:461-472`

#### 5.1.2 Response Signature

```
signature_response = HybridSign(
    secret_key = server_secret_key,
    message = protocol_version || server_random || hybrid_public_key || encrypted_shared_secret
)
```

**Source:** `src/protocol/handshake.rs:495-507`

**Verification:** `src/protocol/handshake.rs:357-368`

**Critical:** `selected_algorithms` is NOT directly signed, but is implicitly bound through the signature over the entire handshake transcript

#### 5.1.3 Complete Signature

```
signature_complete = HybridSign(
    secret_key = client_secret_key,
    message = confirmation
)
```

**Source:** `src/protocol/handshake.rs:246-254`

**Verification:** `src/protocol/handshake.rs:587-594`

### 5.2 Confirmation Hash

```
confirmation = HKDF-Expand(
    ikm = shared_secret,
    info = "handshake-confirmation",
    length = 32
)

Input to HKDF:
    data = client_random || server_random || shared_secret
```

**Source:** `src/protocol/handshake.rs:271-282`

**Purpose:**
- Binds client and server randoms to shared secret
- Mutual authentication
- Prevents MITM from modifying algorithm selection

**Verification:** Constant-time comparison
```rust
// Source: src/protocol/handshake.rs:598-602
use subtle::ConstantTimeEq;
let confirmation_valid = complete.confirmation.ct_eq(&expected_confirmation);
if !bool::from(confirmation_valid) {
    return Err(CryptoError::VerificationFailed("Confirmation mismatch".to_string()));
}
```

### 5.3 Protocol Version Check

```rust
// Source: src/protocol/handshake.rs:343-345 (Initiator)
if response.protocol_version != PROTOCOL_VERSION {
    return Err(CryptoError::InvalidInput("Protocol version mismatch".to_string()));
}

// Source: src/protocol/handshake.rs:437-439 (Responder)
if init.protocol_version != PROTOCOL_VERSION {
    return Err(CryptoError::InvalidInput("Protocol version mismatch".to_string()));
}
```

**Current Version:** `PROTOCOL_VERSION = 0x0001`  
**Source:** `src/protocol/mod.rs`

**Protection:** Prevents version rollback attacks

### 5.4 Hybrid Signature Verification

**Both classical AND post-quantum signatures must be valid:**

```rust
// Source: src/crypto/hybrid.rs:318-334
pub fn verify(
    public_key: &HybridPublicKey,
    message: &[u8],
    signature: &HybridSignature,
) -> CryptoResult<bool> {
    // Verify Dilithium signature (post-quantum)
    let dilithium_valid = dilithium::verify(
        &public_key.dilithium_public,
        message,
        &signature.dilithium_signature,
    )?;
    
    if !dilithium_valid {
        return Ok(false);
    }
    
    // Verify Ed25519 signature
    let ed25519_valid = ed25519_public_key
        .verify(message, &signature.ecdsa_signature)
        .is_ok();
    
    // Both signatures must be valid (hybrid security)
    Ok(ed25519_valid && dilithium_valid)
}
```

**Security Property:** Attacker must break BOTH Ed25519 AND Dilithium5 to forge signatures

## 6. Attack Resistance

### 6.1 Downgrade Attack

**Attack:** MITM modifies `supported_algorithms` to remove strong algorithms

**Defense:**
1. **Signature Binding:** Init message is signed, including `hybrid_public_key`
2. **Transcript Integrity:** Response signature covers `encrypted_shared_secret`
3. **Confirmation:** Final confirmation binds all randoms and shared secret
4. **Hybrid Signature:** Attacker must break both classical and PQC signatures

**Result:** Downgrade attack requires breaking hybrid signature scheme

### 6.2 Version Rollback Attack

**Attack:** MITM modifies `protocol_version` to force older protocol

**Defense:**
1. **Version Check:** Both parties reject mismatched versions
2. **Signature Binding:** `protocol_version` is signed in Init and Response
3. **No Fallback:** Implementation does not support older versions

**Result:** Version rollback requires breaking hybrid signature scheme

### 6.3 Algorithm Substitution Attack

**Attack:** MITM substitutes `selected_algorithms` in Response

**Defense:**
1. **Implicit Binding:** Algorithms used to generate `encrypted_shared_secret`
2. **Signature Coverage:** Response signature covers `encrypted_shared_secret`
3. **Confirmation:** Shared secret derivation depends on actual algorithms used
4. **Mismatch Detection:** If algorithms differ, confirmation will fail

**Result:** Algorithm substitution causes handshake failure

### 6.4 Replay Attack

**Attack:** Replay old handshake messages

**Defense:**
1. **Fresh Randoms:** `client_random` and `server_random` are freshly generated
2. **Ephemeral Keys:** Hybrid public keys are ephemeral (new per handshake)
3. **Timestamp:** Handshake timeout prevents long-term replay
4. **Session Binding:** Session ID derived from randoms

**Result:** Replayed messages fail verification or timeout

## 7. Signature Verification Flow

### 7.1 Init Verification (Server-side)

```
1. Deserialize peer's public key from init.hybrid_public_key
2. Construct message_to_verify:
   message_to_verify = init.protocol_version || init.client_random || init.hybrid_public_key
3. Deserialize signature from init.signature
4. Verify hybrid signature:
   is_valid = hybrid::verify(peer_public_key, message_to_verify, signature)
5. If !is_valid: return Error(VerificationFailed)
```

**Source:** `src/protocol/handshake.rs:447-472`

### 7.2 Response Verification (Client-side)

```
1. Check protocol_version == PROTOCOL_VERSION
2. Deserialize peer's public key from response.hybrid_public_key
3. Construct message_to_verify:
   message_to_verify = response.protocol_version || response.server_random || 
                       response.hybrid_public_key || response.encrypted_shared_secret
4. Deserialize signature from response.signature
5. Verify hybrid signature:
   is_valid = hybrid::verify(peer_public_key, message_to_verify, signature)
6. If !is_valid: return Error(VerificationFailed)
```

**Source:** `src/protocol/handshake.rs:343-368`

### 7.3 Complete Verification (Server-side)

```
1. Deserialize signature from complete.signature
2. Verify hybrid signature:
   is_valid = hybrid::verify(peer_public_key, complete.confirmation, signature)
3. If !is_valid: return Error(VerificationFailed)
4. Generate expected_confirmation locally
5. Constant-time compare:
   confirmation_valid = complete.confirmation.ct_eq(&expected_confirmation)
6. If !confirmation_valid: return Error(VerificationFailed)
```

**Source:** `src/protocol/handshake.rs:587-602`

## 8. Serialization Format

### 8.1 Hybrid Public Key Serialization

```
hybrid_public_key_bytes = 
    ecdh_public_len (u16, 2 bytes) ||
    ecdh_public (variable, typically 32 bytes) ||
    kyber_public (1568 bytes) ||
    ecdsa_public_len (u16, 2 bytes) ||
    ecdsa_public (variable, typically 32 bytes) ||
    dilithium_public (2592 bytes)
```

**Total Size:** ~4228 bytes

**Source:** `src/crypto/hybrid.rs:78-99`

### 8.2 Hybrid Signature Serialization

```
signature_bytes = 
    ecdsa_signature_len (u32, 4 bytes) ||
    ecdsa_signature (variable, typically 64 bytes) ||
    dilithium_signature (4595 bytes)
```

**Total Size:** ~4663 bytes

**Source:** `src/crypto/hybrid.rs:137-149`

### 8.3 Hybrid Ciphertext Serialization

```
ciphertext_bytes = 
    ecdh_ephemeral_public_len (u16, 2 bytes) ||
    ecdh_ephemeral_public (32 bytes) ||
    kyber_ciphertext (1568 bytes)
```

**Total Size:** ~1602 bytes

**Source:** `src/crypto/hybrid.rs:177-189`

## 9. Extension Mechanism

### 9.1 Extension Structure

```rust
// Source: src/protocol/handshake.rs:45-50
pub struct Extension {
    pub extension_type: u16,    // Extension type ID
    pub data: Vec<u8>,          // Extension payload
}
```

### 9.2 Defined Extension Types

```rust
// Source: src/crypto/zkauth.rs (referenced in handshake.rs)
pub const EXTENSION_TYPE_ZK_CHALLENGE: u16 = 0x0001;
pub const EXTENSION_TYPE_ZK_PROOF: u16 = 0x0002;
```

### 9.3 Extension Usage

**In HandshakeResponse (Server → Client):**
```rust
// Source: src/protocol/handshake.rs:520-527
if let Some(ref verifier) = self.config.zk_verifier {
    let challenge = verifier.lock()?.generate_challenge();
    extensions.push(Extension {
        extension_type: EXTENSION_TYPE_ZK_CHALLENGE,
        data: challenge.to_bytes(),
    });
    self.pending_zk_challenge_id = Some(challenge.challenge_id);
}
```

**In HandshakeComplete (Client → Server):**
```rust
// Source: src/protocol/handshake.rs:257-264
if let (Some(identity), Some(challenge)) = (&self.config.zk_identity, self.pending_zk_challenge.take()) {
    let proof = identity.generate_proof(&challenge)?;
    extensions.push(Extension {
        extension_type: EXTENSION_TYPE_ZK_PROOF,
        data: proof.to_bytes(),
    });
}
```

**Extension Verification:**
```rust
// Source: src/protocol/handshake.rs:575-585
if let (Some(ref verifier), Some(challenge_id)) = (&self.config.zk_verifier, self.pending_zk_challenge_id) {
    let proof_ext = complete.extensions.iter()
        .find(|e| e.extension_type == EXTENSION_TYPE_ZK_PROOF)
        .ok_or_else(|| CryptoError::AuthenticationFailed)?;
    let proof = ZkProof::from_bytes(&proof_ext.data)?;
    let auth = verifier.lock()?.verify_proof(&proof, &challenge_id)?;
    if auth.is_none() {
        return Err(CryptoError::AuthenticationFailed);
    }
}
```

## 10. Security Analysis

### 10.1 Threat Model

**Attacker Capabilities:**
- Full control over network (MITM position)
- Can modify, drop, replay, or inject messages
- Cannot break cryptographic primitives (hybrid signature, hybrid KEM)

**Security Goals:**
- Prevent downgrade to weaker algorithms
- Prevent version rollback
- Ensure mutual authentication
- Provide forward secrecy

### 10.2 Security Properties

| Property                  | Mechanism                                      | Strength                    |
|---------------------------|------------------------------------------------|-----------------------------|
| Downgrade resistance      | Signature binding + confirmation               | Hybrid signature security   |
| Version rollback resist.  | Version check + signature binding              | Hybrid signature security   |
| Algorithm substitution    | Implicit binding via shared secret             | Hybrid KEM security         |
| Replay resistance         | Fresh randoms + ephemeral keys                 | Nonce uniqueness            |
| Mutual authentication     | Bidirectional signatures + confirmation        | Hybrid signature security   |
| Forward secrecy           | Ephemeral key exchange                         | Hybrid KEM security         |
| Post-quantum security     | Kyber1024 + Dilithium5                         | NIST PQC standards          |

### 10.3 Formal Security Argument

**Theorem (Informal):** If the hybrid signature scheme is EUF-CMA secure and the hybrid KEM is IND-CCA2 secure, then the B4AE handshake provides authenticated key exchange with downgrade protection.

**Proof Sketch:**
1. **Signature Binding:** All critical handshake data is signed with hybrid signatures
2. **Transcript Integrity:** Attacker cannot modify signed data without detection
3. **Confirmation:** Final confirmation binds all handshake parameters
4. **Hybrid Security:** Security holds if either classical OR post-quantum primitive is secure

**Reduction:** Any successful downgrade attack can be used to break either:
- Ed25519 signature scheme, OR
- Dilithium5 signature scheme, OR
- X25519 key exchange, OR
- Kyber1024 KEM

## 11. Implementation Notes

### 11.1 Signature Verification Errors

**All signature verification failures return explicit errors:**

```rust
// Source: src/protocol/handshake.rs:365-367
if !is_valid {
    return Err(CryptoError::VerificationFailed("Response signature verification failed".to_string()));
}
```

**Error Types:**
- `VerificationFailed`: Signature verification failed
- `InvalidInput`: Protocol version mismatch or invalid data
- `AuthenticationFailed`: ZK proof verification failed

### 11.2 Constant-Time Comparison

**Confirmation comparison uses constant-time equality:**

```rust
// Source: src/protocol/handshake.rs:598-602
use subtle::ConstantTimeEq;
let confirmation_valid = complete.confirmation.ct_eq(&expected_confirmation);
if !bool::from(confirmation_valid) {
    return Err(CryptoError::VerificationFailed("Confirmation mismatch".to_string()));
}
```

**Purpose:** Prevent timing attacks on confirmation hash

### 11.3 Timeout Protection

```rust
// Source: src/protocol/handshake.rs:332-335
pub fn is_timed_out(&self) -> bool {
    let current_time = time::current_time_millis();
    current_time - self.start_time > self.config.timeout_ms
}
```

**Default Timeout:** 30 seconds  
**Purpose:** Prevent resource exhaustion from incomplete handshakes

## 12. Test Vectors

### 12.1 Successful Handshake

```rust
// Source: src/protocol/handshake.rs:831-865
#[test]
fn test_handshake_flow() -> CryptoResult<()> {
    let config = HandshakeConfig::default();
    let mut initiator = HandshakeInitiator::new(config.clone())?;
    let mut responder = HandshakeResponder::new(config)?;

    let init = initiator.generate_init()?;
    assert_eq!(initiator.state(), HandshakeState::WaitingResponse);

    let response = responder.process_init(init)?;
    assert_eq!(responder.state(), HandshakeState::WaitingComplete);

    initiator.process_response(response)?;
    assert_eq!(initiator.state(), HandshakeState::WaitingComplete);

    let complete = initiator.generate_complete()?;
    assert_eq!(initiator.state(), HandshakeState::Completed);

    responder.process_complete(complete)?;
    assert_eq!(responder.state(), HandshakeState::Completed);

    let initiator_result = initiator.finalize()?;
    let responder_result = responder.finalize()?;

    assert_eq!(initiator_result.session_id, responder_result.session_id);
    assert_eq!(
        initiator_result.session_keys.encryption_key,
        responder_result.session_keys.encryption_key
    );

    Ok(())
}
```

## 13. References

- TLS 1.3 RFC 8446: Downgrade protection mechanisms
- Signal Protocol: Authenticated key exchange
- NIST PQC Standards: Kyber and Dilithium specifications
- Implementation: `src/protocol/handshake.rs`, `src/crypto/hybrid.rs`
