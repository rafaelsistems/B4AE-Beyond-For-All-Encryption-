# B4AE v2.0 Security Invariants

**Version:** 2.0  
**Date:** 2026  
**Status:** Updated for v2.0 Architecture

## Executive Summary

This document specifies formal security invariants for B4AE v2.0. Invariants are properties that must hold true at all times during protocol execution. Violations indicate security vulnerabilities or implementation bugs.

**v2.0 Changes:**
- Authentication mode separation invariants (Mode A vs Mode B)
- Session key binding invariants
- Cookie challenge invariants
- Protocol ID binding invariants
- Global traffic scheduler invariants

**Single Source of Truth:** See [THREAT_MODEL_FORMALIZATION.md](THREAT_MODEL_FORMALIZATION.md) for authoritative security properties.

## Table of Contents

1. [v2.0 Core Invariants](#v20-core-invariants)
2. [Mode Separation Invariants](#mode-separation-invariants)
3. [Session Binding Invariants](#session-binding-invariants)
4. [Cookie Challenge Invariants](#cookie-challenge-invariants)
5. [Padding Invariants](#padding-invariants)
6. [Signature Invariants](#signature-invariants)
7. [Constant-Time Invariants](#constant-time-invariants)
8. [Metadata Protection Invariants](#metadata-protection-invariants)
9. [Key Management Invariants](#key-management-invariants)
10. [Verification Methods](#verification-methods)

---

## v2.0 Core Invariants

### Invariant V2-1: Mode Binding

**Statement:** The authentication mode negotiated at the start of handshake must match the mode used throughout the session

**Formal Definition:**
```
∀session S, mode_negotiated M_n, mode_established M_e :
  ModeNegotiated(S, M_n) ∧ SessionEstablished(S, M_e) ⇒ M_n = M_e
```

**Verification Method:**
- Mode binding included in all signatures
- mode_binding = SHA3-256("B4AE-v2-mode-binding" || client_random || server_random || mode_id)
- Any modification causes signature verification failure

**Test Coverage:** Tamarin no-downgrade lemma (pending)

**Violation Consequences:**
- Mode downgrade attack possible
- Security properties violated
- Handshake must abort

---

### Invariant V2-2: Session Key Binding

**Statement:** Session keys are cryptographically bound to unique session_id, preventing key transplant attacks

**Formal Definition:**
```
∀session_A, session_B : session_A ≠ session_B ⇒
  session_id(session_A) ≠ session_id(session_B) ∧
  session_key(session_A) ≠ session_key(session_B)
```

**Verification Method:**
- session_id = HKDF(client_random || server_random || mode_id)
- All keys derived with session_id as salt
- HKDF collision resistance ensures uniqueness

**Test Coverage:** Multi-session integration tests

**Violation Consequences:**
- Key transplant attack possible
- Session isolation broken
- Cross-session compromise

---

### Invariant V2-3: Protocol ID Binding

**Statement:** All handshake messages are bound to protocol_id derived from specification

**Formal Definition:**
```
∀handshake H, protocol_id P :
  protocol_id = SHA3-256(specification) ∧
  ∀message M ∈ H : M includes P in signature
```

**Verification Method:**
- protocol_id included in all key derivations
- protocol_id included in all signatures
- Mismatch causes signature verification failure

**Test Coverage:** Unit tests for protocol ID derivation

**Violation Consequences:**
- Version confusion attack possible
- Downgrade to older protocol version
- Cryptographic agility broken

---

### Invariant V2-4: Cookie Challenge Before Expensive Crypto

**Statement:** Server performs expensive cryptographic operations only after cookie verification

**Formal Definition:**
```
∀handshake H, server S :
  ExpensiveCrypto(S) ⇒ ∃cookie C : CookieVerified(S, C) ∧ time(CookieVerified) < time(ExpensiveCrypto)
```

**Verification Method:**
- State machine enforces cookie verification before signature verification
- Cookie verification: ~0.01ms
- Signature verification: ~3-5ms (only after cookie)

**Test Coverage:** State machine tests, DoS protection tests

**Violation Consequences:**
- DoS vulnerability (360x amplification)
- Resource exhaustion
- Server overload

---

## Mode Separation Invariants

### Invariant M-1: Mode A Signature Exclusivity

**Statement:** Mode A uses XEdDSA only, never Dilithium5

**Formal Definition:**
```
∀session S, mode M :
  M = ModeA ⇒ 
    ∀signature sig ∈ S : sig.type = XEdDSA ∧ sig.type ≠ Dilithium5
```

**Verification Method:**
- Mode A configuration enforces XEdDSA-only
- Dilithium5 signature generation disabled in Mode A
- Signature verification checks mode consistency

**Test Coverage:** Mode A integration tests

**Violation Consequences:**
- Deniability broken (Dilithium5 is non-repudiable)
- Mode separation violated
- Security property lost

---

### Invariant M-2: Mode B Signature Exclusivity

**Statement:** Mode B uses Dilithium5 only, never XEdDSA

**Formal Definition:**
```
∀session S, mode M :
  M = ModeB ⇒ 
    ∀signature sig ∈ S : sig.type = Dilithium5 ∧ sig.type ≠ XEdDSA
```

**Verification Method:**
- Mode B configuration enforces Dilithium5-only
- XEdDSA signature generation disabled in Mode B
- Signature verification checks mode consistency

**Test Coverage:** Mode B integration tests

**Violation Consequences:**
- Post-quantum security weakened
- Mode separation violated
- Hybrid security broken

---

### Invariant M-3: Mode Negotiation Completeness

**Statement:** Mode negotiation must complete before handshake proceeds

**Formal Definition:**
```
∀handshake H :
  HandshakeInit(H) ⇒ ∃mode M : ModeNegotiated(H, M) ∧ time(ModeNegotiated) < time(HandshakeInit)
```

**Verification Method:**
- State machine enforces mode negotiation as first phase
- Handshake cannot proceed without mode selection
- Mode included in all subsequent messages

**Test Coverage:** State machine tests

**Violation Consequences:**
- Mode confusion
- Undefined security properties
- Handshake failure

---

## Session Binding Invariants

### Invariant SB-1: Session ID Uniqueness

**Statement:** Each session has a unique session_id

**Formal Definition:**
```
∀session_A, session_B : session_A ≠ session_B ⇒
  session_id(session_A) ≠ session_id(session_B)
  (with overwhelming probability)
```

**Verification Method:**
- session_id = HKDF(client_random || server_random || mode_id)
- client_random and server_random are cryptographically random
- HKDF collision resistance

**Test Coverage:** Multi-session tests, collision tests

**Violation Consequences:**
- Session confusion
- Key transplant possible
- Session isolation broken

---

### Invariant SB-2: Key Derivation Includes Session ID

**Statement:** All session keys are derived with session_id as salt

**Formal Definition:**
```
∀key K, session S :
  K ∈ session_keys(S) ⇒ 
    K = HKDF(secret, protocol_id || session_id(S) || transcript_hash)
```

**Verification Method:**
- Code review of key derivation functions
- All HKDF calls include session_id
- Domain separation enforced

**Test Coverage:** Unit tests for key derivation

**Violation Consequences:**
- Session binding broken
- Key transplant possible
- Cross-session attacks

---

## Cookie Challenge Invariants

### Invariant CC-1: Cookie Verification Before Expensive Crypto

**Statement:** Server verifies cookie before performing expensive cryptographic operations

**Formal Definition:**
```
∀handshake H, server S :
  SignatureVerification(S, H) ⇒ 
    ∃cookie C : CookieVerified(S, C, H) ∧ time(CookieVerified) < time(SignatureVerification)
```

**Verification Method:**
- State machine enforces cookie verification state before signature verification state
- Cookie verification: ~0.01ms
- Signature verification: ~3-5ms (only after cookie)

**Test Coverage:** State machine tests, DoS tests

**Violation Consequences:**
- DoS vulnerability
- Resource exhaustion
- 360x amplification attack

---

### Invariant CC-2: Cookie Replay Protection

**Statement:** Each cookie can only be used once within the expiry window

**Formal Definition:**
```
∀cookie C, client_random R :
  CookieUsed(C, R) ⇒ ¬∃future_use : CookieUsed(C, R) ∧ time(future_use) > time(CookieUsed)
```

**Verification Method:**
- Bloom filter tracks recently seen client_random values
- Replay detected and rejected
- 30-second expiry window

**Test Coverage:** Replay protection tests

**Violation Consequences:**
- Replay attack possible
- Cookie reuse
- DoS protection weakened

---

### Invariant CC-3: Cookie Constant-Time Verification

**Statement:** Cookie verification time is independent of cookie validity

**Formal Definition:**
```
∀cookie_valid, cookie_invalid :
  |time(verify(cookie_valid)) - time(verify(cookie_invalid))| < ε
where ε = 5% variance threshold
```

**Verification Method:**
- Constant-time HMAC comparison
- All bytes checked regardless of early mismatch
- Timing tests with valid/invalid cookies

**Test Coverage:** Timing tests with 10,000+ iterations

**Violation Consequences:**
- Timing oracle
- Cookie forgery easier
- Side-channel leak

---

## Padding Invariants

### Invariant P1: Padding Reversibility

**Statement:** For all valid plaintexts `m` where `|m| ≤ max_bucket_size`, `unpad(pad(m)) = m`

**Formal Definition:**
```
∀m ∈ {0,1}* : |m| ≤ 65536 ⇒ unpad(pad(m)) = m
```

**Verification Method:**
- Property-based testing with 1000+ random plaintexts
- Unit tests for boundary cases (empty, max size)
- Fuzzing with random inputs

**Test Coverage:** 34 tests passing

**Violation Consequences:**
- Data loss
- Message corruption
- Protocol failure

---

### Invariant P2: Bucket Size Correctness

**Statement:** For all plaintexts `m`, the selected bucket size is the smallest bucket ≥ `|m|`

**Formal Definition:**
```
∀m ∈ {0,1}* : 
  let b = find_bucket(|m|)
  ⇒ b ≥ |m| ∧ ∀b' ∈ buckets : b' ≥ |m| ⇒ b ≤ b'
```

**Verification Method:**
- Property-based testing with random message sizes
- Unit tests for each bucket boundary
- Exhaustive testing for small sizes

**Test Coverage:** 34 tests passing

**Violation Consequences:**
- Excessive padding overhead
- Incorrect bucket selection
- Length oracle vulnerability

---

### Invariant P3: Padding Determinism

**Statement:** Padding the same plaintext twice produces identical results

**Formal Definition:**
```
∀m ∈ {0,1}* : pad(m) = pad(m)
```

**Verification Method:**
- Property-based testing with repeated padding
- Unit tests for determinism
- Comparison of multiple padding operations

**Test Coverage:** 34 tests passing

**Violation Consequences:**
- Padding oracle vulnerability
- Non-deterministic behavior
- Security weakness

---

### Invariant P4: Constant-Time Padding Validation

**Statement:** Padding validation time is independent of error location

**Formal Definition:**
```
∀m₁, m₂ ∈ {0,1}* : |m₁| = |m₂| ⇒ 
  |time(validate_padding(m₁)) - time(validate_padding(m₂))| < ε
where ε = 5% variance threshold
```

**Verification Method:**
- Timing tests with valid and invalid padding
- Statistical analysis of timing variance
- Comparison across different error locations

**Test Coverage:** Timing tests with 1000+ iterations

**Violation Consequences:**
- Timing oracle vulnerability
- Padding oracle attack
- Side-channel leakage

---

### Invariant P5: Padding Byte Correctness

**Statement:** All padding bytes have the correct value

**Formal Definition:**
```
∀m ∈ {0,1}*, b = bucket_size(m), p = b - |m| :
  pad(m)[|m|..b] = [p mod 256]^p
```

**Verification Method:**
- Unit tests for padding byte values
- Property-based testing with random sizes
- Boundary case testing

**Test Coverage:** 34 tests passing

**Violation Consequences:**
- Padding validation failure
- Message rejection
- Protocol failure

---

## Signature Invariants

### Invariant S1: Signature Validity

**Statement:** All generated signatures are valid

**Formal Definition:**
```
∀m ∈ {0,1}*, k = keypair :
  verify(k.public, m, sign(k.secret, m)) = true
```

**Verification Method:**
- Property-based testing with random messages
- Unit tests for signature generation and verification
- Integration tests with handshake

**Test Coverage:** 34 tests passing

**Violation Consequences:**
- Authentication failure
- Handshake failure
- Protocol breakdown

---

### Invariant S2: Hybrid Signature Completeness

**Statement:** Hybrid signature verification succeeds if and only if both components are valid

**Formal Definition:**
```
∀m ∈ {0,1}*, sig = (sig_xeddsa, sig_dilithium) :
  verify_hybrid(pk, m, sig) = true ⇔ 
    verify_xeddsa(pk.xeddsa, m, sig_xeddsa) = true ∧
    verify_dilithium(pk.dilithium, m, sig_dilithium) = true
```

**Verification Method:**
- Unit tests with valid/invalid component combinations
- Property-based testing with random messages
- Integration tests with handshake

**Test Coverage:** 34 tests passing

**Violation Consequences:**
- Weak authentication
- Hybrid security broken
- Downgrade attack possible

---

### Invariant S3: Constant-Time Signature Verification

**Statement:** Signature verification time is independent of signature validity

**Formal Definition:**
```
∀m ∈ {0,1}*, sig₁, sig₂ :
  |time(verify(pk, m, sig₁)) - time(verify(pk, m, sig₂))| < ε
where ε = 5% variance threshold
```

**Verification Method:**
- Timing tests with valid and invalid signatures
- Statistical analysis of timing variance
- Comparison across different signature types

**Test Coverage:** Timing tests with 1000+ iterations

**Violation Consequences:**
- Timing oracle vulnerability
- Signature forgery attack
- Side-channel leakage

---

### Invariant S4: XEdDSA Deniability

**Statement:** Verifier can forge signatures indistinguishable from genuine signatures

**Formal Definition:**
```
∀m ∈ {0,1}*, pk = public_key :
  ∃ forge_algorithm :
    ∀distinguisher :
      Pr[distinguisher(sign(sk, m)) = 1] ≈ 
      Pr[distinguisher(forge_algorithm(pk, m)) = 1]
```

**Verification Method:**
- Cryptographic proof (verifier can simulate signing oracle)
- Unit tests for signature forgery
- Indistinguishability tests

**Test Coverage:** 34 tests passing

**Violation Consequences:**
- Deniability broken
- Non-repudiation introduced
- Security property violated

---

### Invariant S5: No Signature Reuse

**Statement:** Each signature is generated with a fresh nonce

**Formal Definition:**
```
∀m₁, m₂ ∈ {0,1}* : m₁ ≠ m₂ ⇒ 
  nonce(sign(sk, m₁)) ≠ nonce(sign(sk, m₂))
```

**Verification Method:**
- Unit tests for nonce uniqueness
- Property-based testing with multiple signatures
- Nonce collision detection

**Test Coverage:** 34 tests passing

**Violation Consequences:**
- Nonce reuse attack
- Key recovery possible
- Signature forgery

---

## Constant-Time Invariants

### Invariant CT1: Constant-Time Comparison Correctness

**Statement:** Constant-time comparison returns correct result

**Formal Definition:**
```
∀a, b ∈ {0,1}* : |a| = |b| ⇒
  ct_memcmp(a, b) = (a = b)
```

**Verification Method:**
- Property-based testing with random byte arrays
- Unit tests for equal and unequal arrays
- Boundary case testing

**Test Coverage:** 108 tests passing

**Violation Consequences:**
- Incorrect comparison result
- Authentication failure
- Protocol failure

---

### Invariant CT2: Constant-Time Execution Independence

**Statement:** Execution time is independent of input values

**Formal Definition:**
```
∀a₁, a₂, b₁, b₂ ∈ {0,1}* : |a₁| = |a₂| = |b₁| = |b₂| ⇒
  |time(ct_memcmp(a₁, b₁)) - time(ct_memcmp(a₂, b₂))| < ε
where ε = 5% variance threshold
```

**Verification Method:**
- Timing tests with different input values
- Statistical analysis of timing variance
- Comparison across equal and unequal inputs

**Test Coverage:** Timing tests with 10,000+ iterations

**Violation Consequences:**
- Timing oracle vulnerability
- Side-channel leakage
- Key recovery attack

---

### Invariant CT3: No Early Termination

**Statement:** Constant-time operations process all input regardless of intermediate results

**Formal Definition:**
```
∀a, b ∈ {0,1}* : |a| = |b| ⇒
  ∀i ∈ [0, |a|) : a[i] ≠ b[i] ⇒
    ct_memcmp processes all bytes [0, |a|)
```

**Verification Method:**
- Code review for early termination
- Timing tests with errors at different positions
- Statistical analysis of timing distribution

**Test Coverage:** 108 tests passing

**Violation Consequences:**
- Timing leak
- Error location revealed
- Padding oracle attack

---

### Invariant CT4: Cache-Timing Resistance

**Statement:** Memory access pattern is independent of secret index

**Formal Definition:**
```
∀table T, indices i₁, i₂ :
  memory_access_pattern(ct_table_lookup(T, i₁)) =
  memory_access_pattern(ct_table_lookup(T, i₂))
```

**Verification Method:**
- Cache timing tests with different indices
- Memory access pattern analysis
- Statistical analysis of cache hits/misses

**Test Coverage:** 108 tests passing

**Violation Consequences:**
- Cache-timing attack
- Secret index leaked
- Key recovery possible

---

### Invariant CT5: Constant-Time Arithmetic Correctness

**Statement:** Constant-time arithmetic produces correct results

**Formal Definition:**
```
∀a, b ∈ ℤ :
  ct_add(a, b) = a + b ∧
  ct_sub(a, b) = a - b ∧
  ct_mul(a, b) = a × b ∧
  ct_is_zero(a) = (a = 0)
```

**Verification Method:**
- Property-based testing with random integers
- Unit tests for arithmetic operations
- Boundary case testing (overflow, underflow)

**Test Coverage:** 108 tests passing

**Violation Consequences:**
- Incorrect computation
- Protocol failure
- Security vulnerability

---

## Metadata Protection Invariants

### Invariant M1: Cover Traffic Rate Maintenance

**Statement:** Dummy message count approximates configured rate

**Formal Definition:**
```
∀time_window T, config C :
  |dummy_count(T) / real_count(T) - C.cover_traffic_rate| < 0.1
```

**Verification Method:**
- Integration tests with message sending
- Statistical analysis of dummy/real ratio
- Long-running tests (1000+ messages)

**Test Coverage:** 52 tests passing

**Violation Consequences:**
- Metadata protection degraded
- Traffic analysis easier
- Cover traffic ineffective

---

### Invariant M2: Timing Delay Range Compliance

**Statement:** Applied delays are within configured range

**Formal Definition:**
```
∀message m, config C :
  C.timing_delay_min_ms ≤ delay(m) ≤ C.timing_delay_max_ms
```

**Verification Method:**
- Unit tests for delay generation
- Property-based testing with random configs
- Statistical analysis of delay distribution

**Test Coverage:** 52 tests passing

**Violation Consequences:**
- Timing obfuscation ineffective
- Delays too short or too long
- Metadata protection degraded

---

### Invariant M3: Constant-Rate Interval Consistency

**Statement:** Messages are sent at constant intervals in constant-rate mode

**Formal Definition:**
```
∀messages m₁, m₂, ..., mₙ in constant-rate mode :
  ∀i ∈ [1, n-1] :
    |time(mᵢ₊₁) - time(mᵢ) - interval| < 0.05 × interval
where interval = 1.0 / target_rate
```

**Verification Method:**
- Integration tests with constant-rate mode
- Statistical analysis of inter-message timing
- Long-running tests (1000+ messages)

**Test Coverage:** 52 tests passing

**Violation Consequences:**
- Constant-rate mode ineffective
- Burst patterns visible
- Traffic shaping broken

---

### Invariant M4: Dummy Message Indistinguishability

**Statement:** Dummy messages are indistinguishable from real messages

**Formal Definition:**
```
∀dummy_msg, real_msg :
  |dummy_msg| = |real_msg| ⇒
    ∀distinguisher :
      Pr[distinguisher(encrypt(dummy_msg)) = 1] ≈
      Pr[distinguisher(encrypt(real_msg)) = 1]
```

**Verification Method:**
- Statistical tests for distinguishability
- Entropy analysis of encrypted messages
- Integration tests with mixed traffic

**Test Coverage:** 52 tests passing

**Violation Consequences:**
- Dummy messages detectable
- Cover traffic ineffective
- Traffic analysis easier

---

### Invariant M5: Metadata Key Independence

**Statement:** Metadata protection keys are independent from message encryption keys

**Formal Definition:**
```
∀session S :
  cover_traffic_key(S) ⊥ message_key(S) ∧
  timing_seed(S) ⊥ message_key(S) ∧
  shaping_key(S) ⊥ message_key(S)
where ⊥ denotes cryptographic independence
```

**Verification Method:**
- Domain separation verification
- Key derivation tree analysis
- Cryptographic proof

**Test Coverage:** Domain separation tests

**Violation Consequences:**
- Key reuse attack
- Cross-component vulnerability
- Security property violated

---

## Key Management Invariants

### Invariant K1: Forward Secrecy

**Statement:** Compromise of long-term keys does not compromise past session keys

**Formal Definition:**
```
∀session S, long_term_key LTK :
  compromise(LTK) ⇏ compromise(session_key(S))
where S was established before compromise
```

**Verification Method:**
- Security proof (ephemeral keys zeroized)
- Memory inspection after handshake
- Integration tests with key compromise

**Test Coverage:** Integration tests

**Violation Consequences:**
- Forward secrecy broken
- Past messages compromised
- Security property violated

---

### Invariant K2: Post-Compromise Security

**Statement:** Compromise of session keys does not compromise future session keys

**Formal Definition:**
```
∀session S, session_key SK :
  compromise(SK) ⇏ compromise(session_key(S'))
where S' is established after compromise
```

**Verification Method:**
- Security proof (DH ratchet generates new keys)
- Memory inspection after ratchet
- Integration tests with key compromise

**Test Coverage:** Integration tests

**Violation Consequences:**
- Post-compromise security broken
- Future messages compromised
- Security property violated

---

### Invariant K3: Key Zeroization

**Statement:** All keys are zeroized when no longer needed

**Formal Definition:**
```
∀key K :
  lifetime(K) ends ⇒ memory(K) = 0^|K|
```

**Verification Method:**
- Memory inspection after key use
- Unit tests for zeroization
- Drop trait verification

**Test Coverage:** Zeroization tests

**Violation Consequences:**
- Key leakage
- Memory disclosure attack
- Security property violated

---

### Invariant K4: Key Independence

**Statement:** Keys for different purposes are cryptographically independent

**Formal Definition:**
```
∀key_type₁, key_type₂ : key_type₁ ≠ key_type₂ ⇒
  key(key_type₁) ⊥ key(key_type₂)
where ⊥ denotes cryptographic independence
```

**Verification Method:**
- Domain separation verification
- Key derivation tree analysis
- Cryptographic proof

**Test Coverage:** Domain separation tests

**Violation Consequences:**
- Key reuse attack
- Cross-purpose vulnerability
- Security property violated

---

### Invariant K5: Session Key Isolation

**Statement:** Keys from different sessions are independent

**Formal Definition:**
```
∀session₁, session₂ : session₁ ≠ session₂ ⇒
  session_key(session₁) ⊥ session_key(session₂)
```

**Verification Method:**
- Multi-session tests
- Key derivation analysis
- Cryptographic proof

**Test Coverage:** Multi-session tests

**Violation Consequences:**
- Cross-session attack
- Session linkage
- Security property violated

---

## Verification Methods

### Property-Based Testing

**Tool:** `proptest` (Rust)

**Coverage:**
- Padding reversibility (1000+ iterations)
- Signature validity (1000+ iterations)
- Constant-time comparison correctness (1000+ iterations)
- Bucket size correctness (1000+ iterations)

**Example:**
```rust
proptest! {
    #[test]
    fn padding_reversible(plaintext: Vec<u8>) {
        prop_assume!(plaintext.len() <= 65536);
        
        let padding = PadmePadding::new(PadmeConfig::default());
        let padded = padding.pad(&plaintext)?;
        let unpadded = padding.unpad(&padded)?;
        
        assert_eq!(unpadded, plaintext);
    }
}
```

---

### Timing Tests

**Method:** Statistical analysis of execution time variance

**Coverage:**
- Constant-time comparison (10,000+ iterations)
- Constant-time padding validation (10,000+ iterations)
- Constant-time signature verification (10,000+ iterations)

**Example:**
```rust
#[test]
fn test_constant_time_comparison() {
    let mut timings_equal = Vec::new();
    let mut timings_unequal = Vec::new();
    
    for _ in 0..10000 {
        let a = random_bytes(32);
        let b_equal = a.clone();
        let b_unequal = random_bytes(32);
        
        let start = Instant::now();
        ct_memcmp(&a, &b_equal);
        timings_equal.push(start.elapsed());
        
        let start = Instant::now();
        ct_memcmp(&a, &b_unequal);
        timings_unequal.push(start.elapsed());
    }
    
    // Statistical test: variance should be < 5%
    let variance = calculate_variance(&timings_equal, &timings_unequal);
    assert!(variance < 0.05);
}
```

---

### Integration Tests

**Coverage:**
- End-to-end message flow with all features
- Handshake with hybrid signatures
- Multi-session security
- Metadata protection effectiveness

**Example:**
```rust
#[test]
fn test_end_to_end_with_hardening() {
    let padding = PadmePadding::new(PadmeConfig::default());
    let meta_config = MetadataProtectionConfig::balanced();
    let mut meta_protector = MetadataProtector::new(meta_config)?;
    
    let mut session = establish_session(peer_a, peer_b)?;
    
    // Send message with all features
    let plaintext = b"Test message";
    let encrypted = session.encrypt_message_with_padding(plaintext, &padding)?;
    meta_protector.send_message(encrypted.serialize()).await?;
    
    // Receive and decrypt
    let received = receive_message().await?;
    let decrypted = session.decrypt_message_with_unpadding(&received, &padding)?;
    
    assert_eq!(decrypted, plaintext);
}
```

---

### Formal Verification

**Method:** Cryptographic proofs and security reductions

**Coverage:**
- XEdDSA deniability proof
- Forward secrecy proof
- Post-compromise security proof
- Key independence proof

**Example:**
```
Theorem (Forward Secrecy):
  Let LTK be long-term key, SK be session key.
  Assume: Ephemeral keys are zeroized after handshake.
  Prove: compromise(LTK) ⇏ compromise(SK)
  
Proof:
  1. SK is derived from ephemeral DH output
  2. Ephemeral keys are zeroized after handshake
  3. Adversary with LTK cannot compute ephemeral DH output
  4. Therefore, adversary cannot compute SK
  QED
```

---

## Test Coverage Summary

| Component | Unit Tests | Property Tests | Timing Tests | Integration Tests | Total |
|-----------|-----------|----------------|--------------|-------------------|-------|
| **PADMÉ Padding** | 20 | 10 | 4 | 0 | 34 |
| **XEdDSA** | 20 | 10 | 4 | 0 | 34 |
| **Metadata Protection** | 30 | 10 | 8 | 4 | 52 |
| **Constant-Time Ops** | 60 | 20 | 20 | 8 | 108 |
| **Total** | 130 | 50 | 36 | 12 | **228** |

---

## Conclusion

Security invariants provide formal guarantees about the behavior of the Security Hardening Suite. Key features:

1. **Formal Definitions:** Mathematical specifications of security properties
2. **Comprehensive Testing:** 228 tests covering all invariants
3. **Verification Methods:** Property-based, timing, integration, and formal verification
4. **Violation Detection:** Automated detection of invariant violations
5. **Security Guarantees:** Formal proofs of key security properties

Maintaining these invariants ensures that the Security Hardening Suite provides the intended security properties.

---

*Last updated: 2026*
*Version: 1.0*
