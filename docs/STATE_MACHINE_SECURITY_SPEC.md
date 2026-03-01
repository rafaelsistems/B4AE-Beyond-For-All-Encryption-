# B4AE v2.0 State Machine Security Specification

**Version:** 2.0  
**Date:** 2026  
**Status:** Updated for v2.0 Architecture

## Executive Summary

This document specifies the state machine for the B4AE v2.0 protocol, focusing on the 5-phase handshake with mode separation, cookie challenge, session binding, and security invariants per state.

**v2.0 Changes:**
- 5-phase handshake (vs v1.0 3-phase): INIT → MODE_NEGOTIATION → COOKIE_CHALLENGE → HANDSHAKE → ESTABLISHED
- Mode-specific authentication (Mode A deniable, Mode B PQ)
- Stateless cookie challenge for DoS protection
- Session key binding to prevent key transplant
- Protocol ID binding for cryptographic agility

**Single Source of Truth:** See [STATE_MACHINE_SPECIFICATION.md](STATE_MACHINE_SPECIFICATION.md) for complete v2.0 state machine details.

## Table of Contents

1. [v2.0 Handshake State Machine](#v20-handshake-state-machine)
2. [Mode Negotiation States](#mode-negotiation-states)
3. [Cookie Challenge States](#cookie-challenge-states)
4. [Session State Machine](#session-state-machine)
5. [Security Invariants](#security-invariants)
6. [Error Handling States](#error-handling-states)

---

## v2.0 Handshake State Machine

### Overview

The v2.0 handshake establishes a secure session using:
- **Mode negotiation:** Select Mode A (deniable) or Mode B (PQ)
- **Cookie challenge:** DoS protection before expensive crypto
- **Hybrid key exchange:** X25519 + Kyber1024
- **Mode-specific authentication:** XEdDSA (Mode A) or Dilithium5 (Mode B)
- **Session binding:** Keys bound to unique session_id

### 5-Phase State Diagram

```
Phase 1: INIT
  ↓
Phase 2: MODE_NEGOTIATION
  ↓ (mode selected and bound)
Phase 3: COOKIE_CHALLENGE
  ↓ (cookie verified, DoS protection)
Phase 4: HANDSHAKE
  ↓ (mode-specific authentication)
Phase 5: ESTABLISHED
  ↓ (session keys bound to session_id)
```

### Comparison with v1.0

| Aspect | v1.0 (3-phase) | v2.0 (5-phase) |
|--------|----------------|----------------|
| Phases | INIT → HANDSHAKE → ESTABLISHED | INIT → MODE_NEG → COOKIE → HANDSHAKE → ESTABLISHED |
| Authentication | Hybrid (XEdDSA + Dilithium5) always | Mode A (XEdDSA) or Mode B (Dilithium5) |
| DoS Protection | None | Cookie challenge (~0.01ms) |
| Session Binding | Weak | Strong (session_id in all keys) |
| Mode Downgrade | Possible | Prevented (mode binding) |
| Performance | ~9.4ms handshake | Mode A: ~0.45ms, Mode B: ~9.15ms |

---

## Mode Negotiation States

### State: ModeNegotiationInit

**Description:** Client initiates mode negotiation

**Entry Actions:**
1. Prepare list of supported modes (Mode A, Mode B)
2. Indicate preferred mode
3. Generate client_random (32 bytes)
4. Send ModeNegotiation message

**Invariants:**
- At least one mode supported
- client_random is cryptographically random
- Preferred mode is in supported list

**Transitions:**
- `send ModeNegotiation` → ModeNegotiationWait

**Security Properties:**
- Mode preferences expressed clearly
- client_random provides freshness
- No commitment to mode yet

**Message Format:**
```rust
ModeNegotiation {
    client_random: [u8; 32],
    supported_modes: Vec<AuthenticationMode>,  // [ModeA, ModeB]
    preferred_mode: AuthenticationMode,
    timestamp: u64,
}
```

---

### State: ModeNegotiationWait

**Description:** Client waits for server's mode selection

**Invariants:**
- Timeout timer active (prevent DoS)
- No mode commitment yet
- client_random stored for later binding

**Transitions:**
- `receive ModeSelection` → ModeNegotiationComplete
- `timeout` → Error

**Security Properties:**
- Timeout prevents resource exhaustion
- No partial mode state

**Timeout:** 10 seconds (configurable)

---

### State: ModeNegotiationComplete

**Description:** Mode negotiation complete, mode binding computed

**Entry Actions:**
1. Receive server's ModeSelection
2. Verify selected mode is in supported list
3. Compute mode_binding = SHA3-256("B4AE-v2-mode-binding" || client_random || server_random || mode_id)
4. Store mode_binding for signature inclusion

**Invariants:**
- Selected mode is valid
- mode_binding computed correctly
- mode_binding will be included in all signatures

**Transitions:**
- `mode binding computed` → CookieChallengeInit

**Security Properties:**
- Mode binding prevents downgrade attacks
- mode_binding cryptographically ties mode to handshake
- Any mode modification causes signature failure

**Mode Binding:**
```rust
fn compute_mode_binding(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    mode_id: u8,
) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(b"B4AE-v2-mode-binding");
    data.extend_from_slice(client_random);
    data.extend_from_slice(server_random);
    data.push(mode_id);
    
    sha3_256(&data)
}
```

---

## Cookie Challenge States

### State: CookieChallengeInit

**Description:** Client initiates cookie challenge

**Entry Actions:**
1. Prepare ClientHello with minimal information
2. Include client_random and timestamp
3. Send ClientHello to server

**Invariants:**
- ClientHello is minimal (no expensive crypto yet)
- client_random is fresh
- Timestamp is current

**Transitions:**
- `send ClientHello` → CookieChallengeWait

**Security Properties:**
- Minimal client commitment
- No expensive crypto yet
- DoS protection starts here

**Message Format:**
```rust
ClientHello {
    client_random: [u8; 32],
    timestamp: u64,
    mode_binding: [u8; 32],  // From mode negotiation
}
```

---

### State: CookieChallengeWait

**Description:** Client waits for server's cookie challenge

**Invariants:**
- Timeout timer active
- No expensive crypto performed yet
- Ready to receive cookie

**Transitions:**
- `receive CookieChallenge` → CookieChallengeResponse
- `timeout` → Error

**Security Properties:**
- Timeout prevents resource exhaustion
- Client resources minimal

**Timeout:** 10 seconds (configurable)

---

### State: CookieChallengeResponse

**Description:** Client responds with cookie

**Entry Actions:**
1. Receive CookieChallenge from server
2. Extract cookie and server_random
3. Prepare ClientHelloWithCookie
4. Include cookie in message
5. Send ClientHelloWithCookie

**Invariants:**
- Cookie is included verbatim (no modification)
- server_random stored for session_id derivation
- Ready for expensive crypto after cookie verification

**Transitions:**
- `send ClientHelloWithCookie` → HandshakeInit

**Security Properties:**
- Cookie proves client commitment
- Server can verify cookie cheaply (~0.01ms)
- DoS protection active

**Message Format:**
```rust
ClientHelloWithCookie {
    client_random: [u8; 32],
    cookie: Vec<u8>,  // From server
    mode_binding: [u8; 32],
    timestamp: u64,
}
```

---

### State: CookieVerification (Server-Side)

**Description:** Server verifies cookie before expensive crypto

**Entry Actions:**
1. Receive ClientHelloWithCookie
2. Verify cookie = HMAC(server_secret, client_ip || timestamp || client_random)
3. Check timestamp within expiry window (30 seconds)
4. Check client_random not in Bloom filter (replay protection)
5. Add client_random to Bloom filter

**Invariants:**
- Cookie verification is constant-time
- Timestamp within valid window
- No replay detected
- Bloom filter updated

**Transitions:**
- `cookie valid` → HandshakeInit (proceed with expensive crypto)
- `cookie invalid` → Error (reject immediately, ~0.01ms cost)

**Security Properties:**
- Constant-time verification prevents timing oracle
- Replay protection via Bloom filter
- DoS amplification reduced by 360x
- Invalid attempts cost ~0.01ms (vs 3.6ms without cookie)

**Cookie Verification:**
```rust
fn verify_cookie(
    cookie: &[u8],
    client_ip: &str,
    timestamp: u64,
    client_random: &[u8; 32],
    server_secret: &[u8; 32],
    bloom_filter: &mut BloomFilter,
) -> CryptoResult<bool> {
    // Check timestamp
    let now = current_timestamp();
    if now - timestamp > 30_000 {  // 30 seconds
        return Ok(false);
    }
    
    // Check replay (Bloom filter)
    if bloom_filter.contains(client_random) {
        return Ok(false);  // Replay detected
    }
    
    // Verify cookie (constant-time)
    let mut data = Vec::new();
    data.extend_from_slice(client_ip.as_bytes());
    data.extend_from_slice(&timestamp.to_le_bytes());
    data.extend_from_slice(client_random);
    
    let expected_cookie = hmac_sha256(server_secret, &data);
    let cookie_valid = ct_memcmp(cookie, &expected_cookie);
    
    if bool::from(cookie_valid) {
        // Add to Bloom filter
        bloom_filter.insert(client_random);
        Ok(true)
    } else {
        Ok(false)
    }
}
```

---

## Session State Machine

### State: Active (v2.0)

**Description:** Session is active with v2.0 security properties

**Invariants:**
- Session keys bound to unique session_id
- Mode binding enforced
- Protocol ID included in all key derivations
- Global traffic scheduler active (if enabled)

**v2.0 Security Properties:**
- **Session Independence:** Keys from different sessions are cryptographically independent
- **Mode Consistency:** Authentication mode cannot change mid-session
- **Protocol Binding:** All keys bound to protocol_id
- **Metadata Protection:** Global scheduler provides cross-session indistinguishability

**Session Key Derivation:**
```rust
fn derive_session_keys(
    master_secret: &[u8; 32],
    protocol_id: &[u8; 32],
    session_id: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> CryptoResult<SessionKeys> {
    // Root key
    let root_key = hkdf::derive_key(
        &[master_secret],
        &[protocol_id, session_id, transcript_hash].concat(),
        b"B4AE-v2-root-key",
        32,
    )?;
    
    // Chain keys
    let send_chain_key = hkdf::derive_key(
        &[master_secret],
        &[protocol_id, session_id, transcript_hash].concat(),
        b"B4AE-v2-send-chain-key",
        32,
    )?;
    
    let recv_chain_key = hkdf::derive_key(
        &[master_secret],
        &[protocol_id, session_id, transcript_hash].concat(),
        b"B4AE-v2-recv-chain-key",
        32,
    )?;
    
    Ok(SessionKeys {
        root_key,
        send_chain_key,
        recv_chain_key,
    })
}
```

---

## Security Invariants

### Global Invariants (v2.0)

1. **Mode Binding:** mode_negotiated = mode_established (no downgrade)
2. **Session Binding:** All keys include session_id in derivation
3. **Protocol Binding:** All keys include protocol_id in derivation
4. **Cookie Challenge:** Expensive crypto only after cookie verification
5. **Forward Secrecy:** Ephemeral keys zeroized after use
6. **Constant-Time:** All secret-dependent operations are constant-time

### Handshake Invariants (v2.0)

1. **5-Phase Completion:** All 5 phases must complete in order
2. **Mode-Specific Authentication:** Mode A uses XEdDSA only, Mode B uses Dilithium5 only
3. **Cookie Verification:** Cookie verified before signature verification
4. **Session ID Uniqueness:** Each session has unique session_id
5. **Transcript Binding:** All signatures cover entire handshake transcript including mode_binding

### Session Invariants (v2.0)

1. **Session Independence:** Compromise of one session doesn't affect others
2. **Key Isolation:** Keys from different sessions are cryptographically independent
3. **Mode Consistency:** Authentication mode cannot change during session
4. **Protocol Consistency:** protocol_id remains constant during session

---

## Error Handling States

### Error State: ModeDowngradeDetected (v2.0)

**Trigger:** mode_binding verification failed (mode changed after negotiation)

**Actions:**
1. Log security event (mode downgrade attack detected)
2. Zeroize all ephemeral keys
3. Terminate connection immediately
4. Alert security monitoring system

**Security Properties:**
- Mode downgrade attack prevented
- No partial session state
- Security event logged

**Recovery:** None (connection must be re-established)

---

### Error State: CookieVerificationFailed (v2.0)

**Trigger:** Cookie verification failed (invalid, expired, or replayed)

**Actions:**
1. Log event (potential DoS attack or replay)
2. Reject handshake immediately (~0.01ms cost)
3. Do NOT perform expensive crypto
4. Return to listening state

**Security Properties:**
- DoS protection maintained
- Minimal server resources consumed
- Replay attack prevented

**Recovery:** Client can retry with new cookie

---

### Error State: SessionBindingViolation (v2.0)

**Trigger:** Attempt to use key from one session in another session

**Actions:**
1. Log security event (key transplant attack detected)
2. Reject message
3. Terminate affected sessions
4. Alert security monitoring

**Security Properties:**
- Key transplant attack prevented
- Session isolation maintained
- Security event logged

**Recovery:** Sessions must be re-established

---

## State Transition Security Properties (v2.0)

### Property V2-1: Mode Binding Enforcement

**Statement:** A session is never established unless mode_negotiated = mode_established

**Enforcement:** mode_binding included in all signatures, any modification causes verification failure

**Validation:** Tamarin no-downgrade lemma (pending)

---

### Property V2-2: Cookie Challenge Enforcement

**Statement:** Server never performs expensive crypto without valid cookie

**Enforcement:** State machine enforces cookie verification before signature verification

**Validation:** State machine tests, DoS protection tests

---

### Property V2-3: Session Key Binding

**Statement:** All session keys are cryptographically bound to unique session_id

**Enforcement:** session_id included in all key derivations via HKDF

**Validation:** Multi-session tests, key independence tests

---

### Property V2-4: Protocol ID Binding

**Statement:** All keys and signatures are bound to protocol_id

**Enforcement:** protocol_id included in all key derivations and signatures

**Validation:** Unit tests for protocol ID derivation

---

## Conclusion

The v2.0 state machine provides:

1. **5-Phase Handshake:** Mode negotiation → Cookie challenge → Authentication → Establishment
2. **Mode Separation:** Mode A (deniable) vs Mode B (PQ) with clear security properties
3. **DoS Protection:** Cookie challenge reduces amplification by 360x
4. **Session Binding:** Keys bound to unique session_id prevents key transplant
5. **Protocol Binding:** Keys bound to protocol_id enables cryptographic agility
6. **Security-by-Default:** All protections always enabled

**See Also:**
- [STATE_MACHINE_SPECIFICATION.md](STATE_MACHINE_SPECIFICATION.md) - Complete v2.0 state machine
- [THREAT_MODEL_FORMALIZATION.md](THREAT_MODEL_FORMALIZATION.md) - Formal threat model
- [V2_ARCHITECTURE_OVERVIEW.md](V2_ARCHITECTURE_OVERVIEW.md) - v2.0 architecture
- [FORMAL_VERIFICATION.md](FORMAL_VERIFICATION.md) - Verification requirements

---

*Last updated: 2026*  
*Version: 2.0*
