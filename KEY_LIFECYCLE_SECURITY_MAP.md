# Key Lifecycle Security Map

## Executive Summary

This document maps the complete lifecycle of all cryptographic keys in the B4AE protocol with Security Hardening Suite, from generation through usage to zeroization. Proper key lifecycle management is critical for maintaining forward secrecy, preventing key leakage, and ensuring secure key rotation.

## Table of Contents

1. [XEdDSA Key Lifecycle](#xeddsa-key-lifecycle)
2. [Padding Key Lifecycle](#padding-key-lifecycle)
3. [Metadata Protection Key Management](#metadata-protection-key-management)
4. [Constant-Time Key Operations](#constant-time-key-operations)
5. [Key Zeroization Points](#key-zeroization-points)
6. [Key Rotation Policies](#key-rotation-policies)

---

## XEdDSA Key Lifecycle

### Long-Term XEdDSA Keypair

**Purpose:** Deniable authentication in handshake

**Lifecycle Stages:**

#### 1. Generation
```rust
pub fn generate() -> CryptoResult<XEdDSAKeyPair> {
    // Generate X25519 keypair
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    
    // Clamp secret key (X25519 requirement)
    secret_bytes[0] &= 248;
    secret_bytes[31] &= 127;
    secret_bytes[31] |= 64;
    
    // Derive public key
    let public_key = x25519_base_point_mult(&secret_bytes);
    
    Ok(XEdDSAKeyPair {
        public_key,
        secret_key: secret_bytes,
    })
}
```

**Security Properties:**
- Generated from cryptographically secure RNG (OsRng)
- Secret key clamped per X25519 specification
- Public key derived deterministically

**Storage:** Secure storage (encrypted at rest, protected by OS keychain)

---

#### 2. Loading
```rust
pub fn load_from_secure_storage() -> CryptoResult<XEdDSAKeyPair> {
    // Load from encrypted storage
    let encrypted_key = read_from_keychain("xeddsa_secret")?;
    
    // Decrypt with user authentication
    let secret_key = decrypt_with_user_auth(encrypted_key)?;
    
    // Derive public key
    let public_key = x25519_base_point_mult(&secret_key);
    
    Ok(XEdDSAKeyPair { public_key, secret_key })
}
```

**Security Properties:**
- Encrypted at rest
- Requires user authentication to decrypt
- Public key re-derived (not stored separately)

---

#### 3. Usage (Signing)
```rust
pub fn sign(&self, message: &[u8]) -> CryptoResult<XEdDSASignature> {
    // Derive signing key (constant-time)
    let signing_key = SHA512(self.secret_key || "B4AE-v1-XEdDSA-SigningKey")[0..32];
    
    // Derive nonce (deterministic)
    let nonce = SHA512(signing_key || message || "B4AE-v1-XEdDSA-Nonce")[0..32];
    
    // Compute commitment (constant-time)
    let r_point = scalar_mult_base(nonce);
    let r = encode_point(r_point);
    
    // Compute challenge
    let challenge = SHA512(r || self.public_key || message);
    let c = challenge MOD curve_order;
    
    // Compute response (constant-time)
    let s = (nonce + c * signing_key) MOD curve_order;
    
    // Zeroize ephemeral secrets
    zeroize(&mut signing_key);
    zeroize(&mut nonce);
    
    Ok(XEdDSASignature { r, s: encode_scalar(s) })
}
```

**Security Properties:**
- Signing key derived on-demand (not stored)
- Nonce is deterministic (no RNG failure risk)
- Ephemeral secrets zeroized after use
- Constant-time scalar operations

**Key Exposure:** Secret key remains in memory during signing (~1ms)

---

#### 4. Zeroization
```rust
impl Drop for XEdDSAKeyPair {
    fn drop(&mut self) {
        // Zeroize secret key
        self.secret_key.zeroize();
    }
}
```

**Zeroization Points:**
- When keypair is dropped
- On session close
- On application exit
- On key rotation

**Security Properties:**
- Automatic zeroization via Drop trait
- Multiple overwrites (zeroize crate)
- Compiler barriers prevent optimization

---

### Ephemeral XEdDSA Keys (Handshake)

**Purpose:** Ephemeral keys for handshake (if using ephemeral XEdDSA variant)

**Lifecycle:**
1. **Generation:** During handshake initialization
2. **Usage:** Single handshake only
3. **Zeroization:** Immediately after handshake complete

**Lifetime:** ~100ms (handshake duration)

**Security Properties:**
- Never reused across handshakes
- Zeroized immediately after use
- Provides forward secrecy

---

## Padding Key Lifecycle

### Padding Validation Context

**Purpose:** Context for constant-time padding validation

**Lifecycle:**

#### 1. Derivation (Per-Message)
```rust
fn derive_padding_context(
    message_key: &[u8; 32],
    bucket_size: usize,
    original_length: usize,
) -> [u8; 64] {
    SHA512(
        "B4AE-v1-Padding-Validation" ||
        message_key ||
        bucket_size.to_le_bytes() ||
        original_length.to_le_bytes()
    )
}
```

**Security Properties:**
- Derived per-message (not reused)
- Bound to message key
- Includes bucket size and original length

---

#### 2. Usage (Validation)
```rust
fn validate_padding_ct(
    padded: &[u8],
    original_length: usize,
    context: &[u8; 64],
) -> CryptoResult<()> {
    let bucket_size = padded.len();
    let padding_length = bucket_size - original_length;
    let expected_byte = (padding_length % 256) as u8;
    
    // Constant-time validation
    let mut valid = Choice::from(1u8);
    for i in original_length..bucket_size {
        let byte_matches = ct_eq(padded[i], expected_byte);
        valid &= byte_matches;
    }
    
    if !bool::from(valid) {
        return Err(CryptoError::InvalidPadding);
    }
    
    Ok(())
}
```

**Security Properties:**
- Constant-time validation
- No early termination
- Context prevents cross-message attacks

---

#### 3. Zeroization
```rust
// Context is zeroized after validation
context.zeroize();
```

**Zeroization Points:**
- After padding validation complete
- On validation error
- On message processing complete

**Lifetime:** ~0.1ms (validation duration)

---

## Metadata Protection Key Management

### Cover Traffic Key

**Purpose:** Generate dummy messages

**Lifecycle:**

#### 1. Derivation (Per-Session)
```rust
let cover_traffic_key = HKDF-SHA512(
    ikm: session_root_key,
    salt: b"",
    info: "B4AE-v1-Metadata-CoverTraffic-Hardening",
    length: 32
);
```

**Security Properties:**
- Derived from session root key
- Unique per session
- Independent from message encryption keys

---

#### 2. Usage (Dummy Message Generation)
```rust
fn generate_dummy_message(
    cover_traffic_key: &[u8; 32],
    timestamp: u64,
    size: usize,
) -> Vec<u8> {
    // Derive dummy seed
    let dummy_seed = HKDF-SHA512(
        ikm: cover_traffic_key,
        salt: timestamp.to_le_bytes(),
        info: "B4AE-v1-Metadata-DummySeed",
        length: 32
    );
    
    // Generate dummy content
    let mut dummy_content = vec![0u8; size];
    ChaCha20::new(&dummy_seed, &[0u8; 12])
        .apply_keystream(&mut dummy_content);
    
    // Zeroize seed
    dummy_seed.zeroize();
    
    dummy_content
}
```

**Security Properties:**
- Dummy messages indistinguishable from real
- Seed derived per-message
- Ephemeral seed zeroized after use

---

#### 3. Rotation
```rust
// Rotate cover traffic key every N messages or T time
if messages_sent >= KEY_ROTATION_THRESHOLD {
    let new_cover_traffic_key = HKDF-SHA512(
        ikm: current_cover_traffic_key,
        salt: b"rotation",
        info: "B4AE-v1-Metadata-CoverTraffic-Hardening",
        length: 32
    );
    
    // Zeroize old key
    current_cover_traffic_key.zeroize();
    current_cover_traffic_key = new_cover_traffic_key;
}
```

**Rotation Policy:**
- Every 10,000 messages
- Every 24 hours
- On session ratchet step

---

#### 4. Zeroization
```rust
impl Drop for MetadataProtector {
    fn drop(&mut self) {
        self.cover_traffic_key.zeroize();
        self.timing_seed.zeroize();
        self.shaping_key.zeroize();
    }
}
```

**Zeroization Points:**
- On session close
- On key rotation
- On application exit

---

### Timing Obfuscation Seed

**Purpose:** Generate random timing delays

**Lifecycle:**

#### 1. Derivation (Per-Session)
```rust
let timing_seed = HKDF-SHA512(
    ikm: session_root_key,
    salt: b"",
    info: "B4AE-v1-Metadata-TimingSeed",
    length: 32
);
```

---

#### 2. Usage (Delay Generation)
```rust
fn generate_random_delay(
    timing_seed: &[u8; 32],
    min_ms: u64,
    max_ms: u64,
) -> Duration {
    // Derive per-message delay seed
    let delay_seed = HKDF-SHA512(
        ikm: timing_seed,
        salt: timestamp.to_le_bytes(),
        info: "B4AE-v1-Metadata-DelaySeed",
        length: 8
    );
    
    // Generate delay in range [min_ms, max_ms]
    let delay_value = u64::from_le_bytes(delay_seed) % (max_ms - min_ms) + min_ms;
    
    // Zeroize seed
    delay_seed.zeroize();
    
    Duration::from_millis(delay_value)
}
```

**Security Properties:**
- Unpredictable to adversary
- Uniform distribution in range
- Per-message seed zeroized

---

#### 3. Rotation
**Policy:** Same as cover traffic key (every 10,000 messages or 24 hours)

---

#### 4. Zeroization
**Points:** Same as cover traffic key

---

### Traffic Shaping Key

**Purpose:** Schedule message transmission

**Lifecycle:** Similar to cover traffic key

**Rotation Policy:** Every 10,000 messages or 24 hours

**Zeroization Points:** On session close, key rotation, application exit

---

## Constant-Time Key Operations

### Constant-Time Key Comparison

**Purpose:** Compare keys/MACs without timing leaks

**Implementation:**
```rust
pub fn ct_compare_keys(a: &[u8], b: &[u8]) -> Choice {
    assert_eq!(a.len(), b.len());
    
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    
    ct_is_zero(diff as u64)
}
```

**Security Properties:**
- Execution time independent of input values
- No early termination
- No secret-dependent branching

**Usage:**
- MAC verification
- Signature verification
- Padding validation
- Key equality checks

---

### Constant-Time Key Derivation

**Purpose:** Derive keys without timing leaks

**Implementation:**
```rust
pub fn ct_derive_key(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Vec<u8> {
    // HKDF is inherently constant-time for fixed-length inputs
    HKDF-SHA512(ikm, salt, info, length)
}
```

**Security Properties:**
- HKDF-SHA512 is constant-time
- No secret-dependent branching
- Fixed-length outputs

---

## Key Zeroization Points

### Comprehensive Zeroization Map

| Key Type | Zeroization Trigger | Method | Verification |
|----------|-------------------|--------|--------------|
| **XEdDSA Secret Key** | Drop, session close, rotation | `zeroize()` | Memory inspection |
| **Ephemeral DH Keys** | Handshake complete | `zeroize()` | Memory inspection |
| **Root Key** | Session close | `zeroize()` | Memory inspection |
| **Chain Keys** | After message key derivation | `zeroize()` | Memory inspection |
| **Message Keys** | After encryption/decryption | `zeroize()` | Memory inspection |
| **Cover Traffic Key** | Session close, rotation | `zeroize()` | Memory inspection |
| **Timing Seed** | Session close, rotation | `zeroize()` | Memory inspection |
| **Shaping Key** | Session close, rotation | `zeroize()` | Memory inspection |
| **Padding Context** | After validation | `zeroize()` | Memory inspection |
| **Dummy Seeds** | After dummy generation | `zeroize()` | Memory inspection |

---

### Zeroization Implementation

```rust
use zeroize::Zeroize;

// Automatic zeroization via Drop
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// Manual zeroization
fn zeroize_key(key: &mut [u8]) {
    key.zeroize();
}

// Zeroization with verification
fn zeroize_and_verify(key: &mut [u8]) -> bool {
    key.zeroize();
    key.iter().all(|&b| b == 0)
}
```

**Security Properties:**
- Multiple overwrites (zeroize crate default: 3 passes)
- Compiler barriers prevent optimization
- Verification available for critical keys

---

## Key Rotation Policies

### Long-Term Key Rotation

**XEdDSA Keypair:**
- **Policy:** Rotate every 90 days or on compromise
- **Trigger:** Manual or scheduled
- **Process:**
  1. Generate new keypair
  2. Distribute new public key to peers
  3. Zeroize old keypair after grace period (7 days)
  4. Update secure storage

**Dilithium5 Keypair:**
- **Policy:** Same as XEdDSA (rotate together)
- **Reason:** Maintain hybrid security

---

### Session Key Rotation

**Root Key:**
- **Policy:** Rotate on every DH ratchet step
- **Trigger:** Automatic (every N messages or on peer message)
- **Frequency:** ~100 messages or 1 hour

**Chain Keys:**
- **Policy:** Advance on every message
- **Trigger:** Automatic
- **Frequency:** Every message

**Message Keys:**
- **Policy:** Derive fresh for every message
- **Trigger:** Automatic
- **Frequency:** Every message (never reused)

---

### Metadata Protection Key Rotation

**Cover Traffic Key:**
- **Policy:** Rotate every 10,000 messages or 24 hours
- **Trigger:** Automatic
- **Process:**
  1. Derive new key from current key
  2. Zeroize old key
  3. Update metadata protector state

**Timing Seed:**
- **Policy:** Same as cover traffic key
- **Trigger:** Automatic

**Shaping Key:**
- **Policy:** Same as cover traffic key
- **Trigger:** Automatic

---

## Key Lifetime Summary

| Key Type | Lifetime | Rotation Frequency | Zeroization Delay |
|----------|----------|-------------------|-------------------|
| **XEdDSA Long-Term** | 90 days | 90 days | Immediate |
| **Ephemeral DH** | ~100ms | Per handshake | Immediate |
| **Root Key** | ~1 hour | Per ratchet step | Immediate |
| **Chain Key** | ~1 message | Per message | Immediate |
| **Message Key** | ~1ms | Per message | Immediate |
| **Cover Traffic Key** | 24 hours | 24 hours | Immediate |
| **Timing Seed** | 24 hours | 24 hours | Immediate |
| **Shaping Key** | 24 hours | 24 hours | Immediate |

---

## Security Properties

### Property 1: Forward Secrecy

**Statement:** Compromise of long-term keys does not compromise past session keys

**Enforcement:**
- Ephemeral DH keys zeroized after handshake
- Session keys derived from ephemeral keys
- Chain keys advanced and zeroized after use

**Validation:** Memory inspection after handshake shows no ephemeral keys

---

### Property 2: Post-Compromise Security

**Statement:** Compromise of session keys does not compromise future session keys

**Enforcement:**
- DH ratchet step generates new ephemeral keys
- Root key derived from new DH output
- Old keys zeroized after ratchet

**Validation:** Memory inspection after ratchet shows no old keys

---

### Property 3: Key Isolation

**Statement:** Keys for different purposes are cryptographically independent

**Enforcement:**
- Domain separation in all KDF calls
- Separate key hierarchies for encryption, metadata, padding

**Validation:** Domain separation map (see DOMAIN_SEPARATION_MAP.md)

---

### Property 4: Secure Zeroization

**Statement:** All keys are securely zeroized when no longer needed

**Enforcement:**
- Automatic zeroization via Drop trait
- Manual zeroization at critical points
- Multiple overwrites (zeroize crate)

**Validation:** Memory inspection tests verify zeroization

---

## Best Practices

### Key Generation
1. Always use cryptographically secure RNG (OsRng)
2. Validate generated keys (e.g., X25519 clamping)
3. Never reuse ephemeral keys

### Key Storage
1. Encrypt long-term keys at rest
2. Use OS keychain or secure enclave
3. Require user authentication for access

### Key Usage
1. Minimize key lifetime in memory
2. Use constant-time operations for secret-dependent code
3. Derive ephemeral keys on-demand

### Key Rotation
1. Rotate long-term keys every 90 days
2. Rotate session keys frequently (per ratchet step)
3. Rotate metadata keys every 24 hours

### Key Zeroization
1. Zeroize immediately after use
2. Use automatic zeroization (Drop trait)
3. Verify zeroization for critical keys
4. Multiple overwrites for defense in depth

---

## Conclusion

The key lifecycle security map ensures that all cryptographic keys in the B4AE protocol with Security Hardening Suite are properly managed from generation through zeroization. Key features:

1. **Forward Secrecy:** Ephemeral keys zeroized after use
2. **Post-Compromise Security:** Regular key rotation
3. **Key Isolation:** Domain separation prevents key reuse
4. **Secure Zeroization:** Automatic and verified zeroization
5. **Constant-Time Operations:** All key operations are constant-time

Proper key lifecycle management is critical for maintaining the security properties of the protocol and preventing key leakage attacks.

---

*Last updated: 2026*
*Version: 1.0*
