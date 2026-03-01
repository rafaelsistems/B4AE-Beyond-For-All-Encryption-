# Domain Separation Map for Security Hardening Suite

## Executive Summary

This document provides a comprehensive map of all domain separation strings used in Key Derivation Functions (KDFs) throughout the B4AE protocol with Security Hardening Suite. Domain separation ensures that keys derived for different purposes are cryptographically independent, preventing key reuse attacks and cross-protocol attacks.

**Key Principle:** Every KDF call uses a unique `info` string that identifies the protocol version, component, and purpose of the derived key.

## Table of Contents

1. [Domain Separation Overview](#domain-separation-overview)
2. [Handshake Domain Separation](#handshake-domain-separation)
3. [Double Ratchet Domain Separation](#double-ratchet-domain-separation)
4. [Padding Domain Separation](#padding-domain-separation)
5. [Metadata Protection Domain Separation](#metadata-protection-domain-separation)
6. [Constant-Time Operations Domain Separation](#constant-time-operations-domain-separation)
7. [Key Derivation Tree](#key-derivation-tree)
8. [Collision Resistance Analysis](#collision-resistance-analysis)

---

## Domain Separation Overview

### Purpose of Domain Separation

Domain separation ensures that:
1. **Key Independence**: Keys derived for different purposes are cryptographically independent
2. **Cross-Protocol Security**: Keys cannot be reused across different protocol versions
3. **Component Isolation**: Keys from different components (handshake, ratchet, padding) are isolated
4. **Attack Prevention**: Prevents key substitution and cross-protocol attacks

### Domain Separation Format

All domain separation strings follow this format:

```
"B4AE-v{VERSION}-{COMPONENT}-{PURPOSE}-{VARIANT}"
```

**Components:**
- `B4AE`: Protocol identifier
- `v{VERSION}`: Protocol version (e.g., `v1`, `v2`)
- `{COMPONENT}`: Component name (e.g., `Handshake`, `Ratchet`, `Padding`)
- `{PURPOSE}`: Key purpose (e.g., `RootKey`, `ChainKey`, `MessageKey`)
- `{VARIANT}`: Optional variant (e.g., `Send`, `Receive`, `Hardening`)

### KDF Function

All key derivations use HKDF-SHA512:

```rust
fn derive_key(
    ikm: &[u8],           // Input key material
    salt: &[u8],          // Salt (optional, can be empty)
    info: &str,           // Domain separation string
    length: usize,        // Output key length
) -> Vec<u8> {
    HKDF-SHA512(ikm, salt, info.as_bytes(), length)
}
```

---

## Handshake Domain Separation

### Root Key Derivation

**Purpose:** Derive root key from hybrid shared secret (X25519 + Kyber1024)

**Domain String:** `"B4AE-v1-Handshake-RootKey-Hardening"`

**KDF Call:**
```rust
let root_key = HKDF-SHA512(
    ikm: hybrid_shared_secret,  // X25519 || Kyber1024 shared secrets
    salt: handshake_hash,        // SHA-512 of handshake transcript
    info: "B4AE-v1-Handshake-RootKey-Hardening",
    length: 32
);
```

**Inputs:**
- `ikm`: 64 bytes (32 bytes X25519 + 32 bytes Kyber1024)
- `salt`: 64 bytes (SHA-512 of handshake transcript)
- Output: 32 bytes

**Security Property:** Root key is cryptographically independent from any other derived key

---

### Handshake Transcript Hash

**Purpose:** Compute hash of handshake transcript for transcript binding

**Domain String:** `"B4AE-v1-Handshake-Transcript"`

**Hash Computation:**
```rust
let transcript_hash = SHA-512(
    "B4AE-v1-Handshake-Transcript" ||
    handshake_init ||
    handshake_response ||
    handshake_complete
);
```

**Security Property:** Transcript hash binds all handshake messages together

---

### XEdDSA Signing Key Derivation

**Purpose:** Derive Ed25519 signing key from X25519 secret key

**Domain String:** `"B4AE-v1-XEdDSA-SigningKey"`

**KDF Call:**
```rust
let signing_key = SHA-512(
    x25519_secret_key ||
    "B4AE-v1-XEdDSA-SigningKey"
)[0..32];
```

**Inputs:**
- `x25519_secret_key`: 32 bytes
- Output: 32 bytes (first 32 bytes of SHA-512)

**Security Property:** Signing key is derived deterministically from X25519 key

---

### XEdDSA Nonce Derivation

**Purpose:** Derive nonce for XEdDSA signature generation

**Domain String:** `"B4AE-v1-XEdDSA-Nonce"`

**KDF Call:**
```rust
let nonce = SHA-512(
    signing_key ||
    message ||
    "B4AE-v1-XEdDSA-Nonce"
)[0..32];
```

**Inputs:**
- `signing_key`: 32 bytes
- `message`: Variable length
- Output: 32 bytes (first 32 bytes of SHA-512)

**Security Property:** Nonce is deterministic and unique per message

---

## Double Ratchet Domain Separation

### Root Key Chain

**Purpose:** Derive new root key during DH ratchet step

**Domain String:** `"B4AE-v1-Ratchet-RootKey-Hardening"`

**KDF Call:**
```rust
let (new_root_key, new_chain_key) = HKDF-SHA512-Expand(
    ikm: dh_output,
    salt: current_root_key,
    info: "B4AE-v1-Ratchet-RootKey-Hardening",
    length: 64  // 32 bytes root key + 32 bytes chain key
);
```

**Inputs:**
- `ikm`: 32 bytes (DH output)
- `salt`: 32 bytes (current root key)
- Output: 64 bytes (32 bytes new root key + 32 bytes new chain key)

**Security Property:** New root key and chain key are independent

---

### Send Chain Key Derivation

**Purpose:** Derive next send chain key

**Domain String:** `"B4AE-v1-Ratchet-ChainKey-Send"`

**KDF Call:**
```rust
let next_chain_key = HMAC-SHA512(
    key: current_chain_key,
    message: "B4AE-v1-Ratchet-ChainKey-Send" || 0x01
)[0..32];
```

**Inputs:**
- `key`: 32 bytes (current chain key)
- Output: 32 bytes

**Security Property:** Chain key advances forward, cannot be reversed

---

### Receive Chain Key Derivation

**Purpose:** Derive next receive chain key

**Domain String:** `"B4AE-v1-Ratchet-ChainKey-Receive"`

**KDF Call:**
```rust
let next_chain_key = HMAC-SHA512(
    key: current_chain_key,
    message: "B4AE-v1-Ratchet-ChainKey-Receive" || 0x01
)[0..32];
```

**Inputs:**
- `key`: 32 bytes (current chain key)
- Output: 32 bytes

**Security Property:** Separate from send chain key

---

### Message Key Derivation (Send)

**Purpose:** Derive message key for encryption

**Domain String:** `"B4AE-v1-Ratchet-MessageKey-Send"`

**KDF Call:**
```rust
let message_key = HMAC-SHA512(
    key: current_chain_key,
    message: "B4AE-v1-Ratchet-MessageKey-Send" || 0x02
)[0..32];
```

**Inputs:**
- `key`: 32 bytes (current chain key)
- Output: 32 bytes

**Security Property:** Message key is independent from chain key advancement

---

### Message Key Derivation (Receive)

**Purpose:** Derive message key for decryption

**Domain String:** `"B4AE-v1-Ratchet-MessageKey-Receive"`

**KDF Call:**
```rust
let message_key = HMAC-SHA512(
    key: current_chain_key,
    message: "B4AE-v1-Ratchet-MessageKey-Receive" || 0x02
)[0..32];
```

**Inputs:**
- `key`: 32 bytes (current chain key)
- Output: 32 bytes

**Security Property:** Separate from send message key

---

### ChaCha20-Poly1305 Key and Nonce

**Purpose:** Derive encryption key and nonce from message key

**Domain Strings:**
- Encryption key: `"B4AE-v1-AEAD-EncryptionKey"`
- Nonce: `"B4AE-v1-AEAD-Nonce"`

**KDF Calls:**
```rust
let encryption_key = HKDF-SHA512(
    ikm: message_key,
    salt: b"",
    info: "B4AE-v1-AEAD-EncryptionKey",
    length: 32
);

let nonce = HKDF-SHA512(
    ikm: message_key,
    salt: b"",
    info: "B4AE-v1-AEAD-Nonce",
    length: 12
);
```

**Security Property:** Encryption key and nonce are independent

---

## Padding Domain Separation

### Padding Key Derivation (Optional)

**Purpose:** Derive key for authenticated padding (if using authenticated padding variant)

**Domain String:** `"B4AE-v1-Padding-AuthKey-Hardening"`

**KDF Call:**
```rust
let padding_auth_key = HKDF-SHA512(
    ikm: message_key,
    salt: b"",
    info: "B4AE-v1-Padding-AuthKey-Hardening",
    length: 32
);
```

**Note:** Current implementation uses deterministic padding without separate key. This is reserved for future authenticated padding variants.

---

### Padding Validation Context

**Purpose:** Domain separation for padding validation (constant-time)

**Domain String:** `"B4AE-v1-Padding-Validation"`

**Usage:**
```rust
// Used in constant-time padding validation
let validation_context = SHA-512(
    "B4AE-v1-Padding-Validation" ||
    bucket_size ||
    original_length
);
```

**Security Property:** Validation context is independent from encryption keys

---

## Metadata Protection Domain Separation

### Cover Traffic Key Derivation

**Purpose:** Derive key for generating cover traffic (dummy messages)

**Domain String:** `"B4AE-v1-Metadata-CoverTraffic-Hardening"`

**KDF Call:**
```rust
let cover_traffic_key = HKDF-SHA512(
    ikm: session_root_key,
    salt: b"",
    info: "B4AE-v1-Metadata-CoverTraffic-Hardening",
    length: 32
);
```

**Inputs:**
- `ikm`: 32 bytes (session root key)
- Output: 32 bytes

**Security Property:** Cover traffic key is independent from message encryption keys

---

### Dummy Message Seed Derivation

**Purpose:** Derive seed for generating dummy message content

**Domain String:** `"B4AE-v1-Metadata-DummySeed"`

**KDF Call:**
```rust
let dummy_seed = HKDF-SHA512(
    ikm: cover_traffic_key,
    salt: timestamp.to_le_bytes(),
    info: "B4AE-v1-Metadata-DummySeed",
    length: 32
);
```

**Inputs:**
- `ikm`: 32 bytes (cover traffic key)
- `salt`: 8 bytes (timestamp)
- Output: 32 bytes

**Security Property:** Dummy messages are indistinguishable from real messages

---

### Timing Obfuscation Seed

**Purpose:** Derive seed for timing delay RNG

**Domain String:** `"B4AE-v1-Metadata-TimingSeed"`

**KDF Call:**
```rust
let timing_seed = HKDF-SHA512(
    ikm: session_root_key,
    salt: b"",
    info: "B4AE-v1-Metadata-TimingSeed",
    length: 32
);
```

**Inputs:**
- `ikm`: 32 bytes (session root key)
- Output: 32 bytes

**Security Property:** Timing delays are unpredictable to adversary

---

### Traffic Shaping Key

**Purpose:** Derive key for traffic shaping scheduler

**Domain String:** `"B4AE-v1-Metadata-TrafficShaping"`

**KDF Call:**
```rust
let shaping_key = HKDF-SHA512(
    ikm: session_root_key,
    salt: b"",
    info: "B4AE-v1-Metadata-TrafficShaping",
    length: 32
);
```

**Inputs:**
- `ikm`: 32 bytes (session root key)
- Output: 32 bytes

**Security Property:** Traffic shaping is independent from encryption

---

## Constant-Time Operations Domain Separation

### Constant-Time Comparison Context

**Purpose:** Domain separation for constant-time memory comparison

**Domain String:** `"B4AE-v1-ConstantTime-Comparison"`

**Usage:**
```rust
// Used in constant-time comparison for MAC verification
let comparison_context = SHA-512(
    "B4AE-v1-ConstantTime-Comparison" ||
    expected_tag ||
    computed_tag
);
```

**Security Property:** Comparison is constant-time and independent from keys

---

### Cache-Timing Resistance Context

**Purpose:** Domain separation for cache-timing resistant operations

**Domain String:** `"B4AE-v1-ConstantTime-CacheResistant"`

**Usage:**
```rust
// Used in cache-timing resistant table lookup
let lookup_context = SHA-512(
    "B4AE-v1-ConstantTime-CacheResistant" ||
    table_id ||
    index
);
```

**Security Property:** Table lookup is cache-timing resistant

---

## Key Derivation Tree

### Complete Key Hierarchy

```
Root Key (from handshake)
├── Session Root Key
│   ├── Send Chain Key 0
│   │   ├── Message Key 0
│   │   │   ├── Encryption Key
│   │   │   └── Nonce
│   │   ├── Message Key 1
│   │   └── ...
│   ├── Receive Chain Key 0
│   │   ├── Message Key 0
│   │   │   ├── Encryption Key
│   │   │   └── Nonce
│   │   ├── Message Key 1
│   │   └── ...
│   ├── Cover Traffic Key
│   │   ├── Dummy Seed 0
│   │   ├── Dummy Seed 1
│   │   └── ...
│   ├── Timing Obfuscation Seed
│   └── Traffic Shaping Key
├── DH Ratchet Step 1
│   ├── New Root Key
│   ├── New Send Chain Key
│   └── New Receive Chain Key
└── ...
```

### Domain Separation Strings by Level

**Level 0: Handshake**
- `"B4AE-v1-Handshake-RootKey-Hardening"`
- `"B4AE-v1-Handshake-Transcript"`
- `"B4AE-v1-XEdDSA-SigningKey"`
- `"B4AE-v1-XEdDSA-Nonce"`

**Level 1: Session Root**
- `"B4AE-v1-Ratchet-RootKey-Hardening"`
- `"B4AE-v1-Metadata-CoverTraffic-Hardening"`
- `"B4AE-v1-Metadata-TimingSeed"`
- `"B4AE-v1-Metadata-TrafficShaping"`

**Level 2: Chain Keys**
- `"B4AE-v1-Ratchet-ChainKey-Send"`
- `"B4AE-v1-Ratchet-ChainKey-Receive"`

**Level 3: Message Keys**
- `"B4AE-v1-Ratchet-MessageKey-Send"`
- `"B4AE-v1-Ratchet-MessageKey-Receive"`

**Level 4: AEAD Keys**
- `"B4AE-v1-AEAD-EncryptionKey"`
- `"B4AE-v1-AEAD-Nonce"`

**Level 5: Metadata Keys**
- `"B4AE-v1-Metadata-DummySeed"`
- `"B4AE-v1-Padding-Validation"`

---

## Collision Resistance Analysis

### Uniqueness Guarantee

**Theorem:** All domain separation strings are unique and collision-resistant.

**Proof:**
1. All strings start with `"B4AE-v1-"` (protocol identifier)
2. Component names are unique: `Handshake`, `Ratchet`, `Metadata`, `Padding`, `AEAD`, `XEdDSA`, `ConstantTime`
3. Purpose names are unique within each component
4. Variant names are unique within each purpose

**Example:**
- `"B4AE-v1-Ratchet-ChainKey-Send"` ≠ `"B4AE-v1-Ratchet-ChainKey-Receive"` (different variant)
- `"B4AE-v1-Ratchet-MessageKey-Send"` ≠ `"B4AE-v1-Ratchet-ChainKey-Send"` (different purpose)
- `"B4AE-v1-Handshake-RootKey-Hardening"` ≠ `"B4AE-v1-Ratchet-RootKey-Hardening"` (different component)

---

### Collision Probability

**Hash Function:** SHA-512 (512-bit output)

**Birthday Bound:** For n domain strings, collision probability is approximately:
```
P(collision) ≈ n² / 2^513
```

**Current Count:** ~25 domain strings

**Collision Probability:**
```
P(collision) ≈ 25² / 2^513 ≈ 625 / 2^513 ≈ 2^-503
```

**Conclusion:** Collision probability is negligible (< 2^-500)

---

### Cross-Protocol Security

**Property:** Keys derived with B4AE domain strings cannot be used in other protocols

**Enforcement:**
1. All domain strings start with `"B4AE-v1-"`
2. Version number prevents cross-version attacks
3. Component names prevent cross-component attacks

**Example Attack Prevention:**
- Attacker cannot use B4AE handshake key in TLS
- Attacker cannot use B4AE v1 key in B4AE v2
- Attacker cannot use B4AE ratchet key in handshake

---

## Domain Separation Best Practices

### Adding New Domain Strings

When adding new domain strings, follow these rules:

1. **Format:** `"B4AE-v{VERSION}-{COMPONENT}-{PURPOSE}-{VARIANT}"`
2. **Uniqueness:** Ensure string is unique across all existing strings
3. **Documentation:** Document in this file with KDF call details
4. **Testing:** Add test to verify uniqueness
5. **Review:** Security review before deployment

### Example: Adding New Feature

```rust
// New feature: Authenticated padding
let padding_auth_key = HKDF-SHA512(
    ikm: message_key,
    salt: b"",
    info: "B4AE-v1-Padding-AuthKey-Hardening",  // New domain string
    length: 32
);
```

**Checklist:**
- ✅ Follows format
- ✅ Unique (not used elsewhere)
- ✅ Documented in this file
- ✅ Test added
- ✅ Security reviewed

---

## Complete Domain String Registry

### Alphabetical List

1. `"B4AE-v1-AEAD-EncryptionKey"`
2. `"B4AE-v1-AEAD-Nonce"`
3. `"B4AE-v1-ConstantTime-CacheResistant"`
4. `"B4AE-v1-ConstantTime-Comparison"`
5. `"B4AE-v1-Handshake-RootKey-Hardening"`
6. `"B4AE-v1-Handshake-Transcript"`
7. `"B4AE-v1-Metadata-CoverTraffic-Hardening"`
8. `"B4AE-v1-Metadata-DummySeed"`
9. `"B4AE-v1-Metadata-TimingSeed"`
10. `"B4AE-v1-Metadata-TrafficShaping"`
11. `"B4AE-v1-Padding-AuthKey-Hardening"` (reserved)
12. `"B4AE-v1-Padding-Validation"`
13. `"B4AE-v1-Ratchet-ChainKey-Receive"`
14. `"B4AE-v1-Ratchet-ChainKey-Send"`
15. `"B4AE-v1-Ratchet-MessageKey-Receive"`
16. `"B4AE-v1-Ratchet-MessageKey-Send"`
17. `"B4AE-v1-Ratchet-RootKey-Hardening"`
18. `"B4AE-v1-XEdDSA-Nonce"`
19. `"B4AE-v1-XEdDSA-SigningKey"`

### By Component

**Handshake:**
- `"B4AE-v1-Handshake-RootKey-Hardening"`
- `"B4AE-v1-Handshake-Transcript"`

**XEdDSA:**
- `"B4AE-v1-XEdDSA-SigningKey"`
- `"B4AE-v1-XEdDSA-Nonce"`

**Ratchet:**
- `"B4AE-v1-Ratchet-RootKey-Hardening"`
- `"B4AE-v1-Ratchet-ChainKey-Send"`
- `"B4AE-v1-Ratchet-ChainKey-Receive"`
- `"B4AE-v1-Ratchet-MessageKey-Send"`
- `"B4AE-v1-Ratchet-MessageKey-Receive"`

**AEAD:**
- `"B4AE-v1-AEAD-EncryptionKey"`
- `"B4AE-v1-AEAD-Nonce"`

**Padding:**
- `"B4AE-v1-Padding-AuthKey-Hardening"` (reserved)
- `"B4AE-v1-Padding-Validation"`

**Metadata:**
- `"B4AE-v1-Metadata-CoverTraffic-Hardening"`
- `"B4AE-v1-Metadata-DummySeed"`
- `"B4AE-v1-Metadata-TimingSeed"`
- `"B4AE-v1-Metadata-TrafficShaping"`

**Constant-Time:**
- `"B4AE-v1-ConstantTime-Comparison"`
- `"B4AE-v1-ConstantTime-CacheResistant"`

---

## Security Properties Summary

### Property 1: Key Independence

**Statement:** Keys derived with different domain strings are cryptographically independent

**Guarantee:** HKDF-SHA512 with different info strings produces independent outputs

**Validation:** Proven by HKDF security proof

---

### Property 2: Cross-Protocol Security

**Statement:** Keys cannot be reused across different protocols or versions

**Guarantee:** All domain strings include protocol identifier and version

**Validation:** String format enforces uniqueness

---

### Property 3: Component Isolation

**Statement:** Keys from different components are isolated

**Guarantee:** Component name in domain string ensures isolation

**Validation:** No component can derive another component's keys

---

### Property 4: Collision Resistance

**Statement:** Probability of domain string collision is negligible

**Guarantee:** SHA-512 collision resistance + unique strings

**Validation:** Collision probability < 2^-500

---

## Conclusion

The domain separation map ensures that all keys derived in the B4AE protocol with Security Hardening Suite are cryptographically independent and cannot be reused across different contexts. Key features:

1. **Unique Domain Strings**: 19 unique domain strings covering all components
2. **Collision Resistance**: Negligible collision probability (< 2^-500)
3. **Cross-Protocol Security**: Protocol identifier prevents cross-protocol attacks
4. **Component Isolation**: Component names ensure isolation
5. **Version Control**: Version number prevents cross-version attacks

The domain separation scheme provides a strong foundation for key derivation security and prevents a wide range of key reuse attacks.

---

*Last updated: 2026*
*Version: 1.0*
