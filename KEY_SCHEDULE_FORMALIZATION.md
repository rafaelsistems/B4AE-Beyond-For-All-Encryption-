# B4AE Key Schedule Formalization

**Version:** 1.0  
**Date:** 2026  
**Status:** Implementation-Based Specification

## 1. Overview

This document formalizes the complete key derivation schedule for the B4AE protocol, extracted from the actual implementation. All HKDF invocations, info strings, concatenation orders, and encoding schemes are documented with exact source references.

## 2. Cryptographic Primitives

### 2.1 Key Derivation Function

**Algorithm:** HKDF-SHA3-256  
**Source:** `src/crypto/hkdf.rs:8`

```rust
use hkdf::Hkdf;
use sha3::Sha3_256;
```

### 2.2 HKDF Interface

```rust
// Source: src/crypto/hkdf.rs:10-23
pub fn derive_key(
    input_key_material: &[&[u8]],  // Multiple IKM sources
    info: &[u8],                    // Context string
    output_length: usize,           // Output size in bytes
) -> CryptoResult<Vec<u8>>
```

**Behavior:**
1. Concatenate all IKM sources: `ikm = ikm[0] || ikm[1] || ... || ikm[n]`
2. Use empty salt (RFC 5869 compliant)
3. Expand with info string to output_length

## 3. Handshake Key Derivation

### 3.1 Master Secret Derivation

**Formula:**
```
master_secret = HKDF-Extract-Expand(
    salt = client_random || server_random,
    ikm = shared_secret,
    info = "B4AE-v1-master-secret",
    length = 32
)
```

**Source:** `src/protocol/handshake.rs:289-293` (Initiator), `src/protocol/handshake.rs:631-635` (Responder)

**Implementation:**
```rust
fn derive_master_secret(&self, shared_secret: &[u8], server_random: &[u8; 32]) 
    -> CryptoResult<Vec<u8>> 
{
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(&self.client_random);  // 32 bytes
    salt.extend_from_slice(server_random);        // 32 bytes
    hkdf::derive_key_with_salt(&salt, &[shared_secret], b"B4AE-v1-master-secret", 32)
}
```

**Concatenation Order:** `client_random || server_random` (64 bytes total)

### 3.2 Session Keys Derivation

**From master_secret, derive three keys:**

#### 3.2.1 Encryption Key

```
encryption_key = HKDF-Expand(
    ikm = master_secret,
    info = "B4AE-v1-encryption-key",
    length = 32
)
```

**Source:** `src/crypto/hkdf.rs:103-108`

#### 3.2.2 Authentication Key

```
authentication_key = HKDF-Expand(
    ikm = master_secret,
    info = "B4AE-v1-authentication-key",
    length = 32
)
```

**Source:** `src/crypto/hkdf.rs:111-116`

#### 3.2.3 Metadata Key

```
metadata_key = HKDF-Expand(
    ikm = master_secret,
    info = "B4AE-v1-metadata-key",
    length = 32
)
```

**Source:** `src/crypto/hkdf.rs:119-124`

### 3.3 Session ID Derivation

```
session_id = HKDF-Expand(
    ikm = client_random || server_random,
    info = "session-id",
    length = 32
)
```

**Source:** `src/protocol/handshake.rs:308-318`

**Implementation:**
```rust
fn generate_session_id(&self, server_random: &[u8; 32]) -> CryptoResult<[u8; 32]> {
    let mut data = Vec::new();
    data.extend_from_slice(&self.client_random);
    data.extend_from_slice(server_random);
    
    let session_id = hkdf::derive_key(&[&data], b"session-id", 32)?;
    // ...
}
```

### 3.4 Handshake Confirmation

```
confirmation = HKDF-Expand(
    ikm = shared_secret,
    info = "handshake-confirmation",
    length = 32
)
```

**Source:** `src/protocol/handshake.rs:271-282`

**Note:** Used for mutual authentication, not for key derivation

## 4. Hybrid KEM Key Combination

### 4.1 Shared Secret Combination

**Formula:**
```
combined_shared_secret = HKDF-Expand(
    ikm = kyber_shared_secret || x25519_shared_secret,
    info = "B4AE-v1-hybrid-kem",
    length = 32
)
```

**Source:** `src/crypto/hybrid.rs:244-248` (encapsulate), `src/crypto/hybrid.rs:283-287` (decapsulate)

**Concatenation Order:** `kyber_ss || x25519_ss`

**Implementation:**
```rust
let combined_ss = hkdf::derive_key(
    &[kyber_ss.as_bytes(), x25519_ss.as_bytes()],
    b"B4AE-v1-hybrid-kem",
    32
)?;
```

**Security Rationale:** Defense in depth - security holds if either Kyber OR X25519 is secure

## 5. Double Ratchet Key Derivation

### 5.1 Initial Root Key

```
root_key = HKDF-Expand(
    ikm = master_secret,
    info = "B4AE-v2-double-ratchet-root",
    length = 32
)
```

**Source:** `src/crypto/double_ratchet/root_key_manager.rs:35-39`

**Implementation:**
```rust
let root_key_vec = derive_key(
    &[master_secret],
    b"B4AE-v2-double-ratchet-root",
    32,
)?;
```

### 5.2 Initial Chain Keys

#### 5.2.1 Initial Sending Chain Key

```
sending_chain_key_0 = HKDF-Expand(
    ikm = master_secret,
    info = "B4AE-v2-sending-chain-0",
    length = 32
)
```

**Source:** `src/crypto/double_ratchet/session.rs:117-121`

#### 5.2.2 Initial Receiving Chain Key

```
receiving_chain_key_0 = HKDF-Expand(
    ikm = master_secret,
    info = "B4AE-v2-receiving-chain-0",
    length = 32
)
```

**Source:** `src/crypto/double_ratchet/session.rs:123-127`

### 5.3 Root Key Ratchet Step

#### 5.3.1 Hybrid Shared Secret Combination

```
hybrid_shared_secret = kyber_shared_secret || x25519_shared_secret
```

**Source:** `src/crypto/double_ratchet/root_key_manager.rs:62-67`

**Concatenation Order:** Kyber first, X25519 second

**Implementation:**
```rust
let mut hybrid_shared_secret = Vec::with_capacity(
    kyber_shared_secret.len() + x25519_shared_secret.len()
);
hybrid_shared_secret.extend_from_slice(kyber_shared_secret);
hybrid_shared_secret.extend_from_slice(x25519_shared_secret);
```

#### 5.3.2 New Root Key Derivation

```
root_key_{n+1} = HKDF-Expand(
    ikm = root_key_n || hybrid_shared_secret,
    info = "B4AE-v2-root-ratchet",
    length = 32
)
```

**Source:** `src/crypto/double_ratchet/root_key_manager.rs:69-74`

**Implementation:**
```rust
let new_root_key_vec = derive_key(
    &[&self.root_key, &hybrid_shared_secret],
    b"B4AE-v2-root-ratchet",
    32,
)?;
```

**Concatenation Order:** `old_root_key || hybrid_ss`

#### 5.3.3 New Sending Chain Key

```
sending_chain_key_{n+1} = HKDF-Expand(
    ikm = root_key_{n+1},
    info = "B4AE-v2-sending-chain",
    length = 32
)
```

**Source:** `src/crypto/double_ratchet/root_key_manager.rs:79-83`

#### 5.3.4 New Receiving Chain Key

```
receiving_chain_key_{n+1} = HKDF-Expand(
    ikm = root_key_{n+1},
    info = "B4AE-v2-receiving-chain",
    length = 32
)
```

**Source:** `src/crypto/double_ratchet/root_key_manager.rs:86-90`

### 5.4 Message Key Derivation

#### 5.4.1 Message Key Material

```
message_key_material = HKDF-Expand(
    ikm = chain_key || counter_bytes,
    info = "B4AE-v2-message-key",
    length = 64
)
```

**Source:** `src/crypto/double_ratchet/chain_key_ratchet.rs:68-73`

**Counter Encoding:** Big-endian u64 (8 bytes)

**Implementation:**
```rust
let counter_bytes = self.message_counter.to_be_bytes();
let message_key_material = derive_key(
    &[&self.chain_key, &counter_bytes],
    b"B4AE-v2-message-key",
    64,
)?;
```

**Concatenation Order:** `chain_key || counter_bytes`

#### 5.4.2 Key Splitting

```
encryption_key = message_key_material[0..32]   // First 32 bytes
auth_key = message_key_material[32..64]        // Last 32 bytes
```

**Source:** `src/crypto/double_ratchet/chain_key_ratchet.rs:76-78`

### 5.5 Chain Key Advancement

```
chain_key_{n+1} = HKDF-Expand(
    ikm = chain_key_n,
    info = "B4AE-v2-chain-advance",
    length = 32
)
```

**Source:** `src/crypto/double_ratchet/chain_key_ratchet.rs:87-91`

**Implementation:**
```rust
let next_chain_key_vec = derive_key(
    &[&self.chain_key],
    b"B4AE-v2-chain-advance",
    32,
)?;
```

**Security:** One-way function ensures forward secrecy

### 5.6 Nonce Derivation

```
nonce = HKDF-Expand(
    ikm = encryption_key || counter_bytes,
    info = "B4AE-v2-nonce",
    length = 12
)
```

**Source:** `src/crypto/double_ratchet/session.rs:167-173`

**Counter Encoding:** Big-endian u64 (8 bytes)

**Implementation:**
```rust
let counter_bytes = message_counter.to_be_bytes();
let nonce_vec = derive_key(
    &[&message_key.encryption_key, &counter_bytes],
    b"B4AE-v2-nonce",
    12,
)?;
```

**Concatenation Order:** `encryption_key || counter_bytes`

## 6. Domain Separation

### 6.1 Info String Mapping

| Purpose                    | Info String                      | Length | Source                                    |
|----------------------------|----------------------------------|--------|-------------------------------------------|
| Master secret              | `B4AE-v1-master-secret`          | 32     | handshake.rs:292                          |
| Encryption key             | `B4AE-v1-encryption-key`         | 32     | hkdf.rs:105                               |
| Authentication key         | `B4AE-v1-authentication-key`     | 32     | hkdf.rs:113                               |
| Metadata key               | `B4AE-v1-metadata-key`           | 32     | hkdf.rs:121                               |
| Session ID                 | `session-id`                     | 32     | handshake.rs:313                          |
| Handshake confirmation     | `handshake-confirmation`         | 32     | handshake.rs:277                          |
| Hybrid KEM                 | `B4AE-v1-hybrid-kem`             | 32     | hybrid.rs:246                             |
| Double ratchet root        | `B4AE-v2-double-ratchet-root`    | 32     | root_key_manager.rs:37                    |
| Initial sending chain      | `B4AE-v2-sending-chain-0`        | 32     | session.rs:119                            |
| Initial receiving chain    | `B4AE-v2-receiving-chain-0`      | 32     | session.rs:125                            |
| Root ratchet               | `B4AE-v2-root-ratchet`           | 32     | root_key_manager.rs:72                    |
| Sending chain              | `B4AE-v2-sending-chain`          | 32     | root_key_manager.rs:81                    |
| Receiving chain            | `B4AE-v2-receiving-chain`        | 32     | root_key_manager.rs:88                    |
| Message key                | `B4AE-v2-message-key`            | 64     | chain_key_ratchet.rs:71                   |
| Chain advance              | `B4AE-v2-chain-advance`          | 32     | chain_key_ratchet.rs:89                   |
| Nonce                      | `B4AE-v2-nonce`                  | 12     | session.rs:171                            |

### 6.2 Version Separation

- **v1:** Handshake and session establishment
- **v2:** Double Ratchet protocol

**Rationale:** Allows protocol evolution while maintaining backward compatibility

### 6.3 Context Separation

Info strings provide cryptographic domain separation:
- Different purposes use different info strings
- Prevents key reuse across contexts
- Enables security proofs in random oracle model

## 7. Encoding Schemes

### 7.1 Integer Encoding

**All integers use big-endian encoding:**

```rust
// u64 counter encoding
let counter_bytes = counter.to_be_bytes();  // 8 bytes, big-endian

// u16 protocol version
let version_bytes = PROTOCOL_VERSION.to_be_bytes();  // 2 bytes, big-endian

// u32 length prefix
let length_bytes = (length as u32).to_be_bytes();  // 4 bytes, big-endian
```

**Sources:**
- `src/crypto/double_ratchet/chain_key_ratchet.rs:69`
- `src/crypto/double_ratchet/session.rs:168`
- `src/protocol/handshake.rs:207`

### 7.2 Byte Array Concatenation

**Order matters for security:**

```
// Correct order (as implemented)
data = A || B || C

// Incorrect (would break security)
data = C || B || A
```

**Examples:**
- Salt: `client_random || server_random` (not reversed)
- Hybrid SS: `kyber_ss || x25519_ss` (Kyber first)
- IKM: `root_key || hybrid_ss` (root key first)

## 8. Key Lengths

### 8.1 Symmetric Keys

| Key Type           | Length (bytes) | Length (bits) |
|--------------------|----------------|---------------|
| Root key           | 32             | 256           |
| Chain key          | 32             | 256           |
| Encryption key     | 32             | 256           |
| Authentication key | 32             | 256           |
| Metadata key       | 32             | 256           |
| Master secret      | 32             | 256           |
| Session ID         | 32             | 256           |

### 8.2 Asymmetric Keys

| Key Type              | Public Key (bytes) | Secret Key (bytes) | Ciphertext (bytes) |
|-----------------------|--------------------|--------------------|--------------------|
| Kyber-1024            | 1568               | 3168               | 1568               |
| X25519                | 32                 | 32                 | 32 (ephemeral)     |
| Dilithium5            | 2592               | 4864               | N/A                |
| Ed25519               | 32                 | 83 (PKCS#8)        | N/A                |

**Sources:**
- Kyber: `src/crypto/kyber.rs`
- X25519: `src/crypto/hybrid.rs:18`
- Dilithium: `src/crypto/dilithium.rs`
- Ed25519: `src/crypto/hybrid.rs:20-22`

### 8.3 Nonces and Tags

| Type                  | Length (bytes) |
|-----------------------|----------------|
| ChaCha20 nonce        | 12             |
| Poly1305 tag          | 16             |
| Client/Server random  | 32             |

## 9. Salt Usage

### 9.1 Handshake Salt

```
salt = client_random || server_random  // 64 bytes
```

**Purpose:** Binds master secret to specific handshake instance  
**Source:** `src/protocol/handshake.rs:290-292`

### 9.2 Empty Salt (Default)

```rust
// Source: src/crypto/hkdf.rs:18
let hkdf = Hkdf::<Sha3_256>::new(None, &ikm);
```

**When used:** All derivations except master_secret  
**RFC 5869:** Empty salt is acceptable, equivalent to string of zeros

## 10. Key Derivation Tree

```
master_secret (from handshake)
├── encryption_key (B4AE-v1-encryption-key)
├── authentication_key (B4AE-v1-authentication-key)
├── metadata_key (B4AE-v1-metadata-key)
└── root_key_0 (B4AE-v2-double-ratchet-root)
    ├── sending_chain_key_0 (B4AE-v2-sending-chain-0)
    │   ├── message_key_0 (B4AE-v2-message-key, counter=0)
    │   │   ├── encryption_key [0..32]
    │   │   ├── auth_key [32..64]
    │   │   └── nonce (B4AE-v2-nonce)
    │   ├── chain_key_1 (B4AE-v2-chain-advance)
    │   └── message_key_1 (B4AE-v2-message-key, counter=1)
    │       └── ...
    ├── receiving_chain_key_0 (B4AE-v2-receiving-chain-0)
    │   └── (same structure as sending)
    └── [After DH ratchet]
        ├── root_key_1 (B4AE-v2-root-ratchet, with hybrid_ss)
        ├── sending_chain_key_1 (B4AE-v2-sending-chain)
        └── receiving_chain_key_1 (B4AE-v2-receiving-chain)
```

## 11. Security Properties

### 11.1 Forward Secrecy

**Mechanism:** Old keys are zeroized after derivation

```rust
// Source: src/crypto/double_ratchet/root_key_manager.rs:93
self.root_key.zeroize();

// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:94
self.chain_key.zeroize();
```

**Property:** Compromise of current key does not reveal past keys

### 11.2 Post-Compromise Security

**Mechanism:** Fresh entropy from DH ratchet

```rust
// New root key depends on fresh shared secrets
root_key_{n+1} = HKDF(root_key_n || fresh_hybrid_ss, ...)
```

**Property:** Compromise recovery after one DH ratchet step

### 11.3 Key Independence

**Mechanism:** Different info strings for different purposes

**Property:** Compromise of one key type does not reveal other key types

### 11.4 Quantum Resistance

**Mechanism:** Hybrid KEM combines Kyber (PQC) with X25519 (classical)

```
combined_ss = HKDF(kyber_ss || x25519_ss, ...)
```

**Property:** Security holds if either Kyber OR X25519 is secure

## 12. Implementation Notes

### 12.1 Constant-Time Operations

**Not explicitly constant-time:** HKDF operations  
**Rationale:** HKDF operates on public info strings and known-length outputs

**Constant-time where needed:**
```rust
// Source: src/protocol/handshake.rs:598
use subtle::ConstantTimeEq;
let confirmation_valid = complete.confirmation.ct_eq(&expected_confirmation);
```

### 12.2 Zeroization

**All secret keys implement `Zeroize` and `ZeroizeOnDrop`:**

```rust
// Source: src/crypto/double_ratchet/root_key_manager.rs:11
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RootKeyManager { ... }
```

**Explicit zeroization after use:**
```rust
self.root_key.zeroize();
self.chain_key.zeroize();
```

### 12.3 Memory Safety

**Rust guarantees:**
- No buffer overflows in concatenation
- No use-after-free
- No data races (if properly synchronized)

## 13. Test Vectors

### 13.1 Deterministic Derivation Test

```rust
// Source: src/crypto/hkdf.rs:155-165
let ikm = b"input key material";
let info = b"application context";

let key1 = derive_key(&[ikm], info, 32).unwrap();
let key2 = derive_key(&[ikm], info, 32).unwrap();

assert_eq!(key1, key2);  // Same input → same output
```

### 13.2 Different Context Test

```rust
// Source: src/crypto/hkdf.rs:167-175
let key1 = derive_key(&[ikm], b"context1", 32).unwrap();
let key2 = derive_key(&[ikm], b"context2", 32).unwrap();

assert_ne!(key1, key2);  // Different info → different output
```

## 14. References

- RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- NIST SP 800-108: Recommendation for Key Derivation Using Pseudorandom Functions
- Signal Protocol Specification
- Implementation: `src/crypto/hkdf.rs`, `src/crypto/double_ratchet/`
