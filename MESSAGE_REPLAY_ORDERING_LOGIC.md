# B4AE Message Replay and Ordering Logic Specification

**Version:** 1.0  
**Date:** 2026  
**Status:** Implementation-Based Specification

## 1. Overview

This document specifies the message replay protection and out-of-order delivery handling in the B4AE Double Ratchet implementation, extracted from the actual codebase.

**Source Files:**
- `src/crypto/double_ratchet/chain_key_ratchet.rs`
- `src/crypto/double_ratchet/session.rs`
- `src/crypto/double_ratchet/mod.rs`

## 2. Message Metadata

### 2.1 RatchetMessage Structure

```rust
// Source: src/crypto/double_ratchet/session.rs:31-42
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetMessage {
    pub sequence: u64,              // Global message sequence number
    pub message_counter: u64,       // Chain-specific message counter
    pub ratchet_count: u64,         // Current ratchet step count
    pub ratchet_update: Option<RatchetUpdate>,  // Optional DH ratchet
    pub ciphertext: Vec<u8>,        // Encrypted payload
    pub tag: [u8; 16],              // Poly1305 authentication tag
    pub nonce: [u8; 12],            // ChaCha20 nonce
}
```

### 2.2 Counter Semantics

#### 2.2.1 Sequence Number

**Purpose:** Global ordering across all messages in session  
**Scope:** Per-session  
**Monotonicity:** Strictly increasing  
**Source:** `src/crypto/double_ratchet/session.rs:198`

```rust
self.sequence_number += 1;
```

**Usage:**
- Application-level ordering
- Not used for cryptographic operations
- Not validated by protocol (application responsibility)

#### 2.2.2 Message Counter

**Purpose:** Per-chain message ordering and key derivation  
**Scope:** Per-chain (sending or receiving)  
**Monotonicity:** Strictly increasing within chain  
**Reset:** On DH ratchet step  
**Source:** `src/crypto/double_ratchet/chain_key_ratchet.rs:99`

```rust
self.message_counter += 1;
```

**Usage:**
- Key derivation input
- Out-of-order detection
- Replay detection

#### 2.2.3 Ratchet Count

**Purpose:** Track number of DH ratchet steps  
**Scope:** Per-session  
**Monotonicity:** Strictly increasing  
**Never Reset:** Persists across ratchet steps  
**Source:** `src/crypto/double_ratchet/root_key_manager.rs:96`

```rust
self.ratchet_count += 1;
```

**Usage:**
- Replay detection
- Desynchronization detection
- Ratchet ordering

## 3. Out-of-Order Delivery

### 3.1 Sliding Window Protocol

**Maximum Skip:** `MAX_SKIP = 1000` messages  
**Source:** `src/crypto/double_ratchet/mod.rs:23`

```rust
pub const MAX_SKIP: u64 = 1000;
```

**Rationale:** Balance between flexibility and DoS protection

### 3.2 Key Caching Mechanism

#### 3.2.1 Cache Structure

```rust
// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:26-31
pub struct ChainKeyRatchet {
    chain_key: [u8; 32],
    message_counter: u64,
    key_cache: HashMap<u64, MessageKey>,  // Counter → MessageKey
    cache_size_limit: usize,
}
```

**Default Cache Size:** `DEFAULT_CACHE_SIZE = 100` keys  
**Source:** `src/crypto/double_ratchet/mod.rs:26`

**Configurable Range:** [10, 1000] keys  
**Source:** `src/crypto/double_ratchet/session.rs:95-99`

#### 3.2.2 Cache Operations

**Insert:**
```rust
// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:147-159
fn cache_key(&mut self, key: MessageKey) {
    // Enforce cache size limit
    if self.key_cache.len() >= self.cache_size_limit {
        // Remove oldest key (lowest counter)
        if let Some(&oldest_counter) = self.key_cache.keys().min() {
            if let Some(mut old_key) = self.key_cache.remove(&oldest_counter) {
                old_key.encryption_key.zeroize();
                old_key.auth_key.zeroize();
            }
        }
    }
    
    self.key_cache.insert(key.counter, key);
}
```

**Eviction Policy:** Remove oldest (lowest counter) when cache is full

**Retrieve:**
```rust
// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:119-122
if let Some(key) = self.key_cache.remove(&counter) {
    return Ok(Some(key));
}
```

**Note:** Key is removed from cache after retrieval (single-use)

### 3.3 Message Key Derivation for Out-of-Order Messages

```rust
// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:113-145
pub fn get_message_key(&mut self, counter: u64) -> CryptoResult<Option<MessageKey>> {
    // Check if key is in cache
    if let Some(key) = self.key_cache.remove(&counter) {
        return Ok(Some(key));
    }

    // If counter is behind current counter, key is not available
    if counter < self.message_counter {
        return Ok(None);
    }

    // If counter is ahead, check DoS protection
    let skip = counter.saturating_sub(self.message_counter);
    if skip > MAX_SKIP {
        return Err(CryptoError::InvalidInput(
            format!("Counter skip too large - potential DoS (skip: {}, max: {})", 
                skip, MAX_SKIP)
        ));
    }

    // Derive and cache all intermediate keys
    while self.message_counter < counter {
        let key = self.next_message_key()?;
        self.cache_key(key);
    }

    // Derive the requested key
    let key = self.next_message_key()?;
    Ok(Some(key))
}
```

**Algorithm:**
1. Check cache for requested counter
2. If found, return and remove from cache
3. If counter < current, return None (too old)
4. If counter > current:
   - Check skip ≤ MAX_SKIP (DoS protection)
   - Derive and cache all intermediate keys
   - Derive and return requested key

### 3.4 Out-of-Order Scenarios

#### Scenario 1: Message Arrives In Order

```
Current counter: 5
Receive message: counter=5

Action:
1. Derive message_key for counter 5
2. Decrypt message
3. Advance counter to 6
4. No caching needed

Result: ✅ Success
```

#### Scenario 2: Message Arrives Out of Order (Skip Forward)

```
Current counter: 5
Receive message: counter=8

Action:
1. Calculate skip: 8 - 5 = 3
2. Check skip ≤ MAX_SKIP: 3 ≤ 1000 ✅
3. Derive and cache keys for counters 5, 6, 7
4. Derive key for counter 8
5. Decrypt message
6. Advance counter to 9

Cache state: {5, 6, 7}

Result: ✅ Success
```

#### Scenario 3: Delayed Message Arrives (From Cache)

```
Current counter: 9
Cache: {5, 6, 7}
Receive message: counter=6

Action:
1. Check cache for counter 6: Found ✅
2. Remove key from cache
3. Decrypt message
4. Counter remains 9 (no advancement)

Cache state: {5, 7}

Result: ✅ Success
```

#### Scenario 4: Very Old Message (Too Old)

```
Current counter: 100
Cache: {95, 96, 97}
Receive message: counter=50

Action:
1. Check cache: Not found
2. Check counter < current: 50 < 100 ✅
3. Return None (key not available)

Result: ❌ Reject (too old)
```

#### Scenario 5: DoS Attack (Excessive Skip)

```
Current counter: 5
Receive message: counter=1006

Action:
1. Calculate skip: 1006 - 5 = 1001
2. Check skip ≤ MAX_SKIP: 1001 > 1000 ❌
3. Return Error (DoS protection)

Result: ❌ Reject (DoS protection)
```

## 4. Replay Detection

### 4.1 Ratchet Count Validation

```rust
// Source: src/crypto/double_ratchet/session.rs:179-181
if message.ratchet_count < self.root_key_manager.ratchet_count() {
    return Err(CryptoError::AuthenticationFailed);
}
```

**Rule:** Reject messages with old ratchet_count

**Rationale:**
- Prevents replay of messages from previous ratchet epochs
- Detects desynchronization
- Provides ordering across ratchet steps

### 4.2 Message Counter Validation

**Implicit in get_message_key():**

```rust
// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:124-126
if counter < self.message_counter {
    return Ok(None);
}
```

**Rule:** Messages with counter < current_counter are rejected (unless in cache)

**Exception:** Cached keys allow out-of-order delivery within window

### 4.3 Replay Attack Scenarios

#### Scenario 1: Replay Old Message (Same Ratchet)

```
Current state:
  ratchet_count: 5
  message_counter: 100
  cache: {}

Attacker replays:
  ratchet_count: 5
  message_counter: 50

Validation:
1. ratchet_count check: 5 == 5 ✅
2. message_counter check: 50 < 100 ❌
3. Cache check: Not found ❌

Result: ❌ Rejected (counter too old)
```

#### Scenario 2: Replay Old Message (Previous Ratchet)

```
Current state:
  ratchet_count: 5
  message_counter: 100

Attacker replays:
  ratchet_count: 4
  message_counter: 200

Validation:
1. ratchet_count check: 4 < 5 ❌

Result: ❌ Rejected (old ratchet_count)
```

#### Scenario 3: Replay Recent Message (In Cache)

```
Current state:
  ratchet_count: 5
  message_counter: 105
  cache: {100, 101, 102}

Attacker replays:
  ratchet_count: 5
  message_counter: 101

Validation:
1. ratchet_count check: 5 == 5 ✅
2. Cache check: Found ✅
3. Decrypt with cached key
4. Remove key from cache

Result: ✅ Accepted (first time)

Second replay:
1. Cache check: Not found ❌
2. message_counter check: 101 < 105 ❌

Result: ❌ Rejected (key already used)
```

**Conclusion:** Each message can be decrypted at most once

## 5. Cache Management

### 5.1 Cache Size Limits

**Default:** 100 keys  
**Configurable:** [10, 1000] keys  
**Source:** `src/crypto/double_ratchet/session.rs:95-99`

```rust
if config.cache_size < 10 || config.cache_size > 1_000 {
    return Err(CryptoError::InvalidInput(
        format!("Cache size must be between 10 and 1,000, got {}", 
            config.cache_size)
    ));
}
```

### 5.2 Eviction Policy

**Strategy:** Least Recently Used (LRU) by counter value

```rust
// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:149-156
if self.key_cache.len() >= self.cache_size_limit {
    // Remove oldest key (lowest counter)
    if let Some(&oldest_counter) = self.key_cache.keys().min() {
        if let Some(mut old_key) = self.key_cache.remove(&oldest_counter) {
            old_key.encryption_key.zeroize();
            old_key.auth_key.zeroize();
        }
    }
}
```

**Rationale:** Oldest messages are least likely to arrive

### 5.3 Cleanup Operations

#### 5.3.1 Explicit Cleanup

```rust
// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:177-188
pub fn cleanup_old_keys(&mut self, current_counter: u64) {
    let keys_to_remove: Vec<u64> = self.key_cache
        .keys()
        .filter(|&&k| k < current_counter)
        .copied()
        .collect();

    for counter in keys_to_remove {
        if let Some(mut key) = self.key_cache.remove(&counter) {
            key.encryption_key.zeroize();
            key.auth_key.zeroize();
        }
    }
}
```

**Usage:** Called after successful decryption  
**Source:** `src/crypto/double_ratchet/session.rs:221`

```rust
self.receiving_chain.cleanup_old_keys(message.message_counter);
```

**Purpose:** Remove keys that are now too old to be useful

#### 5.3.2 Reset on Ratchet

```rust
// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:163-175
pub fn reset(&mut self, new_chain_key: [u8; 32]) {
    // Securely zeroize old chain key
    self.chain_key.zeroize();

    // Clear and zeroize all cached keys
    for (_, mut key) in self.key_cache.drain() {
        key.encryption_key.zeroize();
        key.auth_key.zeroize();
    }

    // Reset with new chain key
    self.chain_key = new_chain_key;
    self.message_counter = 0;
}
```

**Trigger:** DH ratchet step  
**Effect:** All cached keys are zeroized and removed

## 6. Memory Management

### 6.1 Key Zeroization

**All secret keys are zeroized after use:**

```rust
// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:11-20
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey {
    pub encryption_key: [u8; 32],
    pub auth_key: [u8; 32],
    pub counter: u64,
}
```

**Explicit zeroization:**
```rust
old_key.encryption_key.zeroize();
old_key.auth_key.zeroize();
```

### 6.2 Memory Bounds

**Maximum cache memory:**
```
max_memory = cache_size_limit × sizeof(MessageKey)
           = 1000 × (32 + 32 + 8) bytes
           = 72,000 bytes
           ≈ 70 KB
```

**Maximum skip memory:**
```
max_skip_memory = MAX_SKIP × sizeof(MessageKey)
                = 1000 × 72 bytes
                = 72,000 bytes
                ≈ 70 KB
```

**Total worst-case memory:** ~140 KB per chain (sending + receiving)

### 6.3 DoS Protection

**Protection Mechanisms:**

1. **MAX_SKIP Limit:** Prevents unbounded key derivation
   - Source: `src/crypto/double_ratchet/chain_key_ratchet.rs:130-134`

2. **Cache Size Limit:** Prevents unbounded memory growth
   - Source: `src/crypto/double_ratchet/chain_key_ratchet.rs:147-159`

3. **Handshake Timeout:** Prevents resource exhaustion
   - Source: `src/protocol/handshake.rs:127`

**Attack Scenario:**
```
Attacker sends messages with counters:
  1000, 2000, 3000, 4000, ...

Defense:
1. First message (counter=1000):
   - Skip = 1000 ≤ MAX_SKIP ✅
   - Derive 1000 keys, cache up to cache_size_limit
   
2. Second message (counter=2000):
   - Skip = 1000 ≤ MAX_SKIP ✅
   - Derive 1000 keys, evict old keys
   
3. Third message (counter=3000):
   - Skip = 1000 ≤ MAX_SKIP ✅
   - Derive 1000 keys, evict old keys

Result: Memory bounded, but CPU exhaustion possible
```

**Mitigation:** Application-level rate limiting recommended

## 7. Nonce Derivation

### 7.1 Deterministic Nonce

```rust
// Source: src/crypto/double_ratchet/session.rs:167-173
let counter_bytes = message_counter.to_be_bytes();
let nonce_vec = derive_key(
    &[&message_key.encryption_key, &counter_bytes],
    b"B4AE-v2-nonce",
    12,
)?;
```

**Formula:**
```
nonce = HKDF-Expand(
    ikm = encryption_key || counter_bytes,
    info = "B4AE-v2-nonce",
    length = 12
)
```

**Properties:**
- Deterministic (same key + counter → same nonce)
- Unique per message (counter is unique)
- Bound to encryption key (prevents nonce reuse across keys)

### 7.2 Nonce Uniqueness

**Guarantee:** Each (key, nonce) pair is used at most once

**Proof:**
1. Each message_counter is used at most once per chain
2. Each message_counter derives a unique message_key
3. Nonce is derived from (message_key, message_counter)
4. Therefore, each nonce is unique

**Critical:** ChaCha20 security requires nonce uniqueness

## 8. AAD Construction

### 8.1 Additional Authenticated Data

```rust
// Source: src/crypto/double_ratchet/session.rs:176-178
let mut aad = Vec::with_capacity(16);
aad.extend_from_slice(&message_counter.to_be_bytes());
aad.extend_from_slice(&self.root_key_manager.ratchet_count().to_be_bytes());
```

**Format:**
```
aad = message_counter (8 bytes, big-endian) || 
      ratchet_count (8 bytes, big-endian)
```

**Total Size:** 16 bytes

**Purpose:**
- Bind ciphertext to message metadata
- Prevent message reordering across ratchet steps
- Detect tampering with counters

### 8.2 AAD Verification

```rust
// Source: src/crypto/double_ratchet/session.rs:203-205
let mut aad = Vec::with_capacity(16);
aad.extend_from_slice(&message.message_counter.to_be_bytes());
aad.extend_from_slice(&message.ratchet_count.to_be_bytes());
```

**Verification:** Implicit in AEAD decryption

**Failure:** If AAD doesn't match, Poly1305 verification fails

## 9. Timestamp Handling

### 9.1 Timestamp in RatchetUpdate

```rust
// Source: src/crypto/double_ratchet/session.rs:22-29
pub struct RatchetUpdate {
    pub kyber_public: Vec<u8>,
    pub x25519_public: [u8; 32],
    pub kyber_ciphertext: Option<Vec<u8>>,
    pub ratchet_sequence: u64,
    pub timestamp: u64,  // Unix timestamp in seconds
}
```

**Source:** `src/crypto/double_ratchet/session.rs:234-237`

```rust
timestamp: std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs(),
```

**Usage:**
- Informational (not validated by protocol)
- Application can use for timeout detection
- Not used for cryptographic operations

**Note:** No timestamp validation in current implementation

## 10. Performance Characteristics

### 10.1 Complexity Analysis

**In-order message:**
- Time: O(1) - single key derivation
- Space: O(1) - no caching

**Out-of-order message (skip N):**
- Time: O(N) - derive N intermediate keys
- Space: O(min(N, cache_size)) - cache up to limit

**Cached message:**
- Time: O(1) - cache lookup
- Space: O(1) - remove from cache

**Worst-case (MAX_SKIP):**
- Time: O(1000) - derive 1000 keys
- Space: O(cache_size) - bounded by limit

### 10.2 Benchmarking Considerations

**Factors affecting performance:**
1. Skip distance (N)
2. Cache size
3. HKDF performance
4. Memory allocation

**Recommendation:** Benchmark with realistic skip patterns

## 11. Edge Cases

### 11.1 Counter Overflow

**Type:** u64 (64-bit unsigned integer)  
**Maximum:** 2^64 - 1 = 18,446,744,073,709,551,615

**Overflow scenario:**
```
At 1000 messages/second:
Time to overflow = 2^64 / 1000 / 86400 / 365
                 ≈ 584 million years
```

**Conclusion:** Overflow is not a practical concern

### 11.2 Cache Exhaustion

**Scenario:** Receive many out-of-order messages

**Behavior:**
- Cache fills to cache_size_limit
- Oldest keys are evicted
- Very old messages may become undecryptable

**Mitigation:**
- Increase cache_size (up to 1000)
- Application-level buffering
- Request retransmission

### 11.3 Ratchet During Out-of-Order Window

**Scenario:**
1. Messages 1-100 sent (ratchet_count=0)
2. DH ratchet occurs (ratchet_count=1)
3. Messages 101-200 sent (ratchet_count=1)
4. Message 50 arrives late

**Behavior:**
```
Validation:
  message.ratchet_count (0) < current_ratchet_count (1)
  
Result: ❌ Rejected
```

**Conclusion:** Messages from previous ratchet epoch are rejected

## 12. Security Properties

### 12.1 Replay Resistance

**Property:** Each message can be decrypted at most once

**Mechanism:**
- Cached keys are removed after use
- Old counters are rejected
- Old ratchet_counts are rejected

### 12.2 Reordering Resistance

**Property:** Messages can be processed out-of-order within window

**Mechanism:**
- Key caching
- Bounded skip (MAX_SKIP)
- AAD binds counters to ciphertext

### 12.3 DoS Resistance

**Property:** Bounded resource consumption

**Mechanism:**
- MAX_SKIP limit
- Cache size limit
- Handshake timeout

### 12.4 Forward Secrecy

**Property:** Old keys cannot be derived from current state

**Mechanism:**
- One-way KDF for chain advancement
- Zeroization of old keys
- Cache cleanup

## 13. References

- Signal Protocol: Out-of-order message handling
- RFC 5869: HKDF specification
- ChaCha20-Poly1305: RFC 8439
- Implementation: `src/crypto/double_ratchet/`
