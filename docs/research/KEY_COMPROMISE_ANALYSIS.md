# B4AE Key Compromise Impact Analysis

**Version:** 1.0  
**Date:** 2026  
**Status:** Implementation-Based Specification

## 1. Overview

This document provides a comprehensive analysis of key compromise scenarios in the B4AE protocol, documenting what information leaks under each compromise and what remains secure.

## 2. Key Inventory

### 2.1 Long-Term Keys

| Key Type                  | Size (bytes) | Lifetime      | Storage      | Source                          |
|---------------------------|--------------|---------------|--------------|----------------------------------|
| Dilithium5 Secret Key     | 4864         | Years         | Persistent   | hybrid.rs:289-305               |
| Ed25519 Secret Key (PKCS#8)| 83          | Years         | Persistent   | hybrid.rs:289-305               |
| Kyber1024 Public Key      | 1568         | Per-session   | Ephemeral    | hybrid_dh_ratchet.rs:48-73      |
| X25519 Public Key         | 32           | Per-session   | Ephemeral    | hybrid_dh_ratchet.rs:48-73      |

### 2.2 Session Keys

| Key Type                  | Size (bytes) | Lifetime      | Derivation                      | Source                          |
|---------------------------|--------------|---------------|---------------------------------|----------------------------------|
| Master Secret             | 32           | Per-session   | Handshake KEM                   | handshake.rs:289-293            |
| Encryption Key            | 32           | Per-session   | HKDF(master_secret)             | hkdf.rs:103-108                 |
| Authentication Key        | 32           | Per-session   | HKDF(master_secret)             | hkdf.rs:111-116                 |
| Metadata Key              | 32           | Per-session   | HKDF(master_secret)             | hkdf.rs:119-124                 |
| Session ID                | 32           | Per-session   | HKDF(randoms)                   | handshake.rs:308-318            |

### 2.3 Ratchet Keys

| Key Type                  | Size (bytes) | Lifetime      | Derivation                      | Source                          |
|---------------------------|--------------|---------------|---------------------------------|----------------------------------|
| Root Key                  | 32           | Per-ratchet   | HKDF(old_root, hybrid_ss)       | root_key_manager.rs:69-74       |
| Sending Chain Key         | 32           | Per-ratchet   | HKDF(root_key)                  | root_key_manager.rs:79-83       |
| Receiving Chain Key       | 32           | Per-ratchet   | HKDF(root_key)                  | root_key_manager.rs:86-90       |
| Message Encryption Key    | 32           | Per-message   | HKDF(chain_key, counter)[0..32] | chain_key_ratchet.rs:68-78      |
| Message Auth Key          | 32           | Per-message   | HKDF(chain_key, counter)[32..64]| chain_key_ratchet.rs:68-78      |

## 3. Compromise Scenarios

### 3.1 Scenario 1: Long-Term Identity Key Compromise

#### 3.1.1 Compromised Assets

```
Attacker obtains:
- Dilithium5 secret key (4864 bytes)
- Ed25519 secret key (83 bytes, PKCS#8)
```

**Source:** `src/crypto/hybrid.rs:289-305`

#### 3.1.2 What Leaks

**Immediate Impact:**
1. **Future Impersonation:** Attacker can impersonate victim in new handshakes
2. **Active MITM:** Attacker can perform MITM on future sessions
3. **Signature Forgery:** Attacker can forge signatures as victim

**Does NOT Leak:**
- Past session keys (ephemeral key exchange)
- Past messages (forward secrecy)
- Current active sessions (use ephemeral keys)
- Other users' keys

#### 3.1.3 What Remains Secure

✅ **Past Sessions:**
- All past master secrets (ephemeral key exchange)
- All past messages (cannot decrypt without session keys)
- Past session keys (not derivable from identity keys)

✅ **Current Sessions:**
- Active session keys (derived from ephemeral keys)
- Current messages (use session-specific keys)

✅ **Other Parties:**
- Other users' identity keys
- Other users' sessions

#### 3.1.4 Attack Scenarios

**Attack 1: Impersonate Victim**
```
Attacker → Bob: "I am Alice" (using Alice's compromised key)
Bob → Attacker: Establishes session believing it's Alice
Result: ✅ Attack succeeds
```

**Attack 2: Decrypt Past Traffic**
```
Attacker has: Alice's identity key + recorded past traffic
Attacker tries: Decrypt past messages
Result: ❌ Attack fails (ephemeral keys unknown)
```

**Attack 3: MITM Future Sessions**
```
Alice → Attacker → Bob
Attacker uses Alice's key to impersonate Alice to Bob
Attacker uses own key to impersonate Bob to Alice
Result: ✅ Attack succeeds (active MITM)
```

#### 3.1.5 Recovery

**Steps:**
1. Detect compromise (out-of-band)
2. Revoke compromised identity key
3. Generate new identity keypair
4. Distribute new public key
5. Re-establish trust (out-of-band verification)

**Timeline:** Depends on detection and key distribution

### 3.2 Scenario 2: Master Secret Compromise

#### 3.2.1 Compromised Assets

```
Attacker obtains:
- master_secret (32 bytes)
```

**Derivation:** `src/protocol/handshake.rs:289-293`

#### 3.2.2 What Leaks

**Immediate Impact:**
1. **Session Keys:** All keys derived from master_secret
   - encryption_key
   - authentication_key
   - metadata_key
   - session_id

2. **Initial Ratchet State:**
   - root_key_0
   - sending_chain_key_0
   - receiving_chain_key_0

3. **Current Messages:** Messages encrypted with derived keys

**Derivation Chain:**
```
master_secret
├── encryption_key (B4AE-v1-encryption-key)
├── authentication_key (B4AE-v1-authentication-key)
├── metadata_key (B4AE-v1-metadata-key)
└── root_key_0 (B4AE-v2-double-ratchet-root)
    ├── sending_chain_key_0 (B4AE-v2-sending-chain-0)
    └── receiving_chain_key_0 (B4AE-v2-receiving-chain-0)
```

**Source:** `src/crypto/hkdf.rs:103-124`, `src/crypto/double_ratchet/session.rs:117-127`

#### 3.2.3 What Remains Secure

✅ **Past Messages (Before Compromise):**
- Old chain keys (zeroized)
- Old message keys (zeroized)
- Cannot derive backwards

✅ **Future Messages (After DH Ratchet):**
- New root key (depends on fresh ephemeral keys)
- New chain keys (derived from new root key)
- Post-compromise security

✅ **Other Sessions:**
- Different master_secret per session
- Session isolation

#### 3.2.4 Attack Scenarios

**Attack 1: Decrypt Current Messages**
```
Attacker has: master_secret
Attacker derives: encryption_key, authentication_key
Attacker intercepts: Encrypted messages
Result: ✅ Attack succeeds (until DH ratchet)
```

**Attack 2: Decrypt Past Messages**
```
Attacker has: master_secret + recorded past traffic
Attacker tries: Derive old chain keys
Result: ❌ Attack fails (keys zeroized, one-way KDF)
```

**Attack 3: Decrypt Future Messages (After Ratchet)**
```
Attacker has: master_secret
DH ratchet occurs: New ephemeral keys generated
Attacker tries: Derive new root key
Result: ❌ Attack fails (needs ephemeral secret keys)
```

#### 3.2.5 Recovery

**Automatic Recovery:**
- Next DH ratchet step (default: 100 messages)
- Fresh ephemeral keys provide new entropy
- New root key independent of compromised master_secret

**Source:** `src/crypto/double_ratchet/root_key_manager.rs:48-95`

**Timeline:** ≤ 100 messages (configurable)

### 3.3 Scenario 3: Current Ratchet State Compromise

#### 3.3.1 Compromised Assets

```
Attacker obtains:
- root_key (32 bytes)
- sending_chain_key (32 bytes)
- receiving_chain_key (32 bytes)
- message_counter (8 bytes)
- ratchet_count (8 bytes)
- key_cache (HashMap<u64, MessageKey>)
```

**Source:** `src/crypto/double_ratchet/root_key_manager.rs:13-17`, `src/crypto/double_ratchet/chain_key_ratchet.rs:26-31`

#### 3.3.2 What Leaks

**Immediate Impact:**
1. **Current Messages:** Can decrypt all current messages
2. **Future Messages:** Can decrypt until next DH ratchet
3. **Cached Keys:** Can decrypt out-of-order messages in cache
4. **Chain Advancement:** Can derive future message keys in current ratchet epoch

**Attack Capability:**
```
Attacker can:
1. Derive all future message keys until DH ratchet:
   message_key_n = HKDF(chain_key_n, counter_n)
   chain_key_{n+1} = HKDF(chain_key_n, "B4AE-v2-chain-advance")

2. Decrypt all messages in current ratchet epoch

3. Use cached keys for out-of-order messages
```

**Source:** `src/crypto/double_ratchet/chain_key_ratchet.rs:63-99`

#### 3.3.3 What Remains Secure

✅ **Past Messages:**
- Old chain keys (zeroized)
- Old message keys (zeroized)
- One-way KDF prevents backward derivation

✅ **Future Messages (After DH Ratchet):**
- New root key (depends on fresh ephemeral keys)
- New chain keys (derived from new root key)
- Post-compromise security

✅ **Other Sessions:**
- Different ratchet state per session
- Session isolation

#### 3.3.4 Attack Scenarios

**Attack 1: Decrypt Current and Future Messages (Same Ratchet)**
```
Attacker has: chain_key, message_counter
Attacker derives: All future message keys until ratchet
Result: ✅ Attack succeeds
```

**Attack 2: Decrypt Past Messages**
```
Attacker has: current chain_key
Attacker tries: Derive old chain keys (reverse KDF)
Result: ❌ Attack fails (one-way function)
```

**Attack 3: Decrypt After DH Ratchet**
```
Attacker has: old root_key, old chain_keys
DH ratchet occurs: New ephemeral keys generated
Attacker tries: Derive new root_key
Result: ❌ Attack fails (needs ephemeral secret keys)
```

#### 3.3.5 Recovery

**Automatic Recovery:**
- Next DH ratchet step
- Fresh ephemeral keys provide new entropy
- All keys re-derived from new root key

**Source:** `src/crypto/double_ratchet/session.rs:220-245`, `src/crypto/double_ratchet/session.rs:253-283`

**Timeline:** ≤ 100 messages (default ratchet interval)

**Verification:**
```rust
// Source: src/crypto/double_ratchet/root_key_manager.rs:93-96
self.root_key.zeroize();  // Old root key zeroized
self.root_key = new_root_key;
self.ratchet_count += 1;
```

### 3.4 Scenario 4: Single Message Key Compromise

#### 3.4.1 Compromised Assets

```
Attacker obtains:
- encryption_key (32 bytes) for message N
- auth_key (32 bytes) for message N
- counter (8 bytes)
```

**Source:** `src/crypto/double_ratchet/chain_key_ratchet.rs:11-20`

#### 3.4.2 What Leaks

**Immediate Impact:**
1. **Single Message:** Can decrypt message N only
2. **Nonce:** Can derive nonce for message N

**Attack Capability:**
```
Attacker can:
1. Decrypt message N:
   plaintext = ChaCha20Poly1305.decrypt(
       key=encryption_key,
       nonce=derived_nonce,
       ciphertext=ciphertext,
       aad=aad
   )

2. Derive nonce:
   nonce = HKDF(encryption_key || counter, "B4AE-v2-nonce", 12)
```

**Source:** `src/crypto/double_ratchet/session.rs:167-173`, `src/crypto/double_ratchet/session.rs:180-195`

#### 3.4.3 What Remains Secure

✅ **All Other Messages:**
- Different message keys (key independence)
- Cannot derive other keys from single message key

✅ **Chain Key:**
- Message key does not reveal chain key
- One-way derivation

✅ **Root Key:**
- Message key does not reveal root key
- Multiple layers of derivation

✅ **Past and Future Messages:**
- Complete isolation
- No key reuse

#### 3.4.4 Attack Scenarios

**Attack 1: Decrypt Single Message**
```
Attacker has: message_key for message N
Attacker intercepts: Message N
Result: ✅ Attack succeeds (single message only)
```

**Attack 2: Decrypt Other Messages**
```
Attacker has: message_key for message N
Attacker tries: Decrypt message N+1
Result: ❌ Attack fails (different key)
```

**Attack 3: Derive Chain Key**
```
Attacker has: message_key
Attacker tries: Reverse HKDF to get chain_key
Result: ❌ Attack fails (one-way function)
```

#### 3.4.5 Recovery

**Automatic:**
- No recovery needed
- Compromise is isolated to single message
- All other messages remain secure

**Impact:** Minimal (single message confidentiality loss)

### 3.5 Scenario 5: Ephemeral Key Compromise (During Handshake)

#### 3.5.1 Compromised Assets

```
Attacker obtains (during handshake):
- Kyber1024 secret key (3168 bytes)
- X25519 secret key (32 bytes)
```

**Source:** `src/crypto/hybrid.rs:207-230`

#### 3.5.2 What Leaks

**Immediate Impact:**
1. **Current Handshake:** Can derive shared secret
2. **Current Session:** Can derive all session keys
3. **Current Messages:** Can decrypt all messages in session

**Attack Capability:**
```
Attacker can:
1. Decapsulate to get shared secret:
   kyber_ss = Kyber.decapsulate(kyber_sk, kyber_ct)
   x25519_ss = X25519.dh(x25519_sk, peer_public)
   shared_secret = HKDF(kyber_ss || x25519_ss, "B4AE-v1-hybrid-kem")

2. Derive master_secret and all session keys

3. Decrypt all messages in session
```

**Source:** `src/crypto/hybrid.rs:260-287`

#### 3.5.3 What Remains Secure

✅ **Past Sessions:**
- Different ephemeral keys per session
- Session isolation

✅ **Future Sessions:**
- New ephemeral keys generated
- No key reuse

✅ **Other Parties:**
- Different ephemeral keys per party
- Party isolation

#### 3.5.4 Attack Scenarios

**Attack 1: Passive Decryption**
```
Attacker has: ephemeral secret keys
Attacker observes: Handshake (gets peer's public key and ciphertext)
Attacker derives: shared_secret → master_secret → session keys
Result: ✅ Attack succeeds (entire session compromised)
```

**Attack 2: Decrypt Other Sessions**
```
Attacker has: ephemeral keys from session 1
Attacker tries: Decrypt session 2
Result: ❌ Attack fails (different ephemeral keys)
```

#### 3.5.5 Recovery

**Manual:**
- Terminate compromised session
- Initiate new handshake (new ephemeral keys)

**Timeline:** Immediate (new handshake)

### 3.6 Scenario 6: Ephemeral Key Compromise (During Ratchet)

#### 3.6.1 Compromised Assets

```
Attacker obtains (during DH ratchet):
- Kyber1024 ephemeral secret key (3168 bytes)
- X25519 ephemeral secret key (32 bytes)
```

**Source:** `src/crypto/double_ratchet/hybrid_dh_ratchet.rs:48-73`

#### 3.6.2 What Leaks

**Immediate Impact:**
1. **Current Ratchet Step:** Can derive shared secrets
2. **New Root Key:** Can derive new root key
3. **New Chain Keys:** Can derive new chain keys
4. **Future Messages:** Can decrypt until next ratchet

**Attack Capability:**
```
Attacker can:
1. Derive shared secrets:
   kyber_ss = Kyber.decapsulate(kyber_sk, kyber_ct)
   x25519_ss = X25519.dh(x25519_sk, peer_public)

2. Derive new root key:
   hybrid_ss = kyber_ss || x25519_ss
   new_root_key = HKDF(old_root_key || hybrid_ss, "B4AE-v2-root-ratchet")

3. Derive new chain keys and decrypt messages
```

**Source:** `src/crypto/double_ratchet/root_key_manager.rs:48-95`

#### 3.6.3 What Remains Secure

✅ **Past Messages:**
- Old root key and chain keys (zeroized)
- Forward secrecy maintained

✅ **Future Messages (After Next Ratchet):**
- New ephemeral keys generated
- Post-compromise security

#### 3.6.4 Recovery

**Automatic:**
- Next DH ratchet step (new ephemeral keys)
- Default: 100 messages

**Timeline:** ≤ 100 messages

## 4. Compromise Impact Matrix

| Compromised Asset         | Past Msgs | Current Msgs | Future Msgs | Other Sessions | Recovery                |
|---------------------------|-----------|--------------|-------------|----------------|-------------------------|
| Identity Key              | ✅ Secure | ⚠️ MITM      | ⚠️ MITM     | ✅ Secure      | Manual (revoke)         |
| Master Secret             | ✅ Secure | ❌ Leaked    | ✅ After DR | ✅ Secure      | Auto (DH ratchet)       |
| Ratchet State             | ✅ Secure | ❌ Leaked    | ✅ After DR | ✅ Secure      | Auto (DH ratchet)       |
| Message Key               | ✅ Secure | ⚠️ One msg   | ✅ Secure   | ✅ Secure      | None needed             |
| Ephemeral Key (Handshake) | ✅ Secure | ❌ Leaked    | ❌ Leaked   | ✅ Secure      | Manual (new session)    |
| Ephemeral Key (Ratchet)   | ✅ Secure | ❌ Leaked    | ✅ After DR | ✅ Secure      | Auto (next ratchet)     |

**Legend:**
- ✅ Secure: Information remains confidential
- ❌ Leaked: Information is compromised
- ⚠️: Partial compromise or conditional
- DR: DH Ratchet

## 5. Zeroization Analysis

### 5.1 Zeroized Keys

**Automatically zeroized:**

```rust
// Root key after ratchet
// Source: src/crypto/double_ratchet/root_key_manager.rs:93
self.root_key.zeroize();

// Chain key after advancement
// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:94
self.chain_key.zeroize();

// Cached message keys on eviction
// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:153-155
old_key.encryption_key.zeroize();
old_key.auth_key.zeroize();

// All keys on drop
// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:196-203
impl Drop for ChainKeyRatchet {
    fn drop(&mut self) {
        self.chain_key.zeroize();
        for (_, mut key) in self.key_cache.drain() {
            key.encryption_key.zeroize();
            key.auth_key.zeroize();
        }
    }
}
```

### 5.2 Zeroization Guarantees

**What is zeroized:**
- Old root keys (after ratchet)
- Old chain keys (after advancement)
- Message keys (after use or eviction)
- Cached keys (on cleanup or drop)

**What is NOT zeroized:**
- Long-term identity keys (persistent)
- Current active keys (in use)
- Keys in use for decryption

**Timing:**
- Immediate after derivation (for old keys)
- On cache eviction (for cached keys)
- On drop (for all keys in structure)

### 5.3 Memory Dump Resistance

**Scenario:** Attacker obtains memory dump

**What attacker finds:**
- Current active keys (not yet zeroized)
- Keys currently in cache
- Long-term identity keys (if in memory)

**What attacker does NOT find:**
- Old zeroized keys (overwritten with zeros)
- Keys from previous ratchet epochs
- Keys from completed sessions

**Limitation:** Zeroization does not protect against:
- Memory dumps before zeroization
- Swap file persistence
- Memory compression artifacts
- Hardware memory remanence

## 6. Key Derivation Independence

### 6.1 Derivation Graph

```
Identity Keys (long-term)
    ↓ (sign/verify)
Handshake Messages
    ↓ (KEM)
Shared Secret
    ↓ (HKDF)
Master Secret
    ├→ Encryption Key (independent)
    ├→ Authentication Key (independent)
    ├→ Metadata Key (independent)
    └→ Root Key 0
        ├→ Sending Chain Key 0
        │   ├→ Message Key 0 (independent)
        │   ├→ Chain Key 1
        │   │   └→ Message Key 1 (independent)
        │   └→ ...
        └→ Receiving Chain Key 0
            └→ (same structure)
```

**Independence Property:** Compromise of one key does not reveal sibling keys

**Example:**
- Compromise of `encryption_key` does NOT reveal `authentication_key`
- Compromise of `message_key_0` does NOT reveal `message_key_1`
- Compromise of `sending_chain_key` does NOT reveal `receiving_chain_key`

**Mechanism:** Different HKDF info strings provide domain separation

## 7. Post-Compromise Security Timeline

### 7.1 Recovery Timeline

```
Time 0: Compromise occurs
    ↓
    | Messages 1-100 (compromised)
    | Attacker can decrypt
    ↓
Time T: DH Ratchet (message 100)
    | Fresh ephemeral keys generated
    | New root key derived
    | New chain keys derived
    ↓
    | Messages 101-200 (secure)
    | Attacker CANNOT decrypt
    ↓
Time 2T: Next DH Ratchet (message 200)
    | Security maintained
```

**Default Timeline:**
- Ratchet interval: 100 messages
- Configurable: [1, 10000] messages
- **Source:** `src/crypto/double_ratchet/mod.rs:23`, `src/crypto/double_ratchet/session.rs:88-91`

### 7.2 Worst-Case Recovery

**Scenario:** Compromise occurs immediately after DH ratchet

**Timeline:**
```
Message 101: Compromise occurs
Messages 101-200: Compromised (99 messages)
Message 200: DH Ratchet
Messages 201+: Secure
```

**Maximum Exposure:** `ratchet_interval - 1` messages

### 7.3 Best-Case Recovery

**Scenario:** Compromise occurs immediately before DH ratchet

**Timeline:**
```
Message 199: Compromise occurs
Message 200: DH Ratchet
Messages 200+: Secure
```

**Minimum Exposure:** 1 message

## 8. Recommendations

### 8.1 Key Management

1. **Identity Keys:**
   - Store in secure hardware (HSM, TPM)
   - Minimize exposure time
   - Regular rotation (annually)

2. **Session Keys:**
   - Never persist to disk
   - Zeroize immediately after use
   - Use memory locking (mlock)

3. **Ephemeral Keys:**
   - Generate fresh per session/ratchet
   - Zeroize immediately after use
   - Never reuse

### 8.2 Compromise Detection

1. **Monitoring:**
   - Unexpected handshakes
   - Unusual message patterns
   - Authentication failures

2. **Logging:**
   - Handshake events
   - Ratchet events
   - Decryption failures

3. **Alerting:**
   - Multiple failed authentications
   - Unexpected key usage
   - Timing anomalies

### 8.3 Compromise Response

1. **Immediate:**
   - Terminate affected sessions
   - Revoke compromised keys
   - Alert affected parties

2. **Short-term:**
   - Generate new keys
   - Re-establish sessions
   - Verify integrity

3. **Long-term:**
   - Investigate root cause
   - Improve key protection
   - Update security policies

## 9. References

- Signal Protocol: Post-Compromise Security
- NIST SP 800-57: Key Management Recommendations
- Implementation: `src/crypto/double_ratchet/`, `src/protocol/handshake.rs`
