# B4AE v2.0 Protocol State Machine Specification

**Version:** 2.0  
**Date:** 2026  
**Status:** Research-Grade Formal Specification

## 1. Overview

This document specifies the complete state machine for B4AE v2.0 protocol, including the 5-phase handshake, mode negotiation, cookie challenge, and double ratchet session management.

**Key Changes from v1.0:**
- **5-phase handshake:** INIT → MODE_NEGOTIATION → COOKIE_CHALLENGE → HANDSHAKE → ESTABLISHED
- **Mode negotiation:** Separate authentication modes (Mode A deniable, Mode B PQ)
- **Cookie challenge:** Stateless DoS protection before expensive crypto
- **Session binding:** Keys bound to unique session_id
- **Global traffic scheduler:** Unified traffic management across sessions

**v1.0 State Machine (Deprecated):**
```
INIT → INITIATION → RESPONSE → COMPLETE → ESTABLISHED
```

**v2.0 State Machine (Current):**
```
INIT → MODE_NEGOTIATION → COOKIE_CHALLENGE → HANDSHAKE → ESTABLISHED
```

---

## 2. Handshake State Machine (v2.0)

### 2.1 States

```
HandshakeState (v2.0)
├── Init                    // Initial state
├── ModeNegotiation        // Negotiating authentication mode
├── CookieChallenge        // Solving cookie challenge
├── Handshake              // Performing mode-specific handshake
├── Established            // Session established
└── Failed                 // Handshake failed
```

**Source:** `src/protocol/v2/handshake.rs`

### 2.2 State Transitions (Initiator/Client)

```
[INIT] Init
   |
   | send_mode_negotiation()
   | - Generate client_random (32 bytes)
   | - Send supported modes + preferred mode
   v
[MODE_NEG] ModeNegotiation
   |
   | receive_mode_selection()
   | - Verify selected mode is compatible
   | - Compute mode_binding
   v
[COOKIE] CookieChallenge
   |
   | send_client_hello()
   | - Send minimal data (client_random + timestamp)
   |
   | receive_cookie_challenge()
   | - Receive cookie from server
   |
   | send_client_hello_with_cookie()
   | - Return cookie + HandshakeInit
   v
[HANDSHAKE] Handshake
   |
   | Mode A: XEdDSA signature
   | Mode B: Dilithium5 signature
   |
   | receive_handshake_response()
   | - Verify mode-specific signature
   | - Decapsulate KEM
   v
[ESTABLISHED] Established
   |
   | derive_session_keys()
   | - session_id = HKDF(randoms || mode_id)
   | - Bind keys to session_id
```

### 2.3 State Transitions (Responder/Server)

```
[INIT] Init
   |
   | receive_mode_negotiation()
   | - Compute intersection of supported modes
   | - Select mode (prefer client's preferred if compatible)
   v
[MODE_NEG] ModeNegotiation
   |
   | send_mode_selection()
   | - Send selected mode + server_random
   | - Compute mode_binding
   v
[COOKIE] CookieChallenge
   |
   | receive_client_hello()
   | - Generate cookie = HMAC(secret, client_ip || timestamp || client_random)
   | - Send cookie (stateless, no state stored)
   |
   | receive_client_hello_with_cookie()
   | - Verify cookie (cheap ~0.01ms)
   | - Check Bloom filter for replay
   v
[HANDSHAKE] Handshake
   |
   | Mode A: Verify XEdDSA signature
   | Mode B: Verify Dilithium5 signature
   |
   | send_handshake_response()
   | - Generate mode-specific signature
   | - Encapsulate KEM
   v
[ESTABLISHED] Established
   |
   | derive_session_keys()
   | - session_id = HKDF(randoms || mode_id)
   | - Bind keys to session_id
```

### 2.4 Transition Table (Initiator)

| Current State | Event | Next State | Action | Cost |
|---------------|-------|------------|--------|------|
| Init | send_mode_negotiation() | ModeNegotiation | Generate client_random, send modes | ~0.01ms |
| ModeNegotiation | receive_mode_selection() | CookieChallenge | Verify mode, compute mode_binding | ~0.01ms |
| CookieChallenge | send_client_hello() | CookieChallenge | Send minimal data | ~0.01ms |
| CookieChallenge | receive_cookie_challenge() | CookieChallenge | Receive cookie | ~0.01ms |
| CookieChallenge | send_client_hello_with_cookie() | Handshake | Send cookie + HandshakeInit | ~0.1-5ms |
| Handshake | receive_handshake_response() | Established | Verify signature, decapsulate KEM | ~0.2-5ms |
| Established | derive_session_keys() | Established | Derive keys with session binding | ~0.1ms |
| * | timeout | Failed | Timeout exceeded (30s default) | - |
| * | error | Failed | Error occurred | - |

### 2.5 Transition Table (Responder)

| Current State | Event | Next State | Action | Cost |
|---------------|-------|------------|--------|------|
| Init | receive_mode_negotiation() | ModeNegotiation | Compute mode intersection | ~0.01ms |
| ModeNegotiation | send_mode_selection() | CookieChallenge | Select mode, send server_random | ~0.01ms |
| CookieChallenge | receive_client_hello() | CookieChallenge | Generate cookie (stateless) | ~0.01ms |
| CookieChallenge | receive_client_hello_with_cookie() | Handshake | Verify cookie (cheap) | ~0.01ms |
| Handshake | verify_signature() | Handshake | Verify mode-specific signature | ~0.2-5ms |
| Handshake | send_handshake_response() | Established | Generate signature, encapsulate KEM | ~0.1-5ms |
| Established | derive_session_keys() | Established | Derive keys with session binding | ~0.1ms |
| * | timeout | Failed | Timeout exceeded (30s default) | - |
| * | invalid_cookie | Failed | Cookie verification failed | ~0.01ms |
| * | error | Failed | Error occurred | - |

### 2.6 Performance Comparison: v1.0 vs v2.0

| Phase | v1.0 | v2.0 Mode A | v2.0 Mode B |
|-------|------|-------------|-------------|
| Mode Negotiation | N/A | ~0.02ms | ~0.02ms |
| Cookie Challenge | N/A | ~0.03ms | ~0.03ms |
| Handshake (signatures) | ~9.3ms (XEdDSA + Dilithium5) | ~0.3ms (XEdDSA only) | ~9ms (Dilithium5 only) |
| Key Derivation | ~0.1ms | ~0.1ms | ~0.1ms |
| **Total** | **~9.4ms** | **~0.45ms** | **~9.15ms** |

**Key Improvements:**
- Mode A: **20x faster** than v1.0 (0.45ms vs 9.4ms)
- Mode B: Similar performance to v1.0 but with clear security properties
- Cookie challenge adds minimal overhead (~0.03ms) but provides 360x DoS protection

---

## 3. Ratchet State Machine

### 3.1 States

```
RatchetState (src/crypto/double_ratchet/session.rs:14-28)
├── Active                    // Normal operation
├── RatchetPending           // DH ratchet initiated, waiting for ack
│   ├── pending_update       // RatchetUpdate to send
│   └── sent_at              // Timestamp
├── RatchetReceived          // DH ratchet received, processing
│   ├── received_update      // RatchetUpdate from peer
│   └── processed            // Processing status
└── Error(String)            // Error state with message
```

### 3.2 Ratchet State Transitions

```
[ACTIVE] Active
   |
   | should_ratchet() == true
   | (message_counter % ratchet_interval == 0)
   v
[PENDING] RatchetPending
   |
   | peer processes ratchet_update
   v
[ACTIVE] Active
```

```
[ACTIVE] Active
   |
   | receive message with ratchet_update
   v
[RECEIVED] RatchetReceived
   |
   | process_ratchet_update()
   v
[ACTIVE] Active
```

### 3.3 Ratchet Transition Conditions

**Sender-Initiated Ratchet:**
```
Condition: message_counter > 0 && message_counter % ratchet_interval == 0
Source: src/crypto/double_ratchet/hybrid_dh_ratchet.rs:95-97

if message_count > 0 && message_count % self.ratchet_interval == 0 {
    return true;
}
```

**Receiver-Initiated Ratchet:**
```
Condition: message.ratchet_update.is_some()
Source: src/crypto/double_ratchet/session.rs:186-188

if let Some(ref update) = message.ratchet_update {
    self.process_ratchet_update(update)?;
}
```

### 3.4 Ratchet Sequence Diagram

```
Alice                                    Bob
  |                                       |
  | [ACTIVE]                              | [ACTIVE]
  |                                       |
  | message_counter = 100                 |
  | should_ratchet() = true               |
  |                                       |
  | initiate_ratchet()                    |
  | - generate Kyber keypair              |
  | - generate X25519 keypair             |
  | - create RatchetUpdate                |
  |                                       |
  | [RATCHET_PENDING]                     |
  |                                       |
  | -------- RatchetMessage ----------->  |
  |          (with ratchet_update)        |
  |                                       | [RATCHET_RECEIVED]
  |                                       |
  |                                       | process_ratchet_update()
  |                                       | - derive shared secrets
  |                                       | - ratchet root key
  |                                       | - reset chain keys
  |                                       |
  |                                       | [ACTIVE]
  | [ACTIVE]                              |
  |                                       |
```

## 4. Chain Key Ratchet State

### 4.1 Chain State Variables

```rust
// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:26-31
struct ChainKeyRatchet {
    chain_key: [u8; 32],           // Current chain key
    message_counter: u64,          // Current message counter
    key_cache: HashMap<u64, MessageKey>,  // Cached skipped keys
    cache_size_limit: usize,       // Maximum cache size
}
```

### 4.2 Chain Advancement State Machine

```
[COUNTER=N] chain_key=K_N
   |
   | next_message_key()
   | - derive message_key from K_N
   | - derive K_{N+1} from K_N
   | - zeroize K_N
   v
[COUNTER=N+1] chain_key=K_{N+1}
```

### 4.3 Out-of-Order Message Handling

```
Scenario: Receive message with counter M where M > current_counter

[COUNTER=N] Current state
   |
   | get_message_key(M) where M > N
   | skip = M - N
   |
   | if skip > MAX_SKIP (1000):
   |     return Error (DoS protection)
   |
   | while counter < M:
   |     derive and cache message_key
   |     advance counter
   v
[COUNTER=M+1] Advanced state
   |
   | key_cache contains keys for [N, M-1]
```

**DoS Protection:**
```
MAX_SKIP = 1000  // src/crypto/double_ratchet/mod.rs:23
```

## 5. Root Key Ratchet State

### 5.1 Root Key State Variables

```rust
// Source: src/crypto/double_ratchet/root_key_manager.rs:13-17
struct RootKeyManager {
    root_key: [u8; 32],      // Current root key
    ratchet_count: u64,      // Number of ratchet steps performed
}
```

### 5.2 Root Key Ratchet Transition

```
[ROOT_KEY=RK_N, COUNT=N]
   |
   | ratchet_step(kyber_ss, x25519_ss)
   | - hybrid_ss = kyber_ss || x25519_ss
   | - RK_{N+1} = HKDF(RK_N || hybrid_ss, "B4AE-v2-root-ratchet")
   | - sending_key = HKDF(RK_{N+1}, "B4AE-v2-sending-chain")
   | - receiving_key = HKDF(RK_{N+1}, "B4AE-v2-receiving-chain")
   | - zeroize RK_N
   v
[ROOT_KEY=RK_{N+1}, COUNT=N+1]
```

**Source:** `src/crypto/double_ratchet/root_key_manager.rs:48-95`

## 6. Session Initialization State

### 6.1 Initialization Sequence

```
[UNINITIALIZED]
   |
   | from_handshake(master_secret, session_id, config)
   |
   | 1. Validate config parameters
   | 2. Initialize RootKeyManager from master_secret
   | 3. Derive initial chain keys:
   |    - sending_chain_key = HKDF(master_secret, "B4AE-v2-sending-chain-0")
   |    - receiving_chain_key = HKDF(master_secret, "B4AE-v2-receiving-chain-0")
   | 4. Initialize ChainKeyRatchets
   | 5. Initialize HybridDHRatchet
   v
[INITIALIZED: ACTIVE, ratchet_count=0, sequence=0]
```

**Source:** `src/crypto/double_ratchet/session.rs:78-145`

## 7. Configuration Validation

### 7.1 Valid Configuration Ranges

```
ratchet_interval: [1, 10000]
cache_size: [10, 1000]
max_skip: [100, 10000]
```

**Source:** `src/crypto/double_ratchet/session.rs:88-107`

### 7.2 Configuration Validation State Machine

```
[CONFIG_INPUT]
   |
   | validate ratchet_interval
   | if not in [1, 10000]: return Error
   |
   | validate cache_size
   | if not in [10, 1000]: return Error
   |
   | validate max_skip
   | if not in [100, 10000]: return Error
   v
[CONFIG_VALID]
```

## 8. Error States and Recovery

### 8.1 Error Conditions

| Error Condition              | State Transition           | Recovery                    |
|------------------------------|----------------------------|-----------------------------|
| Invalid ratchet_count        | → Error                    | Reject message              |
| Counter skip > MAX_SKIP      | → Error                    | Reject message              |
| Signature verification fail  | → Failed                   | Restart handshake           |
| Decryption failure           | → Error                    | Request retransmission      |
| Timeout exceeded             | → Failed                   | Restart handshake           |

### 8.2 Desynchronization Detection

```
Condition: message.ratchet_count < local_ratchet_count
Action: Reject message (potential replay or desync)
Source: src/crypto/double_ratchet/session.rs:179-181
```

## 9. Timing Constraints

### 9.1 Handshake Timeout

```
Default: 30000 ms (30 seconds)
Source: src/protocol/handshake.rs:127
Configurable: HandshakeConfig.timeout_ms
```

### 9.2 Timeout Check

```rust
// Source: src/protocol/handshake.rs:332-335
pub fn is_timed_out(&self) -> bool {
    let current_time = time::current_time_millis();
    current_time - self.start_time > self.config.timeout_ms
}
```

## 10. State Invariants

### 10.1 Handshake Invariants

1. **Monotonic Progress:** State transitions only move forward (no backward transitions)
2. **Single Completion:** Once Completed, state cannot change
3. **Timeout Universality:** Any state can transition to Failed on timeout

### 10.2 Ratchet Invariants

1. **Counter Monotonicity:** `message_counter` never decreases
2. **Ratchet Count Monotonicity:** `ratchet_count` never decreases
3. **Key Uniqueness:** Each message uses a unique message key
4. **Forward Secrecy:** Old chain keys are zeroized after advancement

### 10.3 Cache Invariants

1. **Size Limit:** `key_cache.len() <= cache_size_limit`
2. **Counter Validity:** All cached keys have `counter < message_counter`
3. **No Duplicates:** Each counter appears at most once in cache

## 11. Concurrency Considerations

### 11.1 Thread Safety

**Not Thread-Safe:** `DoubleRatchetSession`, `ChainKeyRatchet`, `RootKeyManager`
**Reason:** Mutable state without internal synchronization
**Usage:** Wrap in `Mutex` or `RwLock` for concurrent access

### 11.2 ZK Verifier Thread Safety

```rust
// Source: src/protocol/handshake.rs:115
pub zk_verifier: Option<Arc<Mutex<zkauth::ZkVerifier>>>,
```

**Thread-Safe:** ZkVerifier is wrapped in `Arc<Mutex<_>>`

## 12. State Persistence

### 12.1 Serializable State

```rust
// Source: src/crypto/double_ratchet/session.rs:31-42
#[derive(Serialize, Deserialize)]
pub struct RatchetMessage {
    pub sequence: u64,
    pub message_counter: u64,
    pub ratchet_count: u64,
    pub ratchet_update: Option<RatchetUpdate>,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
    pub nonce: [u8; 12],
}
```

### 12.2 Non-Serializable State

- `DoubleRatchetSession` (contains secret keys)
- `ChainKeyRatchet` (contains chain_key)
- `RootKeyManager` (contains root_key)

**Security:** Secret keys must not be serialized without encryption

## 13. State Diagram Legend

```
[STATE]     - State node
   |        - Transition
   v        - Direction
Condition   - Transition condition
Action      - Transition action
```

## 14. References

- Signal Protocol Specification: https://signal.org/docs/
- Double Ratchet Algorithm: https://signal.org/docs/specifications/doubleratchet/
- Implementation: `src/crypto/double_ratchet/`

## 3. Mode Negotiation State Machine

### 3.1 Mode Selection Algorithm

```
[RECEIVE_NEGOTIATION]
   |
   | supported_client = {Mode_A, Mode_B}
   | supported_server = {Mode_A, Mode_B}
   | preferred_client = Mode_A
   |
   | intersection = supported_client ∩ supported_server
   v
[COMPUTE_INTERSECTION]
   |
   | IF intersection = ∅ THEN
   |   → [FAILED] "No compatible authentication modes"
   |
   | IF preferred_client ∈ intersection THEN
   |   selected = preferred_client
   | ELSE
   |   selected = highest_security(intersection)
   |   // Priority: Mode_B > Mode_A > Mode_C
   v
[MODE_SELECTED]
   |
   | mode_binding = SHA3-256(
   |   "B4AE-v2-mode-binding" ||
   |   client_random ||
   |   server_random ||
   |   mode_id
   | )
   v
[MODE_BOUND]
```

### 3.2 Mode Binding Verification

**Property:** mode_binding must be consistent across all handshake messages

```
[SEND_MESSAGE]
   |
   | message.mode_binding = computed_mode_binding
   | signature = sign(message || mode_binding)
   v
[VERIFY_MESSAGE]
   |
   | expected_mode_binding = SHA3-256(...)
   | IF message.mode_binding ≠ expected_mode_binding THEN
   |   → [FAILED] "Mode downgrade detected"
   |
   | IF NOT verify_signature(signature, message || mode_binding) THEN
   |   → [FAILED] "Signature verification failed"
   v
[VERIFIED]
```

---

## 4. Cookie Challenge State Machine

### 4.1 Cookie Generation (Server)

```
[RECEIVE_CLIENT_HELLO]
   |
   | client_hello = { client_random, timestamp }
   | Cost: ~0.01ms (no crypto)
   v
[GENERATE_COOKIE]
   |
   | cookie = HMAC-SHA256(
   |   key: server_secret,
   |   data: client_ip || timestamp || client_random
   | )
   | Cost: ~0.01ms (HMAC only)
   |
   | NO STATE STORED (stateless)
   v
[SEND_COOKIE_CHALLENGE]
   |
   | challenge = { cookie, server_random }
   | Cost: ~0.01ms
```

### 4.2 Cookie Verification (Server)

```
[RECEIVE_CLIENT_HELLO_WITH_COOKIE]
   |
   | message = { client_random, cookie, handshake_init }
   v
[VERIFY_TIMESTAMP]
   |
   | current_time = now()
   | IF current_time - timestamp > 30s THEN
   |   → [REJECTED] "Cookie expired"
   | IF timestamp > current_time THEN
   |   → [REJECTED] "Future timestamp"
   v
[CHECK_REPLAY]
   |
   | IF bloom_filter.contains(client_random) THEN
   |   → [REJECTED] "Likely replay attack"
   |
   | bloom_filter.insert(client_random)
   v
[VERIFY_COOKIE]
   |
   | expected_cookie = HMAC-SHA256(
   |   key: server_secret,
   |   data: client_ip || timestamp || client_random
   | )
   |
   | IF constant_time_compare(cookie, expected_cookie) = false THEN
   |   → [REJECTED] "Invalid cookie"
   |
   | Cost: ~0.01ms (constant-time)
   v
[COOKIE_VALID]
   |
   | NOW perform expensive crypto operations:
   | - Signature verification (~0.2-5ms)
   | - KEM decapsulation (~0.6ms)
```

### 4.3 DoS Protection Analysis

**Without Cookie Challenge:**
```
[RECEIVE_HANDSHAKE_INIT]
   |
   | Immediately perform expensive operations
   | - Dilithium5 verification: ~3ms
   | - Kyber decapsulation: ~0.6ms
   | Total: ~3.6ms per attempt
   |
   | Attacker can flood with fake handshakes
   | DoS amplification: 1x (no protection)
```

**With Cookie Challenge:**
```
[RECEIVE_CLIENT_HELLO]
   |
   | Cheap cookie generation: ~0.01ms
   v
[RECEIVE_CLIENT_HELLO_WITH_COOKIE]
   |
   | Cheap cookie verification: ~0.01ms
   | IF invalid: reject (total cost ~0.02ms)
   | IF valid: proceed to expensive crypto (~3.6ms)
   |
   | DoS amplification reduced: 360x
   | (3.6ms / 0.01ms = 360)
```

---

## 5. Ratchet State Machine (Double Ratchet)

### 5.1 States

```
RatchetState (v2.0)
├── Active                    // Normal operation
├── RatchetPending           // DH ratchet initiated, waiting for ack
│   ├── pending_update       // RatchetUpdate to send
│   └── sent_at              // Timestamp
├── RatchetReceived          // DH ratchet received, processing
│   ├── received_update      // RatchetUpdate from peer
│   └── processed            // Processing status
└── Error(String)            // Error state with message
```

**Source:** `src/crypto/double_ratchet/session.rs`

### 5.2 Ratchet State Transitions

```
[ACTIVE] Active
   |
   | should_ratchet() == true
   | (message_counter % ratchet_interval == 0)
   | Default: every 100 messages
   v
[PENDING] RatchetPending
   |
   | initiate_ratchet()
   | - Generate fresh Kyber keypair
   | - Generate fresh X25519 keypair
   | - Create RatchetUpdate
   |
   | send_message_with_ratchet_update()
   v
[ACTIVE] Active (after peer processes update)
```

```
[ACTIVE] Active
   |
   | receive_message_with_ratchet_update()
   v
[RECEIVED] RatchetReceived
   |
   | process_ratchet_update()
   | - Derive shared secrets (Kyber + X25519)
   | - Ratchet root key
   | - Reset chain keys
   | - Zeroize old keys
   v
[ACTIVE] Active
```

### 5.3 Root Key Ratchet

```
[ROOT_KEY=RK_N, COUNT=N]
   |
   | ratchet_step(kyber_ss, x25519_ss)
   |
   | hybrid_ss = kyber_ss || x25519_ss
   |
   | RK_{N+1} = HKDF-SHA512(
   |   ikm: RK_N || hybrid_ss,
   |   salt: protocol_id || session_id,
   |   info: "B4AE-v2-root-ratchet",
   |   length: 32
   | )
   |
   | sending_key = HKDF-SHA512(
   |   ikm: RK_{N+1},
   |   salt: protocol_id || session_id,
   |   info: "B4AE-v2-sending-chain",
   |   length: 32
   | )
   |
   | receiving_key = HKDF-SHA512(
   |   ikm: RK_{N+1},
   |   salt: protocol_id || session_id,
   |   info: "B4AE-v2-receiving-chain",
   |   length: 32
   | )
   |
   | zeroize(RK_N)
   v
[ROOT_KEY=RK_{N+1}, COUNT=N+1]
```

**Security Properties:**
- Forward Secrecy: Old root key zeroized
- Post-Compromise Security: Fresh ephemeral keys provide new entropy
- Session Binding: All keys bound to session_id

### 5.4 Chain Key Ratchet

```
[COUNTER=N] chain_key=CK_N
   |
   | next_message_key()
   |
   | message_key = HKDF-SHA512(
   |   ikm: CK_N,
   |   salt: protocol_id || session_id,
   |   info: "B4AE-v2-message-key",
   |   length: 32
   | )
   |
   | CK_{N+1} = HKDF-SHA512(
   |   ikm: CK_N,
   |   salt: protocol_id || session_id,
   |   info: "B4AE-v2-chain-advance",
   |   length: 32
   | )
   |
   | zeroize(CK_N)
   v
[COUNTER=N+1] chain_key=CK_{N+1}
```

**Security Properties:**
- Forward Secrecy: Old chain key zeroized
- Key Independence: Each message uses unique key
- One-Way: Cannot derive CK_N from CK_{N+1}

### 5.5 Out-of-Order Message Handling

```
[COUNTER=N] Current state
   |
   | receive_message(counter=M) where M > N
   | skip = M - N
   |
   | IF skip > MAX_SKIP (1000) THEN
   |   → [ERROR] "Skip limit exceeded (DoS protection)"
   |
   | WHILE counter < M DO
   |   message_key = derive_message_key(chain_key)
   |   cache[counter] = message_key
   |   chain_key = advance_chain_key(chain_key)
   |   counter += 1
   | END WHILE
   v
[COUNTER=M+1] Advanced state
   |
   | key_cache contains keys for [N, M-1]
   | Use cached key to decrypt message M
```

**DoS Protection:** MAX_SKIP = 1000 prevents memory exhaustion

---

## 6. Session Binding State Machine

### 6.1 Session ID Derivation

```
[HANDSHAKE_COMPLETE]
   |
   | client_random (32 bytes)
   | server_random (32 bytes)
   | mode_id (Mode_A or Mode_B)
   v
[DERIVE_SESSION_ID]
   |
   | session_id = HKDF-SHA512(
   |   ikm: client_random || server_random || mode_id,
   |   salt: "B4AE-v2-session-id",
   |   info: "",
   |   length: 32
   | )
   |
   | Property: session_id is unique with overwhelming probability
   v
[SESSION_ID_DERIVED]
```

### 6.2 Key Binding to Session ID

```
[DERIVE_KEYS]
   |
   | master_secret (from hybrid KEM)
   | protocol_id (SHA3-256 of specification)
   | session_id (from above)
   | transcript_hash (SHA-512 of all messages)
   v
[BIND_KEYS]
   |
   | root_key = HKDF-SHA512(
   |   ikm: master_secret,
   |   salt: protocol_id || session_id || transcript_hash,
   |   info: "root-key",
   |   length: 32
   | )
   |
   | session_key = HKDF-SHA512(
   |   ikm: master_secret,
   |   salt: protocol_id || session_id || transcript_hash,
   |   info: "session-key",
   |   length: 32
   | )
   |
   | chain_key = HKDF-SHA512(
   |   ikm: master_secret,
   |   salt: protocol_id || session_id || transcript_hash,
   |   info: "chain-key",
   |   length: 32
   | )
   v
[KEYS_BOUND]
```

**Security Properties:**
- Session Isolation: Keys from Session A cannot be used in Session B
- Key Transplant Prevention: session_id binding prevents key reuse
- Transcript Binding: Keys bound to entire handshake transcript
- Protocol Binding: Keys bound to protocol_id (version binding)

---

## 7. Global Traffic Scheduler State Machine

### 7.1 Message Scheduling

```
[SESSION_SENDS_MESSAGE]
   |
   | message = { session_id, payload, is_dummy: false }
   v
[ENQUEUE_MESSAGE]
   |
   | IF queue.length >= max_queue_depth (10000) THEN
   |   → [ERROR] "Queue full"
   |
   | IF queue.memory >= max_queue_memory (100MB) THEN
   |   → [ERROR] "Memory limit exceeded"
   |
   | interval = 1.0 / target_rate  // e.g., 1/100 = 0.01s
   | scheduled_time = last_send_time + interval
   |
   | scheduled_message = {
   |   session_id: session_id,
   |   payload: payload,
   |   is_dummy: false,
   |   scheduled_time: scheduled_time
   | }
   |
   | unified_queue.enqueue(scheduled_message)
   v
[MESSAGE_QUEUED]
```

### 7.2 Constant-Rate Output

```
[SCHEDULER_LOOP]
   |
   | current_time = now()
   v
[CHECK_QUEUE]
   |
   | IF unified_queue.is_empty() THEN
   |   → [GENERATE_DUMMY]
   | ELSE
   |   → [SEND_NEXT_MESSAGE]
   v
[GENERATE_DUMMY]
   |
   | session_id = random_session_from_pool()
   | payload_size = random_bucket_size()
   | payload = random_bytes(payload_size)
   |
   | dummy_message = {
   |   session_id: session_id,
   |   payload: payload,
   |   is_dummy: true,
   |   scheduled_time: current_time
   | }
   |
   | unified_queue.enqueue(dummy_message)
   v
[SEND_NEXT_MESSAGE]
   |
   | message = unified_queue.peek()
   |
   | IF current_time < message.scheduled_time THEN
   |   sleep(message.scheduled_time - current_time)
   |
   | message = unified_queue.dequeue()
   | send_to_network(message)
   |
   | IF message.is_dummy THEN
   |   stats.dummy_count += 1
   | ELSE
   |   stats.real_count += 1
   |
   | stats.total_count += 1
   v
[SCHEDULER_LOOP] (repeat)
```

### 7.3 Traffic Pattern Analysis

**Without Global Scheduler (v1.0):**
```
Session 1: ████░░░░████░░░░  (burst pattern visible)
Session 2: ░░████░░░░████░░  (burst pattern visible)
Session 3: ░░░░████░░░░████  (burst pattern visible)

Adversary can correlate burst patterns across sessions
```

**With Global Scheduler (v2.0):**
```
Unified:   ████████████████  (constant rate, no bursts)

All sessions mixed into single constant-rate stream
Adversary cannot distinguish per-session patterns
```

---

## 8. State Invariants

### 8.1 Handshake Invariants

1. **Monotonic Progress:** State transitions only move forward
2. **Single Completion:** Once Established, state cannot change
3. **Timeout Universality:** Any state can transition to Failed on timeout
4. **Mode Consistency:** mode_binding must be consistent across all messages
5. **Cookie Validity:** Expensive crypto only after valid cookie

### 8.2 Ratchet Invariants

1. **Counter Monotonicity:** message_counter never decreases
2. **Ratchet Count Monotonicity:** ratchet_count never decreases
3. **Key Uniqueness:** Each message uses a unique message key
4. **Forward Secrecy:** Old keys are zeroized after advancement
5. **Skip Limit:** Out-of-order skip ≤ MAX_SKIP (1000)

### 8.3 Session Binding Invariants

1. **Session ID Uniqueness:** session_id is unique per session (with overwhelming probability)
2. **Key Independence:** Keys from different sessions are cryptographically independent
3. **Transplant Prevention:** Keys from Session A cannot decrypt Session B
4. **Transcript Binding:** Keys bound to complete handshake transcript

### 8.4 Traffic Scheduler Invariants

1. **Constant Rate:** Messages sent at target_rate (e.g., 100 msg/sec)
2. **Queue Bounds:** queue.length ≤ max_queue_depth
3. **Memory Bounds:** queue.memory ≤ max_queue_memory
4. **Dummy Budget:** dummy_ratio ≤ configured_budget (e.g., 20%)

---

## 9. Timing Constraints

### 9.1 Handshake Timeout

```
Default: 30000 ms (30 seconds)
Configurable: HandshakeConfig.timeout_ms
```

**Timeout Check:**
```
[ANY_STATE]
   |
   | current_time = now()
   | elapsed = current_time - start_time
   |
   | IF elapsed > timeout_ms THEN
   |   → [FAILED] "Handshake timeout"
```

### 9.2 Cookie Expiry

```
Default: 30 seconds
```

**Expiry Check:**
```
[VERIFY_COOKIE]
   |
   | current_time = now()
   | cookie_age = current_time - timestamp
   |
   | IF cookie_age > 30s THEN
   |   → [REJECTED] "Cookie expired"
   |
   | IF cookie_age < 0 THEN
   |   → [REJECTED] "Future timestamp"
```

### 9.3 Ratchet Interval

```
Default: 100 messages
Configurable: RatchetConfig.ratchet_interval
Range: [1, 10000]
```

**Ratchet Trigger:**
```
[SEND_MESSAGE]
   |
   | message_counter += 1
   |
   | IF message_counter % ratchet_interval == 0 THEN
   |   → [INITIATE_RATCHET]
```

---

## 10. Error States and Recovery

### 10.1 Error Conditions

| Error Condition | State Transition | Recovery |
|-----------------|------------------|----------|
| Invalid mode selection | → Failed | Restart handshake |
| Cookie verification failed | → Failed | Restart handshake |
| Invalid ratchet_count | → Error | Reject message |
| Counter skip > MAX_SKIP | → Error | Reject message |
| Signature verification failed | → Failed | Restart handshake |
| Decryption failure | → Error | Request retransmission |
| Timeout exceeded | → Failed | Restart handshake |
| Queue full | → Error | Backpressure to application |

### 10.2 Desynchronization Detection

```
[RECEIVE_MESSAGE]
   |
   | IF message.ratchet_count < local_ratchet_count THEN
   |   → [ERROR] "Potential replay or desync"
   |
   | IF message.ratchet_count > local_ratchet_count + 1 THEN
   |   → [ERROR] "Missed ratchet update"
```

---

## 11. Concurrency Considerations

### 11.1 Thread Safety

**Not Thread-Safe:**
- `DoubleRatchetSession` (mutable state)
- `ChainKeyRatchet` (mutable state)
- `RootKeyManager` (mutable state)

**Usage:** Wrap in `Mutex` or `RwLock` for concurrent access

**Thread-Safe:**
- `GlobalTrafficScheduler` (internal synchronization)
- `CookieChallenge` (stateless)

### 11.2 Global Scheduler Concurrency

```
[MULTIPLE_SESSIONS]
   |
   | Session 1 → enqueue(message1)  \
   | Session 2 → enqueue(message2)   } → [UNIFIED_QUEUE] (thread-safe)
   | Session 3 → enqueue(message3)  /
   |
   | Scheduler thread → dequeue() → send_to_network()
```

**Synchronization:** Internal mutex protects unified queue

---

## 12. State Diagram Legend

```
[STATE]         - State node
   |            - Transition
   v            - Direction
Condition       - Transition condition
Action          - Transition action
→ [STATE]       - Error transition
```

---

## 13. References

### 13.1 Specifications

- **Design Document:** `.kiro/specs/b4ae-v2-research-grade-architecture/design.md`
- **Requirements:** `.kiro/specs/b4ae-v2-research-grade-architecture/requirements.md`
- **Threat Model:** `docs/THREAT_MODEL_FORMALIZATION.md`
- **Formal Verification:** `docs/FORMAL_VERIFICATION.md`

### 13.2 Implementation

- **Handshake:** `src/protocol/v2/handshake.rs`
- **Double Ratchet:** `src/crypto/double_ratchet/`
- **Global Scheduler:** `src/protocol/v2/traffic_scheduler.rs`
- **Cookie Challenge:** `src/protocol/v2/cookie.rs`

### 13.3 Related Protocols

- Signal Protocol: https://signal.org/docs/
- Double Ratchet Algorithm: https://signal.org/docs/specifications/doubleratchet/
- Noise Protocol Framework: https://noiseprotocol.org/

---

**Document Status:** Complete  
**Last Updated:** 2026  
**Version:** 2.0  
**Implementation Status:** Specification complete, implementation in progress
