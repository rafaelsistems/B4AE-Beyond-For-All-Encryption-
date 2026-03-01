# B4AE Implementation Security Notes

**Version:** 1.0  
**Date:** 2026  
**Status:** Implementation-Based Specification

## 1. Overview

This document details implementation-level security mechanisms in the B4AE protocol, including constant-time operations, zeroization strategies, memory management, and RNG usage.

## 2. Constant-Time Operations

### 2.1 Confirmation Comparison

**Location:** `src/protocol/handshake.rs:598-602`

```rust
use subtle::ConstantTimeEq;

let confirmation_valid = complete.confirmation.ct_eq(&expected_confirmation);
if !bool::from(confirmation_valid) {
    return Err(CryptoError::VerificationFailed("Confirmation mismatch".to_string()));
}
```

**Purpose:** Prevent timing attacks on handshake confirmation  
**Library:** `subtle` crate (constant-time comparison)  
**Protection:** Timing-independent equality check

### 2.2 Non-Constant-Time Operations

**HKDF Operations:**
- NOT constant-time
- Operates on public info strings
- Output length is public
- **Rationale:** No secret-dependent branching needed

**Signature Verification:**
- Dilithium5: Constant-time (library guarantee)
- Ed25519 (ring): Constant-time (library guarantee)
- **Source:** `src/crypto/hybrid.rs:318-334`

**KEM Operations:**
- Kyber1024: Constant-time (library guarantee)
- X25519: Constant-time (library guarantee)
- **Source:** `src/crypto/hybrid.rs:207-287`

**AEAD Operations:**
- ChaCha20-Poly1305: Constant-time (library guarantee)
- **Source:** `src/crypto/double_ratchet/session.rs:180-195`

## 3. Zeroization Strategy

### 3.1 Automatic Zeroization (ZeroizeOnDrop)

**Root Key Manager:**
```rust
// Source: src/crypto/double_ratchet/root_key_manager.rs:11
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RootKeyManager {
    root_key: [u8; 32],
    ratchet_count: u64,
}
```

**Message Key:**
```rust
// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:11-20
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey {
    pub encryption_key: [u8; 32],
    pub auth_key: [u8; 32],
    pub counter: u64,
}
```

**Behavior:** Keys are automatically zeroized when dropped (out of scope)

### 3.2 Explicit Zeroization

**Root Key After Ratchet:**
```rust
// Source: src/crypto/double_ratchet/root_key_manager.rs:93
self.root_key.zeroize();
```

**Chain Key After Advancement:**
```rust
// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:94
self.chain_key.zeroize();
```

**Cached Keys on Eviction:**
```rust
// Source: src/crypto/double_ratchet/chain_key_ratchet.rs:153-155
if let Some(mut old_key) = self.key_cache.remove(&oldest_counter) {
    old_key.encryption_key.zeroize();
    old_key.auth_key.zeroize();
}
```

**Hybrid Secret Key:**
```rust
// Source: src/crypto/hybrid.rs:348-352
impl Drop for HybridSecretKey {
    fn drop(&mut self) {
        self.ecdh_secret.zeroize();
        self.ecdsa_secret.zeroize();
    }
}
```

### 3.3 Zeroization Timing

| Key Type              | Zeroization Trigger                | Timing                    |
|-----------------------|------------------------------------|---------------------------|
| Root key              | After ratchet step                 | Immediate                 |
| Chain key             | After advancement                  | Immediate                 |
| Message key           | After use or cache eviction        | Immediate                 |
| Cached keys           | On eviction or cleanup             | Immediate                 |
| Session keys          | On drop                            | End of scope              |
| Hybrid secret key     | On drop                            | End of scope              |

### 3.4 Zeroization Guarantees

**What is Guaranteed:**
- Memory is overwritten with zeros
- Compiler cannot optimize away zeroization
- Works across all platforms

**What is NOT Guaranteed:**
- Protection against memory dumps before zeroization
- Protection against swap file persistence
- Protection against hardware memory remanence
- Protection against speculative execution side-channels

**Library:** `zeroize` crate v1.x

## 4. Memory Management

### 4.1 Memory Locking

**Status:** NOT implemented

**Rationale:**
- Platform-specific (mlock on Unix, VirtualLock on Windows)
- Requires elevated privileges
- Limited benefit (swap can be disabled system-wide)

**Recommendation:** Application-level memory locking if needed

### 4.2 Memory Allocation

**Heap Allocation:**
- All keys allocated on heap (Vec, Box)
- Rust's allocator (jemalloc or system allocator)
- No custom allocator

**Stack Allocation:**
- Fixed-size arrays ([u8; 32]) on stack
- Automatically zeroized on drop

**Memory Bounds:**
```
Per-session maximum:
- Root key: 32 bytes
- Chain keys: 64 bytes (sending + receiving)
- Cached keys: 72 KB (1000 keys × 72 bytes)
- Total: ~72 KB per session
```

### 4.3 Memory Safety

**Rust Guarantees:**
- No buffer overflows
- No use-after-free
- No data races (with proper synchronization)
- No null pointer dereferences

**Unsafe Code:**
- Minimal unsafe code in dependencies
- No unsafe code in B4AE protocol implementation
- Cryptographic libraries use unsafe internally (audited)

## 5. Random Number Generation

### 5.1 RNG Source

**Primary RNG:**
```rust
// Source: src/crypto/random.rs (referenced in code)
use rand::rngs::OsRng;
```

**Platform-Specific Sources:**
- Linux: `/dev/urandom`
- Windows: `BCryptGenRandom`
- macOS: `SecRandomCopyBytes`
- WASM: `crypto.getRandomValues()` (browser) or `getrandom` (Node.js)

### 5.2 RNG Usage

**Client/Server Randoms:**
```rust
// Source: src/protocol/handshake.rs:189-191
let mut client_random = [0u8; 32];
random::fill_random(&mut client_random)?;
```

**Ephemeral Keys:**
```rust
// Source: src/crypto/hybrid.rs:217-218
let mut csprng = rand::rngs::OsRng;
let x25519_static_secret = X25519StaticSecret::random_from_rng(&mut csprng);
```

**Kyber/Dilithium:**
- Internal RNG (library-managed)
- Uses OsRng or platform RNG

### 5.3 WASM Entropy Model

**Browser Environment:**
```javascript
// Web Crypto API
crypto.getRandomValues(buffer)
```

**Node.js Environment:**
```javascript
// Node.js crypto module
crypto.randomFillSync(buffer)
```

**Entropy Quality:**
- Browser: High (hardware RNG or OS RNG)
- Node.js: High (OS RNG)
- WASM: Depends on host environment

**Fallback:** None (fails if RNG unavailable)

### 5.4 RNG Failure Handling

**Error Propagation:**
```rust
pub fn fill_random(buf: &mut [u8]) -> CryptoResult<()> {
    OsRng.fill_bytes(buf);
    Ok(())
}
```

**Failure Modes:**
- RNG unavailable: Panic or error
- Insufficient entropy: Blocks (on some platforms)
- WASM without crypto API: Compilation error

**No Fallback:** Protocol does not use weak RNG as fallback

## 6. Key Material Lifetime

### 6.1 Ephemeral Keys

**Handshake Ephemeral Keys:**
- Generated: Per handshake
- Used: Once (encapsulate/decapsulate)
- Zeroized: After handshake completion
- **Lifetime:** ~30 seconds (handshake timeout)

**Ratchet Ephemeral Keys:**
- Generated: Every 100 messages (default)
- Used: Once (DH ratchet)
- Zeroized: After ratchet step
- **Lifetime:** ~100 messages

### 6.2 Session Keys

**Master Secret:**
- Derived: From handshake
- Used: To derive session keys and root key
- Zeroized: After derivation (implicit)
- **Lifetime:** Milliseconds

**Session Keys (encryption, authentication, metadata):**
- Derived: From master secret
- Used: Throughout session
- Zeroized: On session termination
- **Lifetime:** Session duration

### 6.3 Ratchet Keys

**Root Key:**
- Derived: From master secret or previous root key
- Used: To derive chain keys
- Zeroized: After ratchet step
- **Lifetime:** 100 messages (default)

**Chain Keys:**
- Derived: From root key
- Used: To derive message keys
- Zeroized: After each advancement
- **Lifetime:** 1 message

**Message Keys:**
- Derived: From chain key
- Used: Once (encrypt/decrypt single message)
- Zeroized: After use or cache eviction
- **Lifetime:** 1 message (or cached)

### 6.4 Long-Term Keys

**Identity Keys:**
- Generated: Once (or rotated annually)
- Used: Sign handshake messages
- Zeroized: Never (persistent)
- **Lifetime:** Years

**Storage:** Application responsibility (HSM, keychain, file)

## 7. Side-Channel Resistance

### 7.1 Timing Side-Channels

**Protected Operations:**
- Confirmation comparison (constant-time)
- Signature verification (constant-time, library)
- KEM operations (constant-time, library)
- AEAD operations (constant-time, library)

**Unprotected Operations:**
- HKDF (not constant-time, but operates on public data)
- Message size (leaks plaintext size)
- Ratchet timing (leaks ratchet events)

**Mitigation:** Use constant-time libraries for cryptographic operations

### 7.2 Cache Timing Side-Channels

**Vulnerable Operations:**
- HashMap lookups (key cache)
- HKDF (table lookups in SHA3)

**Mitigation:**
- Use constant-time hash functions (SHA3 is relatively resistant)
- Avoid secret-dependent branching

**Limitation:** Full cache-timing resistance not guaranteed

### 7.3 Power Analysis

**Status:** NOT protected

**Rationale:**
- Requires hardware-level protection
- Not feasible in software-only implementation
- Assumes trusted execution environment

**Recommendation:** Use hardware security modules (HSM) for key operations if power analysis is a concern

### 7.4 Speculative Execution (Spectre/Meltdown)

**Status:** Partial protection

**Mechanisms:**
- Zeroization prevents some leakage
- Constant-time operations reduce attack surface

**Limitations:**
- Cannot fully prevent speculative execution attacks
- Requires hardware/OS-level mitigations

**Recommendation:** Keep systems updated with Spectre/Meltdown patches

## 8. Compiler Optimizations

### 8.1 Zeroization and Compiler

**Problem:** Compiler may optimize away "dead stores"

**Solution:** `zeroize` crate uses compiler barriers

```rust
// Prevents compiler from optimizing away zeroization
#[inline(never)]
fn zeroize_impl(buf: &mut [u8]) {
    for byte in buf {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
}
```

**Guarantee:** Zeroization is never optimized away

### 8.2 Constant-Time and Compiler

**Problem:** Compiler may optimize constant-time code into variable-time code

**Solution:** Use `subtle` crate with compiler barriers

```rust
// Prevents compiler from optimizing into branches
pub fn ct_eq(a: &[u8], b: &[u8]) -> Choice {
    // Implementation uses bitwise operations, no branches
}
```

**Guarantee:** Constant-time operations remain constant-time

### 8.3 Optimization Levels

**Recommended:**
- Release builds: `-O2` or `-O3`
- Debug builds: `-O0` (for debugging)

**Security:**
- Optimizations do not break security guarantees
- Zeroization and constant-time operations are preserved

## 9. Dependency Security

### 9.1 Cryptographic Libraries

| Library               | Purpose                  | Version | Audit Status          |
|-----------------------|--------------------------|---------|------------------------|
| pqcrypto-kyber        | Kyber1024 KEM            | Latest  | NIST PQC standard      |
| pqcrypto-dilithium    | Dilithium5 signatures    | Latest  | NIST PQC standard      |
| x25519-dalek          | X25519 key exchange      | 2.x     | Audited (2020)         |
| ring                  | Ed25519 signatures       | 0.17.x  | Audited (ongoing)      |
| chacha20poly1305      | AEAD encryption          | 0.10.x  | Audited (RustCrypto)   |
| sha3                  | SHA3-256 hashing         | 0.10.x  | Audited (RustCrypto)   |
| hkdf                  | HKDF key derivation      | 0.12.x  | Audited (RustCrypto)   |
| zeroize               | Secure zeroization       | 1.x     | Audited (RustCrypto)   |
| subtle                | Constant-time operations | 2.x     | Audited (RustCrypto)   |

### 9.2 Dependency Management

**Cargo.lock:**
- Committed to repository
- Ensures reproducible builds
- Pins exact dependency versions

**Security Updates:**
- Regular dependency updates
- Monitor security advisories
- Use `cargo audit` for vulnerability scanning

### 9.3 Supply Chain Security

**Verification:**
- All dependencies from crates.io
- Checksum verification (Cargo)
- Source code review (critical dependencies)

**Risks:**
- Compromised crates.io account
- Malicious dependency updates
- Transitive dependencies

**Mitigation:**
- Pin dependency versions
- Review dependency updates
- Use `cargo-crev` for code review

## 10. Platform-Specific Considerations

### 10.1 Linux

**RNG:** `/dev/urandom` (non-blocking, sufficient entropy)  
**Memory Locking:** `mlock()` available (requires CAP_IPC_LOCK)  
**Zeroization:** Reliable  
**Constant-Time:** Supported

### 10.2 Windows

**RNG:** `BCryptGenRandom` (CNG API)  
**Memory Locking:** `VirtualLock()` available  
**Zeroization:** Reliable  
**Constant-Time:** Supported

### 10.3 macOS

**RNG:** `SecRandomCopyBytes` (Security framework)  
**Memory Locking:** `mlock()` available  
**Zeroization:** Reliable  
**Constant-Time:** Supported

### 10.4 WASM (Browser)

**RNG:** `crypto.getRandomValues()` (Web Crypto API)  
**Memory Locking:** Not available  
**Zeroization:** Reliable (but no memory locking)  
**Constant-Time:** Supported (but timing attacks easier in browser)

**Limitations:**
- No memory locking
- Easier timing attacks (JavaScript timing)
- Potential for side-channel attacks via browser

### 10.5 WASM (Node.js)

**RNG:** `crypto.randomFillSync()` (Node.js crypto module)  
**Memory Locking:** Not available  
**Zeroization:** Reliable  
**Constant-Time:** Supported

### 10.6 Mobile (iOS/Android)

**RNG:** Platform-specific (SecRandomCopyBytes on iOS, /dev/urandom on Android)  
**Memory Locking:** Limited (requires root/jailbreak)  
**Zeroization:** Reliable  
**Constant-Time:** Supported

**Considerations:**
- Limited memory locking
- Power analysis concerns (battery-powered)
- Side-channel attacks via sensors

## 11. Testing and Verification

### 11.1 Unit Tests

**Coverage:**
- All cryptographic operations
- Key derivation
- Zeroization (via assertions)
- Error handling

**Source:** `src/crypto/*/tests/`

### 11.2 Property-Based Tests

**Coverage:**
- Forward secrecy (chain key ratchet)
- Post-compromise security (root key ratchet)
- Key uniqueness (message keys)
- Counter skip caching

**Source:** `src/crypto/double_ratchet/root_key_manager.rs:tests::property_tests`, `src/crypto/double_ratchet/chain_key_ratchet.rs:tests::property_tests`

**Library:** `proptest` crate

### 11.3 Integration Tests

**Coverage:**
- Handshake flow
- Message encryption/decryption
- Ratchet operations
- Out-of-order delivery

**Source:** `tests/`

### 11.4 Fuzzing

**Status:** NOT implemented

**Recommendation:** Fuzz test:
- Handshake message parsing
- Ratchet message parsing
- Key derivation with random inputs

**Tools:** `cargo-fuzz` (libFuzzer), `afl.rs` (AFL)

## 12. Security Recommendations

### 12.1 Deployment

1. **Use Release Builds:** Enable optimizations (`--release`)
2. **Disable Debug Symbols:** Strip binaries
3. **Enable ASLR:** Address Space Layout Randomization
4. **Enable DEP/NX:** Data Execution Prevention
5. **Use Secure Boot:** Verify boot chain integrity

### 12.2 Key Management

1. **Use HSM:** Store long-term keys in hardware security module
2. **Memory Locking:** Lock key material in memory (if available)
3. **Secure Storage:** Encrypt keys at rest
4. **Key Rotation:** Rotate long-term keys annually
5. **Backup:** Secure backup of long-term keys

### 12.3 Monitoring

1. **Audit Logging:** Log all handshakes and ratchet events
2. **Anomaly Detection:** Detect unusual patterns
3. **Security Updates:** Monitor for vulnerabilities
4. **Dependency Audits:** Regular `cargo audit`

### 12.4 Incident Response

1. **Key Revocation:** Procedure for revoking compromised keys
2. **Session Termination:** Ability to terminate sessions
3. **Forensics:** Logging for post-incident analysis
4. **Recovery:** Procedure for recovering from compromise

## 13. Known Limitations

### 13.1 Side-Channel Attacks

**Timing:**
- Message size leaks plaintext size
- Ratchet timing leaks ratchet events
- HKDF timing leaks (but operates on public data)

**Cache:**
- HashMap lookups not constant-time
- SHA3 table lookups (relatively resistant)

**Power:**
- No power analysis protection
- Requires hardware-level protection

### 13.2 Memory Protection

**No Memory Locking:**
- Keys can be swapped to disk
- Vulnerable to memory dumps

**No Secure Enclave:**
- Keys in process memory
- Vulnerable to process memory access

### 13.3 Platform Limitations

**WASM:**
- No memory locking
- Easier timing attacks
- Limited entropy sources

**Mobile:**
- Limited memory locking
- Power analysis concerns
- Side-channel attacks via sensors

## 14. Future Improvements

### 14.1 Short-Term

1. Implement message padding
2. Add fuzzing tests
3. Implement memory locking (optional)
4. Add HSM support (optional)

### 14.2 Long-Term

1. Formal verification (TLA+, Coq)
2. Side-channel resistance analysis
3. Hardware security module integration
4. Secure enclave support (SGX, TrustZone)

## 15. References

- Zeroize crate: https://docs.rs/zeroize/
- Subtle crate: https://docs.rs/subtle/
- RustCrypto: https://github.com/RustCrypto
- NIST PQC: https://csrc.nist.gov/projects/post-quantum-cryptography
- Implementation: `src/crypto/`, `src/protocol/`
