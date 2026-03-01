# Security Hardening Suite API Documentation

## Overview

The B4AE Security Hardening Suite provides comprehensive protection against metadata leakage, length oracle attacks, and side-channel attacks. This document describes the public APIs for all security hardening components.

## Table of Contents

1. [PADMÉ Padding](#padmé-padding)
2. [XEdDSA Deniable Authentication](#xeddsa-deniable-authentication)
3. [Metadata Protection](#metadata-protection)
4. [Constant-Time Operations](#constant-time-operations)
5. [Configuration Guide](#configuration-guide)
6. [Performance Characteristics](#performance-characteristics)
7. [Security Implications](#security-implications)

---

## PADMÉ Padding

### Overview

PADMÉ (Padding for Anonymity and Deniability in Messaging Environments) implements exponential bucket-based padding to obfuscate message lengths. Messages are padded to the next exponential bucket size (512B, 1KB, 2KB, 4KB, 8KB, 16KB, 32KB, 64KB), preventing length oracle attacks.

### API Reference

#### `PadmeConfig`

Configuration for PADMÉ padding scheme.

```rust
pub struct PadmeConfig {
    pub min_bucket_size: usize,      // Default: 512 bytes
    pub max_bucket_size: usize,      // Default: 65536 bytes (64 KB)
    pub bucket_multiplier: f64,      // Default: 2.0 (exponential)
}
```

**Methods:**
- `PadmeConfig::default()` - Returns default configuration (512B to 64KB, 8 buckets)
- `validate(&self) -> CryptoResult<()>` - Validates configuration parameters

**Example:**
```rust
use b4ae::crypto::padding::PadmeConfig;

// Use default configuration
let config = PadmeConfig::default();

// Custom configuration
let config = PadmeConfig {
    min_bucket_size: 1024,
    max_bucket_size: 16384,
    bucket_multiplier: 2.0,
};
```

#### `PadmePadding`

Main padding implementation.

```rust
pub struct PadmePadding {
    // Private fields
}
```

**Methods:**
- `new(config: PadmeConfig) -> Self` - Creates new padding instance with pre-computed buckets
- `pad(&self, plaintext: &[u8]) -> CryptoResult<PaddedMessage>` - Pads plaintext to next bucket
- `unpad(&self, padded_message: &PaddedMessage) -> CryptoResult<Vec<u8>>` - Removes padding and recovers plaintext
- `find_bucket(&self, length: usize) -> Option<usize>` - Finds smallest bucket for given length
- `buckets(&self) -> &[usize]` - Returns pre-computed bucket sizes
- `config(&self) -> &PadmeConfig` - Returns configuration

**Example:**
```rust
use b4ae::crypto::padding::{PadmeConfig, PadmePadding};

let padding = PadmePadding::new(PadmeConfig::default());

// Pad a message
let plaintext = b"Hello, World!";
let padded = padding.pad(plaintext)?;

// Unpad to recover original
let recovered = padding.unpad(&padded)?;
assert_eq!(recovered, plaintext);
```

#### `PaddedMessage`

Structure containing padded data and metadata.

```rust
pub struct PaddedMessage {
    pub original_length: u32,    // Original plaintext length
    pub bucket_size: u32,        // Bucket size used
    pub padded_data: Vec<u8>,    // Padded data
}
```

### Integration with Double Ratchet

The padding module integrates seamlessly with the Double Ratchet session:

```rust
use b4ae::crypto::padding::{PadmeConfig, PadmePadding};
use b4ae::crypto::double_ratchet::session::DoubleRatchetSession;

let padding = PadmePadding::new(PadmeConfig::default());
let mut session = DoubleRatchetSession::new(/* ... */);

// Encrypt with padding
let plaintext = b"Secret message";
let encrypted = session.encrypt_message_with_padding(plaintext, &padding)?;

// Decrypt with unpadding
let decrypted = session.decrypt_message_with_unpadding(&encrypted, &padding)?;
```

### Performance Characteristics

- **Padding overhead**: 2-100% depending on message size (average <5% for typical distributions)
- **Computation time**: <0.1ms per message for both padding and unpadding
- **Memory overhead**: Maximum 64KB per message
- **Bucket lookup**: O(log n) using binary search (n=8 for default config)

### Security Implications

**Protections:**
- Prevents length oracle attacks through deterministic padding
- Hides exact message lengths (only bucket size visible)
- Constant-time validation prevents timing attacks
- Reversible without data loss

**Limitations:**
- Bucket sizes are distinguishable (512B vs 1KB vs 2KB, etc.)
- Messages exceeding 64KB must be split or rejected
- Padding overhead increases for small messages in large buckets

**Recommended Usage:**
- Always use padding for sensitive communications
- Choose bucket configuration based on typical message size distribution
- Consider splitting large messages into smaller chunks

---

## XEdDSA Deniable Authentication

### Overview

XEdDSA provides deniable authentication - signatures that can be verified but also forged by the verifier. This allows participants to plausibly deny sending messages to third parties. The implementation hybridizes XEdDSA with Dilithium5 for post-quantum security.

### API Reference

#### `XEdDSAKeyPair`

Keypair for XEdDSA signatures.

```rust
pub struct XEdDSAKeyPair {
    pub public_key: [u8; 32],
    // Private fields
}
```

**Methods:**
- `generate() -> CryptoResult<Self>` - Generates new keypair from secure RNG
- `sign(&self, message: &[u8]) -> CryptoResult<XEdDSASignature>` - Signs message
- `verify(verification_key: &[u8; 32], message: &[u8], signature: &XEdDSASignature) -> CryptoResult<bool>` - Verifies signature
- `public_key(&self) -> &[u8; 32]` - Returns X25519 public key
- `verification_key(&self) -> &[u8; 32]` - Returns Ed25519 verification key

**Example:**
```rust
use b4ae::crypto::xeddsa::XEdDSAKeyPair;

// Generate keypair
let keypair = XEdDSAKeyPair::generate()?;

// Sign message
let message = b"Important message";
let signature = keypair.sign(message)?;

// Verify signature
let valid = XEdDSAKeyPair::verify(
    keypair.verification_key(),
    message,
    &signature
)?;
assert!(valid);
```

#### `XEdDSASignature`

XEdDSA signature structure.

```rust
pub struct XEdDSASignature {
    pub r: [u8; 32],  // Commitment
    pub s: [u8; 32],  // Response
}
```

**Size:** 64 bytes total (32 + 32)

#### `DeniableHybridKeyPair`

Hybrid keypair combining XEdDSA and Dilithium5.

```rust
pub struct DeniableHybridKeyPair {
    // Private fields
}
```

**Methods:**
- `generate() -> CryptoResult<Self>` - Generates hybrid keypair
- `sign_with_deniable_hybrid(&self, message: &[u8]) -> CryptoResult<DeniableHybridSignature>` - Signs with both schemes
- `public_key(&self) -> DeniableHybridPublicKey` - Returns hybrid public key
- `xeddsa_public_key(&self) -> &[u8; 32]` - Returns X25519 public key
- `xeddsa_verification_key(&self) -> &[u8; 32]` - Returns Ed25519 verification key

**Example:**
```rust
use b4ae::crypto::xeddsa::DeniableHybridKeyPair;

// Generate hybrid keypair
let keypair = DeniableHybridKeyPair::generate()?;

// Sign message with both XEdDSA and Dilithium5
let message = b"Important message";
let signature = keypair.sign_with_deniable_hybrid(message)?;

// Verify hybrid signature
let public_key = keypair.public_key();
let valid = verify_deniable_hybrid(&public_key, message, &signature)?;
assert!(valid);
```

#### `DeniableHybridSignature`

Hybrid signature containing both XEdDSA and Dilithium5 components.

```rust
pub struct DeniableHybridSignature {
    pub xeddsa_signature: XEdDSASignature,      // 64 bytes
    pub dilithium_signature: DilithiumSignature, // ~4627 bytes
}
```

**Size:** ~4691 bytes total

#### `verify_deniable_hybrid()`

Verifies hybrid signature (both components must be valid).

```rust
pub fn verify_deniable_hybrid(
    public_key: &DeniableHybridPublicKey,
    message: &[u8],
    signature: &DeniableHybridSignature,
) -> CryptoResult<bool>
```

**Returns:** `true` if and only if BOTH signatures are valid

### Integration with Handshake

XEdDSA is automatically used in the handshake protocol:

```rust
use b4ae::protocol::handshake::{HandshakeInitiator, HandshakeResponder};

// Handshake automatically uses hybrid signatures
let initiator = HandshakeInitiator::new(/* ... */);
let responder = HandshakeResponder::new(/* ... */);

// Signatures are verified during handshake
let result = initiator.finalize()?;
```

### Performance Characteristics

- **Signature generation**: ~0.05ms (XEdDSA) + ~3ms (Dilithium5) = ~3.05ms total
- **Signature verification**: ~0.1ms (XEdDSA) + ~3ms (Dilithium5) = ~3.1ms total
- **Signature size**: 64 bytes (XEdDSA) + 4627 bytes (Dilithium5) = 4691 bytes
- **Handshake overhead**: +5ms compared to Ed25519-only

### Security Implications

**Protections:**
- Provides plausible deniability (verifier can forge XEdDSA signatures)
- Maintains post-quantum security through Dilithium5
- Secure if either XEdDSA OR Dilithium5 is secure
- Constant-time verification prevents timing attacks

**Limitations:**
- XEdDSA is not post-quantum secure (but Dilithium5 is)
- Larger signature size compared to Ed25519 alone
- Cannot provide non-repudiation (by design)

**Recommended Usage:**
- Use for all handshakes requiring deniability
- Understand that deniability means participants can deny sending messages
- For non-repudiation, use Dilithium5 only (disable XEdDSA)

---

## Metadata Protection

### Overview

The metadata protection layer coordinates cover traffic generation, timing obfuscation, and traffic shaping to hide communication patterns from network observers.

### API Reference

#### `MetadataProtectionConfig`

Configuration for metadata protection.

```rust
pub struct MetadataProtectionConfig {
    pub cover_traffic_rate: f64,        // 0.0 to 1.0 (fraction of real traffic)
    pub constant_rate_mode: bool,       // Enable constant-rate sending
    pub target_rate_msgs_per_sec: f64,  // Target rate for constant-rate mode
    pub timing_delay_min_ms: u64,       // Minimum random delay
    pub timing_delay_max_ms: u64,       // Maximum random delay
    pub traffic_shaping_enabled: bool,  // Enable traffic shaping
    pub enabled: bool,                  // Master enable/disable
}
```

**Preset Configurations:**
- `MetadataProtectionConfig::high_security()` - Maximum protection (50% cover traffic, constant-rate, 100-2000ms delays)
- `MetadataProtectionConfig::balanced()` - Balanced protection (20% cover traffic, variable-rate, 50-500ms delays)
- `MetadataProtectionConfig::low_overhead()` - Minimal protection (disabled by default)

**Methods:**
- `validate(&self) -> CryptoResult<()>` - Validates configuration parameters

**Example:**
```rust
use b4ae::metadata::MetadataProtectionConfig;

// Use preset configuration
let config = MetadataProtectionConfig::high_security();

// Custom configuration
let config = MetadataProtectionConfig {
    cover_traffic_rate: 0.3,
    constant_rate_mode: false,
    target_rate_msgs_per_sec: 1.0,
    timing_delay_min_ms: 100,
    timing_delay_max_ms: 1000,
    traffic_shaping_enabled: true,
    enabled: true,
};
```

#### `MetadataProtector`

Main orchestrator for metadata protection.

```rust
pub struct MetadataProtector {
    // Private fields
}
```

**Methods:**
- `new(config: MetadataProtectionConfig) -> CryptoResult<Self>` - Creates new protector
- `send_message(&mut self, message: Vec<u8>) -> CryptoResult<()>` - Sends message with protection
- `schedule_cover_traffic(&mut self)` - Schedules dummy messages
- `apply_timing_delay(&self) -> Duration` - Generates random delay
- `statistics(&self) -> &TrafficStatistics` - Returns traffic statistics
- `config(&self) -> &MetadataProtectionConfig` - Returns configuration
- `pending_message_count(&self) -> usize` - Returns pending message count

**Example:**
```rust
use b4ae::metadata::{MetadataProtectionConfig, protector::MetadataProtector};

let config = MetadataProtectionConfig::balanced();
let mut protector = MetadataProtector::new(config)?;

// Send message with metadata protection
let message = b"Encrypted message".to_vec();
protector.send_message(message)?;

// Query statistics
let stats = protector.statistics();
println!("Real messages: {}", stats.real_messages);
println!("Dummy messages: {}", stats.dummy_messages);
println!("Dummy ratio: {:.2}%", stats.dummy_ratio() * 100.0);
```

#### `TrafficStatistics`

Statistics tracking for metadata protection.

```rust
pub struct TrafficStatistics {
    pub real_messages: u64,
    pub dummy_messages: u64,
    pub total_bytes_sent: u64,
    pub average_message_size: f64,
}
```

**Methods:**
- `total_messages(&self) -> u64` - Returns total message count
- `dummy_ratio(&self) -> f64` - Returns ratio of dummy to total messages

### Performance Characteristics

- **Cover traffic overhead**: Configurable (0-100% of real traffic)
- **Timing delay**: Configurable (0-2000ms typical)
- **Constant-rate mode**: Maintains target rate ±5%
- **Memory overhead**: ~5MB per session for message queue
- **Dummy message generation**: <0.5ms per message

### Security Implications

**Protections:**
- Hides traffic patterns from passive network observers
- Prevents timing correlation attacks
- Obscures burst patterns through traffic shaping
- Makes dummy messages indistinguishable from real messages

**Limitations:**
- IP addresses still visible (use Tor/VPN for IP anonymity)
- Global passive adversary can still perform traffic analysis
- Requires mixnet for strong unlinkability
- Increases bandwidth usage proportional to cover traffic rate

**Recommended Usage:**
- Use high_security() for maximum protection
- Use balanced() for typical deployments
- Combine with Tor/VPN for IP-level anonymity
- Monitor statistics to verify cover traffic is being generated

---

## Constant-Time Operations

### Overview

Constant-time operations ensure that execution time is independent of input values, preventing timing side-channel attacks. All cryptographic operations use these primitives.

### API Reference

#### `ConstantTimeMemory`

Constant-time memory operations.

```rust
pub struct ConstantTimeMemory;
```

**Methods:**
- `ct_memcmp(a: &[u8], b: &[u8]) -> Choice` - Compares byte arrays in constant time
- `ct_copy(dst: &mut [u8], src: &[u8], len: usize)` - Copies memory in constant time

**Example:**
```rust
use b4ae::crypto::constant_time::ConstantTimeMemory;
use subtle::Choice;

// Constant-time comparison
let secret1 = [0x42; 32];
let secret2 = [0x42; 32];
let equal = ConstantTimeMemory::ct_memcmp(&secret1, &secret2);
assert!(bool::from(equal));

// Constant-time copy
let src = [1, 2, 3, 4, 5];
let mut dst = [0u8; 5];
ConstantTimeMemory::ct_copy(&mut dst, &src, 5);
```

#### `CacheTimingResistance`

Cache-timing resistant operations.

```rust
pub struct CacheTimingResistance;
```

**Methods:**
- `ct_table_lookup<T>(table: &[T], index: usize) -> T` - Looks up table element in constant time

**Example:**
```rust
use b4ae::crypto::constant_time::CacheTimingResistance;

let table = vec![10, 20, 30, 40, 50];
let value = CacheTimingResistance::ct_table_lookup(&table, 2);
assert_eq!(value, 30);
```

#### `ConstantTimeArithmetic`

Constant-time arithmetic operations.

```rust
pub struct ConstantTimeArithmetic;
```

**Methods:**
- `ct_add(a: u64, b: u64) -> u64` - Adds in constant time
- `ct_sub(a: u64, b: u64) -> u64` - Subtracts in constant time
- `ct_mul(a: u64, b: u64) -> u64` - Multiplies in constant time
- `ct_is_zero(x: u64) -> Choice` - Checks if zero in constant time

**Example:**
```rust
use b4ae::crypto::constant_time::ConstantTimeArithmetic;

let sum = ConstantTimeArithmetic::ct_add(10, 20);
assert_eq!(sum, 30);

let is_zero = ConstantTimeArithmetic::ct_is_zero(0);
assert!(bool::from(is_zero));
```

### Performance Characteristics

- **ct_memcmp**: <20% overhead vs naive comparison
- **ct_table_lookup**: O(n) time (accesses all elements)
- **ct_arithmetic**: <10% overhead vs native operations
- **Overall impact**: <20% computation overhead

### Security Implications

**Protections:**
- Prevents timing side-channel attacks
- Prevents cache-timing attacks
- Execution time independent of secret values
- No secret-dependent branching

**Limitations:**
- Cannot prevent all side-channels (e.g., power analysis requires hardware support)
- Table lookup is O(n) instead of O(1)
- Slight performance overhead

**Recommended Usage:**
- Always use for secret comparisons (MACs, signatures, padding)
- Use for all secret-dependent computations
- Verify with timing tests in your environment

---

## Configuration Guide

### Quick Start

For most applications, use the preset configurations:

```rust
use b4ae::crypto::padding::{PadmeConfig, PadmePadding};
use b4ae::metadata::MetadataProtectionConfig;

// Padding: Use defaults
let padding = PadmePadding::new(PadmeConfig::default());

// Metadata protection: Choose based on security requirements
let meta_config = MetadataProtectionConfig::balanced(); // or high_security()
```

### Security Levels

#### High Security
Maximum protection, higher overhead:

```rust
let padding_config = PadmeConfig::default(); // 8 buckets, 512B-64KB
let meta_config = MetadataProtectionConfig::high_security();
// - 50% cover traffic
// - Constant-rate mode (2 msgs/sec)
// - 100-2000ms timing delays
```

**Use when:**
- Protecting highly sensitive communications
- Adversary has network monitoring capabilities
- Willing to accept higher latency and bandwidth overhead

#### Balanced
Good protection, moderate overhead:

```rust
let padding_config = PadmeConfig::default();
let meta_config = MetadataProtectionConfig::balanced();
// - 20% cover traffic
// - Variable-rate mode
// - 50-500ms timing delays
```

**Use when:**
- Standard security requirements
- Need balance between protection and performance
- Typical deployment scenario

#### Low Overhead
Minimal protection, lowest overhead:

```rust
let padding_config = PadmeConfig {
    min_bucket_size: 2048,
    max_bucket_size: 8192,
    bucket_multiplier: 2.0,
};
let meta_config = MetadataProtectionConfig::low_overhead();
// - No cover traffic
// - No timing delays
// - Padding only
```

**Use when:**
- Performance is critical
- Threat model doesn't include network monitoring
- Padding alone provides sufficient protection

### Custom Configuration

Tailor configuration to your specific needs:

```rust
// Custom padding for specific message size distribution
let padding_config = PadmeConfig {
    min_bucket_size: 1024,      // Minimum 1KB
    max_bucket_size: 16384,     // Maximum 16KB
    bucket_multiplier: 2.0,     // Exponential growth
};

// Custom metadata protection
let meta_config = MetadataProtectionConfig {
    cover_traffic_rate: 0.3,              // 30% dummy traffic
    constant_rate_mode: true,             // Constant-rate sending
    target_rate_msgs_per_sec: 1.0,        // 1 message per second
    timing_delay_min_ms: 200,             // 200ms minimum delay
    timing_delay_max_ms: 1000,            // 1000ms maximum delay
    traffic_shaping_enabled: true,        // Enable shaping
    enabled: true,                        // Enable metadata protection
};
```

### Configuration Validation

All configurations are validated at initialization:

```rust
// This will return an error if invalid
let result = MetadataProtectionConfig {
    cover_traffic_rate: 1.5,  // Invalid: > 1.0
    ..Default::default()
}.validate();

assert!(result.is_err());
```

---

## Performance Characteristics

### Overhead Summary

| Component | Overhead Type | Impact | Configurable |
|-----------|---------------|--------|--------------|
| PADMÉ Padding | Bandwidth | 2-100% (avg <5%) | Yes (bucket sizes) |
| XEdDSA | Computation | +0.05ms per signature | No |
| Dilithium5 | Computation | +3ms per signature | No |
| Cover Traffic | Bandwidth | 0-100% | Yes (rate) |
| Timing Delays | Latency | 0-2000ms | Yes (min/max) |
| Constant-Time Ops | Computation | <20% | No |

### Throughput Impact

With all features enabled (high security):

- **Message throughput**: ~1000 messages/second (1KB messages)
- **Handshake time**: ~150ms (vs ~145ms without hardening)
- **Memory per session**: ~45MB (vs ~40MB without hardening)

### Optimization Tips

1. **Padding**: Choose bucket sizes based on your message size distribution
2. **Cover Traffic**: Start with low rate (0.1-0.2) and increase if needed
3. **Timing Delays**: Use shorter delays for interactive applications
4. **Constant-Rate Mode**: Disable for variable-rate applications

---

## Security Implications

### Threat Model

The security hardening suite protects against:

1. **Length Oracle Attacks**: PADMÉ padding prevents attackers from inferring information from message lengths
2. **Traffic Analysis**: Cover traffic and timing obfuscation prevent pattern recognition
3. **Timing Side-Channels**: Constant-time operations prevent timing attacks
4. **Cache Side-Channels**: Cache-timing resistant operations prevent cache attacks
5. **Deniability**: XEdDSA allows participants to deny sending messages

### What is NOT Protected

1. **IP Addresses**: Still visible to network observers (use Tor/VPN)
2. **Global Passive Adversary**: Requires mixnet for strong unlinkability
3. **Endpoint Compromise**: Cannot protect if endpoints are compromised
4. **Quantum Attacks on XEdDSA**: XEdDSA is not post-quantum (but Dilithium5 is)

### Best Practices

1. **Always use padding** for sensitive communications
2. **Enable metadata protection** when threat model includes network monitoring
3. **Combine with Tor/VPN** for IP-level anonymity
4. **Monitor statistics** to verify cover traffic is being generated
5. **Test timing properties** in your deployment environment
6. **Understand deniability** implications (cannot prove message origin)

### Migration from Non-Hardened

The security hardening suite maintains backward compatibility:

```rust
// Old code (still works)
let encrypted = session.encrypt_message(plaintext)?;

// New code with padding (backward compatible)
let padding = PadmePadding::new(PadmeConfig::default());
let encrypted = session.encrypt_message_with_padding(plaintext, &padding)?;
```

**Migration steps:**
1. Deploy padding first (backward compatible)
2. Deploy constant-time operations (transparent)
3. Deploy metadata protection (optional, per-session)
4. Deploy XEdDSA (requires coordinated upgrade)

---

## Error Handling

### Common Errors

#### `CryptoError::MessageTooLarge`

Message exceeds maximum bucket size (64KB).

**Solution:** Split message into smaller chunks or increase `max_bucket_size`.

```rust
let result = padding.pad(&large_message);
match result {
    Err(CryptoError::MessageTooLarge) => {
        // Split message into chunks
        for chunk in large_message.chunks(60000) {
            let padded = padding.pad(chunk)?;
            // Send chunk
        }
    }
    Ok(padded) => { /* Send padded message */ }
}
```

#### `CryptoError::InvalidPadding`

Padding validation failed during unpadding.

**Cause:** Message was corrupted or tampered with.

**Solution:** Reject message and log security event.

```rust
let result = padding.unpad(&padded_message);
match result {
    Err(CryptoError::InvalidPadding) => {
        log::error!("Invalid padding detected - possible tampering");
        // Reject message
    }
    Ok(plaintext) => { /* Process plaintext */ }
}
```

#### `CryptoError::AuthenticationFailed`

Signature verification failed.

**Cause:** Invalid signature or wrong public key.

**Solution:** Terminate connection and log security event.

```rust
let valid = verify_deniable_hybrid(&public_key, message, &signature)?;
if !valid {
    log::error!("Signature verification failed");
    // Terminate connection
}
```

#### `CryptoError::InvalidInput`

Configuration validation failed.

**Cause:** Invalid configuration parameters.

**Solution:** Fix configuration and retry.

```rust
let config = MetadataProtectionConfig {
    cover_traffic_rate: 1.5,  // Invalid: > 1.0
    ..Default::default()
};

match config.validate() {
    Err(CryptoError::InvalidInput(msg)) => {
        log::error!("Invalid configuration: {}", msg);
        // Fix configuration
    }
    Ok(()) => { /* Configuration valid */ }
}
```

---

## Examples

### Complete Workflow

```rust
use b4ae::crypto::padding::{PadmeConfig, PadmePadding};
use b4ae::crypto::xeddsa::DeniableHybridKeyPair;
use b4ae::metadata::{MetadataProtectionConfig, protector::MetadataProtector};
use b4ae::crypto::double_ratchet::session::DoubleRatchetSession;

// Initialize all components
let padding = PadmePadding::new(PadmeConfig::default());
let meta_config = MetadataProtectionConfig::balanced();
let mut meta_protector = MetadataProtector::new(meta_config)?;
let keypair = DeniableHybridKeyPair::generate()?;
let mut session = DoubleRatchetSession::new(/* ... */);

// Send message with full protection
let plaintext = b"Top secret message";

// 1. Encrypt with padding
let encrypted = session.encrypt_message_with_padding(plaintext, &padding)?;

// 2. Apply metadata protection
meta_protector.send_message(encrypted.serialize()).await?;

// Message is now protected against:
// - Length analysis (PADMÉ padding)
// - Timing analysis (random delays)
// - Traffic analysis (cover traffic)
// - Side-channel attacks (constant-time ops)
```

### Monitoring and Statistics

```rust
use b4ae::metadata::{MetadataProtectionConfig, protector::MetadataProtector};

let config = MetadataProtectionConfig::balanced();
let mut protector = MetadataProtector::new(config)?;

// Send messages
for i in 0..100 {
    let message = format!("Message {}", i).into_bytes();
    protector.send_message(message)?;
}

// Query statistics
let stats = protector.statistics();
println!("Real messages: {}", stats.real_messages);
println!("Dummy messages: {}", stats.dummy_messages);
println!("Total bytes: {}", stats.total_bytes_sent);
println!("Average size: {:.2} bytes", stats.average_message_size);
println!("Dummy ratio: {:.2}%", stats.dummy_ratio() * 100.0);
```

---

## Further Reading

- [Security Documentation](SECURITY_HARDENING_THREAT_MODEL.md) - Threat model and security analysis
- [B4AE Protocol Specification](../specs/B4AE_Protocol_Specification_v1.0.md) - Complete protocol specification
- [Implementation Security Notes](IMPLEMENTATION_SECURITY_NOTES.md) - Implementation details and security considerations

---

## Support

For questions or issues:
- GitHub Issues: https://github.com/your-repo/b4ae/issues
- Security Issues: security@your-domain.com (PGP key available)
- Documentation: https://docs.your-domain.com

---

*Last updated: 2024*
