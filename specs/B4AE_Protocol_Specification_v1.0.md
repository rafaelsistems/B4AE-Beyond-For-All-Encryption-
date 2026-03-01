# B4AE Protocol Specification v1.0

**Document Version:** 1.0  
**Protocol Version:** 1  
**Date:** February 2026  
**Status:** Implemented (codebase aligned with this specification)

## 1. INTRODUCTION

### 1.1 Purpose
This document specifies the B4AE (Beyond For All Encryption) protocol, a quantum-resistant secure communication protocol designed to provide comprehensive protection against current and future cryptographic threats.

### 1.2 Scope
This specification covers:
- Cryptographic primitives and their usage
- Protocol message formats and flows
- Key management and rotation
- Metadata protection mechanisms
- Security considerations and threat model

### 1.3 Terminology
- **B4AE**: Beyond For All Encryption
- **PQC**: Post-Quantum Cryptography
- **KEM**: Key Encapsulation Mechanism
- **AEAD**: Authenticated Encryption with Associated Data
- **HSM**: Hardware Security Module

## 2. PROTOCOL OVERVIEW

### 2.1 Design Goals
1. Quantum resistance against attacks by quantum computers
2. Comprehensive metadata protection
3. Perfect forward secrecy and future secrecy
4. High performance suitable for real-time communication
5. Cross-platform compatibility
6. Enterprise-grade security and compliance

### 2.2 Security Properties
- **Confidentiality**: Messages encrypted with quantum-resistant algorithms
- **Integrity**: Authenticated encryption prevents tampering
- **Authentication**: Mutual authentication using digital signatures
- **Forward Secrecy**: Compromise of long-term keys doesn't affect past sessions
- **Future Secrecy**: Compromise doesn't affect future sessions
- **Metadata Privacy**: Traffic analysis resistance

## 3. CRYPTOGRAPHIC PRIMITIVES

### 3.1 Post-Quantum Algorithms

#### 3.1.1 Key Encapsulation Mechanism (KEM)
```
Algorithm: CRYSTALS-Kyber-1024
Standard: NIST FIPS 203
Security Level: NIST Level 5 (256-bit quantum security)

Key Sizes:
- Public Key: 1568 bytes
- Secret Key: 3168 bytes
- Ciphertext: 1568 bytes
- Shared Secret: 32 bytes
```

#### 3.1.2 Digital Signature
```
Algorithm: CRYSTALS-Dilithium5
Standard: NIST FIPS 204
Security Level: NIST Level 5 (256-bit quantum security)

Key Sizes:
- Public Key: 2592 bytes
- Secret Key: 4864 bytes
- Signature: 4627 bytes (pqcrypto-dilithium5 wire format; NIST FIPS 204 core)
```

### 3.2 Classical Algorithms (Hybrid Mode)

B4AE uses Curve25519/Ed25519 for high performance and broad ecosystem support (x25519-dalek, ring).

#### 3.2.1 Key Exchange
```
Algorithm: X25519 (ECDH over Curve25519)
Standard: RFC 7748
Security Level: ~128-bit classical (256-bit with PQ hybrid)

Key Sizes:
- Public Key: 32 bytes
- Secret Key: 32 bytes
```

#### 3.2.2 Digital Signature
```
Algorithm: Ed25519
Standard: RFC 8032
Security Level: ~128-bit classical (256-bit with PQ hybrid)

Key Sizes:
- Public Key: 32 bytes
- Secret Key: 64 bytes (or 83 bytes PKCS#8)
- Signature: 64 bytes
```

### 3.3 Symmetric Cryptography

#### 3.3.1 Authenticated Encryption
```
Algorithm: AES-256-GCM
Key Size: 32 bytes (256 bits)
Nonce Size: 12 bytes (96 bits)
Tag Size: 16 bytes (128 bits)
```

#### 3.3.2 Key Derivation
```
Algorithm: HKDF with SHA3-256
Output: Variable length (typically 32 bytes)
```

#### 3.3.3 Hash Function
```
Algorithm: SHA3-256
Output: 32 bytes (256 bits)
```

## 4. KEY HIERARCHY

### 4.1 Key Types
```
Master Identity Key (MIK)           [Implemented]
├── Device Master Key (DMK)        [Implemented - derived per device_id]
│   ├── Session Key (SK)          [Implemented - from handshake]
│   │   ├── Message Key (MK)      [Implemented - PFS+ per-message]
│   │   └── Ephemeral Key (EK)    [Implemented]
│   └── Storage Key (STK)          [Implemented - for encrypted storage]
└── Backup Key Shards (BKS)         [Implemented - 2-of-M recovery]
```

**Implementation Status:** MIK/DMK/STK/BKS in `src/key_hierarchy.rs`. MIK generates from CSPRNG; DMK derived via HKDF(MIK, device_id); STK from DMK; BKS 2-of-M XOR-based. export_dmk_for_device/import_dmk_for_device for multi-device sync.

### 4.2 Key Lifetimes
```
Key Type                Lifetime        Rotation
────────────────────────────────────────────────
Master Identity Key     Permanent       Manual only
Device Master Key       1 year          Automatic
Session Key             24 hours        Automatic
Message Key             Per message     Automatic
Ephemeral Key           Per message     Automatic
```

## 5. PROTOCOL MESSAGES

### 5.1 Message Format (EncryptedMessage)
```
┌────────────────────────────────────────────────────────┐
│ B4AE Encrypted Message                                 │
├────────────────────────────────────────────────────────┤
│ Version (2 bytes)                                       │
│ Message Type (1 byte)                                  │
│ Flags (1 byte)                                         │
│ Sequence (8 bytes)                                     │
│ Timestamp (8 bytes)                                    │
│ Nonce (variable, typically 12 bytes for AES-GCM)      │
│ Payload (variable, includes authentication tag)       │
└────────────────────────────────────────────────────────┘

Header fields: version, message_type, flags, sequence, timestamp.
Payload is AES-256-GCM ciphertext (includes 16-byte auth tag inline).
```

### 5.2 Message Types
```
0x01 - HandshakeInit
0x02 - HandshakeResponse
0x03 - HandshakeComplete
0x10 - DataMessage
0x20 - KeyRotation
0x30 - Acknowledgment
0xFF - Error
```

### 5.3 Flags
```
Bit 0: Encrypted
Bit 1: Compressed
Bit 2: Dummy Traffic
Bit 3: Requires Ack
Bit 4-7: Reserved
```

## 6. HANDSHAKE PROTOCOL

### 6.1 Three-Way Handshake
```
Alice                                                Bob
  │                                                   │
  │  HandshakeInit                                    │
  │  ├── Protocol Version                             │
  │  ├── Alice's Hybrid Public Key                    │
  │  ├── Supported Algorithms                         │
  │  └── Signature                                    │
  ├──────────────────────────────────────────────────>│
  │                                                   │
  │                        HandshakeResponse          │
  │                        ├── Bob's Hybrid Public Key│
  │                        ├── Encrypted Shared Secret│
  │                        ├── Selected Algorithms    │
  │                        └── Signature              │
  │<──────────────────────────────────────────────────┤
  │                                                   │
  │  HandshakeComplete                                │
  │  ├── Confirmation                                 │
  │  └── Signature                                    │
  ├──────────────────────────────────────────────────>│
  │                                                   │
  │  [Secure Channel Established]                     │
  │                                                   │
```

### 6.2 HandshakeInit Message
```
HandshakeInit:
├── protocol_version: u16
├── client_random: [u8; 32]
├── hybrid_public_key: HybridPublicKey (length-prefixed serialization)
│   ├── ecdh_public: [u8; 32]     (X25519)
│   ├── kyber_public: [u8; 1568]
│   ├── ecdsa_public: [u8; 32]    (Ed25519)
│   └── dilithium_public: [u8; 2592]
├── supported_algorithms: Vec<AlgorithmId>
├── extensions: Vec<Extension>
└── signature: HybridSignature
```

### 6.3 HandshakeResponse Message
```
HandshakeResponse:
├── protocol_version: u16
├── server_random: [u8; 32]
├── hybrid_public_key: HybridPublicKey
├── encrypted_shared_secret: HybridCiphertext
│   ├── ecdh_ephemeral_public: [u8; 32]     (X25519)
│   └── kyber_ciphertext: [u8; 1568]
├── selected_algorithms: Vec<AlgorithmId>
├── extensions: Vec<Extension>
└── signature: HybridSignature
```

### 6.4 Key Derivation
```
After handshake, derive session keys:

master_secret = HKDF-SHA3-256(
    ikm = shared_secret,  (* from hybrid KEM: kyber_ss || x25519_ss *)
    salt = client_random || server_random,
    info = "B4AE-v1-master-secret",
    length = 32
)

encryption_key = HKDF-SHA3-256(
    ikm = master_secret,
    info = "B4AE-v1-encryption-key",
    length = 32
)

authentication_key = HKDF-SHA3-256(
    ikm = master_secret,
    info = "B4AE-v1-authentication-key",
    length = 32
)

metadata_key = HKDF-SHA3-256(
    ikm = master_secret,
    info = "B4AE-v1-metadata-key",
    length = 32
)
```

## 7. DATA TRANSMISSION

### 7.1 Message Encryption
```
1. Generate per-message ephemeral key:
   message_key = HKDF(session_key, message_counter, 32)

2. Encrypt message:
   ciphertext = AES-256-GCM.encrypt(
       key = message_key,
       nonce = random(12),
       plaintext = message,
       aad = header
   )

3. Apply metadata protection:
   - Pad to block size
   - Add timing delay
   - Generate dummy traffic (if enabled)

4. Transmit encrypted message
```

### 7.2 Message Decryption
```
1. Receive encrypted message

2. Remove metadata protection:
   - Remove padding
   - Extract actual message

3. Derive message key:
   message_key = HKDF(session_key, message_counter, 32)

4. Decrypt message:
   plaintext = AES-256-GCM.decrypt(
       key = message_key,
       nonce = nonce,
       ciphertext = ciphertext,
       aad = header
   )

5. Verify authentication tag
```

## 8. METADATA PROTECTION

### 8.1 Traffic Padding
```
Padding Scheme:
├── Block Sizes: 4KB, 16KB, 64KB (configurable)
├── Padding Format: PKCS#7
└── Overhead: 0-100% depending on message size

Algorithm:
1. Calculate target size: next_multiple(message_size, block_size)
2. Padding length: target_size - message_size
3. Append padding: [padding_length] * padding_length
```

### 8.2 Timing Obfuscation
```
Delay Calculation:
├── Min Delay: 0ms
├── Max Delay: Configurable (default 2000ms)
└── Distribution: Uniform random

Algorithm:
1. Generate random delay: random(0, max_delay)
2. Queue message
3. Wait for delay
4. Transmit message
```

### 8.3 Dummy Traffic
```
Dummy Traffic Generation:
├── Frequency: Configurable (default 10%)
├── Size: Same distribution as real traffic
├── Recipients: Random from contact list
└── Identification: Special flag in header (encrypted)

Algorithm:
1. Periodically check: random(0, 100) < dummy_percent
2. If true: generate dummy message
3. Encrypt with dummy flag set
4. Transmit to random recipient
5. Recipient discards upon decryption
```

## 9. KEY ROTATION

### 9.1 Automatic Rotation
```
Rotation Triggers:
├── Time-based: Every 24 hours
├── Message-based: Every 10,000 messages
├── Data-based: Every 1GB transferred
└── Manual: On-demand

Rotation Process:
1. Generate new session keys
2. Send KeyRotation message
3. Derive new encryption keys
4. Continue with new keys
5. Securely delete old keys
```

### 9.2 KeyRotation Message
```
KeyRotation:
├── new_hybrid_public_key: HybridPublicKey
├── encrypted_new_secret: HybridCiphertext
├── rotation_counter: u64
└── signature: HybridSignature
```

## 10. ERROR HANDLING

### 10.1 Error Types
```
0x01 - Protocol Version Mismatch
0x02 - Unsupported Algorithm
0x03 - Authentication Failed
0x04 - Decryption Failed
0x05 - Invalid Message Format
0x06 - Replay Attack Detected
0xFF - Internal Error
```

### 10.2 Error Message
```
Error:
├── error_code: u8
├── error_message: String
└── recovery_hint: Option<String>
```

## 11. SECURITY CONSIDERATIONS

### 11.1 Threat Model
```
Protected Against:
├── Passive eavesdropping (content and metadata)
├── Active man-in-the-middle attacks
├── Traffic analysis (with proper configuration)
├── Timing attacks (with obfuscation enabled)
├── Replay attacks
├── Quantum computer attacks (based on current understanding)
└── Metadata analysis (local passive adversary)

Not Protected Against:
├── Endpoint compromise (malware, physical access)
├── Side-channel attacks on implementation
├── Social engineering
├── Physical access to devices
├── Global passive adversary (without constant-rate cover traffic)
└── Coercion (rubber-hose cryptanalysis)

Limitations:
├── PQC algorithms are relatively new (standardized 2024)
├── Long-term security not yet proven through extensive cryptanalysis
├── Metadata protection requires proper configuration
├── Performance trade-offs with security features
└── Implementation-dependent side-channel vulnerabilities
```

### 11.2 Cryptographic Assumptions

The security of B4AE relies on the following assumptions:

**Hardness Assumptions:**
├── Module-LWE problem remains hard (Kyber security)
├── Module-SIS problem remains hard (Dilithium security)
├── CDH problem on Curve25519 remains classically hard
├── SHA3-256 provides collision resistance
└── Random oracle model for HKDF

**Implementation Assumptions:**
├── Side-channel resistance requires careful implementation
├── Constant-time operations for critical paths
├── Secure random number generation available
├── Memory protection mechanisms functional
└── No hardware backdoors in cryptographic operations

**Deployment Assumptions:**
├── Endpoints are not compromised
├── Hardware security modules (if used) are trusted
├── Operating system provides basic security guarantees
├── Network infrastructure provides basic connectivity
└── Users follow operational security best practices

### 11.3 Known Limitations

**Cryptographic Limitations:**
1. PQC algorithms are relatively new; unforeseen weaknesses may be discovered
2. Quantum Grover's algorithm reduces symmetric security (AES-256 → 128-bit quantum)
3. Hybrid approach adds bandwidth and computational overhead

**Metadata Protection Limitations:**
1. Global passive adversary can perform traffic correlation
2. Requires constant-rate cover traffic for strong unlinkability (not default)
3. Timing analysis possible without mixnet integration
4. Configuration required for full protection

**Implementation Limitations:**
1. Side-channel vulnerabilities depend on implementation quality
2. Cannot protect against compromised endpoints
3. Performance trade-offs with security features

**Operational Limitations:**
1. Requires secure key storage and distribution
2. More complex than traditional E2EE protocols
3. Not compatible with existing E2EE without adaptation

### 11.4 Security Requirements
```
MUST:
├── Use quantum-resistant algorithms (Kyber-1024, Dilithium5)
├── Implement perfect forward secrecy
├── Protect against replay attacks
├── Validate all signatures
├── Use constant-time operations for critical paths
└── Zeroize sensitive data after use

SHOULD:
├── Enable metadata protection features (requires configuration)
├── Rotate keys regularly (automatic by default)
├── Use hardware security modules where available
├── Implement rate limiting
├── Log security events for audit
└── Conduct regular security assessments

MAY:
├── Support onion routing for enhanced anonymity
├── Implement mix networks for stronger unlinkability
├── Use trusted execution environments
└── Enable constant-rate cover traffic

IMPORTANT NOTES:
├── Security features may have performance implications
├── Metadata protection requires proper configuration
├── Implementation quality affects side-channel resistance
└── Regular security audits recommended
```

## 12. COMPLIANCE

### 12.1 Standards Compliance
```
Cryptographic Standards:
├── NIST FIPS 203 (Kyber)
├── NIST FIPS 204 (Dilithium)
├── NIST FIPS 197 (AES)
└── NIST SP 800-56C (Key Derivation)

Compliance Facilitation:
B4AE provides cryptographic primitives and audit capabilities that 
facilitate compliance with various regulatory frameworks. However, 
protocol implementation alone does not constitute compliance.

Regulatory Considerations:
├── GDPR: Facilitates data protection through encryption and access controls
├── HIPAA: Provides technical safeguards for PHI transmission
├── SOX: Enables financial data protection and audit trails
├── PCI DSS: Supports payment data encryption requirements
└── ISO 27001: Supports information security management

IMPORTANT:
Compliance requires organizational policies, procedures, and controls 
beyond cryptographic protocol implementation. Consult legal and 
compliance experts for specific regulatory requirements.
```

## 13. IMPLEMENTATION NOTES

### 13.1 Performance Targets
```
Operation               Target      Measured (i7-10700K)
────────────────────────────────────────────────────────
Handshake              <200ms      145ms (median), 185ms (95th %ile)
Message Encryption     <10ms       ~0.5ms (1KB message)
Message Decryption     <10ms       ~0.5ms (1KB message)
Throughput             >1000/s     ~1200/s (localhost, 1KB messages)
Memory Usage           <50MB       ~40MB (100 active sessions)

Note: Performance varies significantly based on deployment environment, 
hardware capabilities, and network conditions. Benchmark in your specific 
use case before making performance claims. Network latency typically 
dominates in real-world deployments.
```

### 13.2 Compatibility
```
Minimum Requirements:
├── CPU: 1GHz dual-core
├── RAM: 512MB available
├── Storage: 100MB
└── Network: 1Mbps

Supported Platforms:
├── Desktop: Windows, macOS, Linux
├── Mobile: iOS 14+, Android 8+
├── Web: Modern browsers with WebAssembly
└── IoT: ARM Cortex-A series
```

## 14. VERSION HISTORY

```
Version 1.0 (February 2026)
└── Initial specification
```

## 15. REFERENCES

1. NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
2. NIST FIPS 204: Module-Lattice-Based Digital Signature Standard
3. RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
4. RFC 5116: An Interface and Algorithms for Authenticated Encryption

---

**B4AE Protocol Specification v1.0**  
**Copyright © 2026 B4AE Team**  
**License: MIT OR Apache-2.0**
