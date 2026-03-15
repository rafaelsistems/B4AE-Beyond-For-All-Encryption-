# B4AE v2.0 Mode Selection Guide

**Version:** 2.0  
**Date:** 2026  
**Status:** Production-Ready  
**Target Audience:** Developers, System Architects, Security Engineers

## Overview

B4AE v2.0 introduces authentication mode separation to provide clear, non-overlapping security properties. This guide helps you choose the right mode for your application based on security requirements, performance constraints, and threat model.

**Two Authentication Modes:**
- **Mode A (Deniable):** XEdDSA signatures, fast handshakes, deniable authentication
- **Mode B (PQ Non-Repudiable):** Dilithium5 signatures, post-quantum secure, non-repudiable

**Key Insight:** There is no "best" mode - only the right mode for your specific requirements.

## Quick Decision Tree

```
START: What are your security requirements?

┌─────────────────────────────────────────────────────────────┐
│ Do you need DENIABILITY?                                    │
│ (Ability to plausibly deny sending messages)                │
└─────────────────────────────────────────────────────────────┘
         │
         ├─ YES ──────────────────────────────────────────────┐
         │                                                     │
         │  ┌──────────────────────────────────────────────┐  │
         │  │ Is quantum threat a concern?                 │  │
         │  │ (Data confidential for >10 years?)           │  │
         │  └──────────────────────────────────────────────┘  │
         │           │                                         │
         │           ├─ NO ──> ✅ MODE A (Deniable)           │
         │           │                                         │
         │           └─ YES ──> ⚠️ CONFLICT                   │
         │                      Cannot have both deniability  │
         │                      and post-quantum security     │
         │                      Choose priority:              │
         │                      - Deniability → Mode A        │
         │                      - Quantum → Mode B            │
         │                                                     │
         └─ NO ───────────────────────────────────────────────┤
                                                               │
┌──────────────────────────────────────────────────────────┐  │
│ Do you need NON-REPUDIATION?                             │  │
│ (Proof of authorship for legal/compliance?)              │  │
└──────────────────────────────────────────────────────────┘  │
         │                                                     │
         ├─ YES ──> ✅ MODE B (PQ Non-Repudiable)             │
         │                                                     │
         └─ NO ────────────────────────────────────────────┐  │
                                                            │  │
┌──────────────────────────────────────────────────────┐   │  │
│ Do you need POST-QUANTUM security?                   │   │  │
│ (Data confidential for >10 years?)                   │   │  │
└──────────────────────────────────────────────────────┘   │  │
         │                                                  │  │
         ├─ YES ──> ✅ MODE B (PQ Non-Repudiable)          │  │
         │                                                  │  │
         └─ NO ────────────────────────────────────────┐   │  │
                                                        │   │  │
┌──────────────────────────────────────────────────┐   │   │  │
│ Are you resource-constrained?                    │   │   │  │
│ (IoT, mobile, low-power devices?)                │   │   │  │
└──────────────────────────────────────────────────┘   │   │  │
         │                                              │   │  │
         ├─ YES ──> ✅ MODE A (Deniable)               │   │  │
         │          (30x faster signatures)            │   │  │
         │                                              │   │  │
         └─ NO ──> ✅ MODE A or MODE B                 │   │  │
                   (Either works, choose based on      │   │  │
                    other requirements)                │   │  │
                                                        │   │  │
```

## Mode Comparison Table

| Property | Mode A (Deniable) | Mode B (PQ Non-Repudiable) |
|----------|-------------------|----------------------------|
| **Signatures** | XEdDSA only | Dilithium5 only |
| **Key Exchange** | X25519 + Kyber1024 | X25519 + Kyber1024 |
| **Encryption** | ChaCha20-Poly1305 | ChaCha20-Poly1305 |
| **Deniability** | ✅ Yes | ❌ No |
| **Post-Quantum** | ❌ No | ✅ Yes (NIST L5) |
| **Non-Repudiation** | ❌ No | ✅ Yes |
| **Signature Gen** | ~0.1ms | ~5ms |
| **Signature Verify** | ~0.2ms | ~5ms |
| **Handshake Time** | ~150ms | ~155ms |
| **Signature Size** | 96 bytes | 4595 bytes |
| **Quantum Resistance** | ❌ Vulnerable | ✅ Secure |
| **Legal Evidence** | ❌ No | ✅ Yes |
| **Adversary Coverage** | A₁,A₂,A₄,A₅,A₆ | A₁,A₂,A₃,A₄,A₅,A₆ |

## Use Case Scenarios

### Scenario 1: Private Messaging Application

**Requirements:**
- End-to-end encrypted messaging
- Plausible deniability for users
- Real-time communication (low latency)
- Mobile and desktop clients

**Threat Model:**
- Primary: A₁ (MITM), A₂ (Global Passive), A₆ (Multi-Session)
- Not concerned: A₃ (Quantum) - messages are ephemeral

**Recommended Mode:** ✅ **Mode A (Deniable)**

**Rationale:**
- Deniability important for private communications
- Users should be able to plausibly deny sending messages
- Fast handshakes provide good user experience
- Quantum threat not immediate concern for ephemeral messages
- 30x faster signature operations benefit mobile devices

**Configuration:**
```rust
use b4ae::protocol::v2::AuthenticationMode;

let client = B4aeClient::new_v2(AuthenticationMode::ModeA)?;
client.set_scheduler_rate(100.0); // 100 msg/s, ~5ms latency
client.set_cover_traffic_budget(0.20); // 20% minimum
```

**Security Properties:**
- ✅ Deniable authentication
- ✅ Forward secrecy
- ✅ Post-compromise security
- ✅ Metadata protection (global scheduler)
- ❌ Not post-quantum secure (acceptable trade-off)

---

### Scenario 2: Whistleblowing Platform

**Requirements:**
- Anonymous source protection
- Plausible deniability CRITICAL
- Strong metadata protection
- Integration with Tor

**Threat Model:**
- Primary: A₁ (MITM), A₂ (Global Passive), A₆ (Multi-Session)
- Critical: Deniability for source protection
- High-risk: Nation-state adversaries

**Recommended Mode:** ✅ **Mode A (Deniable)** - REQUIRED

**Rationale:**
- Deniability is non-negotiable for source protection
- Sources must be able to plausibly deny contact
- Mode B would destroy deniability (non-repudiable signatures)
- Strong metadata protection essential
- Must use with Tor for anonymity

**Configuration:**
```rust
use b4ae::protocol::v2::AuthenticationMode;

let client = B4aeClient::new_v2(AuthenticationMode::ModeA)?;
client.set_scheduler_rate(10.0); // 10 msg/s, ~50ms latency (high security)
client.set_cover_traffic_budget(1.00); // 100% cover traffic (maximum protection)
// MUST use with Tor or Nym for network-level anonymity
```

**Security Properties:**
- ✅ Deniable authentication (CRITICAL)
- ✅ Strong metadata protection
- ✅ Cross-session indistinguishability
- ✅ Network anonymity (via Tor)
- ⚠️ Accept quantum vulnerability for deniability

**Critical Warning:** Never use Mode B for whistleblowing - it destroys deniability!

---

### Scenario 3: Legal Document Signing

**Requirements:**
- Digital signatures for contracts
- Non-repudiation for legal validity
- Long-term signature validity (>10 years)
- Compliance with eIDAS/ESIGN Act

**Threat Model:**
- Primary: A₁ (MITM), A₃ (Quantum)
- Critical: Non-repudiation for legal evidence
- Long-term: Quantum threat (10-30 years)

**Recommended Mode:** ✅ **Mode B (PQ Non-Repudiable)** - REQUIRED

**Rationale:**
- Non-repudiation required for legal validity
- Signatures must prove authorship to third parties
- Post-quantum security for long-term validity
- Mode A would not provide legal evidence (deniable)
- Compliance requirements mandate non-repudiable signatures

**Configuration:**
```rust
use b4ae::protocol::v2::AuthenticationMode;

let client = B4aeClient::new_v2(AuthenticationMode::ModeB)?;
client.set_scheduler_rate(1000.0); // 1000 msg/s, ~0.5ms latency (low latency)
client.set_cover_traffic_budget(0.20); // 20% minimum (metadata not critical)
```

**Security Properties:**
- ✅ Non-repudiable signatures (CRITICAL)
- ✅ Post-quantum secure (long-term validity)
- ✅ Legal evidence admissibility
- ✅ Compliance with digital signature regulations
- ❌ Not deniable (by design, required for legal validity)

**Legal Considerations:**
- Signatures can be used as evidence in court
- Key compromise has legal implications
- Implement key revocation procedures
- Consider regulatory requirements (eIDAS, ESIGN Act)

---

### Scenario 4: Financial Transactions

**Requirements:**
- Secure payment processing
- Audit trails for compliance
- Non-repudiation for dispute resolution
- Low latency for real-time transactions

**Threat Model:**
- Primary: A₁ (MITM), A₃ (Quantum)
- Critical: Non-repudiation for audit trails
- Compliance: PCI-DSS, SOX, financial regulations

**Recommended Mode:** ✅ **Mode B (PQ Non-Repudiable)** - REQUIRED

**Rationale:**
- Non-repudiation required for audit trails
- Dispute resolution requires proof of authorship
- Post-quantum security for long-term financial records
- Compliance requirements mandate non-repudiable signatures
- Low latency important but not critical (5ms acceptable)

**Configuration:**
```rust
use b4ae::protocol::v2::AuthenticationMode;

let client = B4aeClient::new_v2(AuthenticationMode::ModeB)?;
client.set_scheduler_rate(1000.0); // 1000 msg/s, ~0.5ms latency
client.set_cover_traffic_budget(0.20); // 20% minimum
// Enable audit logging for all transactions
client.enable_audit_logging(true);
```

**Security Properties:**
- ✅ Non-repudiable signatures (audit trails)
- ✅ Post-quantum secure (long-term records)
- ✅ Compliance with financial regulations
- ✅ Dispute resolution support
- ❌ Not deniable (required for accountability)

**Compliance Considerations:**
- PCI-DSS: Non-repudiation for payment processing
- SOX: Audit trails for financial reporting
- GDPR: Data protection and privacy
- Key management: HSM recommended for financial keys

---

### Scenario 5: IoT Device Communication

**Requirements:**
- Resource-constrained devices (limited CPU/memory)
- Low power consumption
- Secure device-to-cloud communication
- Firmware updates

**Threat Model:**
- Primary: A₁ (MITM), A₄ (State Compromise)
- Constraint: Limited CPU/memory resources
- Not concerned: A₃ (Quantum) - short-term data

**Recommended Mode:** ✅ **Mode A (Deniable)**

**Rationale:**
- Fast handshakes for resource-constrained devices
- Mode A 30x faster signature operations (0.3ms vs 9ms)
- Smaller signature size (96 bytes vs 4595 bytes)
- Lower memory footprint
- Quantum threat not immediate concern for IoT data

**Configuration:**
```rust
use b4ae::protocol::v2::AuthenticationMode;

let client = B4aeClient::new_v2(AuthenticationMode::ModeA)?;
client.set_scheduler_rate(100.0); // 100 msg/s, balanced
client.set_cover_traffic_budget(0.20); // 20% minimum (bandwidth-constrained)
```

**Performance Benefits:**
- Signature generation: 0.1ms (vs 5ms Mode B)
- Signature verification: 0.2ms (vs 5ms Mode B)
- Signature size: 96 bytes (vs 4595 bytes Mode B)
- Memory footprint: ~50% smaller than Mode B

**Security Properties:**
- ✅ Mutual authentication
- ✅ Forward secrecy
- ✅ Post-compromise security
- ✅ Low resource usage
- ❌ Not post-quantum secure (acceptable for IoT)

---

### Scenario 6: Government/Military Communications

**Requirements:**
- Classified information protection
- Long-term confidentiality (>30 years)
- Strong metadata protection
- Nation-state adversary resistance

**Threat Model:**
- Primary: A₁ (MITM), A₂ (Global Passive), A₃ (Quantum)
- Critical: Long-term confidentiality
- High-risk: Nation-state adversaries with quantum computers

**Recommended Mode:** ✅ **Mode B (PQ Non-Repudiable)** - REQUIRED

**Rationale:**
- Post-quantum security for long-term classified data
- Nation-state adversaries may have quantum computers in 10-30 years
- Non-repudiation for accountability and audit trails
- Strong metadata protection against global surveillance
- Compliance with government security standards

**Configuration:**
```rust
use b4ae::protocol::v2::AuthenticationMode;

let client = B4aeClient::new_v2(AuthenticationMode::ModeB)?;
client.set_scheduler_rate(10.0); // 10 msg/s, ~50ms latency (high security)
client.set_cover_traffic_budget(1.00); // 100% cover traffic (maximum protection)
// Deploy on classified network with additional security layers
```

**Security Properties:**
- ✅ Post-quantum secure (CRITICAL for long-term secrets)
- ✅ Non-repudiation (accountability)
- ✅ Strong metadata protection
- ✅ Nation-state adversary resistance
- ❌ Not deniable (required for accountability)

**Deployment Considerations:**
- Deploy on classified network (SIPRNET, JWICS)
- Use hardware security modules (HSM) for key storage
- Implement strict key management procedures
- Regular security audits and penetration testing
- Compliance with NIST, NSA, CNSS standards

## Performance Considerations

### Handshake Performance

**Mode A (Deniable):**
```
Phase 1: Mode Negotiation        ~1ms
Phase 2: Cookie Challenge        ~0.01ms (server), ~1ms (client)
Phase 3: Key Exchange            ~0.6ms (Kyber1024 + X25519)
Phase 4: Signature Operations    ~0.3ms (XEdDSA)
Phase 5: Network RTT             ~145ms (typical)
─────────────────────────────────────────────
Total Handshake Time:            ~150ms
```

**Mode B (PQ Non-Repudiable):**
```
Phase 1: Mode Negotiation        ~1ms
Phase 2: Cookie Challenge        ~0.01ms (server), ~1ms (client)
Phase 3: Key Exchange            ~0.6ms (Kyber1024 + X25519)
Phase 4: Signature Operations    ~9ms (Dilithium5)
Phase 5: Network RTT             ~145ms (typical)
─────────────────────────────────────────────
Total Handshake Time:            ~155ms
```

**Performance Comparison:**

| Metric | Mode A | Mode B | Difference |
|--------|--------|--------|------------|
| Signature Generation | 0.1ms | 5ms | 50x slower |
| Signature Verification | 0.2ms | 5ms | 25x slower |
| Total Signature Ops | 0.3ms | 9ms | 30x slower |
| Complete Handshake | 150ms | 155ms | 3% slower |
| Signature Size | 96 bytes | 4595 bytes | 48x larger |

**Key Insight:** Mode B adds ~5ms to handshake time, which is negligible compared to network RTT (~145ms). The main difference is in signature operations, not total handshake time.

### Message Throughput

**Both modes have identical message encryption/decryption performance:**
- Encryption: ChaCha20-Poly1305 (~1 GB/s on modern CPU)
- Decryption: ChaCha20-Poly1305 (~1 GB/s on modern CPU)
- Throughput: Limited by global scheduler rate, not crypto

**Global Scheduler Impact:**

| Scheduler Rate | Avg Latency | Max Throughput | Use Case |
|----------------|-------------|----------------|----------|
| 10 msg/s | ~50ms | 10 msg/s | High security |
| 100 msg/s | ~5ms | 100 msg/s | Balanced |
| 1000 msg/s | ~0.5ms | 1000 msg/s | Low latency |

**Key Insight:** Message throughput is limited by scheduler rate, not authentication mode.

### Resource Usage

**CPU Usage:**

| Operation | Mode A | Mode B | Notes |
|-----------|--------|--------|-------|
| Handshake (client) | ~2ms CPU | ~7ms CPU | Mode B 3.5x more CPU |
| Handshake (server) | ~2ms CPU | ~7ms CPU | Mode B 3.5x more CPU |
| Message Encrypt | ~0.01ms CPU | ~0.01ms CPU | Identical |
| Message Decrypt | ~0.01ms CPU | ~0.01ms CPU | Identical |

**Memory Usage:**

| Component | Mode A | Mode B | Notes |
|-----------|--------|--------|-------|
| Public Key | 32 bytes | 2592 bytes | Mode B 81x larger |
| Secret Key | 64 bytes | 4864 bytes | Mode B 76x larger |
| Signature | 96 bytes | 4595 bytes | Mode B 48x larger |
| Session State | ~1 KB | ~1 KB | Identical |

**Bandwidth Usage:**

| Message Type | Mode A | Mode B | Notes |
|--------------|--------|--------|-------|
| HandshakeInit | ~200 bytes | ~7000 bytes | Mode B 35x larger |
| HandshakeResponse | ~200 bytes | ~7000 bytes | Mode B 35x larger |
| Encrypted Message | ~100 bytes | ~100 bytes | Identical |

**Key Insight:** Mode B has significantly higher resource usage for handshakes, but identical for messages.

### Performance Recommendations

**Choose Mode A if:**
- ✅ Resource-constrained environment (IoT, mobile)
- ✅ High handshake frequency (many short sessions)
- ✅ Bandwidth-constrained network
- ✅ Low-power devices (battery-operated)

**Choose Mode B if:**
- ✅ Long-lived sessions (few handshakes)
- ✅ Server-side deployment (ample resources)
- ✅ Post-quantum security required
- ✅ Non-repudiation required

**Performance Optimization Tips:**
1. **Session Reuse:** Reuse sessions to amortize handshake cost
2. **Connection Pooling:** Maintain persistent connections
3. **Batch Operations:** Batch multiple messages per session
4. **Scheduler Tuning:** Adjust scheduler rate based on latency requirements

## Security Trade-offs

### Deniability vs Non-Repudiation

**Fundamental Trade-off:** You cannot have both deniability and non-repudiation simultaneously.

**Deniability (Mode A):**
- **Property:** Verifier can forge signatures indistinguishable from real signatures
- **Implication:** Cannot prove message authorship to third parties
- **Use Case:** Private messaging, whistleblowing, anonymous communication
- **Legal Status:** Signatures not admissible as evidence

**Non-Repudiation (Mode B):**
- **Property:** Signatures prove authorship to third parties
- **Implication:** Cannot plausibly deny sending messages
- **Use Case:** Legal contracts, audit trails, compliance
- **Legal Status:** Signatures admissible as evidence

**Decision Matrix:**

| Requirement | Mode A | Mode B |
|-------------|--------|--------|
| Plausible deniability | ✅ | ❌ |
| Legal evidence | ❌ | ✅ |
| Whistleblower protection | ✅ | ❌ |
| Audit trails | ❌ | ✅ |
| Anonymous communication | ✅ | ❌ |
| Compliance (eIDAS, ESIGN) | ❌ | ✅ |

### Classical Security vs Post-Quantum Security

**Quantum Threat Timeline:**
- **Current:** No practical quantum computers exist
- **10 years:** Small quantum computers possible
- **20 years:** Medium quantum computers likely
- **30 years:** Large quantum computers capable of breaking X25519/Ed25519

**Classical Security (Mode A):**
- **Security Level:** 128-bit classical security (X25519, XEdDSA)
- **Quantum Resistance:** ❌ Vulnerable to Shor's algorithm
- **Timeline:** Secure for ~10-30 years
- **Use Case:** Short-term communications, ephemeral data

**Post-Quantum Security (Mode B):**
- **Security Level:** NIST Level 5 (Kyber1024, Dilithium5)
- **Quantum Resistance:** ✅ Resistant to Shor's and Grover's algorithms
- **Timeline:** Secure for >30 years (current knowledge)
- **Use Case:** Long-term confidential data, future-proof security

**Risk Assessment:**

| Data Lifetime | Quantum Risk | Recommended Mode |
|---------------|--------------|------------------|
| <1 year | Low | Mode A |
| 1-5 years | Low | Mode A |
| 5-10 years | Medium | Mode A or B |
| 10-20 years | High | Mode B |
| >20 years | Very High | Mode B |

**Store-Now-Decrypt-Later (SNDL) Attack:**
- **Threat:** Adversary records encrypted traffic today, decrypts with quantum computer in future
- **Mode A:** Vulnerable (X25519 breakable with quantum computer)
- **Mode B:** Secure (Kyber1024 resistant to quantum attacks)
- **Mitigation:** Use Mode B for data requiring >10 year confidentiality

### Performance vs Security

**Latency Trade-off:**

| Scheduler Rate | Latency | Metadata Protection | Recommendation |
|----------------|---------|---------------------|----------------|
| 10 msg/s | 50ms | Very Strong | High-security applications |
| 100 msg/s | 5ms | Strong | Balanced (default) |
| 1000 msg/s | 0.5ms | Moderate | Low-latency applications |

**Bandwidth Trade-off:**

| Cover Traffic | Bandwidth Overhead | Metadata Protection | Recommendation |
|---------------|-------------------|---------------------|----------------|
| 20% | 1.2x | Minimum | Bandwidth-constrained |
| 50% | 1.5x | Strong | Balanced |
| 100% | 2.0x | Maximum | High-security applications |

**Resource Trade-off:**

| Mode | CPU | Memory | Bandwidth | Recommendation |
|------|-----|--------|-----------|----------------|
| Mode A | Low | Low | Low | Resource-constrained |
| Mode B | Medium | Medium | High | Server-side deployment |

## Deployment Considerations

### Platform Constraints

**Mobile Devices:**
- **Recommendation:** Mode A (Deniable)
- **Rationale:** 
  - Limited CPU/battery (Mode A 30x faster signatures)
  - Smaller signature size (96 bytes vs 4595 bytes)
  - Lower memory footprint
  - Better user experience (faster handshakes)

**IoT Devices:**
- **Recommendation:** Mode A (Deniable)
- **Rationale:**
  - Extremely resource-constrained
  - Low power consumption critical
  - Smaller code size
  - Faster handshakes

**Server-Side:**
- **Recommendation:** Mode A or Mode B (based on requirements)
- **Rationale:**
  - Ample resources (CPU, memory, bandwidth)
  - Can handle Mode B overhead
  - Choose based on security requirements, not performance

**Embedded Systems:**
- **Recommendation:** Mode A (Deniable)
- **Rationale:**
  - Limited resources
  - Real-time constraints
  - Smaller code size
  - Faster execution

### Regulatory Requirements

**eIDAS (EU Digital Signature Regulation):**
- **Requirement:** Non-repudiable digital signatures
- **Recommended Mode:** Mode B (PQ Non-Repudiable)
- **Compliance:** Dilithium5 signatures meet eIDAS requirements

**ESIGN Act (US Electronic Signature Law):**
- **Requirement:** Non-repudiable electronic signatures
- **Recommended Mode:** Mode B (PQ Non-Repudiable)
- **Compliance:** Dilithium5 signatures meet ESIGN Act requirements

**GDPR (EU Data Protection Regulation):**
- **Requirement:** Data protection and privacy
- **Recommended Mode:** Mode A or Mode B (based on use case)
- **Compliance:** Both modes provide confidentiality and integrity

**HIPAA (US Healthcare Privacy Law):**
- **Requirement:** Patient data confidentiality and integrity
- **Recommended Mode:** Mode B (PQ Non-Repudiable)
- **Compliance:** Non-repudiation for audit trails, post-quantum for long-term records

**PCI-DSS (Payment Card Industry Security Standard):**
- **Requirement:** Secure payment processing, audit trails
- **Recommended Mode:** Mode B (PQ Non-Repudiable)
- **Compliance:** Non-repudiation for audit trails, strong authentication

**NIST Post-Quantum Cryptography Standards:**
- **Requirement:** Post-quantum secure cryptography
- **Recommended Mode:** Mode B (PQ Non-Repudiable)
- **Compliance:** Kyber1024 and Dilithium5 are NIST PQC standards

### Threat Model Alignment

**Threat Model Assessment:**

1. **Identify Primary Adversaries:**
   - A₁ (Dolev-Yao MITM): Active network attacker
   - A₂ (Global Passive): Mass surveillance
   - A₃ (Quantum): Store-now-decrypt-later
   - A₄ (State Compromise): Memory/storage compromise
   - A₅ (Side-Channel): Timing/cache attacks
   - A₆ (Multi-Session): Cross-session correlation

2. **Assess Adversary Capabilities:**
   - Nation-state: A₁, A₂, A₃, A₄, A₅, A₆
   - Criminal organization: A₁, A₄, A₅
   - Malicious insider: A₄, A₅
   - Script kiddie: A₁

3. **Choose Mode Based on Adversaries:**
   - **A₃ (Quantum) is primary concern:** Mode B
   - **Deniability is critical:** Mode A
   - **Non-repudiation is required:** Mode B
   - **Resource-constrained:** Mode A

**Threat Model Examples:**

| Application | Primary Adversaries | Recommended Mode |
|-------------|---------------------|------------------|
| Private Messaging | A₁, A₂, A₆ | Mode A |
| Whistleblowing | A₁, A₂, A₆ | Mode A |
| Legal Contracts | A₁, A₃ | Mode B |
| Financial Transactions | A₁, A₃ | Mode B |
| IoT Communication | A₁, A₄ | Mode A |
| Government/Military | A₁, A₂, A₃, A₆ | Mode B |

## Migration Guidance

### When to Switch Modes

**Scenario 1: Application Requirements Change**

**Example:** Private messaging app adds legal document signing feature

**Solution:**
- Keep Mode A for private messaging
- Add Mode B for document signing
- Support both modes simultaneously
- Let users choose mode per conversation

```rust
// Private messaging conversation
let private_chat = client.new_session(bob_id, AuthenticationMode::ModeA)?;

// Legal document signing conversation
let legal_docs = client.new_session(lawyer_id, AuthenticationMode::ModeB)?;
```

**Scenario 2: Quantum Threat Becomes Imminent**

**Example:** Practical quantum computers announced, need to migrate to post-quantum

**Solution:**
- Migrate all sessions to Mode B
- Implement gradual rollout
- Support both modes during transition
- Deprecate Mode A after migration complete

```rust
// Phase 1: Support both modes
client.set_supported_modes(vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB]);
client.set_preferred_mode(AuthenticationMode::ModeB);

// Phase 2: Mode B only
client.set_supported_modes(vec![AuthenticationMode::ModeB]);
```

**Scenario 3: Regulatory Requirements Change**

**Example:** New regulation requires non-repudiable signatures

**Solution:**
- Migrate to Mode B for compliance
- Update all clients and servers
- Implement audit logging
- Document compliance measures

### Mode Negotiation Protocol

**Automatic Mode Selection:**

B4AE v2.0 supports automatic mode negotiation between client and server:

```rust
// Client specifies supported modes and preference
let client_modes = vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB];
let client_preferred = AuthenticationMode::ModeA;

client.set_supported_modes(client_modes);
client.set_preferred_mode(client_preferred);

// Server specifies supported modes and preference
let server_modes = vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB];
let server_preferred = AuthenticationMode::ModeB;

server.set_supported_modes(server_modes);
server.set_preferred_mode(server_preferred);

// Negotiation algorithm:
// 1. Find intersection of supported modes
// 2. If client preferred is in intersection, use it
// 3. Else if server preferred is in intersection, use it
// 4. Else use first mode in intersection
// 5. If no intersection, handshake fails
```

**Negotiation Examples:**

| Client Modes | Server Modes | Client Pref | Server Pref | Result |
|--------------|--------------|-------------|-------------|--------|
| [A, B] | [A, B] | A | B | A (client preferred) |
| [A, B] | [A, B] | B | A | B (client preferred) |
| [A] | [B] | A | B | ❌ Fail (no intersection) |
| [A, B] | [B] | A | B | B (only option) |
| [A] | [A, B] | A | B | A (only option) |

**Downgrade Protection:**

Mode negotiation is cryptographically bound to prevent downgrade attacks:

```rust
// Mode binding included in all signatures
mode_binding = SHA3-256("B4AE-v2-mode-binding" || client_random || server_random || mode_id);

// Any modification to negotiated mode causes signature verification failure
```

### Backward Compatibility

**v1.0 to v2.0 Migration:**

B4AE v2.0 is **NOT backward compatible** with v1.0. Migration requires:

1. **Update all clients and servers to v2.0**
2. **Choose authentication mode (Mode A or Mode B)**
3. **Update configuration and code**
4. **Test thoroughly before production deployment**

**Migration Strategies:**

**Strategy 1: Big Bang Migration**
- Migrate all clients and servers simultaneously
- Downtime required
- Fastest migration
- Higher risk

**Strategy 2: Gradual Rollout**
- Deploy v2.0 servers alongside v1.0 servers
- Gradually migrate clients to v2.0
- No downtime
- Slower migration
- Lower risk

**Strategy 3: Dual-Stack Deployment**
- Run v1.0 and v2.0 in parallel
- Clients choose version
- Longest migration period
- Lowest risk
- Higher operational complexity

**Recommendation:** Strategy 2 (Gradual Rollout) for production systems

## Configuration Examples

### Example 1: Private Messaging App (Mode A)

```rust
use b4ae::protocol::v2::{AuthenticationMode, GlobalTrafficScheduler};
use b4ae::B4aeClient;

// Initialize client with Mode A (Deniable)
let mut client = B4aeClient::new_v2(AuthenticationMode::ModeA)?;

// Configure global traffic scheduler
let scheduler = GlobalTrafficScheduler::new(100.0); // 100 msg/s
scheduler.set_cover_traffic_budget(0.20); // 20% cover traffic
client.set_global_scheduler(scheduler);

// Establish session
client.establish_session_v2(&bob_id, AuthenticationMode::ModeA)?;

// Send message
let encrypted = client.encrypt_message_v2(&bob_id, b"Hello, Bob!")?;

// Receive message
let decrypted = client.decrypt_message_v2(&alice_id, &encrypted)?;
```

### Example 2: Legal Document Signing (Mode B)

```rust
use b4ae::protocol::v2::{AuthenticationMode, GlobalTrafficScheduler};
use b4ae::B4aeClient;

// Initialize client with Mode B (PQ Non-Repudiable)
let mut client = B4aeClient::new_v2(AuthenticationMode::ModeB)?;

// Configure global traffic scheduler (low latency)
let scheduler = GlobalTrafficScheduler::new(1000.0); // 1000 msg/s
scheduler.set_cover_traffic_budget(0.20); // 20% cover traffic
client.set_global_scheduler(scheduler);

// Enable audit logging
client.enable_audit_logging(true);

// Establish session
client.establish_session_v2(&lawyer_id, AuthenticationMode::ModeB)?;

// Sign document
let document = b"Legal contract content...";
let encrypted = client.encrypt_message_v2(&lawyer_id, document)?;

// Signature is non-repudiable and can be used as legal evidence
```

### Example 3: Whistleblowing Platform (Mode A + Tor)

```rust
use b4ae::protocol::v2::{AuthenticationMode, GlobalTrafficScheduler};
use b4ae::B4aeClient;

// Initialize client with Mode A (Deniable) - REQUIRED for whistleblowing
let mut client = B4aeClient::new_v2(AuthenticationMode::ModeA)?;

// Configure global traffic scheduler (high security)
let scheduler = GlobalTrafficScheduler::new(10.0); // 10 msg/s (strong metadata protection)
scheduler.set_cover_traffic_budget(1.00); // 100% cover traffic (maximum protection)
client.set_global_scheduler(scheduler);

// CRITICAL: Use with Tor for network-level anonymity
client.set_proxy("socks5://127.0.0.1:9050")?; // Tor SOCKS proxy

// Establish session
client.establish_session_v2(&journalist_id, AuthenticationMode::ModeA)?;

// Send anonymous tip
let tip = b"Confidential information...";
let encrypted = client.encrypt_message_v2(&journalist_id, tip)?;

// Deniability: Source can plausibly deny sending message
```

### Example 4: IoT Device Communication (Mode A)

```rust
use b4ae::protocol::v2::{AuthenticationMode, GlobalTrafficScheduler};
use b4ae::B4aeClient;

// Initialize client with Mode A (Deniable) - optimized for resource-constrained devices
let mut client = B4aeClient::new_v2(AuthenticationMode::ModeA)?;

// Configure global traffic scheduler (balanced)
let scheduler = GlobalTrafficScheduler::new(100.0); // 100 msg/s
scheduler.set_cover_traffic_budget(0.20); // 20% cover traffic (bandwidth-constrained)
client.set_global_scheduler(scheduler);

// Establish session with cloud server
client.establish_session_v2(&cloud_server_id, AuthenticationMode::ModeA)?;

// Send sensor data
let sensor_data = b"Temperature: 25C, Humidity: 60%";
let encrypted = client.encrypt_message_v2(&cloud_server_id, sensor_data)?;

// Performance: Mode A 30x faster signatures, 48x smaller signatures
```

### Example 5: Multi-Mode Application

```rust
use b4ae::protocol::v2::{AuthenticationMode, GlobalTrafficScheduler};
use b4ae::B4aeClient;
use std::collections::HashMap;

// Application supports both modes
let mut client = B4aeClient::new_v2(AuthenticationMode::ModeA)?; // Default mode

// Configure supported modes
client.set_supported_modes(vec![
    AuthenticationMode::ModeA,
    AuthenticationMode::ModeB,
]);

// Track mode per conversation
let mut conversation_modes: HashMap<UserId, AuthenticationMode> = HashMap::new();

// Private messaging: Mode A
conversation_modes.insert(friend_id, AuthenticationMode::ModeA);
client.establish_session_v2(&friend_id, AuthenticationMode::ModeA)?;

// Legal documents: Mode B
conversation_modes.insert(lawyer_id, AuthenticationMode::ModeB);
client.establish_session_v2(&lawyer_id, AuthenticationMode::ModeB)?;

// Send message with appropriate mode
fn send_message(client: &mut B4aeClient, recipient: &UserId, message: &[u8], 
                conversation_modes: &HashMap<UserId, AuthenticationMode>) -> Result<()> {
    let mode = conversation_modes.get(recipient).unwrap();
    let encrypted = client.encrypt_message_v2(recipient, message)?;
    Ok(())
}
```

## Common Mistakes and How to Avoid Them

### Mistake 1: Using Mode A for Legal Contracts

**Problem:** Mode A provides deniable signatures, which are not admissible as legal evidence.

**Symptom:** Signatures cannot be verified by third parties, legal disputes cannot be resolved.

**Solution:** Use Mode B for legal contracts, audit trails, and any scenario requiring non-repudiation.

```rust
// ❌ WRONG: Mode A for legal contracts
let client = B4aeClient::new_v2(AuthenticationMode::ModeA)?;
client.sign_contract(&contract)?; // Signature is deniable, not legal evidence

// ✅ CORRECT: Mode B for legal contracts
let client = B4aeClient::new_v2(AuthenticationMode::ModeB)?;
client.sign_contract(&contract)?; // Signature is non-repudiable, legal evidence
```

### Mistake 2: Using Mode B for Whistleblowing

**Problem:** Mode B provides non-repudiable signatures, which destroy deniability and endanger sources.

**Symptom:** Whistleblowers cannot plausibly deny contact, signatures prove authorship.

**Solution:** Use Mode A for whistleblowing, anonymous communication, and any scenario requiring deniability.

```rust
// ❌ WRONG: Mode B for whistleblowing
let client = B4aeClient::new_v2(AuthenticationMode::ModeB)?;
client.send_anonymous_tip(&journalist_id, &tip)?; // Signature proves authorship, endangers source

// ✅ CORRECT: Mode A for whistleblowing
let client = B4aeClient::new_v2(AuthenticationMode::ModeA)?;
client.send_anonymous_tip(&journalist_id, &tip)?; // Signature is deniable, protects source
```

### Mistake 3: Ignoring Quantum Threat for Long-Term Data

**Problem:** Using Mode A for data requiring >10 year confidentiality exposes it to quantum attacks.

**Symptom:** Data encrypted today can be decrypted with quantum computer in 10-30 years.

**Solution:** Use Mode B for long-term confidential data (>10 year horizon).

```rust
// ❌ WRONG: Mode A for long-term confidential data
let client = B4aeClient::new_v2(AuthenticationMode::ModeA)?;
client.encrypt_classified_document(&document)?; // Vulnerable to quantum attacks

// ✅ CORRECT: Mode B for long-term confidential data
let client = B4aeClient::new_v2(AuthenticationMode::ModeB)?;
client.encrypt_classified_document(&document)?; // Post-quantum secure
```

### Mistake 4: Choosing Mode Based on Performance Alone

**Problem:** Choosing Mode A because it's faster, without considering security requirements.

**Symptom:** Security requirements not met, compliance violations, legal issues.

**Solution:** Choose mode based on security requirements first, then optimize performance.

```rust
// ❌ WRONG: Choosing mode based on performance alone
let client = B4aeClient::new_v2(AuthenticationMode::ModeA)?; // Faster, but wrong for use case

// ✅ CORRECT: Choose mode based on security requirements
let mode = if requires_non_repudiation || requires_post_quantum {
    AuthenticationMode::ModeB
} else if requires_deniability {
    AuthenticationMode::ModeA
} else {
    // Default based on threat model
    AuthenticationMode::ModeA
};
let client = B4aeClient::new_v2(mode)?;
```

### Mistake 5: Not Using Mixnet for Metadata Protection

**Problem:** Relying on global traffic scheduler alone for strong metadata protection.

**Symptom:** Network-level metadata (IP addresses) still visible to adversaries.

**Solution:** Use B4AE v2.0 with Tor or Nym for strong metadata protection.

```rust
// ❌ WRONG: Global scheduler alone for high-security applications
let client = B4aeClient::new_v2(AuthenticationMode::ModeA)?;
// Network-level metadata still visible

// ✅ CORRECT: Global scheduler + Tor for strong metadata protection
let client = B4aeClient::new_v2(AuthenticationMode::ModeA)?;
client.set_proxy("socks5://127.0.0.1:9050")?; // Tor SOCKS proxy
// Network-level metadata protected by Tor
```

## Summary and Recommendations

### Quick Reference

**Choose Mode A (Deniable) if:**
- ✅ Deniability is required or important
- ✅ Resource-constrained environment (IoT, mobile)
- ✅ High handshake frequency
- ✅ Quantum threat not immediate concern (<10 years)
- ✅ Private messaging, whistleblowing, anonymous communication

**Choose Mode B (PQ Non-Repudiable) if:**
- ✅ Non-repudiation is required
- ✅ Post-quantum security is required
- ✅ Long-term confidentiality (>10 years)
- ✅ Legal contracts, audit trails, compliance
- ✅ Financial transactions, government/military communications

### Decision Checklist

- [ ] Identify primary security requirements (deniability, non-repudiation, post-quantum)
- [ ] Assess threat model (which adversaries are primary concern?)
- [ ] Evaluate quantum threat timeline (data lifetime >10 years?)
- [ ] Consider regulatory requirements (eIDAS, ESIGN, HIPAA, PCI-DSS)
- [ ] Assess performance constraints (resource-constrained devices?)
- [ ] Choose authentication mode based on requirements
- [ ] Configure global traffic scheduler based on latency/security trade-off
- [ ] Test thoroughly before production deployment
- [ ] Document mode selection rationale for future reference

### Additional Resources

- **V2_SECURITY_ANALYSIS.md**: Comprehensive security analysis of v2.0 features
- **V2_ARCHITECTURE_OVERVIEW.md**: High-level architecture and design philosophy
- **V2_MIGRATION_GUIDE.md**: Migration from v1.0 to v2.0
- **THREAT_MODEL_FORMALIZATION.md**: Formal threat model (single source of truth)
- **FORMAL_VERIFICATION.md**: Formal verification plan and status

### Support

- **Documentation**: https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-/tree/main/docs
- **Issues**: https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-/issues
- **Email**: rafaelsistems@gmail.com

---

**Document Status:** Complete  
**Last Updated:** 2026  
**Version:** 2.0  
**Author:** B4AE Security Team  
**Review Status:** Production-Ready
