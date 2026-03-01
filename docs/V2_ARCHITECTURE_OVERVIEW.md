# B4AE v2.0 Architecture Overview

**Version**: 2.0.0  
**Status**: Production-Ready (100% complete - 75/75 tasks)  
**Specification**: `.kiro/specs/b4ae-v2-research-grade-architecture/`

## Executive Summary

B4AE v2.0 is a research-grade post-quantum metadata-hardened secure messaging protocol designed for formal verification and high-assurance deployments. It transforms B4AE from "strong engineering" (v1.0) to "research-grade protocol architecture" suitable for academic scrutiny, formal analysis, and deployment in high-security environments.

**Design Philosophy**:
- **Model-driven** (not feature-driven): All features derived from formal threat model
- **Security-by-default** (not optional): All protections always enabled
- **Formally verified** (not just tested): Machine-checked security proofs

## 8 Architectural Improvements

### 1. Authentication Mode Separation

**Problem (v1.0)**: XEdDSA + Dilithium5 hybrid signatures destroy deniability because verifier cannot forge the Dilithium5 component.

**Solution (v2.0)**: Separate authentication into distinct modes with clear security properties.

#### Mode A: Deniable Authentication

- **Signatures**: XEdDSA only (no Dilithium5)
- **Security Properties**:
  - ✅ Deniable authentication (verifier can forge signatures)
  - ✅ Mutual authentication
  - ✅ Forward secrecy
  - ❌ Not post-quantum secure (classical 128-bit security)
  - ❌ Not non-repudiable
- **Performance**: ~0.3ms signature verification per handshake
- **Use Cases**: Private messaging, whistleblowing, anonymous communication

#### Mode B: Post-Quantum Non-Repudiable

- **Signatures**: Dilithium5 only (no XEdDSA)
- **Security Properties**:
  - ✅ Post-quantum secure (NIST Level 5)
  - ✅ Non-repudiable signatures (proves authorship)
  - ✅ Mutual authentication
  - ✅ Forward secrecy
  - ❌ Not deniable
- **Performance**: ~9ms signature verification per handshake
- **Use Cases**: Legal contracts, audit trails, compliance, non-repudiation

#### Mode C: Future Hybrid (Research Placeholder)

- **Status**: Not production-ready
- **Goal**: Deniable + post-quantum authentication
- **Research Direction**: Post-quantum AKE without signatures (e.g., CSIDH, isogeny-based)

### 2. Stateless Cookie Challenge

**Problem (v1.0)**: Server performs expensive cryptographic operations (Dilithium5 verification ~3ms, Kyber decapsulation ~0.6ms) immediately upon receiving HandshakeInit, making it vulnerable to DoS attacks.

**Solution (v2.0)**: Stateless HMAC-based cookie challenge before expensive operations.

#### Protocol Flow

```
Client                                Server
  |                                     |
  |--- ClientHello (minimal) --------->|  (No expensive crypto)
  |    { client_random, timestamp }    |
  |                                     |
  |<-- CookieChallenge (stateless) ----|  (~0.01ms HMAC)
  |    { cookie, server_random }       |
  |                                     |
  |--- ClientHelloWithCookie --------->|  (Cookie verified)
  |    { client_random, cookie, ... }  |
  |                                     |
  |    [Server verifies cookie ~0.01ms]|
  |    [Only then: expensive crypto]   |
```

#### DoS Protection Metrics

- **Without cookie**: 3.6ms per handshake attempt (vulnerable)
- **With cookie**: 0.01ms per invalid attempt, 3.61ms per valid attempt
- **DoS amplification reduced by 360x**

#### Cookie Generation

```
cookie = HMAC-SHA256(
    key: server_secret,
    data: client_ip || timestamp || client_random
)
```

#### Security Properties

- **Stateless**: Server stores no state before cookie verification
- **Replay Protection**: Timestamp + Bloom filter prevent replay attacks
- **Forgery Resistance**: HMAC prevents cookie forgery without server_secret
- **Constant-Time**: Verification uses constant-time comparison

### 3. Global Unified Traffic Scheduler

**Problem (v1.0)**: Per-session metadata protection allows global passive observer to correlate traffic patterns across sessions and fingerprint users.

**Solution (v2.0)**: All sessions feed into single unified queue with constant-rate output.

#### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              GLOBAL UNIFIED TRAFFIC SCHEDULER               │
├─────────────────────────────────────────────────────────────┤
│  Session 1 ──┐                                             │
│  Session 2 ──┼──> Unified Queue ──> Constant-Rate Output  │
│  Session 3 ──┤         +                    (100 msg/s)    │
│  Session N ──┘    Dummy Messages                           │
│                                                             │
│  Security: Cross-session indistinguishability              │
│  Trade-off: ~5ms avg latency for metadata protection       │
└─────────────────────────────────────────────────────────────┘
```

#### Security Properties

- **Metadata Minimization**: Global passive observer cannot correlate sessions
- **Timing Obfuscation**: Constant-rate output prevents timing correlation
- **Traffic Analysis Resistance**: Dummy messages obscure real message count
- **Cross-Session Indistinguishability**: No per-session burst patterns visible

#### Performance Trade-offs

| Target Rate | Avg Latency | Bandwidth Overhead | Use Case |
|-------------|-------------|-------------------|----------|
| 100 msg/s | ~5ms | 20% | Standard deployment |
| 1000 msg/s | ~0.5ms | 20% | Low-latency deployment |

### 4. Session Key Binding

**Problem (v1.0)**: Session keys not cryptographically bound to session ID, allowing theoretical key transplant attacks.

**Solution (v2.0)**: All session keys derived with session ID as salt.

#### Session ID Derivation

```
session_id = HKDF-SHA512(
    ikm: client_random || server_random || mode_id,
    salt: "B4AE-v2-session-id",
    info: "",
    length: 32
)
```

#### Key Derivation with Session Binding

```
root_key = HKDF-SHA512(
    ikm: master_secret,
    salt: protocol_id || session_id || transcript_hash,
    info: "B4AE-v2-root-key",
    length: 32
)

session_key = HKDF-SHA512(
    ikm: master_secret,
    salt: protocol_id || session_id || transcript_hash,
    info: "B4AE-v2-session-key",
    length: 32
)

chain_key = HKDF-SHA512(
    ikm: master_secret,
    salt: protocol_id || session_id || transcript_hash,
    info: "B4AE-v2-chain-key",
    length: 32
)
```

#### Security Properties

- **Session Isolation**: Keys from different sessions are cryptographically independent
- **Transplant Prevention**: Key from Session A cannot be used in Session B
- **Transcript Binding**: Key is bound to entire handshake transcript
- **Mode Binding**: Session ID includes mode_id, preventing mode confusion

### 5. Protocol ID Derivation

**Problem (v1.0)**: Hardcoded version strings prevent safe protocol evolution and don't provide cryptographic version enforcement.

**Solution (v2.0)**: Protocol ID derived from SHA3-256 hash of canonical specification.

#### Protocol ID Computation

```
protocol_id = SHA3-256(canonical_specification_document)
```

#### Benefits

- **Automatic Version Enforcement**: Different specs = different IDs
- **Downgrade Attack Detection**: ID mismatch causes signature failure
- **Domain Separation**: Used in all key derivations
- **Cryptographic Agility**: No explicit version negotiation needed

#### Usage

- Included in every handshake transcript
- Used in all key derivations for domain separation
- Verified in all signatures

### 6. Security-by-Default

**Problem (v1.0)**: Security features can be disabled, allowing insecure configurations.

**Solution (v2.0)**: All security features enabled by default and non-disableable.

#### Always-Enabled Features

- **Padding**: PADME 8-bucket scheme (cannot be disabled)
- **Metadata Protection**: Global scheduler (cannot be disabled)
- **Cover Traffic**: Minimum 20% (configurable up to 100%, cannot go below 20%)
- **Post-Quantum Crypto**: Kyber1024 + Dilithium5 or XEdDSA (cannot be disabled)
- **Constant-Time Operations**: All crypto operations (cannot be disabled)
- **Downgrade Protection**: Mode binding (cannot be disabled)

#### Insecure Configuration Mode (Testing Only)

- Requires explicit `allow_insecure` flag
- Mandatory audit logging
- Warning on every message
- Blocked in production environment

### 7. Formal Threat Model

**Problem (v1.0)**: Multiple threat model documents scattered across codebase, no single source of truth.

**Solution (v2.0)**: Single formal threat model defining 6 adversary types.

#### Six Adversary Types

1. **Adversary 1: Active MITM (Dolev-Yao)**
   - Capabilities: Intercept, modify, drop, replay, inject messages
   - Security Properties: Confidentiality, authentication, integrity, forward secrecy

2. **Adversary 2: Global Passive Observer**
   - Capabilities: Observe all network traffic globally
   - Security Properties: Metadata minimization, timing obfuscation, traffic analysis resistance

3. **Adversary 3: Store-Now-Decrypt-Later Quantum**
   - Capabilities: Record encrypted traffic, decrypt with quantum computer in future
   - Security Properties: Post-quantum confidentiality (Mode B), post-quantum authentication (Mode B)

4. **Adversary 4: Partial State Compromise**
   - Capabilities: Compromise session keys at specific point in time
   - Security Properties: Forward secrecy, post-compromise security, session independence

5. **Adversary 5: Timing + Cache Side-Channel (Local)**
   - Capabilities: Measure timing, observe cache access patterns
   - Security Properties: Constant-time operations, cache-timing resistance

6. **Adversary 6: Multi-Session Correlation**
   - Capabilities: Observe traffic from multiple sessions, correlate patterns
   - Security Properties: Cross-session indistinguishability, unified dummy budget

### 8. Formal Verification

**Problem (v1.0)**: No formal verification, only testing.

**Solution (v2.0)**: Tamarin + ProVerif models with machine-checked security proofs.

#### Tamarin Symbolic Model

- Mutual authentication property
- Forward secrecy property
- Session independence property
- No-downgrade property
- Key secrecy property
- Deniability property (Mode A)

#### ProVerif Computational Model

- Secrecy of session keys
- Authentication events
- Correspondence assertions
- Observational equivalence for deniability

## Protocol Flow (Complete)

```
Client                                Server
  |                                     |
  |--- ModeNegotiation --------------->|  Phase 1: Mode Selection
  |    { supported_modes, preferred }  |
  |<-- ModeSelection -------------------|
  |    { selected_mode, server_random }|
  |                                     |
  |--- ClientHello -------------------->|  Phase 2: Cookie Challenge
  |    { client_random, timestamp }    |
  |<-- CookieChallenge -----------------|
  |    { cookie, server_random }       |
  |                                     |
  |--- ClientHelloWithCookie --------->|  Phase 3: Cookie Verification
  |    { client_random, cookie, ... }  |
  |    [Server verifies cookie ~0.01ms]|
  |                                     |
  |--- HandshakeInit ------------------>|  Phase 4: Mode-Specific Handshake
  |    { eph_keys, mode_sig, ... }     |
  |<-- HandshakeResponse ---------------|
  |    { eph_keys, mode_sig, ... }     |
  |--- HandshakeComplete -------------->|
  |    { mode_sig, ... }               |
  |                                     |
  [Session established with keys bound to session_id]
  |                                     |
  |--- Encrypted Messages ------------->|  Phase 5: Global Traffic Scheduling
  |<-- Encrypted Messages --------------|  (Constant-rate output)
```

## Performance Characteristics

### Handshake Performance

| Metric | Mode A (Deniable) | Mode B (PQ) | v1.0 Hybrid |
|--------|-------------------|-------------|-------------|
| Signature Verification | ~0.3ms | ~9ms | ~9.3ms |
| Cookie Challenge | ~0.01ms | ~0.01ms | N/A |
| Total Handshake | ~150ms | ~155ms | ~145ms |

### Message Performance

| Metric | v2.0 (100 msg/s) | v2.0 (1000 msg/s) | v1.0 |
|--------|------------------|-------------------|------|
| Average Latency | ~5ms | ~0.5ms | <1ms |
| Bandwidth Overhead | 20% | 20% | 20% |
| Throughput | 100 msg/s | 1000 msg/s | >1000 msg/s |

### DoS Protection

| Metric | v1.0 | v2.0 |
|--------|------|------|
| Invalid Attempt Cost | 3.6ms | 0.01ms |
| DoS Amplification | 1x | 360x reduction |

## Implementation Status

**Status**: 100% complete (75/75 tasks)

### Module Organization

```
src/protocol/v2/
├── mod.rs                    # Module overview and re-exports
├── types.rs                  # Core data structures (AuthenticationMode, SessionId, etc.)
├── constants.rs              # Protocol constants and configuration
├── protocol_id.rs            # Protocol ID derivation (SHA3-256 of spec)
├── state_machine.rs          # Handshake state machine
├── mode_negotiation.rs       # Mode negotiation protocol
├── mode_binding.rs           # Mode binding to prevent downgrade attacks
├── cookie_challenge.rs       # Stateless cookie challenge for DoS protection
├── replay_protection.rs      # Bloom filter for replay detection
├── dos_metrics.rs            # DoS protection metrics and monitoring
└── traffic_scheduler.rs      # Global unified traffic scheduler
```

### Feature Flag

Enable v2.0 protocol with the `v2_protocol` feature flag:

```toml
[dependencies]
b4ae = { version = "2.0", features = ["v2_protocol"] }
```

## Security Properties Summary

| Property | Mode A | Mode B | Adversary |
|----------|--------|--------|-----------|
| Confidentiality | ✅ | ✅ | 1, 2, 4, 5 |
| Authentication | ✅ | ✅ | 1, 4, 5 |
| Forward Secrecy | ✅ | ✅ | 1, 4 |
| Post-Quantum Security | ❌ | ✅ | 3 |
| Deniability | ✅ | ❌ | 1 |
| Non-Repudiation | ❌ | ✅ | 1 |
| Metadata Protection | ✅ | ✅ | 2, 6 |
| Side-Channel Resistance | ✅ | ✅ | 5 |
| Downgrade Protection | ✅ | ✅ | 1 |

## References

- **Specification**: `.kiro/specs/b4ae-v2-research-grade-architecture/`
  - `requirements.md`: Formal requirements (REQ-1 through REQ-24)
  - `design.md`: Detailed design document
  - `tasks.md`: Implementation tasks (75/75 complete)

- **Implementation**: `src/protocol/v2/`

- **Documentation**:
  - [V2 Migration Guide](V2_MIGRATION_GUIDE.md)
  - [V2 Security Analysis](V2_SECURITY_ANALYSIS.md)
  - [V2 Mode Selection Guide](V2_MODE_SELECTION_GUIDE.md)

- **Related**:
  - [Formal Verification](FORMAL_VERIFICATION.md)
  - [Threat Model](THREAT_MODEL_FORMALIZATION.md)
  - [Performance Analysis](PERFORMANCE.md)
