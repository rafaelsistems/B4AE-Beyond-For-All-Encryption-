# B4AE v2.0 Deployment Guide

**Version**: 2.0.0  
**Status**: Production-Ready (100% complete)  
**Last Updated**: 2026

## Table of Contents

1. [Overview](#overview)
2. [V2.0 Architecture](#v20-architecture)
3. [Authentication Mode Selection](#authentication-mode-selection)
4. [Deployment Configuration Presets](#deployment-configuration-presets)
5. [Monitoring and Metrics](#monitoring-and-metrics)
6. [Migration and Rollout Strategy](#migration-and-rollout-strategy)
7. [Compatibility Matrix](#compatibility-matrix)
8. [Troubleshooting Guide](#troubleshooting-guide)

---

## Overview

This guide provides comprehensive information for deploying B4AE v2.0 in production environments. B4AE v2.0 is a research-grade post-quantum metadata-hardened secure messaging protocol designed for formal verification and high-assurance deployments.

### V2.0 Key Features

- **Authentication Mode Separation**: Mode A (deniable) vs Mode B (post-quantum non-repudiable)
- **Stateless Cookie Challenge**: DoS protection with 360x amplification reduction
- **Global Unified Traffic Scheduler**: Cross-session metadata protection
- **Session Key Binding**: Cryptographic binding to session ID
- **Protocol ID Derivation**: SHA3-256 of canonical specification
- **Security-by-Default**: All protections always enabled
- **Formal Verification**: Tamarin + ProVerif requirements
- **PADMÉ Padding**: Length obfuscation using exponential bucket padding

### Deployment Benefits

- **Mode-Based Security**: Choose deniability (Mode A) or post-quantum security (Mode B)
- **DoS Resilience**: 0.01ms per invalid handshake attempt vs 3.6ms in v1.0
- **Metadata Protection**: Global scheduler with configurable rates (10-1000 msg/s)
- **Performance**: Mode A ~150ms handshake, Mode B ~155ms handshake
- **Configurable Overhead**: Balance security and performance for your use case
- **Comprehensive Monitoring**: Track effectiveness of security features in real-time

---

## V2.0 Architecture

### 8 Architectural Improvements

B4AE v2.0 represents a fundamental transformation from "strong engineering" to "research-grade protocol architecture":

1. **Authentication Mode Separation** (Mode A/B/C) - Deniable vs PQ
2. **Stateless Cookie Challenge** - DoS protection before expensive crypto
3. **Global Unified Traffic Scheduler** - Cross-session metadata protection
4. **Session Key Binding** - Cryptographic binding to session ID
5. **Protocol ID Derivation** - SHA3-256 of canonical spec
6. **Security-by-Default** - No optional security features
7. **Formal Threat Model** - Single source of truth (6 adversary types)
8. **Formal Verification** - Tamarin + ProVerif requirements

### Protocol Flow

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
  |<-- CookieChallenge -----------------|  (~0.01ms HMAC)
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

### Performance Characteristics

| Metric | Mode A (Deniable) | Mode B (PQ) | v1.0 |
|--------|-------------------|-------------|------|
| Handshake Time | ~150ms | ~155ms | ~145ms |
| Signature Verification | ~0.3ms | ~9ms | ~9.3ms |
| DoS Protection | 0.01ms/invalid | 0.01ms/invalid | 3.6ms/attempt |
| Metadata Latency | ~5ms (100 msg/s) | ~5ms (100 msg/s) | <1ms |

---

## Authentication Mode Selection

### Mode A: Deniable Authentication

**Use Case**: Private messaging, whistleblowing, anonymous communication

**Security Properties**:
- ✅ Deniable authentication (verifier can forge signatures)
- ✅ Mutual authentication
- ✅ Forward secrecy
- ✅ Fast handshake (~0.3ms signature operations)
- ❌ Not post-quantum secure (classical 128-bit security)
- ❌ Not non-repudiable

**Configuration**:
```rust
use b4ae::protocol::v2::{AuthenticationMode, ModeNegotiationConfig};

let config = ModeNegotiationConfig {
    supported_modes: vec![AuthenticationMode::ModeA],
    preferred_mode: AuthenticationMode::ModeA,
};
```

**Recommended For**:
- Private messaging applications
- Whistleblower protection systems
- Journalist-source communications
- Anonymous communication platforms

### Mode B: Post-Quantum Non-Repudiable

**Use Case**: Legal contracts, audit trails, compliance, non-repudiation

**Security Properties**:
- ✅ Post-quantum secure (NIST Level 5)
- ✅ Non-repudiable signatures (prove authorship)
- ✅ Mutual authentication
- ✅ Forward secrecy
- ❌ Not deniable
- ⚠️ Slower handshake (~9ms signature operations)

**Configuration**:
```rust
use b4ae::protocol::v2::{AuthenticationMode, ModeNegotiationConfig};

let config = ModeNegotiationConfig {
    supported_modes: vec![AuthenticationMode::ModeB],
    preferred_mode: AuthenticationMode::ModeB,
};
```

**Recommended For**:
- Legal contracts and agreements
- Audit trails and compliance
- Financial transactions
- Government and military communications

### Mode Comparison

| Property | Mode A (Deniable) | Mode B (PQ) |
|----------|-------------------|-------------|
| Deniability | ✅ Yes | ❌ No |
| Post-Quantum | ❌ No | ✅ Yes |
| Non-Repudiation | ❌ No | ✅ Yes |
| Handshake Speed | ✅ Fast (~0.3ms) | ⚠️ Slower (~9ms) |
| Quantum Resistance | ❌ Vulnerable | ✅ Secure |
| Signatures | XEdDSA only | Dilithium5 only |

**See Also**: [V2_MODE_SELECTION_GUIDE.md](V2_MODE_SELECTION_GUIDE.md) for detailed mode selection guidance.

---

## Monitoring and Metrics

### Available Metrics

The B4AE v2.0 protocol exposes comprehensive metrics through the `TrafficStatistics` API and configuration queries.

#### 1. V2.0 Protocol Metrics

Access v2.0-specific metrics:

```rust
use b4ae::protocol::v2::{ProtocolMetrics, TrafficScheduler};

let scheduler = TrafficScheduler::new(config)?;
let metrics = scheduler.metrics();

// Mode negotiation metrics
println!("Mode A handshakes: {}", metrics.mode_a_handshakes);
println!("Mode B handshakes: {}", metrics.mode_b_handshakes);

// Cookie challenge metrics
println!("Cookie challenges issued: {}", metrics.cookie_challenges_issued);
println!("Cookie verifications: {}", metrics.cookie_verifications);
println!("Invalid cookies rejected: {}", metrics.invalid_cookies_rejected);

// DoS protection metrics
println!("DoS attempts blocked: {}", metrics.dos_attempts_blocked);
println!("Avg cookie verification time: {:.2}ms", metrics.avg_cookie_verification_ms);
```

#### 2. Global Traffic Scheduler Metrics

Monitor cross-session metadata protection:

```rust
use b4ae::protocol::v2::traffic_scheduler::GlobalScheduler;

let scheduler = GlobalScheduler::instance();
let stats = scheduler.statistics();

// Traffic scheduling metrics
println!("Active sessions: {}", stats.active_sessions);
println!("Messages queued: {}", stats.messages_queued);
println!("Messages sent: {}", stats.messages_sent);
println!("Dummy messages: {}", stats.dummy_messages);

// Performance metrics
println!("Avg queue latency: {:.2}ms", stats.avg_queue_latency_ms);
println!("Target rate: {} msg/s", stats.target_rate_msgs_per_sec);
println!("Actual rate: {:.2} msg/s", stats.actual_rate_msgs_per_sec);

// Metadata protection effectiveness
println!("Cross-session indistinguishability: {:.2}%", 
    stats.indistinguishability_score * 100.0);
```

#### 3. Session Binding Metrics

Track session isolation:

```rust
use b4ae::protocol::v2::session_binding::SessionMetrics;

let metrics = SessionMetrics::global();

// Session metrics
println!("Active sessions: {}", metrics.active_sessions);
println!("Session keys derived: {}", metrics.session_keys_derived);
println!("Key transplant attempts blocked: {}", metrics.key_transplant_blocked);

// Session ID uniqueness
println!("Unique session IDs: {}", metrics.unique_session_ids);
```

#### 4. Traffic Statistics

Access real-time traffic statistics through the `MetadataProtector`:

```rust
use b4ae::metadata::protector::MetadataProtector;

let protector = MetadataProtector::new(config)?;
let stats = protector.statistics();

// Real and dummy message counts
println!("Real messages: {}", stats.real_messages);
println!("Dummy messages: {}", stats.dummy_messages);
println!("Total messages: {}", stats.total_messages());

// Bandwidth metrics
println!("Total bytes sent: {}", stats.total_bytes_sent);
println!("Average message size: {:.2} bytes", stats.average_message_size);

// Cover traffic effectiveness
println!("Dummy ratio: {:.2}%", stats.dummy_ratio() * 100.0);
```

**Available Methods:**

- `real_messages: u64` - Count of real messages sent
- `dummy_messages: u64` - Count of dummy/cover traffic messages sent
- `total_bytes_sent: u64` - Total bandwidth used (real + dummy)
- `average_message_size: f64` - Average size of all messages
- `total_messages() -> u64` - Total message count (real + dummy)
- `dummy_ratio() -> f64` - Ratio of dummy to total messages (0.0 to 1.0)

Track padding overhead by comparing original and padded message sizes:

```rust
use b4ae::crypto::padding::PadmePadding;

let padding = PadmePadding::new(config);
let original_size = plaintext.len();
let padded_size = padding.padded_length(original_size);
let overhead = ((padded_size - original_size) as f64 / original_size as f64) * 100.0;

println!("Padding overhead: {:.2}%", overhead);
```

**Bucket Sizes:**
- 512 bytes, 1 KB, 2 KB, 4 KB, 8 KB, 16 KB, 32 KB, 64 KB

**Average Overhead:**
- Typical message distribution: < 5%
- Small messages (< 512B): Up to 100%
- Large messages (> 32KB): < 2%

#### 5. Padding Overhead Metrics

Monitor constant-time operation performance through timing measurements:

```rust
use std::time::Instant;

let start = Instant::now();
// Perform constant-time operation
let result = ct_memcmp(&secret1, &secret2);
let duration = start.elapsed();

println!("Constant-time comparison: {:?}", duration);
```

**Expected Performance:**
- Constant-time comparison: < 20% overhead vs naive comparison
- Table lookup: O(n) but < 1μs for tables up to 256 elements
- Overall throughput: > 1000 messages/second for 1KB messages

#### 6. Constant-Time Operation Performance

Query current configuration and statistics:

```rust
// Get current metadata protection configuration
let config = protector.config();
println!("Cover traffic rate: {}", config.cover_traffic_rate);
println!("Timing delay range: {}-{}ms", 
    config.timing_delay_min_ms, 
    config.timing_delay_max_ms);

// Get padding configuration
let padding_config = padding.config();
println!("Min bucket: {} bytes", padding_config.min_bucket_size);
println!("Max bucket: {} bytes", padding_config.max_bucket_size);
```

#### 7. Configuration Query API

### Monitoring Best Practices

1. **Track Mode Distribution**: Monitor Mode A vs Mode B usage to understand security posture
2. **Monitor DoS Protection**: Track cookie challenge success rate and blocked attempts
3. **Track Dummy Ratio**: Monitor `dummy_ratio()` to ensure cover traffic is being generated at the configured rate
4. **Monitor Bandwidth**: Track `total_bytes_sent` to understand bandwidth overhead
5. **Measure Latency**: Track end-to-end message latency including global scheduler delays
6. **Log Security Events**: Log padding validation failures, authentication failures, and mode downgrade attempts
7. **Performance Baselines**: Establish baseline metrics before enabling features
8. **Session Isolation**: Monitor key transplant attempts to detect attacks

### Example Monitoring Dashboard

```rust
use std::time::Duration;
use tokio::time::interval;
use b4ae::protocol::v2::traffic_scheduler::GlobalScheduler;

async fn monitoring_loop() {
    let mut interval = interval(Duration::from_secs(60));
    
    loop {
        interval.tick().await;
        
        let scheduler = GlobalScheduler::instance();
        let stats = scheduler.statistics();
        
        println!("=== B4AE v2.0 Metrics (1 min) ===");
        println!("Active sessions: {}", stats.active_sessions);
        println!("Messages sent: {}", stats.messages_sent);
        println!("Dummy messages: {}", stats.dummy_messages);
        println!("Dummy ratio: {:.2}%", 
            (stats.dummy_messages as f64 / stats.messages_sent as f64) * 100.0);
        println!("Avg queue latency: {:.2}ms", stats.avg_queue_latency_ms);
        println!("Target rate: {} msg/s", stats.target_rate_msgs_per_sec);
        println!("Actual rate: {:.2} msg/s", stats.actual_rate_msgs_per_sec);
    }
}
```

---

## Deployment Configuration Presets

B4AE v2.0 provides three pre-configured deployment presets optimized for different security/performance trade-offs.

### High Security Configuration

**Use Case**: Maximum security for high-value communications, government/military applications, or when facing sophisticated adversaries.

**Configuration:**

```rust
use b4ae::protocol::v2::{
    AuthenticationMode, ModeNegotiationConfig,
    TrafficSchedulerConfig, GlobalScheduler
};
use b4ae::metadata::MetadataProtectionConfig;
use b4ae::crypto::padding::{PadmeConfig, PadmePadding};

// Mode: Post-Quantum (Mode B)
let mode_config = ModeNegotiationConfig {
    supported_modes: vec![AuthenticationMode::ModeB],
    preferred_mode: AuthenticationMode::ModeB,
};

// Global Traffic Scheduler: High security
let scheduler_config = TrafficSchedulerConfig {
    target_rate_msgs_per_sec: 100.0,
    dummy_message_rate: 0.5,  // 50% dummy traffic
    constant_rate_mode: true,
    max_queue_latency_ms: 10.0,
};
let scheduler = GlobalScheduler::new(scheduler_config)?;

// Metadata protection: High security
let meta_config = MetadataProtectionConfig::high_security();
// - Cover traffic rate: 50%
// - Constant-rate mode: enabled
// - Target rate: 2.0 messages/sec
// - Timing delays: 100-2000ms
// - Traffic shaping: enabled

// Padding: High security
let padding_config = PadmeConfig {
    min_bucket_size: 512,
    max_bucket_size: 65536,
    bucket_multiplier: 2.0,
};
let padding = PadmePadding::new(padding_config);

// Cookie challenge: Always enabled (security-by-default)
// DoS protection: 360x amplification reduction
```

**Performance Impact:**
- Bandwidth overhead: ~50% (cover traffic)
- Latency increase: ~5-10ms (global scheduler) + 100-2000ms (timing delays)
- Padding overhead: < 5% average
- Handshake time: ~155ms (Mode B)
- Throughput: ~100 messages/second (constant-rate)
- DoS protection: 0.01ms per invalid attempt

**Security Benefits:**
- Post-quantum secure (Mode B)
- Strong protection against traffic analysis (global scheduler)
- Cross-session indistinguishability
- Length obfuscation with 8 bucket sizes
- DoS resilience (360x improvement)
- Comprehensive side-channel resistance

**Recommended For:**
- Government and military communications
- High-value financial transactions
- Legal contracts requiring non-repudiation
- Compliance-heavy environments (SOC2, HIPAA)

---

### Balanced Configuration

**Use Case**: Good security with acceptable performance for most production deployments.

**Configuration:**

```rust
use b4ae::protocol::v2::{
    AuthenticationMode, ModeNegotiationConfig,
    TrafficSchedulerConfig, GlobalScheduler
};
use b4ae::metadata::MetadataProtectionConfig;
use b4ae::crypto::padding::{PadmeConfig, PadmePadding};

// Mode: Support both, prefer Mode A (deniable)
let mode_config = ModeNegotiationConfig {
    supported_modes: vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB],
    preferred_mode: AuthenticationMode::ModeA,
};

// Global Traffic Scheduler: Balanced
let scheduler_config = TrafficSchedulerConfig {
    target_rate_msgs_per_sec: 100.0,
    dummy_message_rate: 0.2,  // 20% dummy traffic
    constant_rate_mode: true,
    max_queue_latency_ms: 5.0,
};
let scheduler = GlobalScheduler::new(scheduler_config)?;

// Metadata protection: Balanced
let meta_config = MetadataProtectionConfig::balanced();
// - Cover traffic rate: 20%
// - Constant-rate mode: disabled
// - Timing delays: 50-500ms
// - Traffic shaping: enabled

// Padding: Balanced
let padding_config = PadmeConfig {
    min_bucket_size: 1024,
    max_bucket_size: 16384,
    bucket_multiplier: 2.0,
};
let padding = PadmePadding::new(padding_config);
```

**Performance Impact:**
- Bandwidth overhead: ~20% (cover traffic)
- Latency increase: ~5ms (global scheduler) + 50-500ms (timing delays)
- Padding overhead: < 5% average
- Handshake time: ~150ms (Mode A)
- Throughput: ~100 messages/second
- DoS protection: 0.01ms per invalid attempt

**Security Benefits:**
- Deniable authentication (Mode A) with Mode B fallback
- Moderate protection against traffic analysis
- Cross-session indistinguishability
- Length obfuscation with 5 bucket sizes
- DoS resilience (360x improvement)
- Comprehensive side-channel resistance

**Recommended For:**
- Enterprise messaging applications
- Healthcare communications (HIPAA)
- Legal communications (attorney-client)
- General secure messaging
- Private messaging platforms

---

### Low Overhead Configuration

**Use Case**: Minimal overhead for performance-sensitive applications or when metadata protection is less critical.

**Configuration:**

```rust
use b4ae::protocol::v2::{
    AuthenticationMode, ModeNegotiationConfig,
    TrafficSchedulerConfig, GlobalScheduler
};
use b4ae::metadata::MetadataProtectionConfig;
use b4ae::crypto::padding::{PadmeConfig, PadmePadding};

// Mode: Mode A only (fast handshake)
let mode_config = ModeNegotiationConfig {
    supported_modes: vec![AuthenticationMode::ModeA],
    preferred_mode: AuthenticationMode::ModeA,
};

// Global Traffic Scheduler: Low overhead
let scheduler_config = TrafficSchedulerConfig {
    target_rate_msgs_per_sec: 1000.0,  // High throughput
    dummy_message_rate: 0.0,  // No dummy traffic
    constant_rate_mode: false,
    max_queue_latency_ms: 1.0,
};
let scheduler = GlobalScheduler::new(scheduler_config)?;

// Metadata protection: Low overhead (minimal)
let meta_config = MetadataProtectionConfig::low_overhead();
// - Cover traffic rate: 0%
// - Constant-rate mode: disabled
// - Timing delays: none
// - Traffic shaping: disabled

// Padding: Low overhead
let padding_config = PadmeConfig {
    min_bucket_size: 2048,
    max_bucket_size: 8192,
    bucket_multiplier: 2.0,
};
let padding = PadmePadding::new(padding_config);
```

**Performance Impact:**
- Bandwidth overhead: < 5% (padding only)
- Latency increase: ~0.5-1ms (global scheduler, minimal)
- Padding overhead: < 5% average
- Handshake time: ~150ms (Mode A)
- Throughput: ~1000 messages/second
- DoS protection: 0.01ms per invalid attempt

**Security Benefits:**
- Deniable authentication (Mode A)
- Basic length obfuscation with 3 bucket sizes
- DoS resilience (360x improvement)
- Session key binding
- Comprehensive side-channel resistance
- Minimal metadata protection

**Recommended For:**
- Internal corporate communications
- Low-latency applications
- High-throughput systems
- Development and testing
- Performance-sensitive deployments

---

### Configuration Compatibility and Warnings

#### Compatible Feature Combinations

✅ **Recommended Combinations:**
- Mode B + Global Scheduler + Padding (Maximum security)
- Mode A + Global Scheduler + Padding (Balanced security with deniability)
- Mode A + Padding (Good protection, lower overhead)
- Padding only (Basic length obfuscation)

⚠️ **Warning Combinations:**
- Mode A without quantum resistance (vulnerable to harvest-now-decrypt-later)
- Global Scheduler without padding (cover traffic reveals message sizes)
- No padding + No metadata protection (minimal security hardening)

❌ **Incompatible Combinations:**
- None - all features are compatible in v2.0 (security-by-default)

#### V2.0 Security-by-Default

**Always-Enabled Features** (cannot be disabled):
- Cookie challenge DoS protection
- Session key binding to session_id
- Protocol ID derivation
- Constant-time operations
- Downgrade protection (mode binding)

**Configurable Features**:
- Authentication mode (Mode A vs Mode B)
- Global traffic scheduler rate (10-1000 msg/s)
- Dummy message rate (0-100%)
- Padding bucket configuration
- Timing delays (0-2000ms)

#### Configuration Validation

The system automatically validates configurations and returns errors for invalid settings:

```rust
use b4ae::protocol::v2::TrafficSchedulerConfig;

let config = TrafficSchedulerConfig {
    target_rate_msgs_per_sec: 100.0,
    dummy_message_rate: 1.5,  // Invalid: must be 0.0-1.0
    constant_rate_mode: true,
    max_queue_latency_ms: 5.0,
};

match config.validate() {
    Ok(_) => println!("Configuration valid"),
    Err(e) => eprintln!("Configuration error: {}", e),
}
```

**Validation Rules:**
- `target_rate_msgs_per_sec` must be > 0 and ≤ 10000
- `dummy_message_rate` must be in [0.0, 1.0]
- `max_queue_latency_ms` must be > 0
- `cover_traffic_rate` must be in [0.0, 1.0]
- `timing_delay_min_ms` must be ≤ `timing_delay_max_ms`
- `min_bucket_size` must be ≤ `max_bucket_size`
- `bucket_multiplier` must be > 1.0
- `supported_modes` must not be empty

---

## Migration and Rollout Strategy

### Migration from v1.0 to v2.0

**Breaking Changes:**
- Authentication mode separation (Mode A/B replaces hybrid XEdDSA+Dilithium5)
- Cookie challenge added to handshake flow
- Global traffic scheduler replaces per-session metadata protection
- Session key binding changes key derivation

**See**: [V2_MIGRATION_GUIDE.md](V2_MIGRATION_GUIDE.md) for detailed migration instructions.

### Gradual Rollout Strategy

Deploy v2.0 features incrementally to minimize risk and validate each stage:

#### Phase 1: Cookie Challenge DoS Protection (Week 1)

**Goal**: Enable DoS protection with minimal user impact

**Steps:**
1. Deploy v2.0 with cookie challenge enabled
2. Monitor cookie challenge metrics
3. Validate DoS protection effectiveness
4. Run performance tests

**Rollback Plan**: Revert to v1.0 if handshake success rate < 99%

**Success Criteria**:
- Cookie challenge success rate > 99%
- Invalid attempts blocked: > 95%
- Avg cookie verification time < 0.02ms
- No increase in handshake failures

**Monitoring:**
```rust
let metrics = protocol.dos_metrics();
println!("Cookie challenges issued: {}", metrics.cookie_challenges_issued);
println!("Invalid cookies rejected: {}", metrics.invalid_cookies_rejected);
println!("DoS attempts blocked: {}", metrics.dos_attempts_blocked);
```

#### Phase 2: Mode Selection (Week 2-3)

**Goal**: Enable authentication mode separation with backward compatibility

**Steps:**
1. Deploy with Mode A + Mode B support
2. Configure preferred mode based on use case
3. Monitor mode distribution
4. Validate handshake success rates for both modes

**Rollback Plan**: Revert to v1.0 if mode negotiation failures > 1%

**Success Criteria**:
- Mode negotiation success rate > 99%
- Mode A handshake time < 160ms
- Mode B handshake time < 165ms
- No authentication failures

**Configuration:**
```rust
// Support both modes, prefer Mode A
let mode_config = ModeNegotiationConfig {
    supported_modes: vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB],
    preferred_mode: AuthenticationMode::ModeA,
};
```

**Important**: This phase requires coordinated upgrade as handshake protocol changes.

#### Phase 3: Global Traffic Scheduler (Week 4-5)

**Goal**: Enable cross-session metadata protection with configurable overhead

**Steps:**
1. Deploy global traffic scheduler with low rate (10 msg/s)
2. Enable for 10% of sessions (canary deployment)
3. Monitor queue latency and throughput
4. Gradually increase to 50%, then 100%
5. Upgrade to balanced configuration (100 msg/s) after stabilization

**Rollback Plan**: Disable global scheduler if latency > 20ms or throughput < 50 msg/s

**Success Criteria**:
- Avg queue latency < 10ms
- Actual rate matches target rate (±10%)
- Cross-session indistinguishability > 90%
- No impact on message delivery reliability

**Monitoring:**
```rust
let scheduler = GlobalScheduler::instance();
let stats = scheduler.statistics();
println!("Avg queue latency: {:.2}ms", stats.avg_queue_latency_ms);
println!("Target rate: {} msg/s", stats.target_rate_msgs_per_sec);
println!("Actual rate: {:.2} msg/s", stats.actual_rate_msgs_per_sec);
```

#### Phase 4: Session Key Binding (Week 6)

**Goal**: Enable cryptographic session isolation

**Steps:**
1. Deploy session key binding (automatic in v2.0)
2. Monitor session metrics
3. Validate key transplant protection
4. Run security tests

**Rollback Plan**: Not applicable (core security feature)

**Success Criteria**:
- All sessions have unique session_id
- Key transplant attempts blocked: 100%
- No session key collisions
- No impact on performance

**Monitoring:**
```rust
let metrics = SessionMetrics::global();
println!("Active sessions: {}", metrics.active_sessions);
println!("Unique session IDs: {}", metrics.unique_session_ids);
println!("Key transplant attempts blocked: {}", metrics.key_transplant_blocked);
```

#### Phase 5: PADMÉ Padding (Week 7)

**Goal**: Enable length obfuscation with backward compatibility

**Steps:**
1. Deploy padding with `low_overhead` configuration
2. Enable padding for 10% of sessions (canary deployment)
3. Monitor padding overhead and message sizes
4. Gradually increase to 50%, then 100%
5. Upgrade to `balanced` configuration after stabilization

**Rollback Plan**: Disable padding if overhead > 10% or errors occur

**Success Criteria**:
- Average padding overhead < 5%
- No padding validation errors
- Backward compatibility with non-padded clients maintained

**Backward Compatibility**:
```rust
// Sessions automatically support both padded and unpadded messages
let encrypted = if padding_enabled {
    session.encrypt_message_with_padding(plaintext, &padding)?
} else {
    session.encrypt_message(plaintext)?
};
```

### Backward Compatibility Considerations

#### V1.0 to V2.0 Compatibility

| Feature | V1.0 | V2.0 | Compatible? |
|---------|------|------|-------------|
| Handshake Protocol | Hybrid XEdDSA+Dilithium5 | Mode A or Mode B | ❌ No (breaking change) |
| Cookie Challenge | No | Yes | ❌ No (protocol change) |
| Global Scheduler | No | Yes | ✅ Yes (optional) |
| Session Binding | No | Yes | ❌ No (key derivation change) |
| Padding | Yes | Yes | ✅ Yes (backward compatible) |

**Migration Strategy:**
- **Coordinated Upgrade**: All parties must upgrade to v2.0 simultaneously
- **No Gradual Migration**: v1.0 and v2.0 cannot interoperate
- **Maintenance Window**: Schedule downtime for upgrade
- **Rollback Plan**: Keep v1.0 deployment ready for rollback

#### Interoperability Matrix

| Client Version | Server Version | Compatible? | Notes |
|----------------|----------------|-------------|-------|
| v1.0 | v1.0 | ✅ Yes | Legacy protocol |
| v1.0 | v2.0 | ❌ No | Breaking changes |
| v2.0 | v1.0 | ❌ No | Breaking changes |
| v2.0 | v2.0 | ✅ Yes | Full v2.0 protocol |

### Feature Enablement Order

**Recommended Order:**

1. **Cookie Challenge** (Automatic, core security)
2. **Mode Selection** (Requires coordination)
3. **Global Traffic Scheduler** (Optional, configurable)
4. **Session Key Binding** (Automatic, core security)
5. **PADMÉ Padding** (Optional, backward compatible)

**Rationale:**
- Start with core security features (cookie challenge, session binding)
- Add mode selection (requires coordination)
- Enable optional features last (global scheduler, padding)
- All core security features are always enabled (security-by-default)

---

## Compatibility Matrix

### Feature Compatibility

| Feature | Backward Compatible | Requires Coordination | Performance Impact | Security Benefit |
|---------|--------------------|-----------------------|-------------------|------------------|
| Constant-Time Ops | ✅ Yes | No | < 20% CPU | Side-channel resistance |
| PADMÉ Padding | ✅ Yes | No | < 5% bandwidth | Length obfuscation |
| XEdDSA | ❌ No | Yes | Minimal | Plausible deniability |
| Cover Traffic | ✅ Yes | No | Configurable (0-50%) | Traffic analysis resistance |
| Timing Delays | ✅ Yes | No | Configurable (0-2000ms) | Timing correlation resistance |
| Traffic Shaping | ✅ Yes | No | < 10% latency | Burst pattern hiding |

### Protocol Version Compatibility

| Protocol Version | Padding | XEdDSA | Metadata Protection | Notes |
|------------------|---------|--------|---------------------|-------|
| 1.0 (Non-hardened) | No | No | No | Original B4AE |
| 1.1 (Hardened) | Yes | Yes | Yes | Full security suite |

**Version Negotiation:**
- Handshake includes protocol version
- Clients negotiate highest common version
- Fallback to 1.0 if hardening not supported

### Dependency Compatibility

| Dependency | Minimum Version | Recommended Version | Purpose |
|------------|----------------|---------------------|---------|
| `x25519-dalek` | 2.0 | Latest | X25519 key exchange |
| `curve25519-dalek` | 4.0 | Latest | Curve25519 operations |
| `pqcrypto-dilithium` | 0.5 | Latest | Dilithium5 signatures |
| `sha2` | 0.10 | Latest | SHA-512 for XEdDSA |
| `subtle` | 2.0 | Latest | Constant-time operations |
| `zeroize` | 1.0 | Latest | Secure zeroization |
| `rand` | 0.8 | Latest | RNG for cover traffic |
| `tokio` | 1.0 | Latest | Async runtime |

### Platform Compatibility

| Platform | Supported | Notes |
|----------|-----------|-------|
| Linux (x86_64) | ✅ Yes | Fully tested |
| Linux (ARM64) | ✅ Yes | Fully tested |
| macOS (x86_64) | ✅ Yes | Fully tested |
| macOS (ARM64) | ✅ Yes | Fully tested |
| Windows (x86_64) | ✅ Yes | Fully tested |
| WebAssembly | ⚠️ Partial | No async metadata protection |
| iOS | ✅ Yes | Via mobile SDK |
| Android | ✅ Yes | Via mobile SDK |

---

## Troubleshooting Guide

### Common Issues and Solutions

#### Issue 1: High Padding Overhead

**Symptoms:**
- Bandwidth usage significantly higher than expected
- Average padding overhead > 10%

**Diagnosis:**
```rust
let stats = protector.statistics();
let overhead = (stats.total_bytes_sent as f64 / expected_bytes as f64 - 1.0) * 100.0;
println!("Actual overhead: {:.2}%", overhead);
```

**Solutions:**
1. Adjust bucket configuration for your message size distribution:
   ```rust
   // For larger messages, use larger minimum bucket
   let config = PadmeConfig {
       min_bucket_size: 2048,  // Increased from 512
       max_bucket_size: 32768,
       bucket_multiplier: 2.0,
   };
   ```

2. Analyze message size distribution and optimize buckets:
   ```rust
   // Log message sizes to identify patterns
   println!("Message size: {} -> Bucket: {}", 
       plaintext.len(), 
       padding.padded_length(plaintext.len()));
   ```

3. Consider splitting large messages if they exceed max bucket size

#### Issue 2: Cover Traffic Not Generated

**Symptoms:**
- `dummy_ratio()` returns 0.0 despite configured rate > 0
- No dummy messages in traffic statistics

**Diagnosis:**
```rust
let stats = protector.statistics();
println!("Real: {}, Dummy: {}, Ratio: {:.2}", 
    stats.real_messages, 
    stats.dummy_messages, 
    stats.dummy_ratio());
```

**Solutions:**
1. Verify metadata protection is enabled:
   ```rust
   let config = MetadataProtectionConfig::balanced();
   assert!(config.cover_traffic_rate > 0.0);
   ```

2. Check RNG availability:
   ```rust
   use rand::Rng;
   let mut rng = rand::thread_rng();
   let test = rng.gen::<f64>();  // Should not panic
   ```

3. Ensure sufficient real traffic for cover traffic generation:
   - Cover traffic is generated relative to real traffic
   - Send at least a few real messages first

4. Check logs for cover traffic generation errors

#### Issue 3: Handshake Failures with XEdDSA

**Symptoms:**
- Handshake fails with `AuthenticationFailed` error
- Cannot establish sessions with other parties

**Diagnosis:**
```rust
match handshake_result {
    Err(CryptoError::AuthenticationFailed) => {
        eprintln!("Signature verification failed");
    }
    _ => {}
}
```

**Solutions:**
1. Verify both parties have upgraded to hardened version:
   - XEdDSA requires coordinated upgrade
   - Check protocol version in handshake

2. Verify keypair generation:
   ```rust
   let keypair = XEdDSAKeyPair::generate()?;
   // Test self-signature
   let sig = keypair.sign(b"test")?;
   assert!(XEdDSAKeyPair::verify(&keypair.public_key, b"test", &sig)?);
   ```

3. Check for key corruption or transmission errors

4. Verify Dilithium5 component is also valid

#### Issue 4: Constant-Time Timing Variance

**Symptoms:**
- Timing tests fail with variance > 5%
- Potential side-channel vulnerability detected

**Diagnosis:**
```rust
use std::time::Instant;

let mut timings = Vec::new();
for _ in 0..1000 {
    let start = Instant::now();
    ct_memcmp(&secret1, &secret2);
    timings.push(start.elapsed().as_nanos());
}

let mean = timings.iter().sum::<u128>() / timings.len() as u128;
let variance = timings.iter()
    .map(|t| (*t as i128 - mean as i128).pow(2))
    .sum::<i128>() / timings.len() as i128;
let std_dev = (variance as f64).sqrt();
let cv = std_dev / mean as f64;

println!("Coefficient of variation: {:.2}%", cv * 100.0);
```

**Solutions:**
1. Run tests on dedicated hardware without background processes
2. Disable CPU frequency scaling:
   ```bash
   # Linux
   sudo cpupower frequency-set --governor performance
   ```

3. Increase sample size for statistical significance
4. Check for compiler optimizations that break constant-time guarantees
5. Review implementation for secret-dependent branching

#### Issue 5: Message Too Large for Padding

**Symptoms:**
- `CryptoError::MessageTooLarge` when encrypting
- Messages exceed 64KB maximum bucket size

**Diagnosis:**
```rust
let max_size = padding.config().max_bucket_size;
if plaintext.len() > max_size {
    eprintln!("Message too large: {} > {}", plaintext.len(), max_size);
}
```

**Solutions:**
1. Split large messages into chunks:
   ```rust
   const CHUNK_SIZE: usize = 60000;  // Below 64KB
   
   for chunk in plaintext.chunks(CHUNK_SIZE) {
       let encrypted = session.encrypt_message_with_padding(chunk, &padding)?;
       // Send chunk
   }
   ```

2. Increase maximum bucket size (not recommended for security):
   ```rust
   let config = PadmeConfig {
       max_bucket_size: 131072,  // 128KB
       ..Default::default()
   };
   ```

3. Compress messages before encryption to reduce size

#### Issue 6: High Latency with Timing Delays

**Symptoms:**
- Message delivery latency > 2 seconds
- User experience degraded

**Diagnosis:**
```rust
let config = protector.config();
println!("Timing delay range: {}-{}ms", 
    config.timing_delay_min_ms, 
    config.timing_delay_max_ms);
```

**Solutions:**
1. Reduce timing delay range for better user experience:
   ```rust
   let config = MetadataProtectionConfig {
       timing_delay_min_ms: 10,   // Reduced from 100
       timing_delay_max_ms: 200,  // Reduced from 2000
       ..Default::default()
   };
   ```

2. Disable timing delays for low-latency applications:
   ```rust
   let config = MetadataProtectionConfig {
       timing_delay_min_ms: 0,
       timing_delay_max_ms: 0,
       ..Default::default()
   };
   ```

3. Use `low_overhead` configuration preset

4. Consider trade-off between security and user experience

### Performance Optimization Tips

#### 1. Optimize Bucket Configuration

Match bucket sizes to your message size distribution:

```rust
// Analyze message sizes
let sizes: Vec<usize> = messages.iter().map(|m| m.len()).collect();
let avg_size = sizes.iter().sum::<usize>() / sizes.len();

// Configure buckets around average size
let config = PadmeConfig {
    min_bucket_size: avg_size / 2,
    max_bucket_size: avg_size * 4,
    bucket_multiplier: 2.0,
};
```

#### 2. Batch Message Processing

Process multiple messages together to amortize overhead:

```rust
let messages = vec![msg1, msg2, msg3];
for msg in messages {
    let encrypted = session.encrypt_message_with_padding(&msg, &padding)?;
    protector.send_message(encrypted).await?;
}
```

#### 3. Tune Cover Traffic Rate

Start with low rate and increase based on threat model:

```rust
// Start conservative
let config = MetadataProtectionConfig {
    cover_traffic_rate: 0.1,  // 10%
    ..Default::default()
};

// Monitor and adjust
if threat_level_high {
    config.cover_traffic_rate = 0.3;  // Increase to 30%
}
```

#### 4. Use Constant-Rate Mode Selectively

Enable constant-rate mode only for high-security sessions:

```rust
let config = if high_security_session {
    MetadataProtectionConfig::high_security()
} else {
    MetadataProtectionConfig::balanced()
};
```

### Logging and Debugging

Enable detailed logging for troubleshooting:

```rust
use log::{info, warn, error};

// Log padding operations
info!("Padding {} bytes -> {} bytes", 
    plaintext.len(), 
    padded.len());

// Log cover traffic generation
info!("Generated dummy message: {} bytes", dummy.len());

// Log authentication failures
error!("Signature verification failed for handshake");
```

Configure logging level:

```rust
env_logger::Builder::from_default_env()
    .filter_level(log::LevelFilter::Info)
    .init();
```

### Security Audit Checklist

Before deploying to production, verify:

- [ ] All constant-time operations pass timing variance tests (< 5%)
- [ ] Padding overhead is acceptable for your use case (< 10%)
- [ ] Cover traffic is being generated at configured rate (±10%)
- [ ] Handshake success rate > 99%
- [ ] No padding validation errors in logs
- [ ] No authentication failures in logs
- [ ] Backward compatibility tested with non-hardened clients
- [ ] Performance benchmarks meet requirements
- [ ] Monitoring and alerting configured
- [ ] Rollback plan documented and tested

---

## Additional Resources

### V2.0 Documentation

- [V2.0 Architecture Overview](V2_ARCHITECTURE_OVERVIEW.md) - Comprehensive v2.0 architecture guide
- [V2.0 Migration Guide](V2_MIGRATION_GUIDE.md) - Step-by-step migration from v1.0 to v2.0
- [V2.0 Security Analysis](V2_SECURITY_ANALYSIS.md) - Updated security analysis for v2.0
- [V2.0 Mode Selection Guide](V2_MODE_SELECTION_GUIDE.md) - Guide for choosing Mode A vs Mode B
- [Threat Model Formalization](THREAT_MODEL_FORMALIZATION.md) - Formal threat model (6 adversary types)
- [Formal Verification](FORMAL_VERIFICATION.md) - Tamarin + ProVerif verification plan

### Deployment Guides

- [Enterprise Deployment Guide](ENTERPRISE_DEPLOYMENT_GUIDE.md) - Enterprise-specific deployment
- [Production Deployment](PRODUCTION_DEPLOYMENT.md) - Production deployment checklist
- [Pilot Deployment Guide](PILOT_DEPLOYMENT_GUIDE.md) - Pilot deployment strategy
- [Security Audit Checklist](SECURITY_AUDIT_CHECKLIST.md) - Pre-deployment security audit

### Performance Documentation

- [Performance Analysis](PERFORMANCE.md) - Comprehensive performance metrics
- [Performance Under Attack](PERFORMANCE_UNDER_ATTACK.md) - DoS protection metrics
- [Performance Under Stress](PERFORMANCE_UNDER_STRESS.md) - Stress test results

### Example Code

See `examples/` directory for complete examples:
- `examples/v2_mode_selection.rs` - Mode A vs Mode B selection
- `examples/v2_cookie_challenge.rs` - Cookie challenge DoS protection
- `examples/v2_global_scheduler.rs` - Global traffic scheduler usage
- `examples/v2_session_binding.rs` - Session key binding
- `examples/padding_example.rs` - PADMÉ padding usage
- `examples/full_v2_example.rs` - Complete v2.0 workflow

### Support

For questions or issues:
- GitHub Issues: https://github.com/your-org/b4ae/issues
- Security Issues: security@your-org.com
- Documentation: https://docs.your-org.com/b4ae

---

## Conclusion

B4AE v2.0 provides research-grade security with formal verification, authentication mode separation, and comprehensive protection against DoS attacks and metadata analysis.

**Key Takeaways:**

1. **Mode Selection**: Choose Mode A (deniable) or Mode B (post-quantum) based on security requirements
2. **DoS Protection**: Cookie challenge provides 360x amplification reduction
3. **Metadata Protection**: Global traffic scheduler provides cross-session indistinguishability
4. **Security-by-Default**: Core security features always enabled
5. **Incremental Deployment**: Enable features gradually to minimize risk
6. **Configuration Flexibility**: Choose presets based on security/performance requirements
7. **Monitoring**: Track metrics to ensure features are working as expected
8. **Performance Trade-offs**: Balance security benefits against overhead for your use case

**Recommended Deployment Path:**

1. Start with `low_overhead` configuration
2. Monitor metrics and validate functionality
3. Gradually increase to `balanced` configuration
4. Enable `high_security` for critical communications
5. Continuously monitor and adjust based on threat model

For most production deployments, the **balanced configuration with Mode A** provides an excellent trade-off between security, deniability, and performance.

For compliance-heavy environments requiring non-repudiation and post-quantum security, use **high security configuration with Mode B**.
