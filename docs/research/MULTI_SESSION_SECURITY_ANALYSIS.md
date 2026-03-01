# Multi-Session Security Analysis with Hardening

## Executive Summary

This document analyzes security properties when multiple B4AE sessions are active simultaneously with Security Hardening Suite enabled. Multi-session scenarios introduce additional security considerations for padding, metadata protection, and key isolation.

## Multi-Session Security with Padding

### Session Correlation via Padding

**Threat:** Adversary correlates sessions by observing bucket size patterns

**Example:**
- Session A: Messages consistently in 1KB bucket
- Session B: Messages consistently in 4KB bucket
- Adversary infers different applications or users

**Mitigation:**
1. Use same padding configuration across all sessions
2. Randomize message sizes within application
3. Combine with cover traffic

**Residual Risk:** Low (bucket-level correlation provides minimal information)

---

### Padding Configuration Consistency

**Requirement:** All sessions should use consistent padding configuration

**Implementation:**
```rust
pub struct GlobalPaddingConfig {
    config: PadmeConfig,
}

impl GlobalPaddingConfig {
    pub fn get_for_session(&self, session_id: &SessionId) -> PadmeConfig {
        // Return same config for all sessions
        self.config.clone()
    }
}
```

**Security Property:** Consistent padding prevents session fingerprinting

---

### Independent Padding Keys

**Requirement:** Each session uses independent padding validation context

**Implementation:**
```rust
// Per-session padding context
let padding_context = derive_padding_context(
    session_root_key,  // Unique per session
    bucket_size,
    original_length,
);
```

**Security Property:** Padding validation in one session does not affect others

---

## Session Correlation Resistance

### Metadata Correlation Threats

**Threat 1: Timing Correlation**
- Adversary observes messages from multiple sessions
- Correlates timing patterns to link sessions
- Example: Sessions A and B always send messages simultaneously

**Mitigation:**
- Independent timing obfuscation per session
- Different timing delay ranges per session
- Asynchronous message sending

---

**Threat 2: Traffic Volume Correlation**
- Adversary observes message counts across sessions
- Correlates volume patterns to link sessions
- Example: Sessions A and B have correlated message rates

**Mitigation:**
- Independent cover traffic per session
- Different cover traffic rates per session
- Aggregate traffic shaping across sessions

---

**Threat 3: Bucket Size Correlation**
- Adversary observes bucket sizes across sessions
- Correlates patterns to link sessions
- Example: Sessions A and B use same bucket sizes

**Mitigation:**
- Consistent padding configuration (prevents fingerprinting)
- Message size randomization within application
- Cover traffic with varied sizes

---

### Independent Metadata Protection

**Requirement:** Each session has independent metadata protection

**Implementation:**
```rust
pub struct SessionMetadataProtector {
    session_id: SessionId,
    cover_traffic_key: [u8; 32],    // Unique per session
    timing_seed: [u8; 32],          // Unique per session
    shaping_key: [u8; 32],          // Unique per session
    config: MetadataProtectionConfig,
}

impl SessionMetadataProtector {
    pub fn new(session_root_key: &[u8; 32], config: MetadataProtectionConfig) -> Self {
        // Derive independent keys per session
        let cover_traffic_key = HKDF-SHA512(
            ikm: session_root_key,
            salt: b"",
            info: "B4AE-v1-Metadata-CoverTraffic-Hardening",
            length: 32
        );
        
        let timing_seed = HKDF-SHA512(
            ikm: session_root_key,
            salt: b"",
            info: "B4AE-v1-Metadata-TimingSeed",
            length: 32
        );
        
        let shaping_key = HKDF-SHA512(
            ikm: session_root_key,
            salt: b"",
            info: "B4AE-v1-Metadata-TrafficShaping",
            length: 32
        );
        
        Self {
            session_id: SessionId::new(),
            cover_traffic_key,
            timing_seed,
            shaping_key,
            config,
        }
    }
}
```

**Security Property:** Metadata protection in one session is independent from others

---

### Cross-Session Traffic Analysis

**Threat:** Global adversary correlates traffic across all sessions

**Attack:**
1. Observe all sessions from same endpoint
2. Correlate timing, volume, and patterns
3. Build profile of user behavior
4. Link sessions to same user

**Mitigation:**
- Use Tor/VPN for IP-level anonymity
- Stagger session establishment times
- Vary metadata protection configurations per session
- Use mixnet for strong unlinkability

**Residual Risk:** Medium (global adversary can still perform statistical analysis)

---

## Metadata Protection Across Sessions

### Aggregate Cover Traffic

**Strategy:** Coordinate cover traffic across sessions to avoid amplification

**Implementation:**
```rust
pub struct GlobalCoverTrafficCoordinator {
    sessions: HashMap<SessionId, SessionMetadataProtector>,
    global_cover_traffic_rate: f64,
    max_total_dummy_rate: f64,
}

impl GlobalCoverTrafficCoordinator {
    pub fn should_generate_dummy(&mut self, session_id: &SessionId) -> bool {
        // Calculate total dummy rate across all sessions
        let total_dummy_rate: f64 = self.sessions.values()
            .map(|s| s.current_dummy_rate())
            .sum();
        
        // Check global limit
        if total_dummy_rate >= self.max_total_dummy_rate {
            return false;
        }
        
        // Check per-session limit
        let session = self.sessions.get(session_id)?;
        session.should_generate_dummy()
    }
}
```

**Security Property:** Total cover traffic rate is bounded across all sessions

---

### Independent Timing Obfuscation

**Strategy:** Each session applies independent timing delays

**Implementation:**
```rust
pub fn apply_timing_delay_per_session(
    session_id: &SessionId,
    timing_seed: &[u8; 32],
) -> Duration {
    // Derive per-session, per-message delay seed
    let delay_seed = HKDF-SHA512(
        ikm: timing_seed,
        salt: session_id.as_bytes(),
        info: "B4AE-v1-Metadata-DelaySeed",
        length: 8
    );
    
    // Generate delay
    let delay_ms = u64::from_le_bytes(delay_seed) % 2000;
    Duration::from_millis(delay_ms)
}
```

**Security Property:** Timing delays are independent across sessions

---

### Coordinated Traffic Shaping

**Strategy:** Shape traffic across all sessions to maintain constant rate

**Implementation:**
```rust
pub struct GlobalTrafficShaper {
    sessions: HashMap<SessionId, SessionMetadataProtector>,
    target_global_rate: f64,
    message_queue: VecDeque<(SessionId, Vec<u8>, Instant)>,
}

impl GlobalTrafficShaper {
    pub async fn shape_and_send(&mut self) {
        let interval = Duration::from_secs_f64(1.0 / self.target_global_rate);
        let mut next_send_time = Instant::now();
        
        loop {
            // Wait until next send time
            tokio::time::sleep_until(next_send_time.into()).await;
            
            // Send next message (real or dummy)
            if let Some((session_id, message, _)) = self.message_queue.pop_front() {
                self.send_message(session_id, message).await;
            } else {
                // Generate dummy message for random session
                let session_id = self.select_random_session();
                let dummy = self.generate_dummy_for_session(session_id);
                self.send_message(session_id, dummy).await;
            }
            
            // Advance to next slot
            next_send_time += interval;
        }
    }
}
```

**Security Property:** Global constant rate maintained across all sessions

---

## Key Isolation

### Session Key Independence

**Requirement:** Keys from different sessions must be cryptographically independent

**Enforcement:**
1. Each session derives keys from unique handshake
2. Handshakes use fresh ephemeral keys
3. Domain separation includes session context

**Validation:**
```rust
#[test]
fn test_session_key_independence() {
    let session1 = establish_session(peer_a, peer_b);
    let session2 = establish_session(peer_a, peer_b);
    
    // Session root keys must be different
    assert_ne!(session1.root_key, session2.root_key);
    
    // Message keys must be different
    let msg_key1 = session1.derive_message_key();
    let msg_key2 = session2.derive_message_key();
    assert_ne!(msg_key1, msg_key2);
}
```

---

### Cross-Session Key Derivation Prevention

**Threat:** Adversary uses key from one session in another session

**Defense:** Domain separation includes session-specific context

**Implementation:**
```rust
// Session-specific domain separation
let message_key = HKDF-SHA512(
    ikm: chain_key,
    salt: session_id.as_bytes(),  // Session-specific salt
    info: "B4AE-v1-Ratchet-MessageKey-Send",
    length: 32
);
```

**Security Property:** Keys cannot be used across sessions

---

### Session Isolation on Compromise

**Property:** Compromise of one session does not compromise other sessions

**Guarantee:**
1. Each session has independent root key
2. Each session has independent chain keys
3. Each session has independent metadata protection keys

**Validation:**
```rust
#[test]
fn test_session_isolation_on_compromise() {
    let session1 = establish_session(peer_a, peer_b);
    let session2 = establish_session(peer_a, peer_b);
    
    // Compromise session1 (adversary gets all keys)
    let compromised_keys = session1.export_all_keys();
    
    // Session2 should remain secure
    assert!(!can_decrypt_session2_with_session1_keys(
        &session2,
        &compromised_keys
    ));
}
```

---

## Multi-Session Attack Scenarios

### Scenario 1: Session Linkage via Timing

**Attack:**
1. Adversary observes two sessions from same endpoint
2. Notices messages sent simultaneously
3. Infers sessions belong to same user

**Defense:**
- Independent timing delays per session
- Stagger message sending across sessions
- Use different timing delay ranges

**Result:** Correlation difficulty increased

---

### Scenario 2: Session Linkage via Bucket Sizes

**Attack:**
1. Adversary observes bucket size patterns across sessions
2. Notices similar patterns (e.g., both use 1KB bucket frequently)
3. Infers sessions belong to same application

**Defense:**
- Consistent padding configuration (prevents fingerprinting)
- Message size randomization
- Cover traffic with varied sizes

**Result:** Correlation difficulty increased

---

### Scenario 3: Cross-Session Key Reuse

**Attack:**
1. Adversary compromises one session
2. Attempts to use keys in another session
3. Tries to decrypt messages from other session

**Defense:**
- Independent key derivation per session
- Domain separation includes session context
- Session-specific salts in KDFs

**Result:** Attack fails (keys are independent)

---

### Scenario 4: Cover Traffic Amplification

**Attack:**
1. Adversary triggers cover traffic in multiple sessions
2. Amplifies bandwidth usage
3. Causes DoS

**Defense:**
- Global cover traffic rate limiting
- Coordinate cover traffic across sessions
- Adaptive rate adjustment under load

**Result:** Attack mitigated (rate limited)

---

## Configuration Recommendations

### Independent Sessions (Maximum Isolation)

```rust
// Each session has independent configuration
let session1_config = MetadataProtectionConfig {
    cover_traffic_rate: 0.2,
    timing_delay_min_ms: 50,
    timing_delay_max_ms: 500,
    ..Default::default()
};

let session2_config = MetadataProtectionConfig {
    cover_traffic_rate: 0.3,
    timing_delay_min_ms: 100,
    timing_delay_max_ms: 1000,
    ..Default::default()
};
```

**Use when:** Maximum session isolation required

**Trade-off:** Higher complexity, potential correlation via configuration differences

---

### Coordinated Sessions (Consistent Configuration)

```rust
// All sessions use same configuration
let global_config = MetadataProtectionConfig {
    cover_traffic_rate: 0.2,
    timing_delay_min_ms: 50,
    timing_delay_max_ms: 500,
    ..Default::default()
};

// Apply to all sessions
for session in sessions {
    session.set_metadata_config(global_config.clone());
}
```

**Use when:** Prevent session fingerprinting via configuration

**Trade-off:** Less flexibility, but more consistent

---

### Hybrid Approach (Coordinated with Variation)

```rust
// Base configuration with per-session variation
let base_config = MetadataProtectionConfig::balanced();

for session in sessions {
    let mut session_config = base_config.clone();
    
    // Add random variation (±20%)
    session_config.timing_delay_min_ms = 
        (base_config.timing_delay_min_ms as f64 * (0.8 + rand() * 0.4)) as u64;
    session_config.timing_delay_max_ms = 
        (base_config.timing_delay_max_ms as f64 * (0.8 + rand() * 0.4)) as u64;
    
    session.set_metadata_config(session_config);
}
```

**Use when:** Balance between isolation and consistency

**Trade-off:** Moderate complexity, good security

---

## Monitoring Multi-Session Security

### Metrics to Track

**Per-Session Metrics:**
- Message count
- Dummy message count
- Average message size
- Bucket size distribution
- Timing delay distribution

**Cross-Session Metrics:**
- Total message rate across all sessions
- Total dummy message rate
- Correlation coefficient between sessions
- Timing correlation
- Bucket size correlation

**Alerting:**
- High correlation between sessions (> 0.8)
- Excessive total cover traffic rate
- Session key reuse detected
- Timing patterns too similar

---

## Conclusion

Multi-session security requires careful consideration of session correlation, key isolation, and coordinated metadata protection. Key features:

1. **Independent Keys:** Each session has independent keys
2. **Coordinated Metadata Protection:** Cover traffic and traffic shaping coordinated
3. **Session Isolation:** Compromise of one session does not affect others
4. **Correlation Resistance:** Independent timing and varied configurations
5. **Global Rate Limiting:** Total cover traffic rate bounded

Proper multi-session management ensures that security properties are maintained across all active sessions.

---

*Last updated: 2026*
*Version: 1.0*
