# B4AE v1.0 → v2.0 Migration Guide

**Target Audience**: Developers migrating from B4AE v1.0 to v2.0  
**Migration Complexity**: High (protocol breaking changes)  
**Estimated Migration Time**: 2-4 hours for typical application

## Overview

B4AE v2.0 is **NOT backward compatible** with v1.0. This is a complete protocol redesign addressing 8 critical architectural flaws. Migration requires code changes, configuration updates, and understanding of new security properties.

**Why Migrate?**
- ✅ 360x better DoS protection
- ✅ Clear security properties (deniable vs post-quantum)
- ✅ Cross-session metadata protection
- ✅ Formal verification support
- ✅ Security-by-default (no insecure configurations)

**Migration Path**: v1.0 → v2.0 (no intermediate versions)

## Breaking Changes Summary

| Aspect | v1.0 | v2.0 | Impact |
|--------|------|------|--------|
| **Handshake** | 3-way | 5-phase (mode negotiation + cookie challenge) | HIGH |
| **Signatures** | XEdDSA + Dilithium5 hybrid | Mode A (XEdDSA only) OR Mode B (Dilithium5 only) | HIGH |
| **Traffic Scheduling** | Per-session | Global unified scheduler | MEDIUM |
| **Key Derivation** | Simple HKDF | Session ID binding | MEDIUM |
| **DoS Protection** | None | Stateless cookie challenge | LOW (automatic) |
| **Configuration** | Optional security | Security-by-default | MEDIUM |
| **API** | `B4aeClient` | `B4aeClient` + v2 methods | HIGH |

## Step-by-Step Migration

### Step 1: Update Dependencies

**Before (v1.0)**:
```toml
[dependencies]
b4ae = { version = "1.0", features = ["elara"] }
```

**After (v2.0)**:
```toml
[dependencies]
b4ae = { version = "2.0", features = ["v2_protocol", "elara"] }
```

**Note**: The `v2_protocol` feature flag is required to enable v2.0 protocol.

### Step 2: Choose Authentication Mode

v2.0 requires explicit mode selection. Choose based on your security requirements:

**Mode A (Deniable)** - Choose if:
- ✅ You need plausible deniability (whistleblowing, anonymous communication)
- ✅ You want fast handshakes (~150ms)
- ✅ Classical 128-bit security is sufficient
- ❌ You don't need post-quantum security
- ❌ You don't need non-repudiation

**Mode B (Post-Quantum)** - Choose if:
- ✅ You need post-quantum security (NIST Level 5)
- ✅ You need non-repudiable signatures (legal contracts, audit trails)
- ✅ You can accept slightly slower handshakes (~155ms)
- ❌ You don't need deniability

**Decision Matrix**:

| Use Case | Recommended Mode | Reason |
|----------|------------------|--------|
| Private messaging | Mode A | Deniability important |
| Whistleblowing platform | Mode A | Deniability critical |
| Legal document signing | Mode B | Non-repudiation required |
| Audit trail system | Mode B | Non-repudiation required |
| Long-term confidential data | Mode B | Post-quantum security |
| Real-time chat | Mode A | Fast handshakes |

### Step 3: Update Client Initialization

**Before (v1.0)**:
```rust
use b4ae::{B4aeClient, SecurityProfile};

let mut client = B4aeClient::new(SecurityProfile::Standard)?;
```

**After (v2.0)**:
```rust
use b4ae::protocol::v2::AuthenticationMode;
use b4ae::B4aeClient;

// For deniable authentication
let mut client = B4aeClient::new_v2(AuthenticationMode::ModeA)?;

// OR for post-quantum non-repudiable authentication
let mut client = B4aeClient::new_v2(AuthenticationMode::ModeB)?;
```

### Step 4: Update Handshake Flow

**Before (v1.0)** - 3-way handshake:
```rust
// Alice initiates
let init = alice.initiate_handshake(&bob_id)?;

// Bob responds
let response = bob.respond_to_handshake(&alice_id, init)?;

// Alice processes response
let complete = alice.process_response(&bob_id, response)?;

// Bob completes
bob.complete_handshake(&alice_id, complete)?;
alice.finalize_initiator(&bob_id)?;
```

**After (v2.0)** - 5-phase handshake:
```rust
// Phase 1: Mode Negotiation
let negotiation = alice.initiate_mode_negotiation(&bob_id)?;
let selection = bob.respond_mode_negotiation(&alice_id, negotiation)?;
alice.complete_mode_negotiation(&bob_id, selection)?;

// Phase 2: Cookie Challenge (automatic DoS protection)
let client_hello = alice.send_client_hello(&bob_id)?;
let cookie_challenge = bob.respond_cookie_challenge(&alice_id, client_hello)?;

// Phase 3: Handshake with mode-specific signatures
let init = alice.initiate_handshake_v2(&bob_id, cookie_challenge)?;
let response = bob.respond_to_handshake_v2(&alice_id, init)?;
let complete = alice.process_response_v2(&bob_id, response)?;
bob.complete_handshake_v2(&alice_id, complete)?;
alice.finalize_initiator_v2(&bob_id)?;
```

**Simplification**: Use helper method for automatic flow:
```rust
// Automatic mode negotiation + cookie challenge + handshake
alice.establish_session_v2(&bob_id, AuthenticationMode::ModeA)?;
bob.accept_session_v2(&alice_id)?;
```

### Step 5: Update Message Encryption/Decryption

**Before (v1.0)**:
```rust
// Encrypt (returns Vec<EncryptedMessage> with dummy messages)
let encrypted_list = alice.encrypt_message(&bob_id, b"Hello")?;

// Decrypt (last non-empty is real message)
let mut decrypted = vec![];
for enc in &encrypted_list {
    let d = bob.decrypt_message(&alice_id, enc)?;
    if !d.is_empty() {
        decrypted = d;
    }
}
```

**After (v2.0)**:
```rust
// Encrypt (single message, global scheduler handles dummy traffic)
let encrypted = alice.encrypt_message_v2(&bob_id, b"Hello")?;

// Decrypt (single message)
let decrypted = bob.decrypt_message_v2(&alice_id, &encrypted)?;
```

**Key Difference**: v2.0 uses global traffic scheduler, so dummy messages are handled transparently at the scheduler level, not per-message.

### Step 6: Configure Global Traffic Scheduler

v2.0 introduces global traffic scheduler for cross-session metadata protection.

**Configuration**:
```rust
use b4ae::protocol::v2::GlobalTrafficScheduler;

// Create global scheduler (shared across all sessions)
let scheduler = GlobalTrafficScheduler::new(100.0); // 100 msg/s

// Configure target rate based on requirements
// - 100 msg/s: ~5ms avg latency, good metadata protection
// - 1000 msg/s: ~0.5ms avg latency, less metadata protection
scheduler.set_target_rate(100.0);

// Configure cover traffic budget (20-100%)
// - 20%: Minimum (security-by-default)
// - 50%: Strong metadata protection
// - 100%: Maximum protection (2x bandwidth)
scheduler.set_cover_traffic_budget(0.20); // 20%

// Attach scheduler to client
client.set_global_scheduler(scheduler);
```

**Trade-offs**:

| Target Rate | Avg Latency | Metadata Protection | Bandwidth Overhead |
|-------------|-------------|---------------------|-------------------|
| 100 msg/s | ~5ms | Strong | 20% |
| 1000 msg/s | ~0.5ms | Moderate | 20% |

### Step 7: Update Configuration (Security-by-Default)

v1.0 allowed disabling security features. v2.0 enforces security-by-default.

**Before (v1.0)** - Optional security:
```rust
let config = B4aeConfig {
    enable_padding: true,  // Could be false
    enable_metadata_protection: true,  // Could be false
    cover_traffic_rate: 0.0,  // Could be 0 (disabled)
    // ...
};
```

**After (v2.0)** - Security-by-default:
```rust
let config = B4aeConfig::v2_default(); // All security features enabled

// Cannot disable:
// - Padding (always PADME 8-bucket)
// - Metadata protection (always global scheduler)
// - Cover traffic (minimum 20%, configurable up to 100%)
// - Post-quantum crypto (always Kyber1024 + mode-specific signatures)
// - Constant-time operations (always enabled)
// - Downgrade protection (always mode binding)

// Can configure:
config.set_target_rate(100.0); // Traffic scheduler rate
config.set_cover_traffic_budget(0.20); // 20-100%
```

**Insecure Mode (Testing Only)**:
```rust
// Only for testing/debugging, blocked in production
let config = B4aeConfig::v2_insecure()?; // Requires allow_insecure flag
// - Mandatory audit logging
// - Warning on every message
// - Blocked in production environment
```

### Step 8: Update Error Handling

v2.0 introduces new error types for mode negotiation and cookie challenge.

**New Error Types**:
```rust
use b4ae::protocol::v2::{
    ModeNegotiationError,
    CookieChallengeError,
    ModeValidationError,
};

match result {
    Err(B4aeError::ModeNegotiation(e)) => {
        match e {
            ModeNegotiationError::NoCompatibleModes => {
                // Client and server have no compatible modes
                // Solution: Update client or server to support common mode
            }
            ModeNegotiationError::ModeDowngradeDetected => {
                // Attacker attempted mode downgrade
                // Solution: Abort connection, log security incident
            }
            _ => {}
        }
    }
    Err(B4aeError::CookieChallenge(e)) => {
        match e {
            CookieChallengeError::InvalidCookie => {
                // Cookie verification failed
                // Solution: Retry handshake
            }
            CookieChallengeError::ExpiredTimestamp => {
                // Cookie expired (>30 seconds old)
                // Solution: Retry handshake with fresh cookie
            }
            _ => {}
        }
    }
    Ok(result) => {
        // Success
    }
}
```

### Step 9: Update Tests

**Before (v1.0)**:
```rust
#[test]
fn test_handshake() {
    let mut alice = B4aeClient::new(SecurityProfile::Standard).unwrap();
    let mut bob = B4aeClient::new(SecurityProfile::Standard).unwrap();
    
    let init = alice.initiate_handshake(&bob_id).unwrap();
    let response = bob.respond_to_handshake(&alice_id, init).unwrap();
    let complete = alice.process_response(&bob_id, response).unwrap();
    bob.complete_handshake(&alice_id, complete).unwrap();
    alice.finalize_initiator(&bob_id).unwrap();
}
```

**After (v2.0)**:
```rust
#[test]
fn test_handshake_v2() {
    let mut alice = B4aeClient::new_v2(AuthenticationMode::ModeA).unwrap();
    let mut bob = B4aeClient::new_v2(AuthenticationMode::ModeA).unwrap();
    
    // Mode negotiation
    let negotiation = alice.initiate_mode_negotiation(&bob_id).unwrap();
    let selection = bob.respond_mode_negotiation(&alice_id, negotiation).unwrap();
    alice.complete_mode_negotiation(&bob_id, selection).unwrap();
    
    // Cookie challenge
    let client_hello = alice.send_client_hello(&bob_id).unwrap();
    let cookie_challenge = bob.respond_cookie_challenge(&alice_id, client_hello).unwrap();
    
    // Handshake
    let init = alice.initiate_handshake_v2(&bob_id, cookie_challenge).unwrap();
    let response = bob.respond_to_handshake_v2(&alice_id, init).unwrap();
    let complete = alice.process_response_v2(&bob_id, response).unwrap();
    bob.complete_handshake_v2(&alice_id, complete).unwrap();
    alice.finalize_initiator_v2(&bob_id).unwrap();
}
```

### Step 10: Update Deployment Configuration

**Server Configuration**:
```rust
// v2.0 server requires cookie secret rotation
let server_config = B4aeServerConfig::v2_default();

// Cookie secret rotation (recommended: every 24 hours)
server_config.set_cookie_secret_rotation_interval(Duration::from_secs(86400));

// Bloom filter configuration for replay protection
server_config.set_bloom_filter_size(1_000_000); // 1M entries
server_config.set_bloom_filter_false_positive_rate(0.001); // 0.1%

// Global traffic scheduler
server_config.set_target_rate(100.0); // 100 msg/s
server_config.set_cover_traffic_budget(0.20); // 20%
```

## Migration Checklist

- [ ] Update `Cargo.toml` to v2.0 with `v2_protocol` feature
- [ ] Choose authentication mode (Mode A or Mode B)
- [ ] Update client initialization to `new_v2(mode)`
- [ ] Update handshake flow (mode negotiation + cookie challenge)
- [ ] Update message encryption/decryption to v2 API
- [ ] Configure global traffic scheduler
- [ ] Remove optional security configurations (now always enabled)
- [ ] Update error handling for new error types
- [ ] Update tests to v2 handshake flow
- [ ] Update deployment configuration (cookie secret rotation, Bloom filter)
- [ ] Test mode negotiation between clients with different modes
- [ ] Test cookie challenge DoS protection
- [ ] Test global traffic scheduler latency
- [ ] Update documentation and API references

## Common Migration Issues

### Issue 1: "No compatible authentication modes"

**Cause**: Client and server have no overlapping supported modes.

**Solution**:
```rust
// Ensure both client and server support at least one common mode
let client_modes = vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB];
let server_modes = vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB];

// Or use automatic mode selection
client.set_supported_modes(client_modes);
server.set_supported_modes(server_modes);
```

### Issue 2: "Cookie verification failed"

**Cause**: Cookie expired or invalid.

**Solution**:
```rust
// Retry handshake with fresh cookie
match alice.initiate_handshake_v2(&bob_id, cookie_challenge) {
    Err(B4aeError::CookieChallenge(CookieChallengeError::ExpiredTimestamp)) => {
        // Get fresh cookie
        let client_hello = alice.send_client_hello(&bob_id)?;
        let cookie_challenge = bob.respond_cookie_challenge(&alice_id, client_hello)?;
        // Retry
        alice.initiate_handshake_v2(&bob_id, cookie_challenge)?;
    }
    Ok(init) => { /* Success */ }
    Err(e) => return Err(e),
}
```

### Issue 3: "Mode downgrade detected"

**Cause**: Attacker attempted to downgrade authentication mode.

**Solution**:
```rust
// Abort connection and log security incident
match alice.complete_mode_negotiation(&bob_id, selection) {
    Err(B4aeError::ModeNegotiation(ModeNegotiationError::ModeDowngradeDetected)) => {
        log::error!("Security incident: Mode downgrade attack detected");
        // Abort connection
        return Err(B4aeError::SecurityIncident);
    }
    Ok(_) => { /* Success */ }
    Err(e) => return Err(e),
}
```

### Issue 4: "Global scheduler latency too high"

**Cause**: Target rate too low for application requirements.

**Solution**:
```rust
// Increase target rate for lower latency
scheduler.set_target_rate(1000.0); // 1000 msg/s (~0.5ms avg latency)

// Trade-off: Less metadata protection, but lower latency
```

## Performance Comparison

| Metric | v1.0 | v2.0 Mode A | v2.0 Mode B | Notes |
|--------|------|-------------|-------------|-------|
| Handshake Time | ~145ms | ~150ms | ~155ms | v2.0 adds mode negotiation + cookie challenge |
| Signature Verification | ~9.3ms | ~0.3ms | ~9ms | Mode A 30x faster |
| DoS Protection | None | 360x reduction | 360x reduction | Cookie challenge |
| Message Latency | <1ms | ~5ms (100 msg/s) | ~5ms (100 msg/s) | Global scheduler trade-off |
| Bandwidth Overhead | 20% | 20% | 20% | Configurable |

## Testing Strategy

1. **Unit Tests**: Test mode negotiation, cookie challenge, session binding
2. **Integration Tests**: Test full handshake flow with both modes
3. **Performance Tests**: Measure handshake time, message latency, throughput
4. **Security Tests**: Test DoS protection, mode downgrade detection, replay protection
5. **Compatibility Tests**: Test v1.0 clients cannot connect to v2.0 servers (expected)

## Rollback Plan

If migration fails, you can rollback to v1.0:

1. Revert `Cargo.toml` to v1.0
2. Revert code changes
3. Redeploy v1.0 version

**Note**: v1.0 and v2.0 cannot interoperate. Ensure all clients and servers are on the same version.

## Support

- **Documentation**: [V2 Architecture Overview](V2_ARCHITECTURE_OVERVIEW.md)
- **Security Analysis**: [V2 Security Analysis](V2_SECURITY_ANALYSIS.md)
- **Mode Selection**: [V2 Mode Selection Guide](V2_MODE_SELECTION_GUIDE.md)
- **Issues**: [GitHub Issues](https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-/issues)
- **Email**: rafaelsistems@gmail.com

## Timeline

**Recommended Migration Timeline**:
- Week 1: Read documentation, choose authentication mode
- Week 2: Update code, run tests
- Week 3: Deploy to staging, performance testing
- Week 4: Deploy to production

**Minimum Migration Time**: 2-4 hours for typical application
