# B4AE v2.0 Production Deployment

**Version**: 2.0.0  
**Status**: Production-Ready (100% complete)  
**Last Updated**: 2026

Production deployment guide for B4AE v2.0 with security checklist, build instructions, and configuration.

---

## Overview

B4AE v2.0 is a research-grade post-quantum metadata-hardened secure messaging protocol designed for production deployment in high-assurance environments.

**Key Features:**
- Authentication mode separation (Mode A: deniable, Mode B: post-quantum)
- Stateless cookie challenge (360x DoS amplification reduction)
- Global unified traffic scheduler (cross-session metadata protection)
- Session key binding (cryptographic session isolation)
- Security-by-default (all protections always enabled)

---

## Phase 4: Production Infrastructure

### Prerequisites

- **Rust**: 1.75+ (for building from source)
- **Docker**: 20.10+ (optional, for containerized deployment)
- **HSM**: PKCS#11 compatible (required for Mode B in compliance environments)
- **Monitoring**: Prometheus + Grafana (recommended)
- **Load Balancer**: UDP-capable with sticky sessions

### Build from Source

```bash
# Clone repository
git clone https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-.git
cd B4AE-Beyond-For-All-Encryption-

# Initialize submodules (ELARA)
git submodule update --init --recursive

# Full build with v2.0 protocol
cargo build --release --features v2_protocol

# Build with ELARA transport
cargo build --release --features v2_protocol,elara

# Build without ELARA (minimal)
cargo build --release --no-default-features --features v2_protocol,full-crypto

# Run tests
cargo test --release --features v2_protocol

# Run benchmarks
cargo bench --features v2_protocol
```

**Build Artifacts:**
- Binary: `target/release/b4ae`
- Library: `target/release/libb4ae.so` (or `.dylib` on macOS, `.dll` on Windows)

### Docker Deployment

```bash
# Build image
docker build -t b4ae:v2.0.0 -f Dockerfile .

# Run with balanced configuration
docker run -d \
  --name b4ae-v2 \
  -p 4000:4000/udp \
  -e RUST_LOG=b4ae=info \
  -e B4AE_MODE=balanced \
  -e B4AE_AUTH_MODE=mode_a \
  -v /etc/b4ae:/etc/b4ae:ro \
  b4ae:v2.0.0

# Run with high security configuration
docker run -d \
  --name b4ae-v2-secure \
  -p 4000:4000/udp \
  -e RUST_LOG=b4ae=info \
  -e B4AE_MODE=high_security \
  -e B4AE_AUTH_MODE=mode_b \
  -v /etc/b4ae:/etc/b4ae:ro \
  -v /var/lib/b4ae:/var/lib/b4ae \
  b4ae:v2.0.0

# View logs
docker logs -f b4ae-v2

# Monitor metrics
docker exec b4ae-v2 curl http://localhost:9090/metrics
```

### Configuration

#### Environment Variables

| Variable | Description | Default | Options |
|----------|-------------|---------|---------|
| `RUST_LOG` | Log level | `info` | `error`, `warn`, `info`, `debug`, `trace` |
| `B4AE_MODE` | Security profile | `balanced` | `low_overhead`, `balanced`, `high_security` |
| `B4AE_AUTH_MODE` | Authentication mode | `mode_a` | `mode_a`, `mode_b`, `both` |
| `B4AE_SCHEDULER_RATE` | Global scheduler rate (msg/s) | `100` | `10-1000` |
| `B4AE_DUMMY_RATE` | Dummy message rate (0.0-1.0) | `0.2` | `0.0-1.0` |
| `B4AE_COOKIE_SECRET` | Cookie challenge secret | (generated) | 32-byte hex string |
| `B4AE_HSM_ENABLED` | Enable HSM for keys | `false` | `true`, `false` |
| `B4AE_HSM_TOKEN` | HSM token name | - | PKCS#11 token name |

#### Configuration File

Create `/etc/b4ae/config.toml`:

```toml
[protocol]
version = "2.0"

[authentication]
# Mode A (deniable), Mode B (post-quantum), or both
supported_modes = ["mode_a", "mode_b"]
preferred_mode = "mode_a"

[cookie_challenge]
# Cookie secret (32 bytes hex, rotate every 24 hours)
secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
# Bloom filter size (entries)
bloom_filter_size = 1000000
# Cookie expiry (seconds)
expiry_seconds = 30

[global_scheduler]
# Target rate (messages per second)
target_rate = 100.0
# Dummy message rate (0.0 = none, 1.0 = 100%)
dummy_rate = 0.2
# Constant rate mode
constant_rate = true
# Max queue latency (milliseconds)
max_queue_latency_ms = 5.0

[padding]
# PADMÉ padding configuration
min_bucket_size = 1024
max_bucket_size = 16384
bucket_multiplier = 2.0

[metadata_protection]
# Cover traffic rate (0.0 = none, 1.0 = 100%)
cover_traffic_rate = 0.2
# Timing delays (milliseconds)
timing_delay_min_ms = 50
timing_delay_max_ms = 500
# Traffic shaping
traffic_shaping_enabled = true

[keys]
# Key storage
storage_path = "/var/lib/b4ae/keys"
# HSM configuration (Mode B recommended)
hsm_enabled = false
hsm_token = "B4AE"
hsm_pin = ""  # Set via environment variable B4AE_HSM_PIN

[audit]
# Audit log configuration
enabled = true
sink = "syslog"  # Options: syslog, file, siem
syslog_endpoint = "localhost:514"
file_path = "/var/log/b4ae/audit.log"
# Privacy: hash session IDs and peer identities
hash_identities = true

[monitoring]
# Prometheus metrics endpoint
metrics_enabled = true
metrics_port = 9090
metrics_path = "/metrics"

[network]
# UDP configuration
listen_address = "0.0.0.0:4000"
# ELARA transport (optional)
elara_enabled = true
```

### Security Checklist

Before deploying to production:

- [ ] **Audit Dependencies**: Run `cargo audit` — no vulnerabilities
- [ ] **Security Audit**: Run `scripts/security_audit.sh` (or `.ps1` on Windows)
- [ ] **Release Build**: Use `--release` flag (optimizations enabled)
- [ ] **TLS/HTTPS**: Enable TLS for any exposed HTTP endpoints (metrics, health checks)
- [ ] **Network Exposure**: Restrict UDP port to trusted peers only
- [ ] **Key Rotation**: Implement key rotation policy (90 days recommended)
- [ ] **Cookie Secret Rotation**: Rotate cookie secret every 24 hours
- [ ] **HSM Integration**: Enable HSM for Mode B in compliance environments
- [ ] **Audit Logging**: Configure audit sink to SIEM
- [ ] **Monitoring**: Deploy Prometheus + Grafana dashboard
- [ ] **Backup**: Implement backup strategy for keys and audit logs
- [ ] **Disaster Recovery**: Test failover and recovery procedures
- [ ] **Penetration Testing**: Conduct security assessment before production
- [ ] **Compliance Review**: Verify compliance requirements (SOC2, HIPAA, GDPR)

### Security Hardening

#### 1. Cookie Secret Rotation

Rotate cookie secret every 24 hours to prevent replay attacks:

```bash
#!/bin/bash
# rotate_cookie_secret.sh

# Generate new 32-byte secret
NEW_SECRET=$(openssl rand -hex 32)

# Update configuration
sed -i "s/^secret = .*/secret = \"$NEW_SECRET\"/" /etc/b4ae/config.toml

# Reload B4AE (graceful restart)
systemctl reload b4ae

# Log rotation
echo "$(date): Cookie secret rotated" >> /var/log/b4ae/rotation.log
```

Schedule with cron:
```cron
0 0 * * * /usr/local/bin/rotate_cookie_secret.sh
```

#### 2. Key Rotation

Rotate long-term keys every 90 days:

```rust
use b4ae::crypto::key_rotation::KeyRotationPolicy;

let policy = KeyRotationPolicy {
    rotation_interval_days: 90,
    overlap_period_days: 7,  // Old key valid for 7 days after rotation
    auto_rotate: true,
};

// Automatic rotation
let key_manager = KeyManager::new(policy)?;
key_manager.start_rotation_scheduler().await;
```

#### 3. HSM Integration (Mode B)

For compliance environments, store Dilithium5 keys in HSM:

```rust
use b4ae::crypto::hsm::HsmKeyStore;

// Initialize HSM
let hsm = HsmKeyStore::new("pkcs11:token=B4AE;object=dilithium5_key")?;

// Generate keypair in HSM (private key never leaves HSM)
let keypair = hsm.generate_dilithium5_keypair()?;

// Sign with HSM
let signature = hsm.sign(&message)?;
```

**HSM Requirements:**
- PKCS#11 compatible
- Support for NIST PQC algorithms (Dilithium5)
- Hardware security module (not software emulation)

#### 4. Network Segmentation

Isolate B4AE nodes in dedicated VLAN:

```
┌─────────────────────────────────────────────┐
│  DMZ (Public)                               │
│  - Load Balancer (UDP)                      │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│  B4AE VLAN (Private)                        │
│  - B4AE v2.0 Nodes                          │
│  - Global Scheduler                         │
│  - Cookie Challenge                         │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│  Backend VLAN (Private)                     │
│  - Application Servers                      │
│  - Database                                 │
│  - HSM                                      │
└─────────────────────────────────────────────┘
```

---

## Integration into Applications

### Rust Library

Add to `Cargo.toml`:

```toml
[dependencies]
b4ae = { git = "https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-", features = ["v2_protocol", "elara"] }
```

Example usage:

```rust
use b4ae::protocol::v2::{
    AuthenticationMode, ModeNegotiationConfig,
    TrafficSchedulerConfig, GlobalScheduler,
    B4aeClient,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure authentication mode
    let mode_config = ModeNegotiationConfig {
        supported_modes: vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB],
        preferred_mode: AuthenticationMode::ModeA,
    };
    
    // Configure global scheduler
    let scheduler_config = TrafficSchedulerConfig {
        target_rate_msgs_per_sec: 100.0,
        dummy_message_rate: 0.2,
        constant_rate_mode: true,
        max_queue_latency_ms: 5.0,
    };
    
    // Initialize client
    let client = B4aeClient::new(mode_config, scheduler_config).await?;
    
    // Establish session
    let session = client.connect("peer_address").await?;
    
    // Send message
    let message = b"Hello, B4AE v2.0!";
    session.send(message).await?;
    
    // Receive message
    let received = session.receive().await?;
    println!("Received: {:?}", received);
    
    Ok(())
}
```

### Platform SDKs

- **Web (WASM)**: `b4ae-wasm` — see [PLATFORM_SDK.md](PLATFORM_SDK.md)
- **Android**: `b4ae-android` — JNI bindings
- **iOS**: `b4ae-ffi` — C FFI + Swift wrapper
- **Python**: `b4ae-py` — PyO3 bindings
- **Node.js**: `b4ae-node` — N-API bindings

---

## Performance Tuning

### Mode Selection

Choose authentication mode based on requirements:

| Requirement | Recommended Mode | Handshake Time | Security |
|-------------|------------------|----------------|----------|
| Deniability | Mode A | ~150ms | Classical 128-bit |
| Post-Quantum | Mode B | ~155ms | NIST Level 5 |
| Both | Support both | Varies | Negotiated |

### Global Scheduler Tuning

Adjust scheduler rate based on throughput requirements:

| Use Case | Target Rate | Dummy Rate | Latency | Throughput |
|----------|-------------|------------|---------|------------|
| Low Latency | 1000 msg/s | 0.0 | ~0.5ms | High |
| Balanced | 100 msg/s | 0.2 | ~5ms | Medium |
| High Security | 10 msg/s | 0.5 | ~50ms | Low |

### Resource Allocation

Allocate resources based on load:

| Load | CPU | Memory | Network |
|------|-----|--------|---------|
| Low (< 100 msg/s) | 1 core | 512 MB | 10 Mbps |
| Medium (100-1000 msg/s) | 2 cores | 1 GB | 100 Mbps |
| High (> 1000 msg/s) | 4+ cores | 2 GB | 1 Gbps |

---

## Monitoring and Alerting

### Prometheus Metrics

Expose metrics on port 9090:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'b4ae-v2'
    static_configs:
      - targets: ['localhost:9090']
```

**Key Metrics:**
- `b4ae_mode_a_handshakes_total` - Mode A handshakes
- `b4ae_mode_b_handshakes_total` - Mode B handshakes
- `b4ae_cookie_challenges_total` - Cookie challenges issued
- `b4ae_invalid_cookies_total` - Invalid cookies rejected
- `b4ae_dos_attempts_blocked_total` - DoS attempts blocked
- `b4ae_sessions_active` - Active sessions
- `b4ae_queue_latency_ms` - Global scheduler queue latency
- `b4ae_handshake_duration_ms` - Handshake duration

### Grafana Dashboard

Import dashboard from `monitoring/grafana/b4ae-v2-dashboard.json`

**Panels:**
1. Mode Distribution (pie chart)
2. DoS Protection (line graph)
3. Session Metrics (gauge)
4. Global Scheduler (line graph)
5. Handshake Performance (histogram)
6. Throughput (line graph)

### Alerting Rules

```yaml
# alerts.yml
groups:
  - name: b4ae_v2_alerts
    rules:
      - alert: HighHandshakeFailureRate
        expr: rate(b4ae_handshakes_failed_total[5m]) > 0.01
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High handshake failure rate"
          
      - alert: HighDoSAttempts
        expr: rate(b4ae_dos_attempts_blocked_total[5m]) > 100
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High DoS attack rate"
          
      - alert: HighQueueLatency
        expr: b4ae_queue_latency_ms > 20
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High global scheduler queue latency"
```

---

## Troubleshooting

### Common Issues

#### 1. High Handshake Latency

**Symptoms**: Handshake time > 200ms

**Solutions**:
- Use Mode A instead of Mode B (9ms faster)
- Check network latency
- Verify CPU is not overloaded
- Check HSM performance (Mode B)

#### 2. DoS Attacks

**Symptoms**: High invalid cookie rate

**Solutions**:
- Cookie challenge is working (expected behavior)
- Monitor `b4ae_dos_attempts_blocked_total`
- Verify cookie secret is not compromised
- Check firewall rules

#### 3. High Queue Latency

**Symptoms**: Global scheduler latency > 20ms

**Solutions**:
- Increase `target_rate_msgs_per_sec`
- Reduce `dummy_message_rate`
- Allocate more CPU cores
- Check for network congestion

---

## References

### Documentation

- [V2.0 Architecture Overview](V2_ARCHITECTURE_OVERVIEW.md)
- [V2.0 Migration Guide](V2_MIGRATION_GUIDE.md)
- [V2.0 Security Analysis](V2_SECURITY_ANALYSIS.md)
- [V2.0 Mode Selection Guide](V2_MODE_SELECTION_GUIDE.md)
- [Deployment Guide](DEPLOYMENT_GUIDE.md)
- [Enterprise Deployment Guide](ENTERPRISE_DEPLOYMENT_GUIDE.md)
- [Pilot Deployment Guide](PILOT_DEPLOYMENT_GUIDE.md)

### Performance

- [Performance Analysis](PERFORMANCE.md)
- [Performance Under Attack](PERFORMANCE_UNDER_ATTACK.md)
- [Performance Under Stress](PERFORMANCE_UNDER_STRESS.md)

### Security

- [Threat Model Formalization](THREAT_MODEL_FORMALIZATION.md)
- [Formal Verification](FORMAL_VERIFICATION.md)
- [Security Audit Checklist](SECURITY_AUDIT_CHECKLIST.md)

---

**Document Status:** Complete  
**Last Updated:** 2026  
**Version:** 2.0.0
