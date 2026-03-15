# B4AE v2.0 Enterprise Deployment Guide

**Version**: 2.0.0  
**Status**: Production-Ready (100% complete)  
**Last Updated**: 2026

Enterprise deployment guide for B4AE v2.0 in on-premises, hybrid cloud, and compliance-heavy environments.

---

## 1. Requirements

### Infrastructure

| Component        | Minimum                    | Recommended               |
|-----------------|----------------------------|----------------------------|
| CPU             | x86_64 / ARM64             | AES-NI, AVX2               |
| RAM             | 512 MB per node            | 2 GB+                     |
| Network         | UDP (ELARA), low latency   | Dedicated VLAN             |
| Storage         | Encrypted at rest          | HSM-backed keys            |
| Throughput      | 100 msg/s per node         | 1000 msg/s per node       |

### Software

- Rust 1.75+ (for build) or pre-built binaries
- TLS certificates (if exposing HTTPS endpoints)
- HSM/PKCS#11 (required for Mode B in high-security environments)
- Monitoring stack (Prometheus + Grafana recommended)

### V2.0 Specific Requirements

- **Mode B (PQ)**: Dilithium5 signature verification (~9ms per handshake)
- **Global Traffic Scheduler**: Dedicated CPU core for high-throughput deployments
- **Cookie Challenge**: Bloom filter memory (~10MB for 1M entries)
- **Session Binding**: Additional 32 bytes per session for session_id

---

## 2. Architecture Deployment

### 2.1 Single Node (POC)

```
[App] → [B4AE v2.0 Node] → UDP → [Peer]
         ↓
    [Global Scheduler]
    [Cookie Challenge]
    [Session Binding]
```

- Single process, single port UDP
- Global scheduler handles all sessions
- Suitable for POC, development, small deployments

**Configuration:**
```rust
use b4ae::protocol::v2::{
    AuthenticationMode, ModeNegotiationConfig,
    TrafficSchedulerConfig, GlobalScheduler
};

// Mode: Support both, prefer Mode A
let mode_config = ModeNegotiationConfig {
    supported_modes: vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB],
    preferred_mode: AuthenticationMode::ModeA,
};

// Global scheduler: Balanced
let scheduler_config = TrafficSchedulerConfig {
    target_rate_msgs_per_sec: 100.0,
    dummy_message_rate: 0.2,
    constant_rate_mode: true,
    max_queue_latency_ms: 5.0,
};
```

### 2.2 Multi-Node (Production)

```
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
│  Node A (Region 1)  │◄───►│  Node B (Hub)       │◄───►│  Node C (Region 2)  │
│  - Global Scheduler │     │  - Global Scheduler │     │  - Global Scheduler │
│  - Cookie Challenge │     │  - Cookie Challenge │     │  - Cookie Challenge │
│  - Mode A/B         │     │  - Mode A/B         │     │  - Mode A/B         │
└─────────────────────┘     └─────────────────────┘     └─────────────────────┘
```

- Deploy as microservice (Docker/Kubernetes)
- Each node has independent global scheduler
- Load balancer for UDP (sticky sessions recommended)
- Consider NAT traversal (ELARA) for hybrid cloud

**Load Balancing Considerations:**
- **Sticky Sessions**: Required for cookie challenge (client_random binding)
- **UDP Load Balancing**: Use consistent hashing on client IP
- **Health Checks**: Monitor cookie challenge success rate

### 2.3 Gateway Pattern

```
[Internal Legacy] ←→ [B4AE v2.0 Gateway] ←→ [B4AE v2.0 Network]
                      ↓
                  [Mode Translation]
                  [Cookie Challenge]
                  [Global Scheduler]
```

- Gateway translates B4AE v2.0 ↔ legacy protocol
- Centralized global scheduler for all gateway sessions
- See [GATEWAY_PROXY.md](GATEWAY_PROXY.md)

### 2.4 High-Availability (HA) Deployment

```
┌─────────────────────┐     ┌─────────────────────┐
│  Primary Node       │◄───►│  Secondary Node     │
│  - Active           │     │  - Standby          │
│  - Global Scheduler │     │  - Global Scheduler │
└─────────────────────┘     └─────────────────────┘
         ↓                           ↓
    [Shared State]              [Shared State]
    (Redis/etcd)                (Redis/etcd)
```

**HA Considerations:**
- **Session State**: Replicate session state to secondary node
- **Cookie Secrets**: Shared cookie secret for seamless failover
- **Global Scheduler**: Coordinate scheduler state across nodes
- **Failover Time**: < 1 second with proper health checks

---

## 3. Security Hardening

### 3.1 Network Security

- **Firewall**: Allow UDP only from trusted peers
- **VPN / Private Link**: For WAN connections
- **Rate Limiting**: At perimeter (cookie challenge provides DoS protection)
- **DDoS Protection**: Cookie challenge reduces amplification by 360x
- **Network Segmentation**: Isolate B4AE nodes in dedicated VLAN

**Firewall Rules:**
```bash
# Allow UDP from trusted peers only
iptables -A INPUT -p udp --dport 4000 -s <trusted_peer_ip> -j ACCEPT
iptables -A INPUT -p udp --dport 4000 -j DROP

# Rate limiting (optional, cookie challenge provides primary protection)
iptables -A INPUT -p udp --dport 4000 -m limit --limit 1000/s -j ACCEPT
```

### 3.2 Key Management

#### Mode A (Deniable)

- **Session Keys**: In-memory only (B4AE default: zeroize after use)
- **Long-term Keys**: XEdDSA keypairs
  - Store in HSM via `hsm-pkcs11` feature (recommended)
  - Or `key_store::KeyStore` for persistent MIK (passphrase-encrypted)
- **Key Rotation**: Manual or policy-based (every 90 days recommended)

#### Mode B (Post-Quantum)

- **Session Keys**: In-memory only (B4AE default: zeroize after use)
- **Long-term Keys**: Dilithium5 keypairs
  - **MUST** store in HSM for compliance environments
  - Dilithium5 private keys are large (~2.5KB)
  - HSM must support NIST PQC algorithms
- **Key Rotation**: Every 90 days (compliance requirement)

**HSM Configuration:**
```rust
use b4ae::crypto::hsm::HsmKeyStore;

// Initialize HSM
let hsm = HsmKeyStore::new("pkcs11:token=B4AE;object=dilithium5_key")?;

// Generate Dilithium5 keypair in HSM
let keypair = hsm.generate_dilithium5_keypair()?;

// Sign with HSM (private key never leaves HSM)
let signature = hsm.sign(&message)?;
```

#### Session Key Binding

- **Session ID**: Derived from client_random || server_random || mode_id
- **Key Derivation**: All keys bound to session_id (automatic in v2.0)
- **Key Transplant Protection**: Cryptographic binding prevents key reuse across sessions

**Encrypted Storage:**
```rust
use b4ae::storage::EncryptedStorage;

// Store session state encrypted at rest
let storage = EncryptedStorage::new("storage_key")?;
storage.store_session(session_id, &session_state)?;
```

### 3.3 Audit & Compliance

#### Audit Events

Set `B4aeConfig::audit_sink` with implementation of `AuditSink`:

```rust
use b4ae::audit::{AuditSink, AuditEvent};

struct SiemAuditSink {
    siem_endpoint: String,
}

impl AuditSink for SiemAuditSink {
    fn log_event(&self, event: AuditEvent) {
        // Send to SIEM (Syslog, Splunk, Elastic)
        match event {
            AuditEvent::HandshakeInitiated { session_id, mode, .. } => {
                siem_log!("Handshake initiated: session={}, mode={:?}", session_id, mode);
            }
            AuditEvent::HandshakeCompleted { session_id, mode, duration_ms } => {
                siem_log!("Handshake completed: session={}, mode={:?}, duration={}ms", 
                    session_id, mode, duration_ms);
            }
            AuditEvent::CookieChallengeIssued { client_ip, timestamp } => {
                siem_log!("Cookie challenge issued: client={}, timestamp={}", 
                    client_ip, timestamp);
            }
            AuditEvent::InvalidCookieRejected { client_ip, reason } => {
                siem_log!("Invalid cookie rejected: client={}, reason={}", 
                    client_ip, reason);
            }
            AuditEvent::ModeDowngradeAttempt { session_id, attempted_mode, actual_mode } => {
                siem_log!("Mode downgrade attempt: session={}, attempted={:?}, actual={:?}", 
                    session_id, attempted_mode, actual_mode);
            }
            AuditEvent::KeyTransplantBlocked { session_id, source_session } => {
                siem_log!("Key transplant blocked: session={}, source={}", 
                    session_id, source_session);
            }
            _ => {}
        }
    }
}
```

**Audit Events (V2.0):**
- `HandshakeInitiated` / `HandshakeCompleted` (with mode)
- `SessionCreated` / `SessionClosed`
- `CookieChallengeIssued` / `InvalidCookieRejected`
- `ModeNegotiated` / `ModeDowngradeAttempt`
- `KeyTransplantBlocked`
- `KeyRotation` (peer/session hashed for privacy)

**Privacy Considerations:**
- Session IDs are hashed before logging
- Peer identities are hashed (SHA-256)
- Message content never logged

#### Compliance Requirements

**SOC 2:**
- ✅ Encryption at rest (encrypted storage)
- ✅ Encryption in transit (B4AE v2.0 protocol)
- ✅ Key management (HSM for Mode B)
- ✅ Audit trail (AuditEvent → SIEM)
- ✅ Access control (network ACL, principle of least privilege)

**HIPAA:**
- ✅ PHI encryption (B4AE v2.0 provides)
- ✅ Audit logs (AuditEvent → SIEM)
- ✅ Access control (network ACL)
- ✅ Data retention (configurable)
- ✅ Breach notification (audit logs)

**GDPR:**
- ✅ Data minimization (session IDs hashed)
- ✅ Right to erasure (session cleanup)
- ✅ Data portability (export audit logs)
- ✅ Privacy by design (security-by-default)

### 3.4 Memory Management (Long-Running Services)

Call cleanup functions periodically to prevent memory leaks:

```rust
use tokio::time::{interval, Duration};

async fn cleanup_loop(client: &B4aeClient) {
    let mut interval = interval(Duration::from_secs(3600)); // Every hour
    
    loop {
        interval.tick().await;
        
        // Cleanup old sessions and handshakes
        client.cleanup_old_state().await;
        
        // Or granular control:
        client.cleanup_inactive_sessions(3600).await; // 1 hour inactive
        client.cleanup_stale_handshakes().await; // Failed handshakes
        
        // Cleanup Bloom filter (cookie challenge)
        client.cleanup_bloom_filter().await;
    }
}
```

**Retention Policy:**
- **Active Sessions**: Keep until closed
- **Inactive Sessions**: Cleanup after 1 hour (configurable)
- **Failed Handshakes**: Cleanup after 5 minutes
- **Bloom Filter**: Rotate every 30 seconds (cookie challenge)
- **Audit Logs**: Retain per compliance requirements (90 days - 7 years)

### 3.5 Container / Orchestration

#### Docker

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release --features v2_protocol

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl3 ca-certificates
COPY --from=builder /app/target/release/b4ae /usr/local/bin/
EXPOSE 4000/udp
CMD ["b4ae", "--config", "/etc/b4ae/config.toml"]
```

#### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: b4ae-v2
spec:
  replicas: 3
  selector:
    matchLabels:
      app: b4ae-v2
  template:
    metadata:
      labels:
        app: b4ae-v2
    spec:
      containers:
      - name: b4ae
        image: b4ae:v2.0.0
        ports:
        - containerPort: 4000
          protocol: UDP
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        env:
        - name: RUST_LOG
          value: "b4ae=info"
        - name: B4AE_MODE
          value: "balanced"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: b4ae-v2-service
spec:
  type: LoadBalancer
  selector:
    app: b4ae-v2
  ports:
  - protocol: UDP
    port: 4000
    targetPort: 4000
```

**Resource Limits:**
- **CPU**: 500m (minimum), 2000m (recommended for Mode B)
- **Memory**: 512Mi (minimum), 2Gi (recommended for high throughput)
- **Storage**: 10Gi for audit logs and session state

---

## 4. Monitoring

### Metrics (Prometheus)

Export metrics via Prometheus:

```rust
use prometheus::{register_counter, register_histogram, Counter, Histogram};

// V2.0 specific metrics
let mode_a_handshakes = register_counter!("b4ae_mode_a_handshakes_total", "Mode A handshakes").unwrap();
let mode_b_handshakes = register_counter!("b4ae_mode_b_handshakes_total", "Mode B handshakes").unwrap();
let cookie_challenges = register_counter!("b4ae_cookie_challenges_total", "Cookie challenges issued").unwrap();
let invalid_cookies = register_counter!("b4ae_invalid_cookies_total", "Invalid cookies rejected").unwrap();
let dos_attempts = register_counter!("b4ae_dos_attempts_blocked_total", "DoS attempts blocked").unwrap();

// Session metrics
let active_sessions = register_gauge!("b4ae_sessions_active", "Active sessions").unwrap();
let session_keys_derived = register_counter!("b4ae_session_keys_derived_total", "Session keys derived").unwrap();
let key_transplant_blocked = register_counter!("b4ae_key_transplant_blocked_total", "Key transplant attempts blocked").unwrap();

// Global scheduler metrics
let messages_queued = register_gauge!("b4ae_messages_queued", "Messages in global queue").unwrap();
let queue_latency = register_histogram!("b4ae_queue_latency_ms", "Queue latency in ms").unwrap();
let dummy_messages = register_counter!("b4ae_dummy_messages_total", "Dummy messages sent").unwrap();

// Handshake metrics
let handshake_duration = register_histogram!("b4ae_handshake_duration_ms", "Handshake duration in ms").unwrap();
let handshakes_total = register_counter!("b4ae_handshakes_total", "Total handshakes").unwrap();
let handshakes_failed = register_counter!("b4ae_handshakes_failed_total", "Failed handshakes").unwrap();

// Message metrics
let messages_sent = register_counter!("b4ae_messages_sent_total", "Messages sent").unwrap();
let messages_received = register_counter!("b4ae_messages_received_total", "Messages received").unwrap();
```

### Grafana Dashboard

Create dashboard with panels:

1. **Mode Distribution**: Pie chart (Mode A vs Mode B handshakes)
2. **DoS Protection**: Line graph (cookie challenges, invalid cookies, blocked attempts)
3. **Session Metrics**: Gauge (active sessions, unique session IDs)
4. **Global Scheduler**: Line graph (queue latency, target rate, actual rate)
5. **Handshake Performance**: Histogram (handshake duration by mode)
6. **Throughput**: Line graph (messages sent/received per second)
7. **Security Events**: Table (mode downgrade attempts, key transplant blocks)

### Logging

Structured logs (JSON) for aggregation:

```rust
use tracing::{info, warn, error};

// V2.0 specific logs
info!(
    session_id = %session_id,
    mode = ?mode,
    duration_ms = handshake_duration,
    "Handshake completed"
);

warn!(
    client_ip = %client_ip,
    reason = "expired",
    "Invalid cookie rejected"
);

error!(
    session_id = %session_id,
    attempted_mode = ?attempted_mode,
    actual_mode = ?actual_mode,
    "Mode downgrade attempt detected"
);
```

**Log Levels:**
- `RUST_LOG=b4ae=info` - Production
- `RUST_LOG=b4ae=debug` - Troubleshooting
- `RUST_LOG=b4ae=trace` - Development only (verbose)

---

## 5. Compliance Checklist

- [ ] **Encryption at rest**: Disk encryption (LUKS, BitLocker) + EncryptedStorage
- [ ] **Encryption in transit**: B4AE v2.0 provides (Mode A or Mode B)
- [ ] **Key management**: HSM (`hsm-pkcs11`) for Mode B, KeyStore for Mode A
- [ ] **Audit trail**: AuditEvent → SIEM (Splunk, Elastic, Syslog)
- [ ] **Access control**: Network ACL, principle of least privilege
- [ ] **Data retention**: Policy for session logs, audit logs (90 days - 7 years)
- [ ] **Incident response**: Runbook for key compromise, node breach
- [ ] **DoS protection**: Cookie challenge enabled (default in v2.0)
- [ ] **Mode selection**: Mode A (deniable) or Mode B (PQ) based on requirements
- [ ] **Session isolation**: Session key binding enabled (default in v2.0)
- [ ] **Metadata protection**: Global traffic scheduler configured
- [ ] **Monitoring**: Prometheus + Grafana dashboard deployed
- [ ] **Backup**: Session state and audit logs backed up regularly
- [ ] **Disaster recovery**: HA deployment with failover tested

---

## 6. Rollout Plan

### Phase 1: POC (Week 1-2)

- Single node deployment
- Internal testing only
- Mode A (deniable) for fast handshakes
- Low overhead configuration
- Validate functionality

### Phase 2: Pilot (Week 3-6)

- Multi-node deployment (3 nodes)
- Limited users (10-100)
- One region
- Balanced configuration
- Monitor metrics
- See [PILOT_DEPLOYMENT_GUIDE.md](PILOT_DEPLOYMENT_GUIDE.md)

### Phase 3: Production (Week 7-12)

- Full rollout
- All users
- Multi-region
- High security configuration for critical communications
- Monitoring and alerting
- See [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md)

### Phase 4: Optimization (Ongoing)

- Tuning based on metrics
- Scaling based on load
- Security hardening
- Performance optimization

---

## 7. References

### V2.0 Documentation

- [V2.0 Architecture Overview](V2_ARCHITECTURE_OVERVIEW.md)
- [V2.0 Migration Guide](V2_MIGRATION_GUIDE.md)
- [V2.0 Security Analysis](V2_SECURITY_ANALYSIS.md)
- [V2.0 Mode Selection Guide](V2_MODE_SELECTION_GUIDE.md)
- [Deployment Guide](DEPLOYMENT_GUIDE.md)

### Deployment Guides

- [Production Deployment](PRODUCTION_DEPLOYMENT.md)
- [Pilot Deployment Guide](PILOT_DEPLOYMENT_GUIDE.md)
- [Security Audit Checklist](SECURITY_AUDIT_CHECKLIST.md)

### Performance

- [Performance Analysis](PERFORMANCE.md)
- [Performance Under Attack](PERFORMANCE_UNDER_ATTACK.md)
- [Performance Under Stress](PERFORMANCE_UNDER_STRESS.md)

---

**Document Status:** Complete  
**Last Updated:** 2026  
**Version:** 2.0.0
