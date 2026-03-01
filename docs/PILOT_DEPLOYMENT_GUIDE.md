# B4AE v2.0 Pilot Deployment Guide

**Version:** 2.0  
**Status:** Production-Ready (v2.0 100% Complete)  
**Reference:** V2_ARCHITECTURE_OVERVIEW.md, DEPLOYMENT_GUIDE.md

Panduan deployment pilot untuk evaluasi B4AE v2.0 dalam environment terkontrol.

---

## Phase 4: Pilot Deployment v2.0

### Scope Pilot

- **Duration**: 2–4 minggu
- **Users**: Tim internal / early adopters
- **Traffic**: Test load, bukan production load
- **Environment**: Staging / sandbox
- **v2.0 Features**: Mode A/B testing, cookie challenge, global scheduler

### Step 1: Persiapan

```bash
# Clone
git clone --recursive https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-.git
cd B4AE-Beyond-For-All-Encryption-

# Security audit
./scripts/security_audit.sh   # Linux/macOS
# atau scripts/security_audit.ps1 pada Windows

# Build dengan v2.0 features
cargo build --release --features v2_protocol

# Tests (termasuk v2.0 tests)
cargo test --release --features v2_protocol
```

### Step 2: Konfigurasi v2.0

#### Mode Selection (Mode A vs Mode B)

**Mode A (Deniable Authentication):**
```rust
let config = B4aeConfig {
    authentication_mode: AuthenticationMode::ModeA,  // XEdDSA only
    // ... other config
};
```

**Use cases:**
- Private messaging
- Whistleblowing platforms
- Anonymous communication
- Low-latency requirements

**Mode B (Post-Quantum Non-Repudiable):**
```rust
let config = B4aeConfig {
    authentication_mode: AuthenticationMode::ModeB,  // Dilithium5 only
    // ... other config
};
```

**Use cases:**
- Legal contracts
- Audit trails
- Compliance scenarios
- Long-term confidentiality (>10 years)

#### Cookie Challenge Configuration

```rust
let config = B4aeConfig {
    cookie_challenge_enabled: true,  // Default: true (security-by-default)
    cookie_validity_seconds: 30,     // Default: 30 seconds
    cookie_secret_rotation_hours: 24, // Default: 24 hours
    // ... other config
};
```

**DoS Protection:** 360x improvement dengan cookie challenge

#### Global Traffic Scheduler Configuration

```rust
let config = B4aeConfig {
    global_scheduler_enabled: true,   // Default: true (security-by-default)
    scheduler_target_rate: 100.0,     // Default: 100 msg/s
    cover_traffic_budget: 0.20,       // Default: 20% (minimum)
    // ... other config
};
```

**Scheduler Profiles:**
- **High Security:** 10 msg/s, 50% cover traffic (~50ms latency)
- **Standard:** 100 msg/s, 20% cover traffic (~5ms latency)
- **Low Latency:** 1000 msg/s, 20% cover traffic (~0.5ms latency)

#### Network Configuration

- Firewall rules untuk UDP (ELARA) jika dipakai
- Cookie challenge: tidak perlu port tambahan
- Global scheduler: internal, tidak perlu konfigurasi network

#### Logging Configuration

```bash
# Standard logging
export RUST_LOG=info

# Debug logging (untuk troubleshooting)
export RUST_LOG=debug

# v2.0 specific logging
export RUST_LOG=b4ae::protocol::v2=debug
```

#### Key Management

- Gunakan key management yang aman (HSM opsional)
- Session binding: otomatis di v2.0
- Protocol ID: otomatis derived dari spec

### Step 3: Deploy

**Option A: Bare metal / VM**
```bash
# Deploy binary hasil cargo build --release
./target/release/b4ae-server --config pilot-config.toml

# Jalankan sebagai service (systemd)
sudo systemctl start b4ae-pilot
sudo systemctl enable b4ae-pilot
```

**Option B: Docker**
```bash
# Build dengan v2.0 features
docker build -t b4ae-pilot:v2.0 --build-arg FEATURES=v2_protocol .

# Run dengan environment variables
docker run -e RUST_LOG=info \
           -e B4AE_MODE=ModeA \
           -e B4AE_SCHEDULER_RATE=100 \
           b4ae-pilot:v2.0
```

**Option C: Kubernetes**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: b4ae-pilot-v2
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: b4ae
        image: b4ae-pilot:v2.0
        env:
        - name: RUST_LOG
          value: "info"
        - name: B4AE_MODE
          value: "ModeA"
        - name: B4AE_SCHEDULER_RATE
          value: "100"
```

### Step 4: Monitoring v2.0

#### Metrics to Monitor

**Handshake Metrics:**
- Handshake success rate (target: >99%)
- Handshake latency (Mode A: ~150ms, Mode B: ~155ms)
- Cookie challenge rejection rate (expected: <1% false positives)
- Mode negotiation success rate (target: 100%)

**Message Metrics:**
- Message delivery success (target: >99%)
- Message latency (with scheduler: ~5ms average)
- Throughput (messages/sec)
- Error rate

**DoS Protection Metrics:**
- Invalid cookie attempts (should be rejected quickly)
- Cookie challenge overhead (~0.01ms)
- Bloom filter false positive rate (expected: 0.1%)

**Global Scheduler Metrics:**
- Queue depth (should be <1000 messages)
- Scheduler latency (target: ~5ms for 100 msg/s)
- Dummy message percentage (target: 20%)
- Cross-session indistinguishability

**Security Metrics:**
- Session binding verification (target: 100%)
- Protocol ID mismatch (should be 0)
- Downgrade attack attempts (should be detected)

#### Logging Examples

```
# Handshake success (Mode A)
[INFO] Handshake completed: mode=ModeA, latency=152ms, session_id=abc123

# Cookie challenge rejection
[WARN] Cookie challenge failed: reason=expired, client_ip=192.168.1.100

# Global scheduler stats
[INFO] Scheduler stats: queue_depth=234, latency_avg=4.8ms, dummy_pct=19.5%

# Session binding verification
[DEBUG] Session binding verified: session_id=abc123, protocol_id=def456
```

### Step 5: Testing Scenarios

#### Scenario 1: Mode A vs Mode B Comparison

**Test:**
1. Deploy 2 pilot instances (Mode A dan Mode B)
2. Measure handshake latency untuk masing-masing mode
3. Compare performance dan security properties

**Expected Results:**
- Mode A: ~150ms handshake, deniable signatures
- Mode B: ~155ms handshake, post-quantum secure

#### Scenario 2: DoS Attack Simulation

**Test:**
1. Send 10,000 invalid handshake attempts
2. Measure server CPU usage dan response time

**Expected Results:**
- v2.0 dengan cookie: ~0.1s CPU time (360x improvement)
- Server tetap responsive untuk legitimate clients

#### Scenario 3: Global Scheduler Load Test

**Test:**
1. Create 100 concurrent sessions
2. Send messages dengan varying rates
3. Measure latency dan cross-session indistinguishability

**Expected Results:**
- Average latency: ~5ms (100 msg/s target)
- Queue depth: <500 messages
- Dummy traffic: ~20%

#### Scenario 4: Network Stress Test

**Test:**
1. Simulate 3G network (350ms RTT, 5% packet loss)
2. Measure handshake success rate dan latency

**Expected Results:**
- Handshake success: >95%
- Handshake latency: ~1.4-1.7 seconds (acceptable)

### Step 6: Rollback

- Simpan binary/layer sebelumnya
- Rollback = deploy versi sebelumnya
- Session keys invalidated — client perlu re-handshake
- v2.0 → v1.0 rollback: tidak compatible (breaking changes)

**Rollback Procedure:**
```bash
# Stop v2.0 service
sudo systemctl stop b4ae-pilot

# Deploy v1.0 binary (jika diperlukan)
sudo cp /backup/b4ae-v1.0 /usr/local/bin/b4ae-server

# Start v1.0 service
sudo systemctl start b4ae-pilot

# Note: Clients harus re-handshake dengan v1.0
```

---

## Kriteria Sukses Pilot v2.0

### Functional Requirements
- [ ] Handshake success rate > 99% (Mode A dan Mode B)
- [ ] Message delivery success > 99%
- [ ] Mode negotiation success rate = 100%
- [ ] Cookie challenge false positive rate < 1%
- [ ] Global scheduler latency < 10ms (100 msg/s target)

### Security Requirements
- [ ] No critical security findings
- [ ] DoS protection: 360x improvement verified
- [ ] Session binding: 100% verification success
- [ ] Protocol ID: no downgrade attacks detected
- [ ] Constant-time operations: no timing leaks

### Performance Requirements
- [ ] Handshake latency: Mode A <200ms, Mode B <250ms (including network)
- [ ] Message latency: <10ms (with scheduler)
- [ ] Throughput: >100 msg/s per session
- [ ] Memory usage: <100 MB per 1000 sessions
- [ ] CPU usage: <50% under normal load

### User Feedback
- [ ] Feedback dari pilot users (usability, performance)
- [ ] Mode selection guidance clear dan helpful
- [ ] Error messages informative
- [ ] Documentation adequate

---

## Troubleshooting v2.0

### Issue: Handshake Timeout

**Symptoms:** Handshake tidak complete dalam 30 detik

**Possible Causes:**
- Network latency terlalu tinggi
- Cookie challenge timeout (30 seconds)
- Mode negotiation failure

**Solutions:**
- Increase handshake timeout: `handshake_timeout_ms: 60000`
- Check network connectivity
- Verify mode compatibility (client dan server)

### Issue: Cookie Challenge False Positives

**Symptoms:** Legitimate clients rejected dengan "invalid cookie"

**Possible Causes:**
- Clock skew antara client dan server
- Cookie secret rotation during handshake
- Bloom filter false positive (0.1% expected)

**Solutions:**
- Sync clocks (NTP)
- Increase cookie validity: `cookie_validity_seconds: 60`
- Accept false positive rate (0.1% is acceptable)

### Issue: High Scheduler Latency

**Symptoms:** Message latency >10ms dengan 100 msg/s target

**Possible Causes:**
- Queue depth terlalu tinggi (>1000 messages)
- CPU overload
- Too many concurrent sessions

**Solutions:**
- Increase scheduler rate: `scheduler_target_rate: 1000.0`
- Scale horizontally (add more servers)
- Reduce cover traffic budget: `cover_traffic_budget: 0.10`

### Issue: Mode Negotiation Failure

**Symptoms:** Handshake fails dengan "mode mismatch"

**Possible Causes:**
- Client dan server support different modes
- Mode downgrade attack detected

**Solutions:**
- Verify both client dan server support same modes
- Check mode configuration
- Review security logs for downgrade attempts

---

## Next Steps After Pilot

1. **Analyze Results:**
   - Review metrics dan logs
   - Identify performance bottlenecks
   - Collect user feedback

2. **Security Review:**
   - External security audit (jika belum)
   - Penetration testing
   - Formal verification review

3. **Production Preparation:**
   - Finalize configuration
   - Setup monitoring dan alerting
   - Prepare runbooks

4. **Production Deployment:**
   - Follow PRODUCTION_DEPLOYMENT.md
   - Gradual rollout (canary deployment)
   - Monitor closely

---

## Referensi

- [V2_ARCHITECTURE_OVERVIEW.md](V2_ARCHITECTURE_OVERVIEW.md) - Complete v2.0 architecture
- [V2_MIGRATION_GUIDE.md](V2_MIGRATION_GUIDE.md) - Migration from v1.0 to v2.0
- [V2_MODE_SELECTION_GUIDE.md](V2_MODE_SELECTION_GUIDE.md) - Mode A vs Mode B guidance
- [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md) - Production deployment guide
- [INTEGRATION_TESTING_PLAN.md](INTEGRATION_TESTING_PLAN.md) - Integration testing
- [PERFORMANCE.md](PERFORMANCE.md) - Performance benchmarks

---

*Last updated: 2026*  
*Version: 2.0*
