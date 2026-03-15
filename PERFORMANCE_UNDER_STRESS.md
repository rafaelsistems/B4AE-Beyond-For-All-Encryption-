# B4AE v2.0 Performance Under Stress Analysis

**Version:** 2.0  
**Date:** 2026  
**Status:** Production-Ready (v2.0 100% Complete)  
**Reference:** V2_ARCHITECTURE_OVERVIEW.md, PERFORMANCE.md

## 1. Overview

This document analyzes the performance characteristics of the B4AE v2.0 protocol under realistic stress conditions, including network latency, packet loss, concurrent sessions, resource-constrained devices, and the new v2.0 features (cookie challenge, global traffic scheduler, Mode A/B authentication).

**v2.0 Updates:**
- Cookie challenge DoS protection performance under attack
- Global traffic scheduler performance under load
- Mode A vs Mode B performance comparison under stress
- Session binding overhead analysis

**Critical:** This document provides theoretical analysis and estimates based on v2.0 implementation. Actual benchmarks should be conducted in target environments.

## 2. Baseline Performance (Ideal Conditions) - v2.0

### 2.1 Handshake Performance by Mode

**Modern x86-64 CPU (3.0 GHz, single-threaded):**

#### Mode A (Deniable - XEdDSA Only)

| Operation                  | Time (ms) | Notes                          |
|----------------------------|-----------|--------------------------------|
| Kyber1024 keygen           | 0.5       | Per party                      |
| X25519 keygen              | 0.05      | Per party                      |
| XEdDSA sign                | 0.1       | Per signature                  |
| XEdDSA verify              | 0.2       | Per verification               |
| Kyber1024 encapsulate      | 0.5       | Once per handshake             |
| Kyber1024 decapsulate      | 0.6       | Once per handshake             |
| X25519 DH                  | 0.05      | Once per handshake             |
| HKDF-SHA512 (32 bytes)     | 0.01      | Multiple times                 |
| Cookie challenge (HMAC)    | 0.01      | DoS protection                 |

**Total Handshake Time (Mode A):**
- Cookie challenge: ~0.01 ms (server-side)
- Initiator: ~3.5 ms (keygen + 2 signs + 1 verify + decapsulate)
- Responder: ~3.0 ms (keygen + 1 sign + 2 verifies + encapsulate)
- **Round-trip (0ms latency):** ~6.5 ms + cookie challenge
- **With cookie challenge:** ~6.51 ms

#### Mode B (Post-Quantum - Dilithium5 Only)

| Operation                  | Time (ms) | Notes                          |
|----------------------------|-----------|--------------------------------|
| Kyber1024 keygen           | 0.5       | Per party                      |
| X25519 keygen              | 0.05      | Per party                      |
| Dilithium5 sign            | 5.0       | Per signature                  |
| Dilithium5 verify          | 5.0       | Per verification               |
| Kyber1024 encapsulate      | 0.5       | Once per handshake             |
| Kyber1024 decapsulate      | 0.6       | Once per handshake             |
| X25519 DH                  | 0.05      | Once per handshake             |
| HKDF-SHA512 (32 bytes)     | 0.01      | Multiple times                 |
| Cookie challenge (HMAC)    | 0.01      | DoS protection                 |

**Total Handshake Time (Mode B):**
- Cookie challenge: ~0.01 ms (server-side)
- Initiator: ~18 ms (keygen + 2 signs + 1 verify + decapsulate)
- Responder: ~16 ms (keygen + 1 sign + 2 verifies + encapsulate)
- **Round-trip (0ms latency):** ~34 ms + cookie challenge
- **With cookie challenge:** ~34.01 ms

**Mode Comparison:**
- Mode A: ~6.51 ms (30x faster signatures)
- Mode B: ~34.01 ms (post-quantum secure)
- Cookie overhead: ~0.01 ms (negligible)

**Source:** Estimates based on v2.0 implementation and PQC library performance

### 2.2 Message Encryption Performance

**Per-Message Operations:**

| Operation                  | Time (ms) | Notes                          |
|----------------------------|-----------|--------------------------------|
| HKDF (64 bytes)            | 0.01      | Message key derivation         |
| HKDF (32 bytes)            | 0.01      | Chain advancement              |
| ChaCha20-Poly1305 (1 KB)   | 0.05      | Encryption + MAC               |
| ChaCha20-Poly1305 (10 KB)  | 0.5       | Encryption + MAC               |
| ChaCha20-Poly1305 (100 KB) | 5.0       | Encryption + MAC               |

**Throughput:**
- Small messages (< 1 KB): ~50,000 msg/sec
- Medium messages (10 KB): ~2,000 msg/sec
- Large messages (100 KB): ~200 msg/sec

### 2.3 Cookie Challenge DoS Protection Performance

**v2.0 Feature:** Stateless cookie challenge before expensive crypto operations

**Cookie Challenge Operations:**

| Operation                  | Time (ms) | Notes                          |
|----------------------------|-----------|--------------------------------|
| Cookie generation (HMAC)   | 0.01      | Server-side                    |
| Cookie verification (HMAC) | 0.01      | Server-side                    |
| Bloom filter check         | 0.001     | Replay detection               |
| Timestamp validation       | 0.0001    | 30-second window               |

**DoS Protection Metrics:**

| Scenario                   | Cost per Attempt | DoS Amplification |
|----------------------------|------------------|-------------------|
| v1.0 (no cookie)           | 3.6ms            | 1x (baseline)     |
| v2.0 invalid cookie        | 0.01ms           | **360x reduction**|
| v2.0 valid cookie (Mode A) | 6.51ms           | ~1x (legitimate)  |
| v2.0 valid cookie (Mode B) | 34.01ms          | ~1x (legitimate)  |

**Under DoS Attack (10,000 invalid handshakes/sec):**
- v1.0: 36 seconds CPU time (server overwhelmed)
- v2.0: 0.1 seconds CPU time (360x improvement)

**Result:** v2.0 cookie challenge provides 360x DoS resistance improvement

### 2.4 Global Traffic Scheduler Performance

**v2.0 Feature:** Unified traffic scheduler for cross-session metadata protection

**Scheduler Operations:**

| Operation                  | Time (ms) | Notes                          |
|----------------------------|-----------|--------------------------------|
| Message enqueue            | 0.001     | Add to unified queue           |
| Message dequeue            | 0.001     | Constant-rate output           |
| Dummy message generation   | 0.01      | 20% cover traffic              |
| Timing obfuscation         | 0.001     | Random delay                   |

**Latency by Target Rate:**

| Target Rate | Avg Latency | Max Latency | Bandwidth Overhead | Use Case |
|-------------|-------------|-------------|-------------------|----------|
| 10 msg/s    | ~50ms       | ~100ms      | 20%               | High security |
| 100 msg/s   | ~5ms        | ~10ms       | 20%               | Standard |
| 1000 msg/s  | ~0.5ms      | ~1ms        | 20%               | Low latency |

**Under Load (1000 concurrent sessions, 100 msg/s target):**
- Queue depth: ~500 messages (5 seconds of buffering)
- Memory usage: ~50 MB (500 messages × 100 KB avg)
- CPU usage: ~2% (message scheduling overhead)
- Latency: ~5ms average (within target)

**Trade-off:** Metadata protection adds ~5ms latency for standard deployment

### 2.5 Session Binding Overhead

**v2.0 Feature:** Cryptographic session key binding to session_id

**Session Binding Operations:**

| Operation                  | Time (ms) | Notes                          |
|----------------------------|-----------|--------------------------------|
| session_id derivation      | 0.01      | HKDF(randoms + mode_id)        |
| Key derivation with binding| 0.01      | HKDF with session_id salt      |
| Protocol ID verification   | 0.001     | SHA3-256 comparison            |

**Overhead:** ~0.02ms per handshake (negligible)

**Security Benefit:** Prevents key transplant attacks with minimal overhead

### 2.6 Ratchet Performance

**DH Ratchet Operations:**

| Operation                  | Time (ms) | Notes                          |
|----------------------------|-----------|--------------------------------|
| Kyber1024 keygen           | 0.5       | Ephemeral keypair              |
| X25519 keygen              | 0.05      | Ephemeral keypair              |
| Kyber1024 encapsulate      | 0.5       | Shared secret derivation       |
| X25519 DH                  | 0.05      | Shared secret derivation       |
| HKDF (root key)            | 0.01      | Root key ratchet               |
| HKDF (chain keys)          | 0.02      | 2× chain key derivation        |

**Total Ratchet Overhead:** ~1.2 ms per ratchet step

**Frequency:** Every 100 messages (default)  
**Amortized Overhead:** ~0.012 ms per message

**v2.0 Note:** Ratchet performance unchanged from v1.0, but session binding adds ~0.01ms per key derivation

## 3. Performance Under Network Stress

### 3.1 High Latency (3G Network)

**Network Characteristics:**
- RTT: 200-500 ms
- Bandwidth: 1-5 Mbps
- Jitter: 50-100 ms

**Handshake Performance (Mode A):**
```
Total handshake time = 4 × RTT + computation_time + cookie_challenge
                     = 4 × 350ms + 6.5ms + 0.01ms
                     = 1406.51 ms (~1.4 seconds)
```

**Handshake Performance (Mode B):**
```
Total handshake time = 4 × RTT + computation_time + cookie_challenge
                     = 4 × 350ms + 34ms + 0.01ms
                     = 1434.01 ms (~1.4 seconds)
```

**v2.0 Note:** Cookie challenge adds one additional RTT (4 RTTs total instead of 3)

**Impact:**
- Handshake (Mode A): 216× slower than ideal (6.51ms → 1406ms)
- Handshake (Mode B): 42× slower than ideal (34.01ms → 1434ms)
- Message encryption: Minimal impact (computation-bound)
- Throughput: Limited by bandwidth (1-5 Mbps)
- Global scheduler: Adds ~5ms latency (negligible compared to network latency)

**Mitigation:**
- Session resumption (future enhancement)
- Connection pooling
- Reduce handshake frequency

### 3.2 Packet Loss (5%)

**Network Characteristics:**
- Packet loss: 5%
- RTT: 50 ms
- Retransmission timeout: 200 ms

**Handshake Performance (Mode A):**
```
Expected retransmissions per handshake:
  4 messages × 5% loss = 0.2 retransmissions
  
Average handshake time:
  = 4 × RTT + 0.2 × (RTT + RTO) + computation_time
  = 4 × 50ms + 0.2 × 250ms + 6.51ms
  = 200ms + 50ms + 6.51ms
  = 256.51 ms
```

**Handshake Performance (Mode B):**
```
Average handshake time:
  = 4 × 50ms + 0.2 × 250ms + 34.01ms
  = 200ms + 50ms + 34.01ms
  = 284.01 ms
```

**Impact:**
- Handshake (Mode A): 39× slower than ideal (6.51ms → 256ms)
- Handshake (Mode B): 8× slower than ideal (34.01ms → 284ms)
- Message delivery: 5% require retransmission
- Throughput: Reduced by ~5%
- Global scheduler: Adds ~5ms latency (negligible)

**Mitigation:**
- Forward error correction (FEC)
- Redundant transmission
- Application-level retransmission

### 3.3 Combined Stress (3G + 5% Loss)

**Network Characteristics:**
- RTT: 350 ms
- Packet loss: 5%
- Retransmission timeout: 1000 ms

**Handshake Performance (Mode A):**
```
Expected retransmissions: 0.2
Average handshake time:
  = 4 × 350ms + 0.2 × 1350ms + 6.51ms
  = 1400ms + 270ms + 6.51ms
  = 1676.51 ms (~1.7 seconds)
```

**Handshake Performance (Mode B):**
```
Average handshake time:
  = 4 × 350ms + 0.2 × 1350ms + 34.01ms
  = 1400ms + 270ms + 34.01ms
  = 1704.01 ms (~1.7 seconds)
```

**Impact:**
- Handshake (Mode A): 257× slower than ideal
- Handshake (Mode B): 50× slower than ideal
- Message delivery: Significantly delayed
- Throughput: Limited by bandwidth and loss
- Global scheduler: ~5ms latency (negligible compared to network)

**v2.0 Note:** Cookie challenge overhead (~0.01ms) is negligible compared to network latency

## 4. Performance Under Concurrent Load

### 4.1 Concurrent Sessions (500 sessions)

**Resource Requirements:**

| Resource               | Per Session | 500 Sessions | Notes                    |
|------------------------|-------------|--------------|--------------------------|
| Memory (ratchet state) | 72 KB       | 36 MB        | Cached keys              |
| Memory (session keys)  | 256 bytes   | 125 KB       | Session keys             |
| CPU (idle)             | 0%          | 0%           | No background work       |
| CPU (active)           | 0.05 ms/msg | 25 ms/msg    | 500 concurrent messages  |

**Handshake Throughput:**
```
Single-threaded: 1000ms / 20.5ms = ~48 handshakes/sec
Multi-threaded (8 cores): ~384 handshakes/sec

Time to establish 500 sessions:
  Single-threaded: 500 / 48 = ~10.4 seconds
  Multi-threaded: 500 / 384 = ~1.3 seconds
```

**Message Throughput:**
```
Single-threaded (1 KB messages): ~50,000 msg/sec
Multi-threaded (8 cores): ~400,000 msg/sec

Per-session throughput (500 sessions):
  Single-threaded: 50,000 / 500 = 100 msg/sec per session
  Multi-threaded: 400,000 / 500 = 800 msg/sec per session
```

**Bottlenecks:**
- Memory: 36 MB (acceptable)
- CPU: Computation-bound (parallelizable)
- Network: Bandwidth-bound (depends on message size)

### 4.2 Concurrent Ratchets

**Scenario:** 500 sessions, all ratcheting simultaneously

**Resource Requirements:**
```
CPU time: 500 × 1.2ms = 600ms (single-threaded)
          600ms / 8 cores = 75ms (multi-threaded)

Memory: No additional memory (ephemeral keys zeroized)
```

**Impact:**
- Brief CPU spike during ratchet
- No memory spike (keys zeroized)
- Minimal impact on throughput

### 4.3 Out-of-Order Message Handling

**Scenario:** 500 sessions, 10% out-of-order messages, average skip = 5

**Resource Requirements:**
```
Cache memory per session: 5 keys × 72 bytes = 360 bytes
Total cache memory: 500 × 360 bytes = 180 KB

CPU overhead per out-of-order message:
  5 key derivations × 0.02ms = 0.1ms
  
Total CPU overhead (10% of messages):
  0.1 × 0.1ms = 0.01ms per message (amortized)
```

**Impact:**
- Minimal memory overhead (180 KB)
- Minimal CPU overhead (0.01ms per message)
- Acceptable for realistic out-of-order patterns

## 5. Performance on Resource-Constrained Devices

### 5.1 Low-End Mobile CPU (ARM Cortex-A53, 1.2 GHz)

**Performance Scaling:**
```
Relative to x86-64 (3.0 GHz):
  Clock speed: 1.2 / 3.0 = 0.4×
  Architecture: ~0.6× (ARM vs x86)
  Overall: ~0.24× (4× slower)
```

**Handshake Performance:**
```
Initiator: 11ms × 4 = 44ms
Responder: 9.5ms × 4 = 38ms
Total (0ms latency): 82ms
```

**Message Encryption:**
```
1 KB message: 0.05ms × 4 = 0.2ms
Throughput: ~5,000 msg/sec
```

**Ratchet:**
```
DH ratchet: 1.2ms × 4 = 4.8ms
Amortized: 0.048ms per message
```

**Impact:**
- Handshake: 4× slower (acceptable)
- Message encryption: 4× slower (still fast)
- Ratchet: 4× slower (negligible)

### 5.2 Very Low-End Device (ARM Cortex-M4, 168 MHz)

**Performance Scaling:**
```
Relative to x86-64 (3.0 GHz):
  Clock speed: 0.168 / 3.0 = 0.056×
  Architecture: ~0.3× (Cortex-M vs x86)
  Overall: ~0.017× (60× slower)
```

**Handshake Performance:**
```
Initiator: 11ms × 60 = 660ms
Responder: 9.5ms × 60 = 570ms
Total (0ms latency): 1230ms (~1.2 seconds)
```

**Message Encryption:**
```
1 KB message: 0.05ms × 60 = 3ms
Throughput: ~333 msg/sec
```

**Ratchet:**
```
DH ratchet: 1.2ms × 60 = 72ms
Amortized: 0.72ms per message
```

**Impact:**
- Handshake: 60× slower (noticeable delay)
- Message encryption: 60× slower (still usable)
- Ratchet: 60× slower (noticeable spike)

**Recommendation:** Use hardware acceleration (AES-NI, SHA extensions) if available

### 5.3 WASM (Browser, V8 Engine)

**Performance Scaling:**
```
Relative to native x86-64:
  Overhead: ~1.5-2× (WASM vs native)
```

**Handshake Performance:**
```
Initiator: 11ms × 1.75 = 19.25ms
Responder: 9.5ms × 1.75 = 16.6ms
Total (0ms latency): 35.85ms
```

**Message Encryption:**
```
1 KB message: 0.05ms × 1.75 = 0.0875ms
Throughput: ~11,400 msg/sec
```

**Impact:**
- Handshake: 1.75× slower (acceptable)
- Message encryption: 1.75× slower (still fast)
- Ratchet: 1.75× slower (negligible)

**Limitations:**
- No SIMD (in some browsers)
- No hardware acceleration
- Garbage collection pauses

## 6. Battery Drain Characteristics

### 6.1 Energy Consumption Model

**Handshake Energy:**
```
CPU energy: computation_time × CPU_power
          = 20.5ms × 2W (typical mobile CPU)
          = 0.041 J per handshake

Network energy: 3 messages × (TX_power + RX_power)
              = 3 × (0.5W + 0.3W) × 50ms
              = 0.12 J per handshake

Total: ~0.16 J per handshake
```

**Message Encryption Energy:**
```
CPU energy: 0.05ms × 2W = 0.0001 J per 1 KB message
Network energy: (0.5W + 0.3W) × 10ms = 0.008 J per message

Total: ~0.008 J per 1 KB message
```

**Ratchet Energy:**
```
CPU energy: 1.2ms × 2W = 0.0024 J per ratchet
Amortized: 0.000024 J per message
```

### 6.2 Battery Life Impact

**Scenario:** 1000 messages/day, 10 handshakes/day, typical smartphone (3000 mAh, 3.7V)

```
Battery capacity: 3000 mAh × 3.7V = 11.1 Wh = 39,960 J

Daily energy consumption:
  Handshakes: 10 × 0.16 J = 1.6 J
  Messages: 1000 × 0.008 J = 8 J
  Ratchets: 10 × 0.0024 J = 0.024 J
  Total: ~9.6 J

Battery drain: 9.6 / 39,960 = 0.024% per day
```

**Impact:** Negligible battery drain (< 0.1% per day for typical usage)

### 6.3 High-Usage Scenario

**Scenario:** 10,000 messages/day, 100 handshakes/day

```
Daily energy consumption:
  Handshakes: 100 × 0.16 J = 16 J
  Messages: 10,000 × 0.008 J = 80 J
  Ratchets: 100 × 0.0024 J = 0.24 J
  Total: ~96 J

Battery drain: 96 / 39,960 = 0.24% per day
```

**Impact:** Still negligible (< 0.5% per day even for heavy usage)

## 7. Memory Pressure

### 7.1 Memory Usage Per Session

| Component              | Size (bytes) | Notes                          |
|------------------------|--------------|--------------------------------|
| Root key               | 32           | Current root key               |
| Sending chain key      | 32           | Current sending chain key      |
| Receiving chain key    | 32           | Current receiving chain key    |
| Cached message keys    | 72,000       | 1000 keys × 72 bytes (max)     |
| Session keys           | 96           | 3 keys × 32 bytes              |
| Session metadata       | 128          | Counters, state, etc.          |
| **Total**              | **72,320**   | ~70 KB per session             |

### 7.2 Memory Usage Under Load

**500 Concurrent Sessions:**
```
Total memory: 500 × 72 KB = 36 MB
```

**1000 Concurrent Sessions:**
```
Total memory: 1000 × 72 KB = 72 MB
```

**10,000 Concurrent Sessions:**
```
Total memory: 10,000 × 72 KB = 720 MB
```

**Impact:**
- 500 sessions: Acceptable on all devices
- 1000 sessions: Acceptable on desktop/server
- 10,000 sessions: Requires server-grade hardware

### 7.3 Memory Optimization

**Reduce Cache Size:**
```
cache_size = 10 (minimum)
Memory per session: 10 × 72 + 320 = 1,040 bytes (~1 KB)

10,000 sessions: 10,000 × 1 KB = 10 MB
```

**Trade-off:** Reduced out-of-order tolerance

**Recommendation:** Tune cache_size based on network conditions and memory constraints

## 8. Scalability Analysis

### 8.1 Server Scalability

**Single Server (8-core, 16 GB RAM):**

| Metric                 | Capacity      | Bottleneck                     |
|------------------------|---------------|--------------------------------|
| Concurrent sessions    | ~200,000      | Memory (16 GB / 72 KB)         |
| Handshakes/sec         | ~400          | CPU (8 cores × 50 hs/sec)      |
| Messages/sec           | ~400,000      | CPU (8 cores × 50k msg/sec)    |
| Bandwidth (1 KB msgs)  | ~400 MB/sec   | Network (assuming 1 Gbps)      |

**Scaling Strategy:**
- Horizontal scaling (multiple servers)
- Session affinity (sticky sessions)
- Load balancing

### 8.2 Client Scalability

**Desktop Client:**
- Concurrent sessions: ~1,000 (limited by use case, not hardware)
- Handshakes/sec: ~50 (single-threaded)
- Messages/sec: ~50,000 (single-threaded)

**Mobile Client:**
- Concurrent sessions: ~100 (limited by battery and memory)
- Handshakes/sec: ~12 (4× slower CPU)
- Messages/sec: ~12,500 (4× slower CPU)

### 8.3 Network Scalability

**Bandwidth Requirements:**

| Scenario               | Bandwidth     | Notes                          |
|------------------------|---------------|--------------------------------|
| 1 handshake/sec        | ~24 KB/sec    | 3 messages × 8 KB              |
| 100 messages/sec (1KB) | ~100 KB/sec   | 100 × 1 KB                     |
| 1000 messages/sec (1KB)| ~1 MB/sec     | 1000 × 1 KB                    |

**Scaling:** Linear with message rate and size

## 9. Stress Test Scenarios

### 9.1 Scenario 1: High Handshake Rate

**Setup:**
- 1000 handshakes/sec
- Single server (8-core)

**Expected Performance:**
```
CPU utilization: 1000 / 400 = 250% (2.5 cores)
Memory: Depends on session lifetime
Bandwidth: 1000 × 24 KB = 24 MB/sec
```

**Bottleneck:** CPU (handshake computation)

**Mitigation:**
- Horizontal scaling
- Hardware acceleration (if available)
- Rate limiting

### 9.2 Scenario 2: High Message Rate

**Setup:**
- 100,000 messages/sec (1 KB each)
- Single server (8-core)

**Expected Performance:**
```
CPU utilization: 100,000 / 400,000 = 25% (2 cores)
Memory: Depends on concurrent sessions
Bandwidth: 100,000 × 1 KB = 100 MB/sec
```

**Bottleneck:** Network bandwidth (assuming 1 Gbps)

**Mitigation:**
- Increase bandwidth (10 Gbps)
- Message batching
- Compression

### 9.3 Scenario 3: Mixed Load

**Setup:**
- 100 handshakes/sec
- 10,000 messages/sec (1 KB each)
- 1000 concurrent sessions

**Expected Performance:**
```
CPU utilization:
  Handshakes: 100 / 400 = 25%
  Messages: 10,000 / 400,000 = 2.5%
  Total: ~27.5% (2.2 cores)

Memory: 1000 × 72 KB = 72 MB

Bandwidth:
  Handshakes: 100 × 24 KB = 2.4 MB/sec
  Messages: 10,000 × 1 KB = 10 MB/sec
  Total: ~12.4 MB/sec
```

**Bottleneck:** None (well within capacity)

## 10. Performance Recommendations

### 10.1 For Low-Latency Applications

1. **Reduce Handshake Frequency:**
   - Session resumption (not implemented)
   - Long-lived sessions
   - Connection pooling

2. **Optimize Message Size:**
   - Compression
   - Efficient serialization
   - Avoid large messages

3. **Tune Ratchet Interval:**
   - Increase interval (reduce ratchet overhead)
   - Trade-off: Slower post-compromise recovery

### 10.2 For High-Throughput Applications

1. **Parallel Processing:**
   - Multi-threaded encryption
   - Batch processing
   - SIMD optimizations (if available)

2. **Hardware Acceleration:**
   - AES-NI for ChaCha20
   - SHA extensions for HKDF
   - Crypto accelerators

3. **Network Optimization:**
   - TCP tuning (window size, congestion control)
   - UDP for low-latency (with reliability layer)
   - Message batching

### 10.3 For Resource-Constrained Devices

1. **Reduce Memory Usage:**
   - Smaller cache_size (10-50)
   - Limit concurrent sessions
   - Aggressive cleanup

2. **Reduce CPU Usage:**
   - Increase ratchet_interval (reduce ratchet frequency)
   - Offload to server (if possible)
   - Hardware acceleration

3. **Reduce Battery Drain:**
   - Batch messages
   - Reduce handshake frequency
   - Optimize network usage

## 11. Benchmarking Methodology

### 11.1 Recommended Benchmarks

1. **Handshake Latency:**
   - Measure end-to-end handshake time
   - Vary network conditions (latency, loss)
   - Measure on target hardware

2. **Message Throughput:**
   - Measure messages/sec for various sizes
   - Vary concurrent sessions
   - Measure on target hardware

3. **Memory Usage:**
   - Measure peak memory usage
   - Vary concurrent sessions
   - Vary cache_size

4. **CPU Usage:**
   - Measure CPU utilization
   - Vary message rate
   - Vary concurrent sessions

5. **Battery Drain:**
   - Measure energy consumption
   - Vary usage patterns
   - Measure on target mobile device

### 11.2 Benchmark Tools

**Recommended:**
- `criterion` (Rust benchmarking)
- `perf` (Linux profiling)
- `Instruments` (macOS profiling)
- `iperf3` (network throughput)
- Custom load testing tools

**Source:** `benches/` directory (if available)

## 12. Conclusion - v2.0 Performance Summary

**B4AE v2.0 Protocol Performance:**
- ✅ Fast handshake: ~6.5ms (Mode A), ~34ms (Mode B) on modern CPU
- ✅ High message throughput: 50,000 msg/sec for 1 KB messages
- ✅ Low memory usage: ~70 KB per session
- ✅ Negligible battery drain: < 0.5% per day
- ✅ Scalable: hundreds of thousands of sessions per server
- ✅ **360x DoS protection improvement** via cookie challenge
- ✅ **Cross-session metadata protection** via global scheduler

**v2.0 Performance Improvements:**
- **Cookie Challenge:** 360x DoS resistance with 0.01ms overhead
- **Mode A (Deniable):** 30x faster signatures than Mode B
- **Mode B (PQ):** Post-quantum security with ~34ms handshake
- **Global Scheduler:** Cross-session protection with ~5ms latency
- **Session Binding:** Key transplant prevention with ~0.02ms overhead

**Performance Under Stress:**
- ⚠️ Handshake latency increases with network latency (4× RTT + computation)
- ⚠️ Throughput limited by network bandwidth
- ⚠️ CPU-bound on very low-end devices (60× slower)
- ✅ Acceptable on typical mobile devices (4× slower)
- ✅ Global scheduler adds ~5ms latency (acceptable trade-off)

**v2.0 Trade-offs:**
- **Cookie Challenge:** +1 RTT for DoS protection (acceptable)
- **Global Scheduler:** +5ms latency for metadata protection (configurable)
- **Mode B:** +27.5ms handshake for post-quantum security (acceptable)
- **Session Binding:** +0.02ms for key transplant prevention (negligible)

**Recommendation:** B4AE v2.0 protocol is suitable for most applications, including mobile and server deployments. Mode A provides fast handshakes for deniable authentication, Mode B provides post-quantum security. Cookie challenge and global scheduler provide strong security with minimal performance impact.

**For very low-end devices or extreme network conditions, consider:**
- Mode A for faster handshakes
- Increased ratchet interval
- Hardware acceleration
- Reduced cache size
- Higher scheduler target rate (lower latency, less metadata protection)

## 13. References

- V2_ARCHITECTURE_OVERVIEW.md: Complete v2.0 architecture
- V2_SECURITY_ANALYSIS.md: Security analysis of v2.0 features
- PERFORMANCE.md: Detailed v2.0 performance benchmarks
- NIST PQC Performance: https://csrc.nist.gov/projects/post-quantum-cryptography
- ChaCha20-Poly1305 Performance: RFC 8439
- Signal Protocol Performance: https://signal.org/docs/
- Implementation: `src/protocol/v2/`, `benches/`
