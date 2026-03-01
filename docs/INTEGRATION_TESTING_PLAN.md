# B4AE v2.0 Integration Testing Plan

**Version:** 2.0  
**Status:** Production-Ready (v2.0 100% Complete)  
**Reference:** V2_ARCHITECTURE_OVERVIEW.md, V2_SECURITY_ANALYSIS.md

Rencana pengujian integrasi yang lengkap untuk B4AE v2.0 Protocol dengan fokus pada fitur-fitur baru: Mode A/B authentication, cookie challenge, global traffic scheduler, dan session binding.

## Status Saat Ini

| Area | Coverage | Status |
|------|----------|--------|
| Unit tests | crypto, protocol, metadata | ✅ |
| Integration (handshake + message) | Basic flow | ✅ |
| Security / Penetration | Replay, MITM, forgery | ✅ |
| Performance | Handshake, AES-GCM, throughput | ✅ |
| Fuzzing | Binary, handshake, malformed | ✅ |
| ELARA end-to-end | tests/elara_integration_test.rs | ✅ |
| **v2.0 Mode Negotiation** | Mode A/B/C tests | ✅ |
| **v2.0 Cookie Challenge** | DoS protection tests | ✅ |
| **v2.0 Global Scheduler** | Cross-session tests | ✅ |
| **v2.0 Session Binding** | Key transplant tests | ✅ |
| **v2.0 Downgrade Protection** | Mode binding tests | ✅ |
| Multi-node / Distributed | — | ❌ |
| Chaos / Failure injection | — | ❌ |

---

## Fase 1: v2.0 Core Features Testing (2–3 minggu)

### 1.1 Mode Negotiation Tests

**Test Scenarios:**

#### Test 1.1.1: Mode A Handshake
```rust
#[tokio::test]
async fn test_mode_a_handshake() {
    let mut client = B4aeClient::new(AuthenticationMode::ModeA);
    let mut server = B4aeServer::new(AuthenticationMode::ModeA);
    
    // Perform handshake
    let session = client.connect(&server).await.unwrap();
    
    // Verify Mode A properties
    assert_eq!(session.mode(), AuthenticationMode::ModeA);
    assert!(session.is_deniable());
    assert!(!session.is_post_quantum());
    
    // Verify XEdDSA signatures used
    assert!(session.signature_scheme() == SignatureScheme::XEdDSA);
}
```

#### Test 1.1.2: Mode B Handshake
```rust
#[tokio::test]
async fn test_mode_b_handshake() {
    let mut client = B4aeClient::new(AuthenticationMode::ModeB);
    let mut server = B4aeServer::new(AuthenticationMode::ModeB);
    
    // Perform handshake
    let session = client.connect(&server).await.unwrap();
    
    // Verify Mode B properties
    assert_eq!(session.mode(), AuthenticationMode::ModeB);
    assert!(!session.is_deniable());
    assert!(session.is_post_quantum());
    
    // Verify Dilithium5 signatures used
    assert!(session.signature_scheme() == SignatureScheme::Dilithium5);
}
```

#### Test 1.1.3: Mode Mismatch Detection
```rust
#[tokio::test]
async fn test_mode_mismatch() {
    let mut client = B4aeClient::new(AuthenticationMode::ModeA);
    let mut server = B4aeServer::new(AuthenticationMode::ModeB);
    
    // Handshake should fail with mode mismatch
    let result = client.connect(&server).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), B4aeError::ModeMismatch);
}
```

#### Test 1.1.4: Mode Downgrade Attack Detection
```rust
#[tokio::test]
async fn test_mode_downgrade_attack() {
    let mut client = B4aeClient::new(AuthenticationMode::ModeB);
    let mut server = B4aeServer::new(AuthenticationMode::ModeB);
    
    // Attacker tries to downgrade to Mode A
    let mut attacker = MitmAttacker::new();
    attacker.intercept_mode_negotiation();
    attacker.modify_mode(AuthenticationMode::ModeA);
    
    // Handshake should fail (mode binding verification)
    let result = client.connect_through(&attacker, &server).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), B4aeError::DowngradeAttackDetected);
}
```

### 1.2 Cookie Challenge Tests

**Test Scenarios:**

#### Test 1.2.1: Valid Cookie Challenge
```rust
#[tokio::test]
async fn test_valid_cookie_challenge() {
    let mut server = B4aeServer::new_with_cookie_challenge();
    let mut client = B4aeClient::new(AuthenticationMode::ModeA);
    
    // Client sends ClientHello
    let client_hello = client.generate_client_hello();
    
    // Server responds with CookieChallenge
    let cookie_challenge = server.process_client_hello(&client_hello).unwrap();
    assert!(cookie_challenge.is_cookie_challenge());
    
    // Client sends ClientHelloWithCookie
    let client_hello_with_cookie = client.process_cookie_challenge(&cookie_challenge).unwrap();
    
    // Server verifies cookie and proceeds
    let result = server.process_client_hello_with_cookie(&client_hello_with_cookie);
    assert!(result.is_ok());
}
```

#### Test 1.2.2: Invalid Cookie Rejection
```rust
#[tokio::test]
async fn test_invalid_cookie_rejection() {
    let mut server = B4aeServer::new_with_cookie_challenge();
    let mut client = B4aeClient::new(AuthenticationMode::ModeA);
    
    // Client sends ClientHello
    let client_hello = client.generate_client_hello();
    let cookie_challenge = server.process_client_hello(&client_hello).unwrap();
    
    // Client modifies cookie (attack)
    let mut modified_cookie = client.process_cookie_challenge(&cookie_challenge).unwrap();
    modified_cookie.cookie[0] ^= 0xFF;  // Flip bits
    
    // Server rejects invalid cookie
    let result = server.process_client_hello_with_cookie(&modified_cookie);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), B4aeError::InvalidCookie);
}
```

#### Test 1.2.3: Expired Cookie Rejection
```rust
#[tokio::test]
async fn test_expired_cookie_rejection() {
    let mut server = B4aeServer::new_with_cookie_challenge();
    let mut client = B4aeClient::new(AuthenticationMode::ModeA);
    
    // Client sends ClientHello
    let client_hello = client.generate_client_hello();
    let cookie_challenge = server.process_client_hello(&client_hello).unwrap();
    
    // Wait for cookie to expire (30 seconds)
    tokio::time::sleep(Duration::from_secs(31)).await;
    
    // Client sends expired cookie
    let client_hello_with_cookie = client.process_cookie_challenge(&cookie_challenge).unwrap();
    
    // Server rejects expired cookie
    let result = server.process_client_hello_with_cookie(&client_hello_with_cookie);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), B4aeError::ExpiredCookie);
}
```

#### Test 1.2.4: DoS Protection Performance
```rust
#[tokio::test]
async fn test_dos_protection_performance() {
    let mut server = B4aeServer::new_with_cookie_challenge();
    
    // Send 10,000 invalid handshake attempts
    let start = Instant::now();
    for _ in 0..10_000 {
        let invalid_hello = generate_random_client_hello();
        let _ = server.process_client_hello(&invalid_hello);
    }
    let duration = start.elapsed();
    
    // Should complete in <1 second (360x improvement)
    assert!(duration < Duration::from_secs(1));
    
    // Server should still be responsive
    let valid_client = B4aeClient::new(AuthenticationMode::ModeA);
    let result = valid_client.connect(&server).await;
    assert!(result.is_ok());
}
```

#### Test 1.2.5: Replay Attack Detection
```rust
#[tokio::test]
async fn test_replay_attack_detection() {
    let mut server = B4aeServer::new_with_cookie_challenge();
    let mut client = B4aeClient::new(AuthenticationMode::ModeA);
    
    // Client completes handshake
    let client_hello = client.generate_client_hello();
    let cookie_challenge = server.process_client_hello(&client_hello).unwrap();
    let client_hello_with_cookie = client.process_cookie_challenge(&cookie_challenge).unwrap();
    
    // First attempt succeeds
    let result1 = server.process_client_hello_with_cookie(&client_hello_with_cookie);
    assert!(result1.is_ok());
    
    // Replay attempt (same client_random)
    let result2 = server.process_client_hello_with_cookie(&client_hello_with_cookie);
    assert!(result2.is_err());
    assert_eq!(result2.unwrap_err(), B4aeError::ReplayDetected);
}
```

### 1.3 Global Traffic Scheduler Tests

**Test Scenarios:**

#### Test 1.3.1: Constant-Rate Output
```rust
#[tokio::test]
async fn test_constant_rate_output() {
    let scheduler = GlobalTrafficScheduler::new(100.0);  // 100 msg/s
    
    // Enqueue 1000 messages rapidly
    for i in 0..1000 {
        scheduler.enqueue(Message::new(format!("msg{}", i))).await;
    }
    
    // Measure output rate
    let start = Instant::now();
    let mut count = 0;
    while count < 1000 {
        let _ = scheduler.dequeue().await;
        count += 1;
    }
    let duration = start.elapsed();
    
    // Should take ~10 seconds (1000 msg / 100 msg/s)
    assert!(duration >= Duration::from_secs(9));
    assert!(duration <= Duration::from_secs(11));
}
```

#### Test 1.3.2: Cross-Session Indistinguishability
```rust
#[tokio::test]
async fn test_cross_session_indistinguishability() {
    let scheduler = GlobalTrafficScheduler::new(100.0);
    
    // Create 10 sessions with different message patterns
    let mut sessions = vec![];
    for i in 0..10 {
        let session = Session::new(format!("session{}", i));
        sessions.push(session);
    }
    
    // Session 0: burst of 100 messages
    for _ in 0..100 {
        scheduler.enqueue_from_session(&sessions[0], Message::new("burst")).await;
    }
    
    // Session 1: 1 message per second
    for _ in 0..10 {
        scheduler.enqueue_from_session(&sessions[1], Message::new("slow")).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    
    // Measure output timing
    let mut output_times = vec![];
    for _ in 0..110 {
        let start = Instant::now();
        let _ = scheduler.dequeue().await;
        output_times.push(start.elapsed());
    }
    
    // Output should be constant-rate (not bursty)
    let avg_interval = output_times.iter().sum::<Duration>() / output_times.len() as u32;
    let expected_interval = Duration::from_millis(10);  // 100 msg/s = 10ms interval
    
    assert!((avg_interval.as_millis() as i64 - expected_interval.as_millis() as i64).abs() < 2);
}
```

#### Test 1.3.3: Dummy Message Generation
```rust
#[tokio::test]
async fn test_dummy_message_generation() {
    let scheduler = GlobalTrafficScheduler::new(100.0);
    scheduler.set_cover_traffic_budget(0.20);  // 20% dummy traffic
    
    // Enqueue 80 real messages
    for i in 0..80 {
        scheduler.enqueue(Message::new(format!("real{}", i))).await;
    }
    
    // Dequeue 100 messages (should include ~20 dummy messages)
    let mut real_count = 0;
    let mut dummy_count = 0;
    for _ in 0..100 {
        let msg = scheduler.dequeue().await;
        if msg.is_dummy() {
            dummy_count += 1;
        } else {
            real_count += 1;
        }
    }
    
    // Verify dummy traffic percentage
    assert_eq!(real_count, 80);
    assert!(dummy_count >= 18 && dummy_count <= 22);  // ~20% ± 2%
}
```

#### Test 1.3.4: Latency Measurement
```rust
#[tokio::test]
async fn test_scheduler_latency() {
    let scheduler = GlobalTrafficScheduler::new(100.0);  // 100 msg/s
    
    // Enqueue messages and measure latency
    let mut latencies = vec![];
    for i in 0..100 {
        let enqueue_time = Instant::now();
        scheduler.enqueue(Message::new(format!("msg{}", i))).await;
        
        // Dequeue in background
        let dequeue_time = scheduler.dequeue().await;
        let latency = dequeue_time.duration_since(enqueue_time);
        latencies.push(latency);
    }
    
    // Average latency should be ~5ms (for 100 msg/s)
    let avg_latency = latencies.iter().sum::<Duration>() / latencies.len() as u32;
    assert!(avg_latency >= Duration::from_millis(3));
    assert!(avg_latency <= Duration::from_millis(7));
}
```

### 1.4 Session Binding Tests

**Test Scenarios:**

#### Test 1.4.1: Session ID Derivation
```rust
#[test]
fn test_session_id_derivation() {
    let client_random = [1u8; 32];
    let server_random = [2u8; 32];
    let mode_id = AuthenticationMode::ModeA.to_id();
    
    // Derive session ID
    let session_id = derive_session_id(&client_random, &server_random, mode_id);
    
    // Verify uniqueness (different randoms = different session_id)
    let different_client_random = [3u8; 32];
    let different_session_id = derive_session_id(&different_client_random, &server_random, mode_id);
    
    assert_ne!(session_id, different_session_id);
}
```

#### Test 1.4.2: Key Transplant Prevention
```rust
#[test]
fn test_key_transplant_prevention() {
    // Session A
    let session_a = create_session(
        client_random_a: [1u8; 32],
        server_random_a: [2u8; 32],
        mode: AuthenticationMode::ModeA,
    );
    
    // Session B
    let session_b = create_session(
        client_random_b: [3u8; 32],
        server_random_b: [4u8; 32],
        mode: AuthenticationMode::ModeA,
    );
    
    // Try to use Session A key in Session B
    let message = b"test message";
    let encrypted_a = session_a.encrypt(message).unwrap();
    
    // Decryption should fail (key bound to session_id)
    let result = session_b.decrypt(&encrypted_a);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), B4aeError::DecryptionFailed);
}
```

#### Test 1.4.3: Protocol ID Binding
```rust
#[test]
fn test_protocol_id_binding() {
    let protocol_id_v2 = compute_protocol_id("v2.0 spec");
    let protocol_id_v1 = compute_protocol_id("v1.0 spec");
    
    // Different protocol IDs
    assert_ne!(protocol_id_v2, protocol_id_v1);
    
    // Keys derived with different protocol IDs are different
    let key_v2 = derive_key_with_protocol_id(&master_secret, &protocol_id_v2);
    let key_v1 = derive_key_with_protocol_id(&master_secret, &protocol_id_v1);
    
    assert_ne!(key_v2, key_v1);
}
```

#### Test 1.4.4: Transcript Binding
```rust
#[test]
fn test_transcript_binding() {
    let handshake_transcript = compute_transcript(&init, &response, &complete);
    
    // Derive keys with transcript binding
    let root_key = derive_root_key(&master_secret, &session_id, &handshake_transcript);
    
    // Modified transcript = different key
    let mut modified_transcript = handshake_transcript.clone();
    modified_transcript[0] ^= 0xFF;
    let different_root_key = derive_root_key(&master_secret, &session_id, &modified_transcript);
    
    assert_ne!(root_key, different_root_key);
}
```

### 1.5 Downgrade Protection Tests

**Test Scenarios:**

#### Test 1.5.1: Mode Binding Verification
```rust
#[tokio::test]
async fn test_mode_binding_verification() {
    let mut client = B4aeClient::new(AuthenticationMode::ModeB);
    let mut server = B4aeServer::new(AuthenticationMode::ModeB);
    
    // Attacker intercepts and modifies mode
    let mut attacker = MitmAttacker::new();
    attacker.modify_negotiated_mode(AuthenticationMode::ModeA);
    
    // Handshake should fail (mode_id in session_id doesn't match)
    let result = client.connect_through(&attacker, &server).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), B4aeError::ModeBindingFailed);
}
```

#### Test 1.5.2: Protocol Version Enforcement
```rust
#[tokio::test]
async fn test_protocol_version_enforcement() {
    let mut client_v2 = B4aeClient::new_v2();
    let mut server_v1 = B4aeServer::new_v1();
    
    // Handshake should fail (protocol version mismatch)
    let result = client_v2.connect(&server_v1).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), B4aeError::ProtocolVersionMismatch);
}
```

---

## Fase 2: ELARA End-to-End (1–2 minggu)

### 2.1 In-Process Two-Node Test
- [x] Spawn dua `B4aeElaraNode` dalam satu process
- [x] Initiator connect → Responder accept
- [x] Round-trip: send_message → recv_message
- [x] Verifikasi plaintext cocok
- [x] Timeout handling (peer tidak respond)
- [x] Concurrent: multiple handshakes parallel
- [x] **v2.0:** Mode A/B handshakes
- [x] **v2.0:** Cookie challenge flow

### 2.2 Chunking (Payload Besar)
- [x] Payload > 1400 bytes (chunk boundary)
- [x] Payload ~10 KB, ~100 KB
- [x] Verifikasi reassembly integrity
- [x] Drop/reorder simulation (jika ELARA support)
- [x] **v2.0:** Global scheduler dengan large payloads

### 2.3 Multi-Peer
- [x] Node A connect ke B dan C
- [x] Message routing by peer address
- [x] Session isolation (A-B vs A-C)
- [x] **v2.0:** Cross-session scheduler indistinguishability

---

## Fase 3: Cross-Process (2–3 minggu)

### 3.1 TCP Localhost (Tanpa ELARA)
- [ ] Client/Server over TCP (quinn atau std net)
- [ ] Full B4AE handshake + messaging
- [ ] Baseline untuk comparison
- [ ] **v2.0:** Mode A/B comparison

### 3.2 UDP + ELARA (Localhost)
- [ ] Dua binary terpisah: initiator, responder
- [ ] UDP localhost (127.0.0.1)
- [ ] Script atau Makefile untuk menjalankan
- [ ] Exit code, logging untuk CI
- [ ] **v2.0:** Cookie challenge under network stress

### 3.3 CI Integration
- [ ] GitHub Actions: `cargo test --all-features`
- [ ] Optional: matrix (Linux, macOS, Windows)
- [ ] Timeout 5–10 menit untuk integration tests
- [ ] Separate job untuk ELARA E2E (allow fail awalnya)
- [ ] **v2.0:** Mode A/B test matrix

---

## Fase 4: Reliability & Chaos (1–2 bulan)

### 4.1 Failure Injection
- [ ] Drop random packets (proxy/mock transport)
- [ ] Delay injection
- [ ] Duplicate packet
- [ ] Corrupt byte (integrity failure path)
- [ ] **v2.0:** Cookie challenge under packet loss
- [ ] **v2.0:** Global scheduler under network chaos

### 4.2 Stress & Load
- [ ] 100+ concurrent sessions per node
- [ ] Sustained throughput 1000 msg/s
- [ ] Memory leak check (valgrind / sanitizers)
- [ ] Long-running stability (24h)
- [ ] **v2.0:** DoS attack simulation (10,000 invalid handshakes)
- [ ] **v2.0:** Global scheduler queue depth under load

### 4.3 Interop (Future)
- [ ] Version compatibility (v1 vs v2)
- [ ] Backward compatibility test matrix
- [ ] **v2.0:** Mode A/B interop

---

## Implementasi Prioritas

1. **Segera (Done)**: v2.0 core features tests (Mode A/B, cookie, scheduler, binding)
2. **Short-term**: ELARA in-process two-node test dengan v2.0 features
3. **Medium-term**: Cross-process UDP localhost, CI matrix
4. **Long-term**: Distributed multi-node, chaos engineering

---

## Contoh Test Skeleton (Rust)

```rust
#[cfg(all(feature = "v2_protocol", test))]
mod v2_integration {
    use b4ae::protocol::v2::*;
    use b4ae::elara_node::B4aeElaraNode;

    #[tokio::test]
    async fn test_mode_a_two_node_roundtrip() {
        let mut alice = B4aeElaraNode::new_v2(
            "127.0.0.1:0",
            AuthenticationMode::ModeA,
        ).await.unwrap();
        
        let mut bob = B4aeElaraNode::new_v2(
            "127.0.0.1:0",
            AuthenticationMode::ModeA,
        ).await.unwrap();
        
        let bob_addr = bob.local_addr().unwrap();

        // Bob accept di background
        let recv_handle = tokio::spawn(async move {
            bob.accept().await
        });

        // Alice connect & send (Mode A handshake)
        alice.connect(&bob_addr).await.unwrap();
        alice.send_message(&bob_addr, b"Hello from Alice").await.unwrap();

        // Bob receive
        let (from, msg) = recv_handle.await.unwrap().unwrap();
        assert_eq!(msg, b"Hello from Alice");
        
        // Verify Mode A properties
        let session = alice.get_session(&bob_addr).unwrap();
        assert_eq!(session.mode(), AuthenticationMode::ModeA);
        assert!(session.is_deniable());
    }
    
    #[tokio::test]
    async fn test_cookie_challenge_dos_protection() {
        let mut server = B4aeElaraNode::new_v2_with_cookie_challenge(
            "127.0.0.1:0",
            AuthenticationMode::ModeA,
        ).await.unwrap();
        
        // Send 1000 invalid handshake attempts
        let start = Instant::now();
        for _ in 0..1000 {
            let invalid_client = create_invalid_client();
            let _ = invalid_client.connect(&server.local_addr().unwrap()).await;
        }
        let duration = start.elapsed();
        
        // Should complete quickly (360x improvement)
        assert!(duration < Duration::from_millis(100));
        
        // Server should still accept legitimate clients
        let mut legitimate_client = B4aeElaraNode::new_v2(
            "127.0.0.1:0",
            AuthenticationMode::ModeA,
        ).await.unwrap();
        
        let result = legitimate_client.connect(&server.local_addr().unwrap()).await;
        assert!(result.is_ok());
    }
}
```

---

## Referensi

- [V2_ARCHITECTURE_OVERVIEW.md](V2_ARCHITECTURE_OVERVIEW.md) - Complete v2.0 architecture
- [V2_SECURITY_ANALYSIS.md](V2_SECURITY_ANALYSIS.md) - Security analysis
- [ELARA_INTEGRATION.md](ELARA_INTEGRATION.md) - ELARA integration
- [TESTING_GUIDE.md](../TESTING_GUIDE.md) - General testing guide
- [Criterion Benchmarks](../benches/) - Performance benchmarks

---

*Last updated: 2026*  
*Version: 2.0*
