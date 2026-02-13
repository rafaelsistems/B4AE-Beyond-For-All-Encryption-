# B4AE Integration Testing Plan

Rencana pengujian integrasi yang lebih lengkap untuk B4AE Protocol.

## Status Saat Ini

| Area | Coverage | Status |
|------|----------|--------|
| Unit tests | crypto, protocol, metadata | ✅ |
| Integration (handshake + message) | Basic flow | ✅ |
| Security / Penetration | Replay, MITM, forgery | ✅ |
| Performance | Handshake, AES-GCM, throughput | ✅ |
| Fuzzing | Binary, handshake, malformed | ✅ |
| ELARA end-to-end | Demo only | 🚧 |
| Multi-node / Distributed | — | ❌ |
| Chaos / Failure injection | — | ❌ |

---

## Fase 1: ELARA End-to-End (1–2 minggu)

### 1.1 In-Process Two-Node Test
- [ ] Spawn dua `B4aeElaraNode` dalam satu process
- [ ] Initiator connect → Responder accept
- [ ] Round-trip: send_message → recv_message
- [ ] Verifikasi plaintext cocok
- [ ] Timeout handling (peer tidak respond)
- [ ] Concurrent: multiple handshakes parallel

### 1.2 Chunking (Payload Besar)
- [ ] Payload > 1400 bytes (chunk boundary)
- [ ] Payload ~10 KB, ~100 KB
- [ ] Verifikasi reassembly integrity
- [ ] Drop/reorder simulation (jika ELARA support)

### 1.3 Multi-Peer
- [ ] Node A connect ke B dan C
- [ ] Message routing by peer address
- [ ] Session isolation (A-B vs A-C)

---

## Fase 2: Cross-Process (2–3 minggu)

### 2.1 TCP Localhost (Tanpa ELARA)
- [ ] Client/Server over TCP (quinn atau std net)
- [ ] Full B4AE handshake + messaging
- [ ] Baseline untuk comparison

### 2.2 UDP + ELARA (Localhost)
- [ ] Dua binary terpisah: initiator, responder
- [ ] UDP localhost (127.0.0.1)
- [ ] Script atau Makefile untuk menjalankan
- [ ] Exit code, logging untuk CI

### 2.3 CI Integration
- [ ] GitHub Actions: `cargo test --all-features`
- [ ] Optional: matrix (Linux, macOS, Windows)
- [ ] Timeout 5–10 menit untuk integration tests
- [ ] Separate job untuk ELARA E2E (allow fail awalnya)

---

## Fase 3: Reliability & Chaos (1–2 bulan)

### 3.1 Failure Injection
- [ ] Drop random packets (proxy/mock transport)
- [ ] Delay injection
- [ ] Duplicate packet
- [ ] Corrupt byte (integrity failure path)

### 3.2 Stress & Load
- [ ] 100+ concurrent sessions per node
- [ ] Sustained throughput 1000 msg/s
- [ ] Memory leak check (valgrind / sanitizers)
- [ ] Long-running stability (24h)

### 3.3 Interop (Future)
- [ ] Version compatibility (v1 vs v2)
- [ ] Backward compatibility test matrix

---

## Implementasi Prioritas

1. **Segera**: ELARA in-process two-node test (tanpa network)
2. **Short-term**: Cross-process UDP localhost
3. **Medium-term**: CI matrix, failure injection
4. **Long-term**: Distributed multi-node, chaos engineering

---

## Contoh Test Skeleton (Rust)

```rust
#[cfg(all(feature = "elara", test))]
mod elara_e2e {
    use b4ae::elara_node::B4aeElaraNode;
    use b4ae::protocol::SecurityProfile;

    #[tokio::test]
    async fn test_two_node_roundtrip() {
        let mut alice = B4aeElaraNode::new("127.0.0.1:0", SecurityProfile::Standard).await.unwrap();
        let mut bob = B4aeElaraNode::new("127.0.0.1:0", SecurityProfile::Standard).await.unwrap();
        let bob_addr = bob.local_addr().unwrap();

        // Bob accept di background
        let recv_handle = tokio::spawn(async move {
            bob.accept().await
        });

        // Alice connect & send
        alice.connect(&bob_addr).await.unwrap();
        alice.send_message(&bob_addr, b"Hello from Alice").await.unwrap();

        // Bob receive
        let (from, msg) = recv_handle.await.unwrap().unwrap();
        assert_eq!(msg, b"Hello from Alice");
    }
}
```

---

## Referensi

- [ELARA Integration](ELARA_INTEGRATION.md)
- [Testing Guide](../TESTING_GUIDE.md)
- [Criterion Benchmarks](../benches/)
