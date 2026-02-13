# B4AE Performance Optimization

Phase 3: Performance Optimization

---

## Current Profile

Release build (`cargo build --release`) uses:

- `opt-level = 3`
- `lto = true` (Link-Time Optimization)
- `codegen-units = 1`
- `strip = true`

## Hardware Acceleration (AES-NI, SIMD)

- **AES-GCM**: `aes-gcm` crate uses AES-NI on x86_64, ARMv8 crypto extensions on aarch64
- **SHA-3**: `sha3` crate uses SIMD where available
- **Kyber/Dilithium**: pqcrypto crates use optimized implementations

### Runtime CPU Feature Detection

```rust
use b4ae::crypto::perf;

// Check capabilities
if perf::aes_ni_available() {
    println!("AES-NI: hardware accelerated");
}
if perf::avx2_available() {
    println!("AVX2: SIMD optimizations enabled");
}
perf::print_cpu_capabilities();  // full diagnostic
```

### Build Flags (optional)

For x86_64, ensure `-C target-cpu=native` if targeting a specific host:
```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```
Warning: binary may not run on older CPUs.

## Benchmarks

```bash
cargo bench
```

Results typically:
- Kyber-1024 KeyGen: < 0.15ms
- Dilithium5 Sign: < 1ms
- Hybrid KeyExchange: < 2ms
- Message Encrypt: < 0.5ms
- Handshake: < 150ms

## Tuning Tips

1. **CPU**: Enable AVX2/AVX-512 on x86 for crypto
2. **Network**: Use `elara` feature for UDP—lower latency than TCP in some scenarios
3. **Concurrency**: B4AE sessions are independent; scale with Tokio runtime
4. **Memory**: Release build uses ~50MB; session count affects heap

## CI

Performance tests run in `cargo test --test performance_test`.
