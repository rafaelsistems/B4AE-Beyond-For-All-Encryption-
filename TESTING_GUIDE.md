# B4AE Testing Guide

Panduan lengkap untuk menjalankan dan menginterpretasikan test suite B4AE.

---

## Prerequisites

### Install Rust dan Cargo

**Windows:**
```powershell
# Download dan install rustup
# Kunjungi: https://rustup.rs/
# Atau gunakan:
winget install Rustlang.Rustup
```

**Verifikasi instalasi:**
```powershell
cargo --version
rustc --version
```

---

## Test Suite Overview

B4AE memiliki 5 kategori test suite:

1. **Security Tests** (`tests/security_test.rs`) - 9 tests
2. **Performance Tests** (`tests/performance_test.rs`) - 13 tests
3. **Integration Tests** (`tests/integration_test.rs`) - 4 tests
4. **Fuzzing Tests** (`tests/fuzzing_test.rs`) - 11 tests
5. **Penetration Tests** (`tests/penetration_test.rs`) - 8 tests

**Total: 45 tests**

---

## Running Tests

### 1. Build Project

```powershell
# Build dengan semua features
cargo build --all-features

# Build release version
cargo build --all-features --release
```

### 2. Run All Tests

```powershell
# Run semua tests
cargo test --all-features

# Run dengan output detail
cargo test --all-features -- --nocapture

# Run dengan thread tunggal (untuk debugging)
cargo test --all-features -- --test-threads=1
```

### 3. Run Specific Test Suite

```powershell
# Security tests
cargo test --test security_test

# Performance tests
cargo test --test performance_test

# Integration tests
cargo test --test integration_test

# Fuzzing tests
cargo test --test fuzzing_test

# Penetration tests
cargo test --test penetration_test
```

### 4. Run Specific Test

```powershell
# Run single test by name
cargo test test_replay_attack_prevention

# Run tests matching pattern
cargo test replay

# Run with verbose output
cargo test test_replay_attack_prevention -- --nocapture
```

### 5. Run Ignored Tests

```powershell
# Run tests yang di-ignore (seperti scalability tests)
cargo test -- --ignored

# Run semua tests termasuk yang di-ignore
cargo test -- --include-ignored
```

---

## Benchmarking

### 1. Run Benchmarks

```powershell
# Run semua benchmarks
cargo bench

# Run crypto benchmarks
cargo bench --bench crypto_bench

# Run protocol benchmarks
cargo bench --bench protocol_bench

# Run specific benchmark
cargo bench kyber_keygen
```

### 2. Benchmark Output

Hasil benchmark disimpan di:
- `target/criterion/` - HTML reports
- `target/criterion/*/report/index.html` - Detailed reports

### 3. Compare Benchmarks

```powershell
# Baseline benchmark
cargo bench -- --save-baseline baseline

# Run dan compare dengan baseline
cargo bench -- --baseline baseline
```

---

## Test Categories

### Security Tests

**Tujuan:** Validasi keamanan cryptographic dan protocol

**Tests:**
- `test_replay_attack_prevention` - Replay attack detection
- `test_forward_secrecy` - Perfect forward secrecy
- `test_zero_knowledge_authentication` - ZK-auth
- `test_invalid_signature_rejection` - Signature validation
- `test_key_rotation` - Automatic key rotation
- `test_message_expiration` - Message expiration
- `test_quantum_resistant_key_exchange` - PQC validation
- `test_hybrid_cryptography_fallback` - Hybrid crypto
- `test_memory_zeroization` - Secure memory cleanup

**Expected Results:**
- ✅ All tests should pass
- ⚠️ Timing tests may vary based on hardware

### Performance Tests

**Tujuan:** Validasi performance targets

**Tests:**
- `test_kyber_keygen_performance` - Target: <150µs
- `test_dilithium_sign_performance` - Target: <1000µs
- `test_dilithium_verify_performance` - Target: <400µs
- `test_aes_gcm_performance` - Target: <10µs per KB
- `test_handshake_performance` - Target: <200ms
- `test_message_throughput` - Target: >1000 msg/sec
- `test_end_to_end_latency` - Target: <1ms
- `test_hkdf_performance` - Target: <100µs
- `test_network_bandwidth_overhead` - Target: <20%
- `test_horizontal_scaling` - 10 servers, 100 users each
- `test_sustained_load` - 100 msg/sec for 10 seconds

**Expected Results:**
- ✅ All performance targets should be met
- ⚠️ Results vary based on hardware
- ⚠️ Some tests may be slower on debug builds

**Ignored Tests:**
- `test_scalability_10k_users` - Requires significant resources

### Integration Tests

**Tujuan:** End-to-end protocol validation

**Tests:**
- `test_complete_handshake_flow` - Full handshake
- `test_end_to_end_message_flow` - Message encryption/decryption
- `test_multiple_message_exchange` - Multiple messages
- `test_session_statistics` - Session tracking

**Expected Results:**
- ✅ All tests should pass
- ✅ Session IDs should match
- ✅ Messages should decrypt correctly

### Fuzzing Tests

**Tujuan:** Robustness testing

**Tests:**
- `test_malformed_handshake_init` - Corrupted handshake
- `test_random_data_handling` - Random input handling
- `test_oversized_message` - Large message handling
- `test_empty_message` - Empty message handling
- `test_rapid_handshake_attempts` - DoS resistance
- `test_concurrent_sessions` - Multiple sessions
- `test_invalid_protocol_version` - Version validation
- `test_message_with_special_characters` - Unicode handling
- `test_binary_data_integrity` - Binary data handling
- `test_handshake_timeout` - Timeout handling
- `test_repeated_handshake_complete` - State validation

**Expected Results:**
- ✅ All tests should pass
- ✅ No panics or crashes
- ✅ Graceful error handling

### Penetration Tests

**Tujuan:** Security attack simulation

**Tests:**
- `test_mitm_attack_detection` - MITM detection
- `test_dos_resistance` - DoS resistance
- `test_key_recovery_resistance` - Key recovery attacks
- `test_timing_attack_resistance` - Timing attacks
- `test_handshake_manipulation` - Protocol manipulation
- `test_state_confusion` - State machine attacks
- `test_input_validation_bypass` - Input validation

**Expected Results:**
- ✅ All attacks should be detected/prevented
- ✅ Timing differences should be <10%
- ✅ Invalid inputs should be rejected

---

## Performance Targets

### Cryptographic Operations

| Operation | Target | Measurement |
|-----------|--------|-------------|
| Kyber KeyGen | <150µs | Average over 100 iterations |
| Dilithium Sign | <1000µs | Average over 100 iterations |
| Dilithium Verify | <400µs | Average over 100 iterations |
| AES-GCM Encrypt | <10µs/KB | Average over 1000 iterations |
| HKDF Derive | <100µs | Average over 1000 iterations |

### Protocol Operations

| Operation | Target | Measurement |
|-----------|--------|-------------|
| Complete Handshake | <200ms | Average over 10 iterations |
| Message Throughput | >1000 msg/sec | 1000 messages |
| End-to-End Latency | <1ms | Average over 100 messages |
| Bandwidth Overhead | <20% | Message size comparison |

### Scalability

| Metric | Target | Test |
|--------|--------|------|
| Concurrent Users | 10,000+ | Per server |
| Horizontal Scaling | Linear | Up to 100 servers |
| Sustained Load | 100 msg/sec | 10 seconds |
| Long-term Stability | 24 hours | Stress test (manual) |

---

## Troubleshooting

### Compilation Errors

```powershell
# Update dependencies
cargo update

# Clean and rebuild
cargo clean
cargo build --all-features

# Check for errors
cargo check --all-features
```

### Test Failures

```powershell
# Run with backtrace
$env:RUST_BACKTRACE=1
cargo test --test security_test

# Run with full backtrace
$env:RUST_BACKTRACE="full"
cargo test --test security_test

# Run single failing test
cargo test test_name -- --nocapture
```

### Performance Issues

```powershell
# Build in release mode
cargo build --all-features --release

# Run tests in release mode
cargo test --all-features --release

# Run benchmarks (always release mode)
cargo bench
```

### Missing Dependencies

```powershell
# Install required tools
cargo install cargo-audit
cargo install cargo-flamegraph
cargo install cargo-criterion

# Check for security vulnerabilities
cargo audit

# Generate flamegraph
cargo flamegraph --bench crypto_bench
```

---

## Continuous Integration

### GitLab CI

File `.gitlab-ci.yml` sudah dikonfigurasi untuk:
- Build verification
- Test execution
- Benchmark running
- Security auditing

### Manual CI Steps

```powershell
# Run CI pipeline locally
cargo build --all-features
cargo test --all-features
cargo bench --no-run
cargo audit
```

---

## Advanced Testing

### Code Coverage

```powershell
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --all-features --out Html

# View report
start target/tarpaulin/index.html
```

### Memory Profiling

```powershell
# Install valgrind (Linux only)
# Run with valgrind
valgrind --leak-check=full cargo test

# Windows alternative: use Windows Performance Analyzer
```

### Fuzzing with AFL

```powershell
# Install cargo-afl
cargo install cargo-afl

# Build with AFL
cargo afl build --all-features

# Run AFL fuzzer
cargo afl fuzz -i fuzz_input -o fuzz_output target/debug/b4ae-cli
```

---

## Test Maintenance

### Adding New Tests

1. Create test function in appropriate file
2. Add `#[test]` attribute
3. Use descriptive name: `test_<feature>_<scenario>`
4. Add documentation comment
5. Run test: `cargo test test_name`

### Updating Benchmarks

1. Modify benchmark in `benches/` directory
2. Run benchmark: `cargo bench`
3. Compare with baseline
4. Update documentation if targets change

### Test Best Practices

- ✅ Use descriptive test names
- ✅ Test one thing per test
- ✅ Use assertions with messages
- ✅ Clean up resources
- ✅ Document expected behavior
- ❌ Don't use `unwrap()` without reason
- ❌ Don't ignore test failures
- ❌ Don't skip error handling

---

## Reporting Issues

Jika menemukan test failure:

1. **Capture output:**
   ```powershell
   cargo test test_name -- --nocapture > test_output.txt 2>&1
   ```

2. **Include information:**
   - Rust version: `rustc --version`
   - Cargo version: `cargo --version`
   - OS version
   - Test output
   - Steps to reproduce

3. **Create issue** dengan template:
   ```
   **Test Name:** test_xyz
   **Expected:** Should pass
   **Actual:** Failed with error XYZ
   **Environment:** Windows 11, Rust 1.75
   **Output:** [paste output]
   ```

---

## Next Steps

Setelah semua tests pass:

1. ✅ Review test coverage
2. ✅ Add missing tests
3. ✅ Run benchmarks
4. ✅ Optimize bottlenecks
5. ✅ Document results
6. ✅ Prepare for production

---

**Last Updated:** 4 Februari 2026  
**Version:** 1.0
