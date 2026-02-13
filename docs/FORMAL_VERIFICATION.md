# B4AE Formal Verification Plan

Rencana verifikasi formal dan property-based testing untuk critical paths.

---

## Status

| Area | Status | Tool |
|------|--------|------|
| Property-based testing (proptest) | Done | proptest |
| Handshake invariants | Done | proptest |
| Cryptographic invariants | Partial | proptest |
| TLA+ model checking | Done | TLC |
| **Coq formal spec** | **Done** | **Coq 8.20** |

---

## 1. Proptest Invariants (Implementasi Sekarang)

### Handshake Invariants
- **Completeness**: Jika init → response → complete valid, kedua pihak punya session keys yang sama
- **No regression**: Handshake output deterministic untuk input yang sama
- **State machine**: Invalid transitions must fail

### Crypto Invariants
- **Encrypt/Decrypt roundtrip**: `decrypt(encrypt(m)) == m`
- **Key uniqueness**: Different keys → different ciphertext
- **Nonce uniqueness**: Same key + different nonce → different ciphertext

### Property Tests Location
- `tests/proptest_invariants.rs` (new)

---

## 2. Formal Specification

### TLA+ (specs/B4AE_Handshake.tla)
- Handshake state machine model
- TLC model checking in CI

### Coq (specs/coq/B4AE_Handshake.v)
- Formal model of handshake state machine
- **safety_theorem**: Reachable states satisfy SafetyInvariant
- Both Completed only after valid handshake sequence

---

## 3. Fuzzing

- **libFuzzer**: `cargo fuzz` untuk message parsing, handshake
- **OSS-Fuzz**: Integration ke Google OSS-Fuzz (optional)
- Existing: `tests/fuzzing_test.rs` (unit-style fuzz targets)

---

## Referensi

- [proptest](https://altsysrq.github.io/proptest-book/)
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
- [TLA+](https://lamport.azurewebsites.net/tla/tla.html)
