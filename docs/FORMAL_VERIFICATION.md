# B4AE Formal Verification Plan

Rencana verifikasi formal dan property-based testing untuk critical paths.

---

## Status

| Area | Status | Tool |
|------|--------|------|
| Property-based testing (proptest) | Partial | proptest |
| Handshake invariants | In progress | proptest |
| Cryptographic invariants | Planned | proptest |
| Formal specification | Future | TLA+ / Coq |

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

## 2. Formal Specification (Future)

### TLA+
- Handshake state machine
- Session establishment guarantees
- Replay prevention

### Coq / F*
- Cryptographic primitives correctness
- Protocol security proofs

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
