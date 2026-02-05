# B4AE Compilation Errors - Status dan Solusi

**Tanggal:** 4 Februari 2026  
**Status:** 🔴 33 Compilation Errors

---

## RINGKASAN

File `src/protocol/handshake.rs` berhasil dibuat (461 baris) tetapi ada 33 compilation errors yang perlu diperbaiki.

---

## KATEGORI ERROR

### 1. Serialization Issues (10 errors)
**Problem:** `HybridPublicKey`, `HybridCiphertext`, `HybridSignature` tidak implement `Serialize`/`Deserialize`

**Solusi:**
- Tambahkan `#[derive(Serialize, Deserialize)]` ke struct di `src/crypto/hybrid.rs`
- ATAU gunakan method `to_bytes()` dan `from_bytes()` yang sudah ada

**Files affected:**
- `src/crypto/hybrid.rs` - perlu tambah derives
- `src/protocol/handshake.rs` - gunakan to_bytes/from_bytes

### 2. API Mismatch - B4aeKeyDerivation (12 errors)
**Problem:** `B4aeKeyDerivation::new()` hanya menerima 1 parameter, bukan 2

**Current API:**
```rust
pub fn new(master_secret: Vec<u8>) -> Self
pub fn derive_all_keys(&self) -> CryptoResult<ProtocolKeys>
```

**Expected API:**
```rust
pub fn new(master_secret: &[u8], info: &[u8]) -> Self
pub fn derive_key(&self, length: usize) -> CryptoResult<Vec<u8>>
```

**Solusi:**
- Ubah API `B4aeKeyDerivation` di `src/crypto/hkdf.rs`
- ATAU buat wrapper function baru untuk handshake

### 3. Function Signature Mismatch (5 errors)
**Problem:** Fungsi hybrid memiliki signature berbeda

**Issues:**
- `hybrid::sign()` expects `&HybridSecretKey`, not `&HybridKeyPair`
- `hybrid::decapsulate()` expects `&HybridSecretKey`, not `&HybridKeyPair`
- `hybrid::encapsulate()` hanya menerima 1 parameter (public_key), tidak ada shared_secret

**Solusi:**
- Gunakan `&keypair.secret_key` instead of `&keypair`
- Perbaiki logic encapsulate - generate shared secret di dalam fungsi

### 4. Type Mismatches (6 errors)
**Problem:** Type conversion issues

**Issues:**
- `shared_secret` adalah `&Vec<u8>` tapi expected `Vec<u8>`
- `data` adalah `&Vec<u8>` tapi expected `Vec<u8>`

**Solusi:**
- Gunakan `.clone()` atau `.to_vec()` untuk convert

---

## PRIORITAS PERBAIKAN

### Priority 1: Fix Hybrid Crypto API Usage
1. Gunakan `&keypair.secret_key` untuk sign dan decapsulate
2. Fix encapsulate logic - tidak perlu pass shared_secret

### Priority 2: Fix Serialization
Opsi A (Recommended): Gunakan to_bytes/from_bytes
```rust
// Instead of:
let bytes = bincode::serialize(&public_key)?;

// Use:
let bytes = public_key.to_bytes();
```

Opsi B: Add Serialize/Deserialize derives
```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridPublicKey { ... }
```

### Priority 3: Fix HKDF API
Opsi A: Modify B4aeKeyDerivation
```rust
impl B4aeKeyDerivation {
    pub fn new_with_info(master_secret: &[u8], info: &[u8]) -> Self { ... }
    pub fn derive_key(&self, length: usize) -> CryptoResult<Vec<u8>> { ... }
}
```

Opsi B: Create helper function
```rust
fn derive_handshake_key(secret: &[u8], info: &[u8], len: usize) -> CryptoResult<Vec<u8>> {
    // Use HKDF directly
}
```

---

## LANGKAH SELANJUTNYA

1. **Periksa API yang ada** - Baca file hybrid.rs dan hkdf.rs untuk memahami API sebenarnya
2. **Pilih strategi** - Tentukan apakah akan modify API atau adapt handshake code
3. **Fix errors bertahap** - Mulai dari Priority 1
4. **Test compile** - Compile setelah setiap fix
5. **Run tests** - Setelah compile sukses, run test suite

---

## FILES YANG PERLU DIMODIFIKASI

1. `src/protocol/handshake.rs` - Fix API usage (UTAMA)
2. `src/crypto/hybrid.rs` - Add serialization (OPTIONAL)
3. `src/crypto/hkdf.rs` - Extend API (OPTIONAL)

---

## ESTIMASI WAKTU

- Fix API usage: 30-45 menit
- Fix serialization: 15-30 menit
- Fix HKDF: 15-30 menit
- Testing: 15-30 menit

**Total:** 1.5 - 2.5 jam

---

**Status:** Ready untuk perbaikan
**Next Action:** Periksa API hybrid.rs dan hkdf.rs, lalu fix handshake.rs
