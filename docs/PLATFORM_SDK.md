# B4AE Platform SDK Implementation Guide

Panduan implementasi B4AE SDK untuk iOS, Android, dan Web.

---

## Status: Perencanaan

| Platform | Status | Prioritas |
|----------|--------|-----------|
| **Web (WASM)** | Planning | P1 |
| **Android** | Planning | P2 |
| **iOS** | Planning | P2 |

---

## 1. WebAssembly (Web)

### Kendala
- `ring` crate: dukungan wasm terbatas (experimental)
- `pqcrypto-*`: mungkin perlu wasm-compatible fork
- `std::net`, tokio: tidak available di wasm

### Pendekatan
1. **Option A**: Crate terpisah `b4ae-wasm` dengan subset API
   - Gunakan `getrandom` dengan `wasm-bindgen` untuk RNG
   - Ganti ring dengan pure-Rust crypto (aes-gcm, sha3 sudah wasm-compat)
   - pqcrypto: cek wasm support

2. **Option B**: Conditional compilation di crate utama
   ```toml
   [target.'cfg(target_arch = "wasm32")'.dependencies]
   getrandom = { version = "0.2", features = ["js"] }
   wasm-bindgen = "0.2"
   ```

### Langkah Implementasi
- [ ] `rustup target add wasm32-unknown-unknown`
- [ ] Feature `wasm` di Cargo.toml
- [ ] `#[cfg(target_arch = "wasm32")]` untuk platform-specific code
- [ ] wasm-bindgen exports untuk B4aeClient (handshake, encrypt, decrypt)
- [ ] wasm-pack build script
- [ ] Contoh HTML/JS consuming the wasm module

### Struktur
```
b4ae/
  src/
    lib.rs
    wasm/           # #[cfg(target_arch = "wasm32")]
      mod.rs
      client.rs
```

---

## 2. Android

### Stack
- **JNI** via `jni` crate
- **Kotlin/Java** binding layer
- **AAR** output untuk integrasi ke project Android

### Langkah
- [ ] crate `b4ae-ffi` atau mod `ffi` di b4ae
- [ ] `#[no_mangle]` extern functions untuk JNI
- [ ] Build script: `cargo ndk` atau manual NDK
- [ ] Kotlin wrapper class `B4aeClient`
- [ ] Example app (minimal)

### Dependencies
```toml
[target.'cfg(target_os = "android")'.dependencies]
jni = "0.21"
```

---

## 3. iOS

### Stack
- **Objective-C** atau **Swift** via `cbindgen`
- **XCFramework** output
- **UniFFI** (alternatif) untuk Swift-first API

### Langkah
- [ ] `cbindgen` untuk generate C header
- [ ] Build script: `cargo lipo` untuk universal (arm64 + x86_64)
- [ ] XCFramework packaging
- [ ] Swift Package Manager atau CocoaPods
- [ ] Example app

### Targets
```bash
cargo build --target aarch64-apple-ios --release
cargo build --target x86_64-apple-ios --release  # simulator
```

---

## Referensi

- [wasm-bindgen](https://rustwasm.github.io/wasm-bindgen/)
- [rust-android](https://github.com/rust-android)
- [cbindgen](https://github.com/eqrion/cbindgen)
- [UniFFI](https://mozilla.github.io/uniffi-rs/)
