# B4AE Platform SDK

Bindings B4AE untuk iOS, Android, dan Web. Subset API AES-256-GCM (generateKey, encrypt, decrypt).

---

## Status

| Platform | Status | Lokasi |
|----------|--------|--------|
| **Web (WASM)** | ✅ Implemented | `b4ae-wasm/`, `wasm-demo/` |
| **Android** | ✅ Implemented | `b4ae-android/`, `bindings/kotlin/` |
| **iOS** | ✅ Implemented | `b4ae-ffi/`, `bindings/swift/` |
| **C FFI** | ✅ Implemented | `b4ae-ffi/`, `bindings/b4ae.h` |

---

## 1. WebAssembly (Web)

**Crate:** `b4ae-wasm`

### Build
```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
wasm-pack build b4ae-wasm --target web --out-dir pkg
```

### Demo
```bash
# Build wasm-demo
wasm-pack build b4ae-wasm --target web --out-dir wasm-demo/pkg
# Serve wasm-demo/ via HTTP (e.g. python -m http.server 8080)
```

### JavaScript API
```javascript
import { generate_key, encrypt, decrypt } from './pkg/b4ae_wasm.js';

const key = new Uint8Array(generate_key());
const enc = encrypt(key, new TextEncoder().encode('Hello'));
const dec = decrypt(key, enc);
```

---

## 2. Android (Kotlin)

**Crate:** `b4ae-android` (JNI)

### Build
```bash
cd b4ae-android
cargo build --release --target aarch64-linux-android   # ARM64
cargo build --release --target i686-linux-android      # x86
cargo build --release --target x86_64-linux-android   # x86_64
```

Copy `libb4ae_android.so` ke `android/app/src/main/jniLibs/<abi>/`

### Kotlin Usage
```kotlin
val key = B4AE.generateKey()
val encrypted = B4AE.encrypt(key, "Hello".toByteArray())
val decrypted = B4AE.decrypt(key, encrypted)
```

---

## 3. iOS (Swift)

**Crate:** `b4ae-ffi` (C ABI static lib)

### Build
```bash
cd b4ae-ffi
cargo build --release --target aarch64-apple-ios
cargo build --release --target x86_64-apple-ios   # simulator
# Use lipo for universal binary
```

### Swift Usage
```swift
let key = B4AE.generateKey()
let encrypted = try B4AE.encrypt(key: key, plaintext: Data("Hello".utf8))
let decrypted = try B4AE.decrypt(key: key, encrypted: encrypted)
```

Lihat `bindings/swift/` untuk Swift Package structure.

---

## 4. C FFI

**Header:** `bindings/b4ae.h`

```c
uint8_t* b4ae_generate_key(size_t* out_len);
uint8_t* b4ae_encrypt(const uint8_t* key, size_t key_len,
    const uint8_t* plaintext, size_t plaintext_len, size_t* out_len);
uint8_t* b4ae_decrypt(const uint8_t* key, size_t key_len,
    const uint8_t* encrypted, size_t encrypted_len, size_t* out_len);
void b4ae_free(uint8_t* ptr);
```

---

## Referensi

- [bindings/README.md](../bindings/README.md)
- [wasm-bindgen](https://rustwasm.github.io/wasm-bindgen/)
- [jni-rs](https://github.com/jni-rs/jni-rs)
- [cbindgen](https://github.com/eqrion/cbindgen)
