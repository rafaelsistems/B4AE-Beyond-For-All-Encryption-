# B4AE Platform SDK

Bindings B4AE untuk iOS, Android, dan Web. Subset API AES-256-GCM (generateKey, encrypt, decrypt).

---

## Status

| Platform | Status | Lokasi |
|----------|--------|--------|
| **Web (WASM)** | ✅ 100% | `b4ae-wasm/`, `wasm-demo/` |
| **Android** | ✅ 100% | `b4ae-android/`, `b4ae-android-app/` |
| **iOS** | ✅ 100% | `b4ae-ffi/`, `bindings/swift/` |
| **C FFI** | ✅ Implemented | `b4ae-ffi/`, `bindings/b4ae.h` |

### Build Scripts (repo root)
- `scripts/build_ios.sh` / `build_ios.ps1` — C FFI for Swift Package
- `scripts/build_android.sh` / `build_android.ps1` — JNI .so → b4ae-android-app
- `scripts/build_wasm.ps1` — WASM → wasm-demo/pkg

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
# Option 1: Build script
./scripts/build_wasm.ps1   # or build.sh from wasm-demo/
# Option 2: wasm-pack directly
wasm-pack build b4ae-wasm --target web --out-dir wasm-demo/pkg
# Option 3: npm (from wasm-demo/)
cd wasm-demo && npm run build && npm run serve
```
Serve: `python -m http.server 8080` or `npx serve -l 8080`

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
# Automated (builds all targets, copies to b4ae-android-app)
./scripts/build_android.sh   # Linux/macOS
./scripts/build_android.ps1   # Windows
```

Manual: build `b4ae-android` for each target, copy `.so` to `b4ae-android-app/app/src/main/jniLibs/<abi>/`. Demo app: `b4ae-android-app/`.

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
./scripts/build_ios.sh   # macOS — produces libs/libb4ae_ffi.a
./scripts/build_ios.ps1  # Windows — host only; iOS requires macOS
```

Then: `cd bindings/swift && swift build`

### Swift Usage
```swift
let key = B4AE.generateKey()
let encrypted = try B4AE.encrypt(key: key, plaintext: Data("Hello".utf8))
let decrypted = try B4AE.decrypt(key: key, encrypted: encrypted)
```

Lihat `bindings/swift/README.md` untuk Swift Package.

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
