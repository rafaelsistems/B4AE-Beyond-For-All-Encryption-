# B4AE Platform Bindings

## Swift (iOS/macOS)

**Crate:** `b4ae-ffi` (C ABI) + `bindings/swift`

### Build
```bash
# Build static library
cd b4ae-ffi
cargo build --release

# For iOS (universal)
cargo build --release --target aarch64-apple-ios
cargo build --release --target x86_64-apple-ios
# Then use lipo to create universal binary
```

### Swift Package
- `Sources/B4AE/B4AE.swift` - Swift wrapper calling C FFI
- Requires `libb4ae_ffi.a` to be built and linked

## Kotlin (Android)

**Crate:** `b4ae-android` (JNI)

### Build
```bash
cd b4ae-android
cargo build --release --target aarch64-linux-android   # ARM64
cargo build --release --target i686-linux-android     # x86
cargo build --release --target x86_64-linux-android   # x86_64
```

Copy `libb4ae_android.so` to `android/app/src/main/jniLibs/<abi>/`

### Kotlin Usage
```kotlin
val key = B4AE.generateKey()
val encrypted = B4AE.encrypt(key, "Hello".toByteArray())
val decrypted = B4AE.decrypt(key, encrypted)
```

## C Header
`bindings/b4ae.h` - C API for b4ae_ffi

## WASM (Web)

**Crate:** `b4ae-wasm`

```bash
wasm-pack build b4ae-wasm --target web --out-dir pkg
```

Demo: `wasm-demo/` — run `wasm-pack build b4ae-wasm --target web --out-dir wasm-demo/pkg`
