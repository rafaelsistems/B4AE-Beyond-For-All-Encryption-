# B4AE Swift Package (iOS/macOS)

Swift wrapper for B4AE C FFI - AES-256-GCM encrypt/decrypt.

## Build Native Library

Run from repo root on **macOS** (for iOS targets):

```bash
./scripts/build_ios.sh
```

On Windows (builds for host only; iOS requires macOS):

```powershell
.\scripts\build_ios.ps1
```

This produces `libs/libb4ae_ffi.a` (or per-target in `libs/<target>/`).

## Swift Package Manager

```bash
cd bindings/swift
swift build
```

Or add as dependency:

```swift
.package(url: "https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-.git", path: "bindings/swift")
```

## Usage

```swift
import B4AE

let key = B4AE.generateKey()
let encrypted = try B4AE.encrypt(key: key, plaintext: Data("Hello".utf8))
let decrypted = try B4AE.decrypt(key: key, encrypted: encrypted)
```

## Note

The Swift package links against `libb4ae_ffi.a` in the `libs/` directory. Run `build_ios.sh` on macOS before building the Swift package for iOS.
