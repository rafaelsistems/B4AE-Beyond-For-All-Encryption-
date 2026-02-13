# B4AE Android Demo App

Minimal Android app demonstrating B4AE Platform SDK (AES-256-GCM via JNI).

## Prerequisites

- Android Studio (Arctic Fox or newer)
- Rust toolchain + Android targets:
  ```bash
  rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
  ```

## Build Native Library

```bash
# From repo root
./scripts/build_android.sh    # Linux/macOS
# or
./scripts/build_android.ps1     # Windows
```

This builds `libb4ae_android.so` and copies to `app/src/main/jniLibs/<abi>/`.

## Run

1. Open `b4ae-android-app` in Android Studio
2. Let Gradle sync (may need to run `gradle wrapper` if wrapper is missing)
3. Connect device or start emulator
4. Run app → demonstrates Generate Key → Encrypt → Decrypt

## Structure

- `app/src/main/java/com/b4ae/B4AE.kt` - Kotlin JNI bindings
- `app/src/main/java/com/b4ae/app/MainActivity.kt` - Demo UI
- `app/src/main/jniLibs/` - Native `.so` (populated by build script)
