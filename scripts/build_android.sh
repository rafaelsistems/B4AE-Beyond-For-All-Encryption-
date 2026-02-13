#!/bin/bash
# Build B4AE Android JNI library - produces libb4ae_android.so for each ABI
# Copies to b4ae-android-app/app/src/main/jniLibs/<abi>/

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANDROID_CRATE="$ROOT/b4ae-android"
APP_JNILIBS="$ROOT/b4ae-android-app/app/src/main/jniLibs"

# Targets for Android
TARGETS=(
    "aarch64-linux-android:arm64-v8a"
    "armv7-linux-androideabi:armeabi-v7a"
    "i686-linux-android:x86"
    "x86_64-linux-android:x86_64"
)

mkdir -p "$APP_JNILIBS"
cd "$ANDROID_CRATE"

for entry in "${TARGETS[@]}"; do
    target="${entry%%:*}"
    abi="${entry##*:}"
    if rustup target list | grep -q "$target (installed)"; then
        echo "Building $target -> $abi..."
        cargo build --release --target "$target"
        mkdir -p "$APP_JNILIBS/$abi"
        sofile="target/$target/release/libb4ae_android.so"
        [ -f "$sofile" ] && cp "$sofile" "$APP_JNILIBS/$abi/" && echo "  -> jniLibs/$abi/"
    else
        echo "Skipping $target (not installed). Run: rustup target add $target"
    fi
done

# Fallback: build for host if no Android targets (for CI/laptop without NDK)
if ! ls "$APP_JNILIBS"/*/libb4ae_android.so 1>/dev/null 2>&1; then
    echo "Building for host (no Android targets)..."
    cargo build --release
    echo "  -> target/release/libb4ae_android.so (copy manually to jniLibs for your ABI)"
fi

echo "Done. Open b4ae-android-app in Android Studio and run."
