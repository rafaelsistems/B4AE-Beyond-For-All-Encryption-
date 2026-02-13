#!/bin/bash
# Build B4AE C FFI for iOS/macOS - produces libb4ae_ffi.a for Swift Package
# Run on macOS with Xcode (for iOS targets) or any system for x86_64-apple-darwin

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FFI="$ROOT/b4ae-ffi"
LIBS="$ROOT/bindings/swift/libs"
mkdir -p "$LIBS"

echo "Building b4ae-ffi..."

# macOS (for development / Swift Package on Mac)
if rustup target list | grep -q "x86_64-apple-darwin (default)\|x86_64-apple-darwin (installed)" || rustup target list | grep -q "aarch64-apple-darwin"; then
    echo "Building for macOS..."
    cd "$FFI"
    cargo build --release 2>/dev/null || cargo build --release --target x86_64-apple-darwin 2>/dev/null || true
    if [ -f "$FFI/target/release/libb4ae_ffi.a" ]; then
        cp "$FFI/target/release/libb4ae_ffi.a" "$LIBS/"
        echo "  -> libs/libb4ae_ffi.a (macOS)"
    elif [ -f "$FFI/target/x86_64-apple-darwin/release/libb4ae_ffi.a" ]; then
        cp "$FFI/target/x86_64-apple-darwin/release/libb4ae_ffi.a" "$LIBS/"
        echo "  -> libs/libb4ae_ffi.a (macOS x86_64)"
    fi
fi

# iOS simulator + device (requires macOS with Xcode)
if [[ "$(uname)" == "Darwin" ]]; then
    for target in aarch64-apple-ios x86_64-apple-ios; do
        if rustup target add "$target" 2>/dev/null; then
            echo "Building for $target..."
            cd "$FFI"
            cargo build --release --target "$target"
            mkdir -p "$LIBS/$target"
            cp "$FFI/target/$target/release/libb4ae_ffi.a" "$LIBS/$target/"
            echo "  -> libs/$target/libb4ae_ffi.a"
        fi
    done
fi

# Fallback: at least build for host (Linux/Windows will get x86_64-unknown-linux-gnu etc - won't be iOS)
if [ ! -f "$LIBS/libb4ae_ffi.a" ]; then
    cd "$FFI"
    cargo build --release
    # Copy whatever we got for local development
    for f in "$FFI/target/release/"libb4ae_ffi.*; do
        [ -e "$f" ] && cp "$f" "$LIBS/" 2>/dev/null || true
    done
fi

echo "Done. Swift Package: cd bindings/swift && swift build"
echo "  (Ensure libs/libb4ae_ffi.a exists - build on macOS for iOS)"
