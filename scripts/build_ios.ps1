# Build B4AE C FFI for iOS/macOS - produces libb4ae_ffi.a for Swift Package
# Note: iOS cross-compile requires macOS with Xcode. On Windows this builds host target only.

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$FFI = Join-Path $Root "b4ae-ffi"
$LIBS = Join-Path $Root "bindings\swift\libs"

New-Item -ItemType Directory -Force -Path $LIBS | Out-Null

Write-Host "Building b4ae-ffi..."

# Build for host (Windows: .dll/.lib, Linux: .so/.a) - usable for local Swift package on Mac if run there
Push-Location $FFI
try {
    cargo build --release
    $lib = Get-ChildItem -Path "$FFI\target\release" -Filter "libb4ae_ffi*" -ErrorAction SilentlyContinue
    if ($lib) {
        Copy-Item $lib.FullName -Destination $LIBS -Force
        Write-Host "  -> libs/$($lib.Name)"
    }
} finally {
    Pop-Location
}

Write-Host "Done."
Write-Host "For iOS: Run scripts/build_ios.sh on macOS with Xcode."
Write-Host "Swift Package: cd bindings/swift && swift build"
