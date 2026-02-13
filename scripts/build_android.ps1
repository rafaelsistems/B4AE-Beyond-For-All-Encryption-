# Build B4AE Android JNI library - produces libb4ae_android.so for each ABI
# Copies to b4ae-android-app/app/src/main/jniLibs/<abi>/

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$AndroidCrate = Join-Path $Root "b4ae-android"
$AppJniLibs = Join-Path $Root "b4ae-android-app\app\src\main\jniLibs"

$Targets = @(
    @{ Rust = "aarch64-linux-android"; Abi = "arm64-v8a" },
    @{ Rust = "armv7-linux-androideabi"; Abi = "armeabi-v7a" },
    @{ Rust = "i686-linux-android"; Abi = "x86" },
    @{ Rust = "x86_64-linux-android"; Abi = "x86_64" }
)

New-Item -ItemType Directory -Force -Path $AppJniLibs | Out-Null

foreach ($t in $Targets) {
    $installed = rustup target list | Select-String "$($t.Rust)\s+\(installed\)"
    if ($installed) {
        Write-Host "Building $($t.Rust) -> $($t.Abi)..."
        Push-Location $AndroidCrate
        try {
            cargo build --release --target $t.Rust
            $so = Join-Path $AndroidCrate "target\$($t.Rust)\release\libb4ae_android.so"
            if (Test-Path $so) {
                $dest = Join-Path $AppJniLibs $t.Abi
                New-Item -ItemType Directory -Force -Path $dest | Out-Null
                Copy-Item $so -Destination (Join-Path $dest "libb4ae_android.so") -Force
                Write-Host "  -> jniLibs/$($t.Abi)/"
            }
        } finally {
            Pop-Location
        }
    } else {
        Write-Host "Skipping $($t.Rust). Run: rustup target add $($t.Rust)"
    }
}

# Fallback: build for host
Push-Location $AndroidCrate
cargo build --release
Write-Host "Done. Open b4ae-android-app in Android Studio."
