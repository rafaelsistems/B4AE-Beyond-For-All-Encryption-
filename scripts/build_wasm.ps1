# Build B4AE WASM and prepare wasm-demo
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

Write-Host "Building b4ae-wasm..."
Push-Location $Root
try {
    wasm-pack build b4ae-wasm --target web --out-dir wasm-demo/pkg
    Write-Host "Done. Serve: cd wasm-demo && npx serve -l 8080"
} finally {
    Pop-Location
}
