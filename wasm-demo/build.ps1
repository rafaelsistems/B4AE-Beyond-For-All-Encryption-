# Build B4AE WASM and copy to demo
Set-Location (Join-Path $PSScriptRoot "..")
cargo install wasm-pack 2>$null
wasm-pack build b4ae-wasm --target web --out-dir wasm-demo/pkg
Write-Host "Built. Open wasm-demo/index.html via a local server"
