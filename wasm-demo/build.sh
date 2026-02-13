#!/bin/bash
# Build B4AE WASM and copy to demo
set -e
cd "$(dirname "$0")/.."
cargo install wasm-pack 2>/dev/null || true
wasm-pack build b4ae-wasm --target web --out-dir wasm-demo/pkg
echo "Built. Open wasm-demo/index.html via a local server (e.g. python -m http.server 8080)"
