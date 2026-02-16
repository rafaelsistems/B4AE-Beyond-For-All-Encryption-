# Publishing b4ae-wasm to npm

```bash
# From repo root
wasm-pack build b4ae-wasm --target web --out-dir pkg
cd b4ae-wasm/pkg
npm publish
```

Requires: wasm-pack, npm account, `npm login` first.

Package name from Cargo.toml: `b4ae-wasm`.
