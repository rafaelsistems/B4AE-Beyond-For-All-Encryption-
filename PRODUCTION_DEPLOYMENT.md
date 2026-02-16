# B4AE Production Deployment

Panduan deployment B4AE untuk environment production.

---

## Phase 4: Production Infrastructure

### Prerequisites

- Rust 1.70+
- (Optional) Docker untuk containerized deployment

### Build

```bash
# Full build with all features
cargo build --release --all-features

# Build with ELARA only
cargo build --release --features elara

# Build without ELARA (minimal)
cargo build --release --no-default-features --features full-crypto
```

### Docker

> **Note:** Pastikan submodule `elara` sudah di-init sebelum build:
> `git submodule update --init --recursive`

```bash
# Build image
docker build -t b4ae:latest .

# Run ELARA demo
docker run --rm -it b4ae:latest
```

### Configuration

| Environment | Description | Default |
|-------------|-------------|---------|
| `RUST_LOG` | Log level (error, warn, info, debug, trace) | info |
| `B4AE_SECURITY_PROFILE` | Standard, High, Maximum | Standard |

### Security Checklist

- [ ] Run `cargo audit` — no vulnerabilities
- [ ] Run `scripts/security_audit.sh` (or .ps1 on Windows)
- [ ] Use release build (`--release`)
- [ ] Enable HTTPS/TLS for any exposed endpoints
- [ ] Restrict network exposure
- [ ] Rotate keys per [SECURITY_AUDIT_CHECKLIST](SECURITY_AUDIT_CHECKLIST.md)

---

## Integrasi ke Aplikasi

### Rust Library

```toml
[dependencies]
b4ae = { git = "https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-", features = ["elara"] }
```

### Platform SDKs

- **Web**: `b4ae-wasm` — see [PLATFORM_SDK](PLATFORM_SDK.md)
- **Android**: `b4ae-android` — JNI
- **iOS**: `b4ae-ffi` — C FFI + Swift

---

## Referensi

- [Pilot Deployment Guide](PILOT_DEPLOYMENT_GUIDE.md)
- [Release Checklist](RELEASE_CHECKLIST.md)
- [CRATES_IO_PUBLISH_PREP](CRATES_IO_PUBLISH_PREP.md)
