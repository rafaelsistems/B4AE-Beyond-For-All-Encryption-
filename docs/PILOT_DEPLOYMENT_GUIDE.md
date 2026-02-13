# B4AE Pilot Deployment Guide

Panduan deployment pilot untuk evaluasi B4AE dalam environment terkontrol.

---

## Phase 4: Pilot Deployment

### Scope Pilot

- **Duration**: 2–4 minggu
- **Users**: Tim internal / early adopters
- **Traffic**: Test load, bukan production load
- **Environment**: Staging / sandbox

### Step 1: Persiapan

```bash
# Clone
git clone --recursive https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-.git
cd B4AE-Beyond-For-All-Encryption-

# Security audit
./scripts/security_audit.sh   # Linux/macOS
# atau scripts/security_audit.ps1 pada Windows

# Build
cargo build --release --all-features

# Tests
cargo test --release --all-features
```

### Step 2: Konfigurasi

- Network: firewall rules untuk UDP (ELARA) jika dipakai
- Logging: set `RUST_LOG=info` atau `debug`
- Keys: gunakan key management yang aman (HSM opsional)

### Step 3: Deploy

**Option A: Bare metal / VM**
- Deploy binary hasil `cargo build --release`
- Jalankan sebagai service (systemd, etc.)

**Option B: Docker**
```bash
docker build -t b4ae-pilot .
docker run -e RUST_LOG=info b4ae-pilot
```

### Step 4: Monitoring

- Log level: `info` untuk production, `debug` untuk troubleshooting
- Metrics: handshake count, message throughput, error rate
- Alerts: handshake timeout, decrypt failures

### Step 5: Rollback

- Simpan binary/layer sebelumnya
- Rollback = deploy versi sebelumnya
- Session keys invalidated — client perlu re-handshake

---

## Kriteria Sukses Pilot

- [ ] Handshake success rate > 99%
- [ ] Message delivery success > 99%
- [ ] No critical security findings
- [ ] Performance within targets (see ROADMAP)
- [ ] Feedback dari pilot users

---

## Referensi

- [PRODUCTION_DEPLOYMENT](PRODUCTION_DEPLOYMENT.md)
- [INTEGRATION_TESTING_PLAN](INTEGRATION_TESTING_PLAN.md)
