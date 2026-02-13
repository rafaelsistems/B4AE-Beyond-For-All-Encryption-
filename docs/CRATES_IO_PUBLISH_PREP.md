# Persiapan Publish ke crates.io

Checklist dan tindakan untuk mempublish B4AE ke [crates.io](https://crates.io).

## Status: Persiapan

---

## 1. Cargo.toml

### 1.1 Metadata (Sudah Ada)
- [x] `name`, `version`, `edition`
- [x] `description`, `license`, `repository`
- [x] `keywords`, `categories`

### 1.2 Perlu Ditambah/Periksa
- [ ] `license-file` — jika pakai LICENSE file (MIT/Apache)
- [ ] `documentation` — URL ke docs.rs atau custom
- [ ] `homepage` — https://b4ae.org (jika ada)
- [ ] `readme` — path ke README.md (biasanya auto)

### 1.3 Dependencies
- [ ] **elara-transport**: Saat ini `path = "elara/crates/elara-transport"` — **tidak valid untuk publish**
  - **Opsi A**: Publish `elara-transport` ke crates.io dulu, lalu gunakan `elara-transport = { version = "x.y", optional = true }`
  - **Opsi B**: Gunakan `git = "https://github.com/rafaelsistems/ELARA-Protocol"` (kurang ideal untuk stability)
  - **Opsi C**: Feature `elara` optional; publish B4AE tanpa elara dulu, tambah elara setelah ELARA publish

---

## 2. Publikasi elara-transport

### 2.1 Jika ELARA Repo Terpisah
- [ ] Buat crate `elara-transport` di ELARA-Protocol
- [ ] Publish ke crates.io
- [ ] Update B4AE: `elara-transport = { version = "0.1", optional = true }`

### 2.2 Jika Tetap Submodule
- Publish B4AE **tanpa** feature `elara` default
- Feature `elara` membutuhkan user clone dengan `--recursive` dan build dari source
- Atau: vendor `elara-transport` source ke B4AE (license-permitting) — kompleks

**Rekomendasi**: Publish `elara-transport` ke crates.io untuk kemudahan.

---

## 3. Publikasi B4AE

### 3.1 Versi Pertama
- [ ] `version = "0.1.0"` (atau 0.2.0 jika ada breaking changes)
- [ ] Semantic versioning untuk ke depan
- [ ] CHANGELOG.md terupdate

### 3.2 Pre-Publish Checks
```bash
# Build clean
cargo build --release

# Tests pass
cargo test --all-features

# Publish dry-run (validasi tanpa upload)
cargo publish --dry-run

# Check package contents
cargo package --list
```

### 3.3 Crate Size
- [ ] Exclude `elara/` dari packaged files jika path dep (`.crateignore` atau default)
- [ ] Exclude benches, examples besar jika tidak perlu
- [ ] Target: crate < 5 MB

### 3.4 Documentation
- [ ] `cargo doc --no-deps` — no errors
- [ ] README.md valid (doctests)
- [ ] docs.rs akan auto-build — pastikan feature `elara` tidak break default build

---

## 4. Keamanan & Kebijakan

### 4.1 crates.io Account
- [ ] Buat account crates.io
- [ ] API token untuk publish
- [ ] 2FA jika tersedia

### 4.2 Security
- [ ] `cargo audit` — no vulnerabilities
- [ ] Dependencies up-to-date
- [ ] No secrets in published code

### 4.3 Dual License
- [ ] LICENSE-MIT dan LICENSE-APACHE
- [ ] Cargo.toml: `license = "MIT OR Apache-2.0"`

---

## 5. Post-Publish

### 5.1 Badges
- [ ] Add crates.io badge ke README
- [ ] docs.rs badge
- [ ] License badge

### 5.2 Announcement
- [ ] README update (install from crates.io)
- [ ] GitHub release
- [ ] Changelog

### 5.3 Maintenance
- [ ] Monitor `cargo audit`
- [ ] Dependabot / Renovate
- [ ] Issue/PR response policy

---

## Urutan Disarankan

1. Selesaikan `elara-transport` path → crates.io (atau git) jika feature `elara` akan di-publish.
2. Jalankan `cargo publish --dry-run` dan perbaiki error.
3. Publish B4AE `0.1.0` (atau versi yang dipilih).
4. Update README dan dokumentasi.
