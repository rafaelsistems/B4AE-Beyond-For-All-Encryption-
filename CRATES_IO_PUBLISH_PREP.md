# Persiapan Publish ke crates.io

Checklist dan tindakan untuk mempublish B4AE ke [crates.io](https://crates.io).

## Status: Siap Publish

---

## 1. Cargo.toml

### 1.1 Metadata (Sudah Ada)
- [x] `name`, `version`, `edition`
- [x] `description`, `license`, `repository`
- [x] `keywords`, `categories`
- [x] `documentation` — https://docs.rs/b4ae
- [x] `homepage` — GitHub repo
- [x] `readme` — README.md

### 1.2 Dependencies
- [x] **elara-transport**: `version = "0.1"` dari crates.io (elara-core, elara-wire, elara-transport sudah dipublish)
- Feature `elara` optional; default build tanpa elara OK

---

## 2. Publikasi elara-transport ✅ (sudah selesai)

elara-core, elara-wire, elara-transport v0.1.0 sudah di crates.io. B4AE memakai `version = "0.1"`.

---

## 3. Publikasi B4AE

### 3.1 Versi Pertama
- [x] `version = "1.0.0"`
- [x] CHANGELOG.md terupdate

### 3.2 Pre-Publish Checks
```bash
cargo build --release
cargo test --all-features   # termasuk elara
cargo publish --dry-run     # ✅ Verified OK
cargo package --list
```

**Note:** `keccak v0.1.5` in lockfile is yanked; consider `cargo update -p keccak` if sha3 updates.

### 3.3 Crate Size
- [x] `exclude` in Cargo.toml — exclude elara/, docs/, bindings/, scripts/, etc.
- [x] Target: crate < 5 MB

### 3.4 Documentation
- [ ] `cargo doc --no-deps` — verifikasi no errors
- [ ] docs.rs auto-build — default (tanpa elara) OK

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

1. ~~Selesaikan elara-transport~~ — sudah pakai git dep.
2. Jalankan `cargo publish --dry-run` dan perbaiki error.
3. Publish B4AE `1.0.0`.
4. Update README (badge crates.io).

## Local Development dengan Submodule

Untuk build dari source dengan submodule elara (lebih cepat, offline), tambahkan di workspace root:

```toml
[patch."https://github.com/rafaelsistems/ELARA-Protocol"]
elara-transport = { path = "elara/crates/elara-transport" }
```
