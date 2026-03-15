# Publikasi ELARA ke crates.io

Panduan mempublish crates ELARA (elara-core, elara-wire, elara-transport) ke crates.io agar B4AE dapat memakai `elara-transport` via version dependency.

## Prasyarat

1. **Akun crates.io** — daftar di https://crates.io
2. **cargo login** — `cargo login` dengan API token dari crates.io
3. **Nama crate tersedia** — pastikan `elara-core`, `elara-wire`, `elara-transport` belum dipakai di crates.io (nama harus unik)

## Urutan Publish

Dependency chain: **elara-core → elara-wire → elara-transport**

Publish harus berurutan karena elara-wire bergantung pada elara-core, dan elara-transport bergantung pada keduanya.

## Langkah

### 1. Masuk ke direktori elara

```bash
cd elara   # atau path ke ELARA submodule
```

### 2. Verifikasi build

```bash
cargo build -p elara-core -p elara-wire -p elara-transport
```

### 3. Dry-run (opsional)

```bash
cargo publish -p elara-core --dry-run
```

### 4. Publish

**Linux/macOS:**
```bash
./scripts/publish_to_crates_io.sh
```

**Windows PowerShell:**
```powershell
.\scripts\publish_to_crates_io.ps1
```

**Manual (satu per satu):**
```bash
cargo publish -p elara-core
cargo publish -p elara-wire
cargo publish -p elara-transport
```

## Setelah Publish

### Update B4AE Cargo.toml

Ubah dependency elara-transport dari path ke version:

```toml
# Sebelum (path)
elara-transport = { path = "elara/crates/elara-transport", optional = true }

# Sesudah (version dari crates.io)
elara-transport = { version = "0.1", optional = true }
```

Feature `elara` akan resolve elara-transport dari crates.io. Build B4AE tanpa submodule elara akan berhasil.

### Verifikasi B4AE

```bash
cd ..   # ke root B4AE
# Hapus sementara path ke elara untuk test
cargo build --features elara
```

## Troubleshooting

| Masalah | Solusi |
|---------|--------|
| `elara-core` not found | Publish elara-core dulu |
| Crate name taken | Nama sudah dipakai; ganti nama atau koordinasi dengan pemilik |
| Version already exists | Increment version di workspace Cargo.toml |

## Referensi

- [Crates.io Publishing](https://doc.rust-lang.org/cargo/reference/publishing.html)
- [ELARA Protocol](https://github.com/rafaelsistems/ELARA-Protocol)
- [B4AE CRATES_IO_PUBLISH_PREP.md](CRATES_IO_PUBLISH_PREP.md)
