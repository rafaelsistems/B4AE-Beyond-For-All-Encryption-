# CodeQL: Fix "No Ruby code found" / Disable Unused Languages

B4AE is **Rust**-only. CodeQL default setup analyzes C/C++, Java/Kotlin, Ruby, etc. — causing failures.

---

## Solusi 1: Edit Default Setup (UI)

1. Repo → **Settings** → **Code security and analysis**
2. Di **Code scanning**, klik **CodeQL analysis** → **Edit** (atau **View CodeQL configuration**)
3. Di **Languages**, **hapus centang**:
   - Ruby
   - C/C++
   - Java/Kotlin
   - Python (jika tidak dipakai)
4. **Centang hanya:** Rust
5. **Save changes**

---

## Solusi 2: Switch ke Advanced Setup (Custom Workflow)

1. Repo → **Settings** → **Code security and analysis**
2. Di **Code scanning**, ubah dari **Default** ke **Advanced**
3. Workflow `codeql.yml` di repo akan dipakai → hanya Rust dianalisis

Atau hapus Default setup dan pastikan workflow `.github/workflows/codeql.yml` ada (sudah ada, Rust-only).

---

## Verifikasi

Setelah diubah, CodeQL seharusnya hanya menjalankan **1 job: Analyze (Rust)**.
