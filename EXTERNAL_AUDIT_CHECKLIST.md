# External Audit Checklist

Persiapan untuk external security audit (Trail of Bits, Kudelski Security, Cure53).

---

## Pre-Audit Checklist

### 1. Codebase Readiness
- [ ] Semua tests pass (`cargo test --all-features`)
- [ ] Clippy clean (`cargo clippy -- -D warnings`)
- [ ] `cargo audit` tanpa vulnerability
- [ ] Dokumentasi lengkap (`cargo doc --no-deps`)
- [ ] Fuzzing targets siap (cargo-fuzz)

### 2. Dokumentasi untuk Auditor
- [ ] [SECURITY.md](../SECURITY.md) — responsible disclosure SLA
- [ ] [Protocol Specification](../specs/B4AE_Protocol_Specification_v1.0.md)
- [ ] [ARCHITECTURE](README.md#technical-architecture) overview
- [ ] Threat model (atau buat `docs/THREAT_MODEL.md`)
- [ ] Daftar cryptographic assumptions

### 3. Auditor Target
| Auditor | Website | Catatan |
|---------|---------|---------|
| Trail of Bits | trailofbits.com | Crypto & protocol expertise |
| Kudelski Security | kudelskisecurity.com | Post-quantum focus |
| Cure53 | cure53.de | Open-source friendly |

### 4. Scope Audit
- [ ] Cryptographic implementation (Kyber, Dilithium, Hybrid, HKDF, AES-GCM)
- [ ] Handshake protocol
- [ ] Key hierarchy & storage
- [ ] Metadata protection layer
- [ ] (Opsional) ELARA transport integration

### 5. Budget & Timeline
- [ ] Estimasi biaya (biasanya $20k–100k+ tergantung scope)
- [ ] Target timeline (2–4 bulan umumnya)
- [ ] Sumber dana (Open Collective, sponsor, grant)

---

## Post-Audit
- [ ] Publikasikan laporan audit (redact jika perlu)
- [ ] Remediasi findings sesuai prioritas
- [ ] Update [SECURITY.md](../SECURITY.md) dengan link laporan
