# B4AE — Implementation Roadmap (Bertahap)

Tracker utama untuk implementasi strategi. Update status saat setiap fase selesai.

---

## ✅ Langkah Segera (Selesai)

| Item | Status |
|------|--------|
| Push strategic docs (README, SECURITY, ROADMAP, etc.) | ✅ Done |
| CONTRIBUTORS.md, COMPLIANCE_MATRIX, HYBRID_MODEL_STRATEGY | ✅ Done |
| STRATEGIC_VISION, OPEN_COLLECTIVE_APPLICATION | ✅ Done |

---

## Jangka Pendek (1–3 Bulan)

| Prioritas | Aksi | Doc / Link | Status |
|-----------|------|------------|--------|
| **Trust** | Mulai proses external audit | [EXTERNAL_AUDIT_CHECKLIST.md](EXTERNAL_AUDIT_CHECKLIST.md), [AUDITOR_RFP_OUTREACH.md](AUDITOR_RFP_OUTREACH.md) | ✅ Prep done |
| **Distribution** | Publish b4ae ke crates.io | [CRATES_IO_PUBLISH_PREP.md](CRATES_IO_PUBLISH_PREP.md) — `cargo publish` when ready | ✅ Ready |
| **Visibility** | Kirim whitepaper ke IACR ePrint / arXiv | [WHITEPAPER_DRAFT.md](WHITEPAPER_DRAFT.md), [WHITEPAPER_PUBLICATION_CHECKLIST.md](WHITEPAPER_PUBLICATION_CHECKLIST.md) | ✅ Draft done |
| **Funding** | Selesaikan aplikasi Open Collective | [OPEN_COLLECTIVE_SUBMISSION_CHECKLIST.md](OPEN_COLLECTIVE_SUBMISSION_CHECKLIST.md) | ✅ Checklist done |
| **Website** | GitHub Pages auto-deploy | [.github/workflows/pages.yml](../.github/workflows/pages.yml) → [index.html](index.html) | ✅ Implemented |

---

## Jangka Menengah (3–6 Bulan)

| Prioritas | Aksi | Doc / Link | Status |
|-----------|------|------------|--------|
| **Enterprise** | MVP Enterprise Control Plane API | [enterprise-api/](../enterprise-api/) — `/health`, `/audit/events` | ✅ Implemented |
| **SaaS** | B4AE Secure Relay stub | [b4ae-relay/](../b4ae-relay/) — UDP relay stub | ✅ Implemented |
| **SDK** | Publish ke CocoaPods, Maven Central, npm | [SDK_DISTRIBUTION_CHECKLIST.md](SDK_DISTRIBUTION_CHECKLIST.md), [B4AE.podspec](../bindings/swift/B4AE.podspec), [NPM_PUBLISH](../b4ae-wasm/NPM_PUBLISH.md) | ✅ Configs done |
| **Pilot** | 3 calon enterprise pilot | [PILOT_OUTREACH_TEMPLATE.md](PILOT_OUTREACH_TEMPLATE.md) | ✅ Template done |

---

## Jangka Panjang (6–12 Bulan)

| Periode | Fokus | Status |
|---------|-------|--------|
| **Q3** | Compliance certification draft, paid support tier | ✅ [COMPLIANCE_CERTIFICATION_DRAFT.md](COMPLIANCE_CERTIFICATION_DRAFT.md), [PAID_SUPPORT_TIER.md](PAID_SUPPORT_TIER.md) |
| **Q4** | Government bid, v2.0, partner program | ✅ [GOVERNMENT_BID_CHECKLIST.md](GOVERNMENT_BID_CHECKLIST.md), [V2_PLANNING.md](V2_PLANNING.md), [PARTNER_PROGRAM.md](PARTNER_PROGRAM.md) |
| **KPI** | >5k stars, >100k crates.io downloads/month | ⬜ Ongoing |

---

## Trust Preservation (Ongoing)

- [ ] Audit report dipublikasikan setelah selesai
- [ ] Open core tetap MIT/Apache
- [ ] Hindari klaim marketing berlebihan
- [ ] Changelog dan governance transparan

---

## Referensi

- [STRATEGIC_VISION.md](STRATEGIC_VISION.md)
- [HYBRID_MODEL_STRATEGY.md](HYBRID_MODEL_STRATEGY.md)
- [ROADMAP.md](ROADMAP.md)
- [COMPLIANCE_MATRIX.md](COMPLIANCE_MATRIX.md)
