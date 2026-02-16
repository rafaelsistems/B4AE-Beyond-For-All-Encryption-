# Website / GitHub Pages Positioning

Perbarui positioning untuk "Drop-in Quantum-Safe Transport" di situs dan landing page.

---

## Key Messages

### Tagline
**"Drop-in Quantum-Safe Transport Layer for Modern Apps"**

### Subtitle
**"TLS for the Post-Quantum Era"**

### Value Proposition
- Bukan competitor Signal — infrastructure layer untuk Signal, Matrix, MQTT, gRPC
- Add quantum security dalam 5 menit
- Pluggable, modular, audit-friendly

---

## GitHub Pages Setup

### Opsi 1: docs/ sebagai root
1. Settings → Pages → Source: Deploy from branch
2. Branch: main, folder: /docs
3. Buat `docs/index.html` sebagai landing

### Opsi 2: README sebagai landing
- Gunakan README.md sebagai halaman utama repo
- Pastikan README berisi tagline terbaru (sudah di-update)

### Opsi 3: GitHub Pages dengan Jekyll
1. Buat branch `gh-pages` atau folder `docs/`
2. `index.md` dengan front matter:

```yaml
---
title: B4AE — Quantum-Safe Transport
tagline: Drop-in for Signal, Matrix, MQTT, gRPC
---
```

---

## Konten Landing Page (Minimum)

1. **Hero:** Tagline + link ke GitHub
2. **What is B4AE:** 2–3 kalimat
3. **Quick Start:** `cargo add b4ae`
4. **Features:** Quantum, Metadata, Enterprise
5. **Links:** Repo, docs.rs, SECURITY, CONTRIBUTORS
6. **Contact:** Email untuk security & general

---

## External Website (Opsional)

Jika membangun situs terpisah (b4ae.org):
- Domain & hosting
- SSL
- Sesuaikan dengan positioning di atas
- Link ke Open Collective, crates.io
