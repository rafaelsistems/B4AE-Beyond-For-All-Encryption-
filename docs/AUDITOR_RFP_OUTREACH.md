# External Audit — RFP & Auditor Outreach

Template untuk memulai proses external security audit.

---

## RFP Summary (for Auditors)

**Project:** B4AE (Beyond For All Encryption)  
**Scope:** Quantum-resistant secure transport protocol (Rust)  
**Estimated LOC:** ~15k (core + protocol + crypto)  
**License:** MIT/Apache 2.0 (open source)  
**Target auditors:** Trail of Bits, Kudelski Security, Cure53  

---

## Email Template — Auditor Outreach

**Subject:** Security Audit RFP — B4AE (Quantum-Resistant Transport, Rust)

---

Dear [Auditor Name / Team],

We are seeking an external security audit for **B4AE** (Beyond For All Encryption), an open-source quantum-resistant secure transport protocol implemented in Rust.

**Overview:**
- NIST-standardized PQC: Kyber-1024 (KEM), Dilithium5 (signatures)
- Hybrid with X25519/Ed25519
- Handshake protocol, message encryption, key hierarchy
- Metadata protection (padding, timing, dummy traffic)
- ELARA transport integration (optional)

**Repository:** https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-

**Requested scope:**
1. Cryptographic implementation review (Kyber, Dilithium, hybrid, HKDF, AES-GCM)
2. Handshake protocol security
3. Key storage and hierarchy
4. Metadata protection layer

**Deliverables:** Written report, remediation guidance, (optional) public summary

**Timeline:** Flexible; target completion within 2–4 months of engagement

**Budget:** [To be discussed]

Please indicate your availability and typical process for open-source crypto audits. We are open to a scoped engagement or phased approach.

Best regards,  
[Your name]  
rafaelsistems@gmail.com  

---

## Auditor Contact Info

| Auditor | Website | Contact |
|---------|---------|---------|
| Trail of Bits | trailofbits.com | https://www.trailofbits.com/contact/ |
| Kudelski Security | kudelskisecurity.com | Via website / sales |
| Cure53 | cure53.de | info@cure53.de |

---

## Pre-Submission Checklist

- [ ] Complete [EXTERNAL_AUDIT_CHECKLIST.md](EXTERNAL_AUDIT_CHECKLIST.md)
- [ ] Ensure `cargo test`, `cargo audit`, `cargo clippy` pass
- [ ] Prepare threat model (optional: create docs/THREAT_MODEL.md)
- [ ] Secure budget / funding (Open Collective, grant, sponsor)
- [ ] Send RFP to at least 2 auditors for comparison
