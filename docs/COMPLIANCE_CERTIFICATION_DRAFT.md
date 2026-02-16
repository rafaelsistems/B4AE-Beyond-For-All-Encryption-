# Compliance Certification Draft (Q3)

Draft untuk compliance certification — GDPRE, HIPAA, ISO 27001.

---

## Scope

- B4AE sebagai cryptographic/transport layer
- Enterprise deployment patterns
- Kontrol yang dapat di-demonstrate

---

## GDPR

| Article | B4AE Support | Evidence |
|---------|--------------|----------|
| Art. 32 Security | Encryption, key management | Protocol spec, audit |
| Art. 25 Minimization | Metadata obfuscation | docs/ |
| Art. 5 Integrity | AEAD, signatures | Code |

**Certification path:** Self-assessment → DPA review → Legal sign-off.

---

## HIPAA

| Safeguard | B4AE Support |
|-----------|--------------|
| §164.312(a)(2)(iv) Encryption | AES-256-GCM, Kyber |
| §164.312(b) Audit | AuditSink |
| §164.312(c)(1) Integrity | AEAD |

**Note:** BAA (Business Associate Agreement) dan organizational policy tetap diperlukan.

---

## ISO 27001 Annex A

| Control | Mapping |
|---------|---------|
| A.10.1 Cryptographic controls | COMPLIANCE_MATRIX.md |
| A.14.1 Secure development | TLA+, Coq, fuzzing |
| A.16.1 Incident | AuditSink, SECURITY.md SLA |

---

## Next Steps

- [ ] Engage compliance consultant
- [ ] Formalize control evidence package
- [ ] Target: SOC 2 Type I prep (12 months)
