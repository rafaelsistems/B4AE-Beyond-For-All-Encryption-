# B4AE Compliance Matrix

Formal mapping of B4AE capabilities to regulatory and standards requirements.  
*Enterprise does not buy crypto—they buy compliance assurance.*

---

## GDPR (General Data Protection Regulation)

| Requirement | B4AE Capability | Implementation |
|-------------|-----------------|-----------------|
| **Art. 32 – Security of processing** | Encryption at rest & in transit | `EncryptedStorage`, AES-GCM, Kyber/Dilithium |
| **Art. 32 – Pseudonymization** | ZKAuth, pseudonymous identities | `crypto::zkauth`, identity abstraction |
| **Art. 32 – Confidentiality** | End-to-end encryption | `B4aeClient::encrypt_message` / `decrypt_message` |
| **Art. 25 – Data minimization** | Metadata obfuscation | Padding, timing, dummy traffic (`metadata::*`) |
| **Art. 5(1)(f) – Integrity** | Authenticated encryption | AES-GCM, hybrid signatures |
| **Audit trail (controller)** | AuditSink, event logging | `audit::AuditEvent`, `B4aeClient::audit_sink` |

---

## HIPAA (Health Insurance Portability and Accountability Act)

| Safeguard | B4AE Capability | Implementation |
|-----------|-----------------|-----------------|
| **§164.312(a)(2)(iv) – Encryption** | NIST-aligned algorithms | Kyber, Dilithium, AES-256-GCM |
| **§164.312(b) – Audit controls** | Audit logging | `AuditSink`, `AuditEvent` |
| **§164.312(c)(1) – Integrity** | Tamper detection | AEAD, signature verification |
| **§164.312(e)(1) – Transmission security** | Secure transport | ELARA, TLS-like handshake |
| **Access control (by design)** | Key hierarchy | MIK, DMK, STK, BKS |

---

## ISO 27001 Annex A Controls

| Control | B4AE Support | Notes |
|---------|--------------|-------|
| **A.10.1 – Cryptographic controls** | ✅ | Kyber, Dilithium, AES-GCM, HKDF |
| **A.12.3 – Information backup** | ✅ | Export/import DMK, key persistence |
| **A.13.1 – Network security** | ✅ | Secure transport, metadata protection |
| **A.14.1 – Security in development** | ✅ | Formal verification (TLA+, Coq), fuzzing |
| **A.16.1 – Incident management** | ⚠️ | AuditSink supports logging; incident process is organizational |
| **A.18.1 – Compliance** | ⚠️ | This matrix; compliance program is organizational |

---

## SOC 2 / NIST Cybersecurity Framework

| Domain | B4AE Contribution |
|--------|-------------------|
| **Encryption** | Full protocol, key management |
| **Access Control** | Key hierarchy, ZKAuth |
| **Monitoring** | AuditSink, event taxonomy |
| **Vulnerability management** | SECURITY.md, responsible disclosure |

---

## Disclaimer

This matrix aids assessment only. Actual compliance depends on:

- How B4AE is deployed in your architecture
- Organizational policies and procedures
- Third-party audit and certification

Consult legal and compliance teams before claiming compliance.
