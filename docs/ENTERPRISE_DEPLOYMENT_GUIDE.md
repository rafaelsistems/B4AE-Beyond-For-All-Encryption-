# B4AE Enterprise Deployment Guide

Panduan deployment B4AE untuk lingkungan enterprise (on-prem, hybrid, compliance).

---

## 1. Persyaratan

### Infrastruktur

| Komponen        | Minimum                    | Rekomendasi               |
|-----------------|----------------------------|----------------------------|
| CPU             | x86_64 / ARM64             | AES-NI, AVX2               |
| RAM             | 256 MB per node            | 1 GB+                     |
| Network         | UDP (ELARA), low latency   | Dedicated VLAN             |
| Storage         | Encrypted at rest          | HSM-backed keys (opsional) |

### Software

- Rust 1.70+ (untuk build) atau binary pre-built
- TLS certificates (jika expose HTTPS)
- HSM/PKCS#11 (opsional, feature `hsm-pkcs11`)

---

## 2. Arsitektur Deployment

### 2.1 Single Node (POC)

```
[App] → [B4aeElaraNode] → UDP → [Peer]
```

- Satu process, satu port UDP
- Cocok untuk POC, development

### 2.2 Multi-Node (Production)

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Node A     │◄───►│  Node B     │◄───►│  Node C     │
│  (Region 1) │     │  (Hub)      │     │  (Region 2) │
└─────────────┘     └─────────────┘     └─────────────┘
```

- Deploy sebagai microservice
- Load balancer untuk UDP (sticky sessions jika perlu)
- Consider NAT traversal (ELARA) untuk hybrid cloud

### 2.3 Gateway Pattern

```
[Internal Legacy] ←→ [B4AE Gateway] ←→ [B4AE Network]
```

- Gateway menerjemahkan B4AE ↔ legacy protocol
- Lihat [GATEWAY_PROXY.md](GATEWAY_PROXY.md)

---

## 3. Hardening

### 3.1 Network

- Firewall: allow UDP hanya dari trusted peers
- VPN / private link untuk WAN
- Rate limiting di perimeter

### 3.2 Key Management

- Session keys di memory (B4AE default: zeroize)
- Long-term keys: HSM via `hsm-pkcs11` feature
- Key rotation: manual atau policy-based

### 3.3 Audit & Compliance

- Set `B4aeConfig::audit_sink` dengan implementasi `AuditSink` (mis. `MemoryAuditSink` atau custom sink ke SIEM)
- Events: HandshakeInitiated/Completed, SessionCreated/Closed, KeyRotation (peer/session di-hash untuk privacy)
- Export ke SIEM (Syslog, Splunk, Elastic) via custom sink
- Retention policy sesuai regulasi (GDPR, SOC2, dll)

### 3.4 Container / Orchestration

- Docker: lihat `Dockerfile`
- Kubernetes: deploy sebagai Deployment, Service (LoadBalancer/NodePort untuk UDP)
- Resource limits: CPU, memory
- Readiness/liveness: health check endpoint (tambah jika belum)

---

## 4. Monitoring

### Metrics (Rekomendasi)

| Metric              | Deskripsi                    |
|---------------------|------------------------------|
| `b4ae_sessions_active` | Jumlah session aktif      |
| `b4ae_handshakes_total` | Total handshake sukses/gagal |
| `b4ae_messages_sent` | Pesan terkirim               |
| `b4ae_messages_received` | Pesan diterima          |
| `b4ae_handshake_duration_ms` | Latensi handshake    |

- Export via Prometheus (instrumentasi tracing/metrics)
- Grafana dashboard

### Logging

- `RUST_LOG=b4ae=info,tower=debug`
- Structured logs (JSON) untuk aggregation

---

## 5. Compliance Checklist

- [ ] **Encryption at rest**: disk encryption (LUKS, BitLocker)
- [ ] **Encryption in transit**: B4AE provides; ensure no plaintext leakage
- [ ] **Key management**: HSM atau secure key store
- [ ] **Audit trail**: AuditEvent → SIEM
- [ ] **Access control**: network ACL, principle of least privilege
- [ ] **Data retention**: policy untuk session logs, audit logs
- [ ] **Incident response**: runbook untuk key compromise, node breach

---

## 6. Rollout Plan

1. **Phase 1: POC** — Single node, internal only
2. **Phase 2: Pilot** — Limited users, one region
3. **Phase 3: Production** — Full rollout, monitoring
4. **Phase 4: Optimization** — Tuning, scaling

Lihat [PILOT_DEPLOYMENT_GUIDE.md](PILOT_DEPLOYMENT_GUIDE.md) untuk detail pilot.

---

## 7. Referensi

- [Production Deployment](PRODUCTION_DEPLOYMENT.md)
- [Pilot Deployment Guide](PILOT_DEPLOYMENT_GUIDE.md)
- [Security Audit Checklist](SECURITY_AUDIT_CHECKLIST.md)
- [Performance](PERFORMANCE.md)
