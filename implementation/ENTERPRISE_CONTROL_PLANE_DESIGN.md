# Enterprise Control Plane — MVP Design

Desain MVP untuk commercial layer: dashboard, compliance reporting, audit analytics.

---

## Scope (Commercial — Closed Source)

| Komponen | Deskripsi |
|----------|-----------|
| Key lifecycle dashboard | View, rotate, export keys |
| Compliance reporting UI | GDPR, HIPAA, ISO 27001 reports |
| Audit analytics | Query, filter, export AuditSink events |
| Centralized policy engine | Role-based key governance, retention |
| Admin control plane | User/role management |

---

## Boundary (Critical)

| OPEN (B4AE core) | CLOSED (Enterprise product) |
|------------------|-----------------------------|
| AuditSink API, event format | Dashboard UI |
| Key store, export/import | Policy engine UI |
| Protocol, crypto | Managed hosting |

**Never lock crypto core.**

---

## MVP Features (Q2 Target)

### Phase 1
- [ ] REST API untuk query AuditSink events
- [ ] Simple web dashboard (auth, event list, export CSV)
- [ ] Key rotation trigger via API

### Phase 2
- [ ] Compliance report templates (GDPR Art. 32, HIPAA)
- [ ] Role-based access (admin, viewer, auditor)
- [ ] Policy: retention, key expiration

### Phase 3
- [ ] Integrasi dengan SIEM (Syslog, Splunk)
- [ ] SLA monitoring, alerting

---

## Tech Stack (Sugesti)

- Backend: Rust (Actix/Axum) atau Node
- Frontend: React / Svelte
- Auth: OAuth2, JWT
- DB: PostgreSQL untuk audit log

---

## Pricing Model (Draft)

- Starter: $499/month — 1 tenant, basic dashboard
- Business: $2,000/month — multi-tenant, compliance reports
- Enterprise: Custom — SLA, dedicated support

Lihat [HYBRID_MODEL_STRATEGY.md](HYBRID_MODEL_STRATEGY.md) untuk detail.
