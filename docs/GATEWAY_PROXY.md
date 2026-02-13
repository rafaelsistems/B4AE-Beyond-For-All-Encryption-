# B4AE Gateway / Proxy

Desain dan implementasi gateway yang menjembatani B4AE dengan protocol atau backend lain.

---

## Overview

Gateway menerima koneksi B4AE (handshake + encrypted messages), melakukan decrypt, lalu forward ke backend (TCP, HTTP, dll). Sebaliknya untuk arah masuk dari backend.

---

## Arsitektur

```
                    ┌─────────────────┐
[B4AE Client] ─────►│                 │
                    │  B4AE Gateway   │─────► [Backend: TCP/HTTP/etc]
[B4AE Client] ◄─────│                 │◄─────
                    └─────────────────┘
```

### Komponen

1. **B4AE Listener** — Bind UDP (ELARA) atau TCP, terima handshake, maintain sessions
2. **Backend Connector** — Connect ke backend (TCP socket, HTTP client, dll)
3. **Message Router** — Map B4AE peer ID ↔ backend connection
4. **Config** — ACL, mappings, timeouts

---

## Use Cases

| Use Case              | B4AE Side     | Backend              |
|-----------------------|---------------|----------------------|
| Legacy TCP service    | B4AE clients  | Plain TCP server     |
| REST API              | B4AE clients  | HTTP/HTTPS upstream  |
| Message queue         | B4AE clients  | Redis/RabbitMQ       |
| Federation            | B4AE nodes    | B4AE nodes (relay)   |

---

## Implementasi Minimal

Contoh sketsa binary (bukan production-ready):

```rust
// Sketsa: gateway menerima B4AE, forward ke TCP backend
#[tokio::main]
async fn main() {
    let mut node = B4aeElaraNode::new("0.0.0.0:9000", SecurityProfile::Standard).await?;
    let backend = "127.0.0.1:8080"; // TCP backend

    loop {
        let peer = node.accept().await?;  // B4AE handshake
        let backend = backend.to_string();
        tokio::spawn(async move {
            // Forward: recv B4AE → write to TCP
            // Reverse: read TCP → send B4AE
            proxy_loop(node, peer, backend).await
        });
    }
}
```

Full implementation: lihat `examples/` atau crate `b4ae-gateway` (future).

---

## Konfigurasi (Contoh)

```yaml
# gateway.yaml (contoh)
listen: "0.0.0.0:9000"
backend:
  type: tcp
  addr: "127.0.0.1:8080"
acl:
  - peer_id_prefix: "allowed-"
  - deny_all: false
```

---

## Security Considerations

- Gateway memegang session keys; harus di-hardening (sandbox, minimal privileges)
- Backend communication: pakai TLS jika backend tidak trusted
- Rate limiting, connection limits
- Audit logging (B4AE `AuditEvent`)

---

## Referensi

- [B4AE Protocol](B4AE_Protocol_Specification_v1.0.md)
- [ELARA Integration](ELARA_INTEGRATION.md)
- [Production Deployment](PRODUCTION_DEPLOYMENT.md)
