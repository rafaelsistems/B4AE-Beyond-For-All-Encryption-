# B4AE Plugin Architecture (Signal, Matrix, dll)

Arsitektur untuk mengintegrasikan B4AE sebagai plugin/extension ke protocol messaging existing.

---

## Overview

B4AE dapat diintegrasikan ke aplikasi messaging (Signal, Matrix, dll) melalui:

1. **Crypto Replacement Layer** — Ganti cryptographic layer dengan B4AE
2. **Transport Adapter** — B4AE sebagai transport opsional
3. **Plugin/Bridge** — Aplikasi standalone yang bridge B4AE ↔ protocol target

---

## 1. Signal Integration

### Pendekatan

Signal menggunakan Double Ratchet + X3DH. B4AE menggantikan dengan handshake hybrid + session keys.

| Signal Component   | B4AE Equivalent                |
|--------------------|---------------------------------|
| X3DH Key Agreement | B4AE Handshake (Kyber+ECDH)    |
| Double Ratchet     | B4AE Session + PFS+ rekey      |
| AES-256-CBC/HMAC   | AES-256-GCM (B4AE default)      |
| Curve25519         | x25519-dalek (B4AE hybrid)      |

### Integration Points

1. **Signal Protocol Library** — Fork atau wrap `libsignal`; inject B4AE sebagai crypto backend
2. **Signal Client** — Modify Signal-Android/Signal-iOS untuk pakai B4AE library via FFI/JNI
3. **Bridge App** — Aplikasi terpisah: terima dari Signal (decrypt), encrypt dengan B4AE, kirim ke B4AE peer

### Arsitektur Minimal (Bridge)

```
[Signal Client] → [Bridge: Signal decrypt] → [B4AE encrypt] → [B4AE Network]
[B4AE Network] → [Bridge: B4AE decrypt] → [Signal encrypt] → [Signal Client]
```

- Bridge memerlukan akses ke Signal key material (complex, possible via rooted/jailbreak atau official API jika ada)
- Lebih praktis: **standalone B4AE client** yang interoperate dengan B4AE-only users

---

## 2. Matrix Integration

### Pendekatan

Matrix menggunakan Olm/Megolm (double ratchet). B4AE dapat:

1. **Megolm Replacement** — Room encryption pakai B4AE session keys
2. **Transport** — Matrix over B4AE (B4AE-encrypted transport untuk Matrix HTTP/WebSocket)
3. **Custom Room Type** — `org.b4ae.encrypted` room type dengan B4AE crypto

### Integration Points

1. **matrix-rust-sdk** — Add crypto provider trait; implement B4AE as provider
2. **Client (Element)** — Build dengan B4AE crypto provider
3. **Server (Synapse)** — Optional: server-side B4AE support untuk federation

### Arsitektur (Crypto Provider)

```
[Matrix Client]
    → CryptoProvider trait
        → OlmMegolm (default)
        → B4aeCryptoProvider (optional)
            → B4aeClient (handshake, session, encrypt/decrypt)
```

---

## 3. Gateway / Proxy untuk Legacy Protocol

### Use Case

- Terjemahkan antara B4AE dan protocol lain (XMPP, SMTP, custom TCP)
- Enterprise: B4AE gateway di perimeter; internal pakai legacy

### Arsitektur

```
[Legacy Client] ↔ [Gateway] ↔ [B4AE Network]
                    │
                    ├─ Decrypt B4AE → forward plaintext ke legacy
                    └─ Encrypt plaintext → B4AE → forward ke B4AE peer
```

### Implementasi Minimal

- Binary: `b4ae-gateway --listen 0.0.0.0:8443 --backend tcp://internal:1234`
- Terima koneksi B4AE di port 8443
- Setelah handshake, proxy plaintext ke backend
- Lihat `examples/` untuk sketsa

---

## 4. Langkah Implementasi

### Phase 1: Standalone (Current)
- [x] B4AE core + ELARA transport
- [x] Chat demo, file transfer demo

### Phase 2: SDK & FFI
- [x] C FFI, JNI, WASM bindings
- [ ] Matrix crypto provider trait (Rust)
- [ ] Signal crypto interface (research)

### Phase 3: Bridge/Gateway
- [ ] Minimal TCP gateway (B4AE ↔ plain TCP)
- [ ] Konfigurasi: mappings, ACL

### Phase 4: Full Integration
- [ ] Matrix SDK plugin
- [ ] Signal bridge (jika feasible)

---

## 5. Referensi

- [Signal Protocol](https://signal.org/docs/)
- [Matrix Encryption (Olm/Megolm)](https://spec.matrix.org/unstable/client-server-api/#end-to-end-encryption)
- [B4AE Protocol Spec](../specs/B4AE_Protocol_Specification_v1.0.md)
- [ELARA Integration](ELARA_INTEGRATION.md)
