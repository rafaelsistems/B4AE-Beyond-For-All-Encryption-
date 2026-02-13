# B4AE + ELARA Integration

Dokumentasi integrasi B4AE (quantum-resistant crypto) dengan [ELARA Protocol](https://github.com/rafaelsistems/ELARA-Protocol) (UDP transport).

## Overview

| Komponen | Sumber | Peran |
|----------|--------|-------|
| **Kriptografi** | B4AE | Kyber-1024, Dilithium5, Hybrid, AES-256-GCM |
| **Protokol** | B4AE | Handshake, Session, Message encryption |
| **Transport** | ELARA | UDP, packet delivery, chunking |

## Build

```bash
# Clone dengan submodule
git clone --recursive https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-.git
cd B4AE-Beyond-For-All-Encryption-

# Build dengan feature elara
cargo build --features elara
```

## API

### ElaraTransport

```rust
use b4ae::transport::elara::ElaraTransport;

let transport = ElaraTransport::bind("127.0.0.1:0").await?;
transport.send_to("127.0.0.1:8080", &data).await?;
let (data, from) = transport.recv_from().await?;
```

### B4aeElaraNode

```rust
use b4ae::elara_node::B4aeElaraNode;
use b4ae::protocol::SecurityProfile;

let mut node = B4aeElaraNode::new("127.0.0.1:0", SecurityProfile::Standard).await?;

// Initiator
node.connect("127.0.0.1:8080").await?;
node.send_message("127.0.0.1:8080", b"Hello!").await?;

// Responder
let peer = node.accept().await?;
let (from, plaintext) = node.recv_message().await?;
```

## Chunking

Payload > 1400 bytes otomatis di-chunk. Format:
- Single: `[0x00][data]`
- Multi: `[0x01 total_len chunk_id][data]` + `[0x02 chunk_id][data]`...

## Demo

```bash
cargo run --example b4ae_elara_demo --features elara
```

Output: Alice dan Bob melakukan handshake quantum-resistant dan bertukar pesan via UDP.
