# B4AE + ELARA Integration

Dokumentasi integrasi B4AE (quantum-resistant crypto, [Protocol Specification v1.0](../specs/B4AE_Protocol_Specification_v1.0.md)) dengan [ELARA Protocol](https://github.com/rafaelsistems/ELARA-Protocol) (UDP transport).

## Overview

| Komponen | Sumber | Peran |
|----------|--------|-------|
| **Kriptografi** | B4AE | Kyber-1024, Dilithium5, Hybrid, AES-256-GCM |
| **Protokol** | B4AE | Handshake, Session, Message encryption |
| **Transport** | ELARA | UDP, packet delivery, chunking (MAX_PACKET_SIZE=1400) |
| **Proxy** | B4AE (socks) | SOCKS5 UDP ASSOCIATE untuk IP anonymization (Tor) |

## Feature Flags

| Feature | Dependency | Deskripsi |
|---------|------------|-----------|
| `elara` | elara-transport, tokio | ElaraTransport, B4aeElaraNode |
| `proxy` | socks, elara | ProxyElaraTransport via SOCKS5 |

## Build

```bash
# Clone dengan submodule
git clone --recursive https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-.git
cd B4AE-Beyond-For-All-Encryption-

# Build dengan ELARA transport
cargo build --features elara

# Build dengan proxy (SOCKS5/Tor)
cargo build --features "elara proxy"
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

**Peer ID = peer address** (e.g. `"127.0.0.1:8080"`). Session dikunci oleh `peer_addr`. `connect()`, `send_message()`, `recv_message()` harus memakai alamat yang sama.

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

### B4aeElaraNode dengan Proxy (SOCKS5/Tor)

```rust
use b4ae::{B4aeClient, B4aeConfig};
use b4ae::elara_node::B4aeElaraNode;
use b4ae::protocol::SecurityProfile;

let mut config = B4aeConfig::from_profile(SecurityProfile::Maximum);
config.protocol_config.anonymization.proxy_url =
    Some("socks5://127.0.0.1:9050".into());

let node = B4aeElaraNode::new_with_config("127.0.0.1:0", config).await?;
```

Requires `--features "elara proxy"`.

## Chunking

Payload > MAX_PACKET_SIZE (1400 bytes) otomatis di-chunk. Format:
- **Single:** `[0x00][data]`
- **Multi START:** `[0x01 total_len(4) chunk_id(2)][data]`
- **Multi CONT:** `[0x02 chunk_id(2)][data]`

**MAX_REASSEMBLY_SIZE** ≈ 90 KB (DoS mitigation). Bincode deserialize limit: 128 KB.

## Demo

```bash
cargo run --example b4ae_elara_demo --features elara
```

Output: Alice dan Bob melakukan handshake quantum-resistant dan bertukar pesan via UDP.
