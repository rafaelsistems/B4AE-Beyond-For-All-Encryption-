# B4AE API Design and Documentation v1.0

**Version:** 1.0  
**Date:** February 2026  
**Status:** Implemented (Core API) / Roadmap (Extended API)  
**Protocol Spec:** [B4AE Protocol Specification v1.0](B4AE_Protocol_Specification_v1.0.md)

## Implementation Status

| API Area | Status | Notes |
|----------|--------|-------|
| **B4aeClient** (handshake, encrypt/decrypt) | Implemented | Manual handshake flow + `encrypt_message` / `decrypt_message` |
| **B4aeClient cleanup** | Implemented | `cleanup_inactive_sessions(secs)`, `cleanup_stale_handshakes()`, `cleanup_old_state()` |
| **B4aeConfig** | Implemented | `security_profile`, `crypto_config`, `protocol_config`, `handshake_config`, `audit_sink` |
| **Metadata protection** | Implemented | Padding, timing, dummy, metadata_key MAC di `encrypt_message` (return `Vec<EncryptedMessage>`) |
| **Audit** | Implemented | `B4aeConfig.audit_sink`, log ke handshake/session/key rotation |
| **Key hierarchy** | Implemented | MIK, DMK, STK, BKS; BKS 2-of-2 dengan HMAC-SHA256; export/import |
| **Dummy/timing helpers** | Implemented | `should_generate_dummy()`, `encrypt_dummy_message()`, `timing_delay_ms()` |
| **Encrypted storage** | Implemented | `storage::EncryptedStorage` (STK + AES-GCM), `StorageBackend` trait |
| **Key store** | Implemented | `key_store::KeyStore` (persistent MIK dengan passphrase) |
| **Onion routing** | Implemented | `crypto::onion` (onion_encrypt, onion_decrypt_layer) |
| **IP anonymization** | Implemented | `ProtocolConfig::anonymization.proxy_url`; B4aeElaraNode + feature `proxy` |
| **ELARA transport** | Implemented | ElaraTransport, B4aeElaraNode; feature `elara` |
| **Proxy (SOCKS5)** | Implemented | ProxyElaraTransport; feature `proxy`; proxy_url di B4aeConfig |
| **connect() / session.send_text()** | Roadmap | Higher-level session API planned |
| **generate_identity()** | Roadmap | Identity/backup features planned |
| **Group chat, file transfer** | Examples | `b4ae_chat_demo`, `b4ae_file_transfer_demo` (custom apps) |
| **Platform SDK** | Implemented | Default: `generateKey`, `encrypt`, `decrypt`. Full: `b4ae-ffi --features full-protocol` |

See [docs/PLATFORM_SDK.md](../docs/PLATFORM_SDK.md) for bindings. Sections below document both current and target API.

## 1. API OVERVIEW

### 1.1 Design Principles
- **Simple**: Easy to integrate with minimal code
- **Secure by Default**: Best security practices enabled automatically
- **Cross-Platform**: Consistent API across all platforms
- **Async-First**: Non-blocking operations for better performance
- **Type-Safe**: Strong typing to prevent errors

### 1.2 API Layers
```
┌─────────────────────────────────────────────────────────┐
│ Application Layer                                       │
│ (User Application Code)                                 │
├─────────────────────────────────────────────────────────┤
│ High-Level API                                          │
│ - B4aeClient                                            │
│ - Session Management                                    │
│ - Message Operations                                    │
├─────────────────────────────────────────────────────────┤
│ Mid-Level API                                           │
│ - Protocol Operations                                   │
│ - Key Management                                        │
│ - Metadata Protection                                   │
├─────────────────────────────────────────────────────────┤
│ Low-Level API                                           │
│ - Cryptographic Primitives                              │
│ - Network Transport                                     │
│ - Storage Operations                                    │
└─────────────────────────────────────────────────────────┘
```

## 2. HIGH-LEVEL API

### 2.1 Client Initialization

#### Rust API (Current Implementation)
```rust
use b4ae::{B4aeClient, SecurityProfile, B4aeConfig};

// Simple initialization with security profile
let client = B4aeClient::new(SecurityProfile::Standard)?;

// Advanced initialization with custom config
let config = B4aeConfig::from_profile(SecurityProfile::High);
let client = B4aeClient::with_config(config)?;

// B4aeConfig fields: security_profile, crypto_config, protocol_config, handshake_config, audit_sink
```

#### Current Rust Handshake & Messaging (Implemented)
```rust
use b4ae::prelude::*;

let mut alice = B4aeClient::new(SecurityProfile::Standard)?;
let mut bob = B4aeClient::new(SecurityProfile::Standard)?;
let alice_id = b"alice".to_vec();
let bob_id = b"bob".to_vec();

// Handshake (manual steps)
let init = alice.initiate_handshake(&bob_id)?;
let response = bob.respond_to_handshake(&alice_id, init)?;
let complete = alice.process_response(&bob_id, response)?;
bob.complete_handshake(&alice_id, complete)?;
alice.finalize_initiator(&bob_id)?;

// Encrypt/decrypt (returns Vec — may include dummy + real for metadata protection)
let encrypted_list = alice.encrypt_message(&bob_id, b"Hello!")?;
let mut decrypted = vec![];
for enc in &encrypted_list {
    let d = bob.decrypt_message(&alice_id, enc)?;
    if !d.is_empty() { decrypted = d; }
}
```

#### Swift API (iOS/macOS)
```swift
import B4AE

// Simple initialization
let client = try B4AEClient(securityProfile: .standard)

// Advanced initialization
let config = B4AEConfig(
    securityProfile: .high,
    metadataProtection: true,
    enableDummyTraffic: true,
    storagePath: "/path/to/storage"
)
let client = try B4AEClient(config: config)
```

#### Kotlin API (Android)
```kotlin
import org.b4ae.B4AEClient
import org.b4ae.SecurityProfile

// Simple initialization
val client = B4AEClient(SecurityProfile.STANDARD)

// Advanced initialization
val config = B4AEConfig.Builder()
    .securityProfile(SecurityProfile.HIGH)
    .metadataProtection(true)
    .enableDummyTraffic(true)
    .storagePath("/path/to/storage")
    .build()
val client = B4AEClient(config)
```

#### TypeScript API (Web)
```typescript
import { B4AEClient, SecurityProfile } from 'b4ae-web';

// Simple initialization
const client = new B4AEClient(SecurityProfile.Standard);

// Advanced initialization
const config = {
    securityProfile: SecurityProfile.High,
    metadataProtection: true,
    enableDummyTraffic: true,
    storagePath: '/path/to/storage'
};
const client = new B4AEClient(config);
```

### 2.2 Identity Management [Roadmap]

*The following APIs (2.2–2.6) are target design. Use the handshake + encrypt/decrypt flow above for now.*

#### Create Identity
```rust
// Generate new identity
let identity = client.generate_identity().await?;
println!("Identity ID: {}", identity.id());

// Export identity for backup
let backup = identity.export_encrypted("password")?;
std::fs::write("identity_backup.b4ae", backup)?;

// Import identity from backup
let identity = Identity::import_encrypted(&backup, "password")?;
client.set_identity(identity)?;
```

#### Identity Verification
```rust
// Get identity fingerprint for verification
let fingerprint = identity.fingerprint();
println!("Fingerprint: {}", fingerprint.to_hex());

// Verify another user's identity
let verified = client.verify_identity(
    &peer_id,
    &peer_fingerprint
).await?;
```

### 2.3 Session Management

#### Establish Session
```rust
// Connect to peer
let session = client.connect(&peer_id).await?;

// Connect with custom options
let options = ConnectOptions {
    timeout: Duration::from_secs(30),
    retry_attempts: 3,
    security_profile: SecurityProfile::Maximum,
};
let session = client.connect_with_options(&peer_id, options).await?;
```

#### Session Operations
```rust
// Get session info
let info = session.info();
println!("Session ID: {}", info.id);
println!("Peer: {}", info.peer_id);
println!("Established: {}", info.established_at);

// Check session status
if session.is_active() {
    println!("Session is active");
}

// Close session
session.close().await?;
```

### 2.4 Message Operations

#### Send Message
```rust
// Send text message
session.send_text("Hello, B4AE!").await?;

// Send binary data
let data = vec![0u8; 1024];
session.send_bytes(&data).await?;

// Send with metadata
let message = Message::new()
    .text("Important message")
    .priority(Priority::High)
    .expires_in(Duration::from_hours(24));
session.send(message).await?;
```

#### Receive Message
```rust
// Receive next message
let message = session.receive().await?;
match message.content() {
    MessageContent::Text(text) => println!("Text: {}", text),
    MessageContent::Binary(data) => println!("Binary: {} bytes", data.len()),
}

// Receive with timeout
let message = session.receive_timeout(Duration::from_secs(30)).await?;

// Stream messages
let mut stream = session.message_stream();
while let Some(message) = stream.next().await {
    println!("Received: {:?}", message);
}
```

### 2.5 File Transfer
```rust
// Send file
let file_path = Path::new("document.pdf");
let transfer = session.send_file(file_path).await?;

// Monitor progress
while !transfer.is_complete() {
    let progress = transfer.progress();
    println!("Progress: {}%", progress.percentage());
    tokio::time::sleep(Duration::from_millis(100)).await;
}

// Receive file
let transfer = session.receive_file().await?;
transfer.save_to("received_document.pdf").await?;
```

### 2.6 Group Communication
```rust
// Create group
let group = client.create_group("My Group").await?;

// Add members
group.add_member(&peer_id1).await?;
group.add_member(&peer_id2).await?;

// Send group message
group.send_text("Hello, everyone!").await?;

// Receive group messages
let mut stream = group.message_stream();
while let Some(message) = stream.next().await {
    println!("From {}: {}", message.sender(), message.text());
}
```

## 3. MID-LEVEL API

### 3.1 Protocol Operations

#### Handshake
```rust
use b4ae::protocol::{Handshake, HandshakeConfig};

// Perform handshake
let config = HandshakeConfig::default();
let handshake = Handshake::new(config);
let session_keys = handshake.perform(&peer_public_key).await?;
```

#### Key Exchange
```rust
use b4ae::crypto::hybrid;

// Generate key pair
let keypair = hybrid::keypair()?;

// Encapsulate (sender side)
let (shared_secret, ciphertext) = hybrid::encapsulate(&peer_public_key)?;

// Decapsulate (receiver side)
let shared_secret = hybrid::decapsulate(&secret_key, &ciphertext)?;
```

### 3.2 Key Management

#### Key Rotation
```rust
// Manual key rotation
session.rotate_keys().await?;

// Automatic rotation configuration
let rotation_policy = KeyRotationPolicy {
    time_based: Some(Duration::from_hours(24)),
    message_based: Some(10_000),
    data_based: Some(1_000_000_000), // 1GB
};
session.set_rotation_policy(rotation_policy)?;
```

#### Key Backup
```rust
// Backup keys with encryption
let backup = client.backup_keys("strong_password")?;
std::fs::write("keys_backup.b4ae", backup)?;

// Restore keys
let backup = std::fs::read("keys_backup.b4ae")?;
client.restore_keys(&backup, "strong_password")?;
```

### 3.3 Metadata Protection

#### Configure Protection
```rust
use b4ae::metadata::{ProtectionLevel, MetadataConfig};

// Set protection level
let config = MetadataConfig {
    level: ProtectionLevel::High,
    padding_block_size: 16384,
    max_timing_delay_ms: 5000,
    dummy_traffic_percent: 20,
};
session.set_metadata_config(config)?;
```

## 4. LOW-LEVEL API

### 4.1 Cryptographic Primitives

#### Kyber Operations
```rust
use b4ae::crypto::kyber;

// Generate keypair
let keypair = kyber::keypair()?;

// Encapsulate
let (shared_secret, ciphertext) = kyber::encapsulate(&keypair.public_key)?;

// Decapsulate
let shared_secret = kyber::decapsulate(&keypair.secret_key, &ciphertext)?;
```

#### Dilithium Operations
```rust
use b4ae::crypto::dilithium;

// Generate keypair
let keypair = dilithium::keypair()?;

// Sign message
let signature = dilithium::sign(&keypair.secret_key, message)?;

// Verify signature
let valid = dilithium::verify(&keypair.public_key, message, &signature)?;
```

#### AES-GCM Operations
```rust
use b4ae::crypto::aes_gcm;

// Generate key
let key = aes_gcm::AesKey::generate();

// Encrypt
let (nonce, ciphertext) = aes_gcm::encrypt(&key, plaintext, aad)?;

// Decrypt
let plaintext = aes_gcm::decrypt(&key, &nonce, &ciphertext, aad)?;
```

## 5. ERROR HANDLING

### 5.1 Error Types
```rust
use b4ae::error::B4aeError;

match result {
    Ok(value) => println!("Success: {:?}", value),
    Err(B4aeError::CryptoError(msg)) => eprintln!("Crypto error: {}", msg),
    Err(B4aeError::NetworkError(msg)) => eprintln!("Network error: {}", msg),
    Err(B4aeError::AuthenticationFailed) => eprintln!("Authentication failed"),
    Err(e) => eprintln!("Error: {}", e),
}
```

### 5.2 Result Types
```rust
// Standard result type
pub type B4aeResult<T> = Result<T, B4aeError>;

// Usage
fn my_function() -> B4aeResult<Session> {
    let session = client.connect(&peer_id).await?;
    Ok(session)
}
```

## 6. CALLBACKS AND EVENTS

### 6.1 Event Listeners
```rust
// Register event listener
client.on_message(|message| {
    println!("New message: {:?}", message);
});

client.on_session_established(|session| {
    println!("Session established: {}", session.id());
});

client.on_error(|error| {
    eprintln!("Error occurred: {}", error);
});
```

### 6.2 Async Streams
```rust
// Message stream
let mut messages = session.message_stream();
while let Some(message) = messages.next().await {
    process_message(message);
}

// Event stream
let mut events = client.event_stream();
while let Some(event) = events.next().await {
    match event {
        Event::MessageReceived(msg) => handle_message(msg),
        Event::SessionEstablished(session) => handle_session(session),
        Event::Error(err) => handle_error(err),
    }
}
```

## 7. CONFIGURATION

### 7.1 Client Configuration
```rust
pub struct B4aeConfig {
    /// Security profile
    pub security_profile: SecurityProfile,
    
    /// Enable metadata protection
    pub metadata_protection: bool,
    
    /// Enable dummy traffic
    pub enable_dummy_traffic: bool,
    
    /// Storage path for keys and data
    pub storage_path: Option<PathBuf>,
    
    /// Network configuration
    pub network: NetworkConfig,
    
    /// Logging configuration
    pub logging: LoggingConfig,
}
```

### 7.2 Network Configuration
```rust
pub struct NetworkConfig {
    /// Connection timeout
    pub connect_timeout: Duration,
    
    /// Read timeout
    pub read_timeout: Duration,
    
    /// Maximum retry attempts
    pub max_retries: u32,
    
    /// Enable onion routing
    pub enable_onion_routing: bool,
    
    /// SOCKS5 proxy
    pub proxy: Option<ProxyConfig>,
}
```

## 8. PLATFORM-SPECIFIC APIS

### 8.1 iOS/macOS (Swift)
```swift
// Delegate pattern
class MyDelegate: B4AEClientDelegate {
    func client(_ client: B4AEClient, didReceiveMessage message: B4AEMessage) {
        print("Received: \(message.text)")
    }
    
    func client(_ client: B4AEClient, didEstablishSession session: B4AESession) {
        print("Session established")
    }
}

client.delegate = MyDelegate()
```

### 8.2 Android (Kotlin)
```kotlin
// Listener pattern
client.setMessageListener { message ->
    println("Received: ${message.text}")
}

client.setSessionListener { session ->
    println("Session established: ${session.id}")
}
```

### 8.3 Web (TypeScript)
```typescript
// Promise-based API
client.connect(peerId)
    .then(session => {
        return session.sendText("Hello!");
    })
    .then(() => {
        console.log("Message sent");
    })
    .catch(error => {
        console.error("Error:", error);
    });

// Async/await
async function sendMessage() {
    try {
        const session = await client.connect(peerId);
        await session.sendText("Hello!");
        console.log("Message sent");
    } catch (error) {
        console.error("Error:", error);
    }
}
```

## 9. BEST PRACTICES

### 9.1 Resource Management
```rust
// Use RAII for automatic cleanup
{
    let session = client.connect(&peer_id).await?;
    // Use session
} // Session automatically closed here

// Explicit cleanup
let session = client.connect(&peer_id).await?;
// ... use session ...
session.close().await?;
```

### 9.2 Error Handling
```rust
// Always handle errors
match client.connect(&peer_id).await {
    Ok(session) => {
        // Handle success
    }
    Err(e) => {
        // Handle error appropriately
        log::error!("Connection failed: {}", e);
        // Retry or notify user
    }
}
```

### 9.3 Security
```rust
// Always verify peer identity
let fingerprint = session.peer_fingerprint();
if !verify_fingerprint_with_user(fingerprint) {
    session.close().await?;
    return Err(B4aeError::AuthenticationFailed);
}

// Use appropriate security profile
let session = client.connect_with_options(
    &peer_id,
    ConnectOptions {
        security_profile: SecurityProfile::Maximum,
        ..Default::default()
    }
).await?;
```

## 10. EXAMPLES

### 10.1 Simple Chat Application
```rust
use b4ae::{B4aeClient, SecurityProfile};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize client
    let client = B4aeClient::new(SecurityProfile::Standard)?;
    
    // Generate or load identity
    let identity = client.generate_identity().await?;
    println!("My ID: {}", identity.id());
    
    // Connect to peer
    let peer_id = "peer_id_here";
    let session = client.connect(peer_id).await?;
    
    // Send message
    session.send_text("Hello!").await?;
    
    // Receive messages
    let mut stream = session.message_stream();
    while let Some(message) = stream.next().await {
        println!("Received: {}", message.text());
    }
    
    Ok(())
}
```

### 10.2 File Transfer Application
```rust
use b4ae::{B4aeClient, SecurityProfile};
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = B4aeClient::new(SecurityProfile::High)?;
    let session = client.connect("peer_id").await?;
    
    // Send file
    let file = Path::new("document.pdf");
    let transfer = session.send_file(file).await?;
    
    // Monitor progress
    while !transfer.is_complete() {
        println!("Progress: {}%", transfer.progress().percentage());
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    println!("File sent successfully!");
    Ok(())
}
```

---

**B4AE API Design v1.0**  
**Copyright © 2026 B4AE Team**  
**License: MIT OR Apache-2.0**
