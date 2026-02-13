//! B4AE Message Protocol Implementation (Protocol Specification v1.0 §5, §7)
//!
//! Secure message encryption and decryption.

use crate::crypto::{CryptoError, CryptoResult};
use crate::crypto::aes_gcm::{self, AesKey};
use crate::crypto::pfs_plus::PfsSession;
use crate::protocol::MessageType;
use crate::time;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Message priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessagePriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Urgent = 3,
}

/// Message content types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    /// Text message
    Text(String),
    /// Binary data
    Binary(Vec<u8>),
    /// File transfer
    File {
        filename: String,
        mime_type: String,
        data: Vec<u8>,
    },
    /// Dummy traffic (metadata obfuscation — discard by recipient)
    Dummy,
}

/// B4AE encrypted message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// Protocol version
    pub version: u16,
    /// Message type
    pub message_type: u8,
    /// Message flags
    pub flags: u8,
    /// Sequence number
    pub sequence: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Encrypted payload
    pub payload: Vec<u8>,
    /// Authentication tag (included in payload for AES-GCM)
    pub nonce: Vec<u8>,
}

/// B4AE plaintext message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message content
    pub content: MessageContent,
    /// Message priority
    pub priority: MessagePriority,
    /// Sender ID
    pub sender_id: Option<Vec<u8>>,
    /// Recipient ID
    pub recipient_id: Option<Vec<u8>>,
    /// Metadata
    pub metadata: Vec<(String, String)>,
    /// Expiration time (Unix timestamp)
    pub expires_at: Option<u64>,
}

/// Message flags
pub mod flags {
    pub const ENCRYPTED: u8 = 0b00000001;
    pub const COMPRESSED: u8 = 0b00000010;
    pub const DUMMY_TRAFFIC: u8 = 0b00000100;
    pub const REQUIRES_ACK: u8 = 0b00001000;
}

impl Message {
    /// Create new message
    pub fn new(content: MessageContent) -> Self {
        Message {
            content,
            priority: MessagePriority::Normal,
            sender_id: None,
            recipient_id: None,
            metadata: Vec::new(),
            expires_at: None,
        }
    }

    /// Create text message
    pub fn text(text: impl Into<String>) -> Self {
        Self::new(MessageContent::Text(text.into()))
    }

    /// Create binary message
    pub fn binary(data: Vec<u8>) -> Self {
        Self::new(MessageContent::Binary(data))
    }

    /// Set priority
    pub fn with_priority(mut self, priority: MessagePriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set expiration
    pub fn with_expiration(mut self, expires_in_secs: u64) -> Self {
        self.expires_at = Some(time::current_time_secs().saturating_add(expires_in_secs));
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.push((key, value));
        self
    }

    /// Check if message is expired
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| time::current_time_secs() > exp)
            .unwrap_or(false)
    }

    /// Serialize message to bytes
    pub fn to_bytes(&self) -> CryptoResult<Vec<u8>> {
        let bytes = bincode::serialize(self)
            .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;
        if bytes.len() > crate::MAX_MESSAGE_SIZE {
            return Err(CryptoError::InvalidInput(format!(
                "Serialized message too large: {} > {}",
                bytes.len(),
                crate::MAX_MESSAGE_SIZE
            )));
        }
        Ok(bytes)
    }

    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() > crate::MAX_MESSAGE_SIZE {
            return Err(CryptoError::InvalidInput(format!(
                "Input too large for deserialize: {} > {}",
                bytes.len(),
                crate::MAX_MESSAGE_SIZE
            )));
        }
        bincode::deserialize(bytes)
            .map_err(|e| CryptoError::InvalidInput(e.to_string()))
    }
}

/// Maximum number of sequences to track for replay protection
const REPLAY_WINDOW_SIZE: usize = 4096;

/// Message encryptor/decryptor with replay protection
pub struct MessageCrypto {
    /// PFS+ session for key management
    pfs_session: PfsSession,
    /// Sequence counter (send side)
    sequence: u64,
    /// Received sequence numbers (replay detection; bounded sliding window)
    received_sequences: BTreeSet<u64>,
}

impl MessageCrypto {
    /// Create new message crypto
    pub fn new(pfs_session: PfsSession) -> Self {
        MessageCrypto {
            pfs_session,
            sequence: 0,
            received_sequences: BTreeSet::new(),
        }
    }

    /// Encrypt message
    pub fn encrypt(&mut self, message: &Message) -> CryptoResult<EncryptedMessage> {
        // Check if message is expired
        if message.is_expired() {
            return Err(CryptoError::InvalidInput("Message expired".to_string()));
        }

        // Serialize message
        let plaintext = message.to_bytes()?;
        if plaintext.len() > crate::MAX_MESSAGE_SIZE {
            return Err(CryptoError::InvalidInput(format!(
                "Message too large: {} > {}",
                plaintext.len(),
                crate::MAX_MESSAGE_SIZE
            )));
        }

        // Get next encryption key from PFS+
        let message_key = self.pfs_session.next_send_key()?;
        let aes_key = AesKey::from_bytes(&message_key)?;

        // Encrypt with AES-256-GCM
        let (nonce, ciphertext) = aes_gcm::encrypt(&aes_key, &plaintext, b"")?;

        let timestamp = time::current_time_secs();

        // Create encrypted message
        let encrypted = EncryptedMessage {
            version: crate::PROTOCOL_VERSION,
            message_type: MessageType::DataMessage as u8,
            flags: flags::ENCRYPTED,
            sequence: self.sequence,
            timestamp,
            payload: ciphertext,
            nonce,
        };

        // Increment sequence; reject if at limit (caller should rotate session before u64::MAX)
        if self.sequence == u64::MAX {
            return Err(CryptoError::InvalidInput(
                "Sequence limit reached; rotate session".to_string(),
            ));
        }
        self.sequence += 1;

        Ok(encrypted)
    }

    /// Decrypt message (with replay protection)
    pub fn decrypt(&mut self, encrypted: &EncryptedMessage) -> CryptoResult<Message> {
        // Verify version
        if encrypted.version != crate::PROTOCOL_VERSION {
            return Err(CryptoError::InvalidInput("Invalid protocol version".to_string()));
        }

        // Check if encrypted flag is set
        if encrypted.flags & flags::ENCRYPTED == 0 {
            return Err(CryptoError::InvalidInput("Message not encrypted".to_string()));
        }

        // Replay protection: reject duplicate sequence
        if self.received_sequences.contains(&encrypted.sequence) {
            return Err(CryptoError::DecryptionFailed(
                "Replay attack detected: duplicate sequence".to_string(),
            ));
        }

        if encrypted.payload.len() > crate::MAX_MESSAGE_SIZE {
            return Err(CryptoError::InvalidInput(format!(
                "Payload too large: {} > {}",
                encrypted.payload.len(),
                crate::MAX_MESSAGE_SIZE
            )));
        }

        // Get decryption key from PFS+
        let message_key = self.pfs_session.get_receive_key(encrypted.sequence)?
            .ok_or_else(|| CryptoError::DecryptionFailed("Key not available".to_string()))?;
        
        let aes_key = AesKey::from_bytes(&message_key)?;

        // Decrypt with AES-256-GCM
        let plaintext = aes_gcm::decrypt(&aes_key, &encrypted.nonce, &encrypted.payload, b"")?;

        // If dummy traffic, return Dummy message (recipient discards)
        if encrypted.flags & flags::DUMMY_TRAFFIC != 0 {
            self.record_sequence(encrypted.sequence);
            return Ok(Message::new(MessageContent::Dummy));
        }

        // Deserialize message
        let message = Message::from_bytes(&plaintext)?;

        // Check expiration
        if message.is_expired() {
            return Err(CryptoError::InvalidInput("Message expired".to_string()));
        }

        self.record_sequence(encrypted.sequence);
        Ok(message)
    }

    fn record_sequence(&mut self, seq: u64) {
        self.received_sequences.insert(seq);
        if self.received_sequences.len() > REPLAY_WINDOW_SIZE {
            if let Some(&min) = self.received_sequences.iter().next() {
                self.received_sequences.remove(&min);
            }
        }
    }

    /// Get current sequence number
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Get PFS+ session counters
    pub fn pfs_counters(&self) -> (u64, u64) {
        self.pfs_session.counters()
    }
}

/// Message builder for fluent API
pub struct MessageBuilder {
    message: Message,
}

impl MessageBuilder {
    /// Create new message builder
    pub fn new() -> Self {
        MessageBuilder {
            message: Message::new(MessageContent::Text(String::new())),
        }
    }

    /// Set text content
    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.message.content = MessageContent::Text(text.into());
        self
    }

    /// Set binary content
    pub fn binary(mut self, data: Vec<u8>) -> Self {
        self.message.content = MessageContent::Binary(data);
        self
    }

    /// Set file content
    pub fn file(mut self, filename: String, mime_type: String, data: Vec<u8>) -> Self {
        self.message.content = MessageContent::File {
            filename,
            mime_type,
            data,
        };
        self
    }

    /// Set priority
    pub fn priority(mut self, priority: MessagePriority) -> Self {
        self.message.priority = priority;
        self
    }

    /// Set expiration
    pub fn expires_in(mut self, seconds: u64) -> Self {
        self.message.expires_at = Some(time::current_time_secs().saturating_add(seconds));
        self
    }

    /// Add metadata
    pub fn metadata(mut self, key: String, value: String) -> Self {
        self.message.metadata.push((key, value));
        self
    }

    /// Build the message
    pub fn build(self) -> Message {
        self.message
    }
}

impl Default for MessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_creation() {
        let message = Message::text("Hello, B4AE!");
        match message.content {
            MessageContent::Text(ref text) => assert_eq!(text, "Hello, B4AE!"),
            _ => panic!("Wrong content type"),
        }
    }

    #[test]
    fn test_message_builder() {
        let message = MessageBuilder::new()
            .text("Test message")
            .priority(MessagePriority::High)
            .expires_in(3600)
            .metadata("key".to_string(), "value".to_string())
            .build();

        assert_eq!(message.priority, MessagePriority::High);
        assert!(message.expires_at.is_some());
        assert_eq!(message.metadata.len(), 1);
    }

    #[test]
    fn test_message_expiration() {
        let mut message = Message::text("Test");
        message.expires_at = Some(0); // Already expired
        assert!(message.is_expired());

        let future = time::current_time_secs().saturating_add(3600);
        message.expires_at = Some(future);
        assert!(!message.is_expired());
    }

    #[test]
    fn test_message_serialization() {
        let message = Message::text("Hello, B4AE!");
        let bytes = message.to_bytes().unwrap();
        let deserialized = Message::from_bytes(&bytes).unwrap();

        match deserialized.content {
            MessageContent::Text(ref text) => assert_eq!(text, "Hello, B4AE!"),
            _ => panic!("Wrong content type"),
        }
    }

    #[test]
    #[cfg(feature = "liboqs")]
    fn test_message_encryption() {
        use crate::crypto::pfs_plus::PfsSession;

        // Create PFS+ session
        let send_key = [0x42; 32];
        let receive_key = [0x43; 32];
        let session_id = [0x44; 32];
        let pfs_session = PfsSession::new(&send_key, &receive_key, session_id).unwrap();

        // Create message crypto
        let mut crypto = MessageCrypto::new(pfs_session);

        // Create and encrypt message
        let message = Message::text("Secret message");
        let encrypted = crypto.encrypt(&message).unwrap();

        assert_eq!(encrypted.version, crate::PROTOCOL_VERSION);
        assert_eq!(encrypted.flags & flags::ENCRYPTED, flags::ENCRYPTED);
    }
}
