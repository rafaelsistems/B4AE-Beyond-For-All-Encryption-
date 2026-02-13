// B4AE Session Management Implementation
// Manages secure communication sessions

use crate::audit::{AuditEntry, AuditEvent, AuditSink, hash_for_audit};
use crate::crypto::{CryptoError, CryptoResult};
use crate::crypto::pfs_plus::{PfsSession, PfsManager};
use crate::crypto::hybrid::HybridPublicKey;
use crate::crypto::hkdf;
use crate::protocol::message::{Message, MessageCrypto, EncryptedMessage};
use crate::protocol::handshake::{HandshakeResult, SessionKeys};
use crate::protocol::message::flags;
use crate::error::B4aeResult;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is being established
    Establishing,
    /// Session is active
    Active,
    /// Session is closing
    Closing,
    /// Session is closed
    Closed,
    /// Session has error
    Error,
}

/// Session information
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session ID
    pub session_id: [u8; 32],
    /// Peer ID
    pub peer_id: Vec<u8>,
    /// Session state
    pub state: SessionState,
    /// Established timestamp
    pub established_at: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
}

/// B4AE Session
pub struct Session {
    /// Session ID
    session_id: [u8; 32],
    /// Peer's public key
    peer_public_key: HybridPublicKey,
    /// Session keys
    session_keys: SessionKeys,
    /// Message crypto (with PFS+)
    message_crypto: MessageCrypto,
    /// Session state
    state: SessionState,
    /// Session info
    info: SessionInfo,
    /// Key rotation policy
    rotation_policy: KeyRotationPolicy,
    /// Key rotation counter
    rotation_count: u64,
    /// Last rotation timestamp
    last_rotation_time: u64,
    /// Optional audit sink for key rotation events
    audit_sink: Option<Arc<dyn AuditSink>>,
}

/// Key rotation message untuk komunikasi dengan peer
#[derive(Debug, Clone)]
pub struct KeyRotationMessage {
    /// New encryption key (derived)
    pub new_key_material: Vec<u8>,
    /// Rotation sequence number
    pub rotation_sequence: u64,
    /// Timestamp
    pub timestamp: u64,
}

/// Key rotation policy
#[derive(Debug, Clone)]
pub struct KeyRotationPolicy {
    /// Rotate after this many seconds
    pub time_based: Option<u64>,
    /// Rotate after this many messages
    pub message_based: Option<u64>,
    /// Rotate after this many bytes
    pub data_based: Option<u64>,
}

impl Default for KeyRotationPolicy {
    fn default() -> Self {
        KeyRotationPolicy {
            time_based: Some(3600), // 1 hour
            message_based: Some(10_000),
            data_based: Some(1_000_000_000), // 1GB
        }
    }
}

impl Session {
    /// Create new session from handshake result
    pub fn from_handshake(
        handshake_result: HandshakeResult,
        peer_id: Vec<u8>,
        audit_sink: Option<Arc<dyn AuditSink>>,
    ) -> CryptoResult<Self> {
        // Create PFS+ session
        let pfs_session = PfsSession::new(
            &handshake_result.session_keys.encryption_key,
            &handshake_result.session_keys.encryption_key,
            handshake_result.session_id,
        )?;

        // Create message crypto
        let message_crypto = MessageCrypto::new(pfs_session);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let info = SessionInfo {
            session_id: handshake_result.session_id,
            peer_id: peer_id.clone(),
            state: SessionState::Active,
            established_at: now,
            last_activity: now,
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        };

        Ok(Session {
            session_id: handshake_result.session_id,
            peer_public_key: handshake_result.peer_public_key,
            session_keys: handshake_result.session_keys,
            message_crypto,
            state: SessionState::Active,
            info,
            rotation_policy: KeyRotationPolicy::default(),
            rotation_count: 0,
            last_rotation_time: now,
            audit_sink,
        })
    }

    /// Send message
    pub fn send(&mut self, message: &Message) -> CryptoResult<EncryptedMessage> {
        if self.state != SessionState::Active {
            return Err(CryptoError::InvalidInput("Session not active".to_string()));
        }

        // Encrypt message
        let encrypted = self.message_crypto.encrypt(message)?;

        // Update statistics
        self.info.messages_sent += 1;
        self.info.bytes_sent += encrypted.payload.len() as u64;
        self.update_activity();

        // Check if rotation needed and perform automatic rotation
        if self.needs_rotation() {
            if let Err(e) = self.perform_key_rotation() {
                warn!("Key rotation failed: {}", e);
            }
        }

        Ok(encrypted)
    }

    /// Send dummy message (metadata obfuscation). Same as send but sets DUMMY_TRAFFIC flag.
    pub fn send_dummy(&mut self, message: &Message) -> CryptoResult<EncryptedMessage> {
        if self.state != SessionState::Active {
            return Err(CryptoError::InvalidInput("Session not active".to_string()));
        }

        let mut encrypted = self.message_crypto.encrypt(message)?;
        encrypted.flags |= flags::DUMMY_TRAFFIC;
        self.info.messages_sent += 1;
        self.info.bytes_sent += encrypted.payload.len() as u64;
        self.update_activity();
        Ok(encrypted)
    }

    /// Perform key rotation - derives new session keys
    pub fn perform_key_rotation(&mut self) -> CryptoResult<KeyRotationMessage> {
        info!("Performing key rotation #{}", self.rotation_count + 1);
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Generate new key material using HKDF from current keys
        let rotation_context = format!("B4AE-v1-key-rotation-{}", self.rotation_count + 1);
        
        // Derive new encryption key
        let new_encryption_key = hkdf::derive_key(
            &[&self.session_keys.encryption_key, &self.rotation_count.to_be_bytes()],
            rotation_context.as_bytes(),
            32
        )?;
        
        // Derive new authentication key
        let new_auth_key = hkdf::derive_key(
            &[&self.session_keys.authentication_key, &self.rotation_count.to_be_bytes()],
            rotation_context.as_bytes(),
            32
        )?;
        
        // Derive new metadata key
        let new_metadata_key = hkdf::derive_key(
            &[&self.session_keys.metadata_key, &self.rotation_count.to_be_bytes()],
            rotation_context.as_bytes(),
            32
        )?;
        
        // Create new PFS+ session with rotated keys
        let new_pfs_session = PfsSession::new(
            &new_encryption_key,
            &new_encryption_key,
            self.session_id,
        )?;
        
        // Update session keys
        self.session_keys = SessionKeys {
            encryption_key: new_encryption_key.clone(),
            authentication_key: new_auth_key,
            metadata_key: new_metadata_key,
        };
        
        // Update message crypto
        self.message_crypto = MessageCrypto::new(new_pfs_session);
        
        // Update rotation tracking
        self.rotation_count += 1;
        self.last_rotation_time = now;
        
        // Reset counters for next rotation cycle
        self.info.messages_sent = 0;
        self.info.bytes_sent = 0;
        self.info.established_at = now;
        
        if let Some(sink) = &self.audit_sink {
            sink.log(AuditEntry::new(
                AuditEvent::KeyRotation {
                    session_id_hash: hash_for_audit(&self.session_id),
                },
                None,
            ));
        }
        
        info!("Key rotation #{} completed successfully", self.rotation_count);
        
        Ok(KeyRotationMessage {
            new_key_material: new_encryption_key,
            rotation_sequence: self.rotation_count,
            timestamp: now,
        })
    }

    /// Apply key rotation received from peer
    pub fn apply_peer_rotation(&mut self, rotation_msg: &KeyRotationMessage) -> CryptoResult<()> {
        info!("Applying peer key rotation #{}", rotation_msg.rotation_sequence);
        
        // Verify rotation sequence is expected
        if rotation_msg.rotation_sequence != self.rotation_count + 1 {
            return Err(CryptoError::InvalidInput(format!(
                "Unexpected rotation sequence: expected {}, got {}",
                self.rotation_count + 1,
                rotation_msg.rotation_sequence
            )));
        }
        
        // Generate matching keys using same derivation
        let rotation_context = format!("B4AE-v1-key-rotation-{}", rotation_msg.rotation_sequence);
        
        let new_encryption_key = hkdf::derive_key(
            &[&self.session_keys.encryption_key, &self.rotation_count.to_be_bytes()],
            rotation_context.as_bytes(),
            32
        )?;
        
        let new_auth_key = hkdf::derive_key(
            &[&self.session_keys.authentication_key, &self.rotation_count.to_be_bytes()],
            rotation_context.as_bytes(),
            32
        )?;
        
        let new_metadata_key = hkdf::derive_key(
            &[&self.session_keys.metadata_key, &self.rotation_count.to_be_bytes()],
            rotation_context.as_bytes(),
            32
        )?;
        
        // Create new PFS+ session
        let new_pfs_session = PfsSession::new(
            &new_encryption_key,
            &new_encryption_key,
            self.session_id,
        )?;
        
        // Update session
        self.session_keys = SessionKeys {
            encryption_key: new_encryption_key,
            authentication_key: new_auth_key,
            metadata_key: new_metadata_key,
        };
        self.message_crypto = MessageCrypto::new(new_pfs_session);
        self.rotation_count = rotation_msg.rotation_sequence;
        self.last_rotation_time = rotation_msg.timestamp;
        
        info!("Peer key rotation #{} applied successfully", self.rotation_count);
        
        Ok(())
    }

    /// Get rotation count
    pub fn rotation_count(&self) -> u64 {
        self.rotation_count
    }

    /// Get time since last rotation
    pub fn time_since_rotation(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.last_rotation_time)
    }

    /// Receive and decrypt message
    pub fn receive(&mut self, encrypted: &EncryptedMessage) -> CryptoResult<Message> {
        if self.state != SessionState::Active {
            return Err(CryptoError::InvalidInput("Session not active".to_string()));
        }

        // Decrypt message
        let message = self.message_crypto.decrypt(encrypted)?;

        // Update statistics
        self.info.messages_received += 1;
        self.info.bytes_received += encrypted.payload.len() as u64;
        self.update_activity();

        Ok(message)
    }

    /// Check if key rotation is needed
    pub fn needs_rotation(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check time-based rotation
        if let Some(time_limit) = self.rotation_policy.time_based {
            if now - self.info.established_at > time_limit {
                return true;
            }
        }

        // Check message-based rotation
        if let Some(message_limit) = self.rotation_policy.message_based {
            if self.info.messages_sent >= message_limit {
                return true;
            }
        }

        // Check data-based rotation
        if let Some(data_limit) = self.rotation_policy.data_based {
            if self.info.bytes_sent >= data_limit {
                return true;
            }
        }

        false
    }

    /// Set key rotation policy
    pub fn set_rotation_policy(&mut self, policy: KeyRotationPolicy) {
        self.rotation_policy = policy;
    }

    /// Get session info
    pub fn info(&self) -> &SessionInfo {
        &self.info
    }

    /// Get mutable session info (for tests / rotation policy simulation)
    pub fn info_mut(&mut self) -> &mut SessionInfo {
        &mut self.info
    }

    /// Get session ID
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Get peer public key
    pub fn peer_public_key(&self) -> &HybridPublicKey {
        &self.peer_public_key
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        self.state == SessionState::Active
    }

    /// Close session
    pub fn close(&mut self) {
        self.state = SessionState::Closed;
    }

    /// Update last activity timestamp
    fn update_activity(&mut self) {
        self.info.last_activity = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

/// Session manager for handling multiple sessions
pub struct SessionManager {
    /// Active sessions
    sessions: HashMap<[u8; 32], Session>,
    /// PFS+ manager (reserved for future key rotation)
    #[allow(dead_code)]
    pfs_manager: PfsManager,
    /// Session timeout (seconds)
    session_timeout: u64,
}

impl SessionManager {
    /// Create new session manager
    pub fn new() -> Self {
        SessionManager {
            sessions: HashMap::new(),
            pfs_manager: PfsManager::new(),
            session_timeout: 3600, // 1 hour default
        }
    }

    /// Add session
    pub fn add_session(&mut self, session: Session) -> B4aeResult<()> {
        let session_id = *session.session_id();
        self.sessions.insert(session_id, session);
        Ok(())
    }

    /// Get session
    pub fn get_session(&mut self, session_id: &[u8; 32]) -> Option<&mut Session> {
        self.sessions.get_mut(session_id)
    }

    /// Remove session
    pub fn remove_session(&mut self, session_id: &[u8; 32]) -> Option<Session> {
        self.sessions.remove(session_id)
    }

    /// Get all active sessions
    pub fn active_sessions(&self) -> Vec<&SessionInfo> {
        self.sessions
            .values()
            .filter(|s| s.is_active())
            .map(|s| s.info())
            .collect()
    }

    /// Cleanup inactive sessions
    pub fn cleanup_inactive(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.sessions.retain(|_, session| {
            let inactive_time = now - session.info.last_activity;
            inactive_time < self.session_timeout
        });
    }

    /// Check all sessions for rotation needs
    pub fn check_rotations(&self) -> Vec<[u8; 32]> {
        self.sessions
            .iter()
            .filter_map(|(id, session)| {
                if session.needs_rotation() {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Set session timeout
    pub fn set_timeout(&mut self, timeout_secs: u64) {
        self.session_timeout = timeout_secs;
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe session manager
pub type SharedSessionManager = Arc<Mutex<SessionManager>>;

/// Create shared session manager
pub fn create_shared_manager() -> SharedSessionManager {
    Arc::new(Mutex::new(SessionManager::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::handshake::HandshakeResult;

    fn create_test_handshake_result() -> HandshakeResult {
        let session_keys = SessionKeys {
            encryption_key: vec![0x42; 32],
            authentication_key: vec![0x43; 32],
            metadata_key: vec![0x44; 32],
        };

        HandshakeResult {
            master_secret: vec![0x45; 32],
            session_keys,
            peer_public_key: create_test_public_key(),
            session_id: [0x46; 32],
        }
    }

    fn create_test_public_key() -> HybridPublicKey {
        // Use correct sizes for X25519 (32 bytes) and Ed25519 (32 bytes)
        HybridPublicKey {
            ecdh_public: vec![0; 32],  // X25519 public key size
            kyber_public: crate::crypto::kyber::KyberPublicKey::from_bytes(&[0; 1568]).unwrap(),
            ecdsa_public: vec![0; 32],  // Ed25519 public key size
            dilithium_public: crate::crypto::dilithium::DilithiumPublicKey::from_bytes(&[0; 2592]).unwrap(),
        }
    }

    #[test]
    fn test_session_creation() {
        let handshake_result = create_test_handshake_result();
        let peer_id = vec![0x47; 32];
        
        let session = Session::from_handshake(handshake_result, peer_id, None).unwrap();
        assert!(session.is_active());
    }

    #[test]
    fn test_session_manager() {
        let mut manager = SessionManager::new();
        assert_eq!(manager.session_count(), 0);

        let handshake_result = create_test_handshake_result();
        let peer_id = vec![0x47; 32];
        let session = Session::from_handshake(handshake_result, peer_id, None).unwrap();
        let session_id = *session.session_id();

        manager.add_session(session).unwrap();
        assert_eq!(manager.session_count(), 1);

        let retrieved = manager.get_session(&session_id);
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_rotation_policy() {
        let mut policy = KeyRotationPolicy::default();
        policy.message_based = Some(100);

        let handshake_result = create_test_handshake_result();
        let peer_id = vec![0x47; 32];
        let mut session = Session::from_handshake(handshake_result, peer_id, None).unwrap();
        session.set_rotation_policy(policy);

        // Simulate sending messages
        session.info_mut().messages_sent = 101;
        assert!(session.needs_rotation());
    }

    #[test]
    fn test_session_cleanup() {
        let mut manager = SessionManager::new();
        manager.set_timeout(1); // 1 second timeout

        let handshake_result = create_test_handshake_result();
        let peer_id = vec![0x47; 32];
        let mut session = Session::from_handshake(handshake_result, peer_id, None).unwrap();
        
        // Set old activity time
        session.info_mut().last_activity = 0;
        manager.add_session(session).unwrap();

        assert_eq!(manager.session_count(), 1);
        manager.cleanup_inactive();
        assert_eq!(manager.session_count(), 0);
    }
}
