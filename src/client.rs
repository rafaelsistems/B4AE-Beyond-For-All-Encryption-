// B4AE High-Level Client API
// Provides a simplified interface for common operations

use crate::crypto::{CryptoConfig, SecurityLevel, CryptoError};
use crate::protocol::{SecurityProfile, ProtocolConfig};
use crate::protocol::handshake::{
    HandshakeConfig, HandshakeInitiator, HandshakeResponder,
    HandshakeInit, HandshakeResponse, HandshakeComplete
};
use crate::protocol::session::Session;
use crate::protocol::message::{Message, MessageContent, EncryptedMessage};
use crate::error::{B4aeError, B4aeResult};
use std::collections::HashMap;

/// B4AE Client Configuration
#[derive(Debug, Clone)]
pub struct B4aeConfig {
    /// Security profile preset
    pub security_profile: SecurityProfile,
    /// Cryptographic configuration
    pub crypto_config: CryptoConfig,
    /// Protocol configuration
    pub protocol_config: ProtocolConfig,
    /// Handshake configuration
    pub handshake_config: HandshakeConfig,
}

impl Default for B4aeConfig {
    fn default() -> Self {
        B4aeConfig {
            security_profile: SecurityProfile::Standard,
            crypto_config: CryptoConfig::default(),
            protocol_config: ProtocolConfig::default(),
            handshake_config: HandshakeConfig::default(),
        }
    }
}

impl B4aeConfig {
    /// Create config from security profile
    pub fn from_profile(profile: SecurityProfile) -> Self {
        let security_level = match profile {
            SecurityProfile::Standard => SecurityLevel::Standard,
            SecurityProfile::High => SecurityLevel::High,
            SecurityProfile::Maximum => SecurityLevel::Maximum,
        };
        
        B4aeConfig {
            security_profile: profile,
            crypto_config: CryptoConfig {
                security_level,
                ..CryptoConfig::default()
            },
            protocol_config: profile.to_config(),
            handshake_config: HandshakeConfig::default(),
        }
    }
}

/// B4AE Client
/// High-level API for secure communication
pub struct B4aeClient {
    /// Client configuration
    config: B4aeConfig,
    /// Active sessions indexed by peer ID
    sessions: HashMap<Vec<u8>, Session>,
    /// Pending handshakes (initiator side)
    pending_initiators: HashMap<Vec<u8>, HandshakeInitiator>,
    /// Pending handshakes (responder side)  
    pending_responders: HashMap<Vec<u8>, HandshakeResponder>,
}

impl B4aeClient {
    /// Create new B4AE client with security profile
    pub fn new(profile: SecurityProfile) -> B4aeResult<Self> {
        let config = B4aeConfig::from_profile(profile);
        Ok(B4aeClient {
            config,
            sessions: HashMap::new(),
            pending_initiators: HashMap::new(),
            pending_responders: HashMap::new(),
        })
    }

    /// Create client with custom configuration
    pub fn with_config(config: B4aeConfig) -> B4aeResult<Self> {
        Ok(B4aeClient {
            config,
            sessions: HashMap::new(),
            pending_initiators: HashMap::new(),
            pending_responders: HashMap::new(),
        })
    }

    /// Initiate handshake with peer
    /// Returns HandshakeInit message to send to peer
    pub fn initiate_handshake(&mut self, peer_id: &[u8]) -> B4aeResult<HandshakeInit> {
        let mut initiator = HandshakeInitiator::new(self.config.handshake_config.clone())
            .map_err(|e: CryptoError| B4aeError::CryptoError(e.to_string()))?;
        
        let init = initiator.generate_init()
            .map_err(|e: CryptoError| B4aeError::CryptoError(e.to_string()))?;
        
        self.pending_initiators.insert(peer_id.to_vec(), initiator);
        Ok(init)
    }

    /// Respond to handshake initiation
    /// Returns HandshakeResponse to send back
    pub fn respond_to_handshake(&mut self, peer_id: &[u8], init: HandshakeInit) -> B4aeResult<HandshakeResponse> {
        let mut responder = HandshakeResponder::new(self.config.handshake_config.clone())
            .map_err(|e: CryptoError| B4aeError::CryptoError(e.to_string()))?;
        
        let response = responder.process_init(init)
            .map_err(|e: CryptoError| B4aeError::CryptoError(e.to_string()))?;
        
        self.pending_responders.insert(peer_id.to_vec(), responder);
        Ok(response)
    }

    /// Process handshake response (initiator side)
    /// Returns HandshakeComplete to send to peer
    pub fn process_response(&mut self, peer_id: &[u8], response: HandshakeResponse) -> B4aeResult<HandshakeComplete> {
        let initiator = self.pending_initiators.get_mut(peer_id)
            .ok_or_else(|| B4aeError::ProtocolError("No pending handshake".to_string()))?;
        
        initiator.process_response(response)
            .map_err(|e: CryptoError| B4aeError::CryptoError(e.to_string()))?;
        
        let complete = initiator.generate_complete()
            .map_err(|e: CryptoError| B4aeError::CryptoError(e.to_string()))?;
        
        Ok(complete)
    }

    /// Finalize handshake (initiator side)
    pub fn finalize_initiator(&mut self, peer_id: &[u8]) -> B4aeResult<()> {
        let initiator = self.pending_initiators.remove(peer_id)
            .ok_or_else(|| B4aeError::ProtocolError("No pending handshake".to_string()))?;
        
        let result = initiator.finalize()
            .map_err(|e: CryptoError| B4aeError::CryptoError(e.to_string()))?;
        
        let session = Session::from_handshake(result, peer_id.to_vec())
            .map_err(|e: CryptoError| B4aeError::CryptoError(e.to_string()))?;
        
        self.sessions.insert(peer_id.to_vec(), session);
        Ok(())
    }

    /// Process handshake complete (responder side) and finalize
    pub fn complete_handshake(&mut self, peer_id: &[u8], complete: HandshakeComplete) -> B4aeResult<()> {
        let mut responder = self.pending_responders.remove(peer_id)
            .ok_or_else(|| B4aeError::ProtocolError("No pending handshake".to_string()))?;
        
        responder.process_complete(complete)
            .map_err(|e: CryptoError| B4aeError::CryptoError(e.to_string()))?;
        
        let result = responder.finalize()
            .map_err(|e: CryptoError| B4aeError::CryptoError(e.to_string()))?;
        
        let session = Session::from_handshake(result, peer_id.to_vec())
            .map_err(|e: CryptoError| B4aeError::CryptoError(e.to_string()))?;
        
        self.sessions.insert(peer_id.to_vec(), session);
        Ok(())
    }

    /// Encrypt message for peer
    pub fn encrypt_message(&mut self, peer_id: &[u8], plaintext: &[u8]) -> B4aeResult<EncryptedMessage> {
        let session = self.sessions.get_mut(peer_id)
            .ok_or_else(|| B4aeError::ProtocolError("No session with peer".to_string()))?;
        
        let message = Message::binary(plaintext.to_vec());
        session.send(&message)
            .map_err(|e: CryptoError| B4aeError::CryptoError(e.to_string()))
    }

    /// Decrypt message from peer
    pub fn decrypt_message(&mut self, peer_id: &[u8], encrypted: &EncryptedMessage) -> B4aeResult<Vec<u8>> {
        let session = self.sessions.get_mut(peer_id)
            .ok_or_else(|| B4aeError::ProtocolError("No session with peer".to_string()))?;
        
        let message = session.receive(encrypted)
            .map_err(|e: CryptoError| B4aeError::CryptoError(e.to_string()))?;
        
        match message.content {
            MessageContent::Binary(data) => Ok(data),
            MessageContent::Text(text) => Ok(text.into_bytes()),
            MessageContent::File { data, .. } => Ok(data),
        }
    }

    /// Check if session exists with peer
    pub fn has_session(&self, peer_id: &[u8]) -> bool {
        self.sessions.contains_key(peer_id)
    }

    /// Close session with peer
    pub fn close_session(&mut self, peer_id: &[u8]) {
        if let Some(mut session) = self.sessions.remove(peer_id) {
            session.close();
        }
    }

    /// Get configuration
    pub fn config(&self) -> &B4aeConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = B4aeClient::new(SecurityProfile::Standard).unwrap();
        assert_eq!(client.sessions.len(), 0);
    }

    #[test]
    fn test_config_from_profile() {
        let config = B4aeConfig::from_profile(SecurityProfile::Maximum);
        assert_eq!(config.security_profile, SecurityProfile::Maximum);
    }

    #[test]
    fn test_full_handshake_and_messaging() {
        // Create two clients
        let mut alice = B4aeClient::new(SecurityProfile::Standard).unwrap();
        let mut bob = B4aeClient::new(SecurityProfile::Standard).unwrap();

        let alice_id = b"alice".to_vec();
        let bob_id = b"bob".to_vec();

        // Alice initiates handshake
        let init = alice.initiate_handshake(&bob_id).unwrap();

        // Bob responds
        let response = bob.respond_to_handshake(&alice_id, init).unwrap();

        // Alice processes response and creates complete
        let complete = alice.process_response(&bob_id, response).unwrap();

        // Bob processes complete
        bob.complete_handshake(&alice_id, complete).unwrap();

        // Alice finalizes
        alice.finalize_initiator(&bob_id).unwrap();

        // Now both have sessions
        assert!(alice.has_session(&bob_id));
        assert!(bob.has_session(&alice_id));

        // Alice sends message to Bob
        let plaintext = b"Hello, Bob!";
        let encrypted = alice.encrypt_message(&bob_id, plaintext).unwrap();

        // Bob decrypts
        let decrypted = bob.decrypt_message(&alice_id, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
