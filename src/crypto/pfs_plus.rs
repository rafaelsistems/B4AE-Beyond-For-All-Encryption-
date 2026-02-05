// B4AE Perfect Forward Secrecy Plus (PFS+) Implementation
// Enhanced forward secrecy that protects past, future, and metadata

use crate::crypto::{CryptoError, CryptoResult};
use crate::crypto::hkdf;
use crate::crypto::random;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// PFS+ Key Chain for enhanced forward secrecy
pub struct PfsKeyChain {
    /// Current chain key
    chain_key: [u8; 32],
    /// Message counter
    message_counter: u64,
    /// Key cache for out-of-order messages
    key_cache: HashMap<u64, [u8; 32]>,
    /// Maximum cache size
    max_cache_size: usize,
}

/// PFS+ Session for managing key evolution
pub struct PfsSession {
    /// Send chain
    send_chain: PfsKeyChain,
    /// Receive chain
    receive_chain: PfsKeyChain,
    /// Session ID
    session_id: [u8; 32],
    /// Last rotation time
    last_rotation: u64,
    /// Rotation interval (seconds)
    rotation_interval: u64,
}

impl PfsKeyChain {
    /// Create new key chain from initial key
    pub fn new(initial_key: &[u8]) -> CryptoResult<Self> {
        if initial_key.len() != 32 {
            return Err(CryptoError::InvalidKeySize(
                format!("Expected 32 bytes, got {}", initial_key.len())
            ));
        }

        let mut chain_key = [0u8; 32];
        chain_key.copy_from_slice(initial_key);

        Ok(PfsKeyChain {
            chain_key,
            message_counter: 0,
            key_cache: HashMap::new(),
            max_cache_size: 1000,
        })
    }

    /// Advance the chain and derive next message key
    pub fn next_key(&mut self) -> CryptoResult<[u8; 32]> {
        // Derive message key from current chain key
        let message_key = self.derive_message_key(self.message_counter)?;
        
        // Cache the key for potential out-of-order delivery
        if self.key_cache.len() < self.max_cache_size {
            self.key_cache.insert(self.message_counter, message_key);
        }
        
        // Advance chain key using KDF ratchet
        self.advance_chain()?;
        
        // Increment counter
        self.message_counter += 1;
        
        // Remove old keys from cache for forward secrecy
        // Keep only recent keys (last 10) for out-of-order delivery
        if self.message_counter > 10 {
            let cleanup_before = self.message_counter - 10;
            self.cleanup_cache(cleanup_before);
        }
        
        Ok(message_key)
    }

    /// Get key for specific message counter (for out-of-order messages)
    pub fn get_key(&mut self, counter: u64) -> CryptoResult<Option<[u8; 32]>> {
        // Check cache first
        if let Some(key) = self.key_cache.get(&counter) {
            return Ok(Some(*key));
        }

        // If counter is in the future, we can't derive it yet
        if counter > self.message_counter {
            return Ok(None);
        }

        // For past messages, we can't derive them (forward secrecy)
        Ok(None)
    }

    /// Advance the chain key using KDF ratchet
    fn advance_chain(&mut self) -> CryptoResult<()> {
        // Use HKDF to derive next chain key
        let next_chain_key = hkdf::derive_key(
            &[&self.chain_key],
            b"B4AE-v1-pfs-chain-advance",
            32,
        )?;

        // Zero out old chain key
        for byte in &mut self.chain_key {
            *byte = 0;
        }

        // Update to new chain key
        self.chain_key.copy_from_slice(&next_chain_key);

        Ok(())
    }

    /// Derive message key from chain key and counter
    fn derive_message_key(&self, counter: u64) -> CryptoResult<[u8; 32]> {
        let counter_bytes = counter.to_be_bytes();
        let key = hkdf::derive_key(
            &[&self.chain_key, &counter_bytes],
            b"B4AE-v1-pfs-message-key",
            32,
        )?;

        let mut message_key = [0u8; 32];
        message_key.copy_from_slice(&key);
        Ok(message_key)
    }

    /// Clean up old cached keys (for memory management)
    pub fn cleanup_cache(&mut self, before_counter: u64) {
        self.key_cache.retain(|&counter, _| counter >= before_counter);
    }
}

impl PfsSession {
    /// Create new PFS+ session
    pub fn new(
        send_key: &[u8],
        receive_key: &[u8],
        session_id: [u8; 32],
    ) -> CryptoResult<Self> {
        let send_chain = PfsKeyChain::new(send_key)?;
        let receive_chain = PfsKeyChain::new(receive_key)?;
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(PfsSession {
            send_chain,
            receive_chain,
            session_id,
            last_rotation: now,
            rotation_interval: 3600, // 1 hour default
        })
    }

    /// Get next sending key
    pub fn next_send_key(&mut self) -> CryptoResult<[u8; 32]> {
        self.send_chain.next_key()
    }

    /// Get receiving key for specific counter
    pub fn get_receive_key(&mut self, counter: u64) -> CryptoResult<Option<[u8; 32]>> {
        self.receive_chain.get_key(counter)
    }

    /// Check if session needs key rotation
    pub fn needs_rotation(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now - self.last_rotation > self.rotation_interval
    }

    /// Perform key rotation (generates new chain keys)
    pub fn rotate_keys(&mut self) -> CryptoResult<([u8; 32], [u8; 32])> {
        // Generate new chain keys
        let new_send_key = random::random_bytes(32);
        let new_receive_key = random::random_bytes(32);

        // Create new chains
        self.send_chain = PfsKeyChain::new(&new_send_key)?;
        self.receive_chain = PfsKeyChain::new(&new_receive_key)?;

        // Update rotation time
        self.last_rotation = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut send_key = [0u8; 32];
        let mut receive_key = [0u8; 32];
        send_key.copy_from_slice(&new_send_key);
        receive_key.copy_from_slice(&new_receive_key);

        Ok((send_key, receive_key))
    }

    /// Get session info
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Get current message counters
    pub fn counters(&self) -> (u64, u64) {
        (self.send_chain.message_counter, self.receive_chain.message_counter)
    }

    /// Clean up old keys (call periodically)
    pub fn cleanup(&mut self) {
        let cleanup_threshold = 100; // Keep last 100 keys
        
        if self.send_chain.message_counter > cleanup_threshold {
            let cleanup_before = self.send_chain.message_counter - cleanup_threshold;
            self.send_chain.cleanup_cache(cleanup_before);
        }
        
        if self.receive_chain.message_counter > cleanup_threshold {
            let cleanup_before = self.receive_chain.message_counter - cleanup_threshold;
            self.receive_chain.cleanup_cache(cleanup_before);
        }
    }
}

/// PFS+ Manager for handling multiple sessions
pub struct PfsManager {
    sessions: HashMap<[u8; 32], PfsSession>,
}

impl PfsManager {
    /// Create new PFS+ manager
    pub fn new() -> Self {
        PfsManager {
            sessions: HashMap::new(),
        }
    }

    /// Create new session
    pub fn create_session(
        &mut self,
        session_id: [u8; 32],
        send_key: &[u8],
        receive_key: &[u8],
    ) -> CryptoResult<()> {
        let session = PfsSession::new(send_key, receive_key, session_id)?;
        self.sessions.insert(session_id, session);
        Ok(())
    }

    /// Get session
    pub fn get_session(&mut self, session_id: &[u8; 32]) -> Option<&mut PfsSession> {
        self.sessions.get_mut(session_id)
    }

    /// Remove session
    pub fn remove_session(&mut self, session_id: &[u8; 32]) -> Option<PfsSession> {
        self.sessions.remove(session_id)
    }

    /// Check all sessions for rotation needs
    pub fn check_rotations(&mut self) -> Vec<[u8; 32]> {
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

    /// Cleanup all sessions
    pub fn cleanup_all(&mut self) {
        for session in self.sessions.values_mut() {
            session.cleanup();
        }
    }
}

impl Default for PfsManager {
    fn default() -> Self {
        Self::new()
    }
}

// Secure drop implementations
impl Drop for PfsKeyChain {
    fn drop(&mut self) {
        // Zero out chain key
        for byte in &mut self.chain_key {
            *byte = 0;
        }
        
        // Zero out cached keys
        for (_, key) in self.key_cache.iter_mut() {
            for byte in key {
                *byte = 0;
            }
        }
    }
}

impl Drop for PfsSession {
    fn drop(&mut self) {
        // Zero out session ID
        for byte in &mut self.session_id {
            *byte = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_chain_creation() {
        let initial_key = [0x42; 32];
        let chain = PfsKeyChain::new(&initial_key).unwrap();
        assert_eq!(chain.message_counter, 0);
    }

    #[test]
    fn test_key_derivation() {
        let initial_key = [0x42; 32];
        let mut chain = PfsKeyChain::new(&initial_key).unwrap();
        
        let key1 = chain.next_key().unwrap();
        let key2 = chain.next_key().unwrap();
        
        // Keys should be different
        assert_ne!(key1, key2);
        
        // Counter should advance
        assert_eq!(chain.message_counter, 2);
    }

    #[test]
    fn test_session_creation() {
        let send_key = [0x42; 32];
        let receive_key = [0x43; 32];
        let session_id = [0x44; 32];
        
        let session = PfsSession::new(&send_key, &receive_key, session_id).unwrap();
        assert_eq!(session.session_id(), &session_id);
    }

    #[test]
    fn test_key_rotation() {
        let send_key = [0x42; 32];
        let receive_key = [0x43; 32];
        let session_id = [0x44; 32];
        
        let mut session = PfsSession::new(&send_key, &receive_key, session_id).unwrap();
        
        let (new_send, new_receive) = session.rotate_keys().unwrap();
        
        // New keys should be different from original
        assert_ne!(new_send, send_key);
        assert_ne!(new_receive, receive_key);
    }

    #[test]
    fn test_pfs_manager() {
        let mut manager = PfsManager::new();
        let session_id = [0x44; 32];
        let send_key = [0x42; 32];
        let receive_key = [0x43; 32];
        
        manager.create_session(session_id, &send_key, &receive_key).unwrap();
        
        let session = manager.get_session(&session_id).unwrap();
        assert_eq!(session.session_id(), &session_id);
    }

    #[test]
    fn test_forward_secrecy() {
        let initial_key = [0x42; 32];
        let mut chain = PfsKeyChain::new(&initial_key).unwrap();
        
        // Generate enough keys to trigger cleanup (more than 10)
        for _ in 0..15 {
            let _ = chain.next_key().unwrap();
        }
        
        // Should not be able to get old keys (forward secrecy)
        // Key 0 should be cleaned up by now
        let old_key = chain.get_key(0).unwrap();
        assert!(old_key.is_none());
        
        // Recent keys should still be available (within last 10)
        let recent_key = chain.get_key(14).unwrap();
        assert!(recent_key.is_some());
    }
}