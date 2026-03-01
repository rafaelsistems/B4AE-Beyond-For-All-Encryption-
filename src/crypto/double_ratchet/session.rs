//! Double Ratchet Session
//!
//! Orchestrates the complete Double Ratchet protocol for a session.

use crate::crypto::{CryptoResult, CryptoError};
use crate::crypto::padding::{PadmePadding, PaddedMessage};
use super::{RootKeyManager, ChainKeyRatchet, HybridDHRatchet, HybridPublicKey};
use serde::{Serialize, Deserialize};

/// Ratchet State
#[derive(Debug, Clone)]
pub enum RatchetState {
    /// Normal operation
    Active,
    /// Waiting for ratchet acknowledgment
    RatchetPending {
        pending_update: RatchetUpdate,
        sent_at: u64,
    },
    /// Processing received ratchet
    RatchetReceived {
        received_update: RatchetUpdate,
        processed: bool,
    },
    /// Error state
    Error(String),
}

/// Ratchet Update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetUpdate {
    /// New Kyber-1024 public key
    pub kyber_public: Vec<u8>,
    /// New X25519 public key
    pub x25519_public: [u8; 32],
    /// Kyber ciphertext (for receiver)
    pub kyber_ciphertext: Option<Vec<u8>>,
    /// Ratchet sequence number
    pub ratchet_sequence: u64,
    /// Timestamp
    pub timestamp: u64,
}

/// Ratchet Message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetMessage {
    /// Message sequence number
    pub sequence: u64,
    /// Sending chain message counter
    pub message_counter: u64,
    /// Current ratchet count
    pub ratchet_count: u64,
    /// Optional DH ratchet update (if included)
    pub ratchet_update: Option<RatchetUpdate>,
    /// Encrypted payload (ChaCha20-Poly1305)
    pub ciphertext: Vec<u8>,
    /// Authentication tag
    pub tag: [u8; 16],
    /// Deterministic nonce (derived from counter)
    pub nonce: [u8; 12],
}

/// Double Ratchet Configuration
#[derive(Debug, Clone)]
pub struct DoubleRatchetConfig {
    /// Number of messages between DH ratchet steps
    pub ratchet_interval: u64,
    /// Maximum number of cached message keys
    pub cache_size: usize,
    /// Maximum allowed counter skip (DoS protection)
    pub max_skip: u64,
}

impl Default for DoubleRatchetConfig {
    fn default() -> Self {
        DoubleRatchetConfig {
            ratchet_interval: super::DEFAULT_RATCHET_INTERVAL,
            cache_size: super::DEFAULT_CACHE_SIZE,
            max_skip: super::MAX_SKIP,
        }
    }
}

impl DoubleRatchetConfig {
    /// Validates the configuration parameters.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidInput` if:
    /// - `ratchet_interval` is 0 or > 10,000
    /// - `cache_size` is < 10 or > 1,000
    /// - `max_skip` is < 100 or > 10,000
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::crypto::double_ratchet::session::DoubleRatchetConfig;
    ///
    /// let config = DoubleRatchetConfig::default();
    /// assert!(config.validate().is_ok());
    ///
    /// let mut invalid_config = DoubleRatchetConfig::default();
    /// invalid_config.ratchet_interval = 0;
    /// assert!(invalid_config.validate().is_err());
    /// ```
    pub fn validate(&self) -> CryptoResult<()> {
        if self.ratchet_interval == 0 || self.ratchet_interval > 10_000 {
            return Err(CryptoError::InvalidInput(
                format!("ratchet_interval must be between 1 and 10,000, got {}", 
                    self.ratchet_interval)
            ));
        }

        if self.cache_size < 10 || self.cache_size > 1_000 {
            return Err(CryptoError::InvalidInput(
                format!("cache_size must be between 10 and 1,000, got {}", 
                    self.cache_size)
            ));
        }

        if self.max_skip < 100 || self.max_skip > 10_000 {
            return Err(CryptoError::InvalidInput(
                format!("max_skip must be between 100 and 10,000, got {}", 
                    self.max_skip)
            ));
        }

        Ok(())
    }
}

/// Double Ratchet Session
///
/// Orchestrates the complete Double Ratchet protocol for a session.
pub struct DoubleRatchetSession {
    session_id: [u8; 32],
    root_key_manager: RootKeyManager,
    sending_chain: ChainKeyRatchet,
    receiving_chain: ChainKeyRatchet,
    dh_ratchet: HybridDHRatchet,
    state: RatchetState,
    sequence_number: u64,
}

impl DoubleRatchetSession {
    /// Initialize from handshake result
    ///
    /// Creates a new Double Ratchet session from a handshake master secret.
    /// Derives the initial root key and chain keys, initializes all components.
    ///
    /// # Arguments
    /// * `master_secret` - Master secret from handshake (at least 32 bytes)
    /// * `session_id` - Unique session identifier (32 bytes)
    /// * `config` - Double Ratchet configuration
    ///
    /// # Returns
    /// * `Ok(DoubleRatchetSession)` - Initialized session
    /// * `Err(CryptoError)` - If initialization fails
    pub fn from_handshake(
        master_secret: &[u8],
        session_id: [u8; 32],
        config: DoubleRatchetConfig,
    ) -> CryptoResult<Self> {
        // Validate configuration
        config.validate()?;

        // Initialize root key manager
        let root_key_manager = RootKeyManager::new(master_secret)?;

        // Derive initial chain keys from root key
        use crate::crypto::hkdf::derive_key;
        
        let sending_chain_key_vec = derive_key(
            &[master_secret],
            b"B4AE-v2-sending-chain-0",
            32,
        )?;
        
        let mut sending_chain_key = [0u8; 32];
        sending_chain_key.copy_from_slice(&sending_chain_key_vec);

        let receiving_chain_key_vec = derive_key(
            &[master_secret],
            b"B4AE-v2-receiving-chain-0",
            32,
        )?;
        
        let mut receiving_chain_key = [0u8; 32];
        receiving_chain_key.copy_from_slice(&receiving_chain_key_vec);

        // Initialize chain key ratchets
        let sending_chain = ChainKeyRatchet::with_cache_size(
            sending_chain_key,
            config.cache_size,
        );
        
        let receiving_chain = ChainKeyRatchet::with_cache_size(
            receiving_chain_key,
            config.cache_size,
        );

        // Initialize hybrid DH ratchet
        let dh_ratchet = HybridDHRatchet::new(config.ratchet_interval);

        Ok(DoubleRatchetSession {
            session_id,
            root_key_manager,
            sending_chain,
            receiving_chain,
            dh_ratchet,
            state: RatchetState::Active,
            sequence_number: 0,
        })
    }

    /// Encrypt message with current chain key
    ///
    /// Encrypts a plaintext message using ChaCha20-Poly1305 with a derived message key.
    /// Automatically triggers DH ratchet if the ratchet interval is reached.
    ///
    /// # Arguments
    /// * `plaintext` - Message to encrypt
    ///
    /// # Returns
    /// * `Ok(RatchetMessage)` - Encrypted message with metadata
    /// * `Err(CryptoError)` - If encryption fails
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> CryptoResult<RatchetMessage> {
        if plaintext.is_empty() {
            return Err(CryptoError::InvalidInput("Plaintext cannot be empty".to_string()));
        }

        // Check if DH ratchet should be triggered
        let ratchet_update = if self.dh_ratchet.should_ratchet(self.sending_chain.message_counter()) {
            Some(self.initiate_ratchet()?)
        } else {
            None
        };

        // Derive message key from sending chain
        let message_key = self.sending_chain.next_message_key()?;
        let message_counter = message_key.counter;

        // Derive deterministic nonce from counter
        use crate::crypto::hkdf::derive_key;
        let counter_bytes = message_counter.to_be_bytes();
        let nonce_vec = derive_key(
            &[&message_key.encryption_key, &counter_bytes],
            b"B4AE-v2-nonce",
            12,
        )?;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_vec);

        // Construct AAD (message_counter || ratchet_count)
        let mut aad = Vec::with_capacity(16);
        aad.extend_from_slice(&message_counter.to_be_bytes());
        aad.extend_from_slice(&self.root_key_manager.ratchet_count().to_be_bytes());

        // Encrypt with ChaCha20-Poly1305
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            ChaCha20Poly1305, Nonce,
        };

        let cipher = ChaCha20Poly1305::new_from_slice(&message_key.encryption_key)
            .map_err(|e| CryptoError::EncryptionFailed(format!("ChaCha20Poly1305 init failed: {}", e)))?;

        let nonce_obj = Nonce::from_slice(&nonce);
        let payload = Payload {
            msg: plaintext,
            aad: &aad,
        };

        let ciphertext_with_tag = cipher.encrypt(nonce_obj, payload)
            .map_err(|e| CryptoError::EncryptionFailed(format!("Encryption failed: {}", e)))?;

        // Split ciphertext and tag
        let tag_start = ciphertext_with_tag.len().saturating_sub(16);
        let ciphertext = ciphertext_with_tag[..tag_start].to_vec();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext_with_tag[tag_start..]);

        // Construct ratchet message
        let ratchet_message = RatchetMessage {
            sequence: self.sequence_number,
            message_counter,
            ratchet_count: self.root_key_manager.ratchet_count(),
            ratchet_update,
            ciphertext,
            tag,
            nonce,
        };

        // Increment sequence number
        self.sequence_number += 1;

        Ok(ratchet_message)
    }

    /// Decrypt message and advance receiving chain
    ///
    /// Decrypts a received message, handling out-of-order delivery and ratchet updates.
    ///
    /// # Arguments
    /// * `message` - Encrypted message to decrypt
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Decrypted plaintext
    /// * `Err(CryptoError)` - If decryption or authentication fails
    pub fn decrypt_message(&mut self, message: &RatchetMessage) -> CryptoResult<Vec<u8>> {
        // Validate ratchet count
        if message.ratchet_count < self.root_key_manager.ratchet_count() {
            return Err(CryptoError::AuthenticationFailed);
        }

        // Process ratchet update if present
        if let Some(ref update) = message.ratchet_update {
            self.process_ratchet_update(update)?;
        }

        // Get or derive message key
        let message_key = self.receiving_chain.get_message_key(message.message_counter)?
            .ok_or_else(|| CryptoError::DecryptionFailed(
                "Message key not available".to_string()
            ))?;

        // Construct AAD
        let mut aad = Vec::with_capacity(16);
        aad.extend_from_slice(&message.message_counter.to_be_bytes());
        aad.extend_from_slice(&message.ratchet_count.to_be_bytes());

        // Decrypt with ChaCha20-Poly1305
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            ChaCha20Poly1305, Nonce,
        };

        let cipher = ChaCha20Poly1305::new_from_slice(&message_key.encryption_key)
            .map_err(|e| CryptoError::DecryptionFailed(format!("ChaCha20Poly1305 init failed: {}", e)))?;

        let nonce_obj = Nonce::from_slice(&message.nonce);
        
        // Reconstruct ciphertext with tag
        let mut ciphertext_with_tag = message.ciphertext.clone();
        ciphertext_with_tag.extend_from_slice(&message.tag);

        let payload = Payload {
            msg: &ciphertext_with_tag,
            aad: &aad,
        };

        let plaintext = cipher.decrypt(nonce_obj, payload)
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        // Cleanup old cached keys
        self.receiving_chain.cleanup_old_keys(message.message_counter);

        Ok(plaintext)
    }

    /// Encrypt message with padding
    ///
    /// Pads the plaintext using PADMÉ padding, then encrypts it using the double ratchet.
    /// The padding metadata (original_length, bucket_size) is serialized into the encrypted payload
    /// to enable correct unpadding on decryption.
    ///
    /// # Algorithm
    ///
    /// 1. Pad plaintext using `padding.pad()` to get `PaddedMessage`
    /// 2. Serialize `PaddedMessage` (original_length, bucket_size, padded_data) into bytes
    /// 3. Encrypt serialized data using `encrypt_message()`
    /// 4. Return encrypted `RatchetMessage`
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Message to encrypt
    /// * `padding` - PADMÉ padding instance
    ///
    /// # Returns
    ///
    /// * `Ok(RatchetMessage)` - Encrypted message with padded plaintext
    /// * `Err(CryptoError)` - If padding or encryption fails
    ///
    /// # Security Properties
    ///
    /// - Message length is obfuscated (only bucket size visible)
    /// - Padding is applied before encryption (padding oracle resistant)
    /// - Metadata is authenticated (included in encrypted payload)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use b4ae::crypto::padding::{PadmeConfig, PadmePadding};
    ///
    /// let padding = PadmePadding::new(PadmeConfig::default());
    /// let plaintext = b"Hello, World!";
    /// let encrypted = session.encrypt_message_with_padding(plaintext, &padding)?;
    /// ```
    pub fn encrypt_message_with_padding(
        &mut self,
        plaintext: &[u8],
        padding: &PadmePadding,
    ) -> CryptoResult<RatchetMessage> {
        // Step 1: Pad the plaintext
        let padded_message = padding.pad(plaintext)?;

        // Step 2: Serialize PaddedMessage (original_length || bucket_size || padded_data)
        // We use a simple binary format: 4 bytes original_length + 4 bytes bucket_size + padded_data
        let mut serialized = Vec::with_capacity(8 + padded_message.padded_data.len());
        serialized.extend_from_slice(&padded_message.original_length.to_be_bytes());
        serialized.extend_from_slice(&padded_message.bucket_size.to_be_bytes());
        serialized.extend_from_slice(&padded_message.padded_data);

        // Step 3: Encrypt the serialized padded message
        self.encrypt_message(&serialized)
    }

    /// Decrypt message and remove padding
    ///
    /// Decrypts the message using the double ratchet, then unpads it using PADMÉ padding.
    /// Extracts the padding metadata (original_length, bucket_size) from the decrypted payload
    /// to correctly unpad the message.
    ///
    /// # Algorithm
    ///
    /// 1. Decrypt message using `decrypt_message()` to get serialized `PaddedMessage`
    /// 2. Deserialize to extract original_length, bucket_size, and padded_data
    /// 3. Reconstruct `PaddedMessage` struct
    /// 4. Unpad using `padding.unpad()` to recover original plaintext
    /// 5. Return original plaintext
    ///
    /// # Arguments
    ///
    /// * `message` - Encrypted message to decrypt
    /// * `padding` - PADMÉ padding instance
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Original plaintext (padding removed)
    /// * `Err(CryptoError)` - If decryption, authentication, or unpadding fails
    ///
    /// # Security Properties
    ///
    /// - Decryption happens before unpadding (correct order)
    /// - Padding validation is constant-time (timing attack resistant)
    /// - Authentication verified before unpadding (no padding oracle)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use b4ae::crypto::padding::{PadmeConfig, PadmePadding};
    ///
    /// let padding = PadmePadding::new(PadmeConfig::default());
    /// let decrypted = session.decrypt_message_with_unpadding(&encrypted, &padding)?;
    /// ```
    pub fn decrypt_message_with_unpadding(
        &mut self,
        message: &RatchetMessage,
        padding: &PadmePadding,
    ) -> CryptoResult<Vec<u8>> {
        // Step 1: Decrypt the message
        let decrypted = self.decrypt_message(message)?;

        // Step 2: Deserialize PaddedMessage (original_length || bucket_size || padded_data)
        if decrypted.len() < 8 {
            return Err(CryptoError::DecryptionFailed(
                "Decrypted data too short to contain padding metadata".to_string()
            ));
        }

        // Extract original_length (first 4 bytes)
        let mut original_length_bytes = [0u8; 4];
        original_length_bytes.copy_from_slice(&decrypted[0..4]);
        let original_length = u32::from_be_bytes(original_length_bytes);

        // Extract bucket_size (next 4 bytes)
        let mut bucket_size_bytes = [0u8; 4];
        bucket_size_bytes.copy_from_slice(&decrypted[4..8]);
        let bucket_size = u32::from_be_bytes(bucket_size_bytes);

        // Extract padded_data (remaining bytes)
        let padded_data = decrypted[8..].to_vec();

        // Step 3: Reconstruct PaddedMessage
        let padded_message = PaddedMessage {
            original_length,
            bucket_size,
            padded_data,
        };

        // Step 4: Unpad to recover original plaintext
        padding.unpad(&padded_message)
    }

    /// Perform DH ratchet step (sender-initiated)
    ///
    /// Generates new ephemeral keypairs and creates a ratchet update to send to the peer.
    ///
    /// # Returns
    /// * `Ok(RatchetUpdate)` - Ratchet update to include in next message
    /// * `Err(CryptoError)` - If key generation fails
    pub fn initiate_ratchet(&mut self) -> CryptoResult<RatchetUpdate> {
        // Generate ephemeral keypairs
        let hybrid_public = self.dh_ratchet.generate_ephemeral_keys()?;

        // Create ratchet update
        let update = RatchetUpdate {
            kyber_public: hybrid_public.kyber_public,
            x25519_public: hybrid_public.x25519_public,
            kyber_ciphertext: None, // Will be filled by receiver
            ratchet_sequence: self.root_key_manager.ratchet_count() + 1,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        // Update state
        self.state = RatchetState::RatchetPending {
            pending_update: update.clone(),
            sent_at: update.timestamp,
        };

        Ok(update)
    }

    /// Process received DH ratchet update
    ///
    /// Processes a ratchet update from the peer, derives new shared secrets,
    /// and updates the root key and chain keys.
    ///
    /// # Arguments
    /// * `update` - Ratchet update from peer
    ///
    /// # Returns
    /// * `Ok(())` - Ratchet processed successfully
    /// * `Err(CryptoError)` - If ratchet processing fails
    pub fn process_ratchet_update(&mut self, update: &RatchetUpdate) -> CryptoResult<()> {
        // Validate ratchet update
        if update.kyber_public.len() != 1568 {
            return Err(CryptoError::InvalidInput(
                format!("Invalid Kyber public key size: {}", update.kyber_public.len())
            ));
        }

        if update.ratchet_sequence <= self.root_key_manager.ratchet_count() {
            return Err(CryptoError::InvalidInput(
                "Ratchet sequence number must be greater than current count".to_string()
            ));
        }

        // Construct hybrid public key
        let peer_public = HybridPublicKey {
            kyber_public: update.kyber_public.clone(),
            x25519_public: update.x25519_public,
        };

        // Derive shared secrets
        let (kyber_ss, x25519_ss) = self.dh_ratchet.derive_shared_secrets(&peer_public)?;

        // Perform root key ratchet step
        let (new_sending_key, new_receiving_key) = self.root_key_manager.ratchet_step(
            &kyber_ss,
            &x25519_ss,
        )?;

        // Reset chain keys
        self.sending_chain.reset(new_sending_key);
        self.receiving_chain.reset(new_receiving_key);

        // Update state
        self.state = RatchetState::Active;

        Ok(())
    }

    /// Get current ratchet count
    pub fn ratchet_count(&self) -> u64 {
        self.root_key_manager.ratchet_count()
    }

    /// Get session ID
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Create a test session pair for integration testing
    /// 
    /// This is a test-only helper that creates two sessions that can communicate.
    /// It swaps Bob's chains so that Alice's sending chain matches Bob's receiving chain.
    /// 
    /// # Returns
    /// * `Ok((alice, bob))` - Pair of sessions ready for testing
    /// * `Err(CryptoError)` - If session creation fails
    #[cfg(test)]
    pub fn create_test_pair(
        master_secret: &[u8],
        session_id: [u8; 32],
        config: DoubleRatchetConfig,
    ) -> CryptoResult<(Self, Self)> {
        let mut alice = Self::from_handshake(master_secret, session_id, config.clone())?;
        let mut bob = Self::from_handshake(master_secret, session_id, config)?;
        
        // Swap Bob's chains so Alice's sending = Bob's receiving
        std::mem::swap(&mut bob.sending_chain, &mut bob.receiving_chain);
        
        Ok((alice, bob))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_from_handshake() {
        let master_secret = vec![0x42; 32];
        let session_id = [0x01; 32];
        let config = DoubleRatchetConfig::default();

        let session = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config,
        ).unwrap();

        assert_eq!(session.session_id(), &session_id);
        assert_eq!(session.ratchet_count(), 0);
    }

    #[test]
    fn test_session_invalid_config() {
        let master_secret = vec![0x42; 32];
        let session_id = [0x01; 32];
        
        // Invalid ratchet interval
        let mut config = DoubleRatchetConfig::default();
        config.ratchet_interval = 0;
        assert!(DoubleRatchetSession::from_handshake(&master_secret, session_id, config).is_err());

        // Invalid cache size
        let mut config = DoubleRatchetConfig::default();
        config.cache_size = 5;
        assert!(DoubleRatchetSession::from_handshake(&master_secret, session_id, config).is_err());

        // Invalid max_skip
        let mut config = DoubleRatchetConfig::default();
        config.max_skip = 50;
        assert!(DoubleRatchetSession::from_handshake(&master_secret, session_id, config).is_err());
    }

    #[test]
    fn test_encrypt_decrypt_message() {
        let master_secret = vec![0x42; 32];
        let session_id = [0x01; 32];
        let config = DoubleRatchetConfig::default();

        let mut alice = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config.clone(),
        ).unwrap();

        let mut bob = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config,
        ).unwrap();

        // Swap Bob's chains so Alice's sending = Bob's receiving
        std::mem::swap(&mut bob.sending_chain, &mut bob.receiving_chain);

        let plaintext = b"Hello, Double Ratchet!";
        
        // Alice encrypts
        let encrypted = alice.encrypt_message(plaintext).unwrap();
        
        // Bob decrypts
        let decrypted = bob.decrypt_message(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let master_secret = vec![0x42; 32];
        let session_id = [0x01; 32];
        let config = DoubleRatchetConfig::default();

        let mut session = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config,
        ).unwrap();

        let result = session.encrypt_message(b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_messages() {
        let master_secret = vec![0x42; 32];
        let session_id = [0x01; 32];
        let config = DoubleRatchetConfig::default();

        let mut alice = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config.clone(),
        ).unwrap();

        let mut bob = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config,
        ).unwrap();

        // Swap Bob's chains so Alice's sending = Bob's receiving
        std::mem::swap(&mut bob.sending_chain, &mut bob.receiving_chain);

        for i in 0..10 {
            let plaintext = format!("Message {}", i);
            let encrypted = alice.encrypt_message(plaintext.as_bytes()).unwrap();
            let decrypted = bob.decrypt_message(&encrypted).unwrap();
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }
    }

    #[test]
    fn test_ratchet_message_serialization() {
        let message = RatchetMessage {
            sequence: 1,
            message_counter: 5,
            ratchet_count: 0,
            ratchet_update: None,
            ciphertext: vec![1, 2, 3, 4],
            tag: [0x42; 16],
            nonce: [0x99; 12],
        };

        let serialized = serde_json::to_string(&message).unwrap();
        let deserialized: RatchetMessage = serde_json::from_str(&serialized).unwrap();

        assert_eq!(message.sequence, deserialized.sequence);
        assert_eq!(message.message_counter, deserialized.message_counter);
        assert_eq!(message.ciphertext, deserialized.ciphertext);
    }

    #[test]
    fn test_config_default() {
        let config = DoubleRatchetConfig::default();
        
        assert_eq!(config.ratchet_interval, super::super::DEFAULT_RATCHET_INTERVAL);
        assert_eq!(config.cache_size, super::super::DEFAULT_CACHE_SIZE);
        assert_eq!(config.max_skip, super::super::MAX_SKIP);
    }

    #[test]
    fn test_encrypt_decrypt_with_padding() {
        use crate::crypto::padding::{PadmeConfig, PadmePadding};

        let master_secret = vec![0x42; 32];
        let session_id = [0x01; 32];
        let config = DoubleRatchetConfig::default();

        let mut alice = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config.clone(),
        ).unwrap();

        let mut bob = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config,
        ).unwrap();

        // Swap Bob's chains so Alice's sending = Bob's receiving
        std::mem::swap(&mut bob.sending_chain, &mut bob.receiving_chain);

        // Create padding instance
        let padding = PadmePadding::new(PadmeConfig::default());

        let plaintext = b"Hello, World with Padding!";
        
        // Alice encrypts with padding
        let encrypted = alice.encrypt_message_with_padding(plaintext, &padding).unwrap();
        
        // Bob decrypts with unpadding
        let decrypted = bob.decrypt_message_with_unpadding(&encrypted, &padding).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_with_padding_multiple_messages() {
        use crate::crypto::padding::{PadmeConfig, PadmePadding};

        let master_secret = vec![0x42; 32];
        let session_id = [0x01; 32];
        let config = DoubleRatchetConfig::default();

        let mut alice = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config.clone(),
        ).unwrap();

        let mut bob = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config,
        ).unwrap();

        // Swap Bob's chains so Alice's sending = Bob's receiving
        std::mem::swap(&mut bob.sending_chain, &mut bob.receiving_chain);

        // Create padding instance
        let padding = PadmePadding::new(PadmeConfig::default());

        // Send multiple messages with padding
        for i in 0..5 {
            let plaintext = format!("Padded message number {}", i);
            let encrypted = alice.encrypt_message_with_padding(plaintext.as_bytes(), &padding).unwrap();
            let decrypted = bob.decrypt_message_with_unpadding(&encrypted, &padding).unwrap();
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }
    }

    #[test]
    fn test_encrypt_with_padding_different_sizes() {
        use crate::crypto::padding::{PadmeConfig, PadmePadding};

        let master_secret = vec![0x42; 32];
        let session_id = [0x01; 32];
        let config = DoubleRatchetConfig::default();

        let mut alice = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config.clone(),
        ).unwrap();

        let mut bob = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config,
        ).unwrap();

        // Swap Bob's chains so Alice's sending = Bob's receiving
        std::mem::swap(&mut bob.sending_chain, &mut bob.receiving_chain);

        // Create padding instance
        let padding = PadmePadding::new(PadmeConfig::default());

        // Test messages of different sizes (should map to different buckets)
        let test_messages = vec![
            b"Short".to_vec(),
            vec![0x42; 100],
            vec![0x42; 600],  // Should use 1KB bucket
            vec![0x42; 1500], // Should use 2KB bucket
        ];

        for plaintext in test_messages {
            let encrypted = alice.encrypt_message_with_padding(&plaintext, &padding).unwrap();
            let decrypted = bob.decrypt_message_with_unpadding(&encrypted, &padding).unwrap();
            assert_eq!(plaintext, decrypted);
        }
    }

    #[test]
    fn test_encrypt_with_padding_empty_message() {
        use crate::crypto::padding::{PadmeConfig, PadmePadding};

        let master_secret = vec![0x42; 32];
        let session_id = [0x01; 32];
        let config = DoubleRatchetConfig::default();

        let mut alice = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config.clone(),
        ).unwrap();

        let mut bob = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config,
        ).unwrap();

        // Swap Bob's chains so Alice's sending = Bob's receiving
        std::mem::swap(&mut bob.sending_chain, &mut bob.receiving_chain);

        // Create padding instance
        let padding = PadmePadding::new(PadmeConfig::default());

        // Empty message should work with padding
        let plaintext = b"";
        let encrypted = alice.encrypt_message_with_padding(plaintext, &padding).unwrap();
        let decrypted = bob.decrypt_message_with_unpadding(&encrypted, &padding).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_with_padding_oversized_message() {
        use crate::crypto::padding::{PadmeConfig, PadmePadding};

        let master_secret = vec![0x42; 32];
        let session_id = [0x01; 32];
        let config = DoubleRatchetConfig::default();

        let mut alice = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config,
        ).unwrap();

        // Create padding instance
        let padding = PadmePadding::new(PadmeConfig::default());

        // Message exceeds maximum bucket size (64KB)
        let plaintext = vec![0x42; 65537];
        let result = alice.encrypt_message_with_padding(&plaintext, &padding);
        
        // Should fail with MessageTooLarge error
        assert!(result.is_err());
    }

    #[test]
    fn test_backward_compatibility_padded_and_unpadded() {
        use crate::crypto::padding::{PadmeConfig, PadmePadding};

        let master_secret = vec![0x42; 32];
        let session_id = [0x01; 32];
        let config = DoubleRatchetConfig::default();

        let mut alice = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config.clone(),
        ).unwrap();

        let mut bob = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config,
        ).unwrap();

        // Swap Bob's chains so Alice's sending = Bob's receiving
        std::mem::swap(&mut bob.sending_chain, &mut bob.receiving_chain);

        // Create padding instance
        let padding = PadmePadding::new(PadmeConfig::default());

        // Alice can send both padded and unpadded messages
        let plaintext1 = b"Unpadded message";
        let encrypted1 = alice.encrypt_message(plaintext1).unwrap();
        let decrypted1 = bob.decrypt_message(&encrypted1).unwrap();
        assert_eq!(plaintext1, decrypted1.as_slice());

        let plaintext2 = b"Padded message";
        let encrypted2 = alice.encrypt_message_with_padding(plaintext2, &padding).unwrap();
        let decrypted2 = bob.decrypt_message_with_unpadding(&encrypted2, &padding).unwrap();
        assert_eq!(plaintext2, decrypted2.as_slice());
    }

    #[test]
    fn test_padding_metadata_preserved() {
        use crate::crypto::padding::{PadmeConfig, PadmePadding};

        let master_secret = vec![0x42; 32];
        let session_id = [0x01; 32];
        let config = DoubleRatchetConfig::default();

        let mut alice = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config.clone(),
        ).unwrap();

        let mut bob = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config,
        ).unwrap();

        // Swap Bob's chains so Alice's sending = Bob's receiving
        std::mem::swap(&mut bob.sending_chain, &mut bob.receiving_chain);

        // Create padding instance
        let padding = PadmePadding::new(PadmeConfig::default());

        // Test that padding metadata is correctly preserved through encryption/decryption
        let plaintext = b"Test message for metadata preservation";
        let encrypted = alice.encrypt_message_with_padding(plaintext, &padding).unwrap();
        let decrypted = bob.decrypt_message_with_unpadding(&encrypted, &padding).unwrap();
        
        // Verify exact plaintext recovery
        assert_eq!(plaintext.len(), decrypted.len());
        assert_eq!(plaintext, decrypted.as_slice());
    }
}

    // Tests for DoubleRatchetConfig validation

    #[test]
    fn test_config_default_validation() {
        let config = DoubleRatchetConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_invalid_ratchet_interval_zero() {
        let mut config = DoubleRatchetConfig::default();
        config.ratchet_interval = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_invalid_ratchet_interval_too_large() {
        let mut config = DoubleRatchetConfig::default();
        config.ratchet_interval = 10_001;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_valid_ratchet_interval_boundaries() {
        let mut config = DoubleRatchetConfig::default();
        config.ratchet_interval = 1;
        assert!(config.validate().is_ok());

        config.ratchet_interval = 10_000;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_invalid_cache_size_too_small() {
        let mut config = DoubleRatchetConfig::default();
        config.cache_size = 9;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_invalid_cache_size_too_large() {
        let mut config = DoubleRatchetConfig::default();
        config.cache_size = 1_001;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_valid_cache_size_boundaries() {
        let mut config = DoubleRatchetConfig::default();
        config.cache_size = 10;
        assert!(config.validate().is_ok());

        config.cache_size = 1_000;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_invalid_max_skip_too_small() {
        let mut config = DoubleRatchetConfig::default();
        config.max_skip = 99;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_invalid_max_skip_too_large() {
        let mut config = DoubleRatchetConfig::default();
        config.max_skip = 10_001;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_valid_max_skip_boundaries() {
        let mut config = DoubleRatchetConfig::default();
        config.max_skip = 100;
        assert!(config.validate().is_ok());

        config.max_skip = 10_000;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_all_invalid() {
        let config = DoubleRatchetConfig {
            ratchet_interval: 0,
            cache_size: 5,
            max_skip: 50,
        };
        // Should fail on first validation error (ratchet_interval)
        assert!(config.validate().is_err());
    }
