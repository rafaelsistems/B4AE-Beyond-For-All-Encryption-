//! B4AE Handshake Protocol Implementation (Protocol Specification v1.0 §6)
//!
//! Three-way handshake with quantum-resistant key exchange.

use crate::crypto::{CryptoError, CryptoResult};
use crate::crypto::hybrid::{self, HybridKeyPair, HybridPublicKey, HybridCiphertext, HybridSignature};
use crate::crypto::hkdf;
use crate::crypto::random;
use crate::crypto::zkauth::{self, ZkChallenge, ZkProof, EXTENSION_TYPE_ZK_CHALLENGE, EXTENSION_TYPE_ZK_PROOF};
use crate::protocol::PROTOCOL_VERSION;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use crate::time;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Handshake state machine (matches TLA+/Coq spec: Initiation, WaitingResponse, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initiating handshake (sending Init).
    Initiation,
    /// Waiting for Response.
    WaitingResponse,
    /// Waiting for Complete.
    WaitingComplete,
    /// Handshake completed.
    Completed,
    /// Handshake failed.
    Failed,
}

/// Algorithm identifiers (wire format).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum AlgorithmId {
    /// Kyber-1024 KEM
    Kyber1024 = 0x0001,
    /// Dilithium5 signature
    Dilithium5 = 0x0002,
    /// ECDH P-521
    EcdhP521 = 0x0003,
    /// ECDSA P-521
    EcdsaP521 = 0x0004,
    /// AES-256-GCM
    Aes256Gcm = 0x0005,
    /// SHA3-256
    Sha3_256 = 0x0006,
}

/// Handshake extension (optional data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extension {
    /// Extension type ID.
    pub extension_type: u16,
    /// Extension payload.
    pub data: Vec<u8>,
}

/// Handshake Init message (client → server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeInit {
    /// Protocol version.
    pub protocol_version: u16,
    /// Client randomness (32 bytes).
    pub client_random: [u8; 32],
    /// Hybrid public key for key agreement.
    pub hybrid_public_key: Vec<u8>,
    /// Supported algorithms.
    pub supported_algorithms: Vec<AlgorithmId>,
    /// Optional extensions (e.g. ZK challenge).
    pub extensions: Vec<Extension>,
    /// Signature over init payload.
    pub signature: Vec<u8>,
}

/// Handshake Response message (server → client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Protocol version.
    pub protocol_version: u16,
    /// Server randomness (32 bytes).
    pub server_random: [u8; 32],
    /// Server hybrid public key.
    pub hybrid_public_key: Vec<u8>,
    /// Encrypted shared secret (Kyber encaps).
    pub encrypted_shared_secret: Vec<u8>,
    /// Selected algorithms.
    pub selected_algorithms: Vec<AlgorithmId>,
    /// Optional extensions.
    pub extensions: Vec<Extension>,
    /// Signature over response payload.
    pub signature: Vec<u8>,
}

/// Handshake Complete message (client → server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeComplete {
    /// Confirmation hash (32 bytes).
    pub confirmation: [u8; 32],
    /// Signature.
    pub signature: Vec<u8>,
    /// Optional extensions (e.g. ZK proof)
    #[serde(default)]
    pub extensions: Vec<Extension>,
}

/// Handshake configuration.
#[derive(Clone)]
pub struct HandshakeConfig {
    /// Handshake timeout in milliseconds.
    pub timeout_ms: u64,
    /// Algorithms to advertise.
    pub supported_algorithms: Vec<AlgorithmId>,
    /// Algorithms that must be supported.
    pub required_algorithms: Vec<AlgorithmId>,
    /// Pre-configured extensions.
    pub extensions: Vec<Extension>,
    /// Optional ZK identity for initiator (anonymous auth)
    pub zk_identity: Option<Arc<zkauth::ZkIdentity>>,
    /// Optional ZK verifier for responder (verifies initiator's proof)
    pub zk_verifier: Option<Arc<Mutex<zkauth::ZkVerifier>>>,
    /// Optional HSM backend for signing (when available, ECDSA part uses HSM)
    #[cfg(feature = "hsm")]
    pub hsm: Option<Arc<dyn crate::hsm::HsmBackend>>,
    /// HSM key ID when hsm is configured
    #[cfg(feature = "hsm")]
    pub hsm_key_id: Option<String>,
}

impl std::fmt::Debug for HandshakeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeConfig")
            .field("timeout_ms", &self.timeout_ms)
            .field("supported_algorithms", &self.supported_algorithms)
            .field("required_algorithms", &self.required_algorithms)
            .field("extensions", &self.extensions)
            .field("zk_identity", &self.zk_identity.as_ref().map(|_| "Some"))
            .field("zk_verifier", &self.zk_verifier.as_ref().map(|_| "Some"))
            .finish()
    }
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        HandshakeConfig {
            timeout_ms: 30000,
            supported_algorithms: vec![
                AlgorithmId::Kyber1024,
                AlgorithmId::Dilithium5,
                AlgorithmId::EcdhP521,
                AlgorithmId::EcdsaP521,
                AlgorithmId::Aes256Gcm,
                AlgorithmId::Sha3_256,
            ],
            required_algorithms: vec![
                AlgorithmId::Kyber1024,
                AlgorithmId::Dilithium5,
                AlgorithmId::Aes256Gcm,
            ],
            extensions: Vec::new(),
            zk_identity: None,
            zk_verifier: None,
            #[cfg(feature = "hsm")]
            hsm: None,
            #[cfg(feature = "hsm")]
            hsm_key_id: None,
        }
    }
}

/// Session keys derived from handshake.
#[derive(Clone)]
pub struct SessionKeys {
    /// AES key for message encryption.
    pub encryption_key: Vec<u8>,
    /// HMAC key for message authentication.
    pub authentication_key: Vec<u8>,
    /// Key for metadata protection.
    pub metadata_key: Vec<u8>,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("encryption_key", &"<redacted>")
            .field("authentication_key", &"<redacted>")
            .field("metadata_key", &"<redacted>")
            .finish()
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.encryption_key.zeroize();
        self.authentication_key.zeroize();
        self.metadata_key.zeroize();
    }
}

/// Handshake result containing session keys.
#[derive(Debug)]
pub struct HandshakeResult {
    /// Master secret (before HKDF).
    pub master_secret: Vec<u8>,
    /// Derived session keys.
    pub session_keys: SessionKeys,
    /// Peer's hybrid public key.
    pub peer_public_key: HybridPublicKey,
    /// Session ID (32 bytes).
    pub session_id: [u8; 32],
}

/// Handshake initiator (client)
pub struct HandshakeInitiator {
    config: HandshakeConfig,
    local_keypair: HybridKeyPair,
    state: HandshakeState,
    client_random: [u8; 32],
    server_random: Option<[u8; 32]>,
    shared_secret: Option<Vec<u8>>,
    peer_public_key: Option<HybridPublicKey>,
    start_time: u64,
    /// ZK challenge from responder (when using ZK auth)
    pending_zk_challenge: Option<ZkChallenge>,
}

/// Handshake responder (server)
pub struct HandshakeResponder {
    config: HandshakeConfig,
    local_keypair: HybridKeyPair,
    state: HandshakeState,
    server_random: [u8; 32],
    client_random: Option<[u8; 32]>,
    shared_secret: Option<Vec<u8>>,
    peer_public_key: Option<HybridPublicKey>,
    start_time: u64,
    /// ZK challenge ID (when ZK verifier is used)
    pending_zk_challenge_id: Option<[u8; 16]>,
}

impl HandshakeInitiator {
    /// Create new handshake initiator.
    pub fn new(config: HandshakeConfig) -> CryptoResult<Self> {
        let local_keypair = hybrid::keypair()?;
        let mut client_random = [0u8; 32];
        random::fill_random(&mut client_random)?;
        
        let start_time = time::current_time_millis();

        Ok(HandshakeInitiator {
            config,
            local_keypair,
            state: HandshakeState::Initiation,
            client_random,
            server_random: None,
            shared_secret: None,
            peer_public_key: None,
            start_time,
            pending_zk_challenge: None,
        })
    }

    /// Generate HandshakeInit message.
    pub fn generate_init(&mut self) -> CryptoResult<HandshakeInit> {
        if self.state != HandshakeState::Initiation {
            return Err(CryptoError::InvalidInput("Invalid state for init".to_string()));
        }

        // Serialize public key using to_bytes
        let hybrid_public_key = self.local_keypair.public_key.to_bytes();

        // Create message to sign
        let mut message_to_sign = Vec::new();
        message_to_sign.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        message_to_sign.extend_from_slice(&self.client_random);
        message_to_sign.extend_from_slice(&hybrid_public_key);

        // Sign the message using secret_key
        let signature = hybrid::sign(&self.local_keypair.secret_key, &message_to_sign)?;
        
        // Serialize signature manually
        let mut signature_bytes = Vec::new();
        signature_bytes.extend_from_slice(&(signature.ecdsa_signature.len() as u32).to_be_bytes());
        signature_bytes.extend_from_slice(&signature.ecdsa_signature);
        signature_bytes.extend_from_slice(signature.dilithium_signature.as_bytes());

        self.state = HandshakeState::WaitingResponse;

        Ok(HandshakeInit {
            protocol_version: PROTOCOL_VERSION,
            client_random: self.client_random,
            hybrid_public_key,
            supported_algorithms: self.config.supported_algorithms.clone(),
            extensions: self.config.extensions.clone(),
            signature: signature_bytes,
        })
    }

    /// Process HandshakeResponse from server.
    pub fn process_response(&mut self, response: HandshakeResponse) -> CryptoResult<()> {
        if self.state != HandshakeState::WaitingResponse {
            return Err(CryptoError::InvalidInput("Invalid state for response".to_string()));
        }

        if response.protocol_version != PROTOCOL_VERSION {
            return Err(CryptoError::InvalidInput("Protocol version mismatch".to_string()));
        }

        // Deserialize peer's public key using from_bytes
        let peer_public_key = HybridPublicKey::from_bytes(&response.hybrid_public_key)?;

        // Verify signature
        let mut message_to_verify = Vec::new();
        message_to_verify.extend_from_slice(&response.protocol_version.to_be_bytes());
        message_to_verify.extend_from_slice(&response.server_random);
        message_to_verify.extend_from_slice(&response.hybrid_public_key);
        message_to_verify.extend_from_slice(&response.encrypted_shared_secret);

        // Deserialize signature manually
        let signature = deserialize_signature(&response.signature)?;

        // Verify signature dan kembalikan error jika tidak valid
        let is_valid = hybrid::verify(&peer_public_key, &message_to_verify, &signature)?;
        if !is_valid {
            return Err(CryptoError::VerificationFailed("Response signature verification failed".to_string()));
        }

        // Deserialize ciphertext manually
        let ciphertext = deserialize_ciphertext(&response.encrypted_shared_secret)?;

        // Decapsulate using secret_key
        let shared_secret = hybrid::decapsulate(&self.local_keypair.secret_key, &ciphertext)?;

        self.server_random = Some(response.server_random);
        self.shared_secret = Some(shared_secret);
        self.peer_public_key = Some(peer_public_key);

        // Extract ZK challenge if present and we have zk_identity
        if self.config.zk_identity.is_some() {
            for ext in &response.extensions {
                if ext.extension_type == EXTENSION_TYPE_ZK_CHALLENGE {
                    self.pending_zk_challenge = Some(ZkChallenge::from_bytes(&ext.data)?);
                    break;
                }
            }
        }

        self.state = HandshakeState::WaitingComplete;

        Ok(())
    }

    /// Generate HandshakeComplete message.
    pub fn generate_complete(&mut self) -> CryptoResult<HandshakeComplete> {
        if self.state != HandshakeState::WaitingComplete {
            return Err(CryptoError::InvalidInput("Invalid state for complete".to_string()));
        }

        let confirmation = self.generate_confirmation()?;

        // Sign the confirmation using secret_key
        let signature = hybrid::sign(&self.local_keypair.secret_key, &confirmation)?;
        
        // Serialize signature manually
        let mut signature_bytes = Vec::new();
        signature_bytes.extend_from_slice(&(signature.ecdsa_signature.len() as u32).to_be_bytes());
        signature_bytes.extend_from_slice(&signature.ecdsa_signature);
        signature_bytes.extend_from_slice(signature.dilithium_signature.as_bytes());

        // Add ZK proof extension if we have challenge and identity
        let mut extensions = self.config.extensions.clone();
        if let (Some(identity), Some(challenge)) = (&self.config.zk_identity, self.pending_zk_challenge.take()) {
            let proof = identity.generate_proof(&challenge)?;
            extensions.push(Extension {
                extension_type: EXTENSION_TYPE_ZK_PROOF,
                data: proof.to_bytes(),
            });
        }

        self.state = HandshakeState::Completed;

        Ok(HandshakeComplete {
            confirmation,
            signature: signature_bytes,
            extensions,
        })
    }

    /// Finalizes the handshake after completion. Derives master secret, session keys,
    /// and session ID from the shared secret and server random.
    pub fn finalize(&self) -> CryptoResult<HandshakeResult> {
        if self.state != HandshakeState::Completed {
            return Err(CryptoError::InvalidInput("Handshake not completed".to_string()));
        }

        let shared_secret = self.shared_secret.as_ref()
            .ok_or_else(|| CryptoError::InvalidInput("No shared secret".to_string()))?;

        let server_random = self.server_random
            .ok_or_else(|| CryptoError::InvalidInput("No server random".to_string()))?;

        let peer_public_key = self.peer_public_key.clone()
            .ok_or_else(|| CryptoError::InvalidInput("No peer public key".to_string()))?;

        // Spec: master_secret = HKDF(ikm=shared_secret, salt=client_random||server_random, info="B4AE-v1-master-secret")
        let master_secret = self.derive_master_secret(shared_secret, &server_random)?;
        let session_keys = self.derive_session_keys(&master_secret)?;
        let session_id = self.generate_session_id(&server_random)?;

        Ok(HandshakeResult {
            master_secret,
            session_keys,
            peer_public_key,
            session_id,
        })
    }

    fn generate_confirmation(&self) -> CryptoResult<[u8; 32]> {
        let shared_secret = self.shared_secret.as_ref()
            .ok_or_else(|| CryptoError::InvalidInput("No shared secret".to_string()))?;

        let server_random = self.server_random
            .ok_or_else(|| CryptoError::InvalidInput("No server random".to_string()))?;

        let mut data = Vec::new();
        data.extend_from_slice(&self.client_random);
        data.extend_from_slice(&server_random);
        data.extend_from_slice(shared_secret);

        // Use hkdf::derive_key with correct API
        let confirmation = hkdf::derive_key(
            &[shared_secret],
            b"handshake-confirmation",
            32
        )?;

        let mut result = [0u8; 32];
        result.copy_from_slice(&confirmation);
        Ok(result)
    }

    /// Derive master_secret per spec: HKDF(ikm=shared_secret, salt=client_random||server_random, info="B4AE-v1-master-secret")
    fn derive_master_secret(&self, shared_secret: &[u8], server_random: &[u8; 32]) -> CryptoResult<Vec<u8>> {
        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(&self.client_random);
        salt.extend_from_slice(server_random);
        hkdf::derive_key_with_salt(&salt, &[shared_secret], b"B4AE-v1-master-secret", 32)
    }

    /// Derive session keys from master_secret per spec (B4AE-v1-encryption-key, etc.)
    fn derive_session_keys(&self, master_secret: &[u8]) -> CryptoResult<SessionKeys> {
        let kdf = hkdf::B4aeKeyDerivation::new(master_secret.to_vec());
        let keys = kdf.derive_all_keys()?;
        Ok(SessionKeys {
            encryption_key: keys.encryption_key.clone(),
            authentication_key: keys.authentication_key.clone(),
            metadata_key: keys.metadata_key.clone(),
        })
    }

    fn generate_session_id(&self, server_random: &[u8; 32]) -> CryptoResult<[u8; 32]> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.client_random);
        data.extend_from_slice(server_random);

        let session_id = hkdf::derive_key(
            &[&data],
            b"session-id",
            32
        )?;

        let mut result = [0u8; 32];
        result.copy_from_slice(&session_id);
        Ok(result)
    }

    /// Current handshake state.
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Whether handshake has timed out.
    pub fn is_timed_out(&self) -> bool {
        let current_time = time::current_time_millis();
        current_time - self.start_time > self.config.timeout_ms
    }
}
impl HandshakeResponder {
    /// Create new handshake responder.
    pub fn new(config: HandshakeConfig) -> CryptoResult<Self> {
        let local_keypair = hybrid::keypair()?;
        let mut server_random = [0u8; 32];
        random::fill_random(&mut server_random)?;

        let start_time = time::current_time_millis();

        Ok(HandshakeResponder {
            config,
            local_keypair,
            state: HandshakeState::Initiation,
            server_random,
            client_random: None,
            shared_secret: None,
            peer_public_key: None,
            start_time,
            pending_zk_challenge_id: None,
        })
    }

    /// Process HandshakeInit from client.
    pub fn process_init(&mut self, init: HandshakeInit) -> CryptoResult<HandshakeResponse> {
        if self.state != HandshakeState::Initiation {
            return Err(CryptoError::InvalidInput("Invalid state for init".to_string()));
        }

        if init.protocol_version != PROTOCOL_VERSION {
            return Err(CryptoError::InvalidInput("Protocol version mismatch".to_string()));
        }

        // Deserialize peer's public key using from_bytes
        let peer_public_key = HybridPublicKey::from_bytes(&init.hybrid_public_key)?;

        // Verify signature
        let mut message_to_verify = Vec::new();
        message_to_verify.extend_from_slice(&init.protocol_version.to_be_bytes());
        message_to_verify.extend_from_slice(&init.client_random);
        message_to_verify.extend_from_slice(&init.hybrid_public_key);

        // Deserialize signature manually
        let signature = deserialize_signature(&init.signature)?;

        // Verify signature dan kembalikan error jika tidak valid
        let is_valid = hybrid::verify(&peer_public_key, &message_to_verify, &signature)?;
        if !is_valid {
            return Err(CryptoError::VerificationFailed("Init signature verification failed".to_string()));
        }

        // Encapsulate - returns (shared_secret, ciphertext)
        let (shared_secret, ciphertext) = hybrid::encapsulate(&peer_public_key)?;

        // Serialize ciphertext manually
        let encrypted_shared_secret = serialize_ciphertext(&ciphertext);

        // Serialize our public key using to_bytes
        let hybrid_public_key = self.local_keypair.public_key.to_bytes();

        // Create message to sign
        let mut message_to_sign = Vec::new();
        message_to_sign.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        message_to_sign.extend_from_slice(&self.server_random);
        message_to_sign.extend_from_slice(&hybrid_public_key);
        message_to_sign.extend_from_slice(&encrypted_shared_secret);

        // Sign the message using secret_key
        let response_signature = hybrid::sign(&self.local_keypair.secret_key, &message_to_sign)?;
        
        // Serialize signature manually
        let mut signature_bytes = Vec::new();
        signature_bytes.extend_from_slice(&(response_signature.ecdsa_signature.len() as u32).to_be_bytes());
        signature_bytes.extend_from_slice(&response_signature.ecdsa_signature);
        signature_bytes.extend_from_slice(response_signature.dilithium_signature.as_bytes());

        let selected_algorithms = self.config.supported_algorithms.clone();

        // Add ZK challenge extension if zk_verifier is configured
        let mut extensions = self.config.extensions.clone();
        if let Some(ref verifier) = self.config.zk_verifier {
            let challenge = verifier.lock().map_err(|e| CryptoError::InvalidInput(e.to_string()))?.generate_challenge();
            extensions.push(Extension {
                extension_type: EXTENSION_TYPE_ZK_CHALLENGE,
                data: challenge.to_bytes(),
            });
            self.pending_zk_challenge_id = Some(challenge.challenge_id);
        }

        self.client_random = Some(init.client_random);
        self.shared_secret = Some(shared_secret);
        self.peer_public_key = Some(peer_public_key);
        self.state = HandshakeState::WaitingComplete;

        Ok(HandshakeResponse {
            protocol_version: PROTOCOL_VERSION,
            server_random: self.server_random,
            hybrid_public_key,
            encrypted_shared_secret,
            selected_algorithms,
            extensions,
            signature: signature_bytes,
        })
    }

    /// Process HandshakeComplete from client.
    pub fn process_complete(&mut self, complete: HandshakeComplete) -> CryptoResult<()> {
        if self.state != HandshakeState::WaitingComplete {
            return Err(CryptoError::InvalidInput("Invalid state for complete".to_string()));
        }

        let peer_public_key = self.peer_public_key.as_ref()
            .ok_or_else(|| CryptoError::InvalidInput("No peer public key".to_string()))?;

        // Verify ZK proof if we sent a challenge
        if let (Some(ref verifier), Some(challenge_id)) = (&self.config.zk_verifier, self.pending_zk_challenge_id) {
            let proof_ext = complete.extensions.iter()
                .find(|e| e.extension_type == EXTENSION_TYPE_ZK_PROOF)
                .ok_or_else(|| CryptoError::AuthenticationFailed)?;
            let proof = ZkProof::from_bytes(&proof_ext.data)?;
            let auth = verifier.lock().map_err(|e| CryptoError::InvalidInput(e.to_string()))?
                .verify_proof(&proof, &challenge_id)
                .map_err(|_| CryptoError::AuthenticationFailed)?;
            if auth.is_none() {
                return Err(CryptoError::AuthenticationFailed);
            }
            self.pending_zk_challenge_id = None;
        }

        // Deserialize signature manually
        let signature = deserialize_signature(&complete.signature)?;

        // Verify signature dan kembalikan error jika tidak valid
        let is_valid = hybrid::verify(peer_public_key, &complete.confirmation, &signature)?;
        if !is_valid {
            return Err(CryptoError::VerificationFailed("Complete signature verification failed".to_string()));
        }

        let expected_confirmation = self.generate_expected_confirmation()?;
        
        // Menggunakan constant-time comparison untuk mencegah timing attacks
        // Tidak menggunakan == karena bisa bocor informasi melalui timing
        let confirmation_valid = complete.confirmation.ct_eq(&expected_confirmation);
        if !bool::from(confirmation_valid) {
            return Err(CryptoError::VerificationFailed("Confirmation mismatch".to_string()));
        }

        self.state = HandshakeState::Completed;
        Ok(())
    }

    /// Finalizes the handshake after completion. Derives master secret, session keys,
    /// and session ID from the shared secret and client random.
    pub fn finalize(&self) -> CryptoResult<HandshakeResult> {
        if self.state != HandshakeState::Completed {
            return Err(CryptoError::InvalidInput("Handshake not completed".to_string()));
        }

        let shared_secret = self.shared_secret.as_ref()
            .ok_or_else(|| CryptoError::InvalidInput("No shared secret".to_string()))?;

        let client_random = self.client_random
            .ok_or_else(|| CryptoError::InvalidInput("No client random".to_string()))?;

        let peer_public_key = self.peer_public_key.clone()
            .ok_or_else(|| CryptoError::InvalidInput("No peer public key".to_string()))?;

        // Spec: master_secret = HKDF(ikm=shared_secret, salt=client_random||server_random, info="B4AE-v1-master-secret")
        let master_secret = self.derive_master_secret(shared_secret, &client_random)?;
        let session_keys = self.derive_session_keys(&master_secret)?;
        let session_id = self.generate_session_id(&client_random)?;

        Ok(HandshakeResult {
            master_secret,
            session_keys,
            peer_public_key,
            session_id,
        })
    }

    fn generate_expected_confirmation(&self) -> CryptoResult<[u8; 32]> {
        let shared_secret = self.shared_secret.as_ref()
            .ok_or_else(|| CryptoError::InvalidInput("No shared secret".to_string()))?;

        let client_random = self.client_random
            .ok_or_else(|| CryptoError::InvalidInput("No client random".to_string()))?;

        let mut data = Vec::new();
        data.extend_from_slice(&client_random);
        data.extend_from_slice(&self.server_random);
        data.extend_from_slice(shared_secret);

        // Use hkdf::derive_key with correct API
        let confirmation = hkdf::derive_key(
            &[shared_secret],
            b"handshake-confirmation",
            32
        )?;

        let mut result = [0u8; 32];
        result.copy_from_slice(&confirmation);
        Ok(result)
    }

    /// Derive master_secret per spec: HKDF(ikm=shared_secret, salt=client_random||server_random, info="B4AE-v1-master-secret")
    fn derive_master_secret(&self, shared_secret: &[u8], client_random: &[u8; 32]) -> CryptoResult<Vec<u8>> {
        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(client_random);
        salt.extend_from_slice(&self.server_random);
        hkdf::derive_key_with_salt(&salt, &[shared_secret], b"B4AE-v1-master-secret", 32)
    }

    /// Derive session keys from master_secret per spec (B4AE-v1-encryption-key, etc.)
    fn derive_session_keys(&self, master_secret: &[u8]) -> CryptoResult<SessionKeys> {
        let kdf = hkdf::B4aeKeyDerivation::new(master_secret.to_vec());
        let keys = kdf.derive_all_keys()?;
        Ok(SessionKeys {
            encryption_key: keys.encryption_key.clone(),
            authentication_key: keys.authentication_key.clone(),
            metadata_key: keys.metadata_key.clone(),
        })
    }

    fn generate_session_id(&self, client_random: &[u8; 32]) -> CryptoResult<[u8; 32]> {
        let mut data = Vec::new();
        data.extend_from_slice(client_random);
        data.extend_from_slice(&self.server_random);

        let session_id = hkdf::derive_key(
            &[&data],
            b"session-id",
            32
        )?;

        let mut result = [0u8; 32];
        result.copy_from_slice(&session_id);
        Ok(result)
    }

    /// Current handshake state.
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Whether handshake has timed out.
    pub fn is_timed_out(&self) -> bool {
        let current_time = time::current_time_millis();
        current_time - self.start_time > self.config.timeout_ms
    }
}

// Helper functions for manual serialization/deserialization

fn serialize_ciphertext(ciphertext: &HybridCiphertext) -> Vec<u8> {
    let mut bytes = Vec::new();
    
    // ECDH ephemeral public key length + data
    bytes.extend_from_slice(&(ciphertext.ecdh_ephemeral_public.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&ciphertext.ecdh_ephemeral_public);
    
    // Kyber ciphertext
    bytes.extend_from_slice(ciphertext.kyber_ciphertext.as_bytes());
    
    bytes
}

fn deserialize_ciphertext(bytes: &[u8]) -> CryptoResult<HybridCiphertext> {
    use crate::crypto::kyber::KyberCiphertext;
    
    let mut offset = 0;
    
    // Read ECDH ephemeral public key
    if bytes.len() < offset + 4 {
        return Err(CryptoError::InvalidInput("Insufficient data".to_string()));
    }
    let ecdh_len = u32::from_be_bytes([
        bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]
    ]) as usize;
    offset += 4;
    if ecdh_len > 256 {
        return Err(CryptoError::InvalidInput("ECDH ephemeral key length exceeds limit".to_string()));
    }
    if bytes.len() < offset + ecdh_len {
        return Err(CryptoError::InvalidInput("Insufficient data for ECDH key".to_string()));
    }
    let ecdh_ephemeral_public = bytes[offset..offset + ecdh_len].to_vec();
    offset += ecdh_len;
    
    // Read Kyber ciphertext
    if bytes.len() < offset + KyberCiphertext::SIZE {
        return Err(CryptoError::InvalidInput("Insufficient data for Kyber ciphertext".to_string()));
    }
    let kyber_ciphertext = KyberCiphertext::from_bytes(&bytes[offset..offset + KyberCiphertext::SIZE])?;
    
    Ok(HybridCiphertext {
        ecdh_ephemeral_public,
        kyber_ciphertext,
    })
}

fn deserialize_signature(bytes: &[u8]) -> CryptoResult<HybridSignature> {
    use crate::crypto::dilithium::DilithiumSignature;
    
    let mut offset = 0;
    
    // Read ECDSA signature
    if bytes.len() < offset + 4 {
        return Err(CryptoError::InvalidInput("Insufficient data".to_string()));
    }
    let ecdsa_len = u32::from_be_bytes([
        bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]
    ]) as usize;
    offset += 4;
    if ecdsa_len > 128 {
        return Err(CryptoError::InvalidInput("ECDSA signature length exceeds limit".to_string()));
    }
    if bytes.len() < offset + ecdsa_len {
        return Err(CryptoError::InvalidInput("Insufficient data for ECDSA signature".to_string()));
    }
    let ecdsa_signature = bytes[offset..offset + ecdsa_len].to_vec();
    offset += ecdsa_len;
    
    // Read Dilithium signature
    if bytes.len() < offset + DilithiumSignature::SIZE {
        return Err(CryptoError::InvalidInput("Insufficient data for Dilithium signature".to_string()));
    }
    let dilithium_signature = DilithiumSignature::from_bytes(&bytes[offset..offset + DilithiumSignature::SIZE])?;
    
    Ok(HybridSignature {
        ecdsa_signature,
        dilithium_signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_flow() -> CryptoResult<()> {
        let config = HandshakeConfig::default();
        let mut initiator = HandshakeInitiator::new(config.clone())?;
        let mut responder = HandshakeResponder::new(config)?;

        let init = initiator.generate_init()?;
        assert_eq!(initiator.state(), HandshakeState::WaitingResponse);

        let response = responder.process_init(init)?;
        assert_eq!(responder.state(), HandshakeState::WaitingComplete);

        initiator.process_response(response)?;
        assert_eq!(initiator.state(), HandshakeState::WaitingComplete);

        let complete = initiator.generate_complete()?;
        assert_eq!(initiator.state(), HandshakeState::Completed);

        responder.process_complete(complete)?;
        assert_eq!(responder.state(), HandshakeState::Completed);

        let initiator_result = initiator.finalize()?;
        let responder_result = responder.finalize()?;

        assert_eq!(initiator_result.session_id, responder_result.session_id);
        assert_eq!(
            initiator_result.session_keys.encryption_key,
            responder_result.session_keys.encryption_key
        );

        Ok(())
    }

    #[test]
    fn test_handshake_timeout() -> CryptoResult<()> {
        let mut config = HandshakeConfig::default();
        config.timeout_ms = 0;

        let initiator = HandshakeInitiator::new(config)?;
        std::thread::sleep(std::time::Duration::from_millis(10));

        assert!(initiator.is_timed_out());
        Ok(())
    }

    #[test]
    fn test_invalid_state_transitions() -> CryptoResult<()> {
        let config = HandshakeConfig::default();
        let mut initiator = HandshakeInitiator::new(config)?;

        let result = initiator.generate_complete();
        assert!(result.is_err());

        Ok(())
    }
}
