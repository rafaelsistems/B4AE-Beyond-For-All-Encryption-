// B4AE Handshake Protocol Implementation
// Three-way handshake with quantum-resistant key exchange

use crate::crypto::{CryptoError, CryptoResult};
use crate::crypto::hybrid::{self, HybridKeyPair, HybridPublicKey, HybridCiphertext, HybridSignature};
use crate::crypto::hkdf;
use crate::crypto::random;
use crate::protocol::PROTOCOL_VERSION;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

/// Handshake state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    Initial,
    WaitingResponse,
    WaitingComplete,
    Completed,
    Failed,
}

/// Algorithm identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum AlgorithmId {
    Kyber1024 = 0x0001,
    Dilithium5 = 0x0002,
    EcdhP521 = 0x0003,
    EcdsaP521 = 0x0004,
    Aes256Gcm = 0x0005,
    Sha3_256 = 0x0006,
}

/// Handshake extension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extension {
    pub extension_type: u16,
    pub data: Vec<u8>,
}

/// Handshake Init message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeInit {
    pub protocol_version: u16,
    pub client_random: [u8; 32],
    pub hybrid_public_key: Vec<u8>,
    pub supported_algorithms: Vec<AlgorithmId>,
    pub extensions: Vec<Extension>,
    pub signature: Vec<u8>,
}

/// Handshake Response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub protocol_version: u16,
    pub server_random: [u8; 32],
    pub hybrid_public_key: Vec<u8>,
    pub encrypted_shared_secret: Vec<u8>,
    pub selected_algorithms: Vec<AlgorithmId>,
    pub extensions: Vec<Extension>,
    pub signature: Vec<u8>,
}

/// Handshake Complete message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeComplete {
    pub confirmation: [u8; 32],
    pub signature: Vec<u8>,
}

/// Handshake configuration
#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    pub timeout_ms: u64,
    pub supported_algorithms: Vec<AlgorithmId>,
    pub required_algorithms: Vec<AlgorithmId>,
    pub extensions: Vec<Extension>,
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
        }
    }
}

/// Session keys derived from handshake
#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub encryption_key: Vec<u8>,
    pub authentication_key: Vec<u8>,
    pub metadata_key: Vec<u8>,
}

/// Handshake result containing session keys
#[derive(Debug)]
pub struct HandshakeResult {
    pub master_secret: Vec<u8>,
    pub session_keys: SessionKeys,
    pub peer_public_key: HybridPublicKey,
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
}

impl HandshakeInitiator {
    pub fn new(config: HandshakeConfig) -> CryptoResult<Self> {
        let local_keypair = hybrid::keypair()?;
        let mut client_random = [0u8; 32];
        random::fill_random(&mut client_random)?;
        
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Ok(HandshakeInitiator {
            config,
            local_keypair,
            state: HandshakeState::Initial,
            client_random,
            server_random: None,
            shared_secret: None,
            peer_public_key: None,
            start_time,
        })
    }

    pub fn generate_init(&mut self) -> CryptoResult<HandshakeInit> {
        if self.state != HandshakeState::Initial {
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
        self.state = HandshakeState::WaitingComplete;

        Ok(())
    }

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

        self.state = HandshakeState::Completed;

        Ok(HandshakeComplete {
            confirmation,
            signature: signature_bytes,
        })
    }

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

        let session_keys = self.derive_session_keys(shared_secret, &server_random)?;
        let session_id = self.generate_session_id(&server_random)?;

        Ok(HandshakeResult {
            master_secret: shared_secret.clone(),
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

    fn derive_session_keys(&self, shared_secret: &[u8], server_random: &[u8; 32]) -> CryptoResult<SessionKeys> {
        let mut key_material = Vec::new();
        key_material.extend_from_slice(&self.client_random);
        key_material.extend_from_slice(server_random);

        // Derive three keys using hkdf::derive_key
        let encryption_key = hkdf::derive_key(
            &[shared_secret, &key_material],
            b"B4AE-v1-encryption",
            32
        )?;
        
        let authentication_key = hkdf::derive_key(
            &[shared_secret, &key_material],
            b"B4AE-v1-authentication",
            32
        )?;
        
        let metadata_key = hkdf::derive_key(
            &[shared_secret, &key_material],
            b"B4AE-v1-metadata",
            32
        )?;

        Ok(SessionKeys {
            encryption_key,
            authentication_key,
            metadata_key,
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

    pub fn state(&self) -> HandshakeState {
        self.state
    }

    pub fn is_timed_out(&self) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        current_time - self.start_time > self.config.timeout_ms
    }
}
impl HandshakeResponder {
    pub fn new(config: HandshakeConfig) -> CryptoResult<Self> {
        let local_keypair = hybrid::keypair()?;
        let mut server_random = [0u8; 32];
        random::fill_random(&mut server_random)?;

        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Ok(HandshakeResponder {
            config,
            local_keypair,
            state: HandshakeState::Initial,
            server_random,
            client_random: None,
            shared_secret: None,
            peer_public_key: None,
            start_time,
        })
    }

    pub fn process_init(&mut self, init: HandshakeInit) -> CryptoResult<HandshakeResponse> {
        if self.state != HandshakeState::Initial {
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
            extensions: self.config.extensions.clone(),
            signature: signature_bytes,
        })
    }

    pub fn process_complete(&mut self, complete: HandshakeComplete) -> CryptoResult<()> {
        if self.state != HandshakeState::WaitingComplete {
            return Err(CryptoError::InvalidInput("Invalid state for complete".to_string()));
        }

        let peer_public_key = self.peer_public_key.as_ref()
            .ok_or_else(|| CryptoError::InvalidInput("No peer public key".to_string()))?;

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

        let session_keys = self.derive_session_keys(shared_secret, &client_random)?;
        let session_id = self.generate_session_id(&client_random)?;

        Ok(HandshakeResult {
            master_secret: shared_secret.clone(),
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

    fn derive_session_keys(&self, shared_secret: &[u8], client_random: &[u8; 32]) -> CryptoResult<SessionKeys> {
        let mut key_material = Vec::new();
        key_material.extend_from_slice(client_random);
        key_material.extend_from_slice(&self.server_random);

        // Derive three keys using hkdf::derive_key
        let encryption_key = hkdf::derive_key(
            &[shared_secret, &key_material],
            b"B4AE-v1-encryption",
            32
        )?;
        
        let authentication_key = hkdf::derive_key(
            &[shared_secret, &key_material],
            b"B4AE-v1-authentication",
            32
        )?;
        
        let metadata_key = hkdf::derive_key(
            &[shared_secret, &key_material],
            b"B4AE-v1-metadata",
            32
        )?;

        Ok(SessionKeys {
            encryption_key,
            authentication_key,
            metadata_key,
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

    pub fn state(&self) -> HandshakeState {
        self.state
    }

    pub fn is_timed_out(&self) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

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
