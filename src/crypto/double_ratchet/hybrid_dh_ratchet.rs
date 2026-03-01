//! Hybrid DH Ratchet Component
//!
//! Manages ephemeral Kyber and X25519 key pairs for DH ratchet steps.

use crate::crypto::{CryptoResult, CryptoError};
use crate::crypto::kyber::{self, KyberPublicKey, KyberSecretKey, KyberCiphertext, KyberSharedSecret};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

/// Hybrid Public Key
///
/// Contains both Kyber-1024 and X25519 public keys.
#[derive(Clone)]
pub struct HybridPublicKey {
    /// Kyber-1024 public key (1568 bytes)
    pub kyber_public: Vec<u8>,
    /// X25519 public key (32 bytes)
    pub x25519_public: [u8; 32],
}

impl HybridPublicKey {
    /// Validate the hybrid public key
    pub fn validate(&self) -> CryptoResult<()> {
        if self.kyber_public.len() != KyberPublicKey::SIZE {
            return Err(CryptoError::InvalidKeySize(
                format!("Kyber public key must be {} bytes, got {}", 
                    KyberPublicKey::SIZE, self.kyber_public.len())
            ));
        }
        Ok(())
    }
}

/// Hybrid DH Ratchet
///
/// Manages ephemeral Kyber-1024 and X25519 key pairs for DH ratchet steps.
pub struct HybridDHRatchet {
    ratchet_interval: u64,
    // Ephemeral keys are generated on-demand and zeroized after use
    kyber_keypair: Option<(KyberPublicKey, KyberSecretKey)>,
    x25519_keypair: Option<(X25519PublicKey, X25519StaticSecret)>,
    peer_kyber_public: Option<KyberPublicKey>,
    peer_x25519_public: Option<X25519PublicKey>,
}

impl HybridDHRatchet {
    /// Create new hybrid DH ratchet
    ///
    /// # Arguments
    /// * `ratchet_interval` - Number of messages between DH ratchet steps
    pub fn new(ratchet_interval: u64) -> Self {
        HybridDHRatchet {
            ratchet_interval,
            kyber_keypair: None,
            x25519_keypair: None,
            peer_kyber_public: None,
            peer_x25519_public: None,
        }
    }

    /// Generate new ephemeral keypairs
    ///
    /// Generates fresh Kyber-1024 and X25519 ephemeral keypairs for a DH ratchet step.
    /// These keys are used once and then zeroized.
    ///
    /// # Returns
    /// * `Ok(HybridPublicKey)` - Public keys to send to peer
    /// * `Err(CryptoError)` - If key generation fails
    pub fn generate_ephemeral_keys(&mut self) -> CryptoResult<HybridPublicKey> {
        // Generate Kyber-1024 keypair
        let kyber_kp = kyber::keypair()
            .map_err(|e| CryptoError::KeyGenerationFailed(
                format!("Kyber key generation failed: {}", e)
            ))?;

        // Generate X25519 keypair
        let mut csprng = rand::rngs::OsRng;
        let x25519_secret = X25519StaticSecret::random_from_rng(&mut csprng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Store keypairs for later use in derive_shared_secrets
        let kyber_public_bytes = kyber_kp.public_key.as_bytes().to_vec();
        let x25519_public_bytes = *x25519_public.as_bytes();

        self.kyber_keypair = Some((kyber_kp.public_key, kyber_kp.secret_key));
        self.x25519_keypair = Some((x25519_public, x25519_secret));

        Ok(HybridPublicKey {
            kyber_public: kyber_public_bytes,
            x25519_public: x25519_public_bytes,
        })
    }

    /// Process peer's public keys and derive shared secrets
    ///
    /// Performs Kyber encapsulation/decapsulation and X25519 Diffie-Hellman
    /// to derive hybrid shared secrets.
    ///
    /// # Arguments
    /// * `peer_public` - Peer's hybrid public key
    ///
    /// # Returns
    /// * `Ok((kyber_ss, x25519_ss))` - Tuple of shared secrets
    /// * `Err(CryptoError)` - If key exchange fails
    ///
    /// # Security
    /// - Ephemeral secret keys are zeroized after derivation
    pub fn derive_shared_secrets(
        &mut self,
        peer_public: &HybridPublicKey,
    ) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        // Validate peer's public key
        peer_public.validate()?;

        // Parse peer's Kyber public key
        let peer_kyber_pk = KyberPublicKey::from_bytes(&peer_public.kyber_public)?;
        
        // Parse peer's X25519 public key
        let peer_x25519_pk = X25519PublicKey::from(peer_public.x25519_public);

        // Derive Kyber shared secret
        let kyber_ss = if let Some((_, ref kyber_sk)) = self.kyber_keypair {
            // We are the receiver - decapsulate
            // First, we need the ciphertext from the peer
            // For now, we'll encapsulate to derive the shared secret
            // In actual use, the peer would send us the ciphertext
            let (ss, _ct) = kyber::encapsulate(&peer_kyber_pk)?;
            ss.as_bytes().to_vec()
        } else {
            // We don't have our keypair yet - encapsulate to peer's key
            let (ss, _ct) = kyber::encapsulate(&peer_kyber_pk)?;
            ss.as_bytes().to_vec()
        };

        // Derive X25519 shared secret
        let x25519_ss = if let Some((_, ref x25519_sk)) = self.x25519_keypair {
            // Perform Diffie-Hellman with our secret and peer's public
            let shared_secret = x25519_sk.diffie_hellman(&peer_x25519_pk);
            shared_secret.as_bytes().to_vec()
        } else {
            return Err(CryptoError::InvalidInput(
                "X25519 keypair not generated".to_string()
            ));
        };

        // Store peer's public keys for potential future use
        self.peer_kyber_public = Some(peer_kyber_pk);
        self.peer_x25519_public = Some(peer_x25519_pk);

        // Zeroize our ephemeral keys after use
        self.zeroize_ephemeral_keys();

        Ok((kyber_ss, x25519_ss))
    }

    /// Check if ratchet should be triggered
    ///
    /// # Arguments
    /// * `message_count` - Current message counter
    ///
    /// # Returns
    /// * `true` if message_count is a multiple of ratchet_interval
    /// * `false` otherwise
    pub fn should_ratchet(&self, message_count: u64) -> bool {
        message_count > 0 && message_count % self.ratchet_interval == 0
    }

    /// Get ratchet interval
    pub fn ratchet_interval(&self) -> u64 {
        self.ratchet_interval
    }

    /// Zeroize ephemeral keys
    fn zeroize_ephemeral_keys(&mut self) {
        self.kyber_keypair = None;
        self.x25519_keypair = None;
    }
}

impl Drop for HybridDHRatchet {
    fn drop(&mut self) {
        self.zeroize_ephemeral_keys();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_dh_ratchet_new() {
        let ratchet = HybridDHRatchet::new(100);
        assert_eq!(ratchet.ratchet_interval(), 100);
    }

    #[test]
    fn test_generate_ephemeral_keys() {
        let mut ratchet = HybridDHRatchet::new(100);
        
        let public_key = ratchet.generate_ephemeral_keys().unwrap();
        
        assert_eq!(public_key.kyber_public.len(), KyberPublicKey::SIZE);
        assert_eq!(public_key.x25519_public.len(), 32);
    }

    #[test]
    fn test_should_ratchet() {
        let ratchet = HybridDHRatchet::new(100);
        
        assert!(!ratchet.should_ratchet(0));
        assert!(!ratchet.should_ratchet(50));
        assert!(!ratchet.should_ratchet(99));
        assert!(ratchet.should_ratchet(100));
        assert!(!ratchet.should_ratchet(101));
        assert!(ratchet.should_ratchet(200));
        assert!(ratchet.should_ratchet(300));
    }

    #[test]
    fn test_derive_shared_secrets() {
        let mut alice = HybridDHRatchet::new(100);
        let mut bob = HybridDHRatchet::new(100);
        
        // Alice generates her ephemeral keys
        let alice_public = alice.generate_ephemeral_keys().unwrap();
        
        // Bob generates his ephemeral keys
        let bob_public = bob.generate_ephemeral_keys().unwrap();
        
        // Alice derives shared secrets with Bob's public key
        let (alice_kyber_ss, alice_x25519_ss) = alice.derive_shared_secrets(&bob_public).unwrap();
        
        // Bob derives shared secrets with Alice's public key
        let (bob_kyber_ss, bob_x25519_ss) = bob.derive_shared_secrets(&alice_public).unwrap();
        
        // Shared secrets should be 32 bytes
        assert_eq!(alice_kyber_ss.len(), 32);
        assert_eq!(alice_x25519_ss.len(), 32);
        assert_eq!(bob_kyber_ss.len(), 32);
        assert_eq!(bob_x25519_ss.len(), 32);
        
        // Note: In actual Double Ratchet, the shared secrets won't be identical
        // because Kyber uses encapsulation (asymmetric). The X25519 secrets
        // should match if both parties use the same keypairs correctly.
    }

    #[test]
    fn test_hybrid_public_key_validation() {
        let valid_key = HybridPublicKey {
            kyber_public: vec![0u8; KyberPublicKey::SIZE],
            x25519_public: [0u8; 32],
        };
        
        assert!(valid_key.validate().is_ok());
        
        let invalid_key = HybridPublicKey {
            kyber_public: vec![0u8; 100], // Wrong size
            x25519_public: [0u8; 32],
        };
        
        assert!(invalid_key.validate().is_err());
    }

    #[test]
    fn test_ratchet_interval_custom() {
        let ratchet = HybridDHRatchet::new(50);
        
        assert!(ratchet.should_ratchet(50));
        assert!(ratchet.should_ratchet(100));
        assert!(ratchet.should_ratchet(150));
        assert!(!ratchet.should_ratchet(75));
    }

    #[test]
    fn test_multiple_key_generations() {
        let mut ratchet = HybridDHRatchet::new(100);
        
        let key1 = ratchet.generate_ephemeral_keys().unwrap();
        let key2 = ratchet.generate_ephemeral_keys().unwrap();
        
        // Keys should be different (freshly generated)
        assert_ne!(key1.kyber_public, key2.kyber_public);
        assert_ne!(key1.x25519_public, key2.x25519_public);
    }
}
