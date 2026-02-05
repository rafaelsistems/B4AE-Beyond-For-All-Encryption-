// B4AE Hybrid Cryptography Implementation
// Combines Classical (X25519/Ed25519) with Post-Quantum (Kyber/Dilithium)
// 
// Menggunakan:
// - x25519-dalek untuk key exchange (mendukung static secret)
// - ring untuk Ed25519 digital signatures
// - pqcrypto untuk Post-Quantum (Kyber/Dilithium)

use crate::crypto::{CryptoError, CryptoResult};
use crate::crypto::kyber::{self, KyberPublicKey, KyberSecretKey, KyberCiphertext};
use crate::crypto::dilithium::{self, DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature};
use crate::crypto::hkdf;
use x25519_dalek::{StaticSecret as X25519StaticSecret, PublicKey as X25519PublicKey, EphemeralSecret};
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use ring::rand::SystemRandom;
use std::fmt;
use zeroize::Zeroize;

/// X25519 Public Key Size (32 bytes)
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;
/// Ed25519 Public Key Size (32 bytes)
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
/// Ed25519 Signature Size (64 bytes)
pub const ED25519_SIGNATURE_SIZE: usize = 64;
/// Ed25519 Secret Key Size (PKCS#8 format, ~83 bytes)
pub const ED25519_PKCS8_SIZE: usize = 83;

/// Hybrid Public Key (Classical + Post-Quantum)
#[derive(Clone)]
pub struct HybridPublicKey {
    /// X25519 public key untuk key exchange (32 bytes)
    pub ecdh_public: Vec<u8>,
    /// Kyber-1024 public key untuk post-quantum key exchange
    pub kyber_public: KyberPublicKey,
    /// Ed25519 public key untuk signatures (32 bytes)
    pub ecdsa_public: Vec<u8>,
    /// Dilithium5 public key untuk post-quantum signatures
    pub dilithium_public: DilithiumPublicKey,
}

/// Hybrid Secret Key (Classical + Post-Quantum)
pub struct HybridSecretKey {
    /// X25519 private key seed (32 bytes) - digunakan untuk regenerasi
    pub ecdh_secret: Vec<u8>,
    /// Kyber-1024 secret key
    pub kyber_secret: KyberSecretKey,
    /// Ed25519 keypair dalam format PKCS#8
    pub ecdsa_secret: Vec<u8>,
    /// Dilithium5 secret key
    pub dilithium_secret: DilithiumSecretKey,
}

/// Hybrid Key Pair
pub struct HybridKeyPair {
    pub public_key: HybridPublicKey,
    pub secret_key: HybridSecretKey,
}

/// Hybrid Ciphertext (untuk key exchange)
#[derive(Clone)]
pub struct HybridCiphertext {
    /// Ephemeral X25519 public key
    pub ecdh_ephemeral_public: Vec<u8>,
    /// Kyber ciphertext
    pub kyber_ciphertext: KyberCiphertext,
}

/// Hybrid Signature
#[derive(Clone)]
pub struct HybridSignature {
    /// Ed25519 signature (64 bytes)
    pub ecdsa_signature: Vec<u8>,
    /// Dilithium5 signature
    pub dilithium_signature: DilithiumSignature,
}

impl HybridPublicKey {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // X25519 public key length + data
        bytes.extend_from_slice(&(self.ecdh_public.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.ecdh_public);
        
        // Kyber public key
        bytes.extend_from_slice(self.kyber_public.as_bytes());
        
        // Ed25519 public key length + data
        bytes.extend_from_slice(&(self.ecdsa_public.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.ecdsa_public);
        
        // Dilithium public key
        bytes.extend_from_slice(self.dilithium_public.as_bytes());
        
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        let mut offset = 0;
        
        // Read X25519 public key
        if bytes.len() < offset + 2 {
            return Err(CryptoError::InvalidInput("Insufficient data".to_string()));
        }
        let ecdh_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        
        if bytes.len() < offset + ecdh_len {
            return Err(CryptoError::InvalidInput("Insufficient data for ECDH key".to_string()));
        }
        let ecdh_public = bytes[offset..offset + ecdh_len].to_vec();
        offset += ecdh_len;
        
        // Read Kyber public key
        if bytes.len() < offset + KyberPublicKey::SIZE {
            return Err(CryptoError::InvalidInput("Insufficient data for Kyber key".to_string()));
        }
        let kyber_public = KyberPublicKey::from_bytes(&bytes[offset..offset + KyberPublicKey::SIZE])?;
        offset += KyberPublicKey::SIZE;
        
        // Read Ed25519 public key
        if bytes.len() < offset + 2 {
            return Err(CryptoError::InvalidInput("Insufficient data".to_string()));
        }
        let ecdsa_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        
        if bytes.len() < offset + ecdsa_len {
            return Err(CryptoError::InvalidInput("Insufficient data for ECDSA key".to_string()));
        }
        let ecdsa_public = bytes[offset..offset + ecdsa_len].to_vec();
        offset += ecdsa_len;
        
        // Read Dilithium public key
        if bytes.len() < offset + DilithiumPublicKey::SIZE {
            return Err(CryptoError::InvalidInput("Insufficient data for Dilithium key".to_string()));
        }
        let dilithium_public = DilithiumPublicKey::from_bytes(&bytes[offset..offset + DilithiumPublicKey::SIZE])?;
        
        Ok(HybridPublicKey {
            ecdh_public,
            kyber_public,
            ecdsa_public,
            dilithium_public,
        })
    }
}

impl HybridSignature {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Ed25519 signature length + data
        bytes.extend_from_slice(&(self.ecdsa_signature.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.ecdsa_signature);
        
        // Dilithium signature
        bytes.extend_from_slice(self.dilithium_signature.as_bytes());
        
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        let mut offset = 0;
        
        // Read Ed25519 signature
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
}

impl HybridCiphertext {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // X25519 ephemeral public key length + data
        bytes.extend_from_slice(&(self.ecdh_ephemeral_public.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.ecdh_ephemeral_public);
        
        // Kyber ciphertext
        bytes.extend_from_slice(self.kyber_ciphertext.as_bytes());
        
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        let mut offset = 0;
        
        // Read X25519 ephemeral public key
        if bytes.len() < offset + 2 {
            return Err(CryptoError::InvalidInput("Insufficient data".to_string()));
        }
        let ecdh_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        
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
}

/// Generate hybrid key pair menggunakan ring crate untuk classical crypto
pub fn keypair() -> CryptoResult<HybridKeyPair> {
    let rng = SystemRandom::new();
    let mut csprng = rand::rngs::OsRng;
    
    // Generate Kyber keypair (post-quantum)
    let kyber_keypair = kyber::keypair()?;
    
    // Generate Dilithium keypair (post-quantum)
    let dilithium_keypair = dilithium::keypair()?;
    
    // Generate X25519 static secret untuk key exchange
    // Menggunakan x25519-dalek yang mendukung static secrets
    let x25519_static_secret = X25519StaticSecret::random_from_rng(&mut csprng);
    let x25519_public = X25519PublicKey::from(&x25519_static_secret);
    
    let ecdh_public = x25519_public.as_bytes().to_vec();
    let ecdh_secret = x25519_static_secret.as_bytes().to_vec();
    
    // Generate Ed25519 keypair untuk signatures
    let ed25519_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| CryptoError::KeyGenerationFailed("Failed to generate Ed25519 keypair".to_string()))?;
    
    let ed25519_keypair = Ed25519KeyPair::from_pkcs8(ed25519_pkcs8.as_ref())
        .map_err(|_| CryptoError::KeyGenerationFailed("Failed to parse Ed25519 keypair".to_string()))?;
    
    let ecdsa_public = ed25519_keypair.public_key().as_ref().to_vec();
    let ecdsa_secret = ed25519_pkcs8.as_ref().to_vec();
    
    Ok(HybridKeyPair {
        public_key: HybridPublicKey {
            ecdh_public,
            kyber_public: kyber_keypair.public_key,
            ecdsa_public,
            dilithium_public: dilithium_keypair.public_key,
        },
        secret_key: HybridSecretKey {
            ecdh_secret,
            kyber_secret: kyber_keypair.secret_key,
            ecdsa_secret,
            dilithium_secret: dilithium_keypair.secret_key,
        },
    })
}

/// Alias untuk backward compatibility
pub fn generate_keypair() -> CryptoResult<HybridKeyPair> {
    keypair()
}

/// Hybrid key exchange (encapsulation)
/// Menggunakan X25519 + Kyber untuk defense in depth
pub fn encapsulate(public_key: &HybridPublicKey) -> CryptoResult<(Vec<u8>, HybridCiphertext)> {
    let mut csprng = rand::rngs::OsRng;
    
    // Kyber encapsulation (post-quantum)
    let (kyber_ss, kyber_ct) = kyber::encapsulate(&public_key.kyber_public)?;
    
    // X25519 key exchange menggunakan x25519-dalek
    // Generate ephemeral secret
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut csprng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    
    // Parse recipient's X25519 public key
    let peer_public_bytes: [u8; 32] = public_key.ecdh_public.as_slice()
        .try_into()
        .map_err(|_| CryptoError::EncryptionFailed("Invalid X25519 public key size".to_string()))?;
    let peer_public = X25519PublicKey::from(peer_public_bytes);
    
    // Perform X25519 key agreement
    let x25519_ss = ephemeral_secret.diffie_hellman(&peer_public);
    
    // Combine shared secrets menggunakan HKDF
    // Hybrid KEM: shared_secret = HKDF(kyber_ss || x25519_ss)
    let combined_ss = hkdf::derive_key(
        &[kyber_ss.as_bytes(), x25519_ss.as_bytes()],
        b"B4AE-v1-hybrid-kem",
        32
    )?;
    
    Ok((
        combined_ss,
        HybridCiphertext {
            ecdh_ephemeral_public: ephemeral_public.as_bytes().to_vec(),
            kyber_ciphertext: kyber_ct,
        },
    ))
}

/// Hybrid key exchange (decapsulation)
pub fn decapsulate(
    secret_key: &HybridSecretKey,
    ciphertext: &HybridCiphertext,
) -> CryptoResult<Vec<u8>> {
    // Kyber decapsulation (post-quantum)
    let kyber_ss = kyber::decapsulate(&secret_key.kyber_secret, &ciphertext.kyber_ciphertext)?;
    
    // X25519 key exchange menggunakan x25519-dalek
    // Reconstruct our static secret dari stored bytes
    let our_secret_bytes: [u8; 32] = secret_key.ecdh_secret.as_slice()
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("Invalid X25519 secret key size".to_string()))?;
    let our_static_secret = X25519StaticSecret::from(our_secret_bytes);
    
    // Parse sender's ephemeral public key
    let peer_public_bytes: [u8; 32] = ciphertext.ecdh_ephemeral_public.as_slice()
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("Invalid ephemeral public key size".to_string()))?;
    let peer_public = X25519PublicKey::from(peer_public_bytes);
    
    // Perform X25519 key agreement dengan static secret kita
    let x25519_ss = our_static_secret.diffie_hellman(&peer_public);
    
    // Combine shared secrets menggunakan HKDF
    let combined_ss = hkdf::derive_key(
        &[kyber_ss.as_bytes(), x25519_ss.as_bytes()],
        b"B4AE-v1-hybrid-kem",
        32
    )?;
    
    Ok(combined_ss)
}

/// Hybrid signature generation
/// Menggunakan Ed25519 + Dilithium5 untuk defense in depth
pub fn sign(secret_key: &HybridSecretKey, message: &[u8]) -> CryptoResult<HybridSignature> {
    // Dilithium signature (post-quantum)
    let dilithium_sig = dilithium::sign(&secret_key.dilithium_secret, message)?;
    
    // Ed25519 signature
    let ed25519_keypair = Ed25519KeyPair::from_pkcs8(&secret_key.ecdsa_secret)
        .map_err(|_| CryptoError::SignatureFailed("Failed to parse Ed25519 keypair".to_string()))?;
    
    let ed25519_sig = ed25519_keypair.sign(message);
    
    Ok(HybridSignature {
        ecdsa_signature: ed25519_sig.as_ref().to_vec(),
        dilithium_signature: dilithium_sig,
    })
}

/// Hybrid signature verification
/// Kedua signature (Ed25519 dan Dilithium) harus valid
pub fn verify(
    public_key: &HybridPublicKey,
    message: &[u8],
    signature: &HybridSignature,
) -> CryptoResult<bool> {
    // Verify Dilithium signature (post-quantum)
    let dilithium_valid = dilithium::verify(
        &public_key.dilithium_public,
        message,
        &signature.dilithium_signature,
    )?;
    
    if !dilithium_valid {
        return Ok(false);
    }
    
    // Verify Ed25519 signature
    let ed25519_public_key = signature::UnparsedPublicKey::new(
        &signature::ED25519,
        &public_key.ecdsa_public
    );
    
    let ed25519_valid = ed25519_public_key
        .verify(message, &signature.ecdsa_signature)
        .is_ok();
    
    // Kedua signature harus valid (hybrid security)
    Ok(ed25519_valid && dilithium_valid)
}

impl fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ecdh_preview = if self.ecdh_public.len() >= 8 {
            hex::encode(&self.ecdh_public[..8])
        } else {
            hex::encode(&self.ecdh_public)
        };
        let ecdsa_preview = if self.ecdsa_public.len() >= 8 {
            hex::encode(&self.ecdsa_public[..8])
        } else {
            hex::encode(&self.ecdsa_public)
        };
        
        f.debug_struct("HybridPublicKey")
            .field("ecdh_public", &format!("{}...", ecdh_preview))
            .field("kyber_public", &self.kyber_public)
            .field("ecdsa_public", &format!("{}...", ecdsa_preview))
            .field("dilithium_public", &self.dilithium_public)
            .finish()
    }
}

impl fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridSecretKey([REDACTED])")
    }
}

// Secure drop implementation menggunakan zeroize
impl Drop for HybridSecretKey {
    fn drop(&mut self) {
        // Zero out secret key memory
        self.ecdh_secret.zeroize();
        self.ecdsa_secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_keypair() {
        let keypair = keypair().expect("Failed to generate hybrid keypair");
        
        // X25519 public key should be 32 bytes
        assert_eq!(keypair.public_key.ecdh_public.len(), X25519_PUBLIC_KEY_SIZE);
        
        // Ed25519 public key should be 32 bytes
        assert_eq!(keypair.public_key.ecdsa_public.len(), ED25519_PUBLIC_KEY_SIZE);
        
        // Secret keys should be non-zero
        assert!(!keypair.secret_key.ecdh_secret.is_empty());
        assert!(!keypair.secret_key.ecdsa_secret.is_empty());
    }

    #[test]
    fn test_hybrid_key_exchange() {
        // Generate two keypairs
        let alice = keypair().expect("Failed to generate Alice's keypair");
        let bob = keypair().expect("Failed to generate Bob's keypair");
        
        // Alice encapsulates to Bob
        let (alice_ss, ciphertext) = encapsulate(&bob.public_key)
            .expect("Failed to encapsulate");
        
        // Shared secret should be 32 bytes
        assert_eq!(alice_ss.len(), 32);
        
        // Ciphertext should have valid ephemeral public key
        assert_eq!(ciphertext.ecdh_ephemeral_public.len(), X25519_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_hybrid_signature() {
        let kp = keypair().expect("Failed to generate keypair");
        let message = b"Hello, B4AE Hybrid!";
        
        // Sign message
        let signature = sign(&kp.secret_key, message)
            .expect("Failed to sign");
        
        // Ed25519 signature should be 64 bytes
        assert_eq!(signature.ecdsa_signature.len(), ED25519_SIGNATURE_SIZE);
        
        // Verify signature
        let valid = verify(&kp.public_key, message, &signature)
            .expect("Failed to verify");
        
        assert!(valid, "Signature should be valid");
    }

    #[test]
    fn test_signature_invalid_message() {
        let kp = keypair().expect("Failed to generate keypair");
        let message = b"Hello, B4AE Hybrid!";
        let wrong_message = b"Wrong message";
        
        let signature = sign(&kp.secret_key, message)
            .expect("Failed to sign");
        
        // Verification with wrong message should fail
        let valid = verify(&kp.public_key, wrong_message, &signature)
            .expect("Failed to verify");
        
        assert!(!valid, "Signature should be invalid for wrong message");
    }

    #[test]
    fn test_public_key_serialization() {
        let kp = keypair().expect("Failed to generate keypair");
        
        let bytes = kp.public_key.to_bytes();
        let restored = HybridPublicKey::from_bytes(&bytes)
            .expect("Failed to deserialize public key");
        
        assert_eq!(kp.public_key.ecdh_public, restored.ecdh_public);
        assert_eq!(kp.public_key.ecdsa_public, restored.ecdsa_public);
    }

    #[test]
    fn test_signature_serialization() {
        let kp = keypair().expect("Failed to generate keypair");
        let message = b"Test message";
        
        let signature = sign(&kp.secret_key, message)
            .expect("Failed to sign");
        
        let bytes = signature.to_bytes();
        let restored = HybridSignature::from_bytes(&bytes)
            .expect("Failed to deserialize signature");
        
        assert_eq!(signature.ecdsa_signature, restored.ecdsa_signature);
    }

    #[test]
    fn test_ciphertext_serialization() {
        let bob = keypair().expect("Failed to generate keypair");
        let (_, ciphertext) = encapsulate(&bob.public_key)
            .expect("Failed to encapsulate");
        
        let bytes = ciphertext.to_bytes();
        let restored = HybridCiphertext::from_bytes(&bytes)
            .expect("Failed to deserialize ciphertext");
        
        assert_eq!(ciphertext.ecdh_ephemeral_public, restored.ecdh_ephemeral_public);
    }
}
