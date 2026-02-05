// B4AE Dilithium5 Implementation
// Post-Quantum Digital Signature Scheme

use crate::crypto::{CryptoError, CryptoResult};
use std::fmt;

#[cfg(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt"))]
use pqcrypto_dilithium::dilithium5;

/// Dilithium5 Public Key (2592 bytes)
#[derive(Clone)]
pub struct DilithiumPublicKey {
    #[cfg(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt"))]
    inner: dilithium5::PublicKey,
    #[cfg(not(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt")))]
    data: Vec<u8>,
}

/// Dilithium5 Secret Key (4864 bytes)
pub struct DilithiumSecretKey {
    #[cfg(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt"))]
    inner: dilithium5::SecretKey,
    #[cfg(not(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt")))]
    data: Vec<u8>,
}

/// Dilithium5 Signature (4595 bytes)
#[derive(Clone)]
pub struct DilithiumSignature {
    #[cfg(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt"))]
    inner: dilithium5::DetachedSignature,
    #[cfg(not(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt")))]
    data: Vec<u8>,
}

impl DilithiumPublicKey {
    pub const SIZE: usize = 2592;

    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != Self::SIZE {
            return Err(CryptoError::InvalidKeySize(
                format!("Expected {} bytes, got {}", Self::SIZE, bytes.len())
            ));
        }
        
        #[cfg(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt"))]
        {
            use pqcrypto_traits::sign::PublicKey;
            let inner = dilithium5::PublicKey::from_bytes(bytes)
                .map_err(|_| CryptoError::InvalidKeySize("Invalid Dilithium public key".to_string()))?;
            Ok(DilithiumPublicKey { inner })
        }
        
        #[cfg(not(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt")))]
        Ok(DilithiumPublicKey {
            data: bytes.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        #[cfg(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt"))]
        {
            use pqcrypto_traits::sign::PublicKey;
            self.inner.as_bytes()
        }
        
        #[cfg(not(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt")))]
        &self.data
    }
}

impl DilithiumSecretKey {
    pub const SIZE: usize = 4864;

    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != Self::SIZE {
            return Err(CryptoError::InvalidKeySize(
                format!("Expected {} bytes, got {}", Self::SIZE, bytes.len())
            ));
        }
        
        #[cfg(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt"))]
        {
            use pqcrypto_traits::sign::SecretKey;
            let inner = dilithium5::SecretKey::from_bytes(bytes)
                .map_err(|_| CryptoError::InvalidKeySize("Invalid Dilithium secret key".to_string()))?;
            Ok(DilithiumSecretKey { inner })
        }
        
        #[cfg(not(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt")))]
        Ok(DilithiumSecretKey {
            data: bytes.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        #[cfg(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt"))]
        {
            use pqcrypto_traits::sign::SecretKey;
            self.inner.as_bytes()
        }
        
        #[cfg(not(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt")))]
        &self.data
    }
}

impl DilithiumSignature {
    pub const SIZE: usize = 4627; // pqcrypto-dilithium5 detached signature size

    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        // Allow flexible size for compatibility
        if bytes.len() < 4595 || bytes.len() > 4700 {
            return Err(CryptoError::InvalidInput(
                format!("Expected ~4595-4700 bytes, got {}", bytes.len())
            ));
        }
        
        #[cfg(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt"))]
        {
            use pqcrypto_traits::sign::DetachedSignature;
            let inner = dilithium5::DetachedSignature::from_bytes(bytes)
                .map_err(|_| CryptoError::InvalidInput("Invalid Dilithium signature".to_string()))?;
            Ok(DilithiumSignature { inner })
        }
        
        #[cfg(not(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt")))]
        Ok(DilithiumSignature {
            data: bytes.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        #[cfg(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt"))]
        {
            use pqcrypto_traits::sign::DetachedSignature;
            self.inner.as_bytes()
        }
        
        #[cfg(not(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt")))]
        &self.data
    }
}

/// Dilithium5 Key Pair
pub struct DilithiumKeyPair {
    pub public_key: DilithiumPublicKey,
    pub secret_key: DilithiumSecretKey,
}

/// Generate Dilithium5 key pair
pub fn keypair() -> CryptoResult<DilithiumKeyPair> {
    #[cfg(feature = "liboqs")]
    {
        use oqs::sig::{Sig, Algorithm};
        
        let sig = Sig::new(Algorithm::Dilithium5)
            .map_err(|e| CryptoError::KeyGenerationFailed(e.to_string()))?;
        
        let (pk, sk) = sig.keypair()
            .map_err(|e| CryptoError::KeyGenerationFailed(e.to_string()))?;
        
        Ok(DilithiumKeyPair {
            public_key: DilithiumPublicKey::from_bytes(pk.as_ref())?,
            secret_key: DilithiumSecretKey::from_bytes(sk.as_ref())?,
        })
    }
    
    #[cfg(all(not(feature = "liboqs"), any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt")))]
    {
        // Use real pqcrypto implementation
        let (pk, sk) = dilithium5::keypair();
        
        Ok(DilithiumKeyPair {
            public_key: DilithiumPublicKey { inner: pk },
            secret_key: DilithiumSecretKey { inner: sk },
        })
    }
    
    #[cfg(all(not(feature = "liboqs"), not(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt"))))]
    {
        Err(CryptoError::KeyGenerationFailed(
            "No Dilithium implementation available. Enable 'liboqs' feature for production use".to_string()
        ))
    }
}

/// Sign a message with Dilithium5
pub fn sign(secret_key: &DilithiumSecretKey, message: &[u8]) -> CryptoResult<DilithiumSignature> {
    #[cfg(feature = "liboqs")]
    {
        use oqs::sig::{Sig, Algorithm, SecretKey};
        
        let sig = Sig::new(Algorithm::Dilithium5)
            .map_err(|e| CryptoError::SignatureFailed(e.to_string()))?;
        
        let sk = SecretKey::from_bytes(secret_key.as_bytes())
            .map_err(|e| CryptoError::SignatureFailed(e.to_string()))?;
        
        let signature = sig.sign(message, &sk)
            .map_err(|e| CryptoError::SignatureFailed(e.to_string()))?;
        
        DilithiumSignature::from_bytes(signature.as_ref())
    }
    
    #[cfg(all(not(feature = "liboqs"), any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt")))]
    {
        // Use real pqcrypto implementation
        let sig = dilithium5::detached_sign(message, &secret_key.inner);
        
        Ok(DilithiumSignature { inner: sig })
    }
    
    #[cfg(all(not(feature = "liboqs"), not(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt"))))]
    {
        Err(CryptoError::SignatureFailed(
            "No Dilithium implementation available".to_string()
        ))
    }
}

/// Verify a Dilithium5 signature
pub fn verify(
    public_key: &DilithiumPublicKey,
    message: &[u8],
    signature: &DilithiumSignature,
) -> CryptoResult<bool> {
    #[cfg(feature = "liboqs")]
    {
        use oqs::sig::{Sig, Algorithm, PublicKey, Signature};
        
        let sig = Sig::new(Algorithm::Dilithium5)
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
        
        let pk = PublicKey::from_bytes(public_key.as_bytes())
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
        
        let sig_bytes = Signature::from_bytes(signature.as_bytes())
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
        
        sig.verify(message, &sig_bytes, &pk)
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))
    }
    
    #[cfg(all(not(feature = "liboqs"), any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt")))]
    {
        // Use real pqcrypto implementation
        // Return Ok(false) for invalid signature instead of error
        Ok(dilithium5::verify_detached_signature(&signature.inner, message, &public_key.inner).is_ok())
    }
    
    #[cfg(all(not(feature = "liboqs"), not(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt"))))]
    {
        Err(CryptoError::VerificationFailed(
            "No Dilithium implementation available".to_string()
        ))
    }
}

impl fmt::Debug for DilithiumPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt"))]
        {
            use pqcrypto_traits::sign::PublicKey;
            let bytes = self.inner.as_bytes();
            write!(f, "DilithiumPublicKey({}...)", hex::encode(&bytes[..8]))
        }
        
        #[cfg(not(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt")))]
        write!(f, "DilithiumPublicKey({}...)", hex::encode(&self.data[..8]))
    }
}

impl fmt::Debug for DilithiumSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DilithiumSecretKey([REDACTED])")
    }
}

impl fmt::Debug for DilithiumSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt"))]
        {
            use pqcrypto_traits::sign::DetachedSignature;
            let bytes = self.inner.as_bytes();
            write!(f, "DilithiumSignature({}...)", hex::encode(&bytes[..8]))
        }
        
        #[cfg(not(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt")))]
        write!(f, "DilithiumSignature({}...)", hex::encode(&self.data[..8]))
    }
}

// Secure drop implementation
impl Drop for DilithiumSecretKey {
    fn drop(&mut self) {
        // pqcrypto types handle their own secure drop
        #[cfg(not(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt")))]
        {
            // Zero out secret key memory
            for byte in &mut self.data {
                *byte = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_sizes() {
        assert_eq!(DilithiumPublicKey::SIZE, 2592);
        assert_eq!(DilithiumSecretKey::SIZE, 4864);
        assert_eq!(DilithiumSignature::SIZE, 4627); // pqcrypto-dilithium5 detached signature
    }

    #[test]
    #[cfg(feature = "liboqs")]
    fn test_dilithium_keypair() {
        let keypair = keypair().expect("Failed to generate keypair");
        assert_eq!(keypair.public_key.as_bytes().len(), DilithiumPublicKey::SIZE);
        assert_eq!(keypair.secret_key.as_bytes().len(), DilithiumSecretKey::SIZE);
    }

    #[test]
    #[cfg(feature = "liboqs")]
    fn test_dilithium_sign_verify() {
        let keypair = keypair().expect("Failed to generate keypair");
        let message = b"Hello, B4AE!";
        
        let signature = sign(&keypair.secret_key, message)
            .expect("Failed to sign");
        
        assert_eq!(signature.as_bytes().len(), DilithiumSignature::SIZE);
        
        let valid = verify(&keypair.public_key, message, &signature)
            .expect("Failed to verify");
        
        assert!(valid);
        
        // Test with wrong message
        let wrong_message = b"Wrong message";
        let invalid = verify(&keypair.public_key, wrong_message, &signature)
            .unwrap_or(false);
        
        assert!(!invalid);
    }
}
