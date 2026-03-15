// B4AE Kyber-1024 Implementation
// Post-Quantum Key Encapsulation Mechanism

use crate::crypto::{CryptoError, CryptoResult};
use std::fmt;

#[cfg(feature = "pqcrypto-mlkem")]
use pqcrypto_mlkem::mlkem1024;

#[cfg(all(any(feature = "pqcrypto-kyber", feature = "pqcrypto-alt"), not(feature = "pqcrypto-mlkem")))]
use pqcrypto_kyber::kyber1024;


/// Kyber/ML-KEM-1024 Public Key (1568 bytes)
#[derive(Clone)]
pub struct KyberPublicKey {
    #[cfg(feature = "pqcrypto-mlkem")]
    inner: mlkem1024::PublicKey,
    #[cfg(all(any(feature = "pqcrypto-kyber", feature = "pqcrypto-alt"), not(feature = "pqcrypto-mlkem")))]
    inner: kyber1024::PublicKey,
    #[cfg(not(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
    data: Vec<u8>,
}

/// Kyber/ML-KEM-1024 Secret Key (3168 bytes)
pub struct KyberSecretKey {
    #[cfg(feature = "pqcrypto-mlkem")]
    inner: mlkem1024::SecretKey,
    #[cfg(all(any(feature = "pqcrypto-kyber", feature = "pqcrypto-alt"), not(feature = "pqcrypto-mlkem")))]
    inner: kyber1024::SecretKey,
    #[cfg(not(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
    data: Vec<u8>,
}

/// Kyber/ML-KEM-1024 Ciphertext (1568 bytes)
#[derive(Clone)]
pub struct KyberCiphertext {
    #[cfg(feature = "pqcrypto-mlkem")]
    inner: mlkem1024::Ciphertext,
    #[cfg(all(any(feature = "pqcrypto-kyber", feature = "pqcrypto-alt"), not(feature = "pqcrypto-mlkem")))]
    inner: kyber1024::Ciphertext,
    #[cfg(not(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
    data: Vec<u8>,
}

/// Kyber/ML-KEM-1024 Shared Secret (32 bytes)
pub struct KyberSharedSecret {
    #[cfg(feature = "pqcrypto-mlkem")]
    inner: mlkem1024::SharedSecret,
    #[cfg(all(any(feature = "pqcrypto-kyber", feature = "pqcrypto-alt"), not(feature = "pqcrypto-mlkem")))]
    inner: kyber1024::SharedSecret,
    #[cfg(not(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
    data: [u8; 32],
}

impl KyberPublicKey {
    /// Size in bytes (Kyber-1024).
    pub const SIZE: usize = 1568;

    /// Parse dari raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != Self::SIZE {
            return Err(CryptoError::InvalidKeySize(
                format!("Expected {} bytes, got {}", Self::SIZE, bytes.len())
            ));
        }
        
        #[cfg(feature = "pqcrypto-mlkem")]
        {
            use pqcrypto_traits::kem::PublicKey;
            let inner = mlkem1024::PublicKey::from_bytes(bytes)
                .map_err(|_| CryptoError::InvalidKeySize("Invalid ML-KEM public key".to_string()))?;
            return Ok(KyberPublicKey { inner });
        }
        
        #[cfg(all(any(feature = "pqcrypto-kyber", feature = "pqcrypto-alt"), not(feature = "pqcrypto-mlkem")))]
        {
            use pqcrypto_traits::kem::PublicKey;
            let inner = kyber1024::PublicKey::from_bytes(bytes)
                .map_err(|_| CryptoError::InvalidKeySize("Invalid Kyber public key".to_string()))?;
            return Ok(KyberPublicKey { inner });
        }
        
        #[cfg(not(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
        Ok(KyberPublicKey { data: bytes.to_vec() })
    }

    /// Serialisasi ke bytes.
    pub fn as_bytes(&self) -> &[u8] {
        #[cfg(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt"))]
        {
            use pqcrypto_traits::kem::PublicKey;
            return self.inner.as_bytes();
        }
        
        #[cfg(not(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
        { &self.data }
    }
}

impl KyberSecretKey {
    /// Size in bytes.
    pub const SIZE: usize = 3168;

    /// Parse dari raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != Self::SIZE {
            return Err(CryptoError::InvalidKeySize(
                format!("Expected {} bytes, got {}", Self::SIZE, bytes.len())
            ));
        }
        
        #[cfg(feature = "pqcrypto-mlkem")]
        {
            use pqcrypto_traits::kem::SecretKey;
            let inner = mlkem1024::SecretKey::from_bytes(bytes)
                .map_err(|_| CryptoError::InvalidKeySize("Invalid ML-KEM secret key".to_string()))?;
            return Ok(KyberSecretKey { inner });
        }
        
        #[cfg(all(any(feature = "pqcrypto-kyber", feature = "pqcrypto-alt"), not(feature = "pqcrypto-mlkem")))]
        {
            use pqcrypto_traits::kem::SecretKey;
            let inner = kyber1024::SecretKey::from_bytes(bytes)
                .map_err(|_| CryptoError::InvalidKeySize("Invalid Kyber secret key".to_string()))?;
            return Ok(KyberSecretKey { inner });
        }
        
        #[cfg(not(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
        Ok(KyberSecretKey { data: bytes.to_vec() })
    }

    /// Serialisasi ke bytes.
    pub fn as_bytes(&self) -> &[u8] {
        #[cfg(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt"))]
        {
            use pqcrypto_traits::kem::SecretKey;
            return self.inner.as_bytes();
        }
        
        #[cfg(not(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
        { &self.data }
    }
}

impl KyberCiphertext {
    /// Size in bytes.
    pub const SIZE: usize = 1568;

    /// Parse dari raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != Self::SIZE {
            return Err(CryptoError::InvalidInput(
                format!("Expected {} bytes, got {}", Self::SIZE, bytes.len())
            ));
        }
        
        #[cfg(feature = "pqcrypto-mlkem")]
        {
            use pqcrypto_traits::kem::Ciphertext;
            let inner = mlkem1024::Ciphertext::from_bytes(bytes)
                .map_err(|_| CryptoError::InvalidInput("Invalid ML-KEM ciphertext".to_string()))?;
            return Ok(KyberCiphertext { inner });
        }
        
        #[cfg(all(any(feature = "pqcrypto-kyber", feature = "pqcrypto-alt"), not(feature = "pqcrypto-mlkem")))]
        {
            use pqcrypto_traits::kem::Ciphertext;
            let inner = kyber1024::Ciphertext::from_bytes(bytes)
                .map_err(|_| CryptoError::InvalidInput("Invalid Kyber ciphertext".to_string()))?;
            return Ok(KyberCiphertext { inner });
        }
        
        #[cfg(not(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
        Ok(KyberCiphertext { data: bytes.to_vec() })
    }

    /// Serialisasi ke bytes.
    pub fn as_bytes(&self) -> &[u8] {
        #[cfg(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt"))]
        {
            use pqcrypto_traits::kem::Ciphertext;
            return self.inner.as_bytes();
        }
        
        #[cfg(not(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
        { &self.data }
    }
}

impl KyberSharedSecret {
    /// Size in bytes.
    pub const SIZE: usize = 32;

    /// Parse dari raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != Self::SIZE {
            return Err(CryptoError::InvalidInput(
                format!("Expected {} bytes, got {}", Self::SIZE, bytes.len())
            ));
        }
        
        #[cfg(feature = "pqcrypto-mlkem")]
        {
            use pqcrypto_traits::kem::SharedSecret;
            let inner = mlkem1024::SharedSecret::from_bytes(bytes)
                .map_err(|_| CryptoError::InvalidInput("Invalid ML-KEM shared secret".to_string()))?;
            return Ok(KyberSharedSecret { inner });
        }
        
        #[cfg(all(any(feature = "pqcrypto-kyber", feature = "pqcrypto-alt"), not(feature = "pqcrypto-mlkem")))]
        {
            use pqcrypto_traits::kem::SharedSecret;
            let inner = kyber1024::SharedSecret::from_bytes(bytes)
                .map_err(|_| CryptoError::InvalidInput("Invalid Kyber shared secret".to_string()))?;
            return Ok(KyberSharedSecret { inner });
        }
        
        #[cfg(not(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
        {
            let mut data = [0u8; 32];
            data.copy_from_slice(bytes);
            Ok(KyberSharedSecret { data })
        }
    }

    /// Serialisasi ke bytes.
    pub fn as_bytes(&self) -> &[u8] {
        #[cfg(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt"))]
        {
            use pqcrypto_traits::kem::SharedSecret;
            return self.inner.as_bytes();
        }
        
        #[cfg(not(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
        { &self.data }
    }
}

/// Kyber-1024 Key Pair
pub struct KyberKeyPair {
    /// Public key for encapsulation.
    pub public_key: KyberPublicKey,
    /// Secret key for decapsulation.
    pub secret_key: KyberSecretKey,
}

/// Generate Kyber-1024 key pair
pub fn keypair() -> CryptoResult<KyberKeyPair> {
    #[cfg(feature = "liboqs")]
    {
        use oqs::kem::{Kem, Algorithm};
        
        let kem = Kem::new(Algorithm::Kyber1024)
            .map_err(|e| CryptoError::KeyGenerationFailed(e.to_string()))?;
        
        let (pk, sk) = kem.keypair()
            .map_err(|e| CryptoError::KeyGenerationFailed(e.to_string()))?;
        
        Ok(KyberKeyPair {
            public_key: KyberPublicKey::from_bytes(pk.as_ref())?,
            secret_key: KyberSecretKey::from_bytes(sk.as_ref())?,
        })
    }
    
    #[cfg(all(not(feature = "liboqs"), feature = "pqcrypto-mlkem"))]
    {
        let (pk, sk) = mlkem1024::keypair();
        return Ok(KyberKeyPair {
            public_key: KyberPublicKey { inner: pk },
            secret_key: KyberSecretKey { inner: sk },
        });
    }
    
    #[cfg(all(not(feature = "liboqs"), any(feature = "pqcrypto-kyber", feature = "pqcrypto-alt"), not(feature = "pqcrypto-mlkem")))]
    {
        let (pk, sk) = kyber1024::keypair();
        return Ok(KyberKeyPair {
            public_key: KyberPublicKey { inner: pk },
            secret_key: KyberSecretKey { inner: sk },
        });
    }
    
    #[cfg(not(any(feature = "liboqs", feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
    Err(CryptoError::KeyGenerationFailed(
        "Tidak ada implementasi KEM yang tersedia. Aktifkan feature 'pqcrypto-mlkem'".to_string()
    ))
}

/// Encapsulate: Generate shared secret and ciphertext
pub fn encapsulate(public_key: &KyberPublicKey) -> CryptoResult<(KyberSharedSecret, KyberCiphertext)> {
    #[cfg(feature = "liboqs")]
    {
        use oqs::kem::{Kem, Algorithm, PublicKey};
        
        let kem = Kem::new(Algorithm::Kyber1024)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        let pk = PublicKey::from_bytes(public_key.as_bytes())
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        let (ct, ss) = kem.encapsulate(&pk)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        Ok((
            KyberSharedSecret::from_bytes(ss.as_ref())?,
            KyberCiphertext::from_bytes(ct.as_ref())?,
        ))
    }
    
    #[cfg(all(not(feature = "liboqs"), feature = "pqcrypto-mlkem"))]
    {
        let (ss, ct) = mlkem1024::encapsulate(&public_key.inner);
        return Ok((
            KyberSharedSecret { inner: ss },
            KyberCiphertext { inner: ct },
        ));
    }
    
    #[cfg(all(not(feature = "liboqs"), any(feature = "pqcrypto-kyber", feature = "pqcrypto-alt"), not(feature = "pqcrypto-mlkem")))]
    {
        let (ss, ct) = kyber1024::encapsulate(&public_key.inner);
        return Ok((
            KyberSharedSecret { inner: ss },
            KyberCiphertext { inner: ct },
        ));
    }
    
    #[cfg(not(any(feature = "liboqs", feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
    Err(CryptoError::EncryptionFailed(
        "Tidak ada implementasi KEM yang tersedia".to_string()
    ))
}

/// Decapsulate: Recover shared secret from ciphertext
pub fn decapsulate(
    secret_key: &KyberSecretKey,
    ciphertext: &KyberCiphertext,
) -> CryptoResult<KyberSharedSecret> {
    #[cfg(feature = "liboqs")]
    {
        use oqs::kem::{Kem, Algorithm, SecretKey, Ciphertext};
        
        let kem = Kem::new(Algorithm::Kyber1024)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        
        let sk = SecretKey::from_bytes(secret_key.as_bytes())
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        
        let ct = Ciphertext::from_bytes(ciphertext.as_bytes())
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        
        let ss = kem.decapsulate(&sk, &ct)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        
        KyberSharedSecret::from_bytes(ss.as_ref())
    }
    
    #[cfg(all(not(feature = "liboqs"), feature = "pqcrypto-mlkem"))]
    {
        let ss = mlkem1024::decapsulate(&ciphertext.inner, &secret_key.inner);
        return Ok(KyberSharedSecret { inner: ss });
    }
    
    #[cfg(all(not(feature = "liboqs"), any(feature = "pqcrypto-kyber", feature = "pqcrypto-alt"), not(feature = "pqcrypto-mlkem")))]
    {
        let ss = kyber1024::decapsulate(&ciphertext.inner, &secret_key.inner);
        return Ok(KyberSharedSecret { inner: ss });
    }
    
    #[cfg(not(any(feature = "liboqs", feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
    Err(CryptoError::DecryptionFailed(
        "Tidak ada implementasi KEM yang tersedia".to_string()
    ))
}

impl fmt::Debug for KyberPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt"))]
        {
            use pqcrypto_traits::kem::PublicKey;
            let bytes = self.inner.as_bytes();
            return write!(f, "KyberPublicKey({}...)", hex::encode(&bytes[..8]));
        }
        
        #[cfg(not(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
        { write!(f, "KyberPublicKey({}...)", hex::encode(&self.data[..8])) }
    }
}

impl fmt::Debug for KyberSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KyberSecretKey([REDACTED])")
    }
}

impl fmt::Debug for KyberCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt"))]
        {
            use pqcrypto_traits::kem::Ciphertext;
            let bytes = self.inner.as_bytes();
            return write!(f, "KyberCiphertext({}...)", hex::encode(&bytes[..8]));
        }
        
        #[cfg(not(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
        { write!(f, "KyberCiphertext({}...)", hex::encode(&self.data[..8])) }
    }
}

impl fmt::Debug for KyberSharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KyberSharedSecret([REDACTED])")
    }
}

// Secure drop implementations
impl Drop for KyberSecretKey {
    fn drop(&mut self) {
        #[cfg(not(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
        for byte in &mut self.data { *byte = 0; }
    }
}

impl Drop for KyberSharedSecret {
    fn drop(&mut self) {
        #[cfg(not(any(feature = "pqcrypto-mlkem", feature = "pqcrypto-kyber", feature = "pqcrypto-alt")))]
        for byte in &mut self.data { *byte = 0; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_sizes() {
        assert_eq!(KyberPublicKey::SIZE, 1568);
        assert_eq!(KyberSecretKey::SIZE, 3168);
        assert_eq!(KyberCiphertext::SIZE, 1568);
        assert_eq!(KyberSharedSecret::SIZE, 32);
    }

    #[test]
    #[cfg(feature = "liboqs")]
    fn test_kyber_keypair() {
        let keypair = keypair().expect("Failed to generate keypair");
        assert_eq!(keypair.public_key.as_bytes().len(), KyberPublicKey::SIZE);
        assert_eq!(keypair.secret_key.as_bytes().len(), KyberSecretKey::SIZE);
    }

    #[test]
    #[cfg(feature = "liboqs")]
    fn test_kyber_encapsulation() {
        let keypair = keypair().expect("Failed to generate keypair");
        let (ss1, ct) = encapsulate(&keypair.public_key)
            .expect("Failed to encapsulate");
        
        assert_eq!(ct.as_bytes().len(), KyberCiphertext::SIZE);
        assert_eq!(ss1.as_bytes().len(), KyberSharedSecret::SIZE);
        
        let ss2 = decapsulate(&keypair.secret_key, &ct)
            .expect("Failed to decapsulate");
        
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }
}
