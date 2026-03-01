//! Post-Quantum Cryptography Wrapper Module
//!
//! This module provides safe, ergonomic Rust APIs for NIST-approved post-quantum
//! cryptographic algorithms used in B4AE v2.0:
//!
//! - **Kyber1024**: Post-quantum KEM (Key Encapsulation Mechanism) for key exchange
//! - **Dilithium5**: Post-quantum digital signature scheme for Mode B authentication
//!
//! Both algorithms provide NIST Level 5 security, which is equivalent to AES-256 security
//! and offers the highest level of quantum resistance.
//!
//! # Security Properties
//!
//! ## Kyber1024 (NIST ML-KEM)
//! - **Security Level**: NIST Level 5 (256-bit quantum security)
//! - **Public Key**: 1568 bytes
//! - **Secret Key**: 3168 bytes
//! - **Ciphertext**: 1568 bytes
//! - **Shared Secret**: 32 bytes
//! - **Use Case**: Post-quantum key encapsulation for hybrid key exchange
//!
//! ## Dilithium5 (NIST ML-DSA)
//! - **Security Level**: NIST Level 5 (256-bit quantum security)
//! - **Public Key**: 2592 bytes
//! - **Secret Key**: 4864 bytes
//! - **Signature**: ~4627 bytes
//! - **Use Case**: Post-quantum digital signatures for Mode B authentication
//!
//! # Usage Examples
//!
//! ## Kyber1024 Key Encapsulation
//!
//! ```rust,no_run
//! use b4ae::crypto::pq::{KyberKem, PqKem};
//!
//! // Generate keypair
//! let kem = KyberKem::new()?;
//! let keypair = kem.generate_keypair()?;
//!
//! // Encapsulate: generate shared secret and ciphertext
//! let (shared_secret, ciphertext) = kem.encapsulate(&keypair.public_key)?;
//!
//! // Decapsulate: recover shared secret from ciphertext
//! let recovered_secret = kem.decapsulate(&keypair.secret_key, &ciphertext)?;
//!
//! assert_eq!(shared_secret.as_bytes(), recovered_secret.as_bytes());
//! # Ok::<(), b4ae::crypto::CryptoError>(())
//! ```
//!
//! ## Dilithium5 Digital Signatures
//!
//! ```rust,no_run
//! use b4ae::crypto::pq::{DilithiumSigner, PqSignature};
//!
//! // Generate keypair
//! let signer = DilithiumSigner::new()?;
//! let keypair = signer.generate_keypair()?;
//!
//! // Sign message
//! let message = b"Hello, B4AE v2.0!";
//! let signature = signer.sign(&keypair.secret_key, message)?;
//!
//! // Verify signature
//! let is_valid = signer.verify(&keypair.public_key, message, &signature)?;
//! assert!(is_valid);
//! # Ok::<(), b4ae::crypto::CryptoError>(())
//! ```
//!
//! # Constant-Time Operations
//!
//! All cryptographic operations in this module are designed to be constant-time
//! to prevent timing side-channel attacks. The underlying implementations
//! (pqcrypto-kyber and pqcrypto-dilithium) provide constant-time guarantees.
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe and can be safely shared across threads.
//! Key generation uses cryptographically secure random number generation.

use crate::crypto::{CryptoError, CryptoResult};
use crate::crypto::kyber::{self, KyberPublicKey, KyberSecretKey, KyberCiphertext, KyberSharedSecret};
use crate::crypto::dilithium::{self, DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature};
use std::fmt;

// Re-export key types for convenience
pub use crate::crypto::kyber::{KyberPublicKey as PqKemPublicKey, KyberSecretKey as PqKemSecretKey};
pub use crate::crypto::dilithium::{DilithiumPublicKey as PqSignPublicKey, DilithiumSecretKey as PqSignSecretKey};

/// Post-Quantum Key Encapsulation Mechanism (KEM) trait
///
/// This trait defines the interface for post-quantum KEMs used in B4AE v2.0.
/// Currently implemented by Kyber1024.
pub trait PqKem {
    /// Public key type
    type PublicKey;
    /// Secret key type
    type SecretKey;
    /// Ciphertext type
    type Ciphertext;
    /// Shared secret type
    type SharedSecret;
    /// Keypair type
    type KeyPair;

    /// Generate a new keypair
    fn generate_keypair(&self) -> CryptoResult<Self::KeyPair>;

    /// Encapsulate: generate shared secret and ciphertext
    fn encapsulate(&self, public_key: &Self::PublicKey) -> CryptoResult<(Self::SharedSecret, Self::Ciphertext)>;

    /// Decapsulate: recover shared secret from ciphertext
    fn decapsulate(&self, secret_key: &Self::SecretKey, ciphertext: &Self::Ciphertext) -> CryptoResult<Self::SharedSecret>;
}

/// Post-Quantum Digital Signature trait
///
/// This trait defines the interface for post-quantum signature schemes used in B4AE v2.0.
/// Currently implemented by Dilithium5.
pub trait PqSignature {
    /// Public key type
    type PublicKey;
    /// Secret key type
    type SecretKey;
    /// Signature type
    type Signature;
    /// Keypair type
    type KeyPair;

    /// Generate a new keypair
    fn generate_keypair(&self) -> CryptoResult<Self::KeyPair>;

    /// Sign a message
    fn sign(&self, secret_key: &Self::SecretKey, message: &[u8]) -> CryptoResult<Self::Signature>;

    /// Verify a signature
    fn verify(&self, public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> CryptoResult<bool>;
}

/// Kyber1024 keypair
#[derive(Debug)]
pub struct KyberKeyPair {
    /// Public key for encapsulation
    pub public_key: KyberPublicKey,
    /// Secret key for decapsulation
    pub secret_key: KyberSecretKey,
}

/// Dilithium5 keypair
#[derive(Debug)]
pub struct DilithiumKeyPair {
    /// Public key for verification
    pub public_key: DilithiumPublicKey,
    /// Secret key for signing
    pub secret_key: DilithiumSecretKey,
}

/// Kyber1024 KEM wrapper
///
/// Provides NIST Level 5 post-quantum key encapsulation.
///
/// # Security Properties
/// - **Quantum Security**: 256-bit (NIST Level 5)
/// - **Classical Security**: 256-bit
/// - **IND-CCA2 Secure**: Secure against adaptive chosen-ciphertext attacks
///
/// # Performance
/// - **Key Generation**: ~0.1ms
/// - **Encapsulation**: ~0.1ms
/// - **Decapsulation**: ~0.1ms
#[derive(Debug, Clone, Copy)]
pub struct KyberKem;

impl KyberKem {
    /// Create a new Kyber1024 KEM instance
    pub fn new() -> CryptoResult<Self> {
        Ok(KyberKem)
    }

    /// Get the security level (NIST Level 5)
    pub fn security_level(&self) -> u8 {
        5
    }

    /// Get public key size in bytes
    pub fn public_key_size(&self) -> usize {
        KyberPublicKey::SIZE
    }

    /// Get secret key size in bytes
    pub fn secret_key_size(&self) -> usize {
        KyberSecretKey::SIZE
    }

    /// Get ciphertext size in bytes
    pub fn ciphertext_size(&self) -> usize {
        KyberCiphertext::SIZE
    }

    /// Get shared secret size in bytes
    pub fn shared_secret_size(&self) -> usize {
        KyberSharedSecret::SIZE
    }
}

impl Default for KyberKem {
    fn default() -> Self {
        KyberKem
    }
}

impl PqKem for KyberKem {
    type PublicKey = KyberPublicKey;
    type SecretKey = KyberSecretKey;
    type Ciphertext = KyberCiphertext;
    type SharedSecret = KyberSharedSecret;
    type KeyPair = KyberKeyPair;

    fn generate_keypair(&self) -> CryptoResult<Self::KeyPair> {
        let kp = kyber::keypair()?;
        Ok(KyberKeyPair {
            public_key: kp.public_key,
            secret_key: kp.secret_key,
        })
    }

    fn encapsulate(&self, public_key: &Self::PublicKey) -> CryptoResult<(Self::SharedSecret, Self::Ciphertext)> {
        kyber::encapsulate(public_key)
    }

    fn decapsulate(&self, secret_key: &Self::SecretKey, ciphertext: &Self::Ciphertext) -> CryptoResult<Self::SharedSecret> {
        kyber::decapsulate(secret_key, ciphertext)
    }
}

/// Dilithium5 signature wrapper
///
/// Provides NIST Level 5 post-quantum digital signatures.
///
/// # Security Properties
/// - **Quantum Security**: 256-bit (NIST Level 5)
/// - **Classical Security**: 256-bit
/// - **EUF-CMA Secure**: Existentially unforgeable under chosen-message attacks
/// - **Non-Repudiable**: Signatures prove authorship (cannot be forged by verifier)
///
/// # Performance
/// - **Key Generation**: ~0.5ms
/// - **Signing**: ~3ms
/// - **Verification**: ~3ms
#[derive(Debug, Clone, Copy)]
pub struct DilithiumSigner;

impl DilithiumSigner {
    /// Create a new Dilithium5 signer instance
    pub fn new() -> CryptoResult<Self> {
        Ok(DilithiumSigner)
    }

    /// Get the security level (NIST Level 5)
    pub fn security_level(&self) -> u8 {
        5
    }

    /// Get public key size in bytes
    pub fn public_key_size(&self) -> usize {
        DilithiumPublicKey::SIZE
    }

    /// Get secret key size in bytes
    pub fn secret_key_size(&self) -> usize {
        DilithiumSecretKey::SIZE
    }

    /// Get signature size in bytes
    pub fn signature_size(&self) -> usize {
        DilithiumSignature::SIZE
    }
}

impl Default for DilithiumSigner {
    fn default() -> Self {
        DilithiumSigner
    }
}

impl PqSignature for DilithiumSigner {
    type PublicKey = DilithiumPublicKey;
    type SecretKey = DilithiumSecretKey;
    type Signature = DilithiumSignature;
    type KeyPair = DilithiumKeyPair;

    fn generate_keypair(&self) -> CryptoResult<Self::KeyPair> {
        let kp = dilithium::keypair()?;
        Ok(DilithiumKeyPair {
            public_key: kp.public_key,
            secret_key: kp.secret_key,
        })
    }

    fn sign(&self, secret_key: &Self::SecretKey, message: &[u8]) -> CryptoResult<Self::Signature> {
        dilithium::sign(secret_key, message)
    }

    fn verify(&self, public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> CryptoResult<bool> {
        dilithium::verify(public_key, message, signature)
    }
}

/// NIST security level information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NistSecurityLevel {
    /// Level 1: Equivalent to AES-128 (128-bit quantum security)
    Level1,
    /// Level 2: Equivalent to SHA-256 collision resistance (192-bit quantum security)
    Level2,
    /// Level 3: Equivalent to AES-192 (192-bit quantum security)
    Level3,
    /// Level 4: Equivalent to SHA-384 collision resistance (256-bit quantum security)
    Level4,
    /// Level 5: Equivalent to AES-256 (256-bit quantum security) - HIGHEST
    Level5,
}

impl NistSecurityLevel {
    /// Get the quantum security bits for this level
    pub fn quantum_security_bits(&self) -> u16 {
        match self {
            NistSecurityLevel::Level1 => 128,
            NistSecurityLevel::Level2 => 192,
            NistSecurityLevel::Level3 => 192,
            NistSecurityLevel::Level4 => 256,
            NistSecurityLevel::Level5 => 256,
        }
    }

    /// Get the classical security bits for this level
    pub fn classical_security_bits(&self) -> u16 {
        match self {
            NistSecurityLevel::Level1 => 128,
            NistSecurityLevel::Level2 => 256,
            NistSecurityLevel::Level3 => 192,
            NistSecurityLevel::Level4 => 384,
            NistSecurityLevel::Level5 => 256,
        }
    }

    /// Get a description of this security level
    pub fn description(&self) -> &'static str {
        match self {
            NistSecurityLevel::Level1 => "Equivalent to AES-128",
            NistSecurityLevel::Level2 => "Equivalent to SHA-256 collision resistance",
            NistSecurityLevel::Level3 => "Equivalent to AES-192",
            NistSecurityLevel::Level4 => "Equivalent to SHA-384 collision resistance",
            NistSecurityLevel::Level5 => "Equivalent to AES-256 (HIGHEST)",
        }
    }
}

impl fmt::Display for NistSecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NIST Level {} ({})", 
            match self {
                NistSecurityLevel::Level1 => 1,
                NistSecurityLevel::Level2 => 2,
                NistSecurityLevel::Level3 => 3,
                NistSecurityLevel::Level4 => 4,
                NistSecurityLevel::Level5 => 5,
            },
            self.description()
        )
    }
}

/// Verify NIST Level 5 security parameters for Kyber1024 and Dilithium5
///
/// This function validates that the cryptographic parameters meet NIST Level 5
/// security requirements as specified in REQ-24 and REQ-32.
pub fn verify_nist_level5_parameters() -> CryptoResult<()> {
    // Verify Kyber1024 parameters
    if KyberPublicKey::SIZE != 1568 {
        return Err(CryptoError::InvalidKeySize(
            format!("Kyber1024 public key size mismatch: expected 1568, got {}", KyberPublicKey::SIZE)
        ));
    }
    if KyberSecretKey::SIZE != 3168 {
        return Err(CryptoError::InvalidKeySize(
            format!("Kyber1024 secret key size mismatch: expected 3168, got {}", KyberSecretKey::SIZE)
        ));
    }
    if KyberCiphertext::SIZE != 1568 {
        return Err(CryptoError::InvalidInput(
            format!("Kyber1024 ciphertext size mismatch: expected 1568, got {}", KyberCiphertext::SIZE)
        ));
    }
    if KyberSharedSecret::SIZE != 32 {
        return Err(CryptoError::InvalidInput(
            format!("Kyber1024 shared secret size mismatch: expected 32, got {}", KyberSharedSecret::SIZE)
        ));
    }

    // Verify Dilithium5 parameters
    if DilithiumPublicKey::SIZE != 2592 {
        return Err(CryptoError::InvalidKeySize(
            format!("Dilithium5 public key size mismatch: expected 2592, got {}", DilithiumPublicKey::SIZE)
        ));
    }
    if DilithiumSecretKey::SIZE != 4864 {
        return Err(CryptoError::InvalidKeySize(
            format!("Dilithium5 secret key size mismatch: expected 4864, got {}", DilithiumSecretKey::SIZE)
        ));
    }
    // Dilithium5 signature size is variable but should be around 4627 bytes
    if DilithiumSignature::SIZE < 4595 || DilithiumSignature::SIZE > 4700 {
        return Err(CryptoError::InvalidInput(
            format!("Dilithium5 signature size out of range: expected ~4627, got {}", DilithiumSignature::SIZE)
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nist_level5_parameters() {
        // Verify NIST Level 5 parameters
        verify_nist_level5_parameters().expect("NIST Level 5 parameters verification failed");
    }

    #[test]
    fn test_nist_security_levels() {
        assert_eq!(NistSecurityLevel::Level5.quantum_security_bits(), 256);
        assert_eq!(NistSecurityLevel::Level5.classical_security_bits(), 256);
        assert!(NistSecurityLevel::Level5.description().contains("AES-256"));
    }

    #[test]
    fn test_kyber_kem_sizes() {
        let kem = KyberKem::new().unwrap();
        assert_eq!(kem.public_key_size(), 1568);
        assert_eq!(kem.secret_key_size(), 3168);
        assert_eq!(kem.ciphertext_size(), 1568);
        assert_eq!(kem.shared_secret_size(), 32);
        assert_eq!(kem.security_level(), 5);
    }

    #[test]
    fn test_dilithium_signer_sizes() {
        let signer = DilithiumSigner::new().unwrap();
        assert_eq!(signer.public_key_size(), 2592);
        assert_eq!(signer.secret_key_size(), 4864);
        assert_eq!(signer.signature_size(), 4627);
        assert_eq!(signer.security_level(), 5);
    }

    #[cfg(any(feature = "pqcrypto-kyber", feature = "pqcrypto-alt"))]
    #[test]
    fn test_kyber_kem_operations() {
        let kem = KyberKem::new().unwrap();
        
        // Generate keypair
        let keypair = kem.generate_keypair().expect("Failed to generate keypair");
        
        // Encapsulate
        let (shared_secret1, ciphertext) = kem.encapsulate(&keypair.public_key)
            .expect("Failed to encapsulate");
        
        // Decapsulate
        let shared_secret2 = kem.decapsulate(&keypair.secret_key, &ciphertext)
            .expect("Failed to decapsulate");
        
        // Verify shared secrets match
        assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
    }

    #[cfg(any(feature = "pqcrypto-dilithium", feature = "pqcrypto-alt"))]
    #[test]
    fn test_dilithium_signature_operations() {
        let signer = DilithiumSigner::new().unwrap();
        
        // Generate keypair
        let keypair = signer.generate_keypair().expect("Failed to generate keypair");
        
        // Sign message
        let message = b"B4AE v2.0 - Research-Grade Protocol Architecture";
        let signature = signer.sign(&keypair.secret_key, message)
            .expect("Failed to sign");
        
        // Verify signature
        let is_valid = signer.verify(&keypair.public_key, message, &signature)
            .expect("Failed to verify");
        assert!(is_valid);
        
        // Verify with wrong message fails
        let wrong_message = b"Wrong message";
        let is_invalid = signer.verify(&keypair.public_key, wrong_message, &signature)
            .unwrap_or(false);
        assert!(!is_invalid);
    }

    #[test]
    fn test_trait_implementations() {
        // Test that our wrappers implement the traits correctly
        fn test_kem<K: PqKem>(_kem: K) {}
        fn test_signature<S: PqSignature>(_signer: S) {}
        
        test_kem(KyberKem::new().unwrap());
        test_signature(DilithiumSigner::new().unwrap());
    }
}
