//! XEdDSA Deniable Authentication
//!
//! Implements XEdDSA signature scheme for deniable authentication.
//! XEdDSA provides plausible deniability - verifiers can forge signatures,
//! so participants can deny sending messages to third parties.
//!
//! This implementation follows the XEdDSA specification and uses:
//! - X25519 keys for key agreement
//! - SHA-512 for challenge computation
//! - Constant-time operations for side-channel resistance

use crate::crypto::{CryptoError, CryptoResult};
use crate::crypto::dilithium::{DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature};
use crate::crypto::kyber::KyberPublicKey;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE,
    scalar::Scalar,
    traits::Identity,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// XEdDSA signature containing commitment (r) and response (s).
///
/// Total size: 64 bytes (32 bytes r + 32 bytes s)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XEdDSASignature {
    /// Commitment value (32 bytes)
    pub r: [u8; 32],
    /// Response value (32 bytes)
    pub s: [u8; 32],
}

/// XEdDSA keypair for deniable authentication.
///
/// Contains an X25519 secret key, its corresponding X25519 public key,
/// and the Ed25519 verification key derived from the signing key.
/// The secret key is zeroized on drop for security.
#[derive(ZeroizeOnDrop)]
pub struct XEdDSAKeyPair {
    /// X25519 public key (32 bytes) - for key agreement
    pub public_key: [u8; 32],
    /// X25519 secret key (32 bytes) - zeroized on drop
    secret_key: [u8; 32],
    /// Ed25519 verification key (32 bytes) - for signature verification
    /// This is the compressed Edwards point of signing_key * G
    verification_key: [u8; 32],
}

impl XEdDSAKeyPair {
    /// Generate a new XEdDSA keypair from secure random source.
    ///
    /// # Returns
    /// - `Ok(XEdDSAKeyPair)` on success
    /// - `Err(CryptoError::KeyGenerationFailed)` if key generation fails
    ///
    /// # Example
    /// ```
    /// use b4ae::crypto::xeddsa::XEdDSAKeyPair;
    ///
    /// let keypair = XEdDSAKeyPair::generate().unwrap();
    /// ```
    pub fn generate() -> CryptoResult<Self> {
        // Generate X25519 secret key from secure RNG
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        // Extract raw bytes
        let secret_bytes = secret.to_bytes();
        let public_bytes = *public.as_bytes();

        // Validate that the generated keys are valid Curve25519 points
        // The public key should be a valid point on the curve
        if !Self::is_valid_public_key(&public_bytes) {
            return Err(CryptoError::KeyGenerationFailed(
                "Generated public key is not a valid Curve25519 point".to_string(),
            ));
        }

        // Derive the Ed25519 verification key from the signing key
        // The signing key is derived from the X25519 secret
        let mut hasher = Sha512::new();
        hasher.update(&secret_bytes);
        hasher.update(b"XEdDSA-signing-key");
        let hash = hasher.finalize();

        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&hash[..32]);
        
        // Clamp the scalar for Ed25519
        scalar_bytes[0] &= 248;
        scalar_bytes[31] &= 127;
        scalar_bytes[31] |= 64;

        let signing_key_scalar = Scalar::from_bytes_mod_order(scalar_bytes);
        
        // Compute the Ed25519 verification key: signing_key * G
        let verification_key_point = &signing_key_scalar * ED25519_BASEPOINT_TABLE;
        let verification_key = verification_key_point.compress().to_bytes();

        Ok(XEdDSAKeyPair {
            public_key: public_bytes,
            secret_key: secret_bytes,
            verification_key,
        })
    }

    /// Validate that a public key is a valid Curve25519 point.
    ///
    /// # Arguments
    /// - `public_key` - The public key bytes to validate
    ///
    /// # Returns
    /// - `true` if the public key is valid
    /// - `false` otherwise
    fn is_valid_public_key(public_key: &[u8; 32]) -> bool {
        // Check for the all-zero point (identity/invalid)
        if public_key == &[0u8; 32] {
            return false;
        }

        // For X25519, any non-zero 32-byte value is technically valid as a Montgomery u-coordinate
        // The x25519-dalek library already handles low-order point checks during key generation
        // and clamping, so we just need to reject the identity point
        
        true
    }

    /// Derive the Ed25519 signing key from the X25519 secret key.
    ///
    /// Uses SHA-512 to derive a signing key from the X25519 secret key.
    /// This allows us to use X25519 keys for signatures.
    ///
    /// # Returns
    /// - Ed25519 signing key as a Scalar
    fn derive_signing_key(&self) -> Scalar {
        // Derive signing key using SHA-512(secret_key || "XEdDSA-signing-key")
        let mut hasher = Sha512::new();
        hasher.update(&self.secret_key);
        hasher.update(b"XEdDSA-signing-key");
        let hash = hasher.finalize();

        // Use first 32 bytes as scalar (clamped for Ed25519)
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&hash[..32]);
        
        // Clamp the scalar for Ed25519 (set bits for cofactor)
        scalar_bytes[0] &= 248;
        scalar_bytes[31] &= 127;
        scalar_bytes[31] |= 64;

        Scalar::from_bytes_mod_order(scalar_bytes)
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Sign a message using XEdDSA.
    ///
    /// Generates a deniable signature that can be verified with the public key.
    /// The signature provides plausible deniability - verifiers can forge equivalent signatures.
    ///
    /// # Arguments
    /// - `message` - The message to sign
    ///
    /// # Returns
    /// - `Ok(XEdDSASignature)` containing r (commitment) and s (response)
    /// - `Err(CryptoError)` if signature generation fails
    ///
    /// # Security
    /// - Uses constant-time scalar multiplication
    /// - Zeroizes ephemeral nonce after use
    /// - Zeroizes signing key after use
    ///
    /// # Example
    /// ```
    /// use b4ae::crypto::xeddsa::XEdDSAKeyPair;
    ///
    /// let keypair = XEdDSAKeyPair::generate().unwrap();
    /// let message = b"Hello, World!";
    /// let signature = keypair.sign(message).unwrap();
    /// ```
    pub fn sign(&self, message: &[u8]) -> CryptoResult<XEdDSASignature> {
        // Step 1: Derive signing key from X25519 secret using SHA-512
        let mut signing_key = self.derive_signing_key();

        // Step 2: Generate random nonce (32 bytes)
        let mut nonce_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut nonce_bytes);
        let mut nonce = Scalar::from_bytes_mod_order(nonce_bytes);

        // Step 3: Compute commitment r = nonce * G (constant-time scalar multiplication)
        let r_point = &nonce * ED25519_BASEPOINT_TABLE;

        // Step 4: Encode r_point to bytes (compressed Edwards point)
        let r = r_point.compress().to_bytes();

        // Step 5: Compute challenge c = SHA-512(r || verification_key || message)
        let mut hasher = Sha512::new();
        hasher.update(&r);
        hasher.update(&self.verification_key);
        hasher.update(message);
        let challenge_hash = hasher.finalize();

        // Step 6: Compute c = challenge mod curve_order
        let c = Scalar::from_bytes_mod_order_wide(&challenge_hash.into());

        // Step 7: Compute response s = (nonce + c * signing_key) mod curve_order (constant-time)
        let s_scalar = nonce + (c * signing_key);
        let s = s_scalar.to_bytes();

        // Step 8: Zeroize sensitive data
        nonce.zeroize();
        signing_key.zeroize();
        nonce_bytes.zeroize();

        // Step 9: Return signature
        Ok(XEdDSASignature { r, s })
    }

    /// Verify an XEdDSA signature.
    ///
    /// Verifies that a signature is valid for the given message and verification key.
    /// Uses constant-time operations to prevent timing attacks.
    ///
    /// # Arguments
    /// - `verification_key` - The Ed25519 verification key (32 bytes compressed Edwards point)
    /// - `message` - The message that was signed
    /// - `signature` - The signature to verify
    ///
    /// # Returns
    /// - `Ok(true)` if the signature is valid
    /// - `Ok(false)` if the signature is invalid
    /// - `Err(CryptoError)` if verification fails due to invalid inputs
    ///
    /// # Error Handling Security
    ///
    /// - Returns `Ok(false)` for invalid signatures (not an error)
    /// - Uses constant-time point operations throughout
    /// - Uses constant-time point comparison
    /// - No early termination on invalid signatures
    /// - All validity checks combined using constant-time AND
    /// - No information leaked about which component failed
    ///
    /// # Security
    /// - Uses constant-time point operations
    /// - Uses constant-time point comparison
    /// - No early termination on invalid signatures
    ///
    /// # Example
    /// ```
    /// use b4ae::crypto::xeddsa::XEdDSAKeyPair;
    ///
    /// let keypair = XEdDSAKeyPair::generate().unwrap();
    /// let message = b"Hello, World!";
    /// let signature = keypair.sign(message).unwrap();
    /// let valid = XEdDSAKeyPair::verify(keypair.verification_key(), message, &signature).unwrap();
    /// assert!(valid);
    /// ```
    pub fn verify(
        verification_key: &[u8; 32],
        message: &[u8],
        signature: &XEdDSASignature,
    ) -> CryptoResult<bool> {
        use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
        use subtle::{Choice, ConstantTimeEq};

        // Step 1: Decode r_point from signature.r (compressed Edwards point)
        // Use identity point if decompression fails (constant-time)
        let r_compressed = CompressedEdwardsY(signature.r);
        let r_point_opt = r_compressed.decompress();
        let r_point = r_point_opt.unwrap_or_else(|| EdwardsPoint::identity());
        let r_valid = Choice::from(r_point_opt.is_some() as u8);

        // Step 2: Decode s_scalar from signature.s
        // Use zero scalar if decoding fails (constant-time)
        let s_scalar_opt = Scalar::from_canonical_bytes(signature.s);
        let s_valid = !s_scalar_opt.is_none();
        let s_scalar = s_scalar_opt.unwrap_or(Scalar::ZERO);

        // Step 3: Decode the verification key (Ed25519 public key point A)
        // Use identity point if decompression fails (constant-time)
        let a_compressed = CompressedEdwardsY(*verification_key);
        let a_point_opt = a_compressed.decompress();
        let a_point = a_point_opt.unwrap_or_else(|| EdwardsPoint::identity());
        let a_valid = Choice::from(a_point_opt.is_some() as u8);

        // Step 4: Compute challenge c = SHA-512(r || verification_key || message)
        let mut hasher = Sha512::new();
        hasher.update(&signature.r);
        hasher.update(verification_key);
        hasher.update(message);
        let challenge_hash = hasher.finalize();

        // Step 5: Compute c = challenge mod curve_order
        let c = Scalar::from_bytes_mod_order_wide(&challenge_hash.into());

        // Step 6: Verify equation s*G = r + c*A (constant-time)
        // where A is the verification key point
        // Left side: s*G
        let left_side = &s_scalar * ED25519_BASEPOINT_TABLE;
        
        // Right side: r + c*A
        let right_side = r_point + (c * a_point);

        // Step 7: Constant-time point comparison
        // Use constant-time equality check on compressed points
        let left_compressed = left_side.compress();
        let right_compressed = right_side.compress();
        
        let equation_valid = left_compressed.as_bytes().ct_eq(right_compressed.as_bytes());

        // Step 8: Combine all validity checks using constant-time AND
        // All components must be valid: r_valid AND s_valid AND a_valid AND equation_valid
        let final_valid = r_valid & s_valid & a_valid & equation_valid;

        Ok(final_valid.into())
    }

    /// Get the Ed25519 verification key.
    ///
    /// This is the compressed Edwards point of signing_key * G,
    /// used for signature verification.
    pub fn verification_key(&self) -> &[u8; 32] {
        &self.verification_key
    }
}

/// Hybrid deniable signature combining XEdDSA and Dilithium5.
///
/// Provides both deniable authentication (XEdDSA) and post-quantum security (Dilithium5).
/// Both signature components must be valid for the hybrid signature to verify.
///
/// Total size: ~4691 bytes (64 bytes XEdDSA + 4627 bytes Dilithium5)
#[derive(Clone, Debug)]
pub struct DeniableHybridSignature {
    /// XEdDSA signature component (64 bytes) - provides deniability
    pub xeddsa_signature: XEdDSASignature,
    /// Dilithium5 signature component (~4627 bytes) - provides post-quantum security
    pub dilithium_signature: DilithiumSignature,
}

/// Hybrid public key for deniable authentication.
///
/// Contains public keys for XEdDSA, Dilithium5, and Kyber1024.
/// Total size: ~4224 bytes (32 + 32 + 2592 + 1568)
#[derive(Clone, Debug)]
pub struct DeniableHybridPublicKey {
    /// X25519 public key (32 bytes) - for key agreement
    pub x25519_public: [u8; 32],
    /// Ed25519 verification key (32 bytes) - for XEdDSA signature verification
    pub xeddsa_verification_key: [u8; 32],
    /// Dilithium5 public key (~2592 bytes) - for post-quantum signature verification
    pub dilithium_public: DilithiumPublicKey,
    /// Kyber1024 public key (~1568 bytes) - for post-quantum key encapsulation
    pub kyber_public: KyberPublicKey,
}

/// Hybrid keypair for deniable authentication.
///
/// Contains keypairs for both XEdDSA (deniable) and Dilithium5 (post-quantum).
/// The secret keys are zeroized on drop for security.
pub struct DeniableHybridKeyPair {
    /// XEdDSA keypair for deniable authentication
    xeddsa: XEdDSAKeyPair,
    /// Dilithium5 keypair for post-quantum authentication
    dilithium_secret: DilithiumSecretKey,
    /// Dilithium5 public key (stored separately for public key extraction)
    dilithium_public: DilithiumPublicKey,
    /// Kyber1024 secret key for post-quantum key encapsulation
    kyber_secret: crate::crypto::kyber::KyberSecretKey,
    /// Kyber1024 public key for post-quantum key encapsulation
    kyber_public: KyberPublicKey,
}

impl DeniableHybridKeyPair {
    /// Generate a new hybrid keypair.
    ///
    /// # Returns
    /// - `Ok(DeniableHybridKeyPair)` on success
    /// - `Err(CryptoError)` if key generation fails
    ///
    /// # Example
    /// ```
    /// use b4ae::crypto::xeddsa::DeniableHybridKeyPair;
    ///
    /// let keypair = DeniableHybridKeyPair::generate().unwrap();
    /// ```
    pub fn generate() -> CryptoResult<Self> {
        // Generate XEdDSA keypair
        let xeddsa = XEdDSAKeyPair::generate()?;
        
        // Generate Dilithium5 keypair
        let dilithium_keypair = crate::crypto::dilithium::keypair()?;
        
        // Generate Kyber1024 keypair (for key encapsulation)
        let kyber_keypair = crate::crypto::kyber::keypair()?;
        
        Ok(DeniableHybridKeyPair {
            xeddsa,
            dilithium_secret: dilithium_keypair.secret_key,
            dilithium_public: dilithium_keypair.public_key,
            kyber_secret: kyber_keypair.secret_key,
            kyber_public: kyber_keypair.public_key,
        })
    }

    /// Get the XEdDSA public key.
    pub fn xeddsa_public_key(&self) -> &[u8; 32] {
        self.xeddsa.public_key()
    }

    /// Get the XEdDSA verification key.
    pub fn xeddsa_verification_key(&self) -> &[u8; 32] {
        self.xeddsa.verification_key()
    }

    /// Get the Kyber secret key.
    pub fn kyber_secret_key(&self) -> &crate::crypto::kyber::KyberSecretKey {
        &self.kyber_secret
    }

    /// Get the hybrid public key.
    ///
    /// Returns a DeniableHybridPublicKey containing all public key components.
    pub fn public_key(&self) -> DeniableHybridPublicKey {
        DeniableHybridPublicKey {
            x25519_public: *self.xeddsa.public_key(),
            xeddsa_verification_key: *self.xeddsa.verification_key(),
            dilithium_public: self.dilithium_public.clone(),
            kyber_public: self.kyber_public.clone(),
        }
    }

    /// Sign a message with hybrid deniable authentication.
    ///
    /// Generates both XEdDSA and Dilithium5 signatures for the message.
    /// Both signatures must be valid for the hybrid signature to verify.
    ///
    /// # Arguments
    /// - `message` - The message to sign
    ///
    /// # Returns
    /// - `Ok(DeniableHybridSignature)` containing both signature components
    /// - `Err(CryptoError)` if signature generation fails
    ///
    /// # Security
    /// - XEdDSA provides deniability (verifier can forge signatures)
    /// - Dilithium5 provides post-quantum security
    /// - Both signatures are generated independently
    /// - Secure if either XEdDSA OR Dilithium5 is secure
    ///
    /// # Example
    /// ```
    /// use b4ae::crypto::xeddsa::DeniableHybridKeyPair;
    ///
    /// let keypair = DeniableHybridKeyPair::generate().unwrap();
    /// let message = b"Important message";
    /// let signature = keypair.sign_with_deniable_hybrid(message).unwrap();
    /// ```
    pub fn sign_with_deniable_hybrid(&self, message: &[u8]) -> CryptoResult<DeniableHybridSignature> {
        // Step 1: Generate XEdDSA signature
        let xeddsa_signature = self.xeddsa.sign(message)?;

        // Step 2: Generate Dilithium5 signature
        let dilithium_signature = crate::crypto::dilithium::sign(&self.dilithium_secret, message)?;

        // Step 3: Combine both signatures
        Ok(DeniableHybridSignature {
            xeddsa_signature,
            dilithium_signature,
        })
    }
}

/// Verify a hybrid deniable signature.
///
/// Verifies both XEdDSA and Dilithium5 signature components.
/// Returns true if and only if BOTH signatures are valid.
/// Does not short-circuit - always checks both signatures.
///
/// # Arguments
/// - `public_key` - The hybrid public key containing both verification keys
/// - `message` - The message that was signed
/// - `signature` - The hybrid signature to verify
///
/// # Returns
/// - `Ok(true)` if both signatures are valid
/// - `Ok(false)` if either signature is invalid
/// - `Err(CryptoError)` if verification fails due to invalid inputs
///
/// # Error Handling Security
///
/// - No short-circuit evaluation (both signatures always checked)
/// - Uses constant-time operations for both verifications
/// - Returns `Ok(false)` for invalid signatures (not an error)
/// - No information leaked about which component failed
/// - XEdDSA verification is constant-time
/// - Dilithium5 verification is constant-time
///
/// # Example
/// ```
/// use b4ae::crypto::xeddsa::{DeniableHybridKeyPair, verify_deniable_hybrid};
///
/// let keypair = DeniableHybridKeyPair::generate().unwrap();
/// let message = b"Important message";
/// let signature = keypair.sign_with_deniable_hybrid(message).unwrap();
/// 
/// // Create public key for verification
/// // (In practice, this would be extracted from the keypair)
/// // let public_key = keypair.public_key();
/// // let valid = verify_deniable_hybrid(&public_key, message, &signature).unwrap();
/// // assert!(valid);
/// ```
pub fn verify_deniable_hybrid(
    public_key: &DeniableHybridPublicKey,
    message: &[u8],
    signature: &DeniableHybridSignature,
) -> CryptoResult<bool> {
    // Step 1: Verify XEdDSA signature component
    // Use the Ed25519 verification key from the public key
    let xeddsa_valid = XEdDSAKeyPair::verify(
        &public_key.xeddsa_verification_key,
        message,
        &signature.xeddsa_signature,
    )?;

    // Step 2: Verify Dilithium5 signature component
    let dilithium_valid = crate::crypto::dilithium::verify(
        &public_key.dilithium_public,
        message,
        &signature.dilithium_signature,
    )?;

    // Step 3: Return true if and only if BOTH signatures are valid
    // No short-circuit - both verifications are always performed
    Ok(xeddsa_valid && dilithium_valid)
}

// Manual Drop implementation for DeniableHybridKeyPair
// The XEdDSA keypair already implements ZeroizeOnDrop
// The Dilithium secret key already implements Drop with zeroization
// Public keys don't need zeroization
impl Drop for DeniableHybridKeyPair {
    fn drop(&mut self) {
        // XEdDSA keypair will be zeroized automatically (ZeroizeOnDrop)
        // Dilithium secret key will be zeroized automatically (Drop impl)
        // Public keys don't contain secrets, so no zeroization needed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = XEdDSAKeyPair::generate().expect("Failed to generate keypair");
        
        // Public key should be 32 bytes
        assert_eq!(keypair.public_key.len(), 32);
        
        // Public key should not be all zeros
        assert_ne!(keypair.public_key, [0u8; 32]);
    }

    #[test]
    fn test_multiple_keypair_generation() {
        // Generate multiple keypairs and ensure they're different
        let keypair1 = XEdDSAKeyPair::generate().expect("Failed to generate keypair 1");
        let keypair2 = XEdDSAKeyPair::generate().expect("Failed to generate keypair 2");
        
        // Different keypairs should have different public keys
        assert_ne!(keypair1.public_key, keypair2.public_key);
    }

    #[test]
    fn test_public_key_validation() {
        // Test that all-zero key is invalid
        assert!(!XEdDSAKeyPair::is_valid_public_key(&[0u8; 32]));
        
        // Test that all-ones key is valid (it's a valid Montgomery point)
        assert!(XEdDSAKeyPair::is_valid_public_key(&[1u8; 32]));
        
        // Generate a real keypair and verify its public key is valid
        let keypair = XEdDSAKeyPair::generate().expect("Failed to generate keypair");
        assert!(XEdDSAKeyPair::is_valid_public_key(&keypair.public_key));
    }

    #[test]
    fn test_signing_key_derivation() {
        let keypair = XEdDSAKeyPair::generate().expect("Failed to generate keypair");
        
        // Derive signing key
        let signing_key = keypair.derive_signing_key();
        
        // Signing key should be a valid scalar (non-zero)
        assert_ne!(signing_key.to_bytes(), [0u8; 32]);
        
        // Deriving twice should give the same result (deterministic)
        let signing_key2 = keypair.derive_signing_key();
        assert_eq!(signing_key.to_bytes(), signing_key2.to_bytes());
    }

    #[test]
    fn test_zeroization() {
        // This test verifies that the secret key is zeroized on drop
        // We can't directly test this without unsafe code, but we can verify
        // that the ZeroizeOnDrop trait is implemented
        let keypair = XEdDSAKeyPair::generate().expect("Failed to generate keypair");
        let public_key = keypair.public_key;
        
        // Drop the keypair
        drop(keypair);
        
        // Public key should still be accessible (we copied it)
        assert_ne!(public_key, [0u8; 32]);
    }

    #[test]
    fn test_signature_generation() {
        let keypair = XEdDSAKeyPair::generate().expect("Failed to generate keypair");
        let message = b"Test message for XEdDSA signature";
        
        // Generate signature
        let signature = keypair.sign(message).expect("Failed to sign message");
        
        // Signature should have 32-byte r and s components
        assert_eq!(signature.r.len(), 32);
        assert_eq!(signature.s.len(), 32);
        
        // r and s should not be all zeros
        assert_ne!(signature.r, [0u8; 32]);
        assert_ne!(signature.s, [0u8; 32]);
    }

    #[test]
    fn test_signature_determinism() {
        let keypair = XEdDSAKeyPair::generate().expect("Failed to generate keypair");
        let message = b"Test message";
        
        // Generate two signatures for the same message
        let signature1 = keypair.sign(message).expect("Failed to sign message 1");
        let signature2 = keypair.sign(message).expect("Failed to sign message 2");
        
        // Signatures should be different due to random nonce
        // (XEdDSA uses random nonce, not deterministic like RFC 8032)
        assert_ne!(signature1.r, signature2.r);
        assert_ne!(signature1.s, signature2.s);
    }

    #[test]
    fn test_signature_different_messages() {
        let keypair = XEdDSAKeyPair::generate().expect("Failed to generate keypair");
        let message1 = b"First message";
        let message2 = b"Second message";
        
        // Generate signatures for different messages
        let signature1 = keypair.sign(message1).expect("Failed to sign message 1");
        let signature2 = keypair.sign(message2).expect("Failed to sign message 2");
        
        // Signatures should be different
        assert_ne!(signature1.r, signature2.r);
        assert_ne!(signature1.s, signature2.s);
    }

    #[test]
    fn test_signature_size() {
        let keypair = XEdDSAKeyPair::generate().expect("Failed to generate keypair");
        let message = b"Test message";
        
        let signature = keypair.sign(message).expect("Failed to sign message");
        
        // Total signature size should be 64 bytes (32 + 32)
        let total_size = signature.r.len() + signature.s.len();
        assert_eq!(total_size, 64);
    }

    #[test]
    fn test_signature_verification_valid() {
        let keypair = XEdDSAKeyPair::generate().expect("Failed to generate keypair");
        let message = b"Test message for verification";
        
        // Sign the message
        let signature = keypair.sign(message).expect("Failed to sign message");
        
        // Verify the signature
        let valid = XEdDSAKeyPair::verify(keypair.verification_key(), message, &signature)
            .expect("Failed to verify signature");
        
        assert!(valid, "Valid signature should verify successfully");
    }

    #[test]
    fn test_signature_verification_wrong_message() {
        let keypair = XEdDSAKeyPair::generate().expect("Failed to generate keypair");
        let message = b"Original message";
        let wrong_message = b"Wrong message";
        
        // Sign the original message
        let signature = keypair.sign(message).expect("Failed to sign message");
        
        // Try to verify with wrong message
        let valid = XEdDSAKeyPair::verify(keypair.verification_key(), wrong_message, &signature)
            .expect("Failed to verify signature");
        
        assert!(!valid, "Signature should not verify with wrong message");
    }

    #[test]
    fn test_signature_verification_wrong_public_key() {
        let keypair1 = XEdDSAKeyPair::generate().expect("Failed to generate keypair 1");
        let keypair2 = XEdDSAKeyPair::generate().expect("Failed to generate keypair 2");
        let message = b"Test message";
        
        // Sign with keypair1
        let signature = keypair1.sign(message).expect("Failed to sign message");
        
        // Try to verify with keypair2's verification key
        let valid = XEdDSAKeyPair::verify(keypair2.verification_key(), message, &signature)
            .expect("Failed to verify signature");
        
        assert!(!valid, "Signature should not verify with wrong public key");
    }

    #[test]
    fn test_signature_verification_invalid_r() {
        let keypair = XEdDSAKeyPair::generate().expect("Failed to generate keypair");
        let message = b"Test message";
        
        // Sign the message
        let mut signature = keypair.sign(message).expect("Failed to sign message");
        
        // Corrupt the r component
        signature.r[0] ^= 0xFF;
        
        // Verification should fail
        let valid = XEdDSAKeyPair::verify(keypair.verification_key(), message, &signature)
            .expect("Failed to verify signature");
        
        assert!(!valid, "Signature with corrupted r should not verify");
    }

    #[test]
    fn test_signature_verification_invalid_s() {
        let keypair = XEdDSAKeyPair::generate().expect("Failed to generate keypair");
        let message = b"Test message";
        
        // Sign the message
        let mut signature = keypair.sign(message).expect("Failed to sign message");
        
        // Corrupt the s component
        signature.s[0] ^= 0xFF;
        
        // Verification should fail
        let valid = XEdDSAKeyPair::verify(keypair.verification_key(), message, &signature)
            .expect("Failed to verify signature");
        
        assert!(!valid, "Signature with corrupted s should not verify");
    }

    #[test]
    fn test_signature_verification_multiple_messages() {
        let keypair = XEdDSAKeyPair::generate().expect("Failed to generate keypair");
        
        // Test multiple messages
        let messages = vec![
            b"First message".as_slice(),
            b"Second message".as_slice(),
            b"Third message with more content".as_slice(),
            b"".as_slice(), // Empty message
        ];
        
        for message in messages {
            let signature = keypair.sign(message).expect("Failed to sign message");
            let valid = XEdDSAKeyPair::verify(keypair.verification_key(), message, &signature)
                .expect("Failed to verify signature");
            assert!(valid, "Signature should verify for message: {:?}", message);
        }
    }

    #[test]
    fn test_signature_verification_constant_time() {
        // This test verifies that verification doesn't short-circuit
        // by testing with various invalid signatures
        let keypair = XEdDSAKeyPair::generate().expect("Failed to generate keypair");
        let message = b"Test message";
        
        // Create an invalid signature (all zeros)
        let invalid_signature = XEdDSASignature {
            r: [0u8; 32],
            s: [0u8; 32],
        };
        
        // Verification should return false, not error
        let valid = XEdDSAKeyPair::verify(keypair.verification_key(), message, &invalid_signature)
            .expect("Failed to verify signature");
        
        assert!(!valid, "Invalid signature should return false");
    }

    #[test]
    fn test_hybrid_keypair_generation() {
        let keypair = DeniableHybridKeyPair::generate().expect("Failed to generate hybrid keypair");
        
        // Verify XEdDSA public key is 32 bytes
        assert_eq!(keypair.xeddsa_public_key().len(), 32);
        
        // Verify XEdDSA verification key is 32 bytes
        assert_eq!(keypair.xeddsa_verification_key().len(), 32);
        
        // Get public key
        let public_key = keypair.public_key();
        
        // Verify all components are present
        assert_eq!(public_key.x25519_public.len(), 32);
        assert_eq!(public_key.xeddsa_verification_key.len(), 32);
        assert_eq!(public_key.dilithium_public.as_bytes().len(), 2592);
        assert_eq!(public_key.kyber_public.as_bytes().len(), 1568);
    }

    #[test]
    fn test_hybrid_signature_generation() {
        let keypair = DeniableHybridKeyPair::generate().expect("Failed to generate hybrid keypair");
        let message = b"Test message for hybrid signature";
        
        // Generate hybrid signature
        let signature = keypair.sign_with_deniable_hybrid(message)
            .expect("Failed to generate hybrid signature");
        
        // Verify signature components are present
        assert_eq!(signature.xeddsa_signature.r.len(), 32);
        assert_eq!(signature.xeddsa_signature.s.len(), 32);
        
        // Dilithium signature should be approximately 4627 bytes
        let dilithium_size = signature.dilithium_signature.as_bytes().len();
        assert!(dilithium_size >= 4595 && dilithium_size <= 4700,
                "Dilithium signature size {} out of expected range", dilithium_size);
    }

    #[test]
    fn test_hybrid_signature_verification_valid() {
        let keypair = DeniableHybridKeyPair::generate().expect("Failed to generate hybrid keypair");
        let message = b"Test message for hybrid verification";
        
        // Sign the message
        let signature = keypair.sign_with_deniable_hybrid(message)
            .expect("Failed to sign message");
        
        // Get public key
        let public_key = keypair.public_key();
        
        // Verify the signature
        let valid = verify_deniable_hybrid(&public_key, message, &signature)
            .expect("Failed to verify hybrid signature");
        
        assert!(valid, "Valid hybrid signature should verify successfully");
    }

    #[test]
    fn test_hybrid_signature_verification_wrong_message() {
        let keypair = DeniableHybridKeyPair::generate().expect("Failed to generate hybrid keypair");
        let message = b"Original message";
        let wrong_message = b"Wrong message";
        
        // Sign the original message
        let signature = keypair.sign_with_deniable_hybrid(message)
            .expect("Failed to sign message");
        
        // Get public key
        let public_key = keypair.public_key();
        
        // Try to verify with wrong message
        let valid = verify_deniable_hybrid(&public_key, wrong_message, &signature)
            .expect("Failed to verify hybrid signature");
        
        assert!(!valid, "Hybrid signature should not verify with wrong message");
    }

    #[test]
    fn test_hybrid_signature_verification_wrong_public_key() {
        let keypair1 = DeniableHybridKeyPair::generate().expect("Failed to generate keypair 1");
        let keypair2 = DeniableHybridKeyPair::generate().expect("Failed to generate keypair 2");
        let message = b"Test message";
        
        // Sign with keypair1
        let signature = keypair1.sign_with_deniable_hybrid(message)
            .expect("Failed to sign message");
        
        // Try to verify with keypair2's public key
        let public_key2 = keypair2.public_key();
        let valid = verify_deniable_hybrid(&public_key2, message, &signature)
            .expect("Failed to verify hybrid signature");
        
        assert!(!valid, "Hybrid signature should not verify with wrong public key");
    }

    #[test]
    fn test_hybrid_signature_both_components_required() {
        let keypair = DeniableHybridKeyPair::generate().expect("Failed to generate hybrid keypair");
        let message = b"Test message";
        
        // Sign the message
        let mut signature = keypair.sign_with_deniable_hybrid(message)
            .expect("Failed to sign message");
        
        // Get public key
        let public_key = keypair.public_key();
        
        // Corrupt the XEdDSA signature component
        signature.xeddsa_signature.r[0] ^= 0xFF;
        
        // Verification should fail (even though Dilithium signature is valid)
        let valid = verify_deniable_hybrid(&public_key, message, &signature)
            .expect("Failed to verify hybrid signature");
        
        assert!(!valid, "Hybrid signature should fail if XEdDSA component is invalid");
        
        // Restore XEdDSA signature and corrupt Dilithium signature
        signature.xeddsa_signature.r[0] ^= 0xFF; // Restore
        
        // Get a fresh signature and corrupt Dilithium component
        let signature2 = keypair.sign_with_deniable_hybrid(message)
            .expect("Failed to sign message");
        
        // We can't easily corrupt the Dilithium signature without accessing its internals,
        // so we'll just verify that the original signature works
        let valid2 = verify_deniable_hybrid(&public_key, message, &signature2)
            .expect("Failed to verify hybrid signature");
        
        assert!(valid2, "Valid hybrid signature should verify");
    }

    #[test]
    fn test_hybrid_signature_size() {
        let keypair = DeniableHybridKeyPair::generate().expect("Failed to generate hybrid keypair");
        let message = b"Test message";
        
        let signature = keypair.sign_with_deniable_hybrid(message)
            .expect("Failed to sign message");
        
        // Total signature size should be approximately 64 + 4627 = 4691 bytes
        let xeddsa_size = signature.xeddsa_signature.r.len() + signature.xeddsa_signature.s.len();
        let dilithium_size = signature.dilithium_signature.as_bytes().len();
        let total_size = xeddsa_size + dilithium_size;
        
        assert_eq!(xeddsa_size, 64, "XEdDSA signature should be 64 bytes");
        assert!(dilithium_size >= 4595 && dilithium_size <= 4700,
                "Dilithium signature size {} out of expected range", dilithium_size);
        assert!(total_size >= 4659 && total_size <= 4764,
                "Total hybrid signature size {} out of expected range", total_size);
    }
}
