// B4AE Hybrid Cryptography Implementation
// Combines Classical (ECDH/ECDSA) with Post-Quantum (Kyber/Dilithium)

use crate::crypto::{CryptoError, CryptoResult};
use crate::crypto::kyber::{self, KyberPublicKey, KyberSecretKey, KyberCiphertext, KyberSharedSecret};
use crate::crypto::dilithium::{self, DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature};
use crate::crypto::hkdf;
use std::fmt;

/// Hybrid Public Key (Classical + Post-Quantum)
#[derive(Clone)]
pub struct HybridPublicKey {
    pub ecdh_public: Vec<u8>,      // ECDH-P521 public key (133 bytes)
    pub kyber_public: KyberPublicKey,
    pub ecdsa_public: Vec<u8>,     // ECDSA-P521 public key (133 bytes)
    pub dilithium_public: DilithiumPublicKey,
}

/// Hybrid Secret Key (Classical + Post-Quantum)
pub struct HybridSecretKey {
    pub ecdh_secret: Vec<u8>,      // ECDH-P521 secret key (66 bytes)
    pub kyber_secret: KyberSecretKey,
    pub ecdsa_secret: Vec<u8>,     // ECDSA-P521 secret key (66 bytes)
    pub dilithium_secret: DilithiumSecretKey,
}

/// Hybrid Key Pair
pub struct HybridKeyPair {
    pub public_key: HybridPublicKey,
    pub secret_key: HybridSecretKey,
}

/// Hybrid Ciphertext (for key exchange)
#[derive(Clone)]
pub struct HybridCiphertext {
    pub ecdh_ephemeral_public: Vec<u8>,  // Ephemeral ECDH public key
    pub kyber_ciphertext: KyberCiphertext,
}

/// Hybrid Signature
#[derive(Clone)]
pub struct HybridSignature {
    pub ecdsa_signature: Vec<u8>,        // ECDSA-P521 signature (~132 bytes)
    pub dilithium_signature: DilithiumSignature,
}

impl HybridPublicKey {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // ECDH public key length + data
        bytes.extend_from_slice(&(self.ecdh_public.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.ecdh_public);
        
        // Kyber public key
        bytes.extend_from_slice(self.kyber_public.as_bytes());
        
        // ECDSA public key length + data
        bytes.extend_from_slice(&(self.ecdsa_public.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.ecdsa_public);
        
        // Dilithium public key
        bytes.extend_from_slice(self.dilithium_public.as_bytes());
        
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        let mut offset = 0;
        
        // Read ECDH public key
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
        
        // Read ECDSA public key
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
        
        // ECDSA signature length + data
        bytes.extend_from_slice(&(self.ecdsa_signature.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.ecdsa_signature);
        
        // Dilithium signature
        bytes.extend_from_slice(self.dilithium_signature.as_bytes());
        
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
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
}

impl HybridCiphertext {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // ECDH ephemeral public key length + data
        bytes.extend_from_slice(&(self.ecdh_ephemeral_public.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.ecdh_ephemeral_public);
        
        // Kyber ciphertext
        bytes.extend_from_slice(self.kyber_ciphertext.as_bytes());
        
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        let mut offset = 0;
        
        // Read ECDH ephemeral public key
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

/// Generate hybrid key pair
pub fn keypair() -> CryptoResult<HybridKeyPair> {
    // Generate Kyber keypair
    let kyber_keypair = kyber::keypair()?;
    
    // Generate Dilithium keypair
    let dilithium_keypair = dilithium::keypair()?;
    
    // Generate ECDH and ECDSA keypairs (placeholder - would use actual ECC library)
    #[cfg(feature = "openssl")]
    {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        
        // ECDH-P521
        let group = EcGroup::from_curve_name(Nid::SECP521R1)
            .map_err(|e| CryptoError::KeyGenerationFailed(e.to_string()))?;
        let ecdh_key = EcKey::generate(&group)
            .map_err(|e| CryptoError::KeyGenerationFailed(e.to_string()))?;
        
        let ecdh_public = ecdh_key.public_key().to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut openssl::bn::BigNumContext::new().unwrap()
        ).map_err(|e| CryptoError::KeyGenerationFailed(e.to_string()))?;
        
        let ecdh_secret = ecdh_key.private_key().to_vec();
        
        // ECDSA-P521 (reuse same curve)
        let ecdsa_key = EcKey::generate(&group)
            .map_err(|e| CryptoError::KeyGenerationFailed(e.to_string()))?;
        
        let ecdsa_public = ecdsa_key.public_key().to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut openssl::bn::BigNumContext::new().unwrap()
        ).map_err(|e| CryptoError::KeyGenerationFailed(e.to_string()))?;
        
        let ecdsa_secret = ecdsa_key.private_key().to_vec();
        
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
    
    #[cfg(not(feature = "openssl"))]
    {
        // Placeholder for development
        let ecdh_public = vec![0u8; 133];
        let ecdh_secret = vec![0u8; 66];
        let ecdsa_public = vec![0u8; 133];
        let ecdsa_secret = vec![0u8; 66];
        
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
}

/// Hybrid key exchange (encapsulation)
pub fn encapsulate(public_key: &HybridPublicKey) -> CryptoResult<(Vec<u8>, HybridCiphertext)> {
    // Kyber encapsulation
    let (kyber_ss, kyber_ct) = kyber::encapsulate(&public_key.kyber_public)?;
    
    // ECDH key exchange (placeholder)
    #[cfg(feature = "openssl")]
    {
        use openssl::ec::{EcGroup, EcKey, EcPoint};
        use openssl::nid::Nid;
        use openssl::derive::Deriver;
        use openssl::pkey::PKey;
        
        let group = EcGroup::from_curve_name(Nid::SECP521R1)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        // Generate ephemeral key
        let ephemeral_key = EcKey::generate(&group)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        let ephemeral_public = ephemeral_key.public_key().to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut openssl::bn::BigNumContext::new().unwrap()
        ).map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        // Parse recipient's public key
        let mut ctx = openssl::bn::BigNumContext::new()
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        let recipient_point = EcPoint::from_bytes(&group, &public_key.ecdh_public, &mut ctx)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        let recipient_key = EcKey::from_public_key(&group, &recipient_point)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        // Perform ECDH
        let ephemeral_pkey = PKey::from_ec_key(ephemeral_key)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        let recipient_pkey = PKey::from_ec_key(recipient_key)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        let mut deriver = Deriver::new(&ephemeral_pkey)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        deriver.set_peer(&recipient_pkey)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        let ecdh_ss = deriver.derive_to_vec()
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        // Combine shared secrets using HKDF
        let combined_ss = hkdf::derive_key(&[kyber_ss.as_bytes(), &ecdh_ss], b"B4AE-v1-hybrid-kem", 32)?;
        
        Ok((
            combined_ss,
            HybridCiphertext {
                ecdh_ephemeral_public: ephemeral_public,
                kyber_ciphertext: kyber_ct,
            },
        ))
    }
    
    #[cfg(not(feature = "openssl"))]
    {
        // Placeholder: just use Kyber shared secret
        let combined_ss = kyber_ss.as_bytes().to_vec();
        let ephemeral_public = vec![0u8; 133];
        
        Ok((
            combined_ss,
            HybridCiphertext {
                ecdh_ephemeral_public: ephemeral_public,
                kyber_ciphertext: kyber_ct,
            },
        ))
    }
}

/// Hybrid key exchange (decapsulation)
pub fn decapsulate(
    secret_key: &HybridSecretKey,
    ciphertext: &HybridCiphertext,
) -> CryptoResult<Vec<u8>> {
    // Kyber decapsulation
    let kyber_ss = kyber::decapsulate(&secret_key.kyber_secret, &ciphertext.kyber_ciphertext)?;
    
    // ECDH key exchange (placeholder)
    #[cfg(feature = "openssl")]
    {
        use openssl::ec::{EcGroup, EcKey, EcPoint};
        use openssl::nid::Nid;
        use openssl::derive::Deriver;
        use openssl::pkey::PKey;
        use openssl::bn::BigNum;
        
        let group = EcGroup::from_curve_name(Nid::SECP521R1)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        
        // Parse ephemeral public key
        let mut ctx = openssl::bn::BigNumContext::new()
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        let ephemeral_point = EcPoint::from_bytes(&group, &ciphertext.ecdh_ephemeral_public, &mut ctx)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        
        let ephemeral_key = EcKey::from_public_key(&group, &ephemeral_point)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        
        // Reconstruct our private key
        let private_bn = BigNum::from_slice(&secret_key.ecdh_secret)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        let our_key = EcKey::from_private_components(&group, &private_bn, ephemeral_key.public_key())
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        
        // Perform ECDH
        let our_pkey = PKey::from_ec_key(our_key)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        let ephemeral_pkey = PKey::from_ec_key(ephemeral_key)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        
        let mut deriver = Deriver::new(&our_pkey)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        deriver.set_peer(&ephemeral_pkey)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        
        let ecdh_ss = deriver.derive_to_vec()
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        
        // Combine shared secrets using HKDF
        let combined_ss = hkdf::derive_key(&[kyber_ss.as_bytes(), &ecdh_ss], b"B4AE-v1-hybrid-kem", 32)?;
        
        Ok(combined_ss)
    }
    
    #[cfg(not(feature = "openssl"))]
    {
        // Placeholder: just use Kyber shared secret
        Ok(kyber_ss.as_bytes().to_vec())
    }
}

/// Hybrid signature generation
pub fn sign(secret_key: &HybridSecretKey, message: &[u8]) -> CryptoResult<HybridSignature> {
    // Dilithium signature
    let dilithium_sig = dilithium::sign(&secret_key.dilithium_secret, message)?;
    
    // ECDSA signature (placeholder)
    #[cfg(feature = "openssl")]
    {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::sign::Signer;
        use openssl::hash::MessageDigest;
        use openssl::bn::BigNum;
        
        let group = EcGroup::from_curve_name(Nid::SECP521R1)
            .map_err(|e| CryptoError::SignatureFailed(e.to_string()))?;
        
        let private_bn = BigNum::from_slice(&secret_key.ecdsa_secret)
            .map_err(|e| CryptoError::SignatureFailed(e.to_string()))?;
        
        // Note: This is simplified - proper implementation needs public key reconstruction
        let ecdsa_key = EcKey::from_private_components(&group, &private_bn, 
            &EcKey::generate(&group).unwrap().public_key().clone())
            .map_err(|e| CryptoError::SignatureFailed(e.to_string()))?;
        
        let pkey = PKey::from_ec_key(ecdsa_key)
            .map_err(|e| CryptoError::SignatureFailed(e.to_string()))?;
        
        let mut signer = Signer::new(MessageDigest::sha512(), &pkey)
            .map_err(|e| CryptoError::SignatureFailed(e.to_string()))?;
        
        signer.update(message)
            .map_err(|e| CryptoError::SignatureFailed(e.to_string()))?;
        
        let ecdsa_sig = signer.sign_to_vec()
            .map_err(|e| CryptoError::SignatureFailed(e.to_string()))?;
        
        Ok(HybridSignature {
            ecdsa_signature: ecdsa_sig,
            dilithium_signature: dilithium_sig,
        })
    }
    
    #[cfg(not(feature = "openssl"))]
    {
        // Placeholder
        let ecdsa_sig = vec![0u8; 132];
        
        Ok(HybridSignature {
            ecdsa_signature: ecdsa_sig,
            dilithium_signature: dilithium_sig,
        })
    }
}

/// Hybrid signature verification
pub fn verify(
    public_key: &HybridPublicKey,
    message: &[u8],
    signature: &HybridSignature,
) -> CryptoResult<bool> {
    // Verify Dilithium signature
    let dilithium_valid = dilithium::verify(
        &public_key.dilithium_public,
        message,
        &signature.dilithium_signature,
    )?;
    
    if !dilithium_valid {
        return Ok(false);
    }
    
    // Verify ECDSA signature (placeholder)
    #[cfg(feature = "openssl")]
    {
        use openssl::ec::{EcGroup, EcKey, EcPoint};
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::sign::Verifier;
        use openssl::hash::MessageDigest;
        
        let group = EcGroup::from_curve_name(Nid::SECP521R1)
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
        
        let mut ctx = openssl::bn::BigNumContext::new()
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
        let point = EcPoint::from_bytes(&group, &public_key.ecdsa_public, &mut ctx)
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
        
        let ecdsa_key = EcKey::from_public_key(&group, &point)
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
        
        let pkey = PKey::from_ec_key(ecdsa_key)
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
        
        let mut verifier = Verifier::new(MessageDigest::sha512(), &pkey)
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
        
        verifier.update(message)
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
        
        let ecdsa_valid = verifier.verify(&signature.ecdsa_signature)
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
        
        Ok(ecdsa_valid && dilithium_valid)
    }
    
    #[cfg(not(feature = "openssl"))]
    {
        // Placeholder: only check Dilithium
        Ok(dilithium_valid)
    }
}

impl fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridPublicKey")
            .field("ecdh_public", &format!("{}...", hex::encode(&self.ecdh_public[..8])))
            .field("kyber_public", &self.kyber_public)
            .field("ecdsa_public", &format!("{}...", hex::encode(&self.ecdsa_public[..8])))
            .field("dilithium_public", &self.dilithium_public)
            .finish()
    }
}

impl fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridSecretKey([REDACTED])")
    }
}

// Secure drop implementation
impl Drop for HybridSecretKey {
    fn drop(&mut self) {
        // Zero out secret key memory
        for byte in &mut self.ecdh_secret {
            *byte = 0;
        }
        for byte in &mut self.ecdsa_secret {
            *byte = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(all(feature = "liboqs", feature = "openssl"))]
    fn test_hybrid_keypair() {
        let keypair = keypair().expect("Failed to generate hybrid keypair");
        assert!(keypair.public_key.ecdh_public.len() > 0);
        assert!(keypair.public_key.ecdsa_public.len() > 0);
    }

    #[test]
    #[cfg(all(feature = "liboqs", feature = "openssl"))]
    fn test_hybrid_key_exchange() {
        let alice = keypair().expect("Failed to generate Alice's keypair");
        let bob = keypair().expect("Failed to generate Bob's keypair");
        
        // Alice encapsulates to Bob
        let (alice_ss, ciphertext) = encapsulate(&bob.public_key)
            .expect("Failed to encapsulate");
        
        // Bob decapsulates
        let bob_ss = decapsulate(&bob.secret_key, &ciphertext)
            .expect("Failed to decapsulate");
        
        assert_eq!(alice_ss, bob_ss);
    }

    #[test]
    #[cfg(all(feature = "liboqs", feature = "openssl"))]
    fn test_hybrid_signature() {
        let keypair = keypair().expect("Failed to generate keypair");
        let message = b"Hello, B4AE Hybrid!";
        
        let signature = sign(&keypair.secret_key, message)
            .expect("Failed to sign");
        
        let valid = verify(&keypair.public_key, message, &signature)
            .expect("Failed to verify");
        
        assert!(valid);
    }
}
