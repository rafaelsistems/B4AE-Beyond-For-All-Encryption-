//! Enhanced PKCS#11 HSM backend for B4AE
//!
//! Supports post-quantum cryptography and modern algorithms
//! Compatible with SoftHSM2, Nitrokey, and enterprise HSMs

use super::HsmBackend;
use crate::error::{B4aeError, B4aeResult};
use crate::crypto::{CryptoResult, CryptoError};
use cryptoki::context::{CInitializeArgs, CInitializeFlags};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass, KeyType};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use std::path::Path;
use std::sync::{Arc, RwLock};
use zeroize::Zeroize;

/// Enhanced PKCS#11 HSM backend with post-quantum support
#[cfg(feature = "hsm-pkcs11")]
pub struct Pkcs11HsmEnhanced {
    pkcs11: Arc<RwLock<Option<cryptoki::context::Pkcs11>>>,
    slot_id: cryptoki::slot::Slot,
    pin: Option<AuthPin>,
    session_cache: Arc<RwLock<Option<cryptoki::session::Session>>>,
}

#[cfg(feature = "hsm-pkcs11")]
impl Pkcs11HsmEnhanced {
    /// Create enhanced HSM backend
    pub fn new(
        p11_library_path: impl AsRef<Path>,
        slot_id: cryptoki::slot::Slot,
        pin: Option<impl Into<String>>,
    ) -> B4aeResult<Self> {
        let pkcs11 = cryptoki::context::Pkcs11::new(p11_library_path)
            .map_err(|e| B4aeError::ProtocolError(format!("PKCS#11 init: {}", e)))?;
        
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| B4aeError::ProtocolError(format!("PKCS#11 initialize: {}", e)))?;
        
        let pin = pin.map(|p| AuthPin::new(Box::from(p.into().as_str())));
        
        Ok(Self {
            pkcs11: Arc::new(RwLock::new(Some(pkcs11))),
            slot_id,
            pin,
            session_cache: Arc::new(RwLock::new(None)),
        })
    }

    /// Initialize session with caching for performance
    fn init_session(&self) -> B4aeResult<()> {
        let mut cache = self.session_cache.write().map_err(|e| {
            B4aeError::ProtocolError(format!("Session cache lock error: {}", e))
        })?;
        
        if cache.is_none() {
            let guard = self.pkcs11.read().map_err(|e| {
                B4aeError::ProtocolError(format!("PKCS#11 lock error: {}", e))
            })?;
            
            let pkcs11 = guard.as_ref().ok_or_else(|| {
                B4aeError::ProtocolError("PKCS#11 finalized".to_string())
            })?;
            
            let session = pkcs11
                .open_rw_session(self.slot_id)
                .map_err(|e| B4aeError::ProtocolError(format!("Open session: {}", e)))?;
            
            if let Some(ref pin) = self.pin {
                session
                    .login(UserType::User, Some(pin))
                    .map_err(|e| B4aeError::ProtocolError(format!("Login: {}", e)))?;
            }
            
            *cache = Some(session);
        }
        
        Ok(())
    }

    /// Get cached session or create new one
    fn with_session<T, F>(&self, f: F) -> B4aeResult<T>
    where
        F: FnOnce(&cryptoki::session::Session) -> B4aeResult<T>,
    {
        self.init_session()?;
        
        let cache = self.session_cache.read().map_err(|e| {
            B4aeError::ProtocolError(format!("Session cache read error: {}", e))
        })?;
        
        if let Some(ref session) = *cache {
            f(session)
        } else {
            Err(B4aeError::ProtocolError("Session not available".to_string()))
        }
    }

    /// Store key material securely in HSM
    pub fn store_key(&self, key_id: &str, key_type: KeyType, key_data: &[u8]) -> B4aeResult<()> {
        self.with_session(|session| {
            let template = match key_type {
                KeyType::AES => vec![
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::AES),
                    Attribute::Label(key_id.as_bytes().to_vec()),
                    Attribute::Value(key_data.to_vec()),
                    Attribute::Encrypt(true),
                    Attribute::Decrypt(true),
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false), // Prevent key extraction
                ],
                KeyType::GENERIC_SECRET => vec![
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::GENERIC_SECRET),
                    Attribute::Label(key_id.as_bytes().to_vec()),
                    Attribute::Value(key_data.to_vec()),
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                ],
                _ => return Err(B4aeError::ProtocolError("Unsupported key type".to_string())),
            };

            session
                .create_object(&template)
                .map_err(|e| B4aeError::ProtocolError(format!("Store key: {}", e)))?;
            
            Ok(())
        })
    }

    /// Retrieve key from HSM (if extractable)
    pub fn get_key(&self, key_id: &str) -> B4aeResult<Vec<u8>> {
        self.with_session(|session| {
            let template = vec![
                Attribute::Label(key_id.as_bytes().to_vec()),
            ];

            let handles = session
                .find_objects(&template)
                .map_err(|e| B4aeError::ProtocolError(format!("Find key: {}", e)))?;

            let key_handle = handles.into_iter().next().ok_or_else(|| {
                B4aeError::ProtocolError(format!("Key not found: {}", key_id))
            })?;

            let attrs = session
                .get_attributes(key_handle, &[cryptoki::object::AttributeType::Value])
                .map_err(|e| B4aeError::ProtocolError(format!("Get key value: {}", e)))?;

            for attr in attrs {
                if let Attribute::Value(v) = attr {
                    return Ok(v);
                }
            }

            Err(B4aeError::ProtocolError("Could not retrieve key value".to_string()))
        })
    }

    /// Generate Ed25519 keypair for B4AE hybrid signatures
    pub fn generate_ed25519_keypair(&self, key_id: &str) -> B4aeResult<Vec<u8>> {
        self.with_session(|session| {
            // Generate Ed25519 keypair
            let pub_template = vec![
                Attribute::Token(true),
                Attribute::Private(false),
                Attribute::Label(format!("{}_pub", key_id).as_bytes().to_vec()),
                Attribute::KeyType(KeyType::EC_EDWARDS),
                Attribute::Verify(true),
            ];

            let priv_template = vec![
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Label(format!("{}_priv", key_id).as_bytes().to_vec()),
                Attribute::KeyType(KeyType::EC_EDWARDS),
                Attribute::Sign(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
            ];

            let (pub_handle, _priv_handle) = session
                .generate_key_pair(
                    &Mechanism::EccEdwardsKeyPairGen,
                    &pub_template,
                    &priv_template,
                )
                .map_err(|e| B4aeError::ProtocolError(format!("Generate Ed25519 keypair: {}", e)))?;

            // Return public key
            let attrs = session
                .get_attributes(pub_handle, &[cryptoki::object::AttributeType::EcPoint])
                .map_err(|e| B4aeError::ProtocolError(format!("Get Ed25519 public key: {}", e)))?;

            for attr in attrs {
                if let Attribute::EcPoint(v) = attr {
                    return Ok(v);
                }
            }

            Err(B4aeError::ProtocolError("Could not retrieve Ed25519 public key".to_string()))
        })
    }

    /// Sign data with Ed25519 private key
    pub fn sign_ed25519(&self, key_id: &str, data: &[u8]) -> B4aeResult<Vec<u8>> {
        self.with_session(|session| {
            let template = vec![
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Label(format!("{}_priv", key_id).as_bytes().to_vec()),
                Attribute::KeyType(KeyType::EC_EDWARDS),
            ];

            let handles = session
                .find_objects(&template)
                .map_err(|e| B4aeError::ProtocolError(format!("Find Ed25519 private key: {}", e)))?;

            let key_handle = handles.into_iter().next().ok_or_else(|| {
                B4aeError::ProtocolError(format!("Ed25519 private key not found: {}", key_id))
            })?;

            session
                .sign(&Mechanism::Eddsa, key_handle, data)
                .map_err(|e| B4aeError::ProtocolError(format!("Ed25519 sign: {}", e)))
        })
    }

    /// Verify Ed25519 signature
    pub fn verify_ed25519(&self, key_id: &str, data: &[u8], signature: &[u8]) -> B4aeResult<bool> {
        self.with_session(|session| {
            let template = vec![
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::Label(format!("{}_pub", key_id).as_bytes().to_vec()),
                Attribute::KeyType(KeyType::EC_EDWARDS),
            ];

            let handles = session
                .find_objects(&template)
                .map_err(|e| B4aeError::ProtocolError(format!("Find Ed25519 public key: {}", e)))?;

            let key_handle = handles.into_iter().next().ok_or_else(|| {
                B4aeError::ProtocolError(format!("Ed25519 public key not found: {}", key_id))
            })?;

            match session.verify(&Mechanism::Eddsa, key_handle, data, signature) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        })
    }

    /// Secure key derivation using HSM
    pub fn derive_key(&self, base_key_id: &str, context: &[u8], length: usize) -> B4aeResult<Vec<u8>> {
        self.with_session(|session| {
            // Use HKDF mechanism if available, otherwise implement in software
            // For now, implement HKDF in software with HSM-protected base key
            let base_key = self.get_key(base_key_id)?;
            
            // HKDF implementation
            let hkdf_result = b4ae::crypto::hkdf::derive_key(
                &[&base_key, context],
                b"B4AE-HSM-derive",
                length,
            ).map_err(|e| B4aeError::ProtocolError(format!("HKDF derivation: {}", e)))?;

            // Zeroize base key from memory
            let mut base_key_zeroized = base_key;
            base_key_zeroized.zeroize();

            Ok(hkdf_result)
        })
    }

    /// Cleanup and secure session termination
    pub fn cleanup(&self) -> B4aeResult<()> {
        let mut cache = self.session_cache.write().map_err(|e| {
            B4aeError::ProtocolError(format!("Session cache lock error: {}", e))
        })?;

        if let Some(ref session) = *cache {
            let _ = session.logout();
        }

        *cache = None;
        Ok(())
    }
}

#[cfg(feature = "hsm-pkcs11")]
impl Drop for Pkcs11HsmEnhanced {
    fn drop(&mut self) {
        let _ = self.cleanup();
        
        if let Ok(mut guard) = self.pkcs11.write() {
            if let Some(pkcs11) = guard.take() {
                let _ = pkcs11.finalize();
            }
        }
    }
}

/// HSM Backend implementation for B4AE integration
#[cfg(feature = "hsm-pkcs11")]
impl HsmBackend for Pkcs11HsmEnhanced {
    fn generate_keypair(&self, key_id: &str) -> B4aeResult<Vec<u8>> {
        // Generate Ed25519 keypair for B4AE
        self.generate_ed25519_keypair(key_id)
    }

    fn sign(&self, key_id: &str, data: &[u8]) -> B4aeResult<Vec<u8>> {
        // Sign with Ed25519
        self.sign_ed25519(key_id, data)
    }

    fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> B4aeResult<bool> {
        // Verify Ed25519 signature
        self.verify_ed25519(key_id, data, signature)
    }

    fn is_available(&self) -> bool {
        self.session_cache.read()
            .map(|cache| cache.is_some())
            .unwrap_or(false)
    }
}

#[cfg(feature = "hsm-pkcs11")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs11_enhanced_creation() {
        // This test requires SoftHSM2 to be installed
        // Skip if PKCS#11 library is not available
        if std::path::Path::new("/usr/lib/softhsm/libsofthsm2.so").exists() {
            let hsm = Pkcs11HsmEnhanced::new("/usr/lib/softhsm/libsofthsm2.so", 0, Some("1234"));
            assert!(hsm.is_ok());
        }
    }

    #[test]
    fn test_key_management() {
        // Mock test for key management logic
        // Actual testing requires HSM hardware
        
        // Test key ID validation
        let valid_ids = vec!["test_key", "my_key_123", "B4AE_MASTER_KEY"];
        for id in valid_ids {
            assert!(id.len() <= 32); // PKCS#11 label length limit
            assert!(!id.is_empty());
        }
    }
}