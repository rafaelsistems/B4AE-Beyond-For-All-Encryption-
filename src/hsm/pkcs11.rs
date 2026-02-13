//! PKCS#11 HSM backend
//!
//! Menggunakan cryptoki untuk komunikasi dengan HSM via PKCS#11.
//! Requires: SoftHSM2, Nitrokey, atau PKCS#11 library lain.
//!
//! Setup SoftHSM2 (Linux):
//!   sudo apt install libsofthsm2
//!   mkdir -p /tmp/tokens
//!   echo "directories.tokendir = /tmp/tokens" > /tmp/softhsm2.conf
//!   export SOFTHSM2_CONF=/tmp/softhsm2.conf

use super::HsmBackend;
use crate::error::{B4aeError, B4aeResult};
use cryptoki::context::{CInitializeArgs, CInitializeFlags};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use std::path::Path;
use std::sync::{Arc, RwLock};

/// PKCS#11 HSM backend
#[cfg(feature = "hsm-pkcs11")]
pub struct Pkcs11Hsm {
    pkcs11: Arc<RwLock<Option<cryptoki::context::Pkcs11>>>,
    slot_id: cryptoki::slot::Slot,
    pin: Option<AuthPin>,
}

#[cfg(feature = "hsm-pkcs11")]
impl Pkcs11Hsm {
    /// Buat HSM backend dari path ke library PKCS#11.
    /// `slot_id`: slot index (biasanya 0 untuk SoftHSM).
    /// `pin`: user PIN untuk login (None = tidak login, untuk token yang tidak perlu auth).
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
        })
    }

    fn with_session<T, F>(&self, f: F) -> B4aeResult<T>
    where
        F: FnOnce(&cryptoki::session::Session) -> B4aeResult<T>,
    {
        let guard = self.pkcs11.read().map_err(|e| {
            B4aeError::ProtocolError(format!("Lock error: {}", e))
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
        let result = f(&session);
        let _ = session.logout();
        result
    }
}

#[cfg(feature = "hsm-pkcs11")]
impl HsmBackend for Pkcs11Hsm {
    fn generate_keypair(&self, key_id: &str) -> B4aeResult<Vec<u8>> {
        self.with_session(|session| {
            // EC P-256 keypair for signing
            let pub_template = vec![
                Attribute::Token(true),
                Attribute::Private(false),
                Attribute::Label(key_id.as_bytes().to_vec()),
            ];
            let priv_template = vec![
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Label(key_id.as_bytes().to_vec()),
            ];
            let (pub_handle, _priv_handle) = session
                .generate_key_pair(
                    &Mechanism::EccKeyPairGen,
                    &pub_template,
                    &priv_template,
                )
                .map_err(|e| B4aeError::ProtocolError(format!("Generate keypair: {}", e)))?;
            let attrs = session
                .get_attributes(pub_handle, &[cryptoki::object::AttributeType::EcPoint])
                .map_err(|e| B4aeError::ProtocolError(format!("Get EC point: {}", e)))?;
            for attr in attrs {
                if let Attribute::EcPoint(v) = attr {
                    return Ok(v);
                }
            }
            Err(B4aeError::ProtocolError(
                "Could not get public key bytes".to_string(),
            ))
        })
    }

    fn sign(&self, key_id: &str, data: &[u8]) -> B4aeResult<Vec<u8>> {
        self.with_session(|session| {
            let template = vec![
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Label(key_id.as_bytes().to_vec()),
            ];
            let handles = session
                .find_objects(&template)
                .map_err(|e| B4aeError::ProtocolError(format!("Find key: {}", e)))?;
            let key_handle = handles.into_iter().next().ok_or_else(|| {
                B4aeError::ProtocolError(format!("Key not found: {}", key_id))
            })?;
            session
                .sign(&Mechanism::EcdsaSha256, key_handle, data)
                .map_err(|e| B4aeError::ProtocolError(format!("Sign: {}", e)))
        })
    }

    fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> B4aeResult<bool> {
        self.with_session(|session| {
            let template = vec![
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::Label(key_id.as_bytes().to_vec()),
            ];
            let handles = session
                .find_objects(&template)
                .map_err(|e| B4aeError::ProtocolError(format!("Find key: {}", e)))?;
            let key_handle = handles.into_iter().next().ok_or_else(|| {
                B4aeError::ProtocolError(format!("Key not found: {}", key_id))
            })?;
            match session.verify(&Mechanism::EcdsaSha256, key_handle, data, signature) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        })
    }

    fn is_available(&self) -> bool {
        self.pkcs11
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some()
    }
}
