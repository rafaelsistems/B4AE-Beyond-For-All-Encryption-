//! B4AE Key Hierarchy (Protocol Spec v1.0 §4)
//!
//! Placeholder types for MIK/DMK/STK/BKS. Full implementation roadmap.
//!
//! ```text
//! Master Identity Key (MIK)           [Roadmap]
//! ├── Device Master Key (DMK)        [Roadmap]
//! │   ├── Session Key (SK)          [Implemented - from handshake]
//! │   │   ├── Message Key (MK)      [Implemented - PFS+ per-message]
//! │   │   └── Ephemeral Key (EK)    [Implemented]
//! │   └── Storage Key (STK)          [Roadmap]
//! └── Backup Key Shards (BKS)        [Roadmap]
//! ```

/// Master Identity Key — root of key hierarchy. Roadmap.
#[derive(Debug, Clone)]
pub struct MasterIdentityKey {
    /// Placeholder: key material (not yet derived)
    _placeholder: [u8; 32],
}

/// Device Master Key — per-device key from MIK. Roadmap.
#[derive(Debug, Clone)]
pub struct DeviceMasterKey {
    /// Placeholder: key material
    _placeholder: [u8; 32],
}

/// Storage Key — for encrypted storage. Roadmap.
#[derive(Debug, Clone)]
pub struct StorageKey {
    /// Placeholder: key material
    _placeholder: [u8; 32],
}

impl MasterIdentityKey {
    /// Create placeholder (roadmap).
    #[allow(dead_code)]
    pub fn placeholder() -> Self {
        Self {
            _placeholder: [0u8; 32],
        }
    }
}

impl DeviceMasterKey {
    /// Create placeholder (roadmap).
    #[allow(dead_code)]
    pub fn placeholder() -> Self {
        Self {
            _placeholder: [0u8; 32],
        }
    }
}

impl StorageKey {
    /// Create placeholder (roadmap).
    #[allow(dead_code)]
    pub fn placeholder() -> Self {
        Self {
            _placeholder: [0u8; 32],
        }
    }
}
