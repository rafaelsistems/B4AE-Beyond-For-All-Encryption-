//! B4AE (Beyond For All Encryption) Protocol
//!
//! Implements [B4AE Protocol Specification v1.0](../specs/B4AE_Protocol_Specification_v1.0.md).
//! Quantum-resistant secure communication protocol.

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![allow(unexpected_cfgs)] // liboqs (PQC) feature — bukan elara; elara-transport sudah dari crates.io

/// Cryptographic primitives (Kyber, Dilithium, hybrid, AES-GCM, HKDF, PFS+, ZKAuth).
pub mod crypto;
/// Protocol layer (handshake, message, session).
pub mod protocol;
/// Metadata protection (padding, timing, obfuscation).
pub mod metadata;
/// Safe time utilities (panic-free).
pub mod time;
/// Error types for B4AE.
pub mod error;
/// High-level client API.
pub mod client;
/// Re-exports for common usage.
pub mod prelude;
/// Audit logging for compliance.
pub mod audit;
/// Key hierarchy (MIK, DMK, STK, BKS).
pub mod key_hierarchy;
/// Key persistence (passphrase-protected MIK storage).
pub mod key_store;
/// Encrypted storage using STK.
pub mod storage;
/// Performance monitoring and profiling.
pub mod performance;

#[cfg(feature = "hsm")]
pub mod hsm;

#[cfg(feature = "elara-transport")]
pub mod transport;

#[cfg(feature = "elara-transport")]
pub mod elara_node;

// Re-export commonly used types
pub use error::{B4aeError, B4aeResult};
pub use crypto::{CryptoConfig, SecurityLevel};
pub use client::{B4aeClient, B4aeConfig};
pub use protocol::SecurityProfile;

/// B4AE crate version (Cargo.toml)
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// B4AE wire protocol version (Protocol Specification v1.0).
/// Used in handshake and message headers. Value 1 = spec v1.0.
pub const PROTOCOL_VERSION: u16 = 1;

/// B4AE Protocol Name
pub const PROTOCOL_NAME: &str = "B4AE";

/// B4AE Protocol Full Name
pub const PROTOCOL_FULL_NAME: &str = "Beyond For All Encryption";

/// Maximum message size (plaintext or ciphertext) — DoS mitigation.
pub const MAX_MESSAGE_SIZE: usize = 1 << 20; // 1 MiB

/// Security-hardened core module with panic-free production paths
pub mod security;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn test_protocol_name() {
        assert_eq!(PROTOCOL_NAME, "B4AE");
        assert_eq!(PROTOCOL_FULL_NAME, "Beyond For All Encryption");
    }
}
