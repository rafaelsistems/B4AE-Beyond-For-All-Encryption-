// B4AE (Beyond For All Encryption) Protocol
// Quantum-resistant secure communication protocol

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![allow(unexpected_cfgs)] // liboqs feature untuk implementasi future

pub mod crypto;
pub mod protocol;
pub mod metadata;
pub mod error;
pub mod client;
pub mod prelude;

#[cfg(feature = "elara")]
pub mod transport;

#[cfg(feature = "elara")]
pub mod elara_node;

// Re-export commonly used types
pub use error::{B4aeError, B4aeResult};
pub use crypto::{CryptoConfig, SecurityLevel};
pub use client::{B4aeClient, B4aeConfig};
pub use protocol::SecurityProfile;

/// B4AE Protocol Version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_VERSION: u16 = 1;

/// B4AE Protocol Name
pub const PROTOCOL_NAME: &str = "B4AE";

/// B4AE Protocol Full Name
pub const PROTOCOL_FULL_NAME: &str = "Beyond For All Encryption";

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
