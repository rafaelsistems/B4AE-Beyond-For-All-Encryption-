//! Hybrid Double Ratchet Protocol Implementation
//!
//! This module implements the Signal Protocol's Double Ratchet algorithm enhanced with
//! post-quantum cryptography (Kyber-1024) alongside classical X25519. The implementation
//! provides post-compromise security, self-healing properties, and quantum resistance.
//!
//! The Hybrid Double Ratchet combines three ratcheting mechanisms:
//! 1. **Symmetric Ratchet**: Per-message key derivation (PFS+)
//! 2. **DH Ratchet (Classical)**: X25519 ephemeral key exchanges for forward secrecy
//! 3. **PQC Ratchet**: Kyber-1024 ephemeral key exchanges for quantum resistance

pub mod root_key_manager;
pub mod chain_key_ratchet;
pub mod hybrid_dh_ratchet;
pub mod session;

pub use root_key_manager::RootKeyManager;
pub use chain_key_ratchet::{ChainKeyRatchet, MessageKey};
pub use hybrid_dh_ratchet::{HybridDHRatchet, HybridPublicKey};
pub use session::{
    DoubleRatchetSession, RatchetMessage, RatchetUpdate, RatchetState, DoubleRatchetConfig,
};

use crate::crypto::CryptoResult;

/// Maximum allowed message counter skip to prevent DoS attacks (1000 messages)
pub const MAX_SKIP: u64 = 1000;

/// Default ratchet interval (number of messages between DH ratchet steps)
pub const DEFAULT_RATCHET_INTERVAL: u64 = 100;

/// Default key cache size for out-of-order message delivery
pub const DEFAULT_CACHE_SIZE: usize = 100;
