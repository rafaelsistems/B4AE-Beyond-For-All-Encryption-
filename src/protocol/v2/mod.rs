//! B4AE v2.0 Protocol - Research-Grade Architecture
//!
//! This module implements the B4AE v2.0 protocol, a complete redesign addressing
//! 8 critical architectural flaws from v1.0, transforming B4AE from "strong engineering"
//! to "research-grade protocol architecture" suitable for formal verification and
//! high-assurance deployments.
//!
//! ## Key Architectural Improvements
//!
//! 1. **Authentication Mode Separation**: Separate deniable (XEdDSA) and post-quantum
//!    (Dilithium5) modes instead of contradictory hybrid signatures
//! 2. **Stateless Anti-DoS Cookie Challenge**: Protect against DoS before expensive
//!    cryptographic operations
//! 3. **Global Unified Traffic Scheduler**: Cross-session metadata protection with
//!    constant-rate output
//! 4. **Formal Threat Model**: Single source of truth for security properties
//! 5. **Session Key Binding**: Cryptographically bind keys to session ID to prevent
//!    key transplant attacks
//! 6. **Security-by-Default**: No optional security features, all protections enabled
//! 7. **Cryptographic Agility**: Protocol ID derived from specification hash for
//!    automatic version enforcement
//! 8. **Formal Verification**: Machine-checked proofs using Tamarin and ProVerif
//!
//! ## Design Philosophy
//!
//! - **Model-driven** (not feature-driven)
//! - **Security-by-default** (not optional)
//! - **Formally verified** (not just tested)
//!
//! ## Requirements
//!
//! This implementation satisfies:
//! - REQ-34: Migration path from v1.0 to v2.0
//! - REQ-35: Comprehensive documentation for research-grade protocol
//!
//! ## Module Organization
//!
//! - [`types`]: Core data structures for v2.0 protocol
//! - [`constants`]: Protocol constants and configuration values
//!
//! ## Feature Flag
//!
//! Enable v2.0 protocol with the `v2_protocol` feature flag:
//!
//! ```toml
//! [dependencies]
//! b4ae = { version = "2.0", features = ["v2_protocol"] }
//! ```

pub mod types;
pub mod constants;
pub mod protocol_id;
pub mod state_machine;
pub mod mode_negotiation;
pub mod mode_binding;
pub mod cookie_challenge;
pub mod replay_protection;
pub mod dos_metrics;
pub mod traffic_scheduler;

// Re-export commonly used types
pub use types::*;
pub use constants::*;
pub use protocol_id::*;
pub use state_machine::*;
pub use mode_negotiation::*;
pub use mode_binding::*;
pub use cookie_challenge::*;
pub use replay_protection::*;
pub use dos_metrics::*;
pub use traffic_scheduler::*;
