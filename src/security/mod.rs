//! Security-hardened modules for B4AE
//!
//! This module provides panic-free, security-hardened implementations
//! that follow the 14 strict security requirements.

pub mod hardened_core;
pub mod protocol;
pub mod crypto;
pub mod handshake;
pub mod network;
pub mod migration_guide;
pub mod fuzzing;
pub mod audit;

// Re-export commonly used security types
pub use hardened_core::{
    SecurityResult, SecurityError, SecurityBuffer, SecurityStateMachine,
    constant_time_eq_security, checked_add_security, checked_sub_security,
    checked_mul_security, checked_div_security
};
pub use protocol::{
    ProtocolVersion, MessageType, CipherSuite, SecurityMessageHeader,
    HandshakeState, SecurityHandshakeParser
};
pub use crypto::{
    SecurityKey, KeyType, SecurityHkdf, SecurityAesGcm, SecurityCompare, SecurityRandom
};
pub use handshake::{
    SecurityHybridParser, SecurityHybridCiphertext, SecurityHybridSignature,
    SecurityHandshakeMessageParser, SecurityHandshakeInit, SecurityHandshakeResponse,
    SecurityHandshakeComplete, SecurityHandshakeStateMachine
};
pub use network::{
    SecurityNetworkParser, SecurityNetworkMessage, SecurityHandshakeMessage,
    SecurityDataMessage, SecurityValidationSettings, SecurityStreamingValidator,
    MAX_MESSAGE_SIZE, MAX_HEADER_SIZE, MAX_EXTENSION_SIZE, MAX_HANDSHAKE_SIZE
};
pub use migration_guide::{
    migration_checklist
};
pub use fuzzing::{
    FuzzingConfig, MutationStrategy, CoverageTarget, SecurityFuzzingOrchestrator,
    FuzzingResults, FuzzingResult, ProtocolViolation, TimingLeak, InvalidTransition
};
pub use audit::{
    ReproducibleBuildConfig, DependencyAuditConfig, SecurityVulnerability,
    DependencyAuditResult, ReproducibilityReport, CompleteSecurityReport,
    ReproducibleBuildSystem, DependencyAuditSystem, SecurityAuditOrchestrator
};