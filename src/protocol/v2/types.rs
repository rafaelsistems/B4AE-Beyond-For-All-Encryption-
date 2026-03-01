//! Core data structures for B4AE v2.0 protocol
//!
//! This module defines the fundamental types used throughout the v2.0 protocol,
//! including authentication modes, session identifiers, and message structures.
//!
//! ## Authentication Modes
//!
//! B4AE v2.0 separates authentication into distinct modes with clear security properties:
//!
//! - **Mode A (Deniable)**: XEdDSA-only signatures providing deniable authentication
//! - **Mode B (Post-Quantum)**: Dilithium5-only signatures providing non-repudiable
//!   post-quantum authentication
//! - **Mode C (Future)**: Research placeholder for post-quantum deniable authentication
//!
//! ## Session Binding
//!
//! All session keys are cryptographically bound to:
//! - Session ID (derived from randoms and mode)
//! - Protocol ID (SHA3-256 of canonical specification)
//! - Transcript hash (all handshake messages)
//!
//! This prevents key transplant attacks and ensures session isolation.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Authentication mode for B4AE v2.0 protocol
///
/// Each mode provides distinct security properties and uses different
/// cryptographic primitives. Modes are mutually exclusive - a session
/// uses exactly one mode.
///
/// ## Security Properties
///
/// | Mode | Deniable | Post-Quantum | Non-Repudiable | Performance |
/// |------|----------|--------------|----------------|-------------|
/// | A    | ✅       | ❌           | ❌             | Fast (~0.3ms) |
/// | B    | ❌       | ✅           | ✅             | Slower (~9ms) |
/// | C    | ✅       | ✅           | ❌             | Research only |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthenticationMode {
    /// Mode A: Deniable authentication using XEdDSA only
    ///
    /// **Use Case**: Private messaging, whistleblowing, anonymous communication
    ///
    /// **Security Properties**:
    /// - ✅ Deniable authentication (verifier can forge signatures)
    /// - ✅ Mutual authentication
    /// - ✅ Forward secrecy
    /// - ❌ Not post-quantum secure (classical 128-bit security)
    /// - ❌ Not non-repudiable
    ///
    /// **Performance**: ~0.3ms signature verification per handshake
    ModeA,

    /// Mode B: Post-quantum non-repudiable authentication using Dilithium5 only
    ///
    /// **Use Case**: Legal contracts, audit trails, compliance, non-repudiation
    ///
    /// **Security Properties**:
    /// - ✅ Post-quantum secure (NIST Level 5)
    /// - ✅ Non-repudiable signatures
    /// - ✅ Mutual authentication
    /// - ✅ Forward secrecy
    /// - ❌ Not deniable (signatures prove authorship)
    ///
    /// **Performance**: ~9ms signature verification per handshake
    ModeB,

    /// Mode C: Future hybrid mode (research placeholder)
    ///
    /// **Use Case**: Future research direction for deniable + post-quantum
    ///
    /// **Security Properties**:
    /// - ✅ Deniable authentication
    /// - ✅ Post-quantum secure
    /// - ⚠️ Research-stage (not production-ready)
    ///
    /// **Status**: Placeholder for future research, not implemented in v2.0
    ModeC,
}

impl AuthenticationMode {
    /// Returns the mode identifier byte for protocol encoding
    pub fn mode_id(&self) -> u8 {
        match self {
            AuthenticationMode::ModeA => 0x01,
            AuthenticationMode::ModeB => 0x02,
            AuthenticationMode::ModeC => 0x03,
        }
    }

    /// Creates an authentication mode from a mode identifier byte
    pub fn from_mode_id(id: u8) -> Option<Self> {
        match id {
            0x01 => Some(AuthenticationMode::ModeA),
            0x02 => Some(AuthenticationMode::ModeB),
            0x03 => Some(AuthenticationMode::ModeC),
            _ => None,
        }
    }

    /// Returns true if this mode provides deniable authentication
    pub fn is_deniable(&self) -> bool {
        matches!(self, AuthenticationMode::ModeA | AuthenticationMode::ModeC)
    }

    /// Returns true if this mode provides post-quantum security
    pub fn is_post_quantum(&self) -> bool {
        matches!(self, AuthenticationMode::ModeB | AuthenticationMode::ModeC)
    }

    /// Returns true if this mode provides non-repudiable signatures
    pub fn is_non_repudiable(&self) -> bool {
        matches!(self, AuthenticationMode::ModeB)
    }

    /// Returns true if this mode is production-ready
    ///
    /// Mode C is a research placeholder and not suitable for production use.
    pub fn is_production_ready(&self) -> bool {
        matches!(self, AuthenticationMode::ModeA | AuthenticationMode::ModeB)
    }

    /// Validates that this mode is compatible with the given security requirements
    ///
    /// Returns an error if the mode does not meet the specified requirements.
    pub fn validate_requirements(
        &self,
        require_deniable: bool,
        require_post_quantum: bool,
        require_non_repudiable: bool,
    ) -> Result<(), ModeValidationError> {
        if require_deniable && !self.is_deniable() {
            return Err(ModeValidationError::DeniabilityRequired);
        }

        if require_post_quantum && !self.is_post_quantum() {
            return Err(ModeValidationError::PostQuantumRequired);
        }

        if require_non_repudiable && !self.is_non_repudiable() {
            return Err(ModeValidationError::NonRepudiationRequired);
        }

        Ok(())
    }

    /// Checks if this mode is compatible with another mode for negotiation
    ///
    /// Two modes are compatible if they are the same mode. This is used
    /// during mode negotiation to find the intersection of supported modes.
    pub fn is_compatible_with(&self, other: &AuthenticationMode) -> bool {
        self == other
    }

    /// Returns the cryptographic signature scheme used by this mode
    pub fn signature_scheme(&self) -> SignatureScheme {
        match self {
            AuthenticationMode::ModeA => SignatureScheme::XEdDSA,
            AuthenticationMode::ModeB => SignatureScheme::Dilithium5,
            AuthenticationMode::ModeC => SignatureScheme::Future,
        }
    }

    /// Returns the expected handshake latency for this mode in milliseconds
    ///
    /// This is an approximate value based on signature verification times.
    pub fn expected_handshake_latency_ms(&self) -> f64 {
        match self {
            AuthenticationMode::ModeA => 0.3,  // ~0.3ms for XEdDSA
            AuthenticationMode::ModeB => 9.0,  // ~9ms for Dilithium5
            AuthenticationMode::ModeC => 0.0,  // Unknown (research)
        }
    }

    /// Returns a human-readable description of this mode's security properties
    pub fn security_properties_description(&self) -> &'static str {
        match self {
            AuthenticationMode::ModeA => {
                "Deniable authentication with XEdDSA. Fast performance (~0.3ms). \
                 Classical 128-bit security. Not post-quantum secure."
            }
            AuthenticationMode::ModeB => {
                "Non-repudiable post-quantum authentication with Dilithium5. \
                 Slower performance (~9ms). NIST Level 5 security. Not deniable."
            }
            AuthenticationMode::ModeC => {
                "Future hybrid mode (research placeholder). \
                 Deniable + post-quantum. Not production-ready."
            }
        }
    }

    /// Selects the highest security mode from a list of compatible modes
    ///
    /// Priority order: Mode B > Mode A > Mode C
    ///
    /// Returns None if the list is empty.
    pub fn select_highest_security(modes: &[AuthenticationMode]) -> Option<AuthenticationMode> {
        if modes.is_empty() {
            return None;
        }

        // Priority: Mode B (PQ) > Mode A (Deniable) > Mode C (Research)
        if modes.contains(&AuthenticationMode::ModeB) {
            Some(AuthenticationMode::ModeB)
        } else if modes.contains(&AuthenticationMode::ModeA) {
            Some(AuthenticationMode::ModeA)
        } else if modes.contains(&AuthenticationMode::ModeC) {
            Some(AuthenticationMode::ModeC)
        } else {
            None
        }
    }

    /// Computes the intersection of two mode lists
    ///
    /// Returns a vector of modes that appear in both lists.
    pub fn compute_intersection(
        client_modes: &[AuthenticationMode],
        server_modes: &[AuthenticationMode],
    ) -> Vec<AuthenticationMode> {
        client_modes
            .iter()
            .filter(|mode| server_modes.contains(mode))
            .copied()
            .collect()
    }
}

/// Error type for mode validation failures
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModeValidationError {
    /// Deniability is required but the mode does not provide it
    DeniabilityRequired,
    
    /// Post-quantum security is required but the mode does not provide it
    PostQuantumRequired,
    
    /// Non-repudiation is required but the mode does not provide it
    NonRepudiationRequired,
    
    /// The mode is not production-ready
    NotProductionReady,
}

impl std::fmt::Display for ModeValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModeValidationError::DeniabilityRequired => {
                write!(f, "Deniable authentication is required but mode does not provide it")
            }
            ModeValidationError::PostQuantumRequired => {
                write!(f, "Post-quantum security is required but mode does not provide it")
            }
            ModeValidationError::NonRepudiationRequired => {
                write!(f, "Non-repudiation is required but mode does not provide it")
            }
            ModeValidationError::NotProductionReady => {
                write!(f, "Mode is not production-ready (research placeholder)")
            }
        }
    }
}

impl std::error::Error for ModeValidationError {}

/// Cryptographic signature scheme used by an authentication mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    /// XEdDSA signature scheme (deniable)
    XEdDSA,
    
    /// Dilithium5 signature scheme (post-quantum, non-repudiable)
    Dilithium5,
    
    /// Future signature scheme (research placeholder)
    Future,
}

/// Session identifier uniquely identifying a protocol session
///
/// The session ID is derived using HKDF-SHA512 from:
/// - Client random (32 bytes)
/// - Server random (32 bytes)
/// - Mode ID (1 byte)
///
/// Session IDs are cryptographically bound to all derived keys to prevent
/// key transplant attacks and ensure session isolation.
///
/// ## Security Properties
///
/// - Unique per session with overwhelming probability
/// - Cryptographically independent across sessions
/// - Bound to authentication mode (prevents mode confusion)
/// - Used in all key derivations for session isolation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SessionId([u8; 32]);

impl SessionId {
    /// Creates a new session ID from raw bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        SessionId(bytes)
    }

    /// Returns the session ID as a byte slice
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Converts the session ID to a byte array
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Protocol identifier derived from canonical specification hash
///
/// The protocol ID is computed as SHA3-256 of the canonical protocol
/// specification document. This provides:
///
/// - Automatic version enforcement (different specs = different IDs)
/// - Downgrade attack detection (ID mismatch causes signature failure)
/// - Domain separation in key derivations
/// - Cryptographic agility without explicit version negotiation
///
/// ## Security Properties
///
/// - Changes automatically when protocol specification changes
/// - Included in all handshake transcripts
/// - Used in all key derivations for domain separation
/// - Prevents cross-version attacks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtocolId([u8; 32]);

impl ProtocolId {
    /// Creates a new protocol ID from raw bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        ProtocolId(bytes)
    }

    /// Returns the protocol ID as a byte slice
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Converts the protocol ID to a byte array
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8]> for ProtocolId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Mode negotiation message sent by client
///
/// Contains the client's supported authentication modes and preferred mode.
/// The server will select a compatible mode from the intersection of
/// supported modes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeNegotiation {
    /// Set of authentication modes supported by the client
    pub supported_modes: Vec<AuthenticationMode>,
    
    /// Client's preferred authentication mode
    pub preferred_mode: AuthenticationMode,
    
    /// Client random value (32 bytes) for mode binding
    pub client_random: [u8; 32],
}

/// Mode selection message sent by server
///
/// Contains the server's selected authentication mode from the intersection
/// of client and server supported modes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeSelection {
    /// Authentication mode selected by the server
    pub selected_mode: AuthenticationMode,
    
    /// Server random value (32 bytes) for mode binding
    pub server_random: [u8; 32],
}

/// Mode binding value cryptographically binding mode selection to transcript
///
/// Computed as: SHA3-256("B4AE-v2-mode-binding" || client_random || server_random || mode_id)
///
/// This value is included in all subsequent handshake messages and verified
/// in all signatures to prevent mode downgrade attacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ModeBinding([u8; 32]);

impl ModeBinding {
    /// Creates a new mode binding from raw bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        ModeBinding(bytes)
    }

    /// Returns the mode binding as a byte slice
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Converts the mode binding to a byte array
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8]> for ModeBinding {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Cookie challenge for stateless DoS protection
///
/// The server generates a stateless HMAC-based cookie that the client must
/// return before the server performs expensive cryptographic operations.
///
/// ## Security Properties
///
/// - Stateless (server stores no state)
/// - Replay protected (timestamp + Bloom filter)
/// - Forgery resistant (HMAC with server secret)
/// - Fast verification (~0.01ms)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieChallenge {
    /// HMAC-SHA256 cookie value
    pub cookie: [u8; 32],
    
    /// Server random value (32 bytes)
    pub server_random: [u8; 32],
}

/// Client hello message (minimal, no expensive crypto)
///
/// Sent by client to initiate handshake. Contains only minimal data
/// to allow server to generate cookie challenge without performing
/// expensive operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    /// Client random value (32 bytes)
    pub client_random: [u8; 32],
    
    /// Timestamp for replay protection
    pub timestamp: u64,
}

/// Client hello with cookie (after cookie challenge)
///
/// Sent by client after receiving cookie challenge. Contains the
/// cookie and the actual handshake initialization data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHelloWithCookie {
    /// Original client random value
    pub client_random: [u8; 32],
    
    /// Cookie received from server
    pub cookie: [u8; 32],
    
    /// Timestamp from original ClientHello
    pub timestamp: u64,
}

/// Handshake initialization message
///
/// Sent by client after cookie challenge verification. Contains ephemeral
/// keys for key exchange and a signature that depends on the selected mode.
///
/// ## Mode-Specific Signatures
///
/// - **Mode A**: Contains XEdDSA signature (deniable)
/// - **Mode B**: Contains Dilithium5 signature (post-quantum, non-repudiable)
///
/// The signature covers the entire handshake transcript including mode_binding
/// to prevent downgrade attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeInit {
    /// Ephemeral X25519 public key for classical key exchange
    pub ephemeral_x25519: [u8; 32],
    
    /// Ephemeral Kyber1024 public key for post-quantum key exchange
    pub ephemeral_kyber: Vec<u8>,
    
    /// Mode-specific signature over transcript
    ///
    /// - Mode A: XEdDSA signature (64 bytes)
    /// - Mode B: Dilithium5 signature (~4595 bytes)
    pub signature: Vec<u8>,
    
    /// Timestamp for replay protection
    pub timestamp: u64,
    
    /// Mode binding value to prevent downgrade attacks
    pub mode_binding: ModeBinding,
}

impl HandshakeInit {
    /// Validates the handshake init message structure
    ///
    /// Checks that:
    /// - Signature is non-empty
    /// - Ephemeral keys are valid sizes
    /// - Timestamp is reasonable
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.signature.is_empty() {
            return Err(ValidationError::EmptySignature);
        }
        
        if self.ephemeral_kyber.is_empty() {
            return Err(ValidationError::InvalidKyberKey);
        }
        
        // Timestamp should not be too far in the future (allow 5 minute clock skew)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if self.timestamp > now + 300 {
            return Err(ValidationError::FutureTimestamp);
        }
        
        Ok(())
    }
}

/// Handshake response message
///
/// Sent by server in response to HandshakeInit. Contains server's ephemeral
/// keys and a signature over the transcript.
///
/// ## Mode-Specific Signatures
///
/// - **Mode A**: Contains XEdDSA signature (deniable)
/// - **Mode B**: Contains Dilithium5 signature (post-quantum, non-repudiable)
///
/// The signature covers the entire handshake transcript including both
/// client and server messages to provide mutual authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Ephemeral X25519 public key for classical key exchange
    pub ephemeral_x25519: [u8; 32],
    
    /// Ephemeral Kyber1024 ciphertext for post-quantum key exchange
    pub ephemeral_kyber: Vec<u8>,
    
    /// Mode-specific signature over transcript
    ///
    /// - Mode A: XEdDSA signature (64 bytes)
    /// - Mode B: Dilithium5 signature (~4595 bytes)
    pub signature: Vec<u8>,
    
    /// Timestamp for replay protection
    pub timestamp: u64,
    
    /// Mode binding value to prevent downgrade attacks
    pub mode_binding: ModeBinding,
}

impl HandshakeResponse {
    /// Validates the handshake response message structure
    ///
    /// Checks that:
    /// - Signature is non-empty
    /// - Ephemeral keys are valid sizes
    /// - Timestamp is reasonable
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.signature.is_empty() {
            return Err(ValidationError::EmptySignature);
        }
        
        if self.ephemeral_kyber.is_empty() {
            return Err(ValidationError::InvalidKyberKey);
        }
        
        // Timestamp should not be too far in the future (allow 5 minute clock skew)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if self.timestamp > now + 300 {
            return Err(ValidationError::FutureTimestamp);
        }
        
        Ok(())
    }
}

/// Handshake complete message
///
/// Sent by client to finalize the handshake. Contains a final signature
/// over the complete transcript to confirm mutual authentication.
///
/// ## Mode-Specific Signatures
///
/// - **Mode A**: Contains XEdDSA signature (deniable)
/// - **Mode B**: Contains Dilithium5 signature (post-quantum, non-repudiable)
///
/// After this message is verified, both parties can derive session keys
/// and begin encrypted communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeComplete {
    /// Mode-specific signature over complete transcript
    ///
    /// - Mode A: XEdDSA signature (64 bytes)
    /// - Mode B: Dilithium5 signature (~4595 bytes)
    pub signature: Vec<u8>,
    
    /// Timestamp for replay protection
    pub timestamp: u64,
    
    /// Mode binding value to prevent downgrade attacks
    pub mode_binding: ModeBinding,
}

impl HandshakeComplete {
    /// Validates the handshake complete message structure
    ///
    /// Checks that:
    /// - Signature is non-empty
    /// - Timestamp is reasonable
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.signature.is_empty() {
            return Err(ValidationError::EmptySignature);
        }
        
        // Timestamp should not be too far in the future (allow 5 minute clock skew)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if self.timestamp > now + 300 {
            return Err(ValidationError::FutureTimestamp);
        }
        
        Ok(())
    }
}

/// Validation error for message structures
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Signature field is empty
    EmptySignature,
    
    /// Kyber key is invalid or empty
    InvalidKyberKey,
    
    /// Timestamp is too far in the future
    FutureTimestamp,
    
    /// Timestamp is expired
    ExpiredTimestamp,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::EmptySignature => {
                write!(f, "Signature field cannot be empty")
            }
            ValidationError::InvalidKyberKey => {
                write!(f, "Kyber key is invalid or empty")
            }
            ValidationError::FutureTimestamp => {
                write!(f, "Timestamp is too far in the future (possible clock skew)")
            }
            ValidationError::ExpiredTimestamp => {
                write!(f, "Timestamp is expired")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authentication_mode_properties() {
        // Mode A: Deniable, not PQ, not non-repudiable
        assert!(AuthenticationMode::ModeA.is_deniable());
        assert!(!AuthenticationMode::ModeA.is_post_quantum());
        assert!(!AuthenticationMode::ModeA.is_non_repudiable());

        // Mode B: Not deniable, PQ, non-repudiable
        assert!(!AuthenticationMode::ModeB.is_deniable());
        assert!(AuthenticationMode::ModeB.is_post_quantum());
        assert!(AuthenticationMode::ModeB.is_non_repudiable());

        // Mode C: Deniable, PQ, not non-repudiable
        assert!(AuthenticationMode::ModeC.is_deniable());
        assert!(AuthenticationMode::ModeC.is_post_quantum());
        assert!(!AuthenticationMode::ModeC.is_non_repudiable());
    }

    #[test]
    fn test_mode_id_roundtrip() {
        for mode in [AuthenticationMode::ModeA, AuthenticationMode::ModeB, AuthenticationMode::ModeC] {
            let id = mode.mode_id();
            let recovered = AuthenticationMode::from_mode_id(id).unwrap();
            assert_eq!(mode, recovered);
        }
    }

    #[test]
    fn test_production_ready() {
        assert!(AuthenticationMode::ModeA.is_production_ready());
        assert!(AuthenticationMode::ModeB.is_production_ready());
        assert!(!AuthenticationMode::ModeC.is_production_ready());
    }

    #[test]
    fn test_validate_requirements() {
        // Mode A should pass deniability requirement
        assert!(AuthenticationMode::ModeA
            .validate_requirements(true, false, false)
            .is_ok());

        // Mode A should fail post-quantum requirement
        assert_eq!(
            AuthenticationMode::ModeA.validate_requirements(false, true, false),
            Err(ModeValidationError::PostQuantumRequired)
        );

        // Mode B should pass post-quantum and non-repudiation requirements
        assert!(AuthenticationMode::ModeB
            .validate_requirements(false, true, true)
            .is_ok());

        // Mode B should fail deniability requirement
        assert_eq!(
            AuthenticationMode::ModeB.validate_requirements(true, false, false),
            Err(ModeValidationError::DeniabilityRequired)
        );

        // Mode C should pass deniability and post-quantum requirements
        assert!(AuthenticationMode::ModeC
            .validate_requirements(true, true, false)
            .is_ok());
    }

    #[test]
    fn test_mode_compatibility() {
        // Same modes are compatible
        assert!(AuthenticationMode::ModeA.is_compatible_with(&AuthenticationMode::ModeA));
        assert!(AuthenticationMode::ModeB.is_compatible_with(&AuthenticationMode::ModeB));
        assert!(AuthenticationMode::ModeC.is_compatible_with(&AuthenticationMode::ModeC));

        // Different modes are not compatible
        assert!(!AuthenticationMode::ModeA.is_compatible_with(&AuthenticationMode::ModeB));
        assert!(!AuthenticationMode::ModeB.is_compatible_with(&AuthenticationMode::ModeC));
        assert!(!AuthenticationMode::ModeA.is_compatible_with(&AuthenticationMode::ModeC));
    }

    #[test]
    fn test_signature_scheme() {
        assert_eq!(
            AuthenticationMode::ModeA.signature_scheme(),
            SignatureScheme::XEdDSA
        );
        assert_eq!(
            AuthenticationMode::ModeB.signature_scheme(),
            SignatureScheme::Dilithium5
        );
        assert_eq!(
            AuthenticationMode::ModeC.signature_scheme(),
            SignatureScheme::Future
        );
    }

    #[test]
    fn test_expected_handshake_latency() {
        // Mode A should be fast
        assert!(AuthenticationMode::ModeA.expected_handshake_latency_ms() < 1.0);

        // Mode B should be slower
        assert!(AuthenticationMode::ModeB.expected_handshake_latency_ms() > 5.0);

        // Mode C is unknown
        assert_eq!(AuthenticationMode::ModeC.expected_handshake_latency_ms(), 0.0);
    }

    #[test]
    fn test_select_highest_security() {
        // Empty list returns None
        assert_eq!(AuthenticationMode::select_highest_security(&[]), None);

        // Mode B has highest priority
        let modes = vec![
            AuthenticationMode::ModeA,
            AuthenticationMode::ModeB,
            AuthenticationMode::ModeC,
        ];
        assert_eq!(
            AuthenticationMode::select_highest_security(&modes),
            Some(AuthenticationMode::ModeB)
        );

        // Mode A is preferred over Mode C
        let modes = vec![AuthenticationMode::ModeA, AuthenticationMode::ModeC];
        assert_eq!(
            AuthenticationMode::select_highest_security(&modes),
            Some(AuthenticationMode::ModeA)
        );

        // Single mode
        let modes = vec![AuthenticationMode::ModeC];
        assert_eq!(
            AuthenticationMode::select_highest_security(&modes),
            Some(AuthenticationMode::ModeC)
        );
    }

    #[test]
    fn test_compute_intersection() {
        // Full intersection
        let client = vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB];
        let server = vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB];
        let intersection = AuthenticationMode::compute_intersection(&client, &server);
        assert_eq!(intersection.len(), 2);
        assert!(intersection.contains(&AuthenticationMode::ModeA));
        assert!(intersection.contains(&AuthenticationMode::ModeB));

        // Partial intersection
        let client = vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB];
        let server = vec![AuthenticationMode::ModeB, AuthenticationMode::ModeC];
        let intersection = AuthenticationMode::compute_intersection(&client, &server);
        assert_eq!(intersection.len(), 1);
        assert!(intersection.contains(&AuthenticationMode::ModeB));

        // No intersection
        let client = vec![AuthenticationMode::ModeA];
        let server = vec![AuthenticationMode::ModeB];
        let intersection = AuthenticationMode::compute_intersection(&client, &server);
        assert!(intersection.is_empty());

        // Empty client list
        let client = vec![];
        let server = vec![AuthenticationMode::ModeA];
        let intersection = AuthenticationMode::compute_intersection(&client, &server);
        assert!(intersection.is_empty());
    }

    #[test]
    fn test_security_properties_description() {
        // All modes should have non-empty descriptions
        assert!(!AuthenticationMode::ModeA.security_properties_description().is_empty());
        assert!(!AuthenticationMode::ModeB.security_properties_description().is_empty());
        assert!(!AuthenticationMode::ModeC.security_properties_description().is_empty());

        // Mode A description should mention deniability
        assert!(AuthenticationMode::ModeA
            .security_properties_description()
            .contains("Deniable"));

        // Mode B description should mention post-quantum
        assert!(AuthenticationMode::ModeB
            .security_properties_description()
            .contains("post-quantum"));
    }

    #[test]
    fn test_mode_validation_error_display() {
        let err = ModeValidationError::DeniabilityRequired;
        assert!(err.to_string().contains("Deniable"));

        let err = ModeValidationError::PostQuantumRequired;
        assert!(err.to_string().contains("Post-quantum"));

        let err = ModeValidationError::NonRepudiationRequired;
        assert!(err.to_string().contains("Non-repudiation"));

        let err = ModeValidationError::NotProductionReady;
        assert!(err.to_string().contains("production-ready"));
    }

    #[test]
    fn test_session_id_creation() {
        let bytes = [42u8; 32];
        let session_id = SessionId::new(bytes);
        assert_eq!(session_id.as_bytes(), &bytes);
        assert_eq!(session_id.to_bytes(), bytes);
    }

    #[test]
    fn test_protocol_id_creation() {
        let bytes = [99u8; 32];
        let protocol_id = ProtocolId::new(bytes);
        assert_eq!(protocol_id.as_bytes(), &bytes);
        assert_eq!(protocol_id.to_bytes(), bytes);
    }

    #[test]
    fn test_mode_negotiation_serialization() {
        let msg = ModeNegotiation {
            supported_modes: vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB],
            preferred_mode: AuthenticationMode::ModeB,
            client_random: [1u8; 32],
        };

        // Test serialization roundtrip
        let serialized = bincode::serialize(&msg).unwrap();
        let deserialized: ModeNegotiation = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.supported_modes.len(), 2);
        assert_eq!(deserialized.preferred_mode, AuthenticationMode::ModeB);
        assert_eq!(deserialized.client_random, [1u8; 32]);
    }

    #[test]
    fn test_mode_selection_serialization() {
        let msg = ModeSelection {
            selected_mode: AuthenticationMode::ModeA,
            server_random: [2u8; 32],
        };

        // Test serialization roundtrip
        let serialized = bincode::serialize(&msg).unwrap();
        let deserialized: ModeSelection = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.selected_mode, AuthenticationMode::ModeA);
        assert_eq!(deserialized.server_random, [2u8; 32]);
    }

    #[test]
    fn test_client_hello_serialization() {
        let msg = ClientHello {
            client_random: [3u8; 32],
            timestamp: 1234567890,
        };

        // Test serialization roundtrip
        let serialized = bincode::serialize(&msg).unwrap();
        let deserialized: ClientHello = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.client_random, [3u8; 32]);
        assert_eq!(deserialized.timestamp, 1234567890);
    }

    #[test]
    fn test_cookie_challenge_serialization() {
        let msg = CookieChallenge {
            cookie: [4u8; 32],
            server_random: [5u8; 32],
        };

        // Test serialization roundtrip
        let serialized = bincode::serialize(&msg).unwrap();
        let deserialized: CookieChallenge = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.cookie, [4u8; 32]);
        assert_eq!(deserialized.server_random, [5u8; 32]);
    }

    #[test]
    fn test_client_hello_with_cookie_serialization() {
        let msg = ClientHelloWithCookie {
            client_random: [6u8; 32],
            cookie: [7u8; 32],
            timestamp: 9876543210,
        };

        // Test serialization roundtrip
        let serialized = bincode::serialize(&msg).unwrap();
        let deserialized: ClientHelloWithCookie = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.client_random, [6u8; 32]);
        assert_eq!(deserialized.cookie, [7u8; 32]);
        assert_eq!(deserialized.timestamp, 9876543210);
    }

    #[test]
    fn test_handshake_init_validation() {
        let mode_binding = ModeBinding::new([8u8; 32]);
        
        // Valid handshake init
        let valid_msg = HandshakeInit {
            ephemeral_x25519: [9u8; 32],
            ephemeral_kyber: vec![10u8; 1568], // Kyber1024 public key size
            signature: vec![11u8; 64], // XEdDSA signature size
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            mode_binding: mode_binding.clone(),
        };
        assert!(valid_msg.validate().is_ok());

        // Empty signature should fail
        let invalid_sig = HandshakeInit {
            ephemeral_x25519: [9u8; 32],
            ephemeral_kyber: vec![10u8; 1568],
            signature: vec![],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            mode_binding: mode_binding.clone(),
        };
        assert_eq!(invalid_sig.validate(), Err(ValidationError::EmptySignature));

        // Empty Kyber key should fail
        let invalid_kyber = HandshakeInit {
            ephemeral_x25519: [9u8; 32],
            ephemeral_kyber: vec![],
            signature: vec![11u8; 64],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            mode_binding: mode_binding.clone(),
        };
        assert_eq!(invalid_kyber.validate(), Err(ValidationError::InvalidKyberKey));

        // Future timestamp should fail
        let future_timestamp = HandshakeInit {
            ephemeral_x25519: [9u8; 32],
            ephemeral_kyber: vec![10u8; 1568],
            signature: vec![11u8; 64],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() + 1000, // 1000 seconds in future
            mode_binding,
        };
        assert_eq!(future_timestamp.validate(), Err(ValidationError::FutureTimestamp));
    }

    #[test]
    fn test_handshake_init_serialization() {
        let msg = HandshakeInit {
            ephemeral_x25519: [12u8; 32],
            ephemeral_kyber: vec![13u8; 1568],
            signature: vec![14u8; 64],
            timestamp: 1111111111,
            mode_binding: ModeBinding::new([15u8; 32]),
        };

        // Test serialization roundtrip
        let serialized = bincode::serialize(&msg).unwrap();
        let deserialized: HandshakeInit = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.ephemeral_x25519, [12u8; 32]);
        assert_eq!(deserialized.ephemeral_kyber, vec![13u8; 1568]);
        assert_eq!(deserialized.signature, vec![14u8; 64]);
        assert_eq!(deserialized.timestamp, 1111111111);
        assert_eq!(deserialized.mode_binding.as_bytes(), &[15u8; 32]);
    }

    #[test]
    fn test_handshake_response_validation() {
        let mode_binding = ModeBinding::new([16u8; 32]);
        
        // Valid handshake response
        let valid_msg = HandshakeResponse {
            ephemeral_x25519: [17u8; 32],
            ephemeral_kyber: vec![18u8; 1568], // Kyber1024 ciphertext size
            signature: vec![19u8; 4595], // Dilithium5 signature size
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            mode_binding: mode_binding.clone(),
        };
        assert!(valid_msg.validate().is_ok());

        // Empty signature should fail
        let invalid_sig = HandshakeResponse {
            ephemeral_x25519: [17u8; 32],
            ephemeral_kyber: vec![18u8; 1568],
            signature: vec![],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            mode_binding: mode_binding.clone(),
        };
        assert_eq!(invalid_sig.validate(), Err(ValidationError::EmptySignature));

        // Empty Kyber key should fail
        let invalid_kyber = HandshakeResponse {
            ephemeral_x25519: [17u8; 32],
            ephemeral_kyber: vec![],
            signature: vec![19u8; 4595],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            mode_binding: mode_binding.clone(),
        };
        assert_eq!(invalid_kyber.validate(), Err(ValidationError::InvalidKyberKey));

        // Future timestamp should fail
        let future_timestamp = HandshakeResponse {
            ephemeral_x25519: [17u8; 32],
            ephemeral_kyber: vec![18u8; 1568],
            signature: vec![19u8; 4595],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() + 1000,
            mode_binding,
        };
        assert_eq!(future_timestamp.validate(), Err(ValidationError::FutureTimestamp));
    }

    #[test]
    fn test_handshake_response_serialization() {
        let msg = HandshakeResponse {
            ephemeral_x25519: [20u8; 32],
            ephemeral_kyber: vec![21u8; 1568],
            signature: vec![22u8; 4595],
            timestamp: 2222222222,
            mode_binding: ModeBinding::new([23u8; 32]),
        };

        // Test serialization roundtrip
        let serialized = bincode::serialize(&msg).unwrap();
        let deserialized: HandshakeResponse = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.ephemeral_x25519, [20u8; 32]);
        assert_eq!(deserialized.ephemeral_kyber, vec![21u8; 1568]);
        assert_eq!(deserialized.signature, vec![22u8; 4595]);
        assert_eq!(deserialized.timestamp, 2222222222);
        assert_eq!(deserialized.mode_binding.as_bytes(), &[23u8; 32]);
    }

    #[test]
    fn test_handshake_complete_validation() {
        let mode_binding = ModeBinding::new([24u8; 32]);
        
        // Valid handshake complete
        let valid_msg = HandshakeComplete {
            signature: vec![25u8; 64],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            mode_binding: mode_binding.clone(),
        };
        assert!(valid_msg.validate().is_ok());

        // Empty signature should fail
        let invalid_sig = HandshakeComplete {
            signature: vec![],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            mode_binding: mode_binding.clone(),
        };
        assert_eq!(invalid_sig.validate(), Err(ValidationError::EmptySignature));

        // Future timestamp should fail
        let future_timestamp = HandshakeComplete {
            signature: vec![25u8; 64],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() + 1000,
            mode_binding,
        };
        assert_eq!(future_timestamp.validate(), Err(ValidationError::FutureTimestamp));
    }

    #[test]
    fn test_handshake_complete_serialization() {
        let msg = HandshakeComplete {
            signature: vec![26u8; 64],
            timestamp: 3333333333,
            mode_binding: ModeBinding::new([27u8; 32]),
        };

        // Test serialization roundtrip
        let serialized = bincode::serialize(&msg).unwrap();
        let deserialized: HandshakeComplete = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.signature, vec![26u8; 64]);
        assert_eq!(deserialized.timestamp, 3333333333);
        assert_eq!(deserialized.mode_binding.as_bytes(), &[27u8; 32]);
    }

    #[test]
    fn test_validation_error_display() {
        let err = ValidationError::EmptySignature;
        assert!(err.to_string().contains("Signature"));

        let err = ValidationError::InvalidKyberKey;
        assert!(err.to_string().contains("Kyber"));

        let err = ValidationError::FutureTimestamp;
        assert!(err.to_string().contains("future"));

        let err = ValidationError::ExpiredTimestamp;
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn test_mode_binding_creation() {
        let bytes = [28u8; 32];
        let mode_binding = ModeBinding::new(bytes);
        assert_eq!(mode_binding.as_bytes(), &bytes);
        assert_eq!(mode_binding.to_bytes(), bytes);
    }
}
