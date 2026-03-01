//! Mode Binding for Downgrade Protection
//!
//! This module implements cryptographic binding of the selected authentication mode
//! to the handshake transcript to prevent mode downgrade attacks.
//!
//! ## Security Properties
//!
//! - Mode selection is cryptographically bound to transcript
//! - Any modification of mode causes signature verification to fail
//! - Prevents attacker from downgrading Mode B → Mode A
//! - Provides automatic downgrade detection without explicit checks
//!
//! ## Mode Binding Derivation
//!
//! ```text
//! mode_binding = SHA3-256("B4AE-v2-mode-binding" || client_random || server_random || mode_id)
//! ```
//!
//! ## Integration with Handshake
//!
//! 1. After mode negotiation, both parties derive mode_binding
//! 2. mode_binding is included in all handshake messages (HandshakeInit, HandshakeResponse, HandshakeComplete)
//! 3. mode_binding is included in the transcript used for signature generation
//! 4. Signature verification checks mode_binding consistency
//!
//! ## Requirements
//!
//! - REQ-2: Mode Negotiation Protocol
//! - REQ-38: Downgrade Protection

use sha3::{Digest, Sha3_256};
use crate::protocol::v2::types::{AuthenticationMode, ModeBinding};

/// Domain separation string for mode binding derivation
const MODE_BINDING_DOMAIN: &[u8] = b"B4AE-v2-mode-binding";

/// Derives the mode binding value from negotiation parameters
///
/// The mode binding cryptographically binds the selected authentication mode
/// to the handshake transcript, preventing downgrade attacks.
///
/// ## Algorithm
///
/// ```text
/// mode_binding = SHA3-256("B4AE-v2-mode-binding" || client_random || server_random || mode_id)
/// ```
///
/// ## Parameters
///
/// - `client_random`: 32-byte random value from client's ModeNegotiation
/// - `server_random`: 32-byte random value from server's ModeSelection
/// - `mode`: The selected authentication mode
///
/// ## Returns
///
/// A 32-byte mode binding value that must be included in all subsequent handshake messages.
///
/// ## Example
///
/// ```rust
/// use b4ae::protocol::v2::types::AuthenticationMode;
/// use b4ae::protocol::v2::mode_binding::derive_mode_binding;
///
/// let client_random = [1u8; 32];
/// let server_random = [2u8; 32];
/// let mode = AuthenticationMode::ModeB;
///
/// let binding = derive_mode_binding(&client_random, &server_random, mode);
/// assert_eq!(binding.as_bytes().len(), 32);
/// ```
///
/// ## Security Properties
///
/// - **Deterministic**: Same inputs always produce same output
/// - **Collision Resistant**: SHA3-256 provides 256-bit collision resistance
/// - **Domain Separated**: Unique domain string prevents cross-protocol attacks
/// - **Mode Bound**: Different modes produce different bindings
///
/// ## Requirements
///
/// - REQ-2.9: Derive mode_binding = SHA3-256("B4AE-v2-mode-binding" || client_random || server_random || mode_id)
/// - REQ-2.10: Include mode_binding in all subsequent handshake messages
/// - REQ-38: Downgrade Protection
pub fn derive_mode_binding(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    mode: AuthenticationMode,
) -> ModeBinding {
    let mut hasher = Sha3_256::new();
    
    // Domain separation
    hasher.update(MODE_BINDING_DOMAIN);
    
    // Client random
    hasher.update(client_random);
    
    // Server random
    hasher.update(server_random);
    
    // Mode identifier (as single byte)
    let mode_id = mode.mode_id();
    hasher.update(&[mode_id]);
    
    let result = hasher.finalize();
    let mut binding_bytes = [0u8; 32];
    binding_bytes.copy_from_slice(&result);
    
    ModeBinding::new(binding_bytes)
}

/// Verifies that a mode binding matches the expected value
///
/// This function recomputes the expected mode binding and compares it
/// with the provided binding using constant-time comparison.
///
/// ## Parameters
///
/// - `binding`: The mode binding to verify
/// - `client_random`: 32-byte random value from client's ModeNegotiation
/// - `server_random`: 32-byte random value from server's ModeSelection
/// - `mode`: The selected authentication mode
///
/// ## Returns
///
/// `true` if the binding is valid, `false` otherwise.
///
/// ## Example
///
/// ```rust
/// use b4ae::protocol::v2::types::AuthenticationMode;
/// use b4ae::protocol::v2::mode_binding::{derive_mode_binding, verify_mode_binding};
///
/// let client_random = [1u8; 32];
/// let server_random = [2u8; 32];
/// let mode = AuthenticationMode::ModeB;
///
/// let binding = derive_mode_binding(&client_random, &server_random, mode);
/// assert!(verify_mode_binding(&binding, &client_random, &server_random, mode));
/// ```
///
/// ## Security Properties
///
/// - **Constant-Time**: Uses constant-time comparison to prevent timing attacks
/// - **Downgrade Detection**: Detects any modification of mode selection
/// - **Replay Protection**: Binds to specific random values
///
/// ## Requirements
///
/// - REQ-2.11: Verify mode_binding is consistent across all messages
/// - REQ-2.12: Abort handshake if mode_binding verification fails
/// - REQ-19: Side-Channel Resistance (constant-time operations)
/// - REQ-38: Downgrade Protection
pub fn verify_mode_binding(
    binding: &ModeBinding,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    mode: AuthenticationMode,
) -> bool {
    let expected = derive_mode_binding(client_random, server_random, mode);
    
    // Constant-time comparison
    constant_time_eq(binding.as_bytes(), expected.as_bytes())
}

/// Constant-time equality comparison for 32-byte arrays
///
/// This function compares two 32-byte arrays in constant time to prevent
/// timing side-channel attacks.
///
/// ## Security Properties
///
/// - **Constant-Time**: Execution time independent of input values
/// - **Side-Channel Resistant**: No secret-dependent branching
///
/// ## Requirements
///
/// - REQ-19: Side-Channel Resistance
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Builds a transcript for signature generation/verification
///
/// The transcript includes all handshake parameters that must be authenticated,
/// including the mode_binding to prevent downgrade attacks.
///
/// ## Parameters
///
/// - `protocol_id`: The protocol identifier (SHA3-256 of specification)
/// - `mode_binding`: The mode binding value
/// - `ephemeral_x25519`: Ephemeral X25519 public key
/// - `ephemeral_kyber`: Ephemeral Kyber1024 public key
/// - `timestamp`: Message timestamp
///
/// ## Returns
///
/// A byte vector containing the complete transcript for signing/verification.
///
/// ## Transcript Format
///
/// ```text
/// transcript = protocol_id || mode_binding || ephemeral_x25519 || ephemeral_kyber || timestamp
/// ```
///
/// ## Requirements
///
/// - REQ-2.10: Include mode_binding in all subsequent handshake messages
/// - REQ-26: Transcript Binding
pub fn build_handshake_transcript(
    protocol_id: &[u8; 32],
    mode_binding: &ModeBinding,
    ephemeral_x25519: &[u8; 32],
    ephemeral_kyber: &[u8],
    timestamp: u64,
) -> Vec<u8> {
    let mut transcript = Vec::new();
    
    // Protocol ID for domain separation
    transcript.extend_from_slice(protocol_id);
    
    // Mode binding for downgrade protection
    transcript.extend_from_slice(mode_binding.as_bytes());
    
    // Ephemeral keys
    transcript.extend_from_slice(ephemeral_x25519);
    transcript.extend_from_slice(ephemeral_kyber);
    
    // Timestamp for replay protection
    transcript.extend_from_slice(&timestamp.to_be_bytes());
    
    transcript
}

/// Verifies mode binding consistency across handshake messages
///
/// This function checks that the mode_binding in a handshake message matches
/// the expected value derived from the negotiation parameters.
///
/// ## Parameters
///
/// - `message_binding`: The mode binding from the handshake message
/// - `client_random`: Client random from mode negotiation
/// - `server_random`: Server random from mode selection
/// - `expected_mode`: The mode that was negotiated
///
/// ## Returns
///
/// `Ok(())` if binding is consistent, `Err(DowngradeError)` otherwise.
///
/// ## Requirements
///
/// - REQ-2.11: Verify mode_binding is consistent across all messages
/// - REQ-2.12: Abort handshake if mode_binding verification fails
/// - REQ-38: Downgrade Protection
pub fn verify_handshake_mode_binding(
    message_binding: &ModeBinding,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    expected_mode: AuthenticationMode,
) -> Result<(), DowngradeError> {
    if !verify_mode_binding(message_binding, client_random, server_random, expected_mode) {
        return Err(DowngradeError::ModeBindingMismatch {
            expected_mode,
            message: "Mode binding verification failed - possible downgrade attack detected".to_string(),
        });
    }
    Ok(())
}

/// Error type for downgrade attack detection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DowngradeError {
    /// Mode binding mismatch detected
    ModeBindingMismatch {
        expected_mode: AuthenticationMode,
        message: String,
    },
    /// Mode changed between messages
    ModeChanged {
        original_mode: AuthenticationMode,
        new_mode: AuthenticationMode,
    },
}

impl std::fmt::Display for DowngradeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DowngradeError::ModeBindingMismatch { expected_mode, message } => {
                write!(f, "Mode binding mismatch for {:?}: {}", expected_mode, message)
            }
            DowngradeError::ModeChanged { original_mode, new_mode } => {
                write!(f, "Mode changed from {:?} to {:?} - downgrade attack detected", 
                       original_mode, new_mode)
            }
        }
    }
}

impl std::error::Error for DowngradeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_mode_binding_deterministic() {
        let client_random = [1u8; 32];
        let server_random = [2u8; 32];
        let mode = AuthenticationMode::ModeB;

        let binding1 = derive_mode_binding(&client_random, &server_random, mode);
        let binding2 = derive_mode_binding(&client_random, &server_random, mode);

        assert_eq!(binding1, binding2, "Mode binding should be deterministic");
    }

    #[test]
    fn test_derive_mode_binding_different_inputs() {
        let client_random1 = [1u8; 32];
        let client_random2 = [2u8; 32];
        let server_random = [3u8; 32];
        let mode = AuthenticationMode::ModeA;

        let binding1 = derive_mode_binding(&client_random1, &server_random, mode);
        let binding2 = derive_mode_binding(&client_random2, &server_random, mode);

        assert_ne!(binding1, binding2, "Different inputs should produce different bindings");
    }

    #[test]
    fn test_derive_mode_binding_different_modes() {
        let client_random = [1u8; 32];
        let server_random = [2u8; 32];

        let binding_a = derive_mode_binding(&client_random, &server_random, AuthenticationMode::ModeA);
        let binding_b = derive_mode_binding(&client_random, &server_random, AuthenticationMode::ModeB);

        assert_ne!(binding_a, binding_b, "Different modes should produce different bindings");
    }

    #[test]
    fn test_verify_mode_binding_valid() {
        let client_random = [1u8; 32];
        let server_random = [2u8; 32];
        let mode = AuthenticationMode::ModeB;

        let binding = derive_mode_binding(&client_random, &server_random, mode);
        assert!(verify_mode_binding(&binding, &client_random, &server_random, mode));
    }

    #[test]
    fn test_verify_mode_binding_invalid() {
        let client_random = [1u8; 32];
        let server_random = [2u8; 32];
        let mode = AuthenticationMode::ModeB;

        let binding = derive_mode_binding(&client_random, &server_random, mode);
        
        // Try to verify with different random
        let wrong_random = [99u8; 32];
        assert!(!verify_mode_binding(&binding, &wrong_random, &server_random, mode));
    }

    #[test]
    fn test_verify_mode_binding_detects_mode_change() {
        let client_random = [1u8; 32];
        let server_random = [2u8; 32];

        // Create binding for Mode B
        let binding = derive_mode_binding(&client_random, &server_random, AuthenticationMode::ModeB);
        
        // Try to verify as Mode A (downgrade attack)
        assert!(!verify_mode_binding(&binding, &client_random, &server_random, AuthenticationMode::ModeA),
                "Should detect mode downgrade from B to A");
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn test_build_handshake_transcript() {
        let protocol_id = [1u8; 32];
        let mode_binding = ModeBinding::new([2u8; 32]);
        let ephemeral_x25519 = [3u8; 32];
        let ephemeral_kyber = vec![4u8; 1568]; // Kyber1024 public key size
        let timestamp = 1234567890u64;

        let transcript = build_handshake_transcript(
            &protocol_id,
            &mode_binding,
            &ephemeral_x25519,
            &ephemeral_kyber,
            timestamp,
        );

        // Verify transcript contains all components
        assert_eq!(transcript.len(), 32 + 32 + 32 + 1568 + 8);
        
        // Verify protocol_id is at start
        assert_eq!(&transcript[0..32], &protocol_id);
        
        // Verify mode_binding follows
        assert_eq!(&transcript[32..64], mode_binding.as_bytes());
    }

    #[test]
    fn test_verify_handshake_mode_binding_success() {
        let client_random = [1u8; 32];
        let server_random = [2u8; 32];
        let mode = AuthenticationMode::ModeB;

        let binding = derive_mode_binding(&client_random, &server_random, mode);
        
        let result = verify_handshake_mode_binding(&binding, &client_random, &server_random, mode);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_handshake_mode_binding_detects_downgrade() {
        let client_random = [1u8; 32];
        let server_random = [2u8; 32];

        // Create binding for Mode B
        let binding = derive_mode_binding(&client_random, &server_random, AuthenticationMode::ModeB);
        
        // Try to verify as Mode A (downgrade attack)
        let result = verify_handshake_mode_binding(&binding, &client_random, &server_random, AuthenticationMode::ModeA);
        
        assert!(result.is_err());
        match result {
            Err(DowngradeError::ModeBindingMismatch { expected_mode, .. }) => {
                assert_eq!(expected_mode, AuthenticationMode::ModeA);
            }
            _ => panic!("Expected ModeBindingMismatch error"),
        }
    }

    #[test]
    fn test_downgrade_error_display() {
        let error1 = DowngradeError::ModeBindingMismatch {
            expected_mode: AuthenticationMode::ModeB,
            message: "Test error".to_string(),
        };
        assert!(error1.to_string().contains("Mode binding mismatch"));

        let error2 = DowngradeError::ModeChanged {
            original_mode: AuthenticationMode::ModeB,
            new_mode: AuthenticationMode::ModeA,
        };
        assert!(error2.to_string().contains("downgrade attack detected"));
    }
}
