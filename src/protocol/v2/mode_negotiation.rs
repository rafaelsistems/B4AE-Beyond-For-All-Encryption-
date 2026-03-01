//! Mode negotiation protocol for B4AE v2.0
//!
//! This module implements the mode negotiation protocol that allows client and server
//! to agree on a compatible authentication mode before establishing a session.
//!
//! ## Protocol Flow
//!
//! 1. Client sends `ModeNegotiation` with supported modes and preferred mode
//! 2. Server computes intersection of client and server supported modes
//! 3. Server selects mode from intersection:
//!    - Prefer client's preferred mode if in intersection
//!    - Otherwise select highest security mode (MODE_B > MODE_A > MODE_C)
//! 4. Server sends `ModeSelection` with selected mode
//! 5. Both parties derive mode_binding for downgrade protection
//!
//! ## Security Properties
//!
//! - **Downgrade Protection**: Mode binding is cryptographically bound to transcript
//! - **Compatibility Checking**: Ensures both parties support selected mode
//! - **Priority Ordering**: Highest security mode selected when client preference unavailable
//!
//! ## Requirements
//!
//! This module satisfies:
//! - REQ-2: Mode Negotiation Protocol
//! - REQ-38: Downgrade Protection

use crate::protocol::v2::types::{AuthenticationMode, ModeNegotiation, ModeSelection};
use sha3::{Digest, Sha3_256};
use std::fmt;

/// Error type for mode negotiation failures
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModeNegotiationError {
    /// No compatible authentication modes between client and server
    NoCompatibleModes {
        client_modes: Vec<AuthenticationMode>,
        server_modes: Vec<AuthenticationMode>,
    },

    /// Client's supported modes list is empty
    EmptyClientModes,

    /// Server's supported modes list is empty
    EmptyServerModes,

    /// Client's preferred mode is not in their supported modes list
    PreferredModeNotSupported {
        preferred: AuthenticationMode,
        supported: Vec<AuthenticationMode>,
    },

    /// Selected mode is not production-ready (e.g., Mode C)
    ModeNotProductionReady {
        mode: AuthenticationMode,
    },
}

impl fmt::Display for ModeNegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModeNegotiationError::NoCompatibleModes {
                client_modes,
                server_modes,
            } => {
                write!(
                    f,
                    "No compatible authentication modes. Client supports: {:?}, Server supports: {:?}",
                    client_modes, server_modes
                )
            }
            ModeNegotiationError::EmptyClientModes => {
                write!(f, "Client's supported modes list is empty")
            }
            ModeNegotiationError::EmptyServerModes => {
                write!(f, "Server's supported modes list is empty")
            }
            ModeNegotiationError::PreferredModeNotSupported {
                preferred,
                supported,
            } => {
                write!(
                    f,
                    "Client's preferred mode {:?} is not in their supported modes list: {:?}",
                    preferred, supported
                )
            }
            ModeNegotiationError::ModeNotProductionReady { mode } => {
                write!(
                    f,
                    "Selected mode {:?} is not production-ready (research placeholder)",
                    mode
                )
            }
        }
    }
}

impl std::error::Error for ModeNegotiationError {}

/// Negotiates authentication mode between client and server
///
/// This function implements the server-side mode negotiation logic:
/// 1. Validates input (non-empty mode lists, preferred mode in supported list)
/// 2. Computes intersection of client and server supported modes
/// 3. Selects mode from intersection:
///    - Prefer client's preferred mode if in intersection
///    - Otherwise select highest security mode (MODE_B > MODE_A > MODE_C)
/// 4. Returns error if no compatible modes
///
/// ## Arguments
///
/// * `client_negotiation` - Mode negotiation message from client
/// * `server_supported_modes` - List of modes supported by server
///
/// ## Returns
///
/// * `Ok(AuthenticationMode)` - Selected authentication mode
/// * `Err(ModeNegotiationError)` - Negotiation failed
///
/// ## Example
///
/// ```rust
/// use b4ae::protocol::v2::types::{AuthenticationMode, ModeNegotiation};
/// use b4ae::protocol::v2::mode_negotiation::negotiate_authentication_mode;
///
/// let client_msg = ModeNegotiation {
///     supported_modes: vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB],
///     preferred_mode: AuthenticationMode::ModeB,
///     client_random: [1u8; 32],
/// };
///
/// let server_modes = vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB];
///
/// let selected = negotiate_authentication_mode(&client_msg, &server_modes).unwrap();
/// assert_eq!(selected, AuthenticationMode::ModeB); // Client's preference honored
/// ```
///
/// ## Requirements
///
/// - REQ-2.3: Compute intersection of supported modes
/// - REQ-2.4: Reject if intersection is empty
/// - REQ-2.5: Select mode from intersection
/// - REQ-2.6: Prefer client's preferred mode if in intersection
/// - REQ-2.7: Select highest security mode if preferred not in intersection
pub fn negotiate_authentication_mode(
    client_negotiation: &ModeNegotiation,
    server_supported_modes: &[AuthenticationMode],
) -> Result<AuthenticationMode, ModeNegotiationError> {
    // Validate inputs
    if client_negotiation.supported_modes.is_empty() {
        return Err(ModeNegotiationError::EmptyClientModes);
    }

    if server_supported_modes.is_empty() {
        return Err(ModeNegotiationError::EmptyServerModes);
    }

    // Verify client's preferred mode is in their supported modes list
    if !client_negotiation
        .supported_modes
        .contains(&client_negotiation.preferred_mode)
    {
        return Err(ModeNegotiationError::PreferredModeNotSupported {
            preferred: client_negotiation.preferred_mode,
            supported: client_negotiation.supported_modes.clone(),
        });
    }

    // Compute intersection of client and server supported modes
    let intersection = AuthenticationMode::compute_intersection(
        &client_negotiation.supported_modes,
        server_supported_modes,
    );

    // If intersection is empty, negotiation fails
    if intersection.is_empty() {
        return Err(ModeNegotiationError::NoCompatibleModes {
            client_modes: client_negotiation.supported_modes.clone(),
            server_modes: server_supported_modes.to_vec(),
        });
    }

    // Select mode from intersection
    // Priority 1: Client's preferred mode if in intersection
    let selected_mode = if intersection.contains(&client_negotiation.preferred_mode) {
        client_negotiation.preferred_mode
    } else {
        // Priority 2: Highest security mode (MODE_B > MODE_A > MODE_C)
        AuthenticationMode::select_highest_security(&intersection)
            .expect("intersection is non-empty, so select_highest_security should return Some")
    };

    // Validate that selected mode is production-ready
    // (This prevents accidental selection of Mode C in production)
    if !selected_mode.is_production_ready() {
        return Err(ModeNegotiationError::ModeNotProductionReady {
            mode: selected_mode,
        });
    }

    Ok(selected_mode)
}

/// Derives mode binding value for downgrade protection
///
/// The mode binding is computed as:
/// ```text
/// mode_binding = SHA3-256("B4AE-v2-mode-binding" || client_random || server_random || mode_id)
/// ```
///
/// This value is included in all subsequent handshake messages and verified
/// in all signatures to prevent mode downgrade attacks.
///
/// ## Arguments
///
/// * `client_random` - Client random value (32 bytes)
/// * `server_random` - Server random value (32 bytes)
/// * `mode` - Selected authentication mode
///
/// ## Returns
///
/// Mode binding value (32 bytes)
///
/// ## Example
///
/// ```rust
/// use b4ae::protocol::v2::types::AuthenticationMode;
/// use b4ae::protocol::v2::mode_negotiation::derive_mode_binding;
///
/// let client_random = [1u8; 32];
/// let server_random = [2u8; 32];
/// let mode = AuthenticationMode::ModeB;
///
/// let binding = derive_mode_binding(&client_random, &server_random, mode);
/// assert_eq!(binding.len(), 32);
/// ```
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
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    // Domain separator
    hasher.update(b"B4AE-v2-mode-binding");

    // Client random
    hasher.update(client_random);

    // Server random
    hasher.update(server_random);

    // Mode ID
    hasher.update(&[mode.mode_id()]);

    // Finalize hash
    let result = hasher.finalize();
    let mut binding = [0u8; 32];
    binding.copy_from_slice(&result);
    binding
}

/// Verifies mode binding consistency
///
/// This function verifies that a received mode binding matches the expected
/// value computed from the handshake parameters. This prevents mode downgrade
/// attacks where an attacker attempts to modify the selected mode.
///
/// ## Arguments
///
/// * `received_binding` - Mode binding received in handshake message
/// * `client_random` - Client random value (32 bytes)
/// * `server_random` - Server random value (32 bytes)
/// * `mode` - Selected authentication mode
///
/// ## Returns
///
/// * `true` - Mode binding is valid
/// * `false` - Mode binding is invalid (possible downgrade attack)
///
/// ## Example
///
/// ```rust
/// use b4ae::protocol::v2::types::AuthenticationMode;
/// use b4ae::protocol::v2::mode_negotiation::{derive_mode_binding, verify_mode_binding};
///
/// let client_random = [1u8; 32];
/// let server_random = [2u8; 32];
/// let mode = AuthenticationMode::ModeB;
///
/// let binding = derive_mode_binding(&client_random, &server_random, mode);
/// assert!(verify_mode_binding(&binding, &client_random, &server_random, mode));
/// ```
///
/// ## Requirements
///
/// - REQ-2.11: Verify mode_binding is consistent across all messages
/// - REQ-2.12: Abort handshake if mode_binding verification fails
/// - REQ-38: Downgrade Protection
pub fn verify_mode_binding(
    received_binding: &[u8; 32],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    mode: AuthenticationMode,
) -> bool {
    let expected_binding = derive_mode_binding(client_random, server_random, mode);

    // Constant-time comparison to prevent timing attacks
    use subtle::ConstantTimeEq;
    received_binding.ct_eq(&expected_binding).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negotiate_mode_client_preference_honored() {
        // Client prefers Mode B, server supports both A and B
        let client_msg = ModeNegotiation {
            supported_modes: vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB],
            preferred_mode: AuthenticationMode::ModeB,
            client_random: [1u8; 32],
        };

        let server_modes = vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB];

        let result = negotiate_authentication_mode(&client_msg, &server_modes);
        assert_eq!(result.unwrap(), AuthenticationMode::ModeB);
    }

    #[test]
    fn test_negotiate_mode_highest_security_when_preference_unavailable() {
        // Client prefers Mode A, but server only supports Mode B
        let client_msg = ModeNegotiation {
            supported_modes: vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB],
            preferred_mode: AuthenticationMode::ModeA,
            client_random: [1u8; 32],
        };

        let server_modes = vec![AuthenticationMode::ModeB];

        let result = negotiate_authentication_mode(&client_msg, &server_modes);
        // Should select Mode B (highest security in intersection)
        assert_eq!(result.unwrap(), AuthenticationMode::ModeB);
    }

    #[test]
    fn test_negotiate_mode_priority_order() {
        // Client supports all modes, prefers Mode C (not production-ready)
        // Server supports A and B
        let client_msg = ModeNegotiation {
            supported_modes: vec![
                AuthenticationMode::ModeA,
                AuthenticationMode::ModeB,
                AuthenticationMode::ModeC,
            ],
            preferred_mode: AuthenticationMode::ModeC,
            client_random: [1u8; 32],
        };

        let server_modes = vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB];

        let result = negotiate_authentication_mode(&client_msg, &server_modes);
        // Should select Mode B (highest security: B > A)
        assert_eq!(result.unwrap(), AuthenticationMode::ModeB);
    }

    #[test]
    fn test_negotiate_mode_no_compatible_modes() {
        // Client only supports Mode A, server only supports Mode B
        let client_msg = ModeNegotiation {
            supported_modes: vec![AuthenticationMode::ModeA],
            preferred_mode: AuthenticationMode::ModeA,
            client_random: [1u8; 32],
        };

        let server_modes = vec![AuthenticationMode::ModeB];

        let result = negotiate_authentication_mode(&client_msg, &server_modes);
        assert!(matches!(
            result,
            Err(ModeNegotiationError::NoCompatibleModes { .. })
        ));
    }

    #[test]
    fn test_negotiate_mode_empty_client_modes() {
        let client_msg = ModeNegotiation {
            supported_modes: vec![],
            preferred_mode: AuthenticationMode::ModeA,
            client_random: [1u8; 32],
        };

        let server_modes = vec![AuthenticationMode::ModeA];

        let result = negotiate_authentication_mode(&client_msg, &server_modes);
        assert!(matches!(
            result,
            Err(ModeNegotiationError::EmptyClientModes)
        ));
    }

    #[test]
    fn test_negotiate_mode_empty_server_modes() {
        let client_msg = ModeNegotiation {
            supported_modes: vec![AuthenticationMode::ModeA],
            preferred_mode: AuthenticationMode::ModeA,
            client_random: [1u8; 32],
        };

        let server_modes = vec![];

        let result = negotiate_authentication_mode(&client_msg, &server_modes);
        assert!(matches!(
            result,
            Err(ModeNegotiationError::EmptyServerModes)
        ));
    }

    #[test]
    fn test_negotiate_mode_preferred_not_in_supported() {
        // Client prefers Mode B but doesn't list it in supported modes
        let client_msg = ModeNegotiation {
            supported_modes: vec![AuthenticationMode::ModeA],
            preferred_mode: AuthenticationMode::ModeB,
            client_random: [1u8; 32],
        };

        let server_modes = vec![AuthenticationMode::ModeA, AuthenticationMode::ModeB];

        let result = negotiate_authentication_mode(&client_msg, &server_modes);
        assert!(matches!(
            result,
            Err(ModeNegotiationError::PreferredModeNotSupported { .. })
        ));
    }

    #[test]
    fn test_derive_mode_binding_deterministic() {
        let client_random = [1u8; 32];
        let server_random = [2u8; 32];
        let mode = AuthenticationMode::ModeB;

        let binding1 = derive_mode_binding(&client_random, &server_random, mode);
        let binding2 = derive_mode_binding(&client_random, &server_random, mode);

        assert_eq!(binding1, binding2);
    }

    #[test]
    fn test_derive_mode_binding_different_inputs() {
        let client_random1 = [1u8; 32];
        let client_random2 = [2u8; 32];
        let server_random = [3u8; 32];
        let mode = AuthenticationMode::ModeB;

        let binding1 = derive_mode_binding(&client_random1, &server_random, mode);
        let binding2 = derive_mode_binding(&client_random2, &server_random, mode);

        assert_ne!(binding1, binding2);
    }

    #[test]
    fn test_derive_mode_binding_different_modes() {
        let client_random = [1u8; 32];
        let server_random = [2u8; 32];

        let binding_a = derive_mode_binding(&client_random, &server_random, AuthenticationMode::ModeA);
        let binding_b = derive_mode_binding(&client_random, &server_random, AuthenticationMode::ModeB);

        assert_ne!(binding_a, binding_b);
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
        let wrong_binding = [0u8; 32];

        assert!(!verify_mode_binding(&wrong_binding, &client_random, &server_random, mode));
    }

    #[test]
    fn test_verify_mode_binding_detects_mode_change() {
        let client_random = [1u8; 32];
        let server_random = [2u8; 32];

        // Derive binding for Mode B
        let binding = derive_mode_binding(&client_random, &server_random, AuthenticationMode::ModeB);

        // Try to verify with Mode A (downgrade attack)
        assert!(!verify_mode_binding(&binding, &client_random, &server_random, AuthenticationMode::ModeA));
    }

    #[test]
    fn test_mode_negotiation_error_display() {
        let err = ModeNegotiationError::NoCompatibleModes {
            client_modes: vec![AuthenticationMode::ModeA],
            server_modes: vec![AuthenticationMode::ModeB],
        };
        let display = format!("{}", err);
        assert!(display.contains("No compatible authentication modes"));
    }
}
