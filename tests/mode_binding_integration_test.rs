//! Integration tests for mode binding and downgrade protection
//!
//! This test suite validates that mode binding is properly integrated into
//! the handshake flow and that downgrade attacks are detected.
//!
//! ## Test Coverage
//!
//! - Mode binding derivation and verification
//! - Mode binding inclusion in handshake messages
//! - Downgrade attack detection (Mode B → Mode A)
//! - Mode binding consistency across handshake messages
//! - Transcript building with mode binding
//!
//! ## Requirements
//!
//! - REQ-2: Mode Negotiation Protocol
//! - REQ-38: Downgrade Protection

use b4ae::protocol::v2::mode_binding::{
    derive_mode_binding, verify_mode_binding, verify_handshake_mode_binding,
    build_handshake_transcript, DowngradeError,
};
use b4ae::protocol::v2::types::{
    AuthenticationMode, ModeBinding, HandshakeInit, HandshakeResponse, HandshakeComplete,
};

#[test]
fn test_mode_binding_in_handshake_init() {
    // Simulate mode negotiation
    let client_random = [1u8; 32];
    let server_random = [2u8; 32];
    let mode = AuthenticationMode::ModeB;

    // Derive mode binding
    let mode_binding = derive_mode_binding(&client_random, &server_random, mode);

    // Create HandshakeInit with mode_binding
    let handshake_init = HandshakeInit {
        ephemeral_x25519: [3u8; 32],
        ephemeral_kyber: vec![4u8; 1568], // Kyber1024 public key size
        signature: vec![5u8; 4595],        // Dilithium5 signature size
        timestamp: 1234567890,
        mode_binding: mode_binding.clone(),
    };

    // Verify mode_binding in message matches expected
    assert_eq!(handshake_init.mode_binding, mode_binding);
    assert!(verify_mode_binding(
        &handshake_init.mode_binding,
        &client_random,
        &server_random,
        mode
    ));
}

#[test]
fn test_mode_binding_in_handshake_response() {
    // Simulate mode negotiation
    let client_random = [1u8; 32];
    let server_random = [2u8; 32];
    let mode = AuthenticationMode::ModeB;

    // Derive mode binding
    let mode_binding = derive_mode_binding(&client_random, &server_random, mode);

    // Create HandshakeResponse with mode_binding
    let handshake_response = HandshakeResponse {
        ephemeral_x25519: [3u8; 32],
        ephemeral_kyber: vec![4u8; 1568], // Kyber1024 ciphertext size
        signature: vec![5u8; 4595],        // Dilithium5 signature size
        timestamp: 1234567891,
        mode_binding: mode_binding.clone(),
    };

    // Verify mode_binding in message matches expected
    assert_eq!(handshake_response.mode_binding, mode_binding);
    assert!(verify_mode_binding(
        &handshake_response.mode_binding,
        &client_random,
        &server_random,
        mode
    ));
}

#[test]
fn test_mode_binding_in_handshake_complete() {
    // Simulate mode negotiation
    let client_random = [1u8; 32];
    let server_random = [2u8; 32];
    let mode = AuthenticationMode::ModeB;

    // Derive mode binding
    let mode_binding = derive_mode_binding(&client_random, &server_random, mode);

    // Create HandshakeComplete with mode_binding
    let handshake_complete = HandshakeComplete {
        signature: vec![5u8; 4595], // Dilithium5 signature size
        timestamp: 1234567892,
        mode_binding: mode_binding.clone(),
    };

    // Verify mode_binding in message matches expected
    assert_eq!(handshake_complete.mode_binding, mode_binding);
    assert!(verify_mode_binding(
        &handshake_complete.mode_binding,
        &client_random,
        &server_random,
        mode
    ));
}

#[test]
fn test_mode_binding_consistency_across_messages() {
    // Simulate mode negotiation
    let client_random = [1u8; 32];
    let server_random = [2u8; 32];
    let mode = AuthenticationMode::ModeB;

    // Derive mode binding once
    let mode_binding = derive_mode_binding(&client_random, &server_random, mode);

    // Create all handshake messages with same mode_binding
    let handshake_init = HandshakeInit {
        ephemeral_x25519: [3u8; 32],
        ephemeral_kyber: vec![4u8; 1568],
        signature: vec![5u8; 4595],
        timestamp: 1234567890,
        mode_binding: mode_binding.clone(),
    };

    let handshake_response = HandshakeResponse {
        ephemeral_x25519: [6u8; 32],
        ephemeral_kyber: vec![7u8; 1568],
        signature: vec![8u8; 4595],
        timestamp: 1234567891,
        mode_binding: mode_binding.clone(),
    };

    let handshake_complete = HandshakeComplete {
        signature: vec![9u8; 4595],
        timestamp: 1234567892,
        mode_binding: mode_binding.clone(),
    };

    // Verify all messages have consistent mode_binding
    assert_eq!(handshake_init.mode_binding, mode_binding);
    assert_eq!(handshake_response.mode_binding, mode_binding);
    assert_eq!(handshake_complete.mode_binding, mode_binding);

    // Verify all can be validated
    assert!(verify_mode_binding(
        &handshake_init.mode_binding,
        &client_random,
        &server_random,
        mode
    ));
    assert!(verify_mode_binding(
        &handshake_response.mode_binding,
        &client_random,
        &server_random,
        mode
    ));
    assert!(verify_mode_binding(
        &handshake_complete.mode_binding,
        &client_random,
        &server_random,
        mode
    ));
}

#[test]
fn test_downgrade_attack_detection_mode_b_to_a() {
    // Attacker tries to downgrade from Mode B to Mode A
    let client_random = [1u8; 32];
    let server_random = [2u8; 32];

    // Client and server negotiate Mode B
    let negotiated_mode = AuthenticationMode::ModeB;
    let mode_binding = derive_mode_binding(&client_random, &server_random, negotiated_mode);

    // Attacker creates HandshakeInit with Mode B binding
    let handshake_init = HandshakeInit {
        ephemeral_x25519: [3u8; 32],
        ephemeral_kyber: vec![4u8; 1568],
        signature: vec![5u8; 64], // XEdDSA signature (Mode A)
        timestamp: 1234567890,
        mode_binding: mode_binding.clone(),
    };

    // Server tries to verify with Mode A (attacker's goal)
    let downgraded_mode = AuthenticationMode::ModeA;
    let result = verify_handshake_mode_binding(
        &handshake_init.mode_binding,
        &client_random,
        &server_random,
        downgraded_mode,
    );

    // Should detect downgrade attack
    assert!(result.is_err());
    match result {
        Err(DowngradeError::ModeBindingMismatch { expected_mode, .. }) => {
            assert_eq!(expected_mode, AuthenticationMode::ModeA);
        }
        _ => panic!("Expected ModeBindingMismatch error"),
    }
}

#[test]
fn test_downgrade_attack_detection_modified_binding() {
    // Attacker tries to modify mode_binding
    let client_random = [1u8; 32];
    let server_random = [2u8; 32];
    let mode = AuthenticationMode::ModeB;

    // Derive correct mode binding
    let correct_binding = derive_mode_binding(&client_random, &server_random, mode);

    // Attacker creates modified binding
    let mut modified_binding_bytes = correct_binding.to_bytes();
    modified_binding_bytes[0] ^= 0xFF; // Flip bits
    let modified_binding = ModeBinding::new(modified_binding_bytes);

    // Create HandshakeInit with modified binding
    let handshake_init = HandshakeInit {
        ephemeral_x25519: [3u8; 32],
        ephemeral_kyber: vec![4u8; 1568],
        signature: vec![5u8; 4595],
        timestamp: 1234567890,
        mode_binding: modified_binding,
    };

    // Verification should fail
    let result = verify_handshake_mode_binding(
        &handshake_init.mode_binding,
        &client_random,
        &server_random,
        mode,
    );

    assert!(result.is_err());
}

#[test]
fn test_mode_binding_in_transcript() {
    // Test that mode_binding is included in transcript for signing
    let protocol_id = [1u8; 32];
    let client_random = [2u8; 32];
    let server_random = [3u8; 32];
    let mode = AuthenticationMode::ModeB;

    let mode_binding = derive_mode_binding(&client_random, &server_random, mode);
    let ephemeral_x25519 = [4u8; 32];
    let ephemeral_kyber = vec![5u8; 1568];
    let timestamp = 1234567890u64;

    // Build transcript
    let transcript = build_handshake_transcript(
        &protocol_id,
        &mode_binding,
        &ephemeral_x25519,
        &ephemeral_kyber,
        timestamp,
    );

    // Verify transcript contains mode_binding
    // Transcript format: protocol_id || mode_binding || ephemeral_x25519 || ephemeral_kyber || timestamp
    assert!(transcript.len() >= 32 + 32 + 32 + 1568 + 8);

    // Verify mode_binding is at correct position (after protocol_id)
    let mode_binding_in_transcript = &transcript[32..64];
    assert_eq!(mode_binding_in_transcript, mode_binding.as_bytes());
}

#[test]
fn test_different_randoms_produce_different_bindings() {
    // Test that different client_random or server_random produce different bindings
    let client_random1 = [1u8; 32];
    let client_random2 = [2u8; 32];
    let server_random1 = [3u8; 32];
    let server_random2 = [4u8; 32];
    let mode = AuthenticationMode::ModeB;

    let binding1 = derive_mode_binding(&client_random1, &server_random1, mode);
    let binding2 = derive_mode_binding(&client_random2, &server_random1, mode);
    let binding3 = derive_mode_binding(&client_random1, &server_random2, mode);

    // All should be different
    assert_ne!(binding1, binding2);
    assert_ne!(binding1, binding3);
    assert_ne!(binding2, binding3);
}

#[test]
fn test_different_modes_produce_different_bindings() {
    // Test that different modes produce different bindings
    let client_random = [1u8; 32];
    let server_random = [2u8; 32];

    let binding_a = derive_mode_binding(&client_random, &server_random, AuthenticationMode::ModeA);
    let binding_b = derive_mode_binding(&client_random, &server_random, AuthenticationMode::ModeB);
    let binding_c = derive_mode_binding(&client_random, &server_random, AuthenticationMode::ModeC);

    // All should be different
    assert_ne!(binding_a, binding_b);
    assert_ne!(binding_a, binding_c);
    assert_ne!(binding_b, binding_c);
}

#[test]
fn test_mode_binding_deterministic() {
    // Test that mode binding is deterministic
    let client_random = [1u8; 32];
    let server_random = [2u8; 32];
    let mode = AuthenticationMode::ModeB;

    let binding1 = derive_mode_binding(&client_random, &server_random, mode);
    let binding2 = derive_mode_binding(&client_random, &server_random, mode);

    assert_eq!(binding1, binding2);
}

#[test]
fn test_verify_mode_binding_rejects_wrong_random() {
    // Test that verification fails with wrong random values
    let client_random = [1u8; 32];
    let server_random = [2u8; 32];
    let wrong_random = [99u8; 32];
    let mode = AuthenticationMode::ModeB;

    let binding = derive_mode_binding(&client_random, &server_random, mode);

    // Should fail with wrong client_random
    assert!(!verify_mode_binding(
        &binding,
        &wrong_random,
        &server_random,
        mode
    ));

    // Should fail with wrong server_random
    assert!(!verify_mode_binding(
        &binding,
        &client_random,
        &wrong_random,
        mode
    ));
}

#[test]
fn test_handshake_message_validation_with_mode_binding() {
    // Test that handshake messages validate correctly with mode_binding
    let client_random = [1u8; 32];
    let server_random = [2u8; 32];
    let mode = AuthenticationMode::ModeB;

    let mode_binding = derive_mode_binding(&client_random, &server_random, mode);

    // Create valid HandshakeInit
    let handshake_init = HandshakeInit {
        ephemeral_x25519: [3u8; 32],
        ephemeral_kyber: vec![4u8; 1568],
        signature: vec![5u8; 4595],
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        mode_binding,
    };

    // Should validate successfully
    assert!(handshake_init.validate().is_ok());
}

#[test]
fn test_mode_binding_prevents_replay_across_sessions() {
    // Test that mode_binding from one session cannot be used in another
    let client_random1 = [1u8; 32];
    let server_random1 = [2u8; 32];
    let client_random2 = [3u8; 32];
    let server_random2 = [4u8; 32];
    let mode = AuthenticationMode::ModeB;

    // Session 1 binding
    let binding1 = derive_mode_binding(&client_random1, &server_random1, mode);

    // Try to use Session 1 binding in Session 2
    assert!(!verify_mode_binding(
        &binding1,
        &client_random2,
        &server_random2,
        mode
    ));
}

#[test]
fn test_downgrade_error_display() {
    // Test error message formatting
    let error = DowngradeError::ModeBindingMismatch {
        expected_mode: AuthenticationMode::ModeB,
        message: "Test error".to_string(),
    };

    let display = format!("{}", error);
    assert!(display.contains("Mode binding mismatch"));
    assert!(display.contains("ModeB"));

    let error2 = DowngradeError::ModeChanged {
        original_mode: AuthenticationMode::ModeB,
        new_mode: AuthenticationMode::ModeA,
    };

    let display2 = format!("{}", error2);
    assert!(display2.contains("downgrade attack detected"));
}
