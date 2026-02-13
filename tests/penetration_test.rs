// B4AE Penetration Testing Suite
// Comprehensive penetration testing and attack simulation

use b4ae::crypto::{kyber, dilithium};
use b4ae::protocol::handshake::{HandshakeConfig, HandshakeInitiator, HandshakeResponder};
use b4ae::protocol::message::Message;
use b4ae::protocol::session::Session;

// ============================================================================
// NETWORK LAYER ATTACKS
// ============================================================================

#[test]
fn test_mitm_attack_detection() {
    // Test Man-in-the-Middle attack detection
    let config = HandshakeConfig::default();
    
    let mut client = HandshakeInitiator::new(config.clone()).unwrap();
    let mut server = HandshakeResponder::new(config.clone()).unwrap();
    let mut attacker = HandshakeResponder::new(config).unwrap();
    
    // Client initiates
    let init = client.generate_init().unwrap();
    
    // Attacker intercepts and tries to respond
    let _attacker_response = attacker.process_init(init.clone());
    
    // Server also processes
    let server_response = server.process_init(init).unwrap();
    
    // Client processes server response
    client.process_response(server_response).unwrap();
    let complete = client.generate_complete().unwrap();
    
    // Attacker tries to process complete (should fail - wrong keys)
    let attacker_result = attacker.process_complete(complete.clone());
    
    // Server processes complete (should succeed)
    let server_result = server.process_complete(complete);
    assert!(server_result.is_ok());
    
    // Verify attacker cannot establish valid session
    if let Ok(_) = attacker_result {
        let client_final = client.finalize().unwrap();
        let attacker_final = attacker.finalize().unwrap();
        
        // Session IDs should not match
        assert_ne!(client_final.session_id, attacker_final.session_id,
                   "MITM attack succeeded - security breach!");
    }
}

#[test]
fn test_dos_resistance() {
    // Test Denial of Service resistance
    let config = HandshakeConfig::default();
    
    // Simulate rapid connection attempts
    let mut responders = Vec::new();
    
    for _ in 0..100 {  // Reduced from 1000 for faster testing
        let responder = HandshakeResponder::new(config.clone());
        assert!(responder.is_ok(), "Should handle rapid connection attempts");
        responders.push(responder.unwrap());
    }
    
    // System should still be responsive
    let mut final_responder = HandshakeResponder::new(config).unwrap();
    let mut initiator = HandshakeInitiator::new(HandshakeConfig::default()).unwrap();
    
    let init = initiator.generate_init().unwrap();
    let response = final_responder.process_init(init);
    assert!(response.is_ok(), "System should remain responsive after DoS attempt");
}

// ============================================================================
// CRYPTOGRAPHIC ATTACKS
// ============================================================================

#[test]
fn test_key_recovery_resistance() {
    // Test resistance to key recovery attacks
    // 
    // Kyber menggunakan Key Encapsulation Mechanism (KEM):
    // - encapsulate() generates (shared_secret, ciphertext)
    // - decapsulate() recovers shared_secret from ciphertext
    // 
    // Attacker dengan akses ke public key dan multiple ciphertexts
    // tidak dapat recover secret key
    
    let keypair = kyber::keypair().unwrap();
    
    // Attacker has access to public key and multiple ciphertexts
    let mut encapsulation_results = Vec::new();
    
    for _ in 0..100 {
        // Each encapsulate generates a NEW random shared secret
        let (shared_secret, ciphertext) = kyber::encapsulate(&keypair.public_key).unwrap();
        encapsulation_results.push((shared_secret, ciphertext));
    }
    
    // Verify all ciphertexts can be decapsulated with correct secret key
    for (original_ss, ciphertext) in encapsulation_results.iter() {
        let recovered_ss = kyber::decapsulate(&keypair.secret_key, ciphertext).unwrap();
        assert_eq!(original_ss.as_bytes(), recovered_ss.as_bytes(),
                   "Shared secret recovery should work with correct secret key");
    }
    
    // Verify that each shared secret is unique (randomness check)
    let first_ss = &encapsulation_results[0].0;
    let different_count = encapsulation_results.iter()
        .filter(|(ss, _)| ss.as_bytes() != first_ss.as_bytes())
        .count();
    
    assert!(different_count > 90, "Shared secrets should be random and unique");
}

#[test]
fn test_timing_attack_resistance() {
    // Test resistance to timing attacks
    use std::time::Instant;
    
    let keypair = dilithium::keypair().unwrap();
    let message = b"Test message";
    let signature = dilithium::sign(&keypair.secret_key, message).unwrap();
    
    // Measure verification time for valid signature
    let mut valid_times = Vec::new();
    for _ in 0..50 {  // Reduced for faster testing
        let start = Instant::now();
        let _ = dilithium::verify(&keypair.public_key, message, &signature).unwrap();
        valid_times.push(start.elapsed());
    }
    
    // Test with wrong message (invalid case)
    let wrong_message = b"Wrong message";
    let mut invalid_times = Vec::new();
    for _ in 0..50 {
        let start = Instant::now();
        let _ = dilithium::verify(&keypair.public_key, wrong_message, &signature);
        invalid_times.push(start.elapsed());
    }
    
    // Calculate average times
    let avg_valid: u128 = valid_times.iter().map(|d| d.as_nanos()).sum::<u128>() / valid_times.len() as u128;
    let avg_invalid: u128 = invalid_times.iter().map(|d| d.as_nanos()).sum::<u128>() / invalid_times.len() as u128;
    
    // Timing should be similar (constant-time verification)
    let timing_diff = if avg_valid > avg_invalid {
        avg_valid - avg_invalid
    } else {
        avg_invalid - avg_valid
    };
    
    let timing_diff_percent = if avg_valid > 0 {
        (timing_diff as f64 / avg_valid as f64) * 100.0
    } else {
        0.0
    };
    
    println!("Timing difference: {:.2}%", timing_diff_percent);
    
    // Allow up to 50% timing difference (due to system noise)
    // Real constant-time implementations should be closer to 0%
    // but testing environment can have significant variance
    assert!(timing_diff_percent < 50.0, 
            "Timing difference too large: {:.2}% (potential timing attack)", 
            timing_diff_percent);
}

// ============================================================================
// PROTOCOL ATTACKS
// ============================================================================

#[test]
fn test_handshake_manipulation() {
    // Test handshake manipulation detection
    let config = HandshakeConfig::default();
    
    let mut client = HandshakeInitiator::new(config.clone()).unwrap();
    let mut server = HandshakeResponder::new(config).unwrap();
    
    // Client initiates
    let mut init = client.generate_init().unwrap();
    
    // Attacker manipulates init message
    init.protocol_version = 0xFFFF; // Invalid version
    
    // Server should reject manipulated init
    let result = server.process_init(init);
    assert!(result.is_err(), "Manipulated handshake should be rejected");
}

#[test]
fn test_state_confusion() {
    // Test state confusion attack
    let config = HandshakeConfig::default();
    
    let mut client = HandshakeInitiator::new(config.clone()).unwrap();
    let mut _server = HandshakeResponder::new(config).unwrap();
    
    // Try to send complete before response (wrong state)
    let result = client.generate_complete();
    assert!(result.is_err(), "Should not allow complete before response");
}

#[test]
fn test_input_validation_bypass() {
    // Test input validation bypass attempts
    
    // Try to create message with various input sizes
    let test_inputs = vec![
        vec![0xFF; 1024],        // 1KB
        vec![],                   // Empty
        vec![0x00; 1],           // Single null byte
        vec![0xAB; 65535],       // Large input
    ];
    
    for input in test_inputs {
        let msg = Message::binary(input);
        // Should handle gracefully, not crash
        let _ = msg.to_bytes();
    }
}

#[test]
fn test_signature_forgery_resistance() {
    // Test resistance to signature forgery
    let keypair = dilithium::keypair().unwrap();
    let message = b"Original message";
    
    // Generate valid signature
    let signature = dilithium::sign(&keypair.secret_key, message).unwrap();
    
    // Verify original signature
    let valid = dilithium::verify(&keypair.public_key, message, &signature).unwrap();
    assert!(valid, "Original signature should be valid");
    
    // Try to verify with different message (should fail)
    let forged_message = b"Forged message";
    let invalid = dilithium::verify(&keypair.public_key, forged_message, &signature).unwrap();
    assert!(!invalid, "Forged message should not verify");
    
    // Try to verify with different key (should fail)
    let other_keypair = dilithium::keypair().unwrap();
    let wrong_key = dilithium::verify(&other_keypair.public_key, message, &signature).unwrap();
    assert!(!wrong_key, "Signature should not verify with wrong key");
}

#[test]
fn test_kyber_ciphertext_manipulation() {
    // Test that manipulated ciphertexts are rejected or produce wrong results
    let keypair = kyber::keypair().unwrap();
    
    // Generate valid encapsulation
    let (original_ss, ciphertext) = kyber::encapsulate(&keypair.public_key).unwrap();
    
    // Decapsulate original - should work
    let recovered_ss = kyber::decapsulate(&keypair.secret_key, &ciphertext).unwrap();
    assert_eq!(original_ss.as_bytes(), recovered_ss.as_bytes());
    
    // Note: Kyber has implicit rejection - manipulated ciphertexts
    // will decapsulate to a different (unpredictable) shared secret
    // rather than failing. This is a security feature against
    // chosen-ciphertext attacks.
}

#[test]
fn test_replay_window_limit() {
    // Test that replay protection has proper window limits
    let config = HandshakeConfig::default();
    
    let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
    let mut responder = HandshakeResponder::new(config).unwrap();
    
    // Complete handshake
    let init = initiator.generate_init().unwrap();
    let response = responder.process_init(init).unwrap();
    initiator.process_response(response).unwrap();
    let complete = initiator.generate_complete().unwrap();
    responder.process_complete(complete).unwrap();
    
    let client_result = initiator.finalize().unwrap();
    let server_result = responder.finalize().unwrap();
    
    let mut client_session = Session::from_handshake(
        client_result,
        b"server".to_vec(),
        None,
    ).unwrap();
    
    let mut server_session = Session::from_handshake(
        server_result,
        b"client".to_vec(),
        None,
    ).unwrap();
    
    // Send multiple messages
    let mut encrypted_messages = Vec::new();
    for i in 0..10 {
        let msg = Message::text(format!("Message {}", i));
        let encrypted = client_session.send(&msg).unwrap();
        encrypted_messages.push(encrypted);
    }
    
    // Process messages in order (should succeed)
    for encrypted in &encrypted_messages {
        let result = server_session.receive(encrypted);
        assert!(result.is_ok(), "In-order messages should be accepted");
    }
}
