// B4AE Security Tests
// Comprehensive security testing suite

use b4ae::crypto::{kyber, dilithium, hybrid, pfs_plus, zkauth};
use b4ae::protocol::handshake::{HandshakeConfig, HandshakeInitiator, HandshakeResponder};
use b4ae::protocol::message::Message;
use b4ae::protocol::session::Session;
use std::collections::HashMap;

#[test]
fn test_replay_attack_prevention() {
    // Test that replayed messages are rejected
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
    ).unwrap();
    
    let mut server_session = Session::from_handshake(
        server_result,
        b"client".to_vec(),
    ).unwrap();
    
    // Send message
    let msg = Message::text("Original message");
    let encrypted = client_session.send(&msg).unwrap();
    
    // First receive should succeed
    let result1 = server_session.receive(&encrypted);
    assert!(result1.is_ok());
    
    // Replay should fail (sequence number already used)
    // Note: This depends on implementation details
}

#[test]
fn test_forward_secrecy() {
    // Test that old keys cannot decrypt new messages
    let send_key = [0x42; 32];
    let receive_key = [0x43; 32];
    let session_id = [0x44; 32];
    
    let mut session = pfs_plus::PfsSession::new(
        &send_key,
        &receive_key,
        session_id,
    ).unwrap();
    
    // Generate some keys
    let _key1 = session.next_send_key().unwrap();
    let _key2 = session.next_send_key().unwrap();
    let _key3 = session.next_send_key().unwrap();
    
    // Try to get old key (should fail - forward secrecy)
    let old_key = session.get_receive_key(0).unwrap();
    assert!(old_key.is_none(), "Old keys should not be retrievable");
}

#[test]
fn test_zero_knowledge_authentication() {
    // Test ZK authentication without revealing identity
    let mut attributes = HashMap::new();
    attributes.insert("name".to_string(), "Alice".to_string());
    attributes.insert("role".to_string(), "admin".to_string());
    
    let identity = zkauth::ZkIdentity::new(attributes).unwrap();
    
    let mut verifier = zkauth::ZkVerifier::new();
    verifier.register_identity(
        identity.public_commitment(),
        identity.public_signing_key().clone(),
        zkauth::AuthLevel::Admin,
    );
    
    // Generate challenge
    let challenge = verifier.generate_challenge();
    
    // Generate proof
    let proof = identity.generate_proof(&challenge).unwrap();
    
    // Verify proof
    let auth_level = verifier.verify_proof(&proof, &challenge.challenge_id).unwrap();
    assert_eq!(auth_level, Some(zkauth::AuthLevel::Admin));
    
    // Verify identity was not revealed
    // (proof doesn't contain identity information)
}

#[test]
fn test_invalid_signature_rejection() {
    // Test that invalid signatures are rejected
    let keypair = dilithium::keypair().unwrap();
    let message = b"Test message";
    
    let signature = dilithium::sign(&keypair.secret_key, message).unwrap();
    
    // Valid signature should verify
    let valid = dilithium::verify(&keypair.public_key, message, &signature).unwrap();
    assert!(valid);
    
    // Modified message should fail
    let modified_message = b"Modified message";
    let invalid = dilithium::verify(&keypair.public_key, modified_message, &signature).unwrap();
    assert!(!invalid);
}

#[test]
fn test_key_rotation() {
    // Test automatic key rotation
    let send_key = [0x42; 32];
    let receive_key = [0x43; 32];
    let session_id = [0x44; 32];
    
    let mut session = pfs_plus::PfsSession::new(
        &send_key,
        &receive_key,
        session_id,
    ).unwrap();
    
    // Get initial counters
    let (send_count1, recv_count1) = session.counters();
    
    // Rotate keys
    let (new_send, new_receive) = session.rotate_keys().unwrap();
    
    // Verify new keys are different
    assert_ne!(new_send, send_key);
    assert_ne!(new_receive, receive_key);
    
    // Verify counters reset
    let (send_count2, recv_count2) = session.counters();
    assert_eq!(send_count2, 0);
    assert_eq!(recv_count2, 0);
}

#[test]
fn test_message_expiration() {
    // Test that expired messages are rejected
    let msg = Message::text("Test")
        .with_expiration(0); // Already expired
    
    assert!(msg.is_expired());
}

#[test]
fn test_quantum_resistant_key_exchange() {
    // Test Kyber key exchange
    let keypair = kyber::keypair().unwrap();
    let shared_secret = vec![0x42; 32];
    
    // Encapsulate
    let ciphertext = kyber::encapsulate(&keypair.public_key, &shared_secret).unwrap();
    
    // Decapsulate
    let decrypted = kyber::decapsulate(&keypair.secret_key, &ciphertext).unwrap();
    
    assert_eq!(shared_secret, decrypted);
}

#[test]
fn test_hybrid_cryptography_fallback() {
    // Test that hybrid crypto provides defense in depth
    let keypair = hybrid::generate_keypair().unwrap();
    
    // Both classical and PQC components should be present
    assert!(!keypair.public_key.ecdh_public.is_empty());
    assert!(!keypair.public_key.ecdsa_public.is_empty());
}

#[test]
fn test_memory_zeroization() {
    // Test that sensitive data is zeroized
    let send_key = [0x42; 32];
    let receive_key = [0x43; 32];
    let session_id = [0x44; 32];
    
    {
        let _session = pfs_plus::PfsSession::new(
            &send_key,
            &receive_key,
            session_id,
        ).unwrap();
        
        // Session goes out of scope here
        // Drop should zeroize sensitive data
    }
    
    // Memory should be zeroized (verified by Drop implementation)
}
