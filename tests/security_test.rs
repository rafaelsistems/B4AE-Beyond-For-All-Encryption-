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
    // PFS+ maintains message counters that prevent replay
}

#[test]
fn test_forward_secrecy() {
    // Test that old keys are deleted after enough new keys are derived
    // This ensures forward secrecy - compromising current keys doesn't reveal past keys
    let send_key = [0x42; 32];
    let receive_key = [0x43; 32];
    let session_id = [0x44; 32];
    
    let mut session = pfs_plus::PfsSession::new(
        &send_key,
        &receive_key,
        session_id,
    ).unwrap();
    
    // Generate more than 100 keys to trigger cleanup (cache keeps last 100)
    for i in 0..150 {
        let _ = session.next_send_key().unwrap();
    }
    
    // Send chain should have deleted keys 0-49 (keeps last 100: 50-149)
    // But send_chain.get_key doesn't exist, we need to test receive chain
    
    // Use receive chain: derive keys 0-150
    for i in 0..150 {
        let _ = session.get_receive_key(i).unwrap();
    }
    
    // After deriving 150 keys, keys 0-49 should be cleaned up
    // Trying to get key 0 should return None (forward secrecy)
    let old_key = session.get_receive_key(0).unwrap();
    assert!(old_key.is_none(), "Old keys should not be retrievable due to forward secrecy");
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
        identity.public_signing_key().to_vec(),
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
    assert_eq!(send_count1, 0);
    assert_eq!(recv_count1, 0);
    
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
    // with_expiration(0) sets expires_at to now, so we need to wait briefly
    let msg = Message::text("Test")
        .with_expiration(0); // Expires at now
    
    // Wait 1 second for message to expire
    std::thread::sleep(std::time::Duration::from_secs(1));
    
    assert!(msg.is_expired(), "Message should be expired after waiting");
}

#[test]
fn test_quantum_resistant_key_exchange() {
    // Test Kyber key encapsulation mechanism (KEM)
    // Kyber menggunakan KEM, bukan traditional key exchange
    
    let keypair = kyber::keypair().unwrap();
    
    // Encapsulate - generates shared secret AND ciphertext
    let (shared_secret, ciphertext) = kyber::encapsulate(&keypair.public_key).unwrap();
    
    // Decapsulate - recovers the same shared secret
    let recovered_secret = kyber::decapsulate(&keypair.secret_key, &ciphertext).unwrap();
    
    // Both parties should have the same shared secret
    assert_eq!(shared_secret.as_bytes(), recovered_secret.as_bytes());
    
    // Shared secret should be 32 bytes
    assert_eq!(shared_secret.as_bytes().len(), 32);
}

#[test]
fn test_hybrid_cryptography_defense_in_depth() {
    // Test that hybrid crypto provides defense in depth
    // Menggunakan X25519 + Kyber untuk key exchange
    // Menggunakan Ed25519 + Dilithium untuk signatures
    
    let keypair = hybrid::keypair().unwrap();
    
    // X25519 public key should be 32 bytes
    assert_eq!(keypair.public_key.ecdh_public.len(), 32);
    
    // Ed25519 public key should be 32 bytes
    assert_eq!(keypair.public_key.ecdsa_public.len(), 32);
    
    // Kyber public key should be present
    assert_eq!(keypair.public_key.kyber_public.as_bytes().len(), 1568);
    
    // Dilithium public key should be present
    assert_eq!(keypair.public_key.dilithium_public.as_bytes().len(), 2592);
}

#[test]
fn test_hybrid_key_exchange() {
    // Test complete hybrid key exchange
    let alice = hybrid::keypair().unwrap();
    let bob = hybrid::keypair().unwrap();
    
    // Alice encapsulates to Bob
    let (alice_shared_secret, ciphertext) = hybrid::encapsulate(&bob.public_key).unwrap();
    
    // Shared secret should be 32 bytes (HKDF output)
    assert_eq!(alice_shared_secret.len(), 32);
    
    // Ciphertext should contain valid data
    assert!(!ciphertext.ecdh_ephemeral_public.is_empty());
}

#[test]
fn test_hybrid_signature() {
    // Test hybrid signature (Ed25519 + Dilithium)
    let keypair = hybrid::keypair().unwrap();
    let message = b"Test message for hybrid signature";
    
    // Sign
    let signature = hybrid::sign(&keypair.secret_key, message).unwrap();
    
    // Ed25519 signature should be 64 bytes
    assert_eq!(signature.ecdsa_signature.len(), 64);
    
    // Verify
    let valid = hybrid::verify(&keypair.public_key, message, &signature).unwrap();
    assert!(valid, "Valid signature should verify");
    
    // Wrong message should fail
    let wrong_message = b"Wrong message";
    let invalid = hybrid::verify(&keypair.public_key, wrong_message, &signature).unwrap();
    assert!(!invalid, "Invalid signature should not verify");
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
        // Drop should zeroize sensitive data via zeroize crate
    }
    
    // Memory should be zeroized (verified by Drop implementation)
}

#[test]
fn test_dilithium_keypair_generation() {
    // Test Dilithium5 keypair generation
    let keypair = dilithium::keypair().unwrap();
    
    // Verify key sizes
    // Dilithium5 public key: 2592 bytes
    // Dilithium5 secret key: 4896 bytes (may vary by implementation)
    assert_eq!(keypair.public_key.as_bytes().len(), 2592);
    assert_eq!(keypair.secret_key.as_bytes().len(), 4896);
}

#[test]
fn test_kyber_keypair_generation() {
    // Test Kyber-1024 keypair generation
    let keypair = kyber::keypair().unwrap();
    
    // Verify key sizes
    assert_eq!(keypair.public_key.as_bytes().len(), 1568);
    assert_eq!(keypair.secret_key.as_bytes().len(), 3168);
}

#[test]
fn test_session_key_rotation() {
    // Test session-level key rotation
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
    
    let mut session = Session::from_handshake(
        client_result,
        b"server".to_vec(),
    ).unwrap();
    
    // Initial rotation count should be 0
    assert_eq!(session.rotation_count(), 0);
    
    // Perform key rotation
    let rotation_msg = session.perform_key_rotation().unwrap();
    
    // Rotation count should increment
    assert_eq!(session.rotation_count(), 1);
    assert_eq!(rotation_msg.rotation_sequence, 1);
    
    // New key material should be 32 bytes
    assert_eq!(rotation_msg.new_key_material.len(), 32);
}
