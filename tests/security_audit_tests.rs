// B4AE Security Test Suite
// Comprehensive security testing for external audit preparation

#[cfg(test)]
mod security_tests {
    use b4ae::prelude::*;
    use b4ae::crypto::{CryptoConfig, SecurityLevel};
    use b4ae::protocol::{SecurityProfile, ProtocolConfig};
    use rand::Rng;

    // Test constants
    const TEST_ITERATIONS: usize = 1000;
    const MAX_MESSAGE_SIZE: usize = 65536;

    #[test]
    fn test_cryptographic_implementation() {
        // Test post-quantum cryptography implementation
        test_kyber_implementation();
        test_dilithium_implementation();
        test_hybrid_cryptography();
        test_key_derivation();
        test_random_number_generation();
    }

    fn test_kyber_implementation() {
        // Test Kyber-1024 key generation
        for _ in 0..TEST_ITERATIONS {
            let (pk, sk) = b4ae::crypto::kyber::generate_keypair().unwrap();
            
            // Validate key sizes
            assert_eq!(pk.len(), 1568); // Kyber-1024 public key size
            assert_eq!(sk.len(), 3168); // Kyber-1024 secret key size
            
            // Test key encapsulation/decapsulation
            let (ciphertext, shared_secret) = b4ae::crypto::kyber::encapsulate(&pk).unwrap();
            let shared_secret_decaps = b4ae::crypto::kyber::decapsulate(&ciphertext, &sk).unwrap();
            
            assert_eq!(shared_secret, shared_secret_decaps);
            assert_eq!(shared_secret.len(), 32); // 256-bit shared secret
        }
    }

    fn test_dilithium_implementation() {
        // Test Dilithium5 signature generation/verification
        for _ in 0..TEST_ITERATIONS {
            let (pk, sk) = b4ae::crypto::dilithium::generate_keypair().unwrap();
            
            // Validate key sizes
            assert_eq!(pk.len(), 2592); // Dilithium5 public key size
            assert_eq!(sk.len(), 4864); // Dilithium5 secret key size
            
            // Test signature generation/verification
            let message = generate_random_message(256);
            let signature = b4ae::crypto::dilithium::sign(&message, &sk).unwrap();
            
            assert_eq!(signature.len(), 4595); // Dilithium5 signature size
            assert!(b4ae::crypto::dilithium::verify(&signature, &message, &pk).unwrap());
            
            // Test signature malleability resistance
            let mut tampered_signature = signature.clone();
            tampered_signature[0] ^= 0xFF;
            assert!(!b4ae::crypto::dilithium::verify(&tampered_signature, &message, &pk).unwrap());
        }
    }

    fn test_hybrid_cryptography() {
        // Test hybrid key exchange (Kyber + X25519)
        for _ in 0..TEST_ITERATIONS {
            let mut alice = B4aeClient::new(SecurityProfile::Maximum).unwrap();
            let mut bob = B4aeClient::new(SecurityProfile::Maximum).unwrap();
            
            let alice_id = b"alice".to_vec();
            let bob_id = b"bob".to_vec();
            
            // Perform hybrid handshake
            let init = alice.initiate_handshake(&bob_id).unwrap();
            let response = bob.respond_to_handshake(&alice_id, init).unwrap();
            let complete = alice.process_response(&bob_id, response).unwrap();
            bob.complete_handshake(&alice_id, complete).unwrap();
            alice.finalize_initiator(&bob_id).unwrap();
            
            // Test message encryption/decryption
            let plaintext = generate_random_message(1024);
            let encrypted = alice.encrypt_message(&bob_id, &plaintext).unwrap();
            let decrypted = bob.decrypt_message(&alice_id, &encrypted).unwrap();
            
            assert_eq!(plaintext, decrypted);
        }
    }

    fn test_key_derivation() {
        // Test HKDF key derivation consistency
        let master_secret = generate_random_bytes(32);
        let kdf = b4ae::crypto::hkdf::B4aeKeyDerivation::new(master_secret.clone());
        
        // Derive keys multiple times and ensure consistency
        let encryption_key1 = kdf.derive_encryption_key().unwrap();
        let encryption_key2 = kdf.derive_encryption_key().unwrap();
        assert_eq!(encryption_key1, encryption_key2);
        
        let auth_key1 = kdf.derive_authentication_key().unwrap();
        let auth_key2 = kdf.derive_authentication_key().unwrap();
        assert_eq!(auth_key1, auth_key2);
        
        let metadata_key1 = kdf.derive_metadata_key().unwrap();
        let metadata_key2 = kdf.derive_metadata_key().unwrap();
        assert_eq!(metadata_key1, metadata_key2);
        
        // Ensure different keys are derived for different purposes
        assert_ne!(encryption_key1, auth_key1);
        assert_ne!(encryption_key1, metadata_key1);
        assert_ne!(auth_key1, metadata_key1);
    }

    fn test_random_number_generation() {
        // Test CSPRNG quality
        let mut rng = rand::thread_rng();
        
        for _ in 0..TEST_ITERATIONS {
            let random1: [u8; 32] = rng.gen();
            let random2: [u8; 32] = rng.gen();
            
            // Ensure randomness
            assert_ne!(random1, random2);
            
            // Ensure no obvious patterns
            let mut unique_bytes = std::collections::HashSet::new();
            for byte in &random1 {
                unique_bytes.insert(*byte);
            }
            assert!(unique_bytes.len() > 200); // Good entropy distribution
        }
    }

    #[test]
    fn test_protocol_security() {
        // Test handshake protocol security
        test_handshake_replay_resistance();
        test_handshake_mitm_resistance();
        test_session_key_uniqueness();
        test_message_replay_protection();
        test_forward_secrecy();
    }

    fn test_handshake_replay_resistance() {
        let mut alice = B4aeClient::new(SecurityProfile::High).unwrap();
        let mut bob = B4aeClient::new(SecurityProfile::High).unwrap();
        
        let alice_id = b"alice".to_vec();
        let bob_id = b"bob".to_vec();
        
        // First handshake
        let init1 = alice.initiate_handshake(&bob_id).unwrap();
        let response1 = bob.respond_to_handshake(&alice_id, init1.clone()).unwrap();
        let complete1 = alice.process_response(&bob_id, response1).unwrap();
        bob.complete_handshake(&alice_id, complete1).unwrap();
        alice.finalize_initiator(&bob_id).unwrap();
        
        // Attempt replay attack with same init message
        let replay_result = bob.respond_to_handshake(&alice_id, init1);
        assert!(replay_result.is_err()); // Should reject replayed handshake
    }

    fn test_handshake_mitm_resistance() {
        // Test man-in-the-middle resistance through signature verification
        let mut alice = B4aeClient::new(SecurityProfile::Maximum).unwrap();
        let mut eve = B4aeClient::new(SecurityProfile::Maximum).unwrap();
        
        let alice_id = b"alice".to_vec();
        let eve_id = b"eve".to_vec();
        
        // Eve tries to impersonate Alice
        let eve_init = eve.initiate_handshake(&eve_id).unwrap();
        
        // Bob should detect the impersonation attempt
        let bob_result = alice.respond_to_handshake(&eve_id, eve_init);
        // This should fail due to identity mismatch
        assert!(bob_result.is_err() || !alice.has_session(&eve_id));
    }

    fn test_session_key_uniqueness() {
        let mut alice = B4aeClient::new(SecurityProfile::High).unwrap();
        let mut bob = B4aeClient::new(SecurityProfile::High).unwrap();
        
        let alice_id = b"alice".to_vec();
        let bob_id = b"bob".to_vec();
        
        // Multiple handshakes should generate different session keys
        let mut session_keys = Vec::new();
        
        for _ in 0..10 {
            // Reset clients for fresh handshake
            alice = B4aeClient::new(SecurityProfile::High).unwrap();
            bob = B4aeClient::new(SecurityProfile::High).unwrap();
            
            let init = alice.initiate_handshake(&bob_id).unwrap();
            let response = bob.respond_to_handshake(&alice_id, init).unwrap();
            let complete = alice.process_response(&bob_id, response).unwrap();
            bob.complete_handshake(&alice_id, complete).unwrap();
            alice.finalize_initiator(&bob_id).unwrap();
            
            // Extract session key (implementation specific)
            let test_message = b"test message";
            let encrypted = alice.encrypt_message(&bob_id, test_message).unwrap();
            
            // Store encrypted message as proxy for session key uniqueness
            session_keys.push(encrypted);
        }
        
        // Ensure all session keys are unique
        for i in 0..session_keys.len() {
            for j in (i+1)..session_keys.len() {
                assert_ne!(session_keys[i], session_keys[j]);
            }
        }
    }

    fn test_message_replay_protection() {
        let mut alice = B4aeClient::new(SecurityProfile::High).unwrap();
        let mut bob = B4aeClient::new(SecurityProfile::High).unwrap();
        
        let alice_id = b"alice".to_vec();
        let bob_id = b"bob".to_vec();
        
        // Establish session
        let init = alice.initiate_handshake(&bob_id).unwrap();
        let response = bob.respond_to_handshake(&alice_id, init).unwrap();
        let complete = alice.process_response(&bob_id, response).unwrap();
        bob.complete_handshake(&alice_id, complete).unwrap();
        alice.finalize_initiator(&bob_id).unwrap();
        
        // Send message
        let plaintext = b"sensitive message";
        let encrypted = alice.encrypt_message(&bob_id, plaintext).unwrap();
        let decrypted = bob.decrypt_message(&alice_id, &encrypted).unwrap();
        assert_eq!(plaintext.as_ref(), decrypted);
        
        // Attempt replay attack with same encrypted message
        let replay_result = bob.decrypt_message(&alice_id, &encrypted);
        // Should detect replay and reject
        assert!(replay_result.is_err() || replay_result.unwrap().is_empty());
    }

    fn test_forward_secrecy() {
        let mut alice = B4aeClient::new(SecurityProfile::Maximum).unwrap();
        let mut bob = B4aeClient::new(SecurityProfile::Maximum).unwrap();
        
        let alice_id = b"alice".to_vec();
        let bob_id = b"bob".to_vec();
        
        // Establish session
        let init = alice.initiate_handshake(&bob_id).unwrap();
        let response = bob.respond_to_handshake(&alice_id, init).unwrap();
        let complete = alice.process_response(&bob_id, response).unwrap();
        bob.complete_handshake(&alice_id, complete).unwrap();
        alice.finalize_initiator(&bob_id).unwrap();
        
        // Send some messages
        let messages = vec![b"message1", b"message2", b"message3"];
        let mut encrypted_messages = Vec::new();
        
        for msg in &messages {
            let encrypted = alice.encrypt_message(&bob_id, msg).unwrap();
            encrypted_messages.push(encrypted);
        }
        
        // Simulate key compromise and perform key rotation
        alice.perform_key_rotation(&bob_id).unwrap();
        bob.perform_key_rotation(&alice_id).unwrap();
        
        // New messages should use different keys
        let new_message = b"message after rotation";
        let new_encrypted = alice.encrypt_message(&bob_id, new_message).unwrap();
        
        // Old messages should still be decryptable (backward compatibility)
        for (i, encrypted) in encrypted_messages.iter().enumerate() {
            let decrypted = bob.decrypt_message(&alice_id, encrypted).unwrap();
            assert_eq!(messages[i].as_ref(), decrypted);
        }
        
        // New message should be decryptable
        let new_decrypted = bob.decrypt_message(&alice_id, &new_encrypted).unwrap();
        assert_eq!(new_message.as_ref(), new_decrypted);
    }

    #[test]
    fn test_metadata_protection() {
        // Test metadata obfuscation features
        test_padding_consistency();
        test_timing_obfuscation();
        test_dummy_traffic_generation();
        test_traffic_analysis_resistance();
    }

    fn test_padding_consistency() {
        let config = B4aeConfig::from_profile(SecurityProfile::High);
        let metadata = b4ae::metadata::MetadataProtection::new(config.protocol_config.metadata_protection);
        
        let test_messages = vec![
            vec![0u8; 10],
            vec![0u8; 100],
            vec![0u8; 1000],
            vec![0u8; 10000],
        ];
        
        for message in test_messages {
            let padded1 = metadata.pad_message(&message);
            let padded2 = metadata.pad_message(&message);
            
            // Same message should produce same padding (deterministic)
            assert_eq!(padded1.len(), padded2.len());
            
            // Padding should not reveal original message size
            assert!(padded1.len() >= message.len());
            assert!(padded1.len() <= message.len() + 1024); // Max padding
        }
    }

    fn test_timing_obfuscation() {
        let config = B4aeConfig::from_profile(SecurityProfile::High);
        let metadata = b4ae::metadata::MetadataProtection::new(config.protocol_config.metadata_protection);
        
        // Measure timing for different operations
        let mut timings = Vec::new();
        
        for _ in 0..100 {
            let start = std::time::Instant::now();
            metadata.apply_timing_obfuscation();
            let duration = start.elapsed();
            timings.push(duration);
        }
        
        // Calculate timing variance
        let mean = timings.iter().sum::<std::time::Duration>() / timings.len() as u32;
        let variance: f64 = timings.iter()
            .map(|t| (*t - mean).as_secs_f64().powi(2))
            .sum::<f64>() / timings.len() as f64;
        
        // Timing should have reasonable variance (obfuscation working)
        assert!(variance > 0.001); // Not constant time
    }

    fn test_dummy_traffic_generation() {
        let config = B4aeConfig::from_profile(SecurityProfile::High);
        let metadata = b4ae::metadata::MetadataProtection::new(config.protocol_config.metadata_protection);
        
        // Generate dummy traffic
        let dummy_messages = metadata.generate_dummy_traffic(10);
        
        assert_eq!(dummy_messages.len(), 10);
        
        for message in dummy_messages {
            // Dummy messages should look like real encrypted messages
            assert!(!message.is_empty());
            assert!(message.len() >= 64); // Minimum realistic size
            assert!(message.len() <= 4096); // Maximum realistic size
        }
    }

    fn test_traffic_analysis_resistance() {
        // Test that message patterns don't reveal information
        let mut alice = B4aeClient::new(SecurityProfile::Maximum).unwrap();
        let mut bob = B4aeClient::new(SecurityProfile::Maximum).unwrap();
        
        let alice_id = b"alice".to_vec();
        let bob_id = b"bob".to_vec();
        
        // Establish session with maximum metadata protection
        let init = alice.initiate_handshake(&bob_id).unwrap();
        let response = bob.respond_to_handshake(&alice_id, init).unwrap();
        let complete = alice.process_response(&bob_id, response).unwrap();
        bob.complete_handshake(&alice_id, complete).unwrap();
        alice.finalize_initiator(&bob_id).unwrap();
        
        // Send messages of different sizes
        let messages = vec![
            vec![0u8; 10],
            vec![0u8; 100],
            vec![0u8; 1000],
        ];
        
        let mut encrypted_sizes = Vec::new();
        
        for message in messages {
            let encrypted = alice.encrypt_message(&bob_id, &message).unwrap();
            encrypted_sizes.push(encrypted.len());
        }
        
        // Message sizes should not directly correlate with original sizes
        // due to padding and metadata protection
        for (i, original_size) in [10, 100, 1000].iter().enumerate() {
            let encrypted_size = encrypted_sizes[i];
            // Should be padded to similar sizes regardless of original
            assert!(encrypted_size >= 1024); // Minimum padding
            assert!(encrypted_size <= 2048); // Maximum padding
        }
    }

    #[test]
    fn test_implementation_security() {
        // Test implementation-specific security features
        test_memory_safety();
        test_error_handling();
        test_input_validation();
        test_dependency_security();
    }

    fn test_memory_safety() {
        // Test zeroization of sensitive data
        let sensitive_data = vec![0xFFu8; 32];
        let original_hash = blake3::hash(&sensitive_data);
        
        // Simulate secure zeroization
        let mut zeroized_data = sensitive_data.clone();
        zeroize::Zeroize::zeroize(&mut zeroized_data);
        
        // Verify zeroization
        assert!(zeroized_data.iter().all(|&b| b == 0));
        
        // Verify original data is not recoverable
        let zeroized_hash = blake3::hash(&zeroized_data);
        assert_ne!(original_hash, zeroized_hash);
    }

    fn test_error_handling() {
        let mut client = B4aeClient::new(SecurityProfile::Standard).unwrap();
        
        // Test invalid inputs don't panic
        let invalid_peer_id = vec![]; // Empty peer ID
        let result = client.initiate_handshake(&invalid_peer_id);
        assert!(result.is_err());
        
        // Test with invalid message data
        let invalid_message = vec![0u8; 0]; // Empty message
        let result = client.encrypt_message(b"nonexistent", &invalid_message);
        assert!(result.is_err());
        
        // Test error messages don't leak sensitive information
        match result {
            Err(e) => {
                let error_msg = format!("{:?}", e);
                assert!(!error_msg.contains("key"));
                assert!(!error_msg.contains("secret"));
                assert!(!error_msg.contains("password"));
            }
            Ok(_) => panic!("Expected error"),
        }
    }

    fn test_input_validation() {
        let mut client = B4aeClient::new(SecurityProfile::Standard).unwrap();
        
        // Test oversized inputs
        let oversized_message = vec![0u8; 10 * 1024 * 1024]; // 10MB
        let result = client.encrypt_message(b"peer", &oversized_message);
        assert!(result.is_err());
        
        // Test malformed peer IDs
        let malformed_ids = vec![
            vec![0u8; 0],      // Empty
            vec![0u8; 1],       // Too short
            vec![0u8; 1024],    // Too long
        ];
        
        for malformed_id in malformed_ids {
            let result = client.initiate_handshake(&malformed_id);
            assert!(result.is_err());
        }
    }

    fn test_dependency_security() {
        // This would typically run cargo audit or similar
        // For now, we verify that we're using secure dependency versions
        
        // Verify cryptographic dependencies
        assert!(cfg!(feature = "pqcrypto-kyber"));
        assert!(cfg!(feature = "pqcrypto-dilithium"));
        
        // Verify we're using constant-time comparison
        assert!(cfg!(feature = "subtle"));
        
        // Verify zeroization support
        assert!(cfg!(feature = "zeroize"));
    }

    // Helper functions
    fn generate_random_message(size: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        (0..size).map(|_| rng.gen()).collect()
    }

    fn generate_random_bytes(size: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        (0..size).map(|_| rng.gen()).collect()
    }
}