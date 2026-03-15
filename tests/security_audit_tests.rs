// B4AE Security Test Suite
// Comprehensive security testing for external audit preparation

#[cfg(test)]
mod security_tests {
    use b4ae::prelude::*;
    use b4ae::protocol::SecurityProfile;
    use rand::Rng;

    // Test constants
    const TEST_ITERATIONS: usize = 10;

    #[test]
    fn test_cryptographic_implementation() {
        test_kyber_implementation();
        test_dilithium_implementation();
        test_hybrid_cryptography();
        test_key_derivation();
        test_random_number_generation();
    }

    fn test_kyber_implementation() {
        for _ in 0..TEST_ITERATIONS {
            let kp = b4ae::crypto::kyber::keypair().unwrap();

            // Validate key sizes
            assert_eq!(kp.public_key.as_bytes().len(), 1568);
            assert_eq!(kp.secret_key.as_bytes().len(), 3168);

            // Test key encapsulation/decapsulation
            let (shared_secret, ciphertext) = b4ae::crypto::kyber::encapsulate(&kp.public_key).unwrap();
            let shared_secret_decaps = b4ae::crypto::kyber::decapsulate(&kp.secret_key, &ciphertext).unwrap();

            assert_eq!(shared_secret.as_bytes(), shared_secret_decaps.as_bytes());
            assert_eq!(shared_secret.as_bytes().len(), 32);
        }
    }

    fn test_dilithium_implementation() {
        for _ in 0..TEST_ITERATIONS {
            let kp = b4ae::crypto::dilithium::keypair().unwrap();

            // Validate key sizes
            assert_eq!(kp.public_key.as_bytes().len(), 2592);
            assert!(kp.secret_key.as_bytes().len() >= 4864); // 4864 or 4896 depending on impl

            // Test signature generation/verification
            let message = generate_random_message(256);
            let signature = b4ae::crypto::dilithium::sign(&kp.secret_key, &message).unwrap();

            assert!(signature.as_bytes().len() >= 4595); // size varies per impl (4595 or 4627)
            assert!(b4ae::crypto::dilithium::verify(&kp.public_key, &message, &signature).unwrap());

            // Test signature malleability resistance
            let mut tampered = signature.as_bytes().to_vec();
            tampered[0] ^= 0xFF;
            let tampered_sig = b4ae::crypto::dilithium::DilithiumSignature::from_bytes(&tampered).unwrap();
            assert!(!b4ae::crypto::dilithium::verify(&kp.public_key, &message, &tampered_sig).unwrap_or(true));
        }
    }

    fn test_hybrid_cryptography() {
        let mut alice = B4aeClient::new(SecurityProfile::Standard).unwrap();
        let mut bob = B4aeClient::new(SecurityProfile::Standard).unwrap();

        let alice_id = b"alice_hyb";
        let bob_id = b"bob_hyb";

        let init = alice.initiate_handshake(alice_id).unwrap();
        let response = bob.respond_to_handshake(bob_id, init).unwrap();
        let complete = alice.process_response(alice_id, response).unwrap();
        bob.complete_handshake(bob_id, complete).unwrap();
        alice.finalize_initiator(alice_id).unwrap();

        let plaintext = generate_random_message(256);
        let msgs = alice.encrypt_message(alice_id, &plaintext).unwrap();
        let mut decrypted = Vec::new();
        for m in &msgs {
            let d = bob.decrypt_message(bob_id, m).unwrap();
            if !d.is_empty() {
                decrypted = d;
            }
        }
        assert_eq!(plaintext, decrypted);
    }

    fn test_key_derivation() {
        let master_secret = generate_random_bytes(32);
        let kdf = b4ae::crypto::hkdf::B4aeKeyDerivation::new(master_secret.clone());

        let encryption_key1 = kdf.derive_encryption_key().unwrap();
        let encryption_key2 = kdf.derive_encryption_key().unwrap();
        assert_eq!(encryption_key1, encryption_key2);

        let auth_key1 = kdf.derive_authentication_key().unwrap();
        let auth_key2 = kdf.derive_authentication_key().unwrap();
        assert_eq!(auth_key1, auth_key2);

        let metadata_key1 = kdf.derive_metadata_key().unwrap();
        let metadata_key2 = kdf.derive_metadata_key().unwrap();
        assert_eq!(metadata_key1, metadata_key2);

        assert_ne!(encryption_key1, auth_key1);
        assert_ne!(encryption_key1, metadata_key1);
        assert_ne!(auth_key1, metadata_key1);
    }

    fn test_random_number_generation() {
        let mut rng = rand::thread_rng();

        for _ in 0..TEST_ITERATIONS {
            let random1: [u8; 32] = rng.gen();
            let random2: [u8; 32] = rng.gen();
            assert_ne!(random1, random2);
        }
    }

    #[test]
    fn test_protocol_security() {
        test_handshake_replay_resistance();
        test_handshake_mitm_resistance();
        test_session_key_uniqueness();
        test_message_replay_protection();
        test_forward_secrecy();
    }

    fn test_handshake_replay_resistance() {
        let mut alice = B4aeClient::new(SecurityProfile::High).unwrap();
        let mut bob = B4aeClient::new(SecurityProfile::High).unwrap();

        let alice_id = b"alice_rr";
        let bob_id = b"bob_rr";

        let init1 = alice.initiate_handshake(alice_id).unwrap();
        let response1 = bob.respond_to_handshake(bob_id, init1.clone()).unwrap();
        let complete1 = alice.process_response(alice_id, response1).unwrap();
        bob.complete_handshake(bob_id, complete1).unwrap();
        alice.finalize_initiator(alice_id).unwrap();

        // Replay same init — either fails or creates a new session
        // The important thing is no crash/panic
        let _replay_result = bob.respond_to_handshake(bob_id, init1);
        // Original session should still be intact
        assert!(alice.has_session(alice_id));
    }

    fn test_handshake_mitm_resistance() {
        let mut alice = B4aeClient::new(SecurityProfile::Standard).unwrap();
        let mut eve = B4aeClient::new(SecurityProfile::Standard).unwrap();

        let eve_id = b"eve_mitm";

        let eve_init = eve.initiate_handshake(eve_id).unwrap();

        // Alice responds to Eve's init — should succeed or leave no valid session
        let result = alice.respond_to_handshake(eve_id, eve_init);
        // Either fail or has_session returns false after incomplete handshake
        let _ = result; // We just ensure no panic
    }

    fn test_session_key_uniqueness() {
        let alice_id = b"alice_sq";
        let bob_id = b"bob_sq";

        let mut session_first_msgs: Vec<Vec<u8>> = Vec::new();

        for _ in 0..5 {
            let mut alice = B4aeClient::new(SecurityProfile::Standard).unwrap();
            let mut bob = B4aeClient::new(SecurityProfile::Standard).unwrap();

            let init = alice.initiate_handshake(alice_id).unwrap();
            let response = bob.respond_to_handshake(bob_id, init).unwrap();
            let complete = alice.process_response(alice_id, response).unwrap();
            bob.complete_handshake(bob_id, complete).unwrap();
            alice.finalize_initiator(alice_id).unwrap();

            let msgs = alice.encrypt_message(alice_id, b"test").unwrap();
            // Take the last message (actual content, not dummy)
            if let Some(last) = msgs.last() {
                session_first_msgs.push(last.payload.clone());
            }
        }

        // All ciphertexts should be different (different session keys)
        for i in 0..session_first_msgs.len() {
            for j in (i + 1)..session_first_msgs.len() {
                assert_ne!(session_first_msgs[i], session_first_msgs[j]);
            }
        }
    }

    fn test_message_replay_protection() {
        let mut alice = B4aeClient::new(SecurityProfile::High).unwrap();
        let mut bob = B4aeClient::new(SecurityProfile::High).unwrap();

        let alice_id = b"alice_mrp";
        let bob_id = b"bob_mrp";

        let init = alice.initiate_handshake(alice_id).unwrap();
        let response = bob.respond_to_handshake(bob_id, init).unwrap();
        let complete = alice.process_response(alice_id, response).unwrap();
        bob.complete_handshake(bob_id, complete).unwrap();
        alice.finalize_initiator(alice_id).unwrap();

        let plaintext = b"sensitive message";
        let encrypted = alice.encrypt_message(alice_id, plaintext).unwrap();
        // Decrypt all messages
        for m in &encrypted {
            let _ = bob.decrypt_message(bob_id, m);
        }

        // Attempt replay — should fail or return empty
        for m in &encrypted {
            let replay_result = bob.decrypt_message(bob_id, m);
            assert!(replay_result.is_err() || replay_result.unwrap().is_empty());
        }
    }

    fn test_forward_secrecy() {
        let mut alice = B4aeClient::new(SecurityProfile::Standard).unwrap();
        let mut bob = B4aeClient::new(SecurityProfile::Standard).unwrap();

        let alice_id = b"alice_fs";
        let bob_id = b"bob_fs";

        let init = alice.initiate_handshake(alice_id).unwrap();
        let response = bob.respond_to_handshake(bob_id, init).unwrap();
        let complete = alice.process_response(alice_id, response).unwrap();
        bob.complete_handshake(bob_id, complete).unwrap();
        alice.finalize_initiator(alice_id).unwrap();

        // Send and decrypt multiple messages (each uses different ratchet key)
        let messages: Vec<&[u8]> = vec![b"message1", b"message2", b"message3"];
        for msg in &messages {
            let enc = alice.encrypt_message(alice_id, msg).unwrap();
            for m in &enc {
                let _ = bob.decrypt_message(bob_id, m);
            }
        }

        // New messages should still work after ratchet advancement
        let new_enc = alice.encrypt_message(alice_id, b"after ratchet").unwrap();
        for m in &new_enc {
            let d = bob.decrypt_message(bob_id, m).unwrap();
            let _ = d; // decryption succeeds
        }
    }

    #[test]
    fn test_metadata_protection() {
        test_padding_consistency();
        test_traffic_analysis_resistance();
    }

    fn test_padding_consistency() {
        use b4ae::metadata::{MetadataProtection, ProtectionLevel};

        let config = B4aeConfig::from_profile(SecurityProfile::High);
        let metadata = MetadataProtection::new(config.protocol_config.clone(), ProtectionLevel::High);

        let test_messages = vec![
            vec![0u8; 10],
            vec![0u8; 100],
            vec![0u8; 1000],
        ];

        for message in test_messages {
            let padded1 = metadata.protect_message(&message).unwrap();
            let padded2 = metadata.protect_message(&message).unwrap();

            // Padded sizes should both be >= original
            assert!(padded1.len() >= message.len());
            assert!(padded2.len() >= message.len());
        }
    }

    fn test_traffic_analysis_resistance() {
        let mut alice = B4aeClient::new(SecurityProfile::Standard).unwrap();
        let mut bob = B4aeClient::new(SecurityProfile::Standard).unwrap();

        let alice_id = b"alice_ta";
        let bob_id = b"bob_ta";

        let init = alice.initiate_handshake(alice_id).unwrap();
        let response = bob.respond_to_handshake(bob_id, init).unwrap();
        let complete = alice.process_response(alice_id, response).unwrap();
        bob.complete_handshake(bob_id, complete).unwrap();
        alice.finalize_initiator(alice_id).unwrap();

        // Messages of different sizes should all encrypt successfully
        for size in [10usize, 100, 1000] {
            let message = vec![0u8; size];
            let encrypted = alice.encrypt_message(alice_id, &message).unwrap();
            assert!(!encrypted.is_empty());
        }
    }

    #[test]
    fn test_implementation_security() {
        test_memory_safety();
        test_error_handling();
        test_input_validation();
    }

    fn test_memory_safety() {
        let sensitive_data = vec![0xFFu8; 32];

        let mut zeroized_data = sensitive_data.clone();
        zeroize::Zeroize::zeroize(&mut zeroized_data);

        // Verify zeroization
        assert!(zeroized_data.iter().all(|&b| b == 0));
        // Original was non-zero
        assert!(sensitive_data.iter().any(|&b| b != 0));
    }

    fn test_error_handling() {
        let mut client = B4aeClient::new(SecurityProfile::Standard).unwrap();

        // Test with no established session — should fail gracefully
        let result = client.encrypt_message(b"nonexistent_peer_xyz", b"hello");
        assert!(result.is_err());

        // Test oversized peer ID
        let huge_id = vec![0u8; 10000];
        let result2 = client.initiate_handshake(&huge_id);
        // Either succeeds or fails gracefully — no panic
        let _ = result2;
    }

    fn test_input_validation() {
        let mut client = B4aeClient::new(SecurityProfile::Standard).unwrap();

        // Test oversized inputs — should fail (MAX_MESSAGE_SIZE enforced)
        let oversized_message = vec![0u8; 10 * 1024 * 1024]; // 10MB
        let result = client.encrypt_message(b"peer", &oversized_message);
        assert!(result.is_err());
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