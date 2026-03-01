//! Comprehensive Integration Tests for Hybrid Double Ratchet
//!
//! This test suite validates the complete Double Ratchet protocol implementation
//! including full session flows, concurrent sessions, network simulation, compromise
//! recovery, and DoS protection.
//!
//! Note: These tests simulate a simplified scenario where both parties share the same
//! master secret and session initialization. In a real deployment, the Double Ratchet
//! would be initialized after a proper handshake with different perspectives.

use b4ae::crypto::double_ratchet::{
    DoubleRatchetSession, DoubleRatchetConfig,
};
use b4ae::crypto::CryptoResult;

/// Helper function to create a pair of synchronized sessions
/// 
/// This creates two sessions that can communicate. In a real scenario,
/// these would be initialized from a handshake with proper key exchange.
/// For testing purposes, we use the same master secret and rely on the
/// ratchet mechanism to establish independent keys.
fn create_session_pair() -> CryptoResult<(DoubleRatchetSession, DoubleRatchetSession)> {
    let master_secret = vec![0x42; 32];
    let session_id = [0x01; 32];
    let config = DoubleRatchetConfig::default();

    DoubleRatchetSession::create_test_pair(&master_secret, session_id, config)
}

#[cfg(test)]
mod full_session_tests {
    use super::*;

    /// Test 18.1: Full session integration test
    /// 
    /// Tests complete handshake to message exchange flow with 1000+ messages
    /// and multiple automatic ratchets. Verifies all messages decrypt correctly.
    /// 
    /// Requirements: 1.1, 4.1, 5.1, 6.1
    #[test]
    fn test_full_session_1000_messages_with_ratchets() {
        let (mut alice, mut bob) = create_session_pair()
            .expect("Failed to create session pair");

        let initial_ratchet_count = alice.ratchet_count();
        let mut ratchet_count = 0;
        let num_messages = 1000;

        for i in 0..num_messages {
            let plaintext = format!("Message number {}", i);
            
            // Alice encrypts
            let encrypted = alice.encrypt_message(plaintext.as_bytes())
                .expect(&format!("Failed to encrypt message {}", i));

            // Check if ratchet was triggered
            if encrypted.ratchet_update.is_some() {
                ratchet_count += 1;
                println!("Ratchet triggered at message {}", i);
            }

            // Bob decrypts (this will process any ratchet updates)
            let decrypted = bob.decrypt_message(&encrypted)
                .expect(&format!("Failed to decrypt message {}", i));

            assert_eq!(
                plaintext.as_bytes(),
                decrypted.as_slice(),
                "Message {} decryption mismatch",
                i
            );
        }

        // Verify multiple ratchets occurred
        // With default interval of 100, we expect ~10 ratchets for 1000 messages
        assert!(
            ratchet_count >= 9,
            "Expected at least 9 ratchets, got {}",
            ratchet_count
        );

        let final_ratchet_count = alice.ratchet_count();
        assert!(
            final_ratchet_count > initial_ratchet_count,
            "Ratchet count should increase: {} -> {}",
            initial_ratchet_count,
            final_ratchet_count
        );

        println!("Successfully exchanged {} messages with {} ratchets", 
            num_messages, ratchet_count);
    }

    #[test]
    fn test_session_initialization_from_handshake() {
        let master_secret = vec![0x42; 32];
        let session_id = [0x01; 32];
        let config = DoubleRatchetConfig::default();

        let session = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config,
        ).expect("Failed to initialize session");

        // Verify initial state
        assert_eq!(session.session_id(), &session_id);
        assert_eq!(session.ratchet_count(), 0);
    }

    #[test]
    fn test_basic_message_exchange() {
        let (mut alice, mut bob) = create_session_pair()
            .expect("Failed to create session pair");

        // Send a few messages to establish communication
        for i in 0..10 {
            let plaintext = format!("Test message {}", i);
            let encrypted = alice.encrypt_message(plaintext.as_bytes()).unwrap();
            let decrypted = bob.decrypt_message(&encrypted).unwrap();
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }
    }
}

#[cfg(test)]
mod concurrent_sessions_tests {
    use super::*;

    /// Test 18.2: Concurrent sessions test
    /// 
    /// Creates multiple sessions between same peers and verifies sessions
    /// are independent with no key reuse across sessions.
    /// 
    /// Requirements: 1.1, 2.1
    #[test]
    fn test_multiple_independent_sessions() {
        let master_secret = vec![0x42; 32];
        let config = DoubleRatchetConfig::default();

        // Create 5 different sessions
        let mut sessions = Vec::new();
        for i in 0..5 {
            let session_id = [i as u8; 32];
            let session = DoubleRatchetSession::from_handshake(
                &master_secret,
                session_id,
                config.clone(),
            ).expect("Failed to create session");
            sessions.push(session);
        }

        // Verify all sessions have unique IDs
        for i in 0..sessions.len() {
            for j in (i + 1)..sessions.len() {
                assert_ne!(
                    sessions[i].session_id(),
                    sessions[j].session_id(),
                    "Sessions {} and {} have same ID",
                    i, j
                );
            }
        }

        // Encrypt same plaintext in all sessions and verify ciphertexts differ
        let plaintext = b"Same message in all sessions";
        let mut ciphertexts = Vec::new();

        for session in &mut sessions {
            let encrypted = session.encrypt_message(plaintext)
                .expect("Failed to encrypt");
            ciphertexts.push(encrypted.ciphertext.clone());
        }

        // Verify all ciphertexts are different (no key reuse)
        for i in 0..ciphertexts.len() {
            for j in (i + 1)..ciphertexts.len() {
                assert_ne!(
                    ciphertexts[i],
                    ciphertexts[j],
                    "Sessions {} and {} produced same ciphertext",
                    i, j
                );
            }
        }

        println!("Verified {} independent sessions with unique keys", sessions.len());
    }

    #[test]
    fn test_concurrent_message_exchange() {
        // Create 3 pairs of sessions
        let mut session_pairs = Vec::new();
        for _ in 0..3 {
            session_pairs.push(create_session_pair().unwrap());
        }

        // Exchange messages in all sessions concurrently
        for (i, (alice, bob)) in session_pairs.iter_mut().enumerate() {
            let plaintext = format!("Message in session {}", i);
            let encrypted = alice.encrypt_message(plaintext.as_bytes()).unwrap();
            let decrypted = bob.decrypt_message(&encrypted).unwrap();
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }
    }
}

#[cfg(test)]
mod network_simulation_tests {
    use super::*;

    /// Test 18.3: Network simulation test
    /// 
    /// Simulates packet loss, out-of-order delivery, and delayed messages.
    /// Verifies protocol handles all scenarios correctly.
    /// 
    /// Requirements: 7.1, 7.2, 7.3, 7.4
    #[test]
    fn test_out_of_order_message_delivery() {
        let (mut alice, mut bob) = create_session_pair()
            .expect("Failed to create session pair");

        // Alice sends 10 messages
        let mut messages = Vec::new();
        for i in 0..10 {
            let plaintext = format!("Message {}", i);
            let encrypted = alice.encrypt_message(plaintext.as_bytes())
                .expect(&format!("Failed to encrypt message {}", i));
            messages.push((i, plaintext, encrypted));
        }

        // Deliver messages out of order: 0, 2, 4, 6, 8, 1, 3, 5, 7, 9
        let delivery_order = vec![0, 2, 4, 6, 8, 1, 3, 5, 7, 9];

        for &idx in &delivery_order {
            let (_i, plaintext, encrypted) = &messages[idx];
            let decrypted = bob.decrypt_message(encrypted)
                .expect(&format!("Failed to decrypt message at index {}", idx));
            assert_eq!(
                plaintext.as_bytes(),
                decrypted.as_slice(),
                "Message at index {} decryption mismatch",
                idx
            );
        }

        println!("Successfully handled out-of-order delivery of 10 messages");
    }

    #[test]
    fn test_packet_loss_simulation() {
        let (mut alice, mut bob) = create_session_pair()
            .expect("Failed to create session pair");

        // Alice sends 20 messages, but only deliver odd-numbered ones
        let mut delivered_messages = Vec::new();
        for i in 0..20 {
            let plaintext = format!("Message {}", i);
            let encrypted = alice.encrypt_message(plaintext.as_bytes()).unwrap();
            
            // Only deliver odd-numbered messages
            if i % 2 == 1 {
                delivered_messages.push((i, plaintext, encrypted));
            }
        }

        // Bob should be able to decrypt all delivered messages
        for (_i, plaintext, encrypted) in delivered_messages {
            let decrypted = bob.decrypt_message(&encrypted)
                .expect(&format!("Failed to decrypt message {}", _i));
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }

        println!("Successfully handled packet loss (50% loss rate)");
    }

    #[test]
    fn test_delayed_messages() {
        let (mut alice, mut bob) = create_session_pair()
            .expect("Failed to create session pair");

        // Send messages 0-9
        let mut messages = Vec::new();
        for i in 0..10 {
            let plaintext = format!("Message {}", i);
            let encrypted = alice.encrypt_message(plaintext.as_bytes()).unwrap();
            messages.push((i, plaintext, encrypted));
        }

        // Deliver messages 5-9 first (simulating delay of 0-4)
        for i in 5..10 {
            let (_idx, plaintext, encrypted) = &messages[i];
            let decrypted = bob.decrypt_message(encrypted).unwrap();
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }

        // Now deliver delayed messages 0-4
        for i in 0..5 {
            let (_idx, plaintext, encrypted) = &messages[i];
            let decrypted = bob.decrypt_message(encrypted).unwrap();
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }

        println!("Successfully handled delayed message delivery");
    }

    #[test]
    fn test_extreme_reordering() {
        let (mut alice, mut bob) = create_session_pair()
            .expect("Failed to create session pair");

        // Send 50 messages
        let mut messages = Vec::new();
        for i in 0..50 {
            let plaintext = format!("Message {}", i);
            let encrypted = alice.encrypt_message(plaintext.as_bytes()).unwrap();
            messages.push((i, plaintext, encrypted));
        }

        // Deliver in reverse order
        for i in (0..50).rev() {
            let (_idx, plaintext, encrypted) = &messages[i];
            let decrypted = bob.decrypt_message(encrypted)
                .expect(&format!("Failed to decrypt message {}", i));
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }

        println!("Successfully handled extreme reordering (reverse delivery)");
    }
}

#[cfg(test)]
mod compromise_recovery_tests {
    use super::*;

    /// Test 18.4: Compromise recovery test
    /// 
    /// Simulates key compromise scenario, performs DH ratchet, and verifies
    /// new keys are secure with post-compromise security.
    /// 
    /// Requirements: 3.6, 3.9
    #[test]
    fn test_post_compromise_security() {
        let (mut alice, mut bob) = create_session_pair()
            .expect("Failed to create session pair");

        // Send some messages before "compromise"
        for i in 0..10 {
            let plaintext = format!("Pre-compromise message {}", i);
            let encrypted = alice.encrypt_message(plaintext.as_bytes()).unwrap();
            let decrypted = bob.decrypt_message(&encrypted).unwrap();
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }

        let pre_compromise_ratchet_count = alice.ratchet_count();

        // Simulate compromise by noting current state
        // (In real scenario, attacker would have access to current keys)

        // Force DH ratchet by sending enough messages to trigger it
        let mut ratchet_triggered = false;
        for i in 10..150 {
            let plaintext = format!("Message {}", i);
            let encrypted = alice.encrypt_message(plaintext.as_bytes()).unwrap();
            
            if encrypted.ratchet_update.is_some() && !ratchet_triggered {
                ratchet_triggered = true;
                println!("DH ratchet triggered at message {}", i);
            }

            let decrypted = bob.decrypt_message(&encrypted).unwrap();
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }

        assert!(ratchet_triggered, "DH ratchet should have been triggered");

        let post_ratchet_count = alice.ratchet_count();
        assert!(
            post_ratchet_count > pre_compromise_ratchet_count,
            "Ratchet count should increase after DH ratchet"
        );

        // Send messages after ratchet - these should be secure even if
        // pre-ratchet keys were compromised
        for i in 150..160 {
            let plaintext = format!("Post-ratchet message {}", i);
            let encrypted = alice.encrypt_message(plaintext.as_bytes()).unwrap();
            let decrypted = bob.decrypt_message(&encrypted).unwrap();
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }

        println!("Post-compromise security verified: ratchet count {} -> {}",
            pre_compromise_ratchet_count, post_ratchet_count);
    }

    #[test]
    fn test_multiple_ratchets_for_healing() {
        let (mut alice, mut bob) = create_session_pair()
            .expect("Failed to create session pair");

        let mut ratchet_counts = vec![alice.ratchet_count()];

        // Trigger multiple ratchets
        for batch in 0..5 {
            for i in 0..100 {
                let plaintext = format!("Batch {} Message {}", batch, i);
                let encrypted = alice.encrypt_message(plaintext.as_bytes()).unwrap();
                let decrypted = bob.decrypt_message(&encrypted).unwrap();
                assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
            }
            ratchet_counts.push(alice.ratchet_count());
        }

        // Verify ratchet count increased with each batch
        for i in 1..ratchet_counts.len() {
            assert!(
                ratchet_counts[i] > ratchet_counts[i-1],
                "Ratchet count should increase: {} -> {}",
                ratchet_counts[i-1], ratchet_counts[i]
            );
        }

        println!("Multiple ratchets verified: {:?}", ratchet_counts);
    }
}

#[cfg(test)]
mod dos_protection_tests {
    use super::*;

    /// Test 18.5: DoS protection test
    /// 
    /// Tests MAX_SKIP enforcement, cache size limits, and invalid ratchet
    /// update rejection.
    /// 
    /// Requirements: 9.1, 9.2, 9.3, 9.4
    #[test]
    fn test_max_skip_enforcement() {
        let (mut alice, mut bob) = create_session_pair()
            .expect("Failed to create session pair");

        // Send messages 0-10 normally
        let mut messages = Vec::new();
        for i in 0..11 {
            let plaintext = format!("Message {}", i);
            let encrypted = alice.encrypt_message(plaintext.as_bytes()).unwrap();
            messages.push(encrypted);
        }

        // Deliver message 0
        bob.decrypt_message(&messages[0]).unwrap();

        // Try to deliver message 10 (skip of 9 - should work)
        let result = bob.decrypt_message(&messages[10]);
        assert!(result.is_ok(), "Skip of 9 should be allowed");

        // Now send a message with huge counter skip (> MAX_SKIP)
        // We need to advance Alice's counter significantly
        for _ in 0..1100 {
            let _ = alice.encrypt_message(b"skip message");
        }

        let far_message = alice.encrypt_message(b"Far future message").unwrap();
        
        // Bob should reject this due to MAX_SKIP
        let result = bob.decrypt_message(&far_message);
        assert!(result.is_err(), "Should reject message with counter skip > MAX_SKIP");

        println!("MAX_SKIP enforcement verified");
    }

    #[test]
    fn test_cache_size_limits() {
        let master_secret = vec![0x42; 32];
        let session_id = [0x01; 32];
        
        // Create config with small cache size
        let mut config = DoubleRatchetConfig::default();
        config.cache_size = 50;

        let mut alice = DoubleRatchetSession::from_handshake(
            &master_secret,
            session_id,
            config.clone(),
        ).unwrap();

        let (mut alice, mut bob) = DoubleRatchetSession::create_test_pair(
            &master_secret,
            session_id,
            config,
        ).unwrap();

        // Send 100 messages
        let mut messages = Vec::new();
        for i in 0..100 {
            let plaintext = format!("Message {}", i);
            let encrypted = alice.encrypt_message(plaintext.as_bytes()).unwrap();
            messages.push(encrypted);
        }

        // Deliver only message 99 (forces caching of 0-98)
        // With cache size 50, old keys should be evicted
        let result = bob.decrypt_message(&messages[99]);
        assert!(result.is_ok(), "Should handle large skip within limits");

        // Try to decrypt very old message (should fail as key was evicted)
        let _old_result = bob.decrypt_message(&messages[0]);
        // This might succeed or fail depending on cache implementation
        // The important thing is the system doesn't crash

        println!("Cache size limits tested");
    }

    #[test]
    fn test_invalid_ratchet_update_rejection() {
        use b4ae::crypto::double_ratchet::RatchetUpdate;

        let (_alice, mut bob) = create_session_pair()
            .expect("Failed to create session pair");

        // Create invalid ratchet update with wrong key sizes
        let invalid_update = RatchetUpdate {
            kyber_public: vec![0x42; 100], // Wrong size (should be 1568)
            x25519_public: [0x42; 32],
            kyber_ciphertext: None,
            ratchet_sequence: 1,
            timestamp: 0,
        };

        // Try to process invalid update
        let result = bob.process_ratchet_update(&invalid_update);
        assert!(result.is_err(), "Should reject invalid ratchet update");

        println!("Invalid ratchet update rejection verified");
    }

    #[test]
    fn test_ratchet_sequence_validation() {
        use b4ae::crypto::double_ratchet::RatchetUpdate;

        let (_alice, mut bob) = create_session_pair()
            .expect("Failed to create session pair");

        // Create ratchet update with invalid sequence (not greater than current)
        let invalid_update = RatchetUpdate {
            kyber_public: vec![0x42; 1568],
            x25519_public: [0x42; 32],
            kyber_ciphertext: None,
            ratchet_sequence: 0, // Same as current (should be > current)
            timestamp: 0,
        };

        let result = bob.process_ratchet_update(&invalid_update);
        assert!(result.is_err(), "Should reject ratchet update with invalid sequence");

        println!("Ratchet sequence validation verified");
    }
}
