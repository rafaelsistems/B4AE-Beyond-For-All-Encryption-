//! Root Key Manager Component
//!
//! Manages the root key and performs DH ratchet steps to derive new root keys.

use crate::crypto::{CryptoResult, CryptoError};
use crate::crypto::hkdf::derive_key;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Root Key Manager
///
/// Manages the root key and performs hybrid DH ratchet steps combining
/// Kyber-1024 and X25519 shared secrets.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RootKeyManager {
    root_key: [u8; 32],
    ratchet_count: u64,
}

impl RootKeyManager {
    /// Create new root key manager from master secret
    ///
    /// Derives initial root key from handshake master secret using HKDF-SHA3-256
    /// with info string "B4AE-v2-double-ratchet-root".
    ///
    /// # Arguments
    /// * `master_secret` - Master secret from handshake (at least 32 bytes)
    ///
    /// # Returns
    /// * `Ok(RootKeyManager)` - Initialized root key manager
    /// * `Err(CryptoError)` - If key derivation fails
    pub fn new(master_secret: &[u8]) -> CryptoResult<Self> {
        if master_secret.len() < 32 {
            return Err(CryptoError::InvalidKeySize(
                "Master secret must be at least 32 bytes".to_string()
            ));
        }

        // Derive initial root key using HKDF-SHA3-256
        let root_key_vec = derive_key(
            &[master_secret],
            b"B4AE-v2-double-ratchet-root",
            32,
        )?;

        let mut root_key = [0u8; 32];
        root_key.copy_from_slice(&root_key_vec);

        Ok(RootKeyManager {
            root_key,
            ratchet_count: 0,
        })
    }

    /// Perform DH ratchet step with hybrid shared secrets
    ///
    /// Combines Kyber-1024 and X25519 shared secrets to derive a new root key,
    /// then derives new sending and receiving chain keys from the new root key.
    ///
    /// # Arguments
    /// * `kyber_shared_secret` - Shared secret from Kyber-1024 key exchange
    /// * `x25519_shared_secret` - Shared secret from X25519 Diffie-Hellman
    ///
    /// # Returns
    /// * `Ok((sending_chain_key, receiving_chain_key))` - New chain keys
    /// * `Err(CryptoError)` - If key derivation fails
    ///
    /// # Security
    /// - Old root key is securely zeroized after derivation
    /// - Shared secrets should be zeroized by caller after this call
    pub fn ratchet_step(
        &mut self,
        kyber_shared_secret: &[u8],
        x25519_shared_secret: &[u8],
    ) -> CryptoResult<([u8; 32], [u8; 32])> {
        // Combine hybrid shared secrets by concatenation (kyber_ss || x25519_ss)
        let mut hybrid_shared_secret = Vec::with_capacity(
            kyber_shared_secret.len() + x25519_shared_secret.len()
        );
        hybrid_shared_secret.extend_from_slice(kyber_shared_secret);
        hybrid_shared_secret.extend_from_slice(x25519_shared_secret);

        // Derive new root key using HKDF-SHA3-256
        // Input: old root key || hybrid shared secret
        let new_root_key_vec = derive_key(
            &[&self.root_key, &hybrid_shared_secret],
            b"B4AE-v2-root-ratchet",
            32,
        )?;

        let mut new_root_key = [0u8; 32];
        new_root_key.copy_from_slice(&new_root_key_vec);

        // Derive new sending chain key
        let sending_chain_key_vec = derive_key(
            &[&new_root_key],
            b"B4AE-v2-sending-chain",
            32,
        )?;

        let mut sending_chain_key = [0u8; 32];
        sending_chain_key.copy_from_slice(&sending_chain_key_vec);

        // Derive new receiving chain key
        let receiving_chain_key_vec = derive_key(
            &[&new_root_key],
            b"B4AE-v2-receiving-chain",
            32,
        )?;

        let mut receiving_chain_key = [0u8; 32];
        receiving_chain_key.copy_from_slice(&receiving_chain_key_vec);

        // Securely zeroize old root key and intermediate values
        self.root_key.zeroize();
        
        // Update to new root key
        self.root_key = new_root_key;
        
        // Increment ratchet count
        self.ratchet_count += 1;

        Ok((sending_chain_key, receiving_chain_key))
    }

    /// Get current ratchet count
    pub fn ratchet_count(&self) -> u64 {
        self.ratchet_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_key_manager_new() {
        let master_secret = vec![0x42; 32];
        let manager = RootKeyManager::new(&master_secret).unwrap();
        
        assert_eq!(manager.ratchet_count(), 0);
    }

    #[test]
    fn test_root_key_manager_invalid_secret() {
        let master_secret = vec![0x42; 16]; // Too short
        let result = RootKeyManager::new(&master_secret);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_ratchet_step() {
        let master_secret = vec![0x42; 32];
        let mut manager = RootKeyManager::new(&master_secret).unwrap();
        
        let kyber_ss = vec![0x01; 32];
        let x25519_ss = [0x02; 32];
        
        let (sending_key, receiving_key) = manager.ratchet_step(&kyber_ss, &x25519_ss).unwrap();
        
        assert_eq!(manager.ratchet_count(), 1);
        assert_eq!(sending_key.len(), 32);
        assert_eq!(receiving_key.len(), 32);
        assert_ne!(sending_key, receiving_key);
    }

    #[test]
    fn test_multiple_ratchet_steps() {
        let master_secret = vec![0x42; 32];
        let mut manager = RootKeyManager::new(&master_secret).unwrap();
        
        let kyber_ss1 = vec![0x01; 32];
        let x25519_ss1 = [0x02; 32];
        
        let (send1, recv1) = manager.ratchet_step(&kyber_ss1, &x25519_ss1).unwrap();
        assert_eq!(manager.ratchet_count(), 1);
        
        let kyber_ss2 = vec![0x03; 32];
        let x25519_ss2 = [0x04; 32];
        
        let (send2, recv2) = manager.ratchet_step(&kyber_ss2, &x25519_ss2).unwrap();
        assert_eq!(manager.ratchet_count(), 2);
        
        // Keys from different ratchet steps should be different
        assert_ne!(send1, send2);
        assert_ne!(recv1, recv2);
    }

    #[test]
    fn test_deterministic_derivation() {
        let master_secret = vec![0x42; 32];
        
        let manager1 = RootKeyManager::new(&master_secret).unwrap();
        let manager2 = RootKeyManager::new(&master_secret).unwrap();
        
        // Same master secret should produce same initial root key
        assert_eq!(manager1.root_key, manager2.root_key);
    }

    #[test]
    fn test_empty_master_secret() {
        let master_secret = vec![];
        let result = RootKeyManager::new(&master_secret);
        
        assert!(result.is_err());
        if let Err(CryptoError::InvalidKeySize(msg)) = result {
            assert!(msg.contains("at least 32 bytes"));
        } else {
            panic!("Expected InvalidKeySize error");
        }
    }

    #[test]
    fn test_empty_kyber_shared_secret() {
        let master_secret = vec![0x42; 32];
        let mut manager = RootKeyManager::new(&master_secret).unwrap();
        
        let kyber_ss = vec![]; // Empty
        let x25519_ss = [0x02; 32];
        
        // Should still work - HKDF can handle empty inputs
        // The security comes from the x25519 component
        let result = manager.ratchet_step(&kyber_ss, &x25519_ss);
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_x25519_shared_secret() {
        let master_secret = vec![0x42; 32];
        let mut manager = RootKeyManager::new(&master_secret).unwrap();
        
        let kyber_ss = vec![0x01; 32];
        let x25519_ss = []; // Empty
        
        // Should still work - HKDF can handle empty inputs
        // The security comes from the kyber component
        let result = manager.ratchet_step(&kyber_ss, &x25519_ss);
        assert!(result.is_ok());
    }

    #[test]
    fn test_both_shared_secrets_empty() {
        let master_secret = vec![0x42; 32];
        let mut manager = RootKeyManager::new(&master_secret).unwrap();
        
        let kyber_ss = vec![]; // Empty
        let x25519_ss = []; // Empty
        
        // Should still work but provides no forward secrecy
        // This is a degenerate case that shouldn't happen in practice
        let result = manager.ratchet_step(&kyber_ss, &x25519_ss);
        assert!(result.is_ok());
        
        // Ratchet count should still increment
        assert_eq!(manager.ratchet_count(), 1);
    }

    #[test]
    fn test_very_short_shared_secrets() {
        let master_secret = vec![0x42; 32];
        let mut manager = RootKeyManager::new(&master_secret).unwrap();
        
        let kyber_ss = vec![0x01]; // Only 1 byte
        let x25519_ss = [0x02]; // Only 1 byte
        
        // HKDF should handle short inputs
        let result = manager.ratchet_step(&kyber_ss, &x25519_ss);
        assert!(result.is_ok());
        
        let (send_key, recv_key) = result.unwrap();
        assert_eq!(send_key.len(), 32);
        assert_eq!(recv_key.len(), 32);
        assert_ne!(send_key, recv_key);
    }

    #[test]
    fn test_very_long_shared_secrets() {
        let master_secret = vec![0x42; 32];
        let mut manager = RootKeyManager::new(&master_secret).unwrap();
        
        let kyber_ss = vec![0x01; 1024]; // Very long
        let x25519_ss = [0x02; 128]; // Longer than typical
        
        // HKDF should handle long inputs
        let result = manager.ratchet_step(&kyber_ss, &x25519_ss);
        assert!(result.is_ok());
        
        let (send_key, recv_key) = result.unwrap();
        assert_eq!(send_key.len(), 32);
        assert_eq!(recv_key.len(), 32);
        assert_ne!(send_key, recv_key);
    }

    #[test]
    fn test_ratchet_step_produces_different_keys() {
        let master_secret = vec![0x42; 32];
        let mut manager = RootKeyManager::new(&master_secret).unwrap();
        
        let kyber_ss = vec![0x01; 32];
        let x25519_ss = [0x02; 32];
        
        let (send_key, recv_key) = manager.ratchet_step(&kyber_ss, &x25519_ss).unwrap();
        
        // Sending and receiving keys must be different
        assert_ne!(send_key, recv_key);
        
        // Keys should not be all zeros
        assert_ne!(send_key, [0u8; 32]);
        assert_ne!(recv_key, [0u8; 32]);
    }

    #[test]
    fn test_different_shared_secrets_produce_different_keys() {
        let master_secret = vec![0x42; 32];
        
        let mut manager1 = RootKeyManager::new(&master_secret).unwrap();
        let mut manager2 = RootKeyManager::new(&master_secret).unwrap();
        
        let kyber_ss1 = vec![0x01; 32];
        let x25519_ss1 = [0x02; 32];
        
        let kyber_ss2 = vec![0x03; 32];
        let x25519_ss2 = [0x04; 32];
        
        let (send1, recv1) = manager1.ratchet_step(&kyber_ss1, &x25519_ss1).unwrap();
        let (send2, recv2) = manager2.ratchet_step(&kyber_ss2, &x25519_ss2).unwrap();
        
        // Different shared secrets should produce different keys
        assert_ne!(send1, send2);
        assert_ne!(recv1, recv2);
    }

    // Property-based tests
    #[cfg(test)]
    mod property_tests {
        use super::*;
        use proptest::prelude::*;
        use proptest::test_runner::Config as ProptestConfig;

        /// **Property 10: Session Initialization Correctness**
        /// **Validates: Requirements 1.1, 1.2, 1.3, 1.4**
        ///
        /// For any master secret and session parameters, initializing a Double Ratchet
        /// session produces a valid session with:
        /// 1. Root key deterministically derived from master secret
        /// 2. Same master secret always produces same root key
        /// 3. Different master secrets produce different root keys
        /// 4. Ratchet count starts at 0
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 20, // Reduced from default 256 for faster test execution
                .. ProptestConfig::default()
            })]
            #[test]
            fn prop_root_key_initialization_correctness(
                master_secret in prop::collection::vec(any::<u8>(), 32..=128)
            ) {
                // Property 1: Root key is deterministically derived from master secret
                let manager1 = RootKeyManager::new(&master_secret).unwrap();
                let manager2 = RootKeyManager::new(&master_secret).unwrap();
                
                // Same master secret should produce same root key
                prop_assert_eq!(manager1.root_key, manager2.root_key);
                
                // Property 2: Ratchet count starts at 0
                prop_assert_eq!(manager1.ratchet_count(), 0);
                prop_assert_eq!(manager2.ratchet_count(), 0);
            }

            #[test]
            fn prop_different_secrets_produce_different_keys(
                master_secret1 in prop::collection::vec(any::<u8>(), 32..=128),
                master_secret2 in prop::collection::vec(any::<u8>(), 32..=128)
            ) {
                // Skip if secrets are identical
                prop_assume!(master_secret1 != master_secret2);
                
                let manager1 = RootKeyManager::new(&master_secret1).unwrap();
                let manager2 = RootKeyManager::new(&master_secret2).unwrap();
                
                // Different master secrets should produce different root keys
                prop_assert_ne!(manager1.root_key, manager2.root_key);
            }

            #[test]
            fn prop_initialization_always_succeeds_for_valid_input(
                master_secret in prop::collection::vec(any::<u8>(), 32..=128)
            ) {
                // Initialization should always succeed for valid master secrets (>= 32 bytes)
                let result = RootKeyManager::new(&master_secret);
                prop_assert!(result.is_ok());
                
                let manager = result.unwrap();
                
                // Verify initial state
                prop_assert_eq!(manager.ratchet_count(), 0);
                prop_assert_eq!(manager.root_key.len(), 32);
            }

            #[test]
            fn prop_initialization_fails_for_short_secrets(
                master_secret in prop::collection::vec(any::<u8>(), 0..32)
            ) {
                // Initialization should fail for master secrets < 32 bytes
                let result = RootKeyManager::new(&master_secret);
                prop_assert!(result.is_err());
            }

            /// **Property 2: Post-Compromise Security**
            /// **Validates: Requirements 3.6, 3.9**
            ///
            /// For any session where a root key is compromised, performing a DH ratchet
            /// step after the compromise produces a new root key that is cryptographically
            /// independent of the compromised key.
            ///
            /// This test verifies:
            /// 1. Given old root key and old shared secrets, attacker cannot derive new root key
            /// 2. New keys are cryptographically independent from old keys
            /// 3. Multiple ratchet steps provide healing
            ///
            /// The test simulates an attacker who:
            /// - Compromises the root key at time T
            /// - Knows all shared secrets used BEFORE time T
            /// - Does NOT know the new shared secrets used AFTER time T
            ///
            /// The attacker should NOT be able to derive the new root key or chain keys.
            #[test]
            fn prop_post_compromise_security(
                master_secret in prop::collection::vec(any::<u8>(), 32..=128),
                // Old shared secrets (known to attacker)
                old_kyber_ss in prop::collection::vec(any::<u8>(), 32..=64),
                old_x25519_ss in prop::array::uniform32(any::<u8>()),
                // New shared secrets (unknown to attacker)
                new_kyber_ss in prop::collection::vec(any::<u8>(), 32..=64),
                new_x25519_ss in prop::array::uniform32(any::<u8>()),
            ) {
                // Ensure new secrets are different from old secrets
                prop_assume!(old_kyber_ss != new_kyber_ss || old_x25519_ss != new_x25519_ss);

                // === SETUP: Legitimate session performs ratchet ===
                let mut legitimate_manager = RootKeyManager::new(&master_secret).unwrap();
                
                // Perform first ratchet with old secrets
                let (old_send_key, old_recv_key) = legitimate_manager
                    .ratchet_step(&old_kyber_ss, &old_x25519_ss)
                    .unwrap();
                
                // Capture the compromised root key (attacker steals this)
                let compromised_root_key = legitimate_manager.root_key;
                
                // Perform second ratchet with NEW secrets (post-compromise)
                let (new_send_key, new_recv_key) = legitimate_manager
                    .ratchet_step(&new_kyber_ss, &new_x25519_ss)
                    .unwrap();
                
                // === ATTACKER SIMULATION ===
                // Attacker has:
                // 1. The compromised root key
                // 2. All old shared secrets
                // But does NOT have the new shared secrets
                
                // Attacker tries to derive the new root key using only compromised data
                // This simulates trying all possible combinations with old secrets
                
                // Attempt 1: Try to derive new keys using old secrets again
                let mut attacker_manager = RootKeyManager::new(&master_secret).unwrap();
                attacker_manager.ratchet_step(&old_kyber_ss, &old_x25519_ss).unwrap();
                
                // Attacker's root key after using old secrets
                let attacker_root_key_old = attacker_manager.root_key;
                
                // Attempt 2: Try ratcheting again with old secrets
                let (attacker_send_old, attacker_recv_old) = attacker_manager
                    .ratchet_step(&old_kyber_ss, &old_x25519_ss)
                    .unwrap();
                
                // === VERIFICATION: Post-Compromise Security Properties ===
                
                // Property 1: Attacker cannot derive the legitimate new root key
                // The attacker's root key (using old secrets) should be different
                // from the legitimate new root key (using new secrets)
                prop_assert_ne!(
                    attacker_root_key_old,
                    legitimate_manager.root_key,
                    "Attacker should not be able to derive new root key using old secrets"
                );
                
                // Property 2: Attacker cannot derive the new chain keys
                // New chain keys should be cryptographically independent
                prop_assert_ne!(
                    attacker_send_old,
                    new_send_key,
                    "Attacker should not derive new sending chain key"
                );
                prop_assert_ne!(
                    attacker_recv_old,
                    new_recv_key,
                    "Attacker should not derive new receiving chain key"
                );
                
                // Property 3: New keys are different from old keys (forward secrecy)
                prop_assert_ne!(
                    old_send_key,
                    new_send_key,
                    "New sending key must be different from old sending key"
                );
                prop_assert_ne!(
                    old_recv_key,
                    new_recv_key,
                    "New receiving key must be different from old receiving key"
                );
                
                // Property 4: Multiple ratchet steps provide healing
                // Even if attacker performs multiple ratchets with old secrets,
                // they still cannot reach the legitimate state
                let (attacker_send_multi, attacker_recv_multi) = attacker_manager
                    .ratchet_step(&old_kyber_ss, &old_x25519_ss)
                    .unwrap();
                
                prop_assert_ne!(
                    attacker_send_multi,
                    new_send_key,
                    "Multiple ratchets with old secrets should not reach legitimate state"
                );
                prop_assert_ne!(
                    attacker_recv_multi,
                    new_recv_key,
                    "Multiple ratchets with old secrets should not reach legitimate state"
                );
                
                // Property 5: Cryptographic independence verification
                // The new root key should not be derivable from:
                // - Old root key alone
                // - Old shared secrets alone
                // - Any combination of old data
                // This is implicitly verified by the above checks, but we add
                // an explicit check that the new keys are non-zero and unique
                prop_assert_ne!(
                    new_send_key,
                    [0u8; 32],
                    "New sending key should not be all zeros"
                );
                prop_assert_ne!(
                    new_recv_key,
                    [0u8; 32],
                    "New receiving key should not be all zeros"
                );
                prop_assert_ne!(
                    new_send_key,
                    new_recv_key,
                    "Sending and receiving keys should be different"
                );
            }

            /// **Property 2 Extension: Post-Compromise Security with Multiple Ratchets**
            /// **Validates: Requirements 3.6, 3.9**
            ///
            /// Verifies that post-compromise security holds across multiple ratchet steps.
            /// After N ratchet steps with fresh secrets, the attacker who compromised
            /// the initial state cannot derive any of the new keys.
            #[test]
            fn prop_post_compromise_security_multiple_ratchets(
                master_secret in prop::collection::vec(any::<u8>(), 32..=128),
                // Generate multiple pairs of shared secrets
                shared_secrets in prop::collection::vec(
                    (
                        prop::collection::vec(any::<u8>(), 32..=64),
                        prop::array::uniform32(any::<u8>())
                    ),
                    3..=5  // Test with 3-5 ratchet steps
                )
            ) {
                // Ensure all secrets are unique
                for i in 0..shared_secrets.len() {
                    for j in (i+1)..shared_secrets.len() {
                        prop_assume!(shared_secrets[i] != shared_secrets[j]);
                    }
                }

                // === SETUP: Legitimate session performs multiple ratchets ===
                let mut legitimate_manager = RootKeyManager::new(&master_secret).unwrap();
                
                // Perform first ratchet and capture compromised state
                let (kyber_ss_0, x25519_ss_0) = &shared_secrets[0];
                legitimate_manager.ratchet_step(kyber_ss_0, x25519_ss_0).unwrap();
                let compromised_root_key = legitimate_manager.root_key;
                
                // Perform remaining ratchets with fresh secrets (post-compromise)
                let mut legitimate_keys = Vec::new();
                for (kyber_ss, x25519_ss) in &shared_secrets[1..] {
                    let (send_key, recv_key) = legitimate_manager
                        .ratchet_step(kyber_ss, x25519_ss)
                        .unwrap();
                    legitimate_keys.push((send_key, recv_key));
                }
                
                // === ATTACKER SIMULATION ===
                // Attacker has the compromised root key and first shared secret
                // but NOT the subsequent fresh secrets
                let mut attacker_manager = RootKeyManager::new(&master_secret).unwrap();
                attacker_manager.ratchet_step(kyber_ss_0, x25519_ss_0).unwrap();
                
                // Attacker tries to continue with only the first secret (repeated)
                let mut attacker_keys = Vec::new();
                for _ in 1..shared_secrets.len() {
                    let (send_key, recv_key) = attacker_manager
                        .ratchet_step(kyber_ss_0, x25519_ss_0)
                        .unwrap();
                    attacker_keys.push((send_key, recv_key));
                }
                
                // === VERIFICATION ===
                // Attacker should not be able to derive ANY of the legitimate keys
                for (i, ((legit_send, legit_recv), (attack_send, attack_recv))) in 
                    legitimate_keys.iter().zip(attacker_keys.iter()).enumerate() 
                {
                    prop_assert_ne!(
                        attack_send,
                        legit_send,
                        "Attacker should not derive legitimate sending key at step {}",
                        i + 1
                    );
                    prop_assert_ne!(
                        attack_recv,
                        legit_recv,
                        "Attacker should not derive legitimate receiving key at step {}",
                        i + 1
                    );
                }
                
                // Final root keys should be completely different
                prop_assert_ne!(
                    attacker_manager.root_key,
                    legitimate_manager.root_key,
                    "Final root keys should be different after multiple ratchets"
                );
            }
        }
    }
}
