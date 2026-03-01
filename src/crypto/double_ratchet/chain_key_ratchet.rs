//! Chain Key Ratchet Component
//!
//! Manages symmetric key chain ratcheting for per-message key derivation.

use crate::crypto::{CryptoResult, CryptoError};
use crate::crypto::hkdf::derive_key;
use super::MAX_SKIP;
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Message Key
///
/// Ephemeral key derived from chain key, used to encrypt/decrypt a single message.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey {
    /// Encryption key for ChaCha20
    pub encryption_key: [u8; 32],
    /// Authentication key for Poly1305
    pub auth_key: [u8; 32],
    /// Message counter this key is for
    pub counter: u64,
}

/// Chain Key Ratchet
///
/// Manages symmetric key chain ratcheting for per-message key derivation.
pub struct ChainKeyRatchet {
    chain_key: [u8; 32],
    message_counter: u64,
    key_cache: HashMap<u64, MessageKey>,
    cache_size_limit: usize,
}

impl ChainKeyRatchet {
    /// Create new chain key ratchet
    ///
    /// # Arguments
    /// * `initial_chain_key` - Initial chain key (32 bytes)
    pub fn new(initial_chain_key: [u8; 32]) -> Self {
        ChainKeyRatchet {
            chain_key: initial_chain_key,
            message_counter: 0,
            key_cache: HashMap::new(),
            cache_size_limit: super::DEFAULT_CACHE_SIZE,
        }
    }

    /// Create new chain key ratchet with custom cache size
    pub fn with_cache_size(initial_chain_key: [u8; 32], cache_size: usize) -> Self {
        ChainKeyRatchet {
            chain_key: initial_chain_key,
            message_counter: 0,
            key_cache: HashMap::new(),
            cache_size_limit: cache_size,
        }
    }

    /// Derive next message key and advance chain
    ///
    /// Derives a unique message key for the current counter, then advances
    /// the chain key using a one-way KDF. The old chain key is securely zeroized.
    ///
    /// # Returns
    /// * `Ok(MessageKey)` - Derived message key
    /// * `Err(CryptoError)` - If key derivation fails
    pub fn next_message_key(&mut self) -> CryptoResult<MessageKey> {
        // Derive message key material (64 bytes) using HKDF-SHA3-256
        let counter_bytes = self.message_counter.to_be_bytes();
        let message_key_material = derive_key(
            &[&self.chain_key, &counter_bytes],
            b"B4AE-v2-message-key",
            64,
        )?;

        // Split into encryption key and auth key
        let mut encryption_key = [0u8; 32];
        let mut auth_key = [0u8; 32];
        encryption_key.copy_from_slice(&message_key_material[0..32]);
        auth_key.copy_from_slice(&message_key_material[32..64]);

        let message_key = MessageKey {
            encryption_key,
            auth_key,
            counter: self.message_counter,
        };

        // Advance chain key (one-way function)
        let next_chain_key_vec = derive_key(
            &[&self.chain_key],
            b"B4AE-v2-chain-advance",
            32,
        )?;

        // Securely zeroize old chain key
        self.chain_key.zeroize();

        // Update to new chain key
        self.chain_key.copy_from_slice(&next_chain_key_vec);

        // Increment message counter
        self.message_counter += 1;

        Ok(message_key)
    }

    /// Get message key for specific counter (out-of-order delivery)
    ///
    /// If the counter is in the cache, returns the cached key.
    /// If the counter is ahead, derives and caches all intermediate keys up to MAX_SKIP.
    ///
    /// # Arguments
    /// * `counter` - Message counter to get key for
    ///
    /// # Returns
    /// * `Ok(Some(MessageKey))` - Message key found or derived
    /// * `Ok(None)` - Counter is behind current counter and not in cache
    /// * `Err(CryptoError)` - If counter skip exceeds MAX_SKIP or derivation fails
    pub fn get_message_key(&mut self, counter: u64) -> CryptoResult<Option<MessageKey>> {
        // Check if key is in cache
        if let Some(key) = self.key_cache.remove(&counter) {
            return Ok(Some(key));
        }

        // If counter is behind current counter, key is not available
        if counter < self.message_counter {
            return Ok(None);
        }

        // If counter is ahead, check DoS protection
        let skip = counter.saturating_sub(self.message_counter);
        if skip > MAX_SKIP {
            return Err(CryptoError::InvalidInput(
                format!("Counter skip too large - potential DoS (skip: {}, max: {})", skip, MAX_SKIP)
            ));
        }

        // Derive and cache all intermediate keys
        while self.message_counter < counter {
            let key = self.next_message_key()?;
            self.cache_key(key);
        }

        // Derive the requested key
        let key = self.next_message_key()?;
        Ok(Some(key))
    }

    /// Cache a message key for out-of-order delivery
    fn cache_key(&mut self, key: MessageKey) {
        // Enforce cache size limit
        if self.key_cache.len() >= self.cache_size_limit {
            // Remove oldest key (lowest counter)
            if let Some(&oldest_counter) = self.key_cache.keys().min() {
                if let Some(mut old_key) = self.key_cache.remove(&oldest_counter) {
                    old_key.encryption_key.zeroize();
                    old_key.auth_key.zeroize();
                }
            }
        }

        self.key_cache.insert(key.counter, key);
    }

    /// Reset chain with new key (after DH ratchet)
    ///
    /// Securely zeroizes the old chain key and all cached keys,
    /// then resets the chain with a new key and counter.
    ///
    /// # Arguments
    /// * `new_chain_key` - New chain key (32 bytes)
    pub fn reset(&mut self, new_chain_key: [u8; 32]) {
        // Securely zeroize old chain key
        self.chain_key.zeroize();

        // Clear and zeroize all cached keys
        for (_, mut key) in self.key_cache.drain() {
            key.encryption_key.zeroize();
            key.auth_key.zeroize();
        }

        // Reset with new chain key
        self.chain_key = new_chain_key;
        self.message_counter = 0;
    }

    /// Cleanup old cached keys
    ///
    /// Removes and zeroizes all cached keys with counters less than the specified counter.
    ///
    /// # Arguments
    /// * `current_counter` - Current message counter
    pub fn cleanup_old_keys(&mut self, current_counter: u64) {
        let keys_to_remove: Vec<u64> = self.key_cache
            .keys()
            .filter(|&&k| k < current_counter)
            .copied()
            .collect();

        for counter in keys_to_remove {
            if let Some(mut key) = self.key_cache.remove(&counter) {
                key.encryption_key.zeroize();
                key.auth_key.zeroize();
            }
        }
    }

    /// Get current message counter
    pub fn message_counter(&self) -> u64 {
        self.message_counter
    }

    /// Get cache size
    pub fn cache_size(&self) -> usize {
        self.key_cache.len()
    }
}

impl Drop for ChainKeyRatchet {
    fn drop(&mut self) {
        self.chain_key.zeroize();
        
        // Zeroize all cached keys
        for (_, mut key) in self.key_cache.drain() {
            key.encryption_key.zeroize();
            key.auth_key.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_key_ratchet_new() {
        let initial_key = [0x42; 32];
        let ratchet = ChainKeyRatchet::new(initial_key);
        
        assert_eq!(ratchet.message_counter(), 0);
        assert_eq!(ratchet.cache_size(), 0);
    }

    #[cfg(test)]
    mod property_tests {
        use super::*;
        use proptest::prelude::*;
        use proptest::test_runner::Config as ProptestConfig;
        use std::collections::HashSet;

        /// **Property 1: Forward Secrecy**
        /// 
        /// **Validates: Requirements 2.3, 2.6**
        /// 
        /// This property verifies that the chain key ratchet provides forward secrecy:
        /// An attacker who compromises the current chain state cannot derive any of the
        /// previous message keys.
        /// 
        /// The test:
        /// 1. Advances the chain N times, collecting all message keys
        /// 2. Captures the "compromised" chain state after N advances
        /// 3. Verifies that an attacker with the compromised state cannot derive
        ///    any of the N previous message keys
        /// 4. Verifies that old chain keys are cryptographically independent from
        ///    the current chain key
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 20, // Reduced from default 256 for faster test execution
                .. ProptestConfig::default()
            })]
            #[test]
            fn prop_forward_secrecy(
                initial_key in prop::array::uniform32(any::<u8>()),
                num_advances in 1u64..100u64
            ) {
                // Phase 1: Advance the chain N times and collect message keys
                let mut ratchet = ChainKeyRatchet::new(initial_key);
                let mut message_keys = Vec::new();
                
                for _ in 0..num_advances {
                    let msg_key = ratchet.next_message_key().unwrap();
                    message_keys.push((
                        msg_key.encryption_key,
                        msg_key.auth_key,
                        msg_key.counter
                    ));
                }
                
                // Phase 2: Capture "compromised" state (current chain key and counter)
                // An attacker who compromises the system at this point has:
                // - The current chain_key
                // - The current message_counter
                let compromised_chain_key = ratchet.chain_key;
                let compromised_counter = ratchet.message_counter();
                
                // Phase 3: Verify forward secrecy - attacker cannot derive previous keys
                // Try to reconstruct previous message keys from compromised state
                // This should be impossible due to one-way KDF
                
                // Attempt 1: Try to derive message keys from compromised chain key
                // (This simulates an attacker trying to reverse the chain)
                for (enc_key, auth_key, counter) in &message_keys {
                    // The compromised chain key should not match any previous message keys
                    prop_assert_ne!(
                        &compromised_chain_key[..],
                        &enc_key[..],
                        "Compromised chain key should not match previous encryption key at counter {}",
                        counter
                    );
                    prop_assert_ne!(
                        &compromised_chain_key[..],
                        &auth_key[..],
                        "Compromised chain key should not match previous auth key at counter {}",
                        counter
                    );
                    
                    // Try to derive the old message key from compromised state
                    // This should fail because the KDF is one-way
                    let counter_bytes = counter.to_be_bytes();
                    let attempted_key_material = derive_key(
                        &[&compromised_chain_key, &counter_bytes],
                        b"B4AE-v2-message-key",
                        64,
                    ).unwrap();
                    
                    let attempted_enc_key = &attempted_key_material[0..32];
                    let attempted_auth_key = &attempted_key_material[32..64];
                    
                    // The derived keys should NOT match the original keys
                    // because the chain key has been advanced
                    prop_assert_ne!(
                        attempted_enc_key,
                        &enc_key[..],
                        "Should not be able to derive previous encryption key from compromised state at counter {}",
                        counter
                    );
                    prop_assert_ne!(
                        attempted_auth_key,
                        &auth_key[..],
                        "Should not be able to derive previous auth key from compromised state at counter {}",
                        counter
                    );
                }
                
                // Phase 4: Verify cryptographic independence
                // Create a new ratchet from the compromised state and verify it produces
                // different keys going forward (not backward)
                let mut attacker_ratchet = ChainKeyRatchet::new(compromised_chain_key);
                
                // The attacker can derive future keys from the compromised state
                // (this is expected - forward secrecy doesn't protect future messages)
                let future_key = attacker_ratchet.next_message_key().unwrap();
                
                // But this future key should not match any of the past keys
                for (enc_key, auth_key, counter) in &message_keys {
                    prop_assert_ne!(
                        future_key.encryption_key,
                        *enc_key,
                        "Future key should not match past encryption key at counter {}",
                        counter
                    );
                    prop_assert_ne!(
                        future_key.auth_key,
                        *auth_key,
                        "Future key should not match past auth key at counter {}",
                        counter
                    );
                }
                
                // Phase 5: Verify that all message keys are unique
                // (This is a secondary property but important for forward secrecy)
                for i in 0..message_keys.len() {
                    for j in (i+1)..message_keys.len() {
                        prop_assert_ne!(
                            message_keys[i].0,
                            message_keys[j].0,
                            "Encryption keys at counters {} and {} should be unique",
                            message_keys[i].2,
                            message_keys[j].2
                        );
                        prop_assert_ne!(
                            message_keys[i].1,
                            message_keys[j].1,
                            "Auth keys at counters {} and {} should be unique",
                            message_keys[i].2,
                            message_keys[j].2
                        );
                    }
                }
            }
        }

        /// **Property 4: Unique Message Keys**
        /// 
        /// **Validates: Requirements 2.1, 2.2**
        /// 
        /// This property verifies that every message key derived from the chain is unique:
        /// - No two messages ever use the same encryption key
        /// - No two messages ever use the same authentication key
        /// - Keys from different counters are always different
        /// - This holds for arbitrary N and arbitrary initial chain keys
        /// 
        /// The test:
        /// 1. Derives N message keys from a chain with random initial state
        /// 2. Verifies all encryption keys are unique (no duplicates)
        /// 3. Verifies all auth keys are unique (no duplicates)
        /// 4. Verifies keys are properly associated with their counters
        /// 5. Tests with various N values and initial chain keys
        proptest! {
            #[test]
            fn prop_unique_message_keys(
                initial_key in prop::array::uniform32(any::<u8>()),
                num_keys in 1u64..200u64
            ) {
                let mut ratchet = ChainKeyRatchet::new(initial_key);
                
                // Derive N message keys
                let mut encryption_keys = HashSet::new();
                let mut auth_keys = HashSet::new();
                let mut counter_to_enc_key = HashMap::new();
                let mut counter_to_auth_key = HashMap::new();
                
                for expected_counter in 0..num_keys {
                    let msg_key = ratchet.next_message_key()
                        .expect("Message key derivation should succeed");
                    
                    // Verify counter is correct
                    prop_assert_eq!(
                        msg_key.counter,
                        expected_counter,
                        "Message key counter should match expected value"
                    );
                    
                    // Check encryption key uniqueness
                    prop_assert!(
                        encryption_keys.insert(msg_key.encryption_key),
                        "Encryption key at counter {} is not unique! This key was already used.",
                        expected_counter
                    );
                    
                    // Check auth key uniqueness
                    prop_assert!(
                        auth_keys.insert(msg_key.auth_key),
                        "Auth key at counter {} is not unique! This key was already used.",
                        expected_counter
                    );
                    
                    // Store keys by counter for additional verification
                    counter_to_enc_key.insert(expected_counter, msg_key.encryption_key);
                    counter_to_auth_key.insert(expected_counter, msg_key.auth_key);
                }
                
                // Verify we have exactly N unique encryption keys
                prop_assert_eq!(
                    encryption_keys.len(),
                    num_keys as usize,
                    "Should have exactly {} unique encryption keys",
                    num_keys
                );
                
                // Verify we have exactly N unique auth keys
                prop_assert_eq!(
                    auth_keys.len(),
                    num_keys as usize,
                    "Should have exactly {} unique auth keys",
                    num_keys
                );
                
                // Additional verification: keys from different counters are different
                // (This is redundant with the HashSet check but provides clearer error messages)
                for i in 0..num_keys {
                    for j in (i+1)..num_keys {
                        let enc_key_i = counter_to_enc_key.get(&i).unwrap();
                        let enc_key_j = counter_to_enc_key.get(&j).unwrap();
                        let auth_key_i = counter_to_auth_key.get(&i).unwrap();
                        let auth_key_j = counter_to_auth_key.get(&j).unwrap();
                        
                        prop_assert_ne!(
                            enc_key_i,
                            enc_key_j,
                            "Encryption keys at counters {} and {} must be different",
                            i, j
                        );
                        
                        prop_assert_ne!(
                            auth_key_i,
                            auth_key_j,
                            "Auth keys at counters {} and {} must be different",
                            i, j
                        );
                    }
                }
                
                // Verify that encryption keys and auth keys are different from each other
                // (A key should not be used for both encryption and authentication)
                for counter in 0..num_keys {
                    let enc_key = counter_to_enc_key.get(&counter).unwrap();
                    let auth_key = counter_to_auth_key.get(&counter).unwrap();
                    
                    prop_assert_ne!(
                        enc_key,
                        auth_key,
                        "Encryption key and auth key at counter {} must be different",
                        counter
                    );
                }
            }
        }

        /// **Property 13: Chain Key Advancement**
        /// 
        /// **Validates: Requirements 2.3, 2.6**
        /// 
        /// This property verifies that chain key advancement is deterministic and irreversible:
        /// - Deriving N message keys advances the chain key N times
        /// - Each advancement produces a new chain key cryptographically independent of the previous one
        /// - The same initial state always produces the same sequence of chain keys
        /// - Chain key advancement is irreversible (cannot go backwards)
        /// - Message counter increments correctly with each advancement
        /// - This holds for arbitrary initial states and advancement counts
        /// 
        /// The test:
        /// 1. Creates two ratchets with the same initial state
        /// 2. Advances both ratchets N times
        /// 3. Verifies both produce identical sequences (determinism)
        /// 4. Verifies each chain key in the sequence is unique (irreversibility)
        /// 5. Verifies message counters increment correctly
        /// 6. Verifies chain keys cannot be reversed (one-way property)
        proptest! {
            #[test]
            fn prop_chain_key_advancement(
                initial_key in prop::array::uniform32(any::<u8>()),
                num_advances in 1u64..100u64
            ) {
                // Phase 1: Create two ratchets with identical initial state
                let mut ratchet1 = ChainKeyRatchet::new(initial_key);
                let mut ratchet2 = ChainKeyRatchet::new(initial_key);
                
                // Phase 2: Advance both ratchets N times and collect chain states
                let mut chain_keys_1 = Vec::new();
                let mut chain_keys_2 = Vec::new();
                let mut message_keys_1 = Vec::new();
                
                for expected_counter in 0..num_advances {
                    // Verify counters are in sync before advancement
                    prop_assert_eq!(
                        ratchet1.message_counter(),
                        expected_counter,
                        "Ratchet 1 counter should be {} before advancement",
                        expected_counter
                    );
                    prop_assert_eq!(
                        ratchet2.message_counter(),
                        expected_counter,
                        "Ratchet 2 counter should be {} before advancement",
                        expected_counter
                    );
                    
                    // Capture chain key before advancement (for uniqueness check)
                    chain_keys_1.push(ratchet1.chain_key);
                    
                    // Advance both ratchets
                    let msg_key_1 = ratchet1.next_message_key()
                        .expect("Ratchet 1 advancement should succeed");
                    let msg_key_2 = ratchet2.next_message_key()
                        .expect("Ratchet 2 advancement should succeed");
                    
                    message_keys_1.push((
                        msg_key_1.encryption_key,
                        msg_key_1.auth_key,
                        msg_key_1.counter
                    ));
                    
                    // Verify determinism: same initial state produces same message keys
                    prop_assert_eq!(
                        msg_key_1.encryption_key,
                        msg_key_2.encryption_key,
                        "Encryption keys should be identical at counter {}",
                        expected_counter
                    );
                    prop_assert_eq!(
                        msg_key_1.auth_key,
                        msg_key_2.auth_key,
                        "Auth keys should be identical at counter {}",
                        expected_counter
                    );
                    prop_assert_eq!(
                        msg_key_1.counter,
                        msg_key_2.counter,
                        "Counters should be identical"
                    );
                    
                    // Verify counter incremented correctly
                    prop_assert_eq!(
                        msg_key_1.counter,
                        expected_counter,
                        "Message key counter should match expected value"
                    );
                    
                    // Capture chain key after advancement
                    chain_keys_2.push(ratchet1.chain_key);
                }
                
                // Phase 3: Verify counters incremented correctly
                prop_assert_eq!(
                    ratchet1.message_counter(),
                    num_advances,
                    "Final counter should equal number of advances"
                );
                prop_assert_eq!(
                    ratchet2.message_counter(),
                    num_advances,
                    "Both ratchets should have same final counter"
                );
                
                // Phase 4: Verify each advancement produces a different chain key
                // (irreversibility - each chain key is unique)
                for i in 0..chain_keys_1.len() {
                    for j in (i+1)..chain_keys_1.len() {
                        prop_assert_ne!(
                            chain_keys_1[i],
                            chain_keys_1[j],
                            "Chain key at position {} should differ from position {}",
                            i, j
                        );
                    }
                }
                
                // Phase 5: Verify chain keys before and after each advancement are different
                for i in 0..num_advances as usize {
                    prop_assert_ne!(
                        chain_keys_1[i],
                        chain_keys_2[i],
                        "Chain key should change after advancement at position {}",
                        i
                    );
                }
                
                // Phase 6: Verify irreversibility - cannot derive previous chain keys
                // from current chain key
                let final_chain_key = ratchet1.chain_key;
                
                for i in 0..chain_keys_1.len() {
                    // The final chain key should not match any previous chain key
                    prop_assert_ne!(
                        final_chain_key,
                        chain_keys_1[i],
                        "Final chain key should not match chain key at position {}",
                        i
                    );
                    
                    // Try to derive a message key from the final chain key using an old counter
                    // This should produce a different key than the original
                    let old_counter = i as u64;
                    let counter_bytes = old_counter.to_be_bytes();
                    let attempted_key_material = derive_key(
                        &[&final_chain_key, &counter_bytes],
                        b"B4AE-v2-message-key",
                        64,
                    ).unwrap();
                    
                    let attempted_enc_key = &attempted_key_material[0..32];
                    let attempted_auth_key = &attempted_key_material[32..64];
                    
                    // The attempted keys should NOT match the original keys
                    // (cannot reverse the chain)
                    prop_assert_ne!(
                        attempted_enc_key,
                        &message_keys_1[i].0[..],
                        "Should not be able to derive old encryption key from final chain key at counter {}",
                        old_counter
                    );
                    prop_assert_ne!(
                        attempted_auth_key,
                        &message_keys_1[i].1[..],
                        "Should not be able to derive old auth key from final chain key at counter {}",
                        old_counter
                    );
                }
                
                // Phase 7: Verify cryptographic independence between chain keys
                // Each chain key should be unpredictable from previous chain keys
                for i in 0..(chain_keys_1.len() - 1) {
                    // Try to predict the next chain key by deriving from current with wrong info
                    let wrong_next = derive_key(
                        &[&chain_keys_1[i]],
                        b"wrong-info-string",
                        32,
                    ).unwrap();
                    
                    let mut wrong_next_array = [0u8; 32];
                    wrong_next_array.copy_from_slice(&wrong_next);
                    
                    // Should not match the actual next chain key
                    prop_assert_ne!(
                        wrong_next_array,
                        chain_keys_2[i],
                        "Chain key advancement should use correct KDF info string"
                    );
                }
                
                // Phase 8: Verify that advancing N times is equivalent to advancing 1 time N times
                // (associativity of chain advancement)
                let mut ratchet3 = ChainKeyRatchet::new(initial_key);
                for _ in 0..num_advances {
                    ratchet3.next_message_key().unwrap();
                }
                
                prop_assert_eq!(
                    ratchet3.chain_key,
                    ratchet1.chain_key,
                    "Chain key after N advancements should be the same regardless of how we count"
                );
                prop_assert_eq!(
                    ratchet3.message_counter(),
                    ratchet1.message_counter(),
                    "Message counter after N advancements should be the same"
                );
            }
        }

        /// **Property 16: Counter Skip Caching**
        /// 
        /// **Validates: Requirements 6.2, 7.3**
        /// 
        /// This property verifies that the chain key ratchet correctly handles out-of-order
        /// messages by caching skipped message keys:
        /// - When receiving message N+K (skipping K messages), all K intermediate keys are cached
        /// - Cached keys can be retrieved for out-of-order messages
        /// - Cache correctly handles multiple skips
        /// - Skips within MAX_SKIP limit work correctly
        /// - This holds for arbitrary skip patterns
        /// 
        /// The test:
        /// 1. Generates random skip patterns (sequences of counter jumps)
        /// 2. For each skip, verifies all intermediate keys are cached
        /// 3. Verifies cached keys can be retrieved in any order
        /// 4. Verifies cache size matches expected number of skipped keys
        /// 5. Verifies skipped keys are identical to keys derived in order
        /// 6. Tests with various skip sizes and patterns
        proptest! {
            #[test]
            fn prop_counter_skip_caching(
                initial_key in prop::array::uniform32(any::<u8>()),
                // Generate a single skip size between 2 and 50
                skip_size in 2u64..50u64
            ) {
                // Phase 1: Create reference ratchet that derives keys in order
                let mut reference_ratchet = ChainKeyRatchet::new(initial_key);
                let mut all_keys_in_order = HashMap::new();
                
                // Derive keys from 0 to skip_size (inclusive)
                for counter in 0..=skip_size {
                    let key = reference_ratchet.next_message_key()
                        .expect("Reference key derivation should succeed");
                    all_keys_in_order.insert(counter, (
                        key.encryption_key,
                        key.auth_key,
                        key.counter
                    ));
                }
                
                // Phase 2: Test single skip - jump directly to skip_size
                let mut test_ratchet = ChainKeyRatchet::new(initial_key);
                
                // Get message key at skip_size (this should cache keys 0 to skip_size-1)
                let key = test_ratchet.get_message_key(skip_size)
                    .expect("Should successfully skip and cache keys");
                
                prop_assert!(
                    key.is_some(),
                    "Should get a key when skipping to counter {}",
                    skip_size
                );
                
                let key = key.unwrap();
                
                // Verify the returned key matches the reference
                let reference_key = all_keys_in_order.get(&skip_size)
                    .expect("Reference should have key at this counter");
                
                prop_assert_eq!(
                    key.encryption_key,
                    reference_key.0,
                    "Encryption key at counter {} should match reference",
                    skip_size
                );
                prop_assert_eq!(
                    key.auth_key,
                    reference_key.1,
                    "Auth key at counter {} should match reference",
                    skip_size
                );
                prop_assert_eq!(
                    key.counter,
                    skip_size,
                    "Key counter should match target counter"
                );
                
                // Verify cache size - should have cached skip_size keys (0 to skip_size-1)
                prop_assert_eq!(
                    test_ratchet.cache_size(),
                    skip_size as usize,
                    "Cache should contain {} keys after skipping to counter {}",
                    skip_size,
                    skip_size
                );
                
                // Phase 3: Verify all cached keys can be retrieved and match reference
                // Test retrieval in reverse order
                for counter in (0..skip_size).rev() {
                    let cached_key = test_ratchet.get_message_key(counter)
                        .expect("Should successfully retrieve cached key");
                    
                    prop_assert!(
                        cached_key.is_some(),
                        "Should have cached key at counter {}",
                        counter
                    );
                    
                    let key = cached_key.unwrap();
                    let reference_key = all_keys_in_order.get(&counter)
                        .expect("Reference should have key at this counter");
                    
                    prop_assert_eq!(
                        key.encryption_key,
                        reference_key.0,
                        "Cached encryption key at counter {} should match reference",
                        counter
                    );
                    prop_assert_eq!(
                        key.auth_key,
                        reference_key.1,
                        "Cached auth key at counter {} should match reference",
                        counter
                    );
                    prop_assert_eq!(
                        key.counter,
                        counter,
                        "Cached key counter should match requested counter"
                    );
                }
                
                // After retrieving all cached keys, cache should be empty
                prop_assert_eq!(
                    test_ratchet.cache_size(),
                    0,
                    "Cache should be empty after retrieving all keys"
                );
                
                // Phase 4: Test multiple skips
                let mut multi_skip_ratchet = ChainKeyRatchet::new(initial_key);
                
                // First skip: 0 -> 5
                multi_skip_ratchet.get_message_key(5)
                    .expect("First skip should succeed");
                prop_assert_eq!(
                    multi_skip_ratchet.cache_size(),
                    5,
                    "Should have 5 cached keys after first skip"
                );
                
                // Second skip: 6 -> 10 (current counter is 6 after consuming key 5)
                multi_skip_ratchet.get_message_key(10)
                    .expect("Second skip should succeed");
                prop_assert_eq!(
                    multi_skip_ratchet.cache_size(),
                    9,
                    "Should have 9 cached keys after second skip (0-4, 6-9)"
                );
                
                // Retrieve a key from the first skip
                let early_key = multi_skip_ratchet.get_message_key(2)
                    .expect("Should retrieve key from first skip");
                prop_assert!(
                    early_key.is_some(),
                    "Should have key from first skip in cache"
                );
                
                // Cache size should decrease by 1
                prop_assert_eq!(
                    multi_skip_ratchet.cache_size(),
                    8,
                    "Cache size should decrease after retrieving a key"
                );
                
                // Phase 5: Test DoS protection
                let mut dos_ratchet = ChainKeyRatchet::new(initial_key);
                let dos_result = dos_ratchet.get_message_key(MAX_SKIP + 1);
                prop_assert!(
                    dos_result.is_err(),
                    "Should fail when skipping more than MAX_SKIP messages"
                );
                
                // Phase 6: Test MAX_SKIP boundary with large cache
                let mut boundary_ratchet = ChainKeyRatchet::with_cache_size(initial_key, MAX_SKIP as usize + 10);
                
                // Skip exactly MAX_SKIP (should succeed)
                let max_skip_result = boundary_ratchet.get_message_key(MAX_SKIP);
                prop_assert!(
                    max_skip_result.is_ok(),
                    "Should succeed when skipping exactly MAX_SKIP messages"
                );
                
                if let Ok(Some(key)) = max_skip_result {
                    prop_assert_eq!(
                        key.counter,
                        MAX_SKIP,
                        "Key counter should be MAX_SKIP"
                    );
                    
                    // Should have cached MAX_SKIP keys (0 to MAX_SKIP-1)
                    prop_assert_eq!(
                        boundary_ratchet.cache_size(),
                        MAX_SKIP as usize,
                        "Should cache exactly MAX_SKIP intermediate keys"
                    );
                }
            }
        }
    }

    #[test]
    fn test_next_message_key() {
        let initial_key = [0x42; 32];
        let mut ratchet = ChainKeyRatchet::new(initial_key);
        
        let key1 = ratchet.next_message_key().unwrap();
        assert_eq!(key1.counter, 0);
        assert_eq!(ratchet.message_counter(), 1);
        
        let key2 = ratchet.next_message_key().unwrap();
        assert_eq!(key2.counter, 1);
        assert_eq!(ratchet.message_counter(), 2);
        
        // Keys should be different
        assert_ne!(key1.encryption_key, key2.encryption_key);
        assert_ne!(key1.auth_key, key2.auth_key);
    }

    #[test]
    fn test_get_message_key_in_order() {
        let initial_key = [0x42; 32];
        let mut ratchet = ChainKeyRatchet::new(initial_key);
        
        let key = ratchet.get_message_key(0).unwrap().unwrap();
        assert_eq!(key.counter, 0);
        assert_eq!(ratchet.message_counter(), 1);
    }

    #[test]
    fn test_get_message_key_skip() {
        let initial_key = [0x42; 32];
        let mut ratchet = ChainKeyRatchet::new(initial_key);
        
        // Skip to counter 5
        let key = ratchet.get_message_key(5).unwrap().unwrap();
        assert_eq!(key.counter, 5);
        assert_eq!(ratchet.message_counter(), 6);
        
        // Should have cached keys 0-4
        assert_eq!(ratchet.cache_size(), 5);
    }

    #[test]
    fn test_get_message_key_dos_protection() {
        let initial_key = [0x42; 32];
        let mut ratchet = ChainKeyRatchet::new(initial_key);
        
        // Try to skip more than MAX_SKIP
        let result = ratchet.get_message_key(MAX_SKIP + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_cached_key() {
        let initial_key = [0x42; 32];
        let mut ratchet = ChainKeyRatchet::new(initial_key);
        
        // Skip to counter 5, caching 0-4
        ratchet.get_message_key(5).unwrap();
        
        // Get cached key
        let key = ratchet.get_message_key(2).unwrap().unwrap();
        assert_eq!(key.counter, 2);
        
        // Cache should have one less key now
        assert_eq!(ratchet.cache_size(), 4);
    }

    #[test]
    fn test_reset() {
        let initial_key = [0x42; 32];
        let mut ratchet = ChainKeyRatchet::new(initial_key);
        
        // Advance counter and cache some keys
        ratchet.get_message_key(5).unwrap();
        assert_eq!(ratchet.message_counter(), 6);
        assert!(ratchet.cache_size() > 0);
        
        // Reset
        let new_key = [0x99; 32];
        ratchet.reset(new_key);
        
        assert_eq!(ratchet.message_counter(), 0);
        assert_eq!(ratchet.cache_size(), 0);
    }

    #[test]
    fn test_cleanup_old_keys() {
        let initial_key = [0x42; 32];
        let mut ratchet = ChainKeyRatchet::new(initial_key);
        
        // Skip to counter 10, caching 0-9
        ratchet.get_message_key(10).unwrap();
        assert_eq!(ratchet.cache_size(), 10);
        
        // Cleanup keys older than 5
        ratchet.cleanup_old_keys(5);
        
        // Should have removed keys 0-4, keeping 5-9
        assert_eq!(ratchet.cache_size(), 5);
    }

    #[test]
    fn test_cache_size_limit() {
        let initial_key = [0x42; 32];
        let mut ratchet = ChainKeyRatchet::with_cache_size(initial_key, 10);
        
        // Skip to counter 20, should cache only last 10 keys
        ratchet.get_message_key(20).unwrap();
        
        // Cache should not exceed limit
        assert!(ratchet.cache_size() <= 10);
    }

    #[test]
    fn test_deterministic_derivation() {
        let initial_key = [0x42; 32];
        
        let mut ratchet1 = ChainKeyRatchet::new(initial_key);
        let mut ratchet2 = ChainKeyRatchet::new(initial_key);
        
        let key1 = ratchet1.next_message_key().unwrap();
        let key2 = ratchet2.next_message_key().unwrap();
        
        // Same initial key should produce same message keys
        assert_eq!(key1.encryption_key, key2.encryption_key);
        assert_eq!(key1.auth_key, key2.auth_key);
    }
}
