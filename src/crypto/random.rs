// B4AE Random Number Generation
// Cryptographically secure random number generation

use crate::crypto::CryptoResult;
use rand::rngs::OsRng;
use rand::RngCore;

/// Generate cryptographically secure random bytes
pub fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generate random bytes into existing buffer
pub fn fill_random(buffer: &mut [u8]) -> CryptoResult<()> {
    OsRng.fill_bytes(buffer);
    Ok(())
}

/// Generate random u32
pub fn random_u32() -> u32 {
    OsRng.next_u32()
}

/// Generate random u64
pub fn random_u64() -> u64 {
    OsRng.next_u64()
}

/// Generate random value in range [0, max)
pub fn random_range(max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    
    // Use rejection sampling to avoid modulo bias
    let range = u64::MAX - (u64::MAX % max);
    loop {
        let value = random_u64();
        if value < range {
            return value % max;
        }
    }
}

/// Secure random number generator wrapper
pub struct SecureRng {
    rng: OsRng,
}

impl SecureRng {
    /// Create new secure RNG
    pub fn new() -> Self {
        SecureRng { rng: OsRng }
    }

    /// Generate random bytes
    pub fn generate_bytes(&mut self, length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        self.rng.fill_bytes(&mut bytes);
        bytes
    }

    /// Fill buffer with random bytes
    pub fn fill_bytes(&mut self, buffer: &mut [u8]) {
        self.rng.fill_bytes(buffer);
    }

    /// Generate random u32
    pub fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    /// Generate random u64
    pub fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }
}

impl Default for SecureRng {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.rng.try_fill_bytes(dest)
    }
}

impl rand::CryptoRng for SecureRng {}

/// Generate random delay for timing obfuscation (in milliseconds)
/// Returns delay between min_ms and max_ms
pub fn random_delay_ms(min_ms: u64, max_ms: u64) -> u64 {
    if min_ms >= max_ms {
        return min_ms;
    }
    let range = max_ms - min_ms;
    min_ms + random_range(range + 1)
}

/// Generate random padding size for traffic padding
/// Returns size between min_size and max_size
pub fn random_padding_size(min_size: usize, max_size: usize) -> usize {
    if min_size >= max_size {
        return min_size;
    }
    let range = (max_size - min_size) as u64;
    min_size + random_range(range + 1) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(32);
        let bytes2 = random_bytes(32);
        
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different
    }

    #[test]
    fn test_fill_random() {
        let mut buffer = [0u8; 32];
        fill_random(&mut buffer).unwrap();
        
        // Check that buffer is not all zeros
        assert!(buffer.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_random_range() {
        // Test that values are within range
        for _ in 0..100 {
            let value = random_range(10);
            assert!(value < 10);
        }
    }

    #[test]
    fn test_random_range_distribution() {
        // Test that distribution is roughly uniform
        let mut counts = vec![0; 10];
        for _ in 0..1000 {
            let value = random_range(10) as usize;
            counts[value] += 1;
        }
        
        // Each value should appear roughly 100 times (±50)
        for count in counts {
            assert!(count > 50 && count < 150);
        }
    }

    #[test]
    fn test_secure_rng() {
        let mut rng = SecureRng::new();
        
        let bytes1 = rng.generate_bytes(32);
        let bytes2 = rng.generate_bytes(32);
        
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_random_delay_ms() {
        for _ in 0..100 {
            let delay = random_delay_ms(100, 500);
            assert!(delay >= 100 && delay <= 500);
        }
    }

    #[test]
    fn test_random_padding_size() {
        for _ in 0..100 {
            let size = random_padding_size(1024, 4096);
            assert!(size >= 1024 && size <= 4096);
        }
    }

    #[test]
    fn test_randomness_quality() {
        // Generate many random bytes and check for patterns
        let bytes = random_bytes(10000);
        
        // Count bit distribution
        let mut ones = 0;
        for byte in &bytes {
            ones += byte.count_ones();
        }
        
        // Should be roughly 50% ones (±5%)
        let total_bits = bytes.len() * 8;
        let ones_ratio = ones as f64 / total_bits as f64;
        assert!(ones_ratio > 0.45 && ones_ratio < 0.55);
    }

    #[test]
    fn test_no_duplicate_sequences() {
        // Generate many 16-byte sequences and check for duplicates
        let mut sequences = HashSet::new();
        for _ in 0..1000 {
            let seq = random_bytes(16);
            assert!(!sequences.contains(&seq), "Duplicate sequence found!");
            sequences.insert(seq);
        }
    }
}
