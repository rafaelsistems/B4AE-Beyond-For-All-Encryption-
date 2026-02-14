// B4AE Traffic Obfuscation Implementation
// Dummy traffic generation and pattern obfuscation

use crate::crypto::random::{fill_random, random_range};
use crate::error::{B4aeError, B4aeResult};
use crate::time;
#[cfg(test)]
use std::time::Duration;

/// Dummy message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DummyType {
    /// Random noise
    Noise,
    /// Mimics real message pattern
    Mimic,
    /// Cover traffic
    Cover,
}

/// Dummy traffic generator
pub struct DummyTrafficGenerator {
    /// Percentage of dummy traffic (0-100)
    dummy_percent: u8,
    /// Minimum dummy message size
    min_size: usize,
    /// Maximum dummy message size
    max_size: usize,
    /// Dummy message type
    dummy_type: DummyType,
    /// Last generation time
    last_generated: u64,
    /// Minimum interval between dummy messages (ms)
    min_interval_ms: u64,
}

impl DummyTrafficGenerator {
    /// Create new dummy traffic generator
    pub fn new(dummy_percent: u8, min_size: usize, max_size: usize) -> Self {
        DummyTrafficGenerator {
            dummy_percent: dummy_percent.min(100),
            min_size,
            max_size,
            dummy_type: DummyType::Mimic,
            last_generated: 0,
            min_interval_ms: 100,
        }
    }

    /// Set dummy message type
    pub fn set_dummy_type(&mut self, dummy_type: DummyType) {
        self.dummy_type = dummy_type;
    }

    /// Set minimum interval between dummy messages
    pub fn set_min_interval(&mut self, interval_ms: u64) {
        self.min_interval_ms = interval_ms;
    }

    /// Check if dummy traffic should be generated
    pub fn should_generate(&mut self) -> bool {
        if self.dummy_percent == 0 {
            return false;
        }

        let current_time = time::current_time_millis();

        if current_time - self.last_generated < self.min_interval_ms {
            return false;
        }

        // Random decision based on percentage
        let should_gen = random_range(100) < self.dummy_percent as u64;
        
        if should_gen {
            self.last_generated = current_time;
        }

        should_gen
    }

    /// Generate dummy message
    pub fn generate_dummy(&self) -> B4aeResult<Vec<u8>> {
        let size = if self.max_size > self.min_size {
            self.min_size + (random_range((self.max_size - self.min_size) as u64) as usize)
        } else {
            self.min_size
        };

        match self.dummy_type {
            DummyType::Noise => self.generate_noise(size),
            DummyType::Mimic => self.generate_mimic(size),
            DummyType::Cover => self.generate_cover(size),
        }
    }

    /// Generate random noise
    fn generate_noise(&self, size: usize) -> B4aeResult<Vec<u8>> {
        let mut dummy = vec![0u8; size];
        fill_random(&mut dummy)
            .map_err(|e| B4aeError::CryptoError(format!("Random generation failed: {}", e)))?;
        Ok(dummy)
    }

    /// Generate message that mimics real traffic patterns
    fn generate_mimic(&self, size: usize) -> B4aeResult<Vec<u8>> {
        // Create message with realistic structure
        let mut dummy = Vec::with_capacity(size);

        // Add header-like structure (16 bytes)
        let mut header = vec![0u8; 16.min(size)];
        fill_random(&mut header)
            .map_err(|e| B4aeError::CryptoError(format!("Random generation failed: {}", e)))?;
        dummy.extend_from_slice(&header);

        if size > 16 {
            // Add payload with some patterns
            let payload_size = size - 16;
            let mut payload = vec![0u8; payload_size];
            
            // Mix random data with some patterns
            fill_random(&mut payload)
                .map_err(|e| B4aeError::CryptoError(format!("Random generation failed: {}", e)))?;
            
            // Add some zero blocks to mimic encrypted padding
            if payload_size > 64 {
                let zero_start = payload_size - 32;
                payload[zero_start..].fill(0);
            }

            dummy.extend_from_slice(&payload);
        }

        Ok(dummy)
    }

    /// Generate cover traffic
    fn generate_cover(&self, size: usize) -> B4aeResult<Vec<u8>> {
        // Cover traffic looks like encrypted messages
        let mut dummy = vec![0u8; size];
        fill_random(&mut dummy)
            .map_err(|e| B4aeError::CryptoError(format!("Random generation failed: {}", e)))?;

        let timestamp = time::current_time_secs();
        
        if size >= 8 {
            dummy[0..8].copy_from_slice(&timestamp.to_be_bytes());
        }

        Ok(dummy)
    }

    /// Get current dummy percentage
    pub fn dummy_percent(&self) -> u8 {
        self.dummy_percent
    }

    /// Set dummy percentage
    pub fn set_dummy_percent(&mut self, percent: u8) {
        self.dummy_percent = percent.min(100);
    }
}

/// Traffic pattern obfuscation
pub struct TrafficPattern {
    /// Message sizes history
    message_sizes: Vec<usize>,
    /// Message intervals history (milliseconds)
    message_intervals: Vec<u64>,
    /// Maximum history size
    max_history: usize,
    /// Last message time
    last_message_time: u64,
}

impl TrafficPattern {
    /// Create new traffic pattern analyzer
    pub fn new() -> Self {
        TrafficPattern {
            message_sizes: Vec::new(),
            message_intervals: Vec::new(),
            max_history: 1000,
            last_message_time: 0,
        }
    }

    /// Record message
    pub fn record_message(&mut self, size: usize) {
        let current_time = time::current_time_millis();

        if self.last_message_time > 0 {
            let interval = current_time - self.last_message_time;
            self.message_intervals.push(interval);
            
            if self.message_intervals.len() > self.max_history {
                self.message_intervals.remove(0);
            }
        }

        self.message_sizes.push(size);
        if self.message_sizes.len() > self.max_history {
            self.message_sizes.remove(0);
        }

        self.last_message_time = current_time;
    }

    /// Get average message size
    pub fn average_size(&self) -> usize {
        if self.message_sizes.is_empty() {
            return 0;
        }
        self.message_sizes.iter().sum::<usize>() / self.message_sizes.len()
    }

    /// Get average message interval
    pub fn average_interval(&self) -> u64 {
        if self.message_intervals.is_empty() {
            return 0;
        }
        self.message_intervals.iter().sum::<u64>() / self.message_intervals.len() as u64
    }

    /// Get recommended dummy size based on pattern
    pub fn recommended_dummy_size(&self) -> usize {
        let avg = self.average_size();
        if avg == 0 {
            return 1024; // Default
        }

        // Add some randomness around average
        let variance = (avg / 4).max(256);
        let offset = random_range(variance as u64 * 2) as usize;
        
        if offset > variance {
            avg.saturating_add(offset - variance)
        } else {
            avg.saturating_sub(variance - offset)
        }
    }

    /// Get recommended dummy interval based on pattern
    pub fn recommended_dummy_interval(&self) -> u64 {
        let avg = self.average_interval();
        if avg == 0 {
            return 1000; // Default 1 second
        }

        // Add some randomness around average
        let variance = (avg / 4).max(100);
        let offset = random_range(variance * 2);
        
        if offset > variance {
            avg.saturating_add(offset - variance)
        } else {
            avg.saturating_sub(variance - offset)
        }
    }

    /// Clear history
    pub fn clear(&mut self) {
        self.message_sizes.clear();
        self.message_intervals.clear();
        self.last_message_time = 0;
    }
}

impl Default for TrafficPattern {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dummy_traffic_generator() {
        let mut generator = DummyTrafficGenerator::new(50, 512, 2048);
        generator.set_min_interval(10); // Set shorter interval for testing

        // Test generation decision
        let mut generated_count = 0;
        let iterations = 200; // Reasonable number of iterations
        for _ in 0..iterations {
            if generator.should_generate() {
                generated_count += 1;
            }
            std::thread::sleep(Duration::from_millis(15)); // Sleep longer than min_interval
        }

        // Should generate roughly 50% of the time (with reasonable variance)
        // With 200 iterations and 50% probability, expect 70-130 (within reasonable bounds)
        assert!(generated_count > 70 && generated_count < 130,
            "Generated {} times out of {}, expected 70-130", generated_count, iterations);
    }

    #[test]
    fn test_dummy_message_generation() {
        let generator = DummyTrafficGenerator::new(50, 512, 2048);

        let noise = generator.generate_noise(1024).unwrap();
        assert_eq!(noise.len(), 1024);

        let mimic = generator.generate_mimic(1024).unwrap();
        assert_eq!(mimic.len(), 1024);

        let cover = generator.generate_cover(1024).unwrap();
        assert_eq!(cover.len(), 1024);
    }

    #[test]
    fn test_dummy_types() {
        let mut generator = DummyTrafficGenerator::new(100, 1024, 1024);

        generator.set_dummy_type(DummyType::Noise);
        let dummy1 = generator.generate_dummy().unwrap();
        assert_eq!(dummy1.len(), 1024);

        generator.set_dummy_type(DummyType::Mimic);
        let dummy2 = generator.generate_dummy().unwrap();
        assert_eq!(dummy2.len(), 1024);

        generator.set_dummy_type(DummyType::Cover);
        let dummy3 = generator.generate_dummy().unwrap();
        assert_eq!(dummy3.len(), 1024);
    }

    #[test]
    fn test_traffic_pattern() {
        let mut pattern = TrafficPattern::new();

        // Record some messages
        pattern.record_message(1000);
        std::thread::sleep(Duration::from_millis(100));
        pattern.record_message(1500);
        std::thread::sleep(Duration::from_millis(100));
        pattern.record_message(1200);

        let avg_size = pattern.average_size();
        assert!(avg_size > 1000 && avg_size < 1500);

        let avg_interval = pattern.average_interval();
        // Bounds widened for CI: sleep(100) can exceed 100ms under load; expect ~100ms nominal
        assert!(avg_interval >= 50 && avg_interval < 1200,
            "avg_interval {} outside expected range [50, 1200) for CI timing variability",
            avg_interval);

        let recommended_size = pattern.recommended_dummy_size();
        assert!(recommended_size > 500 && recommended_size < 2000);
    }

    #[test]
    fn test_min_interval() {
        let mut generator = DummyTrafficGenerator::new(100, 512, 1024);
        generator.set_min_interval(1000);

        // First should generate
        assert!(generator.should_generate());

        // Second should not (too soon)
        assert!(!generator.should_generate());

        // After interval, should generate again
        std::thread::sleep(Duration::from_millis(1100));
        assert!(generator.should_generate());
    }

    #[test]
    fn test_zero_percent() {
        let mut generator = DummyTrafficGenerator::new(0, 512, 1024);

        for _ in 0..100 {
            assert!(!generator.should_generate());
        }
    }
}
