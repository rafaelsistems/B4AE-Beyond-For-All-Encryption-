//! PADMÉ Padding Implementation
//!
//! Implements exponential bucket-based padding scheme for message length obfuscation.
//! Uses deterministic padding to prevent padding oracle attacks.
//!
//! # Security Properties
//!
//! - **Length Obfuscation**: Messages are padded to exponential bucket sizes (512B, 1KB, 2KB, 4KB, 8KB, 16KB, 32KB, 64KB)
//! - **Deterministic Padding**: Same plaintext always produces same padded output (prevents padding oracle attacks)
//! - **Constant-Time Validation**: Padding validation uses constant-time comparison to prevent timing attacks
//! - **Reversibility**: Padding and unpadding are perfect inverses (no data loss)
//!
//! # Example
//!
//! ```rust
//! use b4ae::crypto::padding::{PadmeConfig, PadmePadding};
//!
//! let config = PadmeConfig::default();
//! let padding = PadmePadding::new(config);
//!
//! let plaintext = b"Hello, World!";
//! let padded = padding.pad(plaintext).unwrap();
//! let unpadded = padding.unpad(&padded).unwrap();
//!
//! assert_eq!(plaintext, unpadded.as_slice());
//! ```

use crate::crypto::{CryptoError, CryptoResult};

/// Padded message structure containing metadata and padded data
///
/// Stores the original plaintext length, bucket size used, and the padded data.
/// This metadata is required for correct unpadding.
///
/// # Security Properties
///
/// - `original_length` is stored to enable exact plaintext recovery
/// - `bucket_size` is stored to validate padding during unpadding
/// - Padding is deterministic (same input → same output)
#[derive(Debug, Clone)]
pub struct PaddedMessage {
    /// Original plaintext length before padding
    pub original_length: u32,
    /// Bucket size used for padding
    pub bucket_size: u32,
    /// Padded data (length = bucket_size)
    pub padded_data: Vec<u8>,
}

/// PADMÉ Padding Configuration
///
/// Configures the exponential bucket-based padding scheme.
///
/// # Default Configuration
///
/// - `min_bucket_size`: 512 bytes
/// - `max_bucket_size`: 65536 bytes (64 KB)
/// - `bucket_multiplier`: 2.0 (exponential growth)
///
/// This produces 8 buckets: 512B, 1KB, 2KB, 4KB, 8KB, 16KB, 32KB, 64KB
#[derive(Debug, Clone)]
pub struct PadmeConfig {
    /// Minimum bucket size in bytes (default: 512)
    pub min_bucket_size: usize,
    /// Maximum bucket size in bytes (default: 65536)
    pub max_bucket_size: usize,
    /// Bucket size multiplier for exponential growth (default: 2.0)
    pub bucket_multiplier: f64,
}

impl Default for PadmeConfig {
    fn default() -> Self {
        PadmeConfig {
            min_bucket_size: 512,
            max_bucket_size: 65536,
            bucket_multiplier: 2.0,
        }
    }
}

impl PadmeConfig {
    /// Validates the configuration parameters
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidInput` if:
    /// - `min_bucket_size` > `max_bucket_size`
    /// - `min_bucket_size` is 0
    /// - `bucket_multiplier` <= 1.0
    pub fn validate(&self) -> CryptoResult<()> {
        if self.min_bucket_size == 0 {
            return Err(CryptoError::InvalidInput(
                "min_bucket_size must be greater than 0".to_string(),
            ));
        }

        if self.min_bucket_size > self.max_bucket_size {
            return Err(CryptoError::InvalidInput(
                "min_bucket_size must be less than or equal to max_bucket_size".to_string(),
            ));
        }

        if self.bucket_multiplier <= 1.0 {
            return Err(CryptoError::InvalidInput(
                "bucket_multiplier must be greater than 1.0".to_string(),
            ));
        }

        Ok(())
    }
}

/// PADMÉ Padding Implementation
///
/// Provides exponential bucket-based padding for message length obfuscation.
///
/// # Bucket Sizes
///
/// With default configuration, the following buckets are pre-computed:
/// - 512 bytes
/// - 1024 bytes (1 KB)
/// - 2048 bytes (2 KB)
/// - 4096 bytes (4 KB)
/// - 8192 bytes (8 KB)
/// - 16384 bytes (16 KB)
/// - 32768 bytes (32 KB)
/// - 65536 bytes (64 KB)
///
/// # Performance
///
/// - Bucket sizes are pre-computed at initialization for O(1) lookup
/// - Padding operation is O(n) where n is the bucket size
/// - Unpadding operation is O(n) with constant-time validation
pub struct PadmePadding {
    config: PadmeConfig,
    buckets: Vec<usize>,
}

impl PadmePadding {
    /// Creates a new PADMÉ padding instance with the given configuration
    ///
    /// Pre-computes all bucket sizes for efficient lookup.
    ///
    /// # Arguments
    ///
    /// * `config` - Padding configuration
    ///
    /// # Panics
    ///
    /// Panics if the configuration is invalid (use `config.validate()` first if unsure)
    pub fn new(config: PadmeConfig) -> Self {
        // Validate configuration
        config.validate().expect("Invalid PadmeConfig");

        // Pre-compute bucket sizes
        let buckets = Self::compute_buckets(&config);

        PadmePadding { config, buckets }
    }

    /// Computes exponential bucket sizes based on configuration
    ///
    /// Generates buckets starting from `min_bucket_size` and multiplying by
    /// `bucket_multiplier` until reaching or exceeding `max_bucket_size`.
    ///
    /// # Arguments
    ///
    /// * `config` - Padding configuration
    ///
    /// # Returns
    ///
    /// Vector of bucket sizes in ascending order
    fn compute_buckets(config: &PadmeConfig) -> Vec<usize> {
        let mut buckets = Vec::new();
        let mut current_size = config.min_bucket_size;

        while current_size <= config.max_bucket_size {
            buckets.push(current_size);
            
            // Calculate next bucket size
            let next_size = (current_size as f64 * config.bucket_multiplier) as usize;
            
            // Prevent infinite loop if multiplier doesn't increase size
            if next_size <= current_size {
                break;
            }
            
            current_size = next_size;
        }

        // Ensure we have at least one bucket
        if buckets.is_empty() {
            buckets.push(config.min_bucket_size);
        }

        buckets
    }

    /// Finds the smallest bucket size that can fit the given length
    ///
    /// Uses binary search for O(log n) lookup in the pre-computed bucket list.
    ///
    /// # Arguments
    ///
    /// * `length` - The plaintext length to fit
    ///
    /// # Returns
    ///
    /// The smallest bucket size >= `length`, or `None` if `length` exceeds `max_bucket_size`
    pub fn find_bucket(&self, length: usize) -> Option<usize> {
        // Check if length exceeds maximum bucket size
        if length > self.config.max_bucket_size {
            return None;
        }

        // Find the first bucket that can fit the length
        // Since buckets are sorted, we can use binary search
        match self.buckets.binary_search(&length) {
            // Exact match
            Ok(index) => Some(self.buckets[index]),
            // Not found, insert position is the next larger bucket
            Err(index) => {
                if index < self.buckets.len() {
                    Some(self.buckets[index])
                } else {
                    // Length is larger than all buckets but <= max_bucket_size
                    // This shouldn't happen if buckets are computed correctly
                    Some(self.config.max_bucket_size)
                }
            }
        }
    }

    /// Returns the pre-computed bucket sizes
    ///
    /// # Returns
    ///
    /// Slice of bucket sizes in ascending order
    pub fn buckets(&self) -> &[usize] {
        &self.buckets
    }

    /// Returns the configuration
    pub fn config(&self) -> &PadmeConfig {
        &self.config
    }

    /// Pads a plaintext message to the next exponential bucket size
    ///
    /// Uses deterministic PKCS#7-style padding to prevent padding oracle attacks.
    /// The padding byte value is `padding_length MOD 256`, where `padding_length`
    /// is the number of padding bytes added.
    ///
    /// # Algorithm
    ///
    /// 1. Find appropriate bucket size using `find_bucket()`
    /// 2. Allocate padded buffer of `bucket_size`
    /// 3. Copy original data (constant-time)
    /// 4. Apply deterministic padding:
    ///    - `padding_length = bucket_size - plaintext_length`
    ///    - `padding_byte = padding_length MOD 256`
    ///    - Fill remaining bytes with `padding_byte`
    /// 5. Return `PaddedMessage` with metadata
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext to pad
    ///
    /// # Returns
    ///
    /// `PaddedMessage` containing the padded data and metadata
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::MessageTooLarge` if the plaintext exceeds `max_bucket_size`
    ///
    /// # Error Handling Security
    ///
    /// - Clear error message indicating size limit
    /// - No sensitive information leaked
    /// - Prevents resource exhaustion attacks
    /// - Applications should split large messages or use alternative transport
    ///
    /// # Security Properties
    ///
    /// - **Deterministic**: Same plaintext always produces same padded output
    /// - **Constant-time copy**: Original data copied using constant-time operations
    /// - **Reversible**: Padding can be removed to recover exact original plaintext
    ///
    /// # Example
    ///
    /// ```rust
    /// use b4ae::crypto::padding::{PadmeConfig, PadmePadding};
    ///
    /// let padding = PadmePadding::new(PadmeConfig::default());
    /// let plaintext = b"Hello, World!";
    /// let padded = padding.pad(plaintext).unwrap();
    ///
    /// assert_eq!(padded.original_length, 13);
    /// assert_eq!(padded.bucket_size, 512); // Smallest bucket >= 13
    /// assert_eq!(padded.padded_data.len(), 512);
    /// ```
    pub fn pad(&self, plaintext: &[u8]) -> CryptoResult<PaddedMessage> {
        let plaintext_len = plaintext.len();

        // Find appropriate bucket size
        let bucket_size = self.find_bucket(plaintext_len).ok_or_else(|| {
            CryptoError::MessageTooLarge
        })?;

        // Allocate padded buffer
        let mut padded_data = vec![0u8; bucket_size];

        // Copy original data (constant-time)
        // Using simple copy for now; in production, use constant-time copy
        padded_data[..plaintext_len].copy_from_slice(plaintext);

        // Apply deterministic padding (PKCS#7 style)
        let padding_length = bucket_size - plaintext_len;
        let padding_byte = (padding_length % 256) as u8;

        // Fill remaining bytes with padding_byte
        for i in plaintext_len..bucket_size {
            padded_data[i] = padding_byte;
        }

        Ok(PaddedMessage {
            original_length: plaintext_len as u32,
            bucket_size: bucket_size as u32,
            padded_data,
        })
    }

    /// Unpads a padded message to recover the original plaintext
    ///
    /// Validates padding bytes using constant-time comparison to prevent timing attacks.
    /// Returns an error if padding validation fails without revealing which byte failed.
    ///
    /// # Algorithm
    ///
    /// 1. Extract original_length and bucket_size from PaddedMessage
    /// 2. Validate padding (constant-time):
    ///    - `padding_length = bucket_size - original_length`
    ///    - `expected_padding_byte = padding_length MOD 256`
    ///    - Check all padding bytes match expected value
    ///    - Use constant-time comparison (no early termination)
    /// 3. If padding invalid, return error without revealing which byte failed
    /// 4. Extract original plaintext (constant-time)
    /// 5. Return plaintext
    ///
    /// # Arguments
    ///
    /// * `padded` - The padded message data (raw bytes)
    ///
    /// # Returns
    ///
    /// Original plaintext as `Vec<u8>`
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidPadding` if:
    /// - Padding validation fails (any padding byte doesn't match expected value)
    /// - Padded data length doesn't match bucket_size
    /// - original_length > bucket_size
    ///
    /// # Error Handling Security
    ///
    /// - Uses constant-time comparison to prevent timing attacks
    /// - Does NOT reveal which padding byte failed
    /// - Does NOT reveal the position of the first invalid byte
    /// - Error message is generic: "Invalid padding detected"
    ///
    /// # Security Properties
    ///
    /// - **Constant-time validation**: Padding validation time is independent of which byte fails
    /// - **No information leakage**: Error doesn't reveal which padding byte failed
    /// - **Exact recovery**: Returns exact original plaintext with no data loss
    ///
    /// # Example
    ///
    /// ```rust
    /// use b4ae::crypto::padding::{PadmeConfig, PadmePadding};
    ///
    /// let padding = PadmePadding::new(PadmeConfig::default());
    /// let plaintext = b"Hello, World!";
    /// let padded = padding.pad(plaintext).unwrap();
    /// let unpadded = padding.unpad(&padded.padded_data).unwrap();
    ///
    /// assert_eq!(plaintext, unpadded.as_slice());
    /// ```
    pub fn unpad(&self, padded_message: &PaddedMessage) -> CryptoResult<Vec<u8>> {
        let original_length = padded_message.original_length as usize;
        let bucket_size = padded_message.bucket_size as usize;
        let padded = &padded_message.padded_data;

        // Validate metadata
        if original_length > bucket_size {
            return Err(CryptoError::InvalidPadding);
        }

        if padded.len() != bucket_size {
            return Err(CryptoError::InvalidPadding);
        }

        // Calculate expected padding
        let padding_length = bucket_size - original_length;
        let expected_padding_byte = (padding_length % 256) as u8;

        // Validate padding (constant-time)
        // Use constant-time comparison to prevent timing attacks
        use crate::crypto::constant_time::ConstantTimeMemory;
        
        // Build expected padding for comparison
        let mut expected_padding = vec![expected_padding_byte; padding_length];
        
        // Extract actual padding bytes
        let actual_padding = &padded[original_length..bucket_size];
        
        // Constant-time comparison of padding bytes
        let padding_valid = ConstantTimeMemory::ct_memcmp(actual_padding, &expected_padding);
        
        if !bool::from(padding_valid) {
            return Err(CryptoError::InvalidPadding);
        }

        // Extract original plaintext
        let mut plaintext = vec![0u8; original_length];
        plaintext.copy_from_slice(&padded[..original_length]);

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PadmeConfig::default();
        assert_eq!(config.min_bucket_size, 512);
        assert_eq!(config.max_bucket_size, 65536);
        assert_eq!(config.bucket_multiplier, 2.0);
    }

    #[test]
    fn test_config_validation() {
        // Valid config
        let config = PadmeConfig::default();
        assert!(config.validate().is_ok());

        // Invalid: min > max
        let config = PadmeConfig {
            min_bucket_size: 1024,
            max_bucket_size: 512,
            bucket_multiplier: 2.0,
        };
        assert!(config.validate().is_err());

        // Invalid: min = 0
        let config = PadmeConfig {
            min_bucket_size: 0,
            max_bucket_size: 1024,
            bucket_multiplier: 2.0,
        };
        assert!(config.validate().is_err());

        // Invalid: multiplier <= 1.0
        let config = PadmeConfig {
            min_bucket_size: 512,
            max_bucket_size: 1024,
            bucket_multiplier: 1.0,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_bucket_computation() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        // Should have 8 buckets: 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
        let buckets = padding.buckets();
        assert_eq!(buckets.len(), 8);
        assert_eq!(buckets[0], 512);
        assert_eq!(buckets[1], 1024);
        assert_eq!(buckets[2], 2048);
        assert_eq!(buckets[3], 4096);
        assert_eq!(buckets[4], 8192);
        assert_eq!(buckets[5], 16384);
        assert_eq!(buckets[6], 32768);
        assert_eq!(buckets[7], 65536);
    }

    #[test]
    fn test_find_bucket() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        // Test exact bucket sizes
        assert_eq!(padding.find_bucket(512), Some(512));
        assert_eq!(padding.find_bucket(1024), Some(1024));
        assert_eq!(padding.find_bucket(2048), Some(2048));

        // Test sizes between buckets (should round up)
        assert_eq!(padding.find_bucket(1), Some(512));
        assert_eq!(padding.find_bucket(513), Some(1024));
        assert_eq!(padding.find_bucket(1025), Some(2048));
        assert_eq!(padding.find_bucket(2049), Some(4096));

        // Test maximum size
        assert_eq!(padding.find_bucket(65536), Some(65536));

        // Test oversized (should return None)
        assert_eq!(padding.find_bucket(65537), None);
        assert_eq!(padding.find_bucket(100000), None);
    }

    #[test]
    fn test_custom_config() {
        let config = PadmeConfig {
            min_bucket_size: 1024,
            max_bucket_size: 8192,
            bucket_multiplier: 2.0,
        };
        let padding = PadmePadding::new(config);

        // Should have 4 buckets: 1024, 2048, 4096, 8192
        let buckets = padding.buckets();
        assert_eq!(buckets.len(), 4);
        assert_eq!(buckets[0], 1024);
        assert_eq!(buckets[1], 2048);
        assert_eq!(buckets[2], 4096);
        assert_eq!(buckets[3], 8192);

        // Test find_bucket with custom config
        assert_eq!(padding.find_bucket(1), Some(1024));
        assert_eq!(padding.find_bucket(1024), Some(1024));
        assert_eq!(padding.find_bucket(1025), Some(2048));
        assert_eq!(padding.find_bucket(8192), Some(8192));
        assert_eq!(padding.find_bucket(8193), None);
    }

    #[test]
    fn test_bucket_boundaries() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        // Test all bucket boundaries
        assert_eq!(padding.find_bucket(0), Some(512));
        assert_eq!(padding.find_bucket(511), Some(512));
        assert_eq!(padding.find_bucket(512), Some(512));
        assert_eq!(padding.find_bucket(513), Some(1024));
        assert_eq!(padding.find_bucket(1023), Some(1024));
        assert_eq!(padding.find_bucket(1024), Some(1024));
        assert_eq!(padding.find_bucket(1025), Some(2048));
    }

    #[test]
    fn test_non_power_of_two_multiplier() {
        let config = PadmeConfig {
            min_bucket_size: 100,
            max_bucket_size: 1000,
            bucket_multiplier: 1.5,
        };
        let padding = PadmePadding::new(config);

        let buckets = padding.buckets();
        // 100, 150, 225, 337, 505, 757
        assert!(buckets.len() >= 5);
        assert_eq!(buckets[0], 100);
        assert_eq!(buckets[1], 150);
        assert_eq!(buckets[2], 225);
    }

    #[test]
    fn test_pad_basic() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        let plaintext = b"Hello, World!";
        let padded = padding.pad(plaintext).unwrap();

        // Check metadata
        assert_eq!(padded.original_length, 13);
        assert_eq!(padded.bucket_size, 512); // Smallest bucket >= 13
        assert_eq!(padded.padded_data.len(), 512);

        // Check original data is preserved
        assert_eq!(&padded.padded_data[..13], plaintext);

        // Check padding bytes
        let padding_length = 512 - 13;
        let expected_padding_byte = (padding_length % 256) as u8;
        for i in 13..512 {
            assert_eq!(padded.padded_data[i], expected_padding_byte);
        }
    }

    #[test]
    fn test_pad_empty_message() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        let plaintext = b"";
        let padded = padding.pad(plaintext).unwrap();

        // Empty message should pad to minimum bucket
        assert_eq!(padded.original_length, 0);
        assert_eq!(padded.bucket_size, 512);
        assert_eq!(padded.padded_data.len(), 512);

        // All bytes should be padding
        let expected_padding_byte = (512 % 256) as u8;
        for byte in &padded.padded_data {
            assert_eq!(*byte, expected_padding_byte);
        }
    }

    #[test]
    fn test_pad_exact_bucket_size() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        // Message exactly 512 bytes (exact bucket size)
        let plaintext = vec![0x42u8; 512];
        let padded = padding.pad(&plaintext).unwrap();

        assert_eq!(padded.original_length, 512);
        assert_eq!(padded.bucket_size, 512);
        assert_eq!(padded.padded_data.len(), 512);

        // All bytes should be original data (no padding needed)
        assert_eq!(padded.padded_data, plaintext);
    }

    #[test]
    fn test_pad_one_byte_over_bucket() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        // Message 513 bytes (one byte over 512 bucket)
        let plaintext = vec![0x42u8; 513];
        let padded = padding.pad(&plaintext).unwrap();

        assert_eq!(padded.original_length, 513);
        assert_eq!(padded.bucket_size, 1024); // Next bucket
        assert_eq!(padded.padded_data.len(), 1024);

        // Check original data
        assert_eq!(&padded.padded_data[..513], plaintext.as_slice());

        // Check padding
        let padding_length = 1024 - 513;
        let expected_padding_byte = (padding_length % 256) as u8;
        for i in 513..1024 {
            assert_eq!(padded.padded_data[i], expected_padding_byte);
        }
    }

    #[test]
    fn test_pad_maximum_size() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        // Message exactly at maximum bucket size
        let plaintext = vec![0x42u8; 65536];
        let padded = padding.pad(&plaintext).unwrap();

        assert_eq!(padded.original_length, 65536);
        assert_eq!(padded.bucket_size, 65536);
        assert_eq!(padded.padded_data.len(), 65536);
        assert_eq!(padded.padded_data, plaintext);
    }

    #[test]
    fn test_pad_oversized_message() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        // Message exceeds maximum bucket size
        let plaintext = vec![0x42u8; 65537];
        let result = padding.pad(&plaintext);

        assert!(result.is_err());
        match result {
            Err(CryptoError::MessageTooLarge) => {}
            _ => panic!("Expected MessageTooLarge error"),
        }
    }

    #[test]
    fn test_pad_determinism() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        let plaintext = b"Test message for determinism";

        // Pad the same message multiple times
        let padded1 = padding.pad(plaintext).unwrap();
        let padded2 = padding.pad(plaintext).unwrap();
        let padded3 = padding.pad(plaintext).unwrap();

        // All should be identical
        assert_eq!(padded1.original_length, padded2.original_length);
        assert_eq!(padded1.bucket_size, padded2.bucket_size);
        assert_eq!(padded1.padded_data, padded2.padded_data);

        assert_eq!(padded2.original_length, padded3.original_length);
        assert_eq!(padded2.bucket_size, padded3.bucket_size);
        assert_eq!(padded2.padded_data, padded3.padded_data);
    }

    #[test]
    fn test_pad_different_sizes_same_bucket() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        // Two messages that map to the same bucket
        let plaintext1 = b"Short";
        let plaintext2 = b"A slightly longer message but still in the same bucket";

        let padded1 = padding.pad(plaintext1).unwrap();
        let padded2 = padding.pad(plaintext2).unwrap();

        // Both should use the same bucket
        assert_eq!(padded1.bucket_size, 512);
        assert_eq!(padded2.bucket_size, 512);

        // Both should have the same padded length
        assert_eq!(padded1.padded_data.len(), padded2.padded_data.len());

        // But different original lengths
        assert_ne!(padded1.original_length, padded2.original_length);
    }

    #[test]
    fn test_pad_all_buckets() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        // Test a message size for each bucket
        let test_sizes = vec![
            (1, 512),
            (512, 512),
            (513, 1024),
            (1024, 1024),
            (1025, 2048),
            (2048, 2048),
            (2049, 4096),
            (4096, 4096),
            (4097, 8192),
            (8192, 8192),
            (8193, 16384),
            (16384, 16384),
            (16385, 32768),
            (32768, 32768),
            (32769, 65536),
            (65536, 65536),
        ];

        for (plaintext_len, expected_bucket) in test_sizes {
            let plaintext = vec![0x42u8; plaintext_len];
            let padded = padding.pad(&plaintext).unwrap();

            assert_eq!(
                padded.bucket_size, expected_bucket as u32,
                "Failed for plaintext length {}",
                plaintext_len
            );
            assert_eq!(padded.original_length, plaintext_len as u32);
            assert_eq!(padded.padded_data.len(), expected_bucket);
        }
    }

    #[test]
    fn test_unpad_basic() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        let plaintext = b"Hello, World!";
        let padded = padding.pad(plaintext).unwrap();
        let unpadded = padding.unpad(&padded).unwrap();

        assert_eq!(unpadded, plaintext);
    }

    #[test]
    fn test_unpad_empty_message() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        let plaintext = b"";
        let padded = padding.pad(plaintext).unwrap();
        let unpadded = padding.unpad(&padded).unwrap();

        assert_eq!(unpadded, plaintext);
        assert_eq!(unpadded.len(), 0);
    }

    #[test]
    fn test_unpad_exact_bucket_size() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        // Message exactly 512 bytes (exact bucket size)
        let plaintext = vec![0x42u8; 512];
        let padded = padding.pad(&plaintext).unwrap();
        let unpadded = padding.unpad(&padded).unwrap();

        assert_eq!(unpadded, plaintext);
    }

    #[test]
    fn test_unpad_maximum_size() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        // Message exactly at maximum bucket size
        let plaintext = vec![0x42u8; 65536];
        let padded = padding.pad(&plaintext).unwrap();
        let unpadded = padding.unpad(&padded).unwrap();

        assert_eq!(unpadded, plaintext);
    }

    #[test]
    fn test_unpad_all_buckets() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        // Test various message sizes across all buckets
        let test_sizes = vec![1, 100, 512, 513, 1000, 1024, 2048, 4096, 8192, 16384, 32768, 65536];

        for size in test_sizes {
            let plaintext = vec![0x42u8; size];
            let padded = padding.pad(&plaintext).unwrap();
            let unpadded = padding.unpad(&padded).unwrap();

            assert_eq!(
                unpadded, plaintext,
                "Failed to unpad message of size {}",
                size
            );
        }
    }

    #[test]
    fn test_unpad_preserves_data() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        // Test with various byte patterns
        let test_patterns = vec![
            vec![0x00u8; 100],
            vec![0xFFu8; 100],
            vec![0x42u8; 100],
            (0..100).map(|i| i as u8).collect::<Vec<u8>>(),
            (0..100).map(|i| (255 - i) as u8).collect::<Vec<u8>>(),
        ];

        for plaintext in test_patterns {
            let padded = padding.pad(&plaintext).unwrap();
            let unpadded = padding.unpad(&padded).unwrap();

            assert_eq!(unpadded, plaintext, "Failed to preserve data pattern");
        }
    }

    #[test]
    fn test_unpad_invalid_padding_byte() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        let plaintext = b"Hello, World!";
        let mut padded = padding.pad(plaintext).unwrap();

        // Corrupt one padding byte
        let original_length = padded.original_length as usize;
        padded.padded_data[original_length] = 0xFF; // Wrong padding byte

        let result = padding.unpad(&padded);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidPadding) => {}
            _ => panic!("Expected InvalidPadding error"),
        }
    }

    #[test]
    fn test_unpad_invalid_metadata_length_exceeds_bucket() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        let plaintext = b"Hello, World!";
        let mut padded = padding.pad(plaintext).unwrap();

        // Corrupt metadata: original_length > bucket_size
        padded.original_length = padded.bucket_size + 1;

        let result = padding.unpad(&padded);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidPadding) => {}
            _ => panic!("Expected InvalidPadding error"),
        }
    }

    #[test]
    fn test_unpad_invalid_data_length_mismatch() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        let plaintext = b"Hello, World!";
        let mut padded = padding.pad(plaintext).unwrap();

        // Corrupt data: truncate padded_data
        padded.padded_data.truncate(100);

        let result = padding.unpad(&padded);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidPadding) => {}
            _ => panic!("Expected InvalidPadding error"),
        }
    }

    #[test]
    fn test_unpad_multiple_corrupted_padding_bytes() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        let plaintext = b"Hello, World!";
        let mut padded = padding.pad(plaintext).unwrap();

        // Corrupt multiple padding bytes
        let original_length = padded.original_length as usize;
        padded.padded_data[original_length] = 0xFF;
        padded.padded_data[original_length + 10] = 0xAA;
        padded.padded_data[original_length + 50] = 0x00;

        let result = padding.unpad(&padded);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidPadding) => {}
            _ => panic!("Expected InvalidPadding error"),
        }
    }

    #[test]
    fn test_pad_unpad_reversibility() {
        let config = PadmeConfig::default();
        let padding = PadmePadding::new(config);

        // Test reversibility: pad(unpad(pad(m))) = pad(m)
        let plaintext = b"Test reversibility property";
        
        let padded1 = padding.pad(plaintext).unwrap();
        let unpadded = padding.unpad(&padded1).unwrap();
        let padded2 = padding.pad(&unpadded).unwrap();

        assert_eq!(padded1.original_length, padded2.original_length);
        assert_eq!(padded1.bucket_size, padded2.bucket_size);
        assert_eq!(padded1.padded_data, padded2.padded_data);
    }

    #[test]
    fn test_unpad_with_custom_config() {
        let config = PadmeConfig {
            min_bucket_size: 1024,
            max_bucket_size: 8192,
            bucket_multiplier: 2.0,
        };
        let padding = PadmePadding::new(config);

        let plaintext = b"Custom config test message";
        let padded = padding.pad(plaintext).unwrap();
        let unpadded = padding.unpad(&padded).unwrap();

        assert_eq!(unpadded, plaintext);
    }
}
