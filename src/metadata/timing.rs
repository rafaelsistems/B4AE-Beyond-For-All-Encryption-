// B4AE Timing Obfuscation Implementation
// Random delays to prevent timing analysis attacks

use crate::crypto::random::random_range;
use std::time::Duration;

/// Timing obfuscator for adding random delays to messages.
///
/// This struct provides a simple interface for generating random delays
/// uniformly distributed between a configured minimum and maximum value.
/// Uses cryptographically secure random number generation to prevent
/// timing prediction attacks.
///
/// # Examples
///
/// ```
/// use b4ae::metadata::timing::TimingObfuscator;
/// use std::time::Duration;
///
/// let obfuscator = TimingObfuscator::new(100, 2000);
/// let delay = obfuscator.random_delay();
/// assert!(delay >= Duration::from_millis(100));
/// assert!(delay <= Duration::from_millis(2000));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingObfuscator {
    min_delay: Duration,
    max_delay: Duration,
}

impl TimingObfuscator {
    /// Create a new timing obfuscator with the specified delay range.
    ///
    /// # Arguments
    ///
    /// * `min_delay_ms` - Minimum delay in milliseconds
    /// * `max_delay_ms` - Maximum delay in milliseconds
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidInput` if `min_delay_ms` > `max_delay_ms`.
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::metadata::timing::TimingObfuscator;
    ///
    /// let obfuscator = TimingObfuscator::new(100, 2000).unwrap();
    /// ```
    pub fn new(min_delay_ms: u64, max_delay_ms: u64) -> crate::crypto::CryptoResult<Self> {
        use crate::crypto::CryptoError;

        if min_delay_ms > max_delay_ms {
            return Err(CryptoError::InvalidInput(
                format!(
                    "min_delay_ms ({}) must be <= max_delay_ms ({})",
                    min_delay_ms, max_delay_ms
                )
            ));
        }

        Ok(Self {
            min_delay: Duration::from_millis(min_delay_ms),
            max_delay: Duration::from_millis(max_delay_ms),
        })
    }

    /// Create a new timing obfuscator with the specified delay range (unchecked).
    ///
    /// # Arguments
    ///
    /// * `min_delay_ms` - Minimum delay in milliseconds
    /// * `max_delay_ms` - Maximum delay in milliseconds
    ///
    /// # Panics
    ///
    /// Panics if `min_delay_ms` > `max_delay_ms`.
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::metadata::timing::TimingObfuscator;
    ///
    /// let obfuscator = TimingObfuscator::new_unchecked(100, 2000);
    /// ```
    pub fn new_unchecked(min_delay_ms: u64, max_delay_ms: u64) -> Self {
        assert!(
            min_delay_ms <= max_delay_ms,
            "min_delay_ms ({}) must be <= max_delay_ms ({})",
            min_delay_ms,
            max_delay_ms
        );

        Self {
            min_delay: Duration::from_millis(min_delay_ms),
            max_delay: Duration::from_millis(max_delay_ms),
        }
    }

    /// Generate a random delay uniformly distributed in the configured range.
    ///
    /// Uses cryptographically secure random number generation to ensure
    /// delays cannot be predicted by an adversary.
    ///
    /// # Returns
    ///
    /// A `Duration` uniformly distributed in [min_delay, max_delay].
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::metadata::timing::TimingObfuscator;
    ///
    /// let obfuscator = TimingObfuscator::new(100, 2000);
    /// let delay = obfuscator.random_delay();
    /// // delay is between 100ms and 2000ms
    /// ```
    pub fn random_delay(&self) -> Duration {
        let min_ms = self.min_delay.as_millis() as u64;
        let max_ms = self.max_delay.as_millis() as u64;

        // Handle edge case where min == max
        if min_ms == max_ms {
            return self.min_delay;
        }

        // Generate random delay uniformly in [min_ms, max_ms]
        let range = max_ms - min_ms;
        let random_offset = random_range(range + 1); // +1 to include max_ms
        let delay_ms = min_ms + random_offset;

        Duration::from_millis(delay_ms)
    }

    /// Get the minimum delay.
    pub fn min_delay(&self) -> Duration {
        self.min_delay
    }

    /// Get the maximum delay.
    pub fn max_delay(&self) -> Duration {
        self.max_delay
    }
}

/// Calculate random delay for timing obfuscation
/// 
/// Returns a random delay between min_ms and max_ms milliseconds.
/// Uses cryptographically secure random number generation.
pub fn calculate_delay(min_ms: u64, max_ms: u64) -> u64 {
    if min_ms >= max_ms {
        return min_ms;
    }

    let range = max_ms - min_ms;
    min_ms + random_range(range)
}

/// Calculate delay with exponential distribution
/// 
/// Provides more natural-looking delays that mimic human behavior.
/// Lambda parameter controls the distribution shape (higher = shorter delays).
pub fn calculate_exponential_delay(lambda: f64, max_ms: u64) -> u64 {
    use std::f64;

    if lambda <= 0.0 {
        return 0;
    }

    // Generate uniform random [0, 1)
    let u = random_range(u32::MAX as u64) as f64 / u32::MAX as f64;
    
    // Transform to exponential distribution: -ln(1-u) / lambda
    let delay = -(1.0 - u).ln() / lambda;
    
    // Convert to milliseconds and cap at max
    let delay_ms = (delay * 1000.0) as u64;
    delay_ms.min(max_ms)
}

/// Calculate delay with normal distribution
/// 
/// Provides delays centered around mean_ms with standard deviation std_dev_ms.
/// Uses Box-Muller transform for normal distribution.
pub fn calculate_normal_delay(mean_ms: u64, std_dev_ms: u64, max_ms: u64) -> u64 {
    use std::f64::consts::PI;

    // Box-Muller transform
    let u1 = random_range(u32::MAX as u64) as f64 / u32::MAX as f64;
    let u2 = random_range(u32::MAX as u64) as f64 / u32::MAX as f64;
    
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos();
    
    let delay = mean_ms as f64 + z * std_dev_ms as f64;
    let delay_ms = delay.max(0.0) as u64;
    
    delay_ms.min(max_ms)
}

/// Timing strategy for different scenarios
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingStrategy {
    /// No delay
    None,
    /// Uniform random delay
    Uniform,
    /// Exponential distribution (mimics network delays)
    Exponential,
    /// Normal distribution (mimics human behavior)
    Normal,
}

/// Timing obfuscation configuration
#[derive(Debug, Clone)]
pub struct TimingConfig {
    /// Delay distribution strategy
    pub strategy: TimingStrategy,
    /// Minimum delay in milliseconds
    pub min_delay_ms: u64,
    /// Maximum delay in milliseconds
    pub max_delay_ms: u64,
    /// Mean delay (for Normal strategy)
    pub mean_delay_ms: u64,
    /// Standard deviation (for Normal strategy)
    pub std_dev_ms: u64,
    /// Lambda for exponential distribution
    pub lambda: f64,
}

impl Default for TimingConfig {
    fn default() -> Self {
        TimingConfig {
            strategy: TimingStrategy::Exponential,
            min_delay_ms: 0,
            max_delay_ms: 2000,
            mean_delay_ms: 500,
            std_dev_ms: 200,
            lambda: 0.002, // Average 500ms delay
        }
    }
}

impl TimingConfig {
    /// Validates the configuration parameters.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidInput` if:
    /// - `min_delay_ms` > `max_delay_ms`
    /// - `lambda` <= 0.0 when using Exponential strategy
    /// - `std_dev_ms` is 0 when using Normal strategy
    /// - `mean_delay_ms` > `max_delay_ms` when using Normal strategy
    ///
    /// # Examples
    ///
    /// ```
    /// use b4ae::metadata::timing::TimingConfig;
    ///
    /// let config = TimingConfig::default();
    /// assert!(config.validate().is_ok());
    ///
    /// let mut invalid_config = TimingConfig::default();
    /// invalid_config.min_delay_ms = 2000;
    /// invalid_config.max_delay_ms = 100;
    /// assert!(invalid_config.validate().is_err());
    /// ```
    pub fn validate(&self) -> crate::crypto::CryptoResult<()> {
        use crate::crypto::CryptoError;

        // Validate delay range
        if self.min_delay_ms > self.max_delay_ms {
            return Err(CryptoError::InvalidInput(
                format!(
                    "min_delay_ms ({}) must be <= max_delay_ms ({})",
                    self.min_delay_ms, self.max_delay_ms
                )
            ));
        }

        // Validate strategy-specific parameters
        match self.strategy {
            TimingStrategy::Exponential => {
                if self.lambda <= 0.0 {
                    return Err(CryptoError::InvalidInput(
                        format!(
                            "lambda must be > 0.0 for Exponential strategy, got {}",
                            self.lambda
                        )
                    ));
                }
            }
            TimingStrategy::Normal => {
                if self.std_dev_ms == 0 {
                    return Err(CryptoError::InvalidInput(
                        "std_dev_ms must be > 0 for Normal strategy".to_string()
                    ));
                }
                if self.mean_delay_ms > self.max_delay_ms {
                    return Err(CryptoError::InvalidInput(
                        format!(
                            "mean_delay_ms ({}) should be <= max_delay_ms ({}) for Normal strategy",
                            self.mean_delay_ms, self.max_delay_ms
                        )
                    ));
                }
            }
            TimingStrategy::None | TimingStrategy::Uniform => {
                // No additional validation needed
            }
        }

        Ok(())
    }

    /// Calculate delay based on configured strategy
    pub fn calculate_delay(&self) -> u64 {
        match self.strategy {
            TimingStrategy::None => 0,
            TimingStrategy::Uniform => calculate_delay(self.min_delay_ms, self.max_delay_ms),
            TimingStrategy::Exponential => calculate_exponential_delay(self.lambda, self.max_delay_ms),
            TimingStrategy::Normal => calculate_normal_delay(
                self.mean_delay_ms,
                self.std_dev_ms,
                self.max_delay_ms,
            ),
        }
    }

    /// Get delay as Duration
    pub fn get_delay_duration(&self) -> Duration {
        Duration::from_millis(self.calculate_delay())
    }
}

/// Adaptive timing that adjusts based on network conditions
pub struct AdaptiveTiming {
    config: TimingConfig,
    recent_delays: Vec<u64>,
    max_samples: usize,
}

impl AdaptiveTiming {
    /// Create new adaptive timing
    pub fn new(config: TimingConfig) -> Self {
        AdaptiveTiming {
            config,
            recent_delays: Vec::new(),
            max_samples: 100,
        }
    }

    /// Record actual network delay
    pub fn record_delay(&mut self, delay_ms: u64) {
        self.recent_delays.push(delay_ms);
        if self.recent_delays.len() > self.max_samples {
            self.recent_delays.remove(0);
        }
    }

    /// Calculate delay adjusted for network conditions
    pub fn calculate_adaptive_delay(&self) -> u64 {
        if self.recent_delays.is_empty() {
            return self.config.calculate_delay();
        }

        // Calculate average recent delay
        let avg_delay: u64 = self.recent_delays.iter().sum::<u64>() / self.recent_delays.len() as u64;
        
        // Add random component on top of average
        let random_component = calculate_delay(0, self.config.max_delay_ms / 2);
        
        (avg_delay + random_component).min(self.config.max_delay_ms)
    }

    /// Get current average delay
    pub fn average_delay(&self) -> u64 {
        if self.recent_delays.is_empty() {
            return 0;
        }
        self.recent_delays.iter().sum::<u64>() / self.recent_delays.len() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uniform_delay() {
        let min = 100;
        let max = 500;

        for _ in 0..100 {
            let delay = calculate_delay(min, max);
            assert!(delay >= min && delay <= max);
        }
    }

    #[test]
    fn test_exponential_delay() {
        let lambda = 0.002;
        let max = 5000;

        for _ in 0..100 {
            let delay = calculate_exponential_delay(lambda, max);
            assert!(delay <= max);
        }
    }

    #[test]
    fn test_normal_delay() {
        let mean = 500;
        let std_dev = 100;
        let max = 2000;

        let mut delays = Vec::new();
        for _ in 0..1000 {
            let delay = calculate_normal_delay(mean, std_dev, max);
            assert!(delay <= max);
            delays.push(delay);
        }

        // Check that average is roughly around mean
        let avg: u64 = delays.iter().sum::<u64>() / delays.len() as u64;
        assert!(avg > mean - 100 && avg < mean + 100);
    }

    #[test]
    fn test_timing_config() {
        let config = TimingConfig::default();
        
        for _ in 0..100 {
            let delay = config.calculate_delay();
            assert!(delay <= config.max_delay_ms);
        }
    }

    #[test]
    fn test_adaptive_timing() {
        let config = TimingConfig::default();
        let mut adaptive = AdaptiveTiming::new(config);

        // Record some delays
        adaptive.record_delay(100);
        adaptive.record_delay(200);
        adaptive.record_delay(150);

        assert_eq!(adaptive.average_delay(), 150);

        let delay = adaptive.calculate_adaptive_delay();
        assert!(delay > 0);
    }

    #[test]
    fn test_timing_strategies() {
        let mut config = TimingConfig::default();

        config.strategy = TimingStrategy::None;
        assert_eq!(config.calculate_delay(), 0);

        config.strategy = TimingStrategy::Uniform;
        let delay = config.calculate_delay();
        assert!(delay <= config.max_delay_ms);
    }

    // Tests for TimingObfuscator

    #[test]
    fn test_timing_obfuscator_new() {
        let obfuscator = TimingObfuscator::new(100, 2000).unwrap();
        assert_eq!(obfuscator.min_delay(), Duration::from_millis(100));
        assert_eq!(obfuscator.max_delay(), Duration::from_millis(2000));
    }

    #[test]
    fn test_timing_obfuscator_random_delay_range() {
        let obfuscator = TimingObfuscator::new(100, 2000).unwrap();

        // Test multiple delays to ensure they're in range
        for _ in 0..100 {
            let delay = obfuscator.random_delay();
            assert!(delay >= Duration::from_millis(100));
            assert!(delay <= Duration::from_millis(2000));
        }
    }

    #[test]
    fn test_timing_obfuscator_edge_case_equal_delays() {
        let obfuscator = TimingObfuscator::new(500, 500).unwrap();
        
        // When min == max, should always return that value
        for _ in 0..10 {
            let delay = obfuscator.random_delay();
            assert_eq!(delay, Duration::from_millis(500));
        }
    }

    #[test]
    fn test_timing_obfuscator_zero_delays() {
        let obfuscator = TimingObfuscator::new(0, 0).unwrap();
        
        let delay = obfuscator.random_delay();
        assert_eq!(delay, Duration::from_millis(0));
    }

    #[test]
    fn test_timing_obfuscator_distribution() {
        let obfuscator = TimingObfuscator::new(0, 1000).unwrap();
        
        let mut delays = Vec::new();
        for _ in 0..1000 {
            let delay = obfuscator.random_delay();
            delays.push(delay.as_millis() as u64);
        }

        // Check that we get a reasonable distribution
        // Average should be around 500ms for uniform distribution
        let avg: u64 = delays.iter().sum::<u64>() / delays.len() as u64;
        assert!(avg > 400 && avg < 600, "Average delay {} not in expected range", avg);

        // Check that we get values across the range
        let min_observed = *delays.iter().min().unwrap();
        let max_observed = *delays.iter().max().unwrap();
        assert!(min_observed < 200, "Min observed {} too high", min_observed);
        assert!(max_observed > 800, "Max observed {} too low", max_observed);
    }

    #[test]
    fn test_timing_obfuscator_invalid_range() {
        // Should return error when min > max
        let result = TimingObfuscator::new(2000, 100);
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "min_delay_ms")]
    fn test_timing_obfuscator_unchecked_invalid_range() {
        // Should panic when min > max
        TimingObfuscator::new_unchecked(2000, 100);
    }
}

    // Tests for TimingConfig validation

    #[test]
    fn test_timing_config_default_validation() {
        let config = TimingConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_timing_config_invalid_delay_range() {
        let mut config = TimingConfig::default();
        config.min_delay_ms = 2000;
        config.max_delay_ms = 100;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_timing_config_exponential_invalid_lambda() {
        let mut config = TimingConfig::default();
        config.strategy = TimingStrategy::Exponential;
        config.lambda = 0.0;
        assert!(config.validate().is_err());

        config.lambda = -1.0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_timing_config_exponential_valid_lambda() {
        let mut config = TimingConfig::default();
        config.strategy = TimingStrategy::Exponential;
        config.lambda = 0.001;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_timing_config_normal_invalid_std_dev() {
        let mut config = TimingConfig::default();
        config.strategy = TimingStrategy::Normal;
        config.std_dev_ms = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_timing_config_normal_invalid_mean() {
        let mut config = TimingConfig::default();
        config.strategy = TimingStrategy::Normal;
        config.mean_delay_ms = 3000;
        config.max_delay_ms = 2000;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_timing_config_normal_valid() {
        let mut config = TimingConfig::default();
        config.strategy = TimingStrategy::Normal;
        config.mean_delay_ms = 500;
        config.std_dev_ms = 100;
        config.max_delay_ms = 2000;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_timing_config_uniform_valid() {
        let mut config = TimingConfig::default();
        config.strategy = TimingStrategy::Uniform;
        config.min_delay_ms = 100;
        config.max_delay_ms = 500;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_timing_config_none_valid() {
        let mut config = TimingConfig::default();
        config.strategy = TimingStrategy::None;
        assert!(config.validate().is_ok());
    }
