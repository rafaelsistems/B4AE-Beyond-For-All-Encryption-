// B4AE Timing Obfuscation Implementation
// Random delays to prevent timing analysis attacks

use crate::crypto::random::random_range;
use std::time::Duration;

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
}
