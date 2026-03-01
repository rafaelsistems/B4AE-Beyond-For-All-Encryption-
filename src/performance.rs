//! B4AE Performance Monitoring and Profiling Tools
//!
//! Real-time performance monitoring for production deployments

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};
use serde::{Serialize, Deserialize};

/// Performance metrics for B4AE operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Operation name
    pub operation: String,
    /// Number of operations
    pub count: u64,
    /// Total time in microseconds
    pub total_time_us: u64,
    /// Average time in microseconds
    pub avg_time_us: u64,
    /// Minimum time in microseconds
    pub min_time_us: u64,
    /// Maximum time in microseconds
    pub max_time_us: u64,
    /// Operations per second
    pub ops_per_second: f64,
    /// Error count
    pub error_count: u64,
    /// Error rate (0.0 - 1.0)
    pub error_rate: f64,
    /// Memory usage in bytes (if available)
    pub memory_usage_bytes: Option<u64>,
    /// Last updated timestamp
    pub last_updated: SystemTime,
}

impl PerformanceMetrics {
    /// Create new metrics for an operation
    pub fn new(operation: String) -> Self {
        Self {
            operation,
            count: 0,
            total_time_us: 0,
            avg_time_us: 0,
            min_time_us: u64::MAX,
            max_time_us: 0,
            ops_per_second: 0.0,
            error_count: 0,
            error_rate: 0.0,
            memory_usage_bytes: None,
            last_updated: SystemTime::now(),
        }
    }

    /// Record a successful operation
    pub fn record_success(&mut self, duration: Duration) {
        let duration_us = duration.as_micros() as u64;
        self.count += 1;
        self.total_time_us += duration_us;
        self.avg_time_us = self.total_time_us / self.count;
        self.min_time_us = self.min_time_us.min(duration_us);
        self.max_time_us = self.max_time_us.max(duration_us);
        
        // Calculate ops per second based on recent activity
        if let Ok(elapsed) = self.last_updated.elapsed() {
            if elapsed.as_secs() > 0 {
                self.ops_per_second = self.count as f64 / elapsed.as_secs_f64();
            }
        }
        
        self.last_updated = SystemTime::now();
    }

    /// Record a failed operation
    pub fn record_error(&mut self, duration: Duration) {
        self.record_success(duration);
        self.error_count += 1;
        self.error_rate = self.error_count as f64 / self.count as f64;
    }

    /// Update memory usage
    pub fn update_memory_usage(&mut self, bytes: u64) {
        self.memory_usage_bytes = Some(bytes);
    }

    /// Get performance summary
    pub fn summary(&self) -> String {
        format!(
            "{}: {} ops, {:.2} ops/s, avg: {}μs, min: {}μs, max: {}μs, errors: {} ({:.2}%)",
            self.operation,
            self.count,
            self.ops_per_second,
            self.avg_time_us,
            self.min_time_us,
            self.max_time_us,
            self.error_count,
            self.error_rate * 100.0
        )
    }
}

/// Performance monitor for B4AE operations
#[derive(Debug, Clone)]
pub struct PerformanceMonitor {
    metrics: Arc<RwLock<HashMap<String, PerformanceMetrics>>>,
    enabled: Arc<RwLock<bool>>,
    start_time: Instant,
}

impl PerformanceMonitor {
    /// Create new performance monitor
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
            enabled: Arc::new(RwLock::new(true)),
            start_time: Instant::now(),
        }
    }

    /// Enable performance monitoring
    pub fn enable(&self) {
        if let Ok(mut guard) = self.enabled.write() {
            *guard = true;
        }
    }

    /// Disable performance monitoring
    pub fn disable(&self) {
        if let Ok(mut guard) = self.enabled.write() {
            *guard = false;
        }
    }

    /// Check if monitoring is enabled
    pub fn is_enabled(&self) -> bool {
        *self.enabled.read().unwrap()
    }

    /// Record operation timing
    pub fn record_operation<F, R>(&self, operation: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        if !self.is_enabled() {
            return f();
        }

        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();

        let mut metrics = self.metrics.write().unwrap();
        let metric = metrics.entry(operation.to_string())
            .or_insert_with(|| PerformanceMetrics::new(operation.to_string()));
        metric.record_success(duration);

        result
    }

    /// Record operation with error handling
    pub fn record_operation_result<F, R>(&self, operation: &str, f: F) -> Result<R, Box<dyn std::error::Error>>
    where
        F: FnOnce() -> Result<R, Box<dyn std::error::Error>>,
    {
        if !self.is_enabled() {
            return f();
        }

        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();

        let mut metrics = self.metrics.write().unwrap();
        let metric = metrics.entry(operation.to_string())
            .or_insert_with(|| PerformanceMetrics::new(operation.to_string()));

        match &result {
            Ok(_) => metric.record_success(duration),
            Err(_) => metric.record_error(duration),
        }

        result
    }

    /// Get metrics for specific operation
    pub fn get_metrics(&self, operation: &str) -> Option<PerformanceMetrics> {
        self.metrics.read().ok()?.get(operation).cloned()
    }

    /// Get all metrics
    pub fn get_all_metrics(&self) -> HashMap<String, PerformanceMetrics> {
        self.metrics.read().unwrap().clone()
    }

    /// Get system uptime
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Generate performance report
    pub fn generate_report(&self) -> PerformanceReport {
        let metrics = self.get_all_metrics();
        let uptime = self.uptime();
        
        PerformanceReport {
            uptime,
            total_operations: metrics.values().map(|m| m.count).sum(),
            total_errors: metrics.values().map(|m| m.error_count).sum(),
            operations: metrics,
            timestamp: SystemTime::now(),
        }
    }

    /// Reset all metrics
    pub fn reset(&mut self) {
        self.metrics.write().unwrap().clear();
        self.start_time = Instant::now();
    }
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Comprehensive performance report
#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceReport {
    pub uptime: Duration,
    pub total_operations: u64,
    pub total_errors: u64,
    pub operations: HashMap<String, PerformanceMetrics>,
    pub timestamp: SystemTime,
}

impl PerformanceReport {
    /// Generate human-readable report
    pub fn to_string(&self) -> String {
        let mut report = String::new();
        report.push_str(&format!("B4AE Performance Report\n"));
        report.push_str(&format!("Uptime: {:.2} seconds\n", self.uptime.as_secs_f64()));
        report.push_str(&format!("Total Operations: {}\n", self.total_operations));
        report.push_str(&format!("Total Errors: {}\n", self.total_errors));
        report.push_str(&format!("Overall Error Rate: {:.2}%\n", 
            (self.total_errors as f64 / self.total_operations as f64) * 100.0));
        report.push_str("\nOperation Details:\n");
        
        for (operation, metrics) in &self.operations {
            report.push_str(&format!("  {}: {}\n", operation, metrics.summary()));
        }
        
        report
    }

    /// Export as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Real-time performance dashboard
#[derive(Debug, Clone)]
pub struct PerformanceDashboard {
    monitor: PerformanceMonitor,
    update_interval: Duration,
}

impl PerformanceDashboard {
    /// Create new performance dashboard
    pub fn new(update_interval: Duration) -> Self {
        Self {
            monitor: PerformanceMonitor::new(),
            update_interval,
        }
    }

    /// Start monitoring in background thread
    pub fn start_monitoring(&self) {
        let monitor = self.monitor.clone();
        let interval = self.update_interval;
        
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(interval);
                let report = monitor.generate_report();
                println!("{}", report.to_string());
            }
        });
    }

    /// Get performance monitor for recording operations
    pub fn monitor(&self) -> PerformanceMonitor {
        self.monitor.clone()
    }
}

/// Performance profiling utilities
pub mod profiling {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    /// Save performance report to file
    pub fn save_report(report: &PerformanceReport, filename: &str) -> std::io::Result<()> {
        let mut file = File::create(filename)?;
        file.write_all(report.to_string().as_bytes())?;
        
        // Also save JSON version
        let json_filename = format!("{}.json", filename.trim_end_matches(".txt"));
        let mut json_file = File::create(json_filename)?;
        json_file.write_all(report.to_json().unwrap().as_bytes())?;
        
        Ok(())
    }

    /// Load performance report from file
    pub fn load_report(filename: &str) -> Result<PerformanceReport, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(filename)?;
        let report: PerformanceReport = serde_json::from_str(&content)?;
        Ok(report)
    }

    /// Compare two performance reports
    pub fn compare_reports(baseline: &PerformanceReport, current: &PerformanceReport) -> String {
        let mut comparison = String::new();
        comparison.push_str("Performance Comparison Report\n");
        comparison.push_str("=============================\n\n");
        
        // Compare overall metrics
        comparison.push_str(&format!("Baseline Operations: {}\n", baseline.total_operations));
        comparison.push_str(&format!("Current Operations: {}\n", current.total_operations));
        comparison.push_str(&format!("Operations Change: {:.1}%\n", 
            ((current.total_operations as f64 - baseline.total_operations as f64) / baseline.total_operations as f64) * 100.0));
        
        comparison.push_str(&format!("Baseline Errors: {}\n", baseline.total_errors));
        comparison.push_str(&format!("Current Errors: {}\n", current.total_errors));
        
        // Compare operation-specific metrics
        comparison.push_str("\nOperation Comparison:\n");
        for (operation, current_metrics) in &current.operations {
            if let Some(baseline_metrics) = baseline.operations.get(operation) {
                let avg_change = ((current_metrics.avg_time_us as f64 - baseline_metrics.avg_time_us as f64) / baseline_metrics.avg_time_us as f64) * 100.0;
                comparison.push_str(&format!("  {}: {:.1}% avg time change\n", operation, avg_change));
            }
        }
        
        comparison
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_monitor() {
        let monitor = PerformanceMonitor::new();
        
        // Test basic operation recording
        monitor.record_operation("test_operation", || {
            std::thread::sleep(Duration::from_millis(10));
            "result"
        });
        
        let metrics = monitor.get_metrics("test_operation").unwrap();
        assert_eq!(metrics.operation, "test_operation");
        assert_eq!(metrics.count, 1);
        assert!(metrics.avg_time_us >= 10_000); // At least 10ms
    }

    #[test]
    fn test_error_recording() {
        let monitor = PerformanceMonitor::new();
        
        let result: Result<String, Box<dyn std::error::Error>> = monitor.record_operation_result("error_operation", || {
            std::thread::sleep(Duration::from_millis(5));
            Err("test error".into())
        });
        
        assert!(result.is_err());
        
        let metrics = monitor.get_metrics("error_operation").unwrap();
        assert_eq!(metrics.error_count, 1);
        assert!(metrics.error_rate > 0.0);
    }

    #[test]
    fn test_performance_report() {
        let monitor = PerformanceMonitor::new();
        
        // Record some operations
        for _ in 0..5 {
            monitor.record_operation("report_test", || {
                std::thread::sleep(Duration::from_millis(1));
            });
        }
        
        let report = monitor.generate_report();
        assert_eq!(report.total_operations, 5);
        assert_eq!(report.total_errors, 0);
        assert!(report.operations.contains_key("report_test"));
    }
}