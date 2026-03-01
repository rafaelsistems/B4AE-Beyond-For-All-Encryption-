//! Integration tests for DoS mitigation metrics
//!
//! This test suite validates the DoS metrics tracking functionality,
//! including counter increments, derived metrics calculations, and
//! thread safety.

use b4ae::protocol::v2::dos_metrics::{DosMetrics, DosMetricsSnapshot, SharedDosMetrics};
use std::sync::Arc;
use std::thread;

#[test]
fn test_metrics_initialization() {
    let metrics = DosMetrics::new();
    
    // All counters should start at zero
    assert_eq!(metrics.cookie_challenges_issued(), 0);
    assert_eq!(metrics.cookie_verifications_succeeded(), 0);
    assert_eq!(metrics.cookie_verifications_failed(), 0);
    assert_eq!(metrics.cookie_expired_rejections(), 0);
    assert_eq!(metrics.replay_detections(), 0);
    assert_eq!(metrics.handshake_attempts(), 0);
    assert_eq!(metrics.handshake_completions(), 0);
    
    // Derived metrics should handle zero values
    assert_eq!(metrics.cookie_success_rate(), 0.0);
    assert_eq!(metrics.handshake_success_rate(), 0.0);
    assert_eq!(metrics.dos_amplification_reduction(), 360.0);
}

#[test]
fn test_cookie_challenge_tracking() {
    let metrics = DosMetrics::new();
    
    // Issue 5 cookie challenges
    for _ in 0..5 {
        metrics.increment_cookie_challenges_issued();
    }
    
    assert_eq!(metrics.cookie_challenges_issued(), 5);
}

#[test]
fn test_cookie_verification_tracking() {
    let metrics = DosMetrics::new();
    
    // Track various verification outcomes
    metrics.increment_cookie_verifications_succeeded();
    metrics.increment_cookie_verifications_succeeded();
    metrics.increment_cookie_verifications_succeeded();
    metrics.increment_cookie_verifications_failed();
    metrics.increment_cookie_expired_rejections();
    
    assert_eq!(metrics.cookie_verifications_succeeded(), 3);
    assert_eq!(metrics.cookie_verifications_failed(), 1);
    assert_eq!(metrics.cookie_expired_rejections(), 1);
    
    // Success rate should be 3/5 = 60%
    assert_eq!(metrics.cookie_success_rate(), 60.0);
}

#[test]
fn test_replay_detection_tracking() {
    let metrics = DosMetrics::new();
    
    // Detect 3 replay attacks
    for _ in 0..3 {
        metrics.increment_replay_detections();
    }
    
    assert_eq!(metrics.replay_detections(), 3);
}

#[test]
fn test_handshake_tracking() {
    let metrics = DosMetrics::new();
    
    // Track 10 handshake attempts, 7 completions
    for _ in 0..10 {
        metrics.increment_handshake_attempts();
    }
    
    for _ in 0..7 {
        metrics.increment_handshake_completions();
    }
    
    assert_eq!(metrics.handshake_attempts(), 10);
    assert_eq!(metrics.handshake_completions(), 7);
    assert_eq!(metrics.handshake_success_rate(), 70.0);
}

#[test]
fn test_dos_amplification_calculation() {
    let metrics = DosMetrics::new();
    
    // DoS amplification reduction should always be 360x
    // (3.6ms expensive crypto / 0.01ms HMAC = 360)
    assert_eq!(metrics.dos_amplification_reduction(), 360.0);
}

#[test]
fn test_snapshot_consistency() {
    let metrics = DosMetrics::new();
    
    // Set up some metrics
    metrics.increment_cookie_challenges_issued();
    metrics.increment_cookie_challenges_issued();
    metrics.increment_cookie_verifications_succeeded();
    metrics.increment_cookie_verifications_failed();
    metrics.increment_replay_detections();
    metrics.increment_handshake_attempts();
    metrics.increment_handshake_attempts();
    metrics.increment_handshake_completions();
    
    let snapshot = metrics.snapshot();
    
    // Verify snapshot matches current state
    assert_eq!(snapshot.cookie_challenges_issued, 2);
    assert_eq!(snapshot.cookie_verifications_succeeded, 1);
    assert_eq!(snapshot.cookie_verifications_failed, 1);
    assert_eq!(snapshot.replay_detections, 1);
    assert_eq!(snapshot.handshake_attempts, 2);
    assert_eq!(snapshot.handshake_completions, 1);
    
    // Verify derived metrics
    assert_eq!(snapshot.cookie_success_rate, 50.0);
    assert_eq!(snapshot.handshake_success_rate, 50.0);
    assert_eq!(snapshot.dos_amplification_reduction, 360.0);
}

#[test]
fn test_snapshot_helper_methods() {
    let metrics = DosMetrics::new();
    
    metrics.increment_cookie_verifications_succeeded();
    metrics.increment_cookie_verifications_succeeded();
    metrics.increment_cookie_verifications_failed();
    metrics.increment_cookie_expired_rejections();
    metrics.increment_handshake_attempts();
    metrics.increment_handshake_attempts();
    metrics.increment_handshake_attempts();
    metrics.increment_handshake_completions();
    
    let snapshot = metrics.snapshot();
    
    // Total verifications = succeeded + failed + expired
    assert_eq!(snapshot.total_cookie_verifications(), 4);
    
    // Total rejections = failed + expired
    assert_eq!(snapshot.total_cookie_rejections(), 2);
    
    // Failed handshakes = attempts - completions
    assert_eq!(snapshot.failed_handshakes(), 2);
}

#[test]
fn test_reset_functionality() {
    let metrics = DosMetrics::new();
    
    // Set up some metrics
    metrics.increment_cookie_challenges_issued();
    metrics.increment_cookie_verifications_succeeded();
    metrics.increment_replay_detections();
    metrics.increment_handshake_attempts();
    
    // Verify metrics are set
    assert_eq!(metrics.cookie_challenges_issued(), 1);
    assert_eq!(metrics.cookie_verifications_succeeded(), 1);
    assert_eq!(metrics.replay_detections(), 1);
    assert_eq!(metrics.handshake_attempts(), 1);
    
    // Reset all metrics
    metrics.reset();
    
    // Verify all metrics are zero
    assert_eq!(metrics.cookie_challenges_issued(), 0);
    assert_eq!(metrics.cookie_verifications_succeeded(), 0);
    assert_eq!(metrics.replay_detections(), 0);
    assert_eq!(metrics.handshake_attempts(), 0);
}

#[test]
fn test_concurrent_updates() {
    let metrics: SharedDosMetrics = Arc::new(DosMetrics::new());
    let mut handles = vec![];
    
    // Spawn 5 threads, each incrementing different counters
    for i in 0..5 {
        let metrics_clone = Arc::clone(&metrics);
        let handle = thread::spawn(move || {
            for _ in 0..20 {
                match i {
                    0 => metrics_clone.increment_cookie_challenges_issued(),
                    1 => metrics_clone.increment_cookie_verifications_succeeded(),
                    2 => metrics_clone.increment_replay_detections(),
                    3 => metrics_clone.increment_handshake_attempts(),
                    4 => metrics_clone.increment_handshake_completions(),
                    _ => {}
                }
            }
        });
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Each counter should have 20 increments
    assert_eq!(metrics.cookie_challenges_issued(), 20);
    assert_eq!(metrics.cookie_verifications_succeeded(), 20);
    assert_eq!(metrics.replay_detections(), 20);
    assert_eq!(metrics.handshake_attempts(), 20);
    assert_eq!(metrics.handshake_completions(), 20);
}

#[test]
fn test_realistic_dos_attack_scenario() {
    let metrics = DosMetrics::new();
    
    // Simulate a DoS attack scenario:
    // - 1000 handshake attempts (many from attacker)
    // - 1000 cookie challenges issued
    // - 100 valid cookies (legitimate users)
    // - 800 invalid cookies (attacker with wrong cookies)
    // - 50 expired cookies (attacker replaying old cookies)
    // - 50 replay detections (attacker replaying valid cookies)
    // - 90 successful handshakes (some legitimate users fail for other reasons)
    
    for _ in 0..1000 {
        metrics.increment_handshake_attempts();
        metrics.increment_cookie_challenges_issued();
    }
    
    for _ in 0..100 {
        metrics.increment_cookie_verifications_succeeded();
    }
    
    for _ in 0..800 {
        metrics.increment_cookie_verifications_failed();
    }
    
    for _ in 0..50 {
        metrics.increment_cookie_expired_rejections();
    }
    
    for _ in 0..50 {
        metrics.increment_replay_detections();
    }
    
    for _ in 0..90 {
        metrics.increment_handshake_completions();
    }
    
    let snapshot = metrics.snapshot();
    
    // Verify attack metrics
    assert_eq!(snapshot.cookie_challenges_issued, 1000);
    assert_eq!(snapshot.total_cookie_verifications(), 950);
    assert_eq!(snapshot.total_cookie_rejections(), 850);
    assert_eq!(snapshot.replay_detections, 50);
    
    // Cookie success rate should be low (100/950 ≈ 10.5%)
    assert!((snapshot.cookie_success_rate - 10.526).abs() < 0.01);
    
    // Handshake success rate should be low (90/1000 = 9%)
    assert_eq!(snapshot.handshake_success_rate, 9.0);
    
    // DoS amplification reduction demonstrates effectiveness
    assert_eq!(snapshot.dos_amplification_reduction, 360.0);
    
    // Calculate cost savings:
    // Without cookie: 1000 attempts × 3.6ms = 3600ms
    // With cookie: 90 valid × 3.6ms + 910 invalid × 0.01ms = 324ms + 9.1ms = 333.1ms
    // Savings: 3600ms - 333.1ms = 3266.9ms (91% reduction in CPU time)
}

#[test]
fn test_legitimate_traffic_scenario() {
    let metrics = DosMetrics::new();
    
    // Simulate legitimate traffic:
    // - 100 handshake attempts
    // - 100 cookie challenges issued
    // - 98 valid cookies (2 expired due to network delay)
    // - 0 invalid cookies
    // - 2 expired cookies
    // - 0 replay detections
    // - 95 successful handshakes (3 fail for other reasons)
    
    for _ in 0..100 {
        metrics.increment_handshake_attempts();
        metrics.increment_cookie_challenges_issued();
    }
    
    for _ in 0..98 {
        metrics.increment_cookie_verifications_succeeded();
    }
    
    for _ in 0..2 {
        metrics.increment_cookie_expired_rejections();
    }
    
    for _ in 0..95 {
        metrics.increment_handshake_completions();
    }
    
    let snapshot = metrics.snapshot();
    
    // Verify legitimate traffic metrics
    assert_eq!(snapshot.cookie_challenges_issued, 100);
    assert_eq!(snapshot.total_cookie_verifications(), 100);
    assert_eq!(snapshot.cookie_success_rate, 98.0);
    assert_eq!(snapshot.replay_detections, 0);
    assert_eq!(snapshot.handshake_success_rate, 95.0);
}

#[test]
fn test_metrics_independence_after_clone() {
    let metrics1 = DosMetrics::new();
    
    metrics1.increment_cookie_challenges_issued();
    metrics1.increment_handshake_attempts();
    
    let metrics2 = metrics1.clone();
    
    // Both should have same initial values
    assert_eq!(metrics1.cookie_challenges_issued(), 1);
    assert_eq!(metrics2.cookie_challenges_issued(), 1);
    
    // Increment metrics1
    metrics1.increment_cookie_challenges_issued();
    
    // metrics1 should change, metrics2 should not
    assert_eq!(metrics1.cookie_challenges_issued(), 2);
    assert_eq!(metrics2.cookie_challenges_issued(), 1);
    
    // Increment metrics2
    metrics2.increment_handshake_attempts();
    
    // metrics2 should change, metrics1 should not
    assert_eq!(metrics1.handshake_attempts(), 1);
    assert_eq!(metrics2.handshake_attempts(), 2);
}

#[test]
fn test_edge_case_zero_division() {
    let metrics = DosMetrics::new();
    
    // With no verifications, success rate should be 0.0 (not panic)
    assert_eq!(metrics.cookie_success_rate(), 0.0);
    
    // With no handshake attempts, success rate should be 0.0 (not panic)
    assert_eq!(metrics.handshake_success_rate(), 0.0);
}

#[test]
fn test_edge_case_all_failures() {
    let metrics = DosMetrics::new();
    
    // All cookie verifications fail
    for _ in 0..10 {
        metrics.increment_cookie_verifications_failed();
    }
    
    // Success rate should be 0%
    assert_eq!(metrics.cookie_success_rate(), 0.0);
    
    // All handshakes fail
    for _ in 0..10 {
        metrics.increment_handshake_attempts();
    }
    
    // Success rate should be 0%
    assert_eq!(metrics.handshake_success_rate(), 0.0);
}

#[test]
fn test_edge_case_all_successes() {
    let metrics = DosMetrics::new();
    
    // All cookie verifications succeed
    for _ in 0..10 {
        metrics.increment_cookie_verifications_succeeded();
    }
    
    // Success rate should be 100%
    assert_eq!(metrics.cookie_success_rate(), 100.0);
    
    // All handshakes succeed
    for _ in 0..10 {
        metrics.increment_handshake_attempts();
        metrics.increment_handshake_completions();
    }
    
    // Success rate should be 100%
    assert_eq!(metrics.handshake_success_rate(), 100.0);
}

#[test]
fn test_snapshot_equality() {
    let metrics = DosMetrics::new();
    
    metrics.increment_cookie_challenges_issued();
    metrics.increment_handshake_attempts();
    
    let snapshot1 = metrics.snapshot();
    let snapshot2 = metrics.snapshot();
    
    // Two snapshots taken at same time should be equal
    assert_eq!(snapshot1, snapshot2);
}

#[test]
fn test_default_trait() {
    let metrics = DosMetrics::default();
    
    // Default should be same as new()
    assert_eq!(metrics.cookie_challenges_issued(), 0);
    assert_eq!(metrics.handshake_attempts(), 0);
}

#[test]
fn test_large_counter_values() {
    let metrics = DosMetrics::new();
    
    // Test with large values (simulate long-running server)
    for _ in 0..1_000_000 {
        metrics.increment_cookie_challenges_issued();
    }
    
    assert_eq!(metrics.cookie_challenges_issued(), 1_000_000);
}

#[test]
fn test_mixed_verification_outcomes() {
    let metrics = DosMetrics::new();
    
    // Mix of all verification outcomes
    for _ in 0..50 {
        metrics.increment_cookie_verifications_succeeded();
    }
    
    for _ in 0..30 {
        metrics.increment_cookie_verifications_failed();
    }
    
    for _ in 0..20 {
        metrics.increment_cookie_expired_rejections();
    }
    
    let snapshot = metrics.snapshot();
    
    // Total verifications = 100
    assert_eq!(snapshot.total_cookie_verifications(), 100);
    
    // Success rate = 50/100 = 50%
    assert_eq!(snapshot.cookie_success_rate, 50.0);
    
    // Total rejections = 30 + 20 = 50
    assert_eq!(snapshot.total_cookie_rejections(), 50);
}
