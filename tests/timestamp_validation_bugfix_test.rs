//! Bug Condition Exploration Test for Timestamp Validation Fix
//!
//! This test demonstrates the bug where validate_security() uses hardcoded
//! current_timestamp = 0, making timestamp validation non-functional.
//!
//! **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists.
//! The test encodes the expected behavior (accepting current timestamps).
//! When the code is fixed, this test will pass.

use b4ae::security::hardened_core::SecurityError;
use b4ae::security::protocol::{
    SecurityMessageHeader, ProtocolVersion, MessageType, CipherSuite
};
use proptest::prelude::*;

/// **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 2.4**
///
/// Property 1: Fault Condition - Timestamp Validation Uses Hardcoded Zero
///
/// This property tests that validate_security() SHOULD accept messages with timestamps
/// near the CURRENT time (within MAX_TIMESTAMP_DRIFT = 3600 seconds).
///
/// **EXPECTED OUTCOME ON UNFIXED CODE**: This test will FAIL because the hardcoded
/// current_timestamp = 0 makes validation compare against Unix epoch (1970), causing
/// current timestamps (e.g., from 2024) to be incorrectly REJECTED as too far in the future.
///
/// **EXPECTED OUTCOME AFTER FIX**: This test will PASS because the actual current time
/// will be used, properly accepting timestamps within the drift window.
///
/// This test demonstrates the bug by showing that valid current timestamps are rejected.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_timestamp_validation_accepts_current_timestamps(
        // Generate timestamps within ±1 hour of current time
        // This simulates legitimate messages with current timestamps
        offset in -3600i64..=3600i64
    ) {
        let current_time = crate::time::current_time_secs();
        let timestamp = if offset < 0 {
            current_time.saturating_sub(offset.abs() as u64)
        } else {
            current_time.saturating_add(offset as u64)
        };

        // Create a valid header with a current timestamp
        let header = SecurityMessageHeader {
            version: ProtocolVersion::V1_0,
            message_type: MessageType::Data,
            cipher_suite: CipherSuite::Aes256Gcm,
            message_id: 12345,
            payload_length: 1024, // Valid payload size
            timestamp,
        };

        // Validate the header
        let result = header.validate_security();

        // EXPECTED BEHAVIOR: Should accept timestamps within MAX_TIMESTAMP_DRIFT
        // of current time (no timestamp error)
        //
        // ON UNFIXED CODE: This assertion will FAIL because hardcoded
        // current_timestamp = 0 makes validation reject current timestamps
        // (e.g., 1704067200 for 2024) as too far in the future.
        //
        // AFTER FIX: This assertion will PASS because actual current time
        // will be used, properly accepting these valid timestamps.
        prop_assert!(
            !matches!(result, Err(SecurityError::InvalidTimestamp(_))),
            "Expected no InvalidTimestamp error for current timestamp {} (offset {}), but got: {:?}",
            timestamp,
            offset,
            result
        );
    }
}

// Need to import the time module
use b4ae::time;

/// Unit test: Current timestamp should be accepted
///
/// **Validates: Requirements 2.3, 2.4**
#[test]
fn test_current_timestamp_should_be_accepted() {
    let current_time = b4ae::time::current_time_secs();
    
    let header = SecurityMessageHeader {
        version: ProtocolVersion::V1_0,
        message_type: MessageType::Data,
        cipher_suite: CipherSuite::Aes256Gcm,
        message_id: 1,
        payload_length: 100,
        timestamp: current_time,
    };

    let result = header.validate_security();

    // EXPECTED: Should be accepted (within drift window of current time)
    // ON UNFIXED CODE: Will incorrectly reject because current_time is far from 0
    assert!(
        !matches!(result, Err(SecurityError::InvalidTimestamp(_))),
        "Expected no InvalidTimestamp for current timestamp {}, got: {:?}",
        current_time,
        result
    );
}

/// Unit test: Timestamp 1 hour ago should be accepted
///
/// **Validates: Requirements 2.1, 2.4**
#[test]
fn test_timestamp_one_hour_ago_should_be_accepted() {
    let current_time = b4ae::time::current_time_secs();
    let one_hour_ago = current_time.saturating_sub(3600);
    
    let header = SecurityMessageHeader {
        version: ProtocolVersion::V1_0,
        message_type: MessageType::HandshakeInit,
        cipher_suite: CipherSuite::HybridKyber1024X25519,
        message_id: 2,
        payload_length: 500,
        timestamp: one_hour_ago,
    };

    let result = header.validate_security();

    // EXPECTED: Should be accepted (exactly at drift boundary)
    // ON UNFIXED CODE: Will incorrectly reject
    assert!(
        !matches!(result, Err(SecurityError::InvalidTimestamp(_))),
        "Expected no InvalidTimestamp for 1-hour-old timestamp {}, got: {:?}",
        one_hour_ago,
        result
    );
}

/// Unit test: Timestamp 1 hour in future should be accepted
///
/// **Validates: Requirements 2.2, 2.4**
#[test]
fn test_timestamp_one_hour_future_should_be_accepted() {
    let current_time = b4ae::time::current_time_secs();
    let one_hour_future = current_time.saturating_add(3600);
    
    let header = SecurityMessageHeader {
        version: ProtocolVersion::V1_0,
        message_type: MessageType::KeepAlive,
        cipher_suite: CipherSuite::Aes256Gcm,
        message_id: 3,
        payload_length: 50,
        timestamp: one_hour_future,
    };

    let result = header.validate_security();

    // EXPECTED: Should be accepted (exactly at drift boundary)
    // ON UNFIXED CODE: Will incorrectly reject
    assert!(
        !matches!(result, Err(SecurityError::InvalidTimestamp(_))),
        "Expected no InvalidTimestamp for 1-hour-future timestamp {}, got: {:?}",
        one_hour_future,
        result
    );
}

/// Unit test: Demonstrates the bug - epoch timestamp incorrectly passes
///
/// **Validates: Requirements 1.1, 1.3**
#[test]
fn test_bug_demonstration_epoch_timestamp_incorrectly_passes() {
    // This timestamp is from 1970, should be rejected
    let epoch_timestamp = 100u64;
    
    let header = SecurityMessageHeader {
        version: ProtocolVersion::V1_0,
        message_type: MessageType::Data,
        cipher_suite: CipherSuite::Aes256Gcm,
        message_id: 4,
        payload_length: 100,
        timestamp: epoch_timestamp,
    };

    let result = header.validate_security();

    // ON UNFIXED CODE: This will PASS validation (bug!)
    // AFTER FIX: This will correctly FAIL validation
    //
    // This test documents the bug behavior but doesn't assert on it
    // because we want the test suite to pass after the fix
    println!("Bug demonstration: epoch timestamp (100) validation result: {:?}", result);
    println!("On unfixed code, this should be Ok(()) - demonstrating the bug");
    println!("After fix, this should be Err(InvalidTimestamp(_))");
}
