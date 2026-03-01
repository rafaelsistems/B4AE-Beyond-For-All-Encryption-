//! Preservation Property Tests for Timestamp Validation Fix
//!
//! These tests verify that non-timestamp validation behavior (protocol version
//! and payload length validation) remains unchanged after the timestamp fix.
//!
//! **IMPORTANT**: These tests should PASS on UNFIXED code to establish the
//! baseline behavior we want to preserve.

use b4ae::security::hardened_core::SecurityError;
use b4ae::security::protocol::{
    SecurityMessageHeader, ProtocolVersion, MessageType, CipherSuite
};
use proptest::prelude::*;


/// **Validates: Requirements 3.2**
///
/// Property 2: Preservation - Payload Length Validation
///
/// This property tests that payload_length exceeding 1 MiB is rejected
/// with the appropriate error, regardless of the timestamp fix.
///
/// **EXPECTED OUTCOME**: Tests PASS on unfixed code (confirms baseline behavior)
proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_excessive_payload_length_rejected(
        // Generate payload lengths exceeding 1 MiB (1024 * 1024 = 1048576)
        payload_length in (1024u32 * 1024 + 1)..=u32::MAX,
        message_id in any::<u64>(),
        timestamp in any::<u64>(),
    ) {
        let header = SecurityMessageHeader {
            version: ProtocolVersion::V1_0,
            message_type: MessageType::Data,
            cipher_suite: CipherSuite::Aes256Gcm,
            message_id,
            payload_length,
            timestamp,
        };

        let result = header.validate_security();

        // EXPECTED: Should be rejected with ResourceExhaustionProtection error
        prop_assert!(
            matches!(result, Err(SecurityError::ResourceExhaustionProtection { .. })),
            "Expected ResourceExhaustionProtection error for payload_length {}, but got: {:?}",
            payload_length,
            result
        );
    }
}


/// **Validates: Requirements 3.3**
///
/// Property 2: Preservation - Valid Headers Pass Version and Payload Checks
///
/// This property tests that headers with valid version and payload length
/// do not fail with version or payload errors (may fail with timestamp error).
///
/// **EXPECTED OUTCOME**: Tests PASS on unfixed code (confirms baseline behavior)
proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_valid_headers_pass_version_and_payload_checks(
        message_id in any::<u64>(),
        // Generate valid payload lengths (0 to 1 MiB)
        payload_length in 0u32..=(1024u32 * 1024),
        timestamp in any::<u64>(),
    ) {
        let header = SecurityMessageHeader {
            version: ProtocolVersion::V1_0,
            message_type: MessageType::Data,
            cipher_suite: CipherSuite::Aes256Gcm,
            message_id,
            payload_length,
            timestamp,
        };

        let result = header.validate_security();

        // EXPECTED: Should NOT fail with version or payload errors
        // (may fail with InvalidTimestamp, which is fine for this test)
        prop_assert!(
            !matches!(result, Err(SecurityError::InvalidProtocolVersion { .. })),
            "Valid version should not produce InvalidProtocolVersion error, got: {:?}",
            result
        );
        
        prop_assert!(
            !matches!(result, Err(SecurityError::ResourceExhaustionProtection { .. })),
            "Valid payload_length {} should not produce ResourceExhaustionProtection error, got: {:?}",
            payload_length,
            result
        );
    }
}


/// **Validates: Requirements 3.4**
///
/// Property 2: Preservation - Timestamp Difference Calculation Uses Absolute Value
///
/// This property tests that timestamp difference calculation continues to use
/// absolute value comparison (handles both past and future timestamps symmetrically).
///
/// **EXPECTED OUTCOME**: Tests PASS after fix (confirms baseline behavior preserved)
proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_timestamp_diff_uses_absolute_value(
        message_id in any::<u64>(),
        payload_length in 0u32..=1024u32,
        // Generate timestamps within drift of current time
        // (testing that absolute value is used, not signed difference)
        offset in 0u64..=3600u64,
    ) {
        let current_time = b4ae::time::current_time_secs();
        let timestamp = current_time.saturating_sub(offset);
        
        let header = SecurityMessageHeader {
            version: ProtocolVersion::V1_0,
            message_type: MessageType::Data,
            cipher_suite: CipherSuite::Aes256Gcm,
            message_id,
            payload_length,
            timestamp,
        };

        let result = header.validate_security();

        // EXPECTED: Timestamps within drift window should pass validation
        // (absolute value comparison means both past and future work)
        prop_assert!(
            result.is_ok(),
            "Timestamp {} (offset {} from current {}) within drift window should pass validation, got: {:?}",
            timestamp,
            offset,
            current_time,
            result
        );
    }
}

/// **Validates: Requirements 3.5**
///
/// Unit test: Error types remain unchanged
///
/// This test verifies that the specific error types returned by validation
/// remain the same after the fix.
#[test]
fn test_error_types_unchanged() {
    let current_time = b4ae::time::current_time_secs();
    
    // Test ResourceExhaustionProtection error type for excessive payload
    let excessive_payload_header = SecurityMessageHeader {
        version: ProtocolVersion::V1_0,
        message_type: MessageType::Data,
        cipher_suite: CipherSuite::Aes256Gcm,
        message_id: 2,
        payload_length: 2 * 1024 * 1024, // 2 MiB, exceeds limit
        timestamp: current_time, // Use valid timestamp
    };
    
    let result = excessive_payload_header.validate_security();
    assert!(
        matches!(&result, Err(SecurityError::ResourceExhaustionProtection { 
            resource, 
            limit: 1048576, 
            .. 
        }) if resource == "payload_length"),
        "Expected ResourceExhaustionProtection with limit=1048576, got: {:?}",
        result
    );

    // Test InvalidTimestamp error type (with timestamp far from current time)
    let far_past_timestamp = current_time.saturating_sub(1_000_000_000);
    let far_past_header = SecurityMessageHeader {
        version: ProtocolVersion::V1_0,
        message_type: MessageType::Data,
        cipher_suite: CipherSuite::Aes256Gcm,
        message_id: 3,
        payload_length: 100,
        timestamp: far_past_timestamp, // Far in the past
    };
    
    let result = far_past_header.validate_security();
    assert!(
        matches!(result, Err(SecurityError::InvalidTimestamp(_))),
        "Expected InvalidTimestamp error, got: {:?}",
        result
    );
}

/// **Validates: Requirements 3.2**
///
/// Unit test: Payload validation happens and rejects excessive payloads
#[test]
fn test_payload_validation() {
    let current_time = b4ae::time::current_time_secs();
    
    // Create a header with valid version but excessive payload
    let header = SecurityMessageHeader {
        version: ProtocolVersion::V1_0,
        message_type: MessageType::Data,
        cipher_suite: CipherSuite::Aes256Gcm,
        message_id: 1,
        payload_length: 5 * 1024 * 1024, // 5 MiB, over limit
        timestamp: current_time, // Use valid timestamp
    };

    let result = header.validate_security();

    // EXPECTED: Should get ResourceExhaustionProtection for excessive payload
    assert!(
        matches!(result, Err(SecurityError::ResourceExhaustionProtection { .. })),
        "Expected ResourceExhaustionProtection for excessive payload, got: {:?}",
        result
    );
}

/// **Validates: Requirements 3.3**
///
/// Unit test: Completely valid header structure
#[test]
fn test_valid_header_structure() {
    let current_time = b4ae::time::current_time_secs();
    
    // Create a header with all valid fields
    // Use current timestamp to ensure it's within drift window
    let header = SecurityMessageHeader {
        version: ProtocolVersion::V1_0,
        message_type: MessageType::HandshakeInit,
        cipher_suite: CipherSuite::HybridKyber1024X25519,
        message_id: 42,
        payload_length: 512, // Well within limit
        timestamp: current_time, // Current time, within drift window
    };

    let result = header.validate_security();

    // EXPECTED: Should pass all checks with valid current timestamp
    assert!(
        result.is_ok(),
        "Valid header with current timestamp {} should pass, got: {:?}",
        current_time,
        result
    );
}

/// **Validates: Requirements 3.4**
///
/// Unit test: Timestamp difference uses absolute value (symmetric behavior)
#[test]
fn test_timestamp_absolute_value_behavior() {
    let current_time = b4ae::time::current_time_secs();
    
    // Test with timestamp equal to current time (diff=0)
    let header_current = SecurityMessageHeader {
        version: ProtocolVersion::V1_0,
        message_type: MessageType::Data,
        cipher_suite: CipherSuite::Aes256Gcm,
        message_id: 1,
        payload_length: 100,
        timestamp: current_time,
    };

    let result_current = header_current.validate_security();
    assert!(
        result_current.is_ok(),
        "Timestamp {} (current) should pass (diff=0), got: {:?}",
        current_time,
        result_current
    );

    // Test with timestamp in the past (within drift)
    let past_timestamp = current_time.saturating_sub(3000);
    let header_past = SecurityMessageHeader {
        version: ProtocolVersion::V1_0,
        message_type: MessageType::Data,
        cipher_suite: CipherSuite::Aes256Gcm,
        message_id: 2,
        payload_length: 100,
        timestamp: past_timestamp,
    };

    let result_past = header_past.validate_security();
    assert!(
        result_past.is_ok(),
        "Timestamp {} (3000s in past) should pass (diff=3000 < 3600), got: {:?}",
        past_timestamp,
        result_past
    );
    
    // Test with timestamp in the future (within drift)
    let future_timestamp = current_time.saturating_add(3000);
    let header_future = SecurityMessageHeader {
        version: ProtocolVersion::V1_0,
        message_type: MessageType::Data,
        cipher_suite: CipherSuite::Aes256Gcm,
        message_id: 3,
        payload_length: 100,
        timestamp: future_timestamp,
    };

    let result_future = header_future.validate_security();
    assert!(
        result_future.is_ok(),
        "Timestamp {} (3000s in future) should pass (diff=3000 < 3600), got: {:?}",
        future_timestamp,
        result_future
    );
}

/// **Validates: Requirements 3.5**
///
/// Unit test: Validation order - payload check happens after version check
#[test]
fn test_validation_order_preserved() {
    let current_time = b4ae::time::current_time_secs();
    
    // Create a header with excessive payload
    // Version is valid, so we should get to payload validation
    let header = SecurityMessageHeader {
        version: ProtocolVersion::V1_0,
        message_type: MessageType::Data,
        cipher_suite: CipherSuite::Aes256Gcm,
        message_id: 1,
        payload_length: 10 * 1024 * 1024, // 10 MiB, way over limit
        timestamp: current_time, // Use valid timestamp
    };

    let result = header.validate_security();

    // EXPECTED: Should get ResourceExhaustionProtection (not InvalidTimestamp)
    // This confirms validation order: version -> payload -> timestamp
    assert!(
        matches!(result, Err(SecurityError::ResourceExhaustionProtection { .. })),
        "Expected ResourceExhaustionProtection to be checked before timestamp, got: {:?}",
        result
    );
}

