#!/bin/bash
# B4AE Test Runner Script
# Comprehensive test execution for Phase 3

set -e

echo "========================================="
echo "B4AE Phase 3 Test Suite"
echo "========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run tests
run_test() {
    local test_name=$1
    local test_command=$2
    
    echo -e "${YELLOW}Running: $test_name${NC}"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if eval "$test_command"; then
        echo -e "${GREEN}✓ PASSED: $test_name${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗ FAILED: $test_name${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    echo ""
}

# 1. Unit Tests
echo "========================================="
echo "1. UNIT TESTS"
echo "========================================="
run_test "Crypto Unit Tests" "cargo test --lib crypto::"
run_test "Protocol Unit Tests" "cargo test --lib protocol::"
run_test "Metadata Unit Tests" "cargo test --lib metadata::"

# 2. Integration Tests
echo "========================================="
echo "2. INTEGRATION TESTS"
echo "========================================="
run_test "Handshake Integration" "cargo test --test integration_test test_complete_handshake_flow"
run_test "Message Flow Integration" "cargo test --test integration_test test_end_to_end_message_flow"
run_test "Multiple Messages" "cargo test --test integration_test test_multiple_message_exchange"
run_test "Session Statistics" "cargo test --test integration_test test_session_statistics"

# 3. Security Tests
echo "========================================="
echo "3. SECURITY TESTS"
echo "========================================="
run_test "Replay Attack Prevention" "cargo test --test security_test test_replay_attack_prevention"
run_test "Forward Secrecy" "cargo test --test security_test test_forward_secrecy"
run_test "Zero-Knowledge Auth" "cargo test --test security_test test_zero_knowledge_authentication"
run_test "Invalid Signature Rejection" "cargo test --test security_test test_invalid_signature_rejection"
run_test "Key Rotation" "cargo test --test security_test test_key_rotation"
run_test "Message Expiration" "cargo test --test security_test test_message_expiration"
run_test "Quantum Resistant KE" "cargo test --test security_test test_quantum_resistant_key_exchange"
run_test "Hybrid Crypto Fallback" "cargo test --test security_test test_hybrid_cryptography_fallback"
run_test "Memory Zeroization" "cargo test --test security_test test_memory_zeroization"

# 4. Performance Tests
echo "========================================="
echo "4. PERFORMANCE TESTS"
echo "========================================="
run_test "Kyber KeyGen Performance" "cargo test --test performance_test test_kyber_keygen_performance --release"
run_test "Dilithium Sign Performance" "cargo test --test performance_test test_dilithium_sign_performance --release"
run_test "Dilithium Verify Performance" "cargo test --test performance_test test_dilithium_verify_performance --release"
run_test "AES-GCM Performance" "cargo test --test performance_test test_aes_gcm_performance --release"
run_test "Handshake Performance" "cargo test --test performance_test test_handshake_performance --release"
run_test "Message Throughput" "cargo test --test performance_test test_message_throughput --release"
run_test "End-to-End Latency" "cargo test --test performance_test test_end_to_end_latency --release"
run_test "HKDF Performance" "cargo test --test performance_test test_hkdf_performance --release"

# 5. Fuzzing Tests
echo "========================================="
echo "5. FUZZING TESTS"
echo "========================================="
run_test "Malformed Handshake" "cargo test --test fuzzing_test test_malformed_handshake_init"
run_test "Random Data Handling" "cargo test --test fuzzing_test test_random_data_handling"
run_test "Oversized Message" "cargo test --test fuzzing_test test_oversized_message"
run_test "Empty Message" "cargo test --test fuzzing_test test_empty_message"
run_test "Rapid Handshake Attempts" "cargo test --test fuzzing_test test_rapid_handshake_attempts"
run_test "Concurrent Sessions" "cargo test --test fuzzing_test test_concurrent_sessions"
run_test "Invalid Protocol Version" "cargo test --test fuzzing_test test_invalid_protocol_version"
run_test "Special Characters" "cargo test --test fuzzing_test test_message_with_special_characters"
run_test "Binary Data Integrity" "cargo test --test fuzzing_test test_binary_data_integrity"
run_test "Handshake Timeout" "cargo test --test fuzzing_test test_handshake_timeout"
run_test "Repeated Complete" "cargo test --test fuzzing_test test_repeated_handshake_complete"

# 6. Code Quality Checks
echo "========================================="
echo "6. CODE QUALITY CHECKS"
echo "========================================="
run_test "Clippy Lints" "cargo clippy --all-targets --all-features -- -D warnings"
run_test "Format Check" "cargo fmt --all -- --check"
run_test "Security Audit" "cargo audit"

# 7. Documentation Tests
echo "========================================="
echo "7. DOCUMENTATION TESTS"
echo "========================================="
run_test "Doc Tests" "cargo test --doc"
run_test "Doc Build" "cargo doc --no-deps"

# Summary
echo "========================================="
echo "TEST SUMMARY"
echo "========================================="
echo -e "Total Tests:  $TOTAL_TESTS"
echo -e "${GREEN}Passed:       $PASSED_TESTS${NC}"
echo -e "${RED}Failed:       $FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}ALL TESTS PASSED! ✓${NC}"
    echo -e "${GREEN}=========================================${NC}"
    exit 0
else
    echo -e "${RED}=========================================${NC}"
    echo -e "${RED}SOME TESTS FAILED! ✗${NC}"
    echo -e "${RED}=========================================${NC}"
    exit 1
fi
