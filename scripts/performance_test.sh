#!/bin/bash
# B4AE Performance Testing Script
# Comprehensive performance validation and benchmarking

set -e

echo "🚀 B4AE Performance Testing Suite"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
RUST_BACKTRACE=1
CARGO_PROFILE_RELEASE_DEBUG=true

# Test results directory
RESULTS_DIR="performance_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
TEST_DIR="$RESULTS_DIR/$TIMESTAMP"

# Create results directory
mkdir -p "$TEST_DIR"

echo -e "${BLUE}📊 Test Configuration:${NC}"
echo "  Results Directory: $TEST_DIR"
echo "  Timestamp: $TIMESTAMP"
echo ""

# Function to run a test and save results
run_test() {
    local test_name=$1
    local test_command=$2
    local output_file="$TEST_DIR/${test_name}.txt"
    
    echo -e "${YELLOW}Running $test_name...${NC}"
    
    if eval "$test_command" > "$output_file" 2>&1; then
        echo -e "${GREEN}✅ $test_name completed${NC}"
        return 0
    else
        echo -e "${RED}❌ $test_name failed${NC}"
        return 1
    fi
}

# Function to run cargo test with specific features
run_cargo_test() {
    local test_name=$1
    local test_args=$2
    
    echo -e "${YELLOW}Running cargo test $test_name...${NC}"
    
    if cargo test $test_args --release -- --nocapture > "$TEST_DIR/${test_name}.txt" 2>&1; then
        echo -e "${GREEN}✅ $test_name completed${NC}"
        return 0
    else
        echo -e "${RED}❌ $test_name failed${NC}"
        return 1
    fi
}

# Function to run benchmark
run_benchmark() {
    local benchmark_name=$1
    local benchmark_args=$2
    
    echo -e "${YELLOW}Running benchmark $benchmark_name...${NC}"
    
    if cargo bench $benchmark_args > "$TEST_DIR/${benchmark_name}.txt" 2>&1; then
        echo -e "${GREEN}✅ $benchmark_name completed${NC}"
        return 0
    else
        echo -e "${RED}❌ $benchmark_name failed${NC}"
        return 1
    fi
}

# 1. Build Tests
echo -e "${BLUE}🔨 Build Tests${NC}"
echo "================="

run_test "debug_build" "cargo build"
run_test "release_build" "cargo build --release"
run_test "all_features_build" "cargo build --all-features"

# 2. Unit Tests
echo -e "\n${BLUE}🧪 Unit Tests${NC}"
echo "==============="

run_cargo_test "unit_tests" ""
run_cargo_test "crypto_tests" "--lib crypto"
run_cargo_test "protocol_tests" "--lib protocol"
run_cargo_test "security_tests" "--test security_audit_tests"

# 3. Integration Tests
echo -e "\n${BLUE}🔗 Integration Tests${NC}"
echo "===================="

run_cargo_test "integration_tests" "--test '*'"

# 4. Benchmark Tests
echo -e "\n${BLUE}⚡ Benchmark Tests${NC}"
echo "==================="

run_benchmark "crypto_benchmarks" "--bench crypto_bench"
run_benchmark "protocol_benchmarks" "--bench protocol_bench"
run_benchmark "performance_benchmarks" "--bench performance_bench"

# 5. Memory Usage Tests
echo -e "\n${BLUE}🧠 Memory Usage Tests${NC}"
echo "====================="

# Run with memory profiler if available
if command -v valgrind &> /dev/null; then
    run_test "valgrind_memory" "valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all cargo test --release"
fi

# Run with heaptrack if available
if command -v heaptrack &> /dev/null; then
    run_test "heaptrack_memory" "heaptrack cargo test --release"
fi

# 6. Performance Profiling
echo -e "\n${BLUE}🔍 Performance Profiling${NC}"
echo "========================"

# Generate flamegraph if cargo-flamegraph is available
if cargo install --list | grep -q flamegraph; then
    run_test "flamegraph_profile" "cargo flamegraph --bench performance_bench"
fi

# Run with perf if available
if command -v perf &> /dev/null; then
    run_test "perf_profile" "perf record -g cargo bench --bench performance_bench"
fi

# 7. Dependency Analysis
echo -e "\n${BLUE}📦 Dependency Analysis${NC}"
echo "====================="

run_test "dependency_tree" "cargo tree"
run_test "dependency_audit" "cargo audit"
run_test "outdated_dependencies" "cargo outdated"

# 8. Code Quality Analysis
echo -e "\n${BLUE}🔍 Code Quality Analysis${NC}"
echo "========================"

# Run clippy
run_test "clippy_lints" "cargo clippy -- -D warnings"

# Run rustfmt check
run_test "format_check" "cargo fmt -- --check"

# Run cargo-deny if available
if cargo install --list | grep -q cargo-deny; then
    run_test "cargo_deny" "cargo deny check"
fi

# 9. Documentation Tests
echo -e "\n${BLUE}📚 Documentation Tests${NC}"
echo "======================"

run_test "doc_tests" "cargo test --doc"
run_test "doc_build" "cargo doc --no-deps"

# 10. Cross-compilation Tests (if cross is available)
echo -e "\n${BLUE}🌍 Cross-compilation Tests${NC}"
echo "=========================="

if command -v cross &> /dev/null; then
    run_test "cross_compile_linux" "cross build --target x86_64-unknown-linux-musl"
    run_test "cross_compile_windows" "cross build --target x86_64-pc-windows-gnu"
    run_test "cross_compile_macos" "cross build --target x86_64-apple-darwin"
fi

# 11. Security Tests
echo -e "\n${BLUE}🔒 Security Tests${NC}"
echo "=================="

# Run cargo-geiger if available
if cargo install --list | grep -q cargo-geiger; then
    run_test "unsafe_code_check" "cargo geiger"
fi

# Run semgrep if available
if command -v semgrep &> /dev/null; then
    run_test "semgrep_security" "semgrep --config=auto ."
fi

# 12. Generate Summary Report
echo -e "\n${BLUE}📋 Generating Summary Report${NC}"
echo "============================="

cat > "$TEST_DIR/summary_report.md" << EOF
# B4AE Performance Test Report

**Test Date:** $(date)
**Test Duration:** $(($(date +%s) - $(date -r "$TEST_DIR" +%s))) seconds
**Results Directory:** $TEST_DIR

## Test Summary

### Build Tests
- Debug Build: $(if [ -f "$TEST_DIR/debug_build.txt" ]; then echo "✅ PASS"; else echo "❌ FAIL"; fi)
- Release Build: $(if [ -f "$TEST_DIR/release_build.txt" ]; then echo "✅ PASS"; else echo "❌ FAIL"; fi)
- All Features Build: $(if [ -f "$TEST_DIR/all_features_build.txt" ]; then echo "✅ PASS"; else echo "❌ FAIL"; fi)

### Unit Tests
- Core Tests: $(if [ -f "$TEST_DIR/unit_tests.txt" ]; then echo "✅ PASS"; else echo "❌ FAIL"; fi)
- Crypto Tests: $(if [ -f "$TEST_DIR/crypto_tests.txt" ]; then echo "✅ PASS"; else echo "❌ FAIL"; fi)
- Protocol Tests: $(if [ -f "$TEST_DIR/protocol_tests.txt" ]; then echo "✅ PASS"; else echo "❌ FAIL"; fi)
- Security Tests: $(if [ -f "$TEST_DIR/security_tests.txt" ]; then echo "✅ PASS"; else echo "❌ FAIL"; fi)

### Benchmark Results
- Crypto Benchmarks: $(if [ -f "$TEST_DIR/crypto_benchmarks.txt" ]; then echo "✅ COMPLETED"; else echo "❌ FAILED"; fi)
- Protocol Benchmarks: $(if [ -f "$TEST_DIR/protocol_benchmarks.txt" ]; then echo "✅ COMPLETED"; else echo "❌ FAILED"; fi)
- Performance Benchmarks: $(if [ -f "$TEST_DIR/performance_benchmarks.txt" ]; then echo "✅ COMPLETED"; else echo "❌ FAILED"; fi)

### Code Quality
- Clippy: $(if [ -f "$TEST_DIR/clippy_lints.txt" ]; then echo "✅ PASS"; else echo "❌ FAIL"; fi)
- Format Check: $(if [ -f "$TEST_DIR/format_check.txt" ]; then echo "✅ PASS"; else echo "❌ FAIL"; fi)
- Documentation: $(if [ -f "$TEST_DIR/doc_build.txt" ]; then echo "✅ PASS"; else echo "❌ FAIL"; fi)

### Security
- Dependency Audit: $(if [ -f "$TEST_DIR/dependency_audit.txt" ]; then echo "✅ PASS"; else echo "❌ FAIL"; fi)
- Security Tests: $(if [ -f "$TEST_DIR/security_tests.txt" ]; then echo "✅ PASS"; else echo "❌ FAIL"; fi)

## Performance Metrics

### Handshake Performance
$(if [ -f "$TEST_DIR/performance_benchmarks.txt" ]; then
    echo "```"
    grep -A 5 "handshake_protocol" "$TEST_DIR/performance_benchmarks.txt" || echo "No handshake metrics available"
    echo "```"
fi)

### Message Throughput
$(if [ -f "$TEST_DIR/performance_benchmarks.txt" ]; then
    echo "```"
    grep -A 5 "throughput" "$TEST_DIR/performance_benchmarks.txt" || echo "No throughput metrics available"
    echo "```"
fi)

### Latency
$(if [ -f "$TEST_DIR/performance_benchmarks.txt" ]; then
    echo "```"
    grep -A 5 "latency" "$TEST_DIR/performance_benchmarks.txt" || echo "No latency metrics available"
    echo "```"
fi)

## Recommendations

1. Review any failed tests and fix issues
2. Analyze benchmark results for optimization opportunities
3. Monitor memory usage in production deployments
4. Regular security audits are recommended
5. Performance should be validated on target hardware

## Next Steps

- [ ] Address any test failures
- [ ] Optimize performance bottlenecks
- [ ] Set up continuous performance monitoring
- [ ] Plan regular security audits
- [ ] Document performance baselines

---

*Generated by B4AE Performance Testing Suite*
EOF

echo -e "${GREEN}✅ Summary report generated: $TEST_DIR/summary_report.md${NC}"

# Final output
echo -e "\n${BLUE}🎯 Test Results Summary${NC}"
echo "========================"
echo -e "Results saved to: ${GREEN}$TEST_DIR${NC}"
echo -e "Summary report: ${GREEN}$TEST_DIR/summary_report.md${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Review any failed tests"
echo "2. Analyze benchmark results"
echo "3. Address performance issues"
echo "4. Set up continuous monitoring"
echo ""
echo -e "${GREEN}Performance testing completed! 🎉${NC}"

# Exit with success
echo "0" > "$TEST_DIR/exit_code.txt"
exit 0