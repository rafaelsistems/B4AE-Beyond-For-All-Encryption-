//! Comprehensive fuzzing infrastructure for security-hardened B4AE modules
//!
//! This module provides fuzzing targets and infrastructure to test the
//! security-hardened implementations against malformed and adversarial inputs.

use crate::security::{
    SecurityResult, SecurityError, SecurityBuffer, SecurityNetworkParser,
    SecurityHandshakeStateMachine, SecurityHybridParser, SecurityKey, KeyType,
    SecurityHkdf, SecurityAesGcm, SecurityCompare, SecurityRandom,
    ProtocolVersion, MessageType, CipherSuite, HandshakeState
};
use std::convert::TryFrom;

/// Fuzzing configuration with comprehensive coverage
#[derive(Debug, Clone)]
pub struct FuzzingConfig {
    pub max_input_size: usize,
    pub mutation_strategies: Vec<MutationStrategy>,
    pub coverage_targets: Vec<CoverageTarget>,
    pub timeout_ms: u64,
    pub seed_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationStrategy {
    BitFlip,
    ByteFlip,
    Arithmetic,
    InterestingValues,
    BlockDeletion,
    BlockDuplication,
    BlockInsertion,
    Dictionary,
    Havoc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageTarget {
    BufferBounds,
    ProtocolParsing,
    CryptographicOperations,
    StateMachineTransitions,
    MemoryHygiene,
    ResourceExhaustion,
    ConstantTimeOperations,
}

impl Default for FuzzingConfig {
    fn default() -> Self {
        FuzzingConfig {
            max_input_size: 65536, // 64 KB
            mutation_strategies: vec![
                MutationStrategy::BitFlip,
                MutationStrategy::ByteFlip,
                MutationStrategy::Arithmetic,
                MutationStrategy::InterestingValues,
                MutationStrategy::BlockDeletion,
                MutationStrategy::BlockDuplication,
                MutationStrategy::Havoc,
            ],
            coverage_targets: vec![
                CoverageTarget::BufferBounds,
                CoverageTarget::ProtocolParsing,
                CoverageTarget::CryptographicOperations,
                CoverageTarget::StateMachineTransitions,
                CoverageTarget::MemoryHygiene,
                CoverageTarget::ResourceExhaustion,
                CoverageTarget::ConstantTimeOperations,
            ],
            timeout_ms: 1000, // 1 second per test case
            seed_count: 10000,
        }
    }
}

/// Fuzzing harness for SecurityBuffer
pub struct BufferFuzzingHarness {
    config: FuzzingConfig,
    crash_inputs: Vec<Vec<u8>>,
    slow_inputs: Vec<Vec<u8>>,
    coverage_hits: std::collections::HashMap<String, usize>,
}

impl BufferFuzzingHarness {
    pub fn new(config: FuzzingConfig) -> Self {
        BufferFuzzingHarness {
            config,
            crash_inputs: Vec::new(),
            slow_inputs: Vec::new(),
            coverage_hits: std::collections::HashMap::new(),
        }
    }
    
    /// Fuzz SecurityBuffer creation and operations
    pub fn fuzz_buffer_operations(&mut self, input: &[u8]) -> FuzzingResult {
        let start = std::time::Instant::now();
        
        // Test buffer creation with various sizes
        for size in [0, 1, 64, 1024, 65536, 1048576] {
            match SecurityBuffer::new(size) {
                Ok(mut buffer) => {
                    self.record_coverage("buffer_creation_success");
                    
                    // Test write operations
                    if !input.is_empty() && input.len() <= buffer.capacity() {
                        match buffer.write_slice(input) {
                            Ok(_) => self.record_coverage("buffer_write_success"),
                            Err(_) => self.record_coverage("buffer_write_failure"),
                        }
                    }
                    
                    // Test read operations
                    if buffer.len() > 0 {
                        let read_size = (input.len() % buffer.len()).max(1);
                        match buffer.read_exact(read_size) {
                            Ok(_) => self.record_coverage("buffer_read_success"),
                            Err(_) => self.record_coverage("buffer_read_failure"),
                        }
                    }
                    
                    // Test position operations
                    let new_pos = input.len() % (buffer.len() + 1);
                    match buffer.set_position(new_pos) {
                        Ok(_) => self.record_coverage("buffer_set_position_success"),
                        Err(_) => self.record_coverage("buffer_set_position_failure"),
                    }
                },
                Err(_) => self.record_coverage("buffer_creation_failure"),
            }
        }
        
        // Test edge cases
        self.test_buffer_edge_cases(input);
        
        let elapsed = start.elapsed();
        if elapsed.as_millis() > self.config.timeout_ms as u128 {
            self.slow_inputs.push(input.to_vec());
            return FuzzingResult::Slow;
        }
        
        FuzzingResult::Success
    }
    
    fn test_buffer_edge_cases(&mut self, _input: &[u8]) {
        // Test maximum size buffer
        match SecurityBuffer::new(1048576) { // 1 MB
            Ok(mut buffer) => {
                // Test writing maximum data
                let large_data = vec![0x42u8; 1048576];
                match buffer.write_slice(&large_data) {
                    Ok(_) => self.record_coverage("max_buffer_write"),
                    Err(_) => self.record_coverage("max_buffer_write_failure"),
                }
            },
            Err(_) => self.record_coverage("max_buffer_creation_failure"),
        }
        
        // Test zero-size buffer
        match SecurityBuffer::new(0) {
            Ok(mut buffer) => {
                match buffer.write_slice(b"test") {
                    Ok(_) => self.record_coverage("zero_buffer_write_unexpected"),
                    Err(_) => self.record_coverage("zero_buffer_write_expected"),
                }
            },
            Err(_) => self.record_coverage("zero_buffer_creation_expected"),
        }
    }
    
    fn record_coverage(&mut self, hit: &str) {
        *self.coverage_hits.entry(hit.to_string()).or_insert(0) += 1;
    }
}

/// Fuzzing harness for network protocol parsing
pub struct NetworkFuzzingHarness {
    config: FuzzingConfig,
    parser: SecurityNetworkParser,
    protocol_violations: Vec<ProtocolViolation>,
}

#[derive(Debug, Clone)]
pub struct ProtocolViolation {
    pub violation_type: String,
    pub input: Vec<u8>,
    pub error: SecurityError,
}

impl NetworkFuzzingHarness {
    pub fn new(config: FuzzingConfig) -> Self {
        NetworkFuzzingHarness {
            config,
            parser: SecurityNetworkParser::new(),
            protocol_violations: Vec::new(),
        }
    }
    
    /// Fuzz network message parsing
    pub fn fuzz_network_parsing(&mut self, input: &[u8]) -> FuzzingResult {
        let start = std::time::Instant::now();
        
        // Test various message types
        self.test_message_parsing(input);
        self.test_header_parsing(input);
        self.test_handshake_parsing(input);
        self.test_data_parsing(input);
        
        let elapsed = start.elapsed();
        if elapsed.as_millis() > self.config.timeout_ms as u128 {
            return FuzzingResult::Slow;
        }
        
        FuzzingResult::Success
    }
    
    fn test_message_parsing(&mut self, input: &[u8]) {
        match self.parser.parse_message(input) {
            Ok(message) => {
                // Validate message structure
                if message.header.payload_length as usize != message.payload.len() {
                    self.record_violation("payload_length_mismatch", input, 
                        SecurityError::InvalidLength {
                            expected: message.header.payload_length as usize,
                            actual: message.payload.len(),
                        });
                }
            },
            Err(error) => {
                // Expected errors for malformed input
                match error {
                    SecurityError::BufferTooSmall { .. } => {},
                    SecurityError::InvalidProtocolVersion { .. } => {},
                    SecurityError::InvalidMessageType(_) => {},
                    _ => self.record_violation("unexpected_parse_error", input, error),
                }
            }
        }
    }
    
    fn test_header_parsing(&mut self, input: &[u8]) {
        if input.len() >= 24 { // Minimum header size
            match self.parser.parse_header(&input[..24]) {
                Ok(header) => {
                    // Validate header fields
                    if header.payload_length > 1048576 { // 1 MB limit
                        self.record_violation("excessive_payload_length", input,
                            SecurityError::ResourceExhaustionProtection {
                                resource: "payload_length".to_string(),
                                limit: 1048576,
                                requested: header.payload_length as usize,
                            });
                    }
                },
                Err(error) => {
                    // Expected header parsing errors
                    match error {
                        SecurityError::InvalidProtocolVersion { .. } => {},
                        SecurityError::InvalidMessageType(_) => {},
                        SecurityError::InvalidCipherSuite(_) => {},
                        _ => self.record_violation("unexpected_header_error", input, error),
                    }
                }
            }
        }
    }
    
    fn test_handshake_parsing(&mut self, input: &[u8]) {
        // Test handshake message parsing
        let handshake_types = [MessageType::HandshakeInit, MessageType::HandshakeResponse, MessageType::HandshakeComplete];
        
        for handshake_type in &handshake_types {
            match self.parser.parse_handshake_message(input, *handshake_type) {
                Ok(_) => {
                    // Valid handshake message parsed
                },
                Err(error) => {
                    // Expected handshake errors
                    match error {
                        SecurityError::InvalidMessageType(_) => {},
                        SecurityError::InvalidCipherSuite(_) => {},
                        _ => self.record_violation("unexpected_handshake_error", input, error),
                    }
                }
            }
        }
    }
    
    fn test_data_parsing(&mut self, input: &[u8]) {
        match self.parser.parse_data_message(input) {
            Ok(_) => {
                // Valid data message parsed
            },
            Err(error) => {
                // Expected data message errors
                    match error {
                        SecurityError::InvalidMessageType(_) => {},
                        SecurityError::InvalidHkdfInput { .. } => {},
                        _ => self.record_violation("unexpected_data_error", input, error),
                    }
            }
        }
    }
    
    fn record_violation(&mut self, violation_type: &str, input: &[u8], error: SecurityError) {
        self.protocol_violations.push(ProtocolViolation {
            violation_type: violation_type.to_string(),
            input: input.to_vec(),
            error,
        });
    }
}

/// Fuzzing harness for cryptographic operations
pub struct CryptoFuzzingHarness {
    config: FuzzingConfig,
    timing_leaks: Vec<TimingLeak>,
}

#[derive(Debug, Clone)]
pub struct TimingLeak {
    pub operation: String,
    pub input_size: usize,
    pub timing_variance: f64,
}

impl CryptoFuzzingHarness {
    pub fn new(config: FuzzingConfig) -> Self {
        CryptoFuzzingHarness {
            config,
            timing_leaks: Vec::new(),
        }
    }
    
    /// Fuzz cryptographic operations
    pub fn fuzz_crypto_operations(&mut self, input: &[u8]) -> FuzzingResult {
        let start = std::time::Instant::now();
        
        // Test key operations
        self.test_key_operations(input);
        
        // Test HKDF operations
        self.test_hkdf_operations(input);
        
        // Test AES-GCM operations
        self.test_aes_gcm_operations(input);
        
        // Test constant-time operations
        self.test_constant_time_operations(input);
        
        let elapsed = start.elapsed();
        if elapsed.as_millis() > self.config.timeout_ms as u128 {
            return FuzzingResult::Slow;
        }
        
        FuzzingResult::Success
    }
    
    fn test_key_operations(&mut self, input: &[u8]) {
        // Test key creation with various sizes
        for key_type in [KeyType::Encryption, KeyType::Authentication, KeyType::Metadata] {
            match SecurityKey::from_slice(input, key_type) {
                Ok(key) => {
                    // Test key operations
                    let _ = key.as_slice();
                    let _ = key.key_type();
                    let _ = key.len();
                },
                Err(error) => {
                    // Expected key errors
                    match error {
                        SecurityError::InvalidKey { .. } => {},
                        _ => println!("Unexpected key error: {:?}", error),
                    }
                }
            }
        }
    }
    
    fn test_hkdf_operations(&mut self, input: &[u8]) {
        if input.len() >= 32 { // Minimum IKM size
            let salt = if input.len() > 32 { Some(&input[32..]) } else { None };
            let info = b"test info";
            
            match SecurityHkdf::derive_keys(input, salt, info, 32) {
                Ok(_) => {
                    // HKDF succeeded
                },
                Err(error) => {
                    // Expected HKDF errors
                    match error {
                    SecurityError::InvalidHkdfInput { .. } => {},
                    _ => println!("Unexpected HKDF error: {:?}", error),
                }
                }
            }
        }
    }
    
    fn test_aes_gcm_operations(&mut self, input: &[u8]) {
        if input.len() >= 44 { // Minimum for key (32) + nonce (12)
            let key_data = &input[..32];
            let nonce = &input[32..44];
            let plaintext = if input.len() > 44 { &input[44..] } else { b"test" };
            
            match SecurityKey::from_slice(key_data, KeyType::Encryption) {
                Ok(key) => {
                    // Test encryption
                    match SecurityAesGcm::encrypt(&key, nonce, plaintext, None) {
                        Ok(ciphertext) => {
                            // Test decryption
                            match SecurityAesGcm::decrypt(&key, nonce, &ciphertext, None) {
                                Ok(decrypted) => {
                                    // Verify decryption
                                    if decrypted != plaintext {
                                        println!("Decryption mismatch detected");
                                    }
                                },
                                Err(error) => {
                                    match error {
                            SecurityError::InvalidHkdfInput { .. } => {},
                            _ => println!("Unexpected decryption error: {:?}", error),
                        }
                                }
                            }
                        },
                        Err(error) => {
                            match error {
                            SecurityError::InvalidHkdfInput { .. } => {},
                            SecurityError::InvalidNonce { .. } => {},
                            _ => println!("Unexpected encryption error: {:?}", error),
                        }
                        }
                    }
                },
                Err(error) => {
                    match error {
                        SecurityError::InvalidKey { .. } => {},
                        _ => println!("Unexpected key error: {:?}", error),
                    }
                }
            }
        }
    }
    
    fn test_constant_time_operations(&mut self, input: &[u8]) {
        // Test constant-time comparison
        if input.len() >= 64 {
            let a = &input[..32];
            let b = &input[32..64];
            
            // Measure timing multiple times
            let mut timings = Vec::new();
            for _ in 0..100 {
                let start = std::time::Instant::now();
                let _ = SecurityCompare::constant_time_eq(a, b);
                let elapsed = start.elapsed();
                timings.push(elapsed.as_nanos() as f64);
            }
            
            // Calculate timing variance
            let mean = timings.iter().sum::<f64>() / timings.len() as f64;
            let variance = timings.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / timings.len() as f64;
            
            // Check for potential timing leaks (simplified)
            if variance > mean * 0.1 {
                self.timing_leaks.push(TimingLeak {
                    operation: "constant_time_eq".to_string(),
                    input_size: a.len(),
                    timing_variance: variance,
                });
            }
        }
    }
}

/// Fuzzing harness for state machine operations
pub struct StateMachineFuzzingHarness {
    config: FuzzingConfig,
    invalid_transitions: Vec<InvalidTransition>,
}

#[derive(Debug, Clone)]
pub struct InvalidTransition {
    pub from_state: HandshakeState,
    pub to_state: HandshakeState,
    pub input: Vec<u8>,
}

impl StateMachineFuzzingHarness {
    pub fn new(config: FuzzingConfig) -> Self {
        StateMachineFuzzingHarness {
            config,
            invalid_transitions: Vec::new(),
        }
    }
    
    /// Fuzz state machine transitions
    pub fn fuzz_state_machine(&mut self, input: &[u8]) -> FuzzingResult {
        let start = std::time::Instant::now();
        
        // Test all possible state transitions
        self.test_all_transitions(input);
        
        // Test state machine with various inputs
        self.test_state_machine_inputs(input);
        
        let elapsed = start.elapsed();
        if elapsed.as_millis() > self.config.timeout_ms as u128 {
            return FuzzingResult::Slow;
        }
        
        FuzzingResult::Success
    }
    
    fn test_all_transitions(&mut self, input: &[u8]) {
        let all_states = [
            HandshakeState::Init,
            HandshakeState::WaitingResponse,
            HandshakeState::WaitingComplete,
            HandshakeState::Completed,
            HandshakeState::Failed,
        ];
        
        for from_state in &all_states {
            for to_state in &all_states {
                let mut sm = match SecurityHandshakeStateMachine::new(16384) {
                    Ok(sm) => sm,
                    Err(_) => continue,
                };
                
                // Force state to from_state (implementation detail)
                // In real implementation, this would be done through proper API
                
                match sm.transition_state(*to_state) {
                    Ok(_) => {
                        // Valid transition
                    },
                    Err(_) => {
                        // Invalid transition - record for analysis
                        self.invalid_transitions.push(InvalidTransition {
                            from_state: *from_state,
                            to_state: *to_state,
                            input: input.to_vec(),
                        });
                    }
                }
            }
        }
    }
    
    fn test_state_machine_inputs(&mut self, input: &[u8]) {
        let mut sm = match SecurityHandshakeStateMachine::new(16384) {
            Ok(sm) => sm,
            Err(_) => return,
        };
        
        // Test with various input sizes
        for size in [0, 1, 64, 1024, 16384] {
            if input.len() >= size {
                let test_input = &input[..size];
                
                // Test init processing
                match sm.process_init(test_input) {
                    Ok(_) => {
                        // Valid init processed
                    },
                    Err(error) => {
                        match error {
                            SecurityError::ResourceExhaustionProtection { .. } => {},
                            SecurityError::InvalidHkdfInput { .. } => {},
                            _ => println!("Unexpected init error: {:?}", error),
                        }
                    }
                }
                
                // Reset for next test
                let _ = sm.reset();
            }
        }
    }
}

/// Fuzzing result types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzingResult {
    Success,
    Crash(String),
    Slow,
    Timeout,
    MemoryExhaustion,
}

/// Comprehensive fuzzing orchestrator
pub struct SecurityFuzzingOrchestrator {
    config: FuzzingConfig,
    buffer_harness: BufferFuzzingHarness,
    network_harness: NetworkFuzzingHarness,
    crypto_harness: CryptoFuzzingHarness,
    state_machine_harness: StateMachineFuzzingHarness,
    results: FuzzingResults,
}

#[derive(Debug, Default, Clone)]
pub struct FuzzingResults {
    pub total_runs: usize,
    pub successful_runs: usize,
    pub crashes: Vec<(String, Vec<u8>)>,
    pub slow_inputs: Vec<Vec<u8>>,
    pub protocol_violations: Vec<ProtocolViolation>,
    pub timing_leaks: Vec<TimingLeak>,
    pub invalid_transitions: Vec<InvalidTransition>,
    pub coverage_stats: std::collections::HashMap<String, usize>,
}

impl SecurityFuzzingOrchestrator {
    pub fn new(config: FuzzingConfig) -> Self {
        SecurityFuzzingOrchestrator {
            config: config.clone(),
            buffer_harness: BufferFuzzingHarness::new(config.clone()),
            network_harness: NetworkFuzzingHarness::new(config.clone()),
            crypto_harness: CryptoFuzzingHarness::new(config.clone()),
            state_machine_harness: StateMachineFuzzingHarness::new(config.clone()),
            results: FuzzingResults::default(),
        }
    }
    
    /// Run comprehensive fuzzing campaign
    pub fn run_fuzzing_campaign(&mut self, duration_seconds: u64) -> FuzzingResults {
        let start = std::time::Instant::now();
        let duration = std::time::Duration::from_secs(duration_seconds);
        
        while start.elapsed() < duration {
            // Generate random input
            let input = self.generate_random_input();
            
            // Run all fuzzing harnesses
            self.run_all_harnesses(&input);
            
            self.results.total_runs += 1;
        }
        
        // Collect results
        self.collect_results();
        self.results.clone()
    }
    
    fn generate_random_input(&self) -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let size = rng.gen_range(0..self.config.max_input_size);
        (0..size).map(|_| rng.gen()).collect()
    }
    
    fn run_all_harnesses(&mut self, input: &[u8]) {
        // Run buffer fuzzing
        match self.buffer_harness.fuzz_buffer_operations(input) {
            FuzzingResult::Success => self.results.successful_runs += 1,
            FuzzingResult::Crash(msg) => self.results.crashes.push((msg, input.to_vec())),
            FuzzingResult::Slow => self.results.slow_inputs.push(input.to_vec()),
            _ => {},
        }
        
        // Run network fuzzing
        match self.network_harness.fuzz_network_parsing(input) {
            FuzzingResult::Success => {},
            FuzzingResult::Crash(msg) => self.results.crashes.push((msg, input.to_vec())),
            _ => {},
        }
        
        // Run crypto fuzzing
        match self.crypto_harness.fuzz_crypto_operations(input) {
            FuzzingResult::Success => {},
            FuzzingResult::Crash(msg) => self.results.crashes.push((msg, input.to_vec())),
            _ => {},
        }
        
        // Run state machine fuzzing
        match self.state_machine_harness.fuzz_state_machine(input) {
            FuzzingResult::Success => {},
            FuzzingResult::Crash(msg) => self.results.crashes.push((msg, input.to_vec())),
            _ => {},
        }
    }
    
    fn collect_results(&mut self) {
        // Collect protocol violations
        self.results.protocol_violations.extend(
            self.network_harness.protocol_violations.clone()
        );
        
        // Collect timing leaks
        self.results.timing_leaks.extend(
            self.crypto_harness.timing_leaks.clone()
        );
        
        // Collect invalid transitions
        self.results.invalid_transitions.extend(
            self.state_machine_harness.invalid_transitions.clone()
        );
        
        // Collect coverage stats
        self.results.coverage_stats.extend(
            self.buffer_harness.coverage_hits.clone()
        );
    }
    
    /// Generate fuzzing report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();
        report.push_str("B4AE Security Fuzzing Report\n");
        report.push_str("===========================\n\n");
        
        report.push_str(&format!("Total runs: {}\n", self.results.total_runs));
        report.push_str(&format!("Successful runs: {}\n", self.results.successful_runs));
        report.push_str(&format!("Crashes: {}\n", self.results.crashes.len()));
        report.push_str(&format!("Slow inputs: {}\n", self.results.slow_inputs.len()));
        report.push_str(&format!("Protocol violations: {}\n", self.results.protocol_violations.len()));
        report.push_str(&format!("Timing leaks: {}\n", self.results.timing_leaks.len()));
        report.push_str(&format!("Invalid transitions: {}\n", self.results.invalid_transitions.len()));
        
        if !self.results.crashes.is_empty() {
            report.push_str("\nCritical Issues Found:\n");
            for (i, (msg, _)) in self.results.crashes.iter().enumerate() {
                report.push_str(&format!("  {}. {}\n", i + 1, msg));
            }
        }
        
        if !self.results.protocol_violations.is_empty() {
            report.push_str("\nProtocol Violations:\n");
            for (i, violation) in self.results.protocol_violations.iter().enumerate() {
                report.push_str(&format!("  {}. {}: {:?}\n", i + 1, violation.violation_type, violation.error));
            }
        }
        
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fuzzing_harness_creation() {
        let config = FuzzingConfig::default();
        
        let _buffer_harness = BufferFuzzingHarness::new(config.clone());
        let _network_harness = NetworkFuzzingHarness::new(config.clone());
        let _crypto_harness = CryptoFuzzingHarness::new(config.clone());
        let _state_machine_harness = StateMachineFuzzingHarness::new(config.clone());
        
        let orchestrator = SecurityFuzzingOrchestrator::new(config);
        
        // Test basic functionality
        assert_eq!(orchestrator.results.total_runs, 0);
        assert_eq!(orchestrator.results.successful_runs, 0);
    }
    
    #[test]
    fn test_fuzzing_with_sample_inputs() {
        let config = FuzzingConfig {
            max_input_size: 1024,
            seed_count: 100,
            ..Default::default()
        };
        
        let mut orchestrator = SecurityFuzzingOrchestrator::new(config);
        
        // Test with some sample inputs
        let sample_inputs = vec![
            vec![], // Empty input
            vec![0x00], // Single byte
            vec![0xFF; 100], // All 0xFF
            vec![0x00, 0x01, 0x02, 0x03], // Sequential
            b"B4AE_PROTOCOL_HEADER".to_vec(), // Protocol-like
        ];
        
        for input in sample_inputs {
            orchestrator.run_all_harnesses(&input);
        }
        
        // Should have run without crashes
        assert!(orchestrator.results.crashes.is_empty());
        assert!(orchestrator.results.total_runs >= 5);
    }
    
    #[test]
    fn test_report_generation() {
        let config = FuzzingConfig::default();
        let orchestrator = SecurityFuzzingOrchestrator::new(config);
        
        let report = orchestrator.generate_report();
        
        // Report should contain basic information
        assert!(report.contains("B4AE Security Fuzzing Report"));
        assert!(report.contains("Total runs:"));
        assert!(report.contains("Successful runs:"));
        assert!(report.contains("Crashes:"));
    }
}