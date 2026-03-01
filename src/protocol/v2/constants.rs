//! Protocol constants for B4AE v2.0
//!
//! This module defines all protocol constants used in the v2.0 implementation,
//! including timing parameters, size limits, and cryptographic domain separators.
//!
//! ## Design Principles
//!
//! - **Security-by-default**: All security features enabled, no optional security
//! - **Formally specified**: All constants derived from formal threat model
//! - **Performance-aware**: Constants balanced for security and performance
//!
//! ## Constant Categories
//!
//! - **Protocol Identification**: Version and protocol ID constants
//! - **Timing Parameters**: Timeouts and replay protection windows
//! - **Size Limits**: Message sizes and queue depths for DoS protection
//! - **Cryptographic Parameters**: Key sizes and domain separators
//! - **Traffic Scheduling**: Global scheduler configuration
//! - **Metadata Protection**: Padding and dummy traffic parameters

/// B4AE v2.0 protocol version
///
/// This version number is used for logging and diagnostics. The actual
/// protocol version enforcement is done via the protocol ID (SHA3-256
/// of canonical specification).
pub const PROTOCOL_VERSION_V2: &str = "2.0.0";

/// Protocol name for v2.0
pub const PROTOCOL_NAME_V2: &str = "B4AE-v2";

/// Domain separator for mode binding derivation
///
/// Used in: mode_binding = SHA3-256(DOMAIN_MODE_BINDING || client_random || server_random || mode_id)
pub const DOMAIN_MODE_BINDING: &[u8] = b"B4AE-v2-mode-binding";

/// Domain separator for session ID derivation
///
/// Used in: session_id = HKDF-SHA512(client_random || server_random || mode_id, DOMAIN_SESSION_ID, "", 32)
pub const DOMAIN_SESSION_ID: &[u8] = b"B4AE-v2-session-id";

/// Domain separator for session key derivation
///
/// Used in: session_key = HKDF-SHA512(master_secret, protocol_id || session_id || transcript_hash, DOMAIN_SESSION_KEY, 32)
pub const DOMAIN_SESSION_KEY: &[u8] = b"B4AE-v2-session-key";

/// Domain separator for root key derivation
///
/// Used in: root_key = HKDF-SHA512(master_secret, protocol_id || session_id || transcript_hash, DOMAIN_ROOT_KEY, 32)
pub const DOMAIN_ROOT_KEY: &[u8] = b"B4AE-v2-root-key";

/// Domain separator for chain key derivation
///
/// Used in: chain_key = HKDF-SHA512(master_secret, protocol_id || session_id || transcript_hash, DOMAIN_CHAIN_KEY, 32)
pub const DOMAIN_CHAIN_KEY: &[u8] = b"B4AE-v2-chain-key";

/// Domain separator for handshake transcript hash
///
/// Used in: transcript_hash = SHA512(DOMAIN_HANDSHAKE_TRANSCRIPT || protocol_id || messages)
pub const DOMAIN_HANDSHAKE_TRANSCRIPT: &[u8] = b"B4AE-v2-Handshake-Transcript";

/// Cookie timeout window in seconds
///
/// Cookies are valid for 30 seconds after generation. This balances:
/// - Security: Short window limits replay attack opportunities
/// - Usability: Long enough for typical network latencies
/// - DoS protection: Expired cookies rejected without expensive crypto
///
/// **Requirement**: REQ-3 (Stateless Cookie Challenge)
pub const COOKIE_TIMEOUT_SECONDS: u64 = 30;

/// Bloom filter size for replay protection (number of entries)
///
/// Sized to handle expected request rate with acceptable false positive rate.
/// For 1M entries with 0.1% false positive rate, requires ~1 MB memory.
///
/// **Requirement**: REQ-4 (Replay Protection)
pub const BLOOM_FILTER_SIZE: usize = 1_000_000;

/// Bloom filter false positive rate
///
/// Trade-off between memory usage and false positive rate:
/// - 0.1% false positive rate: ~1 MB for 1M entries
/// - 0.01% false positive rate: ~1.4 MB for 1M entries
///
/// **Requirement**: REQ-4 (Replay Protection)
pub const BLOOM_FILTER_FALSE_POSITIVE_RATE: f64 = 0.001;

/// Maximum message size in bytes (1 MiB)
///
/// Limits memory usage and prevents DoS attacks via oversized messages.
///
/// **Requirement**: REQ-23 (Memory Usage Requirements)
pub const MAX_MESSAGE_SIZE: usize = 1 << 20; // 1 MiB

/// Maximum queue depth for global traffic scheduler
///
/// Prevents unbounded memory growth from message queue. When limit is
/// reached, new messages are rejected with "Queue full" error.
///
/// **Requirement**: REQ-5 (Global Unified Traffic Scheduler)
pub const MAX_QUEUE_DEPTH: usize = 10_000;

/// Maximum queue memory in bytes (100 MB)
///
/// Prevents unbounded memory growth from message queue. When limit is
/// reached, new messages are rejected with "Memory limit exceeded" error.
///
/// **Requirement**: REQ-23 (Memory Usage Requirements)
pub const MAX_QUEUE_MEMORY: usize = 100 * 1024 * 1024; // 100 MB

/// Default target rate for global traffic scheduler (messages per second)
///
/// Configurable constant-rate output. Trade-offs:
/// - Higher rate (1000 msg/s): Lower latency (~0.5ms), higher bandwidth overhead
/// - Lower rate (100 msg/s): Higher latency (~5ms), lower bandwidth overhead
///
/// **Requirement**: REQ-5 (Global Unified Traffic Scheduler)
pub const DEFAULT_TARGET_RATE: f64 = 100.0; // messages per second

/// Minimum cover traffic rate (percentage of total traffic)
///
/// Security-by-default: Cannot be disabled or reduced below 20%.
/// Dummy messages fill gaps to maintain constant-rate output.
///
/// **Requirement**: REQ-8 (Security-by-Default Configuration)
pub const MIN_COVER_TRAFFIC_RATE: f64 = 0.20; // 20%

/// Default cover traffic budget (percentage of total traffic)
///
/// Configurable between MIN_COVER_TRAFFIC_RATE and 100%.
/// Trade-off between metadata protection and bandwidth overhead.
///
/// **Requirement**: REQ-6 (Global Dummy Message Generation)
pub const DEFAULT_COVER_TRAFFIC_BUDGET: f64 = 0.20; // 20%

/// Session state memory size per session (bytes)
///
/// Approximate memory usage per active session for capacity planning.
///
/// **Requirement**: REQ-23 (Memory Usage Requirements)
pub const SESSION_STATE_SIZE: usize = 2 * 1024; // 2 KB

/// Random value size (bytes)
///
/// Used for client_random and server_random in mode negotiation and
/// cookie challenge. 32 bytes provides 256 bits of entropy.
pub const RANDOM_SIZE: usize = 32;

/// Cookie size (bytes)
///
/// HMAC-SHA256 output size. Used for stateless DoS protection.
pub const COOKIE_SIZE: usize = 32;

/// Session ID size (bytes)
///
/// HKDF-SHA512 output size. Used for session identification and key binding.
pub const SESSION_ID_SIZE: usize = 32;

/// Protocol ID size (bytes)
///
/// SHA3-256 output size. Used for protocol version enforcement and domain separation.
pub const PROTOCOL_ID_SIZE: usize = 32;

/// Mode binding size (bytes)
///
/// SHA3-256 output size. Used for mode downgrade protection.
pub const MODE_BINDING_SIZE: usize = 32;

/// Handshake timeout in seconds
///
/// Maximum time allowed for handshake completion. Prevents resource
/// exhaustion from incomplete handshakes.
pub const HANDSHAKE_TIMEOUT_SECONDS: u64 = 60;

/// Performance target: Cookie generation time (milliseconds)
///
/// Target: ~0.02ms for HMAC-SHA256 computation
///
/// **Requirement**: REQ-21 (Handshake Performance Requirements)
pub const TARGET_COOKIE_GENERATION_MS: f64 = 0.02;

/// Performance target: Cookie verification time (milliseconds)
///
/// Target: ~0.02ms for HMAC-SHA256 verification
///
/// **Requirement**: REQ-21 (Handshake Performance Requirements)
pub const TARGET_COOKIE_VERIFICATION_MS: f64 = 0.02;

/// Performance target: Mode A signature generation time (milliseconds)
///
/// Target: ~0.1ms for XEdDSA signature generation
///
/// **Requirement**: REQ-21 (Handshake Performance Requirements)
pub const TARGET_MODE_A_SIGN_MS: f64 = 0.1;

/// Performance target: Mode A signature verification time (milliseconds)
///
/// Target: ~0.2ms for XEdDSA signature verification
///
/// **Requirement**: REQ-21 (Handshake Performance Requirements)
pub const TARGET_MODE_A_VERIFY_MS: f64 = 0.2;

/// Performance target: Mode B signature generation time (milliseconds)
///
/// Target: ~5ms for Dilithium5 signature generation
///
/// **Requirement**: REQ-21 (Handshake Performance Requirements)
pub const TARGET_MODE_B_SIGN_MS: f64 = 5.0;

/// Performance target: Mode B signature verification time (milliseconds)
///
/// Target: ~5ms for Dilithium5 signature verification
///
/// **Requirement**: REQ-21 (Handshake Performance Requirements)
pub const TARGET_MODE_B_VERIFY_MS: f64 = 5.0;

/// Performance target: Mode A total handshake time (milliseconds)
///
/// Target: ~150ms including network latency
///
/// **Requirement**: REQ-21 (Handshake Performance Requirements)
pub const TARGET_MODE_A_HANDSHAKE_MS: f64 = 150.0;

/// Performance target: Mode B total handshake time (milliseconds)
///
/// Target: ~155ms including network latency
///
/// **Requirement**: REQ-21 (Handshake Performance Requirements)
pub const TARGET_MODE_B_HANDSHAKE_MS: f64 = 155.0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version() {
        assert_eq!(PROTOCOL_VERSION_V2, "2.0.0");
        assert_eq!(PROTOCOL_NAME_V2, "B4AE-v2");
    }

    #[test]
    fn test_size_constants() {
        assert_eq!(RANDOM_SIZE, 32);
        assert_eq!(COOKIE_SIZE, 32);
        assert_eq!(SESSION_ID_SIZE, 32);
        assert_eq!(PROTOCOL_ID_SIZE, 32);
        assert_eq!(MODE_BINDING_SIZE, 32);
    }

    #[test]
    fn test_security_by_default() {
        // Minimum cover traffic rate cannot be zero
        assert!(MIN_COVER_TRAFFIC_RATE > 0.0);
        // Default cover traffic budget must meet minimum
        assert!(DEFAULT_COVER_TRAFFIC_BUDGET >= MIN_COVER_TRAFFIC_RATE);
    }

    #[test]
    fn test_performance_targets() {
        // Cookie operations should be very fast
        assert!(TARGET_COOKIE_GENERATION_MS < 0.1);
        assert!(TARGET_COOKIE_VERIFICATION_MS < 0.1);
        
        // Mode A should be faster than Mode B
        assert!(TARGET_MODE_A_SIGN_MS < TARGET_MODE_B_SIGN_MS);
        assert!(TARGET_MODE_A_VERIFY_MS < TARGET_MODE_B_VERIFY_MS);
        assert!(TARGET_MODE_A_HANDSHAKE_MS < TARGET_MODE_B_HANDSHAKE_MS);
    }

    #[test]
    fn test_domain_separators_unique() {
        // Ensure all domain separators are unique to prevent cross-protocol attacks
        let separators = vec![
            DOMAIN_MODE_BINDING,
            DOMAIN_SESSION_ID,
            DOMAIN_SESSION_KEY,
            DOMAIN_ROOT_KEY,
            DOMAIN_CHAIN_KEY,
            DOMAIN_HANDSHAKE_TRANSCRIPT,
        ];
        
        for i in 0..separators.len() {
            for j in (i + 1)..separators.len() {
                assert_ne!(separators[i], separators[j], 
                    "Domain separators must be unique");
            }
        }
    }
}
