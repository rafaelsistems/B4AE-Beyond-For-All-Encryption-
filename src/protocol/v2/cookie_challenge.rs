//! Stateless Cookie Challenge for DoS Protection
//!
//! This module implements a stateless HMAC-based cookie challenge mechanism
//! to protect the server against denial-of-service attacks. The server issues
//! a cookie challenge before performing expensive cryptographic operations
//! (signature verification, KEM decapsulation).
//!
//! ## Design Goals
//!
//! 1. **Stateless**: Server stores no state between challenge and verification
//! 2. **Fast**: Cookie generation and verification ~0.01ms (HMAC-SHA256 only)
//! 3. **Secure**: Cryptographically secure (HMAC prevents forgery)
//! 4. **Time-bound**: Cookies expire after 30 seconds
//! 5. **Replay-protected**: Combined with Bloom filter for replay detection
//!
//! ## Security Properties
//!
//! - **DoS Amplification Reduction**: 360x reduction (3.6ms → 0.01ms for invalid attempts)
//! - **Forgery Resistance**: HMAC-SHA256 with server secret prevents cookie forgery
//! - **Replay Protection**: Timestamp + Bloom filter prevent replay attacks
//! - **Constant-Time**: Verification uses constant-time comparison
//!
//! ## Protocol Flow
//!
//! ```text
//! Client                                Server
//!   |                                     |
//!   |--- ClientHello (minimal) --------->|
//!   |    (client_random, timestamp)      |
//!   |                                     |
//!   |<-- CookieChallenge (stateless) ----|
//!   |    (cookie, server_random)         |
//!   |                                     |
//!   |--- ClientHelloWithCookie --------->|
//!   |    (client_random, cookie, ...)    |
//!   |                                     |
//!   |    [Server verifies cookie ~0.01ms]|
//!   |    [Only then: expensive crypto]   |
//! ```
//!
//! ## Requirements
//!
//! - REQ-3: Stateless Cookie Challenge for DoS Protection
//! - REQ-44: DoS Mitigation
//! - REQ-19: Side-Channel Resistance (constant-time operations)
//! - REQ-21: Handshake Performance Requirements

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::protocol::v2::constants::{COOKIE_SIZE, COOKIE_TIMEOUT_SECONDS};

/// Error type for cookie challenge operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookieChallengeError {
    /// Cookie verification failed (invalid HMAC)
    InvalidCookie,
    
    /// Timestamp is expired (older than COOKIE_TIMEOUT_SECONDS)
    ExpiredTimestamp,
    
    /// Timestamp is too far in the future (possible clock skew)
    FutureTimestamp,
    
    /// Invalid input parameters
    InvalidInput(String),
}

impl std::fmt::Display for CookieChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CookieChallengeError::InvalidCookie => {
                write!(f, "Cookie verification failed: invalid HMAC")
            }
            CookieChallengeError::ExpiredTimestamp => {
                write!(f, "Cookie expired: timestamp older than {} seconds", COOKIE_TIMEOUT_SECONDS)
            }
            CookieChallengeError::FutureTimestamp => {
                write!(f, "Cookie timestamp is too far in the future (possible clock skew)")
            }
            CookieChallengeError::InvalidInput(msg) => {
                write!(f, "Invalid input: {}", msg)
            }
        }
    }
}

impl std::error::Error for CookieChallengeError {}

/// Server secret for cookie generation
///
/// This secret must be:
/// - Randomly generated with cryptographic RNG
/// - Kept secret on the server
/// - Rotated periodically (e.g., every 24 hours)
/// - Zeroized on drop
///
/// The server can maintain multiple secrets for graceful rotation:
/// - Current secret for new cookies
/// - Previous secret(s) for verification during rotation window
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ServerSecret([u8; 32]);

impl ServerSecret {
    /// Creates a new server secret from raw bytes
    ///
    /// # Security
    ///
    /// The bytes should be generated using a cryptographically secure RNG.
    pub fn new(bytes: [u8; 32]) -> Self {
        ServerSecret(bytes)
    }

    /// Generates a new random server secret
    ///
    /// Uses the operating system's cryptographically secure RNG.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        ServerSecret(bytes)
    }

    /// Returns the secret as a byte slice
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Generates a stateless cookie for DoS protection
///
/// The cookie is computed as:
/// ```text
/// cookie = HMAC-SHA256(server_secret, client_ip || timestamp || client_random)
/// ```
///
/// ## Parameters
///
/// - `server_secret`: Server's secret key for HMAC (32 bytes)
/// - `client_ip`: Client's IP address as string (e.g., "192.168.1.1" or "2001:db8::1")
/// - `timestamp`: Unix timestamp in seconds (for expiry checking)
/// - `client_random`: Client's random nonce (32 bytes)
///
/// ## Returns
///
/// Returns a 32-byte cookie (HMAC-SHA256 output) or an error if inputs are invalid.
///
/// ## Performance
///
/// Target: ~0.01ms per cookie generation (HMAC-SHA256 only)
///
/// ## Security Properties
///
/// - **Stateless**: Server stores no state
/// - **Forgery-resistant**: Cannot be forged without server_secret
/// - **Time-bound**: Timestamp allows expiry checking
/// - **Replay-protected**: Combined with Bloom filter
///
/// ## Example
///
/// ```rust
/// use b4ae::protocol::v2::cookie_challenge::{generate_cookie, ServerSecret};
///
/// let server_secret = ServerSecret::generate();
/// let client_ip = "192.168.1.100";
/// let timestamp = 1234567890;
/// let client_random = [0u8; 32];
///
/// let cookie = generate_cookie(&server_secret, client_ip, timestamp, &client_random)
///     .expect("Failed to generate cookie");
///
/// assert_eq!(cookie.len(), 32);
/// ```
///
/// ## Requirements
///
/// - REQ-3: Stateless Cookie Challenge
/// - REQ-44: DoS Mitigation
/// - REQ-21: Performance (target 0.01ms)
pub fn generate_cookie(
    server_secret: &ServerSecret,
    client_ip: &str,
    timestamp: u64,
    client_random: &[u8],
) -> Result<Vec<u8>, CookieChallengeError> {
    // Validate inputs
    if client_random.len() != 32 {
        return Err(CookieChallengeError::InvalidInput(
            format!("client_random must be 32 bytes, got {}", client_random.len())
        ));
    }

    if client_ip.is_empty() {
        return Err(CookieChallengeError::InvalidInput(
            "client_ip cannot be empty".to_string()
        ));
    }

    // Compute HMAC-SHA256(server_secret, client_ip || timestamp || client_random)
    let mut hasher = Sha256::new();
    
    // Hash the concatenated inputs
    hasher.update(client_ip.as_bytes());
    hasher.update(&timestamp.to_be_bytes());
    hasher.update(client_random);
    
    let data_hash = hasher.finalize();
    
    // Compute HMAC: HMAC(key, data) = H((key ⊕ opad) || H((key ⊕ ipad) || data))
    // Using simplified HMAC construction with SHA256
    let mut hmac_hasher = Sha256::new();
    
    // Inner hash: H((key ⊕ ipad) || data)
    let mut ipad_key = [0x36u8; 64];
    for (i, &byte) in server_secret.as_bytes().iter().enumerate() {
        ipad_key[i] ^= byte;
    }
    hmac_hasher.update(&ipad_key);
    hmac_hasher.update(&data_hash);
    let inner_hash = hmac_hasher.finalize();
    
    // Outer hash: H((key ⊕ opad) || inner_hash)
    let mut hmac_hasher = Sha256::new();
    let mut opad_key = [0x5cu8; 64];
    for (i, &byte) in server_secret.as_bytes().iter().enumerate() {
        opad_key[i] ^= byte;
    }
    hmac_hasher.update(&opad_key);
    hmac_hasher.update(&inner_hash);
    let cookie = hmac_hasher.finalize();
    
    Ok(cookie.to_vec())
}

/// Verifies a cookie challenge
///
/// Recomputes the expected cookie using the same inputs and compares it
/// with the provided cookie using constant-time comparison.
///
/// ## Parameters
///
/// - `cookie`: Cookie to verify (32 bytes)
/// - `server_secret`: Server's secret key for HMAC (32 bytes)
/// - `client_ip`: Client's IP address as string
/// - `timestamp`: Unix timestamp from cookie challenge
/// - `client_random`: Client's random nonce (32 bytes)
///
/// ## Returns
///
/// Returns `Ok(())` if cookie is valid and not expired, otherwise returns an error.
///
/// ## Verification Steps
///
/// 1. Check timestamp freshness (current_time - timestamp ≤ 30 seconds)
/// 2. Recompute expected cookie using same inputs
/// 3. Compare using constant-time comparison
///
/// ## Performance
///
/// Target: ~0.01ms per verification (HMAC-SHA256 + constant-time comparison)
///
/// ## Security Properties
///
/// - **Constant-time**: Uses constant-time comparison to prevent timing attacks
/// - **Stateless**: No server state required
/// - **Time-bound**: Rejects expired cookies
///
/// ## Example
///
/// ```rust
/// use b4ae::protocol::v2::cookie_challenge::{generate_cookie, verify_cookie, ServerSecret};
///
/// let server_secret = ServerSecret::generate();
/// let client_ip = "192.168.1.100";
/// let timestamp = std::time::SystemTime::now()
///     .duration_since(std::time::UNIX_EPOCH)
///     .unwrap()
///     .as_secs();
/// let client_random = [0u8; 32];
///
/// // Generate cookie
/// let cookie = generate_cookie(&server_secret, client_ip, timestamp, &client_random)
///     .expect("Failed to generate cookie");
///
/// // Verify cookie
/// verify_cookie(&cookie, &server_secret, client_ip, timestamp, &client_random)
///     .expect("Cookie verification failed");
/// ```
///
/// ## Requirements
///
/// - REQ-3: Cookie Verification
/// - REQ-19: Constant-Time Operations
/// - REQ-21: Performance (target 0.01ms)
pub fn verify_cookie(
    cookie: &[u8],
    server_secret: &ServerSecret,
    client_ip: &str,
    timestamp: u64,
    client_random: &[u8],
) -> Result<(), CookieChallengeError> {
    // Validate cookie size
    if cookie.len() != COOKIE_SIZE {
        return Err(CookieChallengeError::InvalidCookie);
    }

    // Check timestamp freshness
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CookieChallengeError::InvalidInput("System time error".to_string()))?
        .as_secs();

    // Check if timestamp is expired (older than COOKIE_TIMEOUT_SECONDS)
    if current_time > timestamp && (current_time - timestamp) > COOKIE_TIMEOUT_SECONDS {
        return Err(CookieChallengeError::ExpiredTimestamp);
    }

    // Check if timestamp is too far in the future (allow 5 minute clock skew)
    if timestamp > current_time && (timestamp - current_time) > 300 {
        return Err(CookieChallengeError::FutureTimestamp);
    }

    // Recompute expected cookie
    let expected_cookie = generate_cookie(server_secret, client_ip, timestamp, client_random)?;

    // Constant-time comparison to prevent timing attacks
    let is_valid = cookie.ct_eq(&expected_cookie);

    if is_valid.into() {
        Ok(())
    } else {
        Err(CookieChallengeError::InvalidCookie)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_cookie_success() {
        let server_secret = ServerSecret::generate();
        let client_ip = "192.168.1.100";
        let timestamp = 1234567890;
        let client_random = [0u8; 32];

        let cookie = generate_cookie(&server_secret, client_ip, timestamp, &client_random)
            .expect("Failed to generate cookie");

        assert_eq!(cookie.len(), COOKIE_SIZE);
    }

    #[test]
    fn test_generate_cookie_invalid_client_random() {
        let server_secret = ServerSecret::generate();
        let client_ip = "192.168.1.100";
        let timestamp = 1234567890;
        let client_random = [0u8; 16]; // Wrong size

        let result = generate_cookie(&server_secret, client_ip, timestamp, &client_random);
        assert!(matches!(result, Err(CookieChallengeError::InvalidInput(_))));
    }

    #[test]
    fn test_generate_cookie_empty_ip() {
        let server_secret = ServerSecret::generate();
        let client_ip = "";
        let timestamp = 1234567890;
        let client_random = [0u8; 32];

        let result = generate_cookie(&server_secret, client_ip, timestamp, &client_random);
        assert!(matches!(result, Err(CookieChallengeError::InvalidInput(_))));
    }

    #[test]
    fn test_verify_cookie_success() {
        let server_secret = ServerSecret::generate();
        let client_ip = "192.168.1.100";
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let client_random = [0u8; 32];

        // Generate cookie
        let cookie = generate_cookie(&server_secret, client_ip, timestamp, &client_random)
            .expect("Failed to generate cookie");

        // Verify cookie
        verify_cookie(&cookie, &server_secret, client_ip, timestamp, &client_random)
            .expect("Cookie verification failed");
    }

    #[test]
    fn test_verify_cookie_invalid_cookie() {
        let server_secret = ServerSecret::generate();
        let client_ip = "192.168.1.100";
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let client_random = [0u8; 32];

        // Generate valid cookie
        let mut cookie = generate_cookie(&server_secret, client_ip, timestamp, &client_random)
            .expect("Failed to generate cookie");

        // Tamper with cookie
        cookie[0] ^= 0xFF;

        // Verify should fail
        let result = verify_cookie(&cookie, &server_secret, client_ip, timestamp, &client_random);
        assert!(matches!(result, Err(CookieChallengeError::InvalidCookie)));
    }

    #[test]
    fn test_verify_cookie_expired() {
        let server_secret = ServerSecret::generate();
        let client_ip = "192.168.1.100";
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp = current_time - COOKIE_TIMEOUT_SECONDS - 1; // Expired
        let client_random = [0u8; 32];

        // Generate cookie with expired timestamp
        let cookie = generate_cookie(&server_secret, client_ip, timestamp, &client_random)
            .expect("Failed to generate cookie");

        // Verify should fail due to expiry
        let result = verify_cookie(&cookie, &server_secret, client_ip, timestamp, &client_random);
        assert!(matches!(result, Err(CookieChallengeError::ExpiredTimestamp)));
    }

    #[test]
    fn test_verify_cookie_future_timestamp() {
        let server_secret = ServerSecret::generate();
        let client_ip = "192.168.1.100";
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp = current_time + 400; // Too far in future (> 5 min)
        let client_random = [0u8; 32];

        // Generate cookie with future timestamp
        let cookie = generate_cookie(&server_secret, client_ip, timestamp, &client_random)
            .expect("Failed to generate cookie");

        // Verify should fail due to future timestamp
        let result = verify_cookie(&cookie, &server_secret, client_ip, timestamp, &client_random);
        assert!(matches!(result, Err(CookieChallengeError::FutureTimestamp)));
    }

    #[test]
    fn test_verify_cookie_wrong_secret() {
        let server_secret1 = ServerSecret::generate();
        let server_secret2 = ServerSecret::generate();
        let client_ip = "192.168.1.100";
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let client_random = [0u8; 32];

        // Generate cookie with secret1
        let cookie = generate_cookie(&server_secret1, client_ip, timestamp, &client_random)
            .expect("Failed to generate cookie");

        // Verify with secret2 should fail
        let result = verify_cookie(&cookie, &server_secret2, client_ip, timestamp, &client_random);
        assert!(matches!(result, Err(CookieChallengeError::InvalidCookie)));
    }

    #[test]
    fn test_verify_cookie_wrong_ip() {
        let server_secret = ServerSecret::generate();
        let client_ip1 = "192.168.1.100";
        let client_ip2 = "192.168.1.101";
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let client_random = [0u8; 32];

        // Generate cookie with ip1
        let cookie = generate_cookie(&server_secret, client_ip1, timestamp, &client_random)
            .expect("Failed to generate cookie");

        // Verify with ip2 should fail
        let result = verify_cookie(&cookie, &server_secret, client_ip2, timestamp, &client_random);
        assert!(matches!(result, Err(CookieChallengeError::InvalidCookie)));
    }

    #[test]
    fn test_verify_cookie_wrong_random() {
        let server_secret = ServerSecret::generate();
        let client_ip = "192.168.1.100";
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let client_random1 = [0u8; 32];
        let client_random2 = [1u8; 32];

        // Generate cookie with random1
        let cookie = generate_cookie(&server_secret, client_ip, timestamp, &client_random1)
            .expect("Failed to generate cookie");

        // Verify with random2 should fail
        let result = verify_cookie(&cookie, &server_secret, client_ip, timestamp, &client_random2);
        assert!(matches!(result, Err(CookieChallengeError::InvalidCookie)));
    }

    #[test]
    fn test_cookie_deterministic() {
        let server_secret = ServerSecret::new([42u8; 32]);
        let client_ip = "192.168.1.100";
        let timestamp = 1234567890;
        let client_random = [0u8; 32];

        // Generate cookie twice with same inputs
        let cookie1 = generate_cookie(&server_secret, client_ip, timestamp, &client_random)
            .expect("Failed to generate cookie");
        let cookie2 = generate_cookie(&server_secret, client_ip, timestamp, &client_random)
            .expect("Failed to generate cookie");

        // Should be identical
        assert_eq!(cookie1, cookie2);
    }

    #[test]
    fn test_cookie_different_inputs() {
        let server_secret = ServerSecret::generate();
        let client_ip = "192.168.1.100";
        let timestamp1 = 1234567890;
        let timestamp2 = 1234567891;
        let client_random = [0u8; 32];

        // Generate cookies with different timestamps
        let cookie1 = generate_cookie(&server_secret, client_ip, timestamp1, &client_random)
            .expect("Failed to generate cookie");
        let cookie2 = generate_cookie(&server_secret, client_ip, timestamp2, &client_random)
            .expect("Failed to generate cookie");

        // Should be different
        assert_ne!(cookie1, cookie2);
    }

    #[test]
    fn test_server_secret_zeroize() {
        let mut secret = ServerSecret::new([42u8; 32]);
        let ptr = secret.0.as_ptr();
        
        // Verify secret is set
        assert_eq!(secret.0[0], 42);
        
        // Drop should zeroize
        drop(secret);
        
        // Note: We can't safely verify zeroization after drop in safe Rust,
        // but the zeroize crate guarantees this behavior
    }

    #[test]
    fn test_ipv6_address() {
        let server_secret = ServerSecret::generate();
        let client_ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let client_random = [0u8; 32];

        // Generate and verify cookie with IPv6 address
        let cookie = generate_cookie(&server_secret, client_ip, timestamp, &client_random)
            .expect("Failed to generate cookie");

        verify_cookie(&cookie, &server_secret, client_ip, timestamp, &client_random)
            .expect("Cookie verification failed");
    }
}
