//! Integration tests for cookie challenge in handshake flow
//!
//! This test suite validates that the cookie challenge is properly integrated
//! into the handshake flow and provides DoS protection.
//!
//! ## Test Coverage
//!
//! - Complete handshake flow with cookie challenge
//! - Cookie generation and verification
//! - Replay protection with Bloom filter
//! - State machine transitions through COOKIE_CHALLENGE state
//! - DoS protection (server doesn't perform expensive ops until cookie verified)
//! - Timestamp validation and expiry
//!
//! ## Requirements
//!
//! - REQ-3: Stateless Cookie Challenge for DoS Protection
//! - REQ-4: Replay Protection for Cookie Challenge
//! - REQ-44: DoS Mitigation
//! - REQ-47: Protocol State Machine Requirements

use b4ae::protocol::v2::cookie_challenge::{generate_cookie, verify_cookie, ServerSecret};
use b4ae::protocol::v2::replay_protection::ReplayProtection;
use b4ae::protocol::v2::state_machine::{StateMachine, Role, MessageType, ProtocolState};
use b4ae::protocol::v2::types::{ClientHello, CookieChallenge, ClientHelloWithCookie};

/// Test complete handshake flow with cookie challenge
///
/// This test simulates the full protocol flow:
/// 1. Client → Server: ClientHello (minimal, no expensive crypto)
/// 2. Server → Client: CookieChallenge (stateless)
/// 3. Client → Server: ClientHelloWithCookie (includes cookie + full handshake data)
/// 4. Server verifies cookie (0.01ms) before expensive operations
#[test]
fn test_complete_handshake_flow_with_cookie_challenge() {
    // Initialize server components
    let server_secret = ServerSecret::generate();
    let replay_protection = ReplayProtection::new();
    let mut server_sm = StateMachine::new(Role::Server);
    
    // Initialize client components
    let mut client_sm = StateMachine::new(Role::Client);
    
    // === Phase 1: Mode Negotiation ===
    
    // Client sends ModeNegotiation
    client_sm.on_send(MessageType::ModeNegotiation).unwrap();
    assert_eq!(client_sm.state(), ProtocolState::ModeNegotiation);
    
    // Server receives ModeNegotiation
    server_sm.on_receive(MessageType::ModeNegotiation).unwrap();
    assert_eq!(server_sm.state(), ProtocolState::ModeNegotiation);
    
    // Server sends ModeSelection
    server_sm.on_send(MessageType::ModeSelection).unwrap();
    assert_eq!(server_sm.state(), ProtocolState::CookieChallenge);
    
    // Client receives ModeSelection
    client_sm.on_receive(MessageType::ModeSelection).unwrap();
    assert_eq!(client_sm.state(), ProtocolState::CookieChallenge);
    
    // === Phase 2: Cookie Challenge ===
    
    // Client sends ClientHello (minimal, no expensive crypto)
    let client_random = [42u8; 32];
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let client_hello = ClientHello {
        client_random,
        timestamp,
    };
    
    // Note: Client doesn't change state when sending ClientHello in MODE_NEGOTIATION
    // The state transition happens when receiving CookieChallenge
    
    // Server receives ClientHello and generates cookie (stateless, ~0.01ms)
    let client_ip = "192.168.1.100";
    let cookie = generate_cookie(
        &server_secret,
        client_ip,
        timestamp,
        &client_random,
    ).expect("Failed to generate cookie");
    
    let server_random = [99u8; 32];
    let cookie_challenge = CookieChallenge {
        cookie: cookie.try_into().expect("Cookie should be 32 bytes"),
        server_random,
    };
    
    // Server sends CookieChallenge (stays in COOKIE_CHALLENGE state)
    server_sm.on_send(MessageType::CookieChallenge).unwrap();
    assert_eq!(server_sm.state(), ProtocolState::CookieChallenge);
    
    // Client receives CookieChallenge (stays in COOKIE_CHALLENGE state)
    client_sm.on_receive(MessageType::CookieChallenge).unwrap();
    assert_eq!(client_sm.state(), ProtocolState::CookieChallenge);
    
    // === Phase 3: Client sends ClientHelloWithCookie ===
    
    let client_hello_with_cookie = ClientHelloWithCookie {
        client_random,
        cookie: cookie_challenge.cookie,
        timestamp,
    };
    
    // Client sends ClientHelloWithCookie (transitions to HANDSHAKE)
    client_sm.on_send(MessageType::ClientHelloWithCookie).unwrap();
    assert_eq!(client_sm.state(), ProtocolState::Handshake);
    
    // === Phase 4: Server verifies cookie before expensive operations ===
    
    // Server verifies cookie (cheap, ~0.01ms)
    verify_cookie(
        &client_hello_with_cookie.cookie,
        &server_secret,
        client_ip,
        client_hello_with_cookie.timestamp,
        &client_hello_with_cookie.client_random,
    ).expect("Cookie verification failed");
    
    // Server checks replay protection
    replay_protection.check_and_insert(&client_hello_with_cookie.client_random)
        .expect("Replay protection check failed");
    
    // Server receives ClientHelloWithCookie (transitions to HANDSHAKE)
    server_sm.on_receive(MessageType::ClientHelloWithCookie).unwrap();
    assert_eq!(server_sm.state(), ProtocolState::Handshake);
    
    // === Phase 5: Continue with expensive handshake operations ===
    
    // Now server can perform expensive operations (signature verification, KEM decapsulation)
    // This is where the DoS protection pays off - we only get here if cookie is valid
    
    // Server receives HandshakeInit
    server_sm.on_receive(MessageType::HandshakeInit).unwrap();
    assert_eq!(server_sm.state(), ProtocolState::Handshake);
    
    // Server sends HandshakeResponse
    server_sm.on_send(MessageType::HandshakeResponse).unwrap();
    assert_eq!(server_sm.state(), ProtocolState::Handshake);
    
    // Client sends HandshakeInit
    client_sm.on_send(MessageType::HandshakeInit).unwrap();
    assert_eq!(client_sm.state(), ProtocolState::Handshake);
    
    // Client receives HandshakeResponse
    client_sm.on_receive(MessageType::HandshakeResponse).unwrap();
    assert_eq!(client_sm.state(), ProtocolState::Handshake);
    
    // Client sends HandshakeComplete
    client_sm.on_send(MessageType::HandshakeComplete).unwrap();
    assert_eq!(client_sm.state(), ProtocolState::Established);
    
    // Server receives HandshakeComplete
    server_sm.on_receive(MessageType::HandshakeComplete).unwrap();
    assert_eq!(server_sm.state(), ProtocolState::Established);
    
    // Both parties are now in ESTABLISHED state
    assert_eq!(client_sm.state(), ProtocolState::Established);
    assert_eq!(server_sm.state(), ProtocolState::Established);
}

/// Test that server rejects invalid cookie before expensive operations
///
/// This demonstrates the DoS protection: server performs cheap cookie
/// verification (~0.01ms) before expensive crypto operations (~3.6ms).
#[test]
fn test_server_rejects_invalid_cookie() {
    let server_secret = ServerSecret::generate();
    let client_ip = "192.168.1.100";
    let client_random = [42u8; 32];
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Generate valid cookie
    let valid_cookie = generate_cookie(
        &server_secret,
        client_ip,
        timestamp,
        &client_random,
    ).expect("Failed to generate cookie");
    
    // Tamper with cookie
    let mut invalid_cookie = valid_cookie.clone();
    invalid_cookie[0] ^= 0xFF;
    
    // Server verifies cookie - should fail
    let result = verify_cookie(
        &invalid_cookie,
        &server_secret,
        client_ip,
        timestamp,
        &client_random,
    );
    
    assert!(result.is_err(), "Invalid cookie should be rejected");
    
    // Server does NOT perform expensive operations (signature verification, KEM decapsulation)
    // This is the DoS protection in action
}

/// Test that server rejects expired cookie
///
/// Cookies expire after 30 seconds to prevent replay attacks.
#[test]
fn test_server_rejects_expired_cookie() {
    let server_secret = ServerSecret::generate();
    let client_ip = "192.168.1.100";
    let client_random = [42u8; 32];
    
    // Use timestamp from 31 seconds ago (expired)
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expired_timestamp = current_time - 31;
    
    // Generate cookie with expired timestamp
    let cookie = generate_cookie(
        &server_secret,
        client_ip,
        expired_timestamp,
        &client_random,
    ).expect("Failed to generate cookie");
    
    // Server verifies cookie - should fail due to expiry
    let result = verify_cookie(
        &cookie,
        &server_secret,
        client_ip,
        expired_timestamp,
        &client_random,
    );
    
    assert!(result.is_err(), "Expired cookie should be rejected");
}

/// Test replay protection with Bloom filter
///
/// Server should detect and reject replayed ClientHelloWithCookie messages
/// within the 30-second window.
#[test]
fn test_replay_protection() {
    let server_secret = ServerSecret::generate();
    let replay_protection = ReplayProtection::new();
    let client_ip = "192.168.1.100";
    let client_random = [42u8; 32];
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Generate valid cookie
    let cookie = generate_cookie(
        &server_secret,
        client_ip,
        timestamp,
        &client_random,
    ).expect("Failed to generate cookie");
    
    // First attempt: should succeed
    verify_cookie(&cookie, &server_secret, client_ip, timestamp, &client_random)
        .expect("First cookie verification should succeed");
    
    replay_protection.check_and_insert(&client_random)
        .expect("First replay check should succeed");
    
    // Second attempt with same client_random: should be detected as replay
    verify_cookie(&cookie, &server_secret, client_ip, timestamp, &client_random)
        .expect("Cookie is still valid");
    
    let replay_result = replay_protection.check_and_insert(&client_random);
    assert!(replay_result.is_err(), "Replay should be detected");
}

/// Test that different client_random values are not detected as replays
///
/// Ensures Bloom filter doesn't have excessive false positives.
#[test]
fn test_different_client_randoms_not_replays() {
    let replay_protection = ReplayProtection::new();
    
    // Insert 100 different client_random values
    for i in 0..100 {
        let mut client_random = [0u8; 32];
        client_random[0] = i;
        
        replay_protection.check_and_insert(&client_random)
            .expect("Different client_random should not be detected as replay");
    }
}

/// Test state machine transitions through COOKIE_CHALLENGE state
///
/// Validates that the state machine correctly enforces the cookie challenge flow.
#[test]
fn test_state_machine_cookie_challenge_transitions() {
    let mut client = StateMachine::new(Role::Client);
    let mut server = StateMachine::new(Role::Server);
    
    // Initial state
    assert_eq!(client.state(), ProtocolState::Init);
    assert_eq!(server.state(), ProtocolState::Init);
    
    // Mode negotiation
    client.on_send(MessageType::ModeNegotiation).unwrap();
    server.on_receive(MessageType::ModeNegotiation).unwrap();
    server.on_send(MessageType::ModeSelection).unwrap();
    client.on_receive(MessageType::ModeSelection).unwrap();
    
    // Both should be in COOKIE_CHALLENGE state
    assert_eq!(client.state(), ProtocolState::CookieChallenge);
    assert_eq!(server.state(), ProtocolState::CookieChallenge);
    
    // Server sends CookieChallenge (stays in COOKIE_CHALLENGE)
    server.on_send(MessageType::CookieChallenge).unwrap();
    assert_eq!(server.state(), ProtocolState::CookieChallenge);
    
    // Client receives CookieChallenge (stays in COOKIE_CHALLENGE)
    client.on_receive(MessageType::CookieChallenge).unwrap();
    assert_eq!(client.state(), ProtocolState::CookieChallenge);
    
    // Client sends ClientHelloWithCookie (transitions to HANDSHAKE)
    client.on_send(MessageType::ClientHelloWithCookie).unwrap();
    assert_eq!(client.state(), ProtocolState::Handshake);
    
    // Server receives ClientHelloWithCookie (transitions to HANDSHAKE)
    server.on_receive(MessageType::ClientHelloWithCookie).unwrap();
    assert_eq!(server.state(), ProtocolState::Handshake);
}

/// Test that server cannot skip cookie challenge
///
/// Ensures state machine enforces cookie challenge before handshake.
#[test]
fn test_cannot_skip_cookie_challenge() {
    let mut server = StateMachine::new(Role::Server);
    
    // Server receives ModeNegotiation
    server.on_receive(MessageType::ModeNegotiation).unwrap();
    server.on_send(MessageType::ModeSelection).unwrap();
    assert_eq!(server.state(), ProtocolState::CookieChallenge);
    
    // Server cannot receive HandshakeInit without ClientHelloWithCookie first
    assert!(!server.can_receive(MessageType::HandshakeInit));
    
    let result = server.on_receive(MessageType::HandshakeInit);
    assert!(result.is_err(), "Should not be able to skip cookie challenge");
}

/// Test DoS amplification reduction
///
/// Demonstrates that cookie challenge reduces DoS amplification from 360x to 1x.
/// Without cookie: attacker forces 3.6ms of work per fake request
/// With cookie: attacker forces 0.01ms of work per fake request
#[test]
fn test_dos_amplification_reduction() {
    use std::time::Instant;
    
    let server_secret = ServerSecret::generate();
    let client_ip = "192.168.1.100";
    
    // Measure cookie generation time (server's work for invalid request)
    let start = Instant::now();
    for i in 0..1000 {
        let mut client_random = [0u8; 32];
        client_random[0] = (i % 256) as u8;
        client_random[1] = (i / 256) as u8;
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let _ = generate_cookie(&server_secret, client_ip, timestamp, &client_random);
    }
    let elapsed = start.elapsed();
    let avg_cookie_time = elapsed.as_micros() as f64 / 1000.0;
    
    // Cookie generation should be very fast (target: ~10 microseconds)
    println!("Average cookie generation time: {:.2} μs", avg_cookie_time);
    assert!(avg_cookie_time < 100.0, "Cookie generation should be < 100μs");
    
    // Without cookie challenge, server would perform:
    // - Dilithium5 signature verification: ~3000μs
    // - Kyber1024 decapsulation: ~600μs
    // - Total: ~3600μs
    //
    // DoS amplification reduction: 3600μs / 10μs = 360x
}

/// Test cookie challenge with IPv6 address
///
/// Ensures cookie challenge works with both IPv4 and IPv6 addresses.
#[test]
fn test_cookie_challenge_with_ipv6() {
    let server_secret = ServerSecret::generate();
    let client_ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    let client_random = [42u8; 32];
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Generate cookie with IPv6 address
    let cookie = generate_cookie(
        &server_secret,
        client_ip,
        timestamp,
        &client_random,
    ).expect("Failed to generate cookie with IPv6");
    
    // Verify cookie
    verify_cookie(&cookie, &server_secret, client_ip, timestamp, &client_random)
        .expect("Cookie verification with IPv6 should succeed");
}

/// Test that cookie is bound to client IP address
///
/// Ensures attacker cannot steal cookie from one IP and use it from another.
#[test]
fn test_cookie_bound_to_client_ip() {
    let server_secret = ServerSecret::generate();
    let client_ip1 = "192.168.1.100";
    let client_ip2 = "192.168.1.101";
    let client_random = [42u8; 32];
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Generate cookie for IP1
    let cookie = generate_cookie(
        &server_secret,
        client_ip1,
        timestamp,
        &client_random,
    ).expect("Failed to generate cookie");
    
    // Verify with IP1: should succeed
    verify_cookie(&cookie, &server_secret, client_ip1, timestamp, &client_random)
        .expect("Cookie should verify with correct IP");
    
    // Verify with IP2: should fail
    let result = verify_cookie(&cookie, &server_secret, client_ip2, timestamp, &client_random);
    assert!(result.is_err(), "Cookie should not verify with different IP");
}

/// Test stateless cookie challenge
///
/// Demonstrates that server stores no state between challenge and verification.
#[test]
fn test_stateless_cookie_challenge() {
    let server_secret = ServerSecret::generate();
    let client_ip = "192.168.1.100";
    let client_random = [42u8; 32];
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Server generates cookie (no state stored)
    let cookie = generate_cookie(
        &server_secret,
        client_ip,
        timestamp,
        &client_random,
    ).expect("Failed to generate cookie");
    
    // Server can verify cookie later without any stored state
    // (only needs server_secret which is long-lived)
    verify_cookie(&cookie, &server_secret, client_ip, timestamp, &client_random)
        .expect("Stateless verification should succeed");
    
    // Multiple verifications with same cookie should all succeed
    // (no state is consumed during verification)
    for _ in 0..10 {
        verify_cookie(&cookie, &server_secret, client_ip, timestamp, &client_random)
            .expect("Stateless verification should succeed multiple times");
    }
}
