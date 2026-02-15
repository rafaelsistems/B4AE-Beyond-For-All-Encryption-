// B4AE Fuzzing Tests
// Protocol fuzzing and robustness testing

use b4ae::protocol::handshake::{HandshakeConfig, HandshakeInitiator, HandshakeResponder};
use b4ae::protocol::message::Message;
use b4ae::crypto::random;

#[test]
fn test_malformed_handshake_init() {
    // Test handling of malformed handshake init messages
    let config = HandshakeConfig::default();
    let mut responder = HandshakeResponder::new(config).unwrap();
    
    // Create a valid init first
    let mut initiator = HandshakeInitiator::new(HandshakeConfig::default()).unwrap();
    let mut init = initiator.generate_init().unwrap();
    
    // Corrupt the signature
    if let Some(last) = init.signature.last_mut() {
        *last = last.wrapping_add(1);
    }
    
    // Should reject corrupted init
    let result = responder.process_init(init);
    assert!(result.is_err(), "Should reject corrupted handshake init");
}

#[test]
fn test_random_data_handling() {
    // Test that random data doesn't crash the system
    for _ in 0..100 {
        let random_data = random::random_bytes(1024);
        
        // Try to deserialize as message
        let result = Message::from_bytes(&random_data);
        // Should fail gracefully, not panic
        assert!(result.is_err());
    }
}

#[test]
fn test_oversized_message() {
    // Test handling of oversized messages (DoS mitigation)
    // MAX_MESSAGE_SIZE = 1 MiB; messages exceeding it must be rejected
    let oversized_data = vec![0u8; 10 * 1024 * 1024]; // 10MB
    let msg = Message::binary(oversized_data);
    
    // Should reject oversized messages
    let serialized = msg.to_bytes();
    assert!(serialized.is_err(), "Oversized messages must be rejected");

    // Large but valid messages (just under 1 MiB) should succeed
    let large_valid_data = vec![0u8; (1024 * 1024) - 256]; // ~1 MiB - overhead
    let msg_valid = Message::binary(large_valid_data);
    assert!(msg_valid.to_bytes().is_ok(), "Large valid messages should serialize");
}

#[test]
fn test_empty_message() {
    // Test handling of empty messages
    let msg = Message::text("");
    let serialized = msg.to_bytes().unwrap();
    let deserialized = Message::from_bytes(&serialized).unwrap();
    
    match deserialized.content {
        b4ae::protocol::message::MessageContent::Text(text) => {
            assert_eq!(text, "");
        }
        _ => panic!("Wrong message type"),
    }
}

#[test]
fn test_rapid_handshake_attempts() {
    // Test rapid handshake attempts (potential DoS)
    let config = HandshakeConfig::default();
    
    for _ in 0..100 {
        let _initiator = HandshakeInitiator::new(config.clone()).unwrap();
        let _responder = HandshakeResponder::new(config.clone()).unwrap();
    }
    
    // Should handle rapid creation without issues
}

#[test]
fn test_concurrent_sessions() {
    // Test multiple concurrent sessions
    let config = HandshakeConfig::default();
    
    let mut sessions = Vec::new();
    
    for _ in 0..10 {
        let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
        let mut responder = HandshakeResponder::new(config.clone()).unwrap();
        
        let init = initiator.generate_init().unwrap();
        let response = responder.process_init(init).unwrap();
        initiator.process_response(response).unwrap();
        let complete = initiator.generate_complete().unwrap();
        responder.process_complete(complete).unwrap();
        
        let client_result = initiator.finalize().unwrap();
        sessions.push(client_result);
    }
    
    // All sessions should have unique IDs
    let mut session_ids = std::collections::HashSet::new();
    for session in sessions {
        assert!(session_ids.insert(session.session_id));
    }
}

#[test]
fn test_invalid_protocol_version() {
    // Test handling of invalid protocol versions
    let config = HandshakeConfig::default();
    let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
    let mut responder = HandshakeResponder::new(config).unwrap();
    
    let mut init = initiator.generate_init().unwrap();
    
    // Corrupt protocol version
    init.protocol_version = 0xFFFF;
    
    // Should reject invalid version
    let result = responder.process_init(init);
    assert!(result.is_err(), "Should reject invalid protocol version");
}

#[test]
fn test_message_with_special_characters() {
    // Test messages with special characters
    let special_chars = "Hello 世界 🌍 \n\r\t\0";
    let msg = Message::text(special_chars);
    
    let serialized = msg.to_bytes().unwrap();
    let deserialized = Message::from_bytes(&serialized).unwrap();
    
    match deserialized.content {
        b4ae::protocol::message::MessageContent::Text(text) => {
            assert_eq!(text, special_chars);
        }
        _ => panic!("Wrong message type"),
    }
}

#[test]
fn test_binary_data_integrity() {
    // Test binary data with all byte values
    let mut binary_data = Vec::new();
    for i in 0..=255u8 {
        binary_data.push(i);
    }
    
    let msg = Message::binary(binary_data.clone());
    let serialized = msg.to_bytes().unwrap();
    let deserialized = Message::from_bytes(&serialized).unwrap();
    
    match deserialized.content {
        b4ae::protocol::message::MessageContent::Binary(data) => {
            assert_eq!(data, binary_data);
        }
        _ => panic!("Wrong message type"),
    }
}

#[test]
fn test_handshake_timeout() {
    // Test handshake timeout handling
    let mut config = HandshakeConfig::default();
    config.timeout_ms = 0; // Immediate timeout
    
    let initiator = HandshakeInitiator::new(config).unwrap();
    
    // Wait a bit
    std::thread::sleep(std::time::Duration::from_millis(10));
    
    // Should be timed out
    assert!(initiator.is_timed_out());
}

#[test]
fn test_repeated_handshake_complete() {
    // Test handling of repeated handshake complete messages
    let config = HandshakeConfig::default();
    let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
    let mut responder = HandshakeResponder::new(config).unwrap();
    
    let init = initiator.generate_init().unwrap();
    let response = responder.process_init(init).unwrap();
    initiator.process_response(response).unwrap();
    let complete = initiator.generate_complete().unwrap();
    
    // First complete should succeed
    responder.process_complete(complete.clone()).unwrap();
    
    // Second complete should fail (wrong state)
    let result = responder.process_complete(complete);
    assert!(result.is_err(), "Should reject repeated complete");
}
