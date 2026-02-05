// B4AE Integration Tests
// End-to-end testing of complete protocol flow

use b4ae::crypto::hybrid;
use b4ae::protocol::handshake::{HandshakeConfig, HandshakeInitiator, HandshakeResponder};
use b4ae::protocol::message::{Message, MessagePriority};
use b4ae::protocol::session::Session;

#[test]
fn test_complete_handshake_flow() {
    // Test complete handshake between client and server
    let config = HandshakeConfig::default();
    
    let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
    let mut responder = HandshakeResponder::new(config).unwrap();
    
    // Step 1: Client initiates
    let init = initiator.generate_init().unwrap();
    
    // Step 2: Server responds
    let response = responder.process_init(init).unwrap();
    
    // Step 3: Client processes response
    initiator.process_response(response).unwrap();
    
    // Step 4: Client completes
    let complete = initiator.generate_complete().unwrap();
    
    // Step 5: Server processes complete
    responder.process_complete(complete).unwrap();
    
    // Step 6: Both derive session keys
    let client_result = initiator.finalize().unwrap();
    let server_result = responder.finalize().unwrap();
    
    // Verify session IDs match
    assert_eq!(client_result.session_id, server_result.session_id);
    
    // Verify session keys match
    assert_eq!(
        client_result.session_keys.encryption_key,
        server_result.session_keys.encryption_key
    );
}

#[test]
fn test_end_to_end_message_flow() {
    // Test complete message encryption and decryption flow
    let config = HandshakeConfig::default();
    
    let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
    let mut responder = HandshakeResponder::new(config).unwrap();
    
    // Complete handshake
    let init = initiator.generate_init().unwrap();
    let response = responder.process_init(init).unwrap();
    initiator.process_response(response).unwrap();
    let complete = initiator.generate_complete().unwrap();
    responder.process_complete(complete).unwrap();
    
    let client_result = initiator.finalize().unwrap();
    let server_result = responder.finalize().unwrap();
    
    // Create sessions
    let mut client_session = Session::from_handshake(
        client_result,
        b"server".to_vec(),
    ).unwrap();
    
    let mut server_session = Session::from_handshake(
        server_result,
        b"client".to_vec(),
    ).unwrap();
    
    // Send message from client to server
    let message = Message::text("Hello, B4AE!")
        .with_priority(MessagePriority::High);
    
    let encrypted = client_session.send(&message).unwrap();
    let decrypted = server_session.receive(&encrypted).unwrap();
    
    // Verify message content
    match decrypted.content {
        b4ae::protocol::message::MessageContent::Text(text) => {
            assert_eq!(text, "Hello, B4AE!");
        }
        _ => panic!("Wrong message type"),
    }
}

#[test]
fn test_multiple_message_exchange() {
    // Test multiple messages in both directions
    let config = HandshakeConfig::default();
    
    let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
    let mut responder = HandshakeResponder::new(config).unwrap();
    
    // Complete handshake
    let init = initiator.generate_init().unwrap();
    let response = responder.process_init(init).unwrap();
    initiator.process_response(response).unwrap();
    let complete = initiator.generate_complete().unwrap();
    responder.process_complete(complete).unwrap();
    
    let client_result = initiator.finalize().unwrap();
    let server_result = responder.finalize().unwrap();
    
    let mut client_session = Session::from_handshake(
        client_result,
        b"server".to_vec(),
    ).unwrap();
    
    let mut server_session = Session::from_handshake(
        server_result,
        b"client".to_vec(),
    ).unwrap();
    
    // Exchange multiple messages
    for i in 0..10 {
        let msg = Message::text(format!("Message {}", i));
        let encrypted = client_session.send(&msg).unwrap();
        let decrypted = server_session.receive(&encrypted).unwrap();
        
        match decrypted.content {
            b4ae::protocol::message::MessageContent::Text(text) => {
                assert_eq!(text, format!("Message {}", i));
            }
            _ => panic!("Wrong message type"),
        }
    }
}

#[test]
fn test_session_statistics() {
    // Test session statistics tracking
    let config = HandshakeConfig::default();
    
    let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
    let mut responder = HandshakeResponder::new(config).unwrap();
    
    // Complete handshake
    let init = initiator.generate_init().unwrap();
    let response = responder.process_init(init).unwrap();
    initiator.process_response(response).unwrap();
    let complete = initiator.generate_complete().unwrap();
    responder.process_complete(complete).unwrap();
    
    let client_result = initiator.finalize().unwrap();
    let server_result = responder.finalize().unwrap();
    
    let mut client_session = Session::from_handshake(
        client_result,
        b"server".to_vec(),
    ).unwrap();
    
    let mut server_session = Session::from_handshake(
        server_result,
        b"client".to_vec(),
    ).unwrap();
    
    // Send messages and check statistics
    for _ in 0..5 {
        let msg = Message::text("Test");
        let encrypted = client_session.send(&msg).unwrap();
        server_session.receive(&encrypted).unwrap();
    }
    
    let client_info = client_session.info();
    assert_eq!(client_info.messages_sent, 5);
    
    let server_info = server_session.info();
    assert_eq!(server_info.messages_received, 5);
}
