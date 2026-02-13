//! ELARA Integration Tests
//!
//! Two-node in-process tests for B4AE + ELARA.
//! Requires `--features elara`.

#![cfg(feature = "elara")]

use b4ae::elara_node::B4aeElaraNode;
use b4ae::protocol::SecurityProfile;

#[tokio::test]
async fn test_two_node_roundtrip() {
    let mut alice = B4aeElaraNode::new("127.0.0.1:0", SecurityProfile::Standard)
        .await
        .unwrap();
    let mut bob =
        B4aeElaraNode::new("127.0.0.1:0", SecurityProfile::Standard)
            .await
            .unwrap();
    let bob_addr = bob.local_addr();

    // Bob: accept connection & receive message in background
    let recv_handle = tokio::spawn(async move {
        let peer = bob.accept().await.unwrap();
        let (from, msg) = bob.recv_message().await.unwrap();
        (peer, from, msg)
    });

    // Alice: connect and send
    alice.connect(&bob_addr).await.unwrap();
    alice
        .send_message(&bob_addr, b"Hello from Alice")
        .await
        .unwrap();

    // Verify Bob received correctly (peer/from = Alice's addr, Bob sees sender)
    let (peer, from, msg) = recv_handle.await.unwrap();
    assert_eq!(peer, from, "peer from accept should match sender of message");
    assert!(from.starts_with("127.0.0.1:"), "sender should be localhost");
    assert_eq!(msg, b"Hello from Alice");
}

#[tokio::test]
async fn test_two_node_large_payload() {
    // Test chunking: payload > 1400 bytes
    let mut alice = B4aeElaraNode::new("127.0.0.1:0", SecurityProfile::Standard)
        .await
        .unwrap();
    let mut bob =
        B4aeElaraNode::new("127.0.0.1:0", SecurityProfile::Standard)
            .await
            .unwrap();
    let bob_addr = bob.local_addr();

    let recv_handle = tokio::spawn(async move {
        let _peer = bob.accept().await.unwrap();
        let (_from, msg) = bob.recv_message().await.unwrap();
        msg
    });

    alice.connect(&bob_addr).await.unwrap();
    let payload: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    alice.send_message(&bob_addr, &payload).await.unwrap();

    let received = recv_handle.await.unwrap();
    assert_eq!(received, payload);
}
