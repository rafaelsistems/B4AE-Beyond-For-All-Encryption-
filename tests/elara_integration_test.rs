//! ELARA Integration Tests
//!
//! Two-node in-process tests for B4AE + ELARA.
//! Requires `--features elara`.
//! Ignored in CI (UDP/ELARA may hang on GitHub runners); run locally with:
//! `cargo test --test elara_integration_test --all-features -- --ignored`

#![cfg(feature = "elara")]

use b4ae::elara_node::B4aeElaraNode;
use b4ae::protocol::SecurityProfile;

#[tokio::test]
#[ignore = "ELARA UDP tests hang in CI; run locally with --ignored"]
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
#[ignore = "ELARA UDP tests hang in CI; run locally with --ignored"]
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

#[tokio::test]
#[ignore = "ELARA UDP tests hang in CI; run locally with --ignored"]
async fn test_concurrent_two_connections() {
    // Two initiators connect to one responder (sequential accepts)
    let mut alice = B4aeElaraNode::new("127.0.0.1:0", SecurityProfile::Standard)
        .await
        .unwrap();
    let mut bob =
        B4aeElaraNode::new("127.0.0.1:0", SecurityProfile::Standard)
            .await
            .unwrap();
    let mut carol =
        B4aeElaraNode::new("127.0.0.1:0", SecurityProfile::Standard)
            .await
            .unwrap();

    let bob_addr = bob.local_addr();

    // Bob accepts two connections (alice, then carol)
    let bob_handle = tokio::spawn(async move {
        let _p1 = bob.accept().await.unwrap();
        let (_, m1) = bob.recv_message().await.unwrap();
        let _p2 = bob.accept().await.unwrap();
        let (_, m2) = bob.recv_message().await.unwrap();
        (m1, m2)
    });

    alice.connect(&bob_addr).await.unwrap();
    alice.send_message(&bob_addr, b"from alice").await.unwrap();

    carol.connect(&bob_addr).await.unwrap();
    carol.send_message(&bob_addr, b"from carol").await.unwrap();

    let (m1, m2) = bob_handle.await.unwrap();
    assert!(m1 == b"from alice" || m1 == b"from carol");
    assert!(m2 == b"from alice" || m2 == b"from carol");
    assert_ne!(m1, m2);
}

#[tokio::test]
#[ignore = "ELARA UDP tests hang in CI; run locally with --ignored"]
async fn test_bidirectional_messages() {
    let mut alice = B4aeElaraNode::new("127.0.0.1:0", SecurityProfile::Standard)
        .await
        .unwrap();
    let mut bob =
        B4aeElaraNode::new("127.0.0.1:0", SecurityProfile::Standard)
            .await
            .unwrap();
    let bob_addr = bob.local_addr();
    let alice_addr = alice.local_addr();

    let recv_handle = tokio::spawn(async move {
        let _peer = bob.accept().await.unwrap();
        bob.send_message(&alice_addr, b"Hi Alice").await.unwrap();
        let (_, msg) = bob.recv_message().await.unwrap();
        msg
    });

    alice.connect(&bob_addr).await.unwrap();
    let (_, from_bob) = alice.recv_message().await.unwrap();
    assert_eq!(from_bob, b"Hi Alice");
    alice.send_message(&bob_addr, b"Hi Bob").await.unwrap();

    let bob_received = recv_handle.await.unwrap();
    assert_eq!(bob_received, b"Hi Bob");
}
