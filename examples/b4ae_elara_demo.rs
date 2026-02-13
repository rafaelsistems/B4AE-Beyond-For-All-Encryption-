//! Demo B4AE + ELARA
//!
//! Menjalankan dua node (Alice & Bob) yang berkomunikasi melalui UDP
//! menggunakan crypto quantum-resistant B4AE dan transport ELARA.
//!
//! Jalankan dengan: cargo run --example b4ae_elara_demo --features elara

use b4ae::elara_node::B4aeElaraNode;
use b4ae::protocol::SecurityProfile;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::main]
async fn main() -> Result<(), String> {
    tracing_subscriber::fmt::init();

    println!("=== B4AE + ELARA Demo ===\n");
    println!("Alice dan Bob akan melakukan handshake dan bertukar pesan via UDP.\n");

    let alice_addr = "127.0.0.1:0";
    let bob_addr = "127.0.0.1:0";

    let mut alice = B4aeElaraNode::new(alice_addr, SecurityProfile::Standard)
        .await
        .map_err(|e| format!("Alice init: {}", e))?;
    let mut bob = B4aeElaraNode::new(bob_addr, SecurityProfile::Standard)
        .await
        .map_err(|e| format!("Bob init: {}", e))?;

    alice.set_recv_timeout(Duration::from_secs(60));
    bob.set_recv_timeout(Duration::from_secs(60));

    let alice_listen = alice.local_addr();
    let bob_listen = bob.local_addr();

    println!("Alice listening on: {}", alice_listen);
    println!("Bob listening on: {}\n", bob_listen);

    let alice_node = tokio::spawn(async move {
        let mut alice = alice;
        let peer = bob_listen;
        println!("[Alice] Connecting to Bob at {}...", peer);
        timeout(
            Duration::from_secs(30),
            alice.connect(&peer),
        )
        .await
        .map_err(|e| format!("Connect timeout: {}", e))?
        .map_err(|e| format!("Connect: {}", e))?;
        println!("[Alice] Connected!");
        let msg = b"Hello from Alice via B4AE+ELARA!";
        alice.send_message(&peer, msg).await?;
        println!("[Alice] Sent: {}", String::from_utf8_lossy(msg));
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(alice)
    });

    let bob_node = tokio::spawn(async move {
        let mut bob = bob;
        println!("[Bob] Waiting for connection...");
        let peer = timeout(
            Duration::from_secs(30),
            bob.accept(),
        )
        .await
        .map_err(|e| format!("Accept timeout: {}", e))?
        .map_err(|e| format!("Accept: {}", e))?;
        println!("[Bob] Connected from {}!", peer);
        let (from, plaintext) = timeout(
            Duration::from_secs(10),
            bob.recv_message(),
        )
        .await
        .map_err(|e| format!("Recv timeout: {}", e))?
        .map_err(|e| format!("Recv: {}", e))?;
        println!("[Bob] Received from {}: {}", from, String::from_utf8_lossy(&plaintext));

        let reply = b"Hello back from Bob!";
        bob.send_message(&from, reply).await?;
        println!("[Bob] Sent reply");
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(bob)
    });

    let alice = alice_node
        .await
        .map_err(|e| format!("Alice task failed: {}", e))?
        .map_err(|e: Box<dyn std::error::Error + Send + Sync>| format!("Alice: {}", e))?;
    let _bob = bob_node
        .await
        .map_err(|e| format!("Bob task failed: {}", e))?
        .map_err(|e: Box<dyn std::error::Error + Send + Sync>| format!("Bob: {}", e))?;

    let mut alice = alice;
    let (from, plaintext) = timeout(
        Duration::from_secs(10),
        alice.recv_message(),
    )
    .await
    .map_err(|e| format!("Timeout: {}", e))?
    .map_err(|e| format!("Recv: {}", e))?;
    println!("\n[Alice] Received from {}: {}", from, String::from_utf8_lossy(&plaintext));

    println!("\n=== Demo Complete ===");
    println!("B4AE (quantum-resistant) + ELARA (UDP transport) bekerja!");
    Ok(())
}
