//! B4AE Secure Relay — MVP stub
//!
//! Listens on UDP, logs received packets. Full B4AE relay would
//! parse protocol and forward encrypted messages.

use tokio::net::UdpSocket;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = "0.0.0.0:8473";
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    println!("B4AE Relay listening on udp://{}", bind_addr);

    let mut buf = [0u8; 65535];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let payload = &buf[..len];
        // MVP: log only. Full: parse B4AE, forward to destination
        println!("Relay received {} bytes from {} (stub)", len, addr);
        if payload.len() <= 64 {
            println!("  hex: {}", hex::encode(payload));
        }
        // Echo back for testing (remove in production)
        let _ = socket.send_to(payload, addr).await;
    }
}
