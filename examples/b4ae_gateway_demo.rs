//! B4AE Gateway Demo
//!
//! Minimal proxy: terima koneksi B4AE, forward plaintext ke TCP backend.
//!
//! Usage:
//!   cargo run --example b4ae_gateway_demo --features elara -- <listen_addr> <backend_host> [port]
//!
//! Example:
//!   Terminal 1: nc -l 8080  (backend simulan)
//!   Terminal 2: b4ae_gateway_demo 127.0.0.1:9000 127.0.0.1 8080
//!   Terminal 3: b4ae_chat_demo client 127.0.0.1:9000  (chat client → gateway → nc)

use b4ae::elara_node::B4aeElaraNode;
use b4ae::protocol::SecurityProfile;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("B4AE Gateway Demo - proxy B4AE → TCP backend");
        eprintln!("Usage: b4ae_gateway_demo <b4ae_listen> <backend_host> [port]");
        eprintln!("Example: b4ae_gateway_demo 127.0.0.1:9000 127.0.0.1 8080");
        std::process::exit(1);
    }

    let listen_addr = &args[2];
    let backend_host = &args[3];
    let backend_port = args.get(4).map(|s| s.as_str()).unwrap_or("8080");
    let backend_addr = format!("{}:{}", backend_host, backend_port);

    let mut node = B4aeElaraNode::new(listen_addr, SecurityProfile::Standard).await?;
    node.set_recv_timeout(Duration::from_secs(300));

    println!("[Gateway] B4AE listening on {}", node.local_addr());
    println!("[Gateway] Backend: {}\n", backend_addr);

    let peer = node.accept().await?;
    println!("[Gateway] B4AE client connected from {}", peer);

    let backend = TcpStream::connect(&backend_addr).await?;
    println!("[Gateway] Connected to backend\n");

    let (mut br, mut bw) = backend.into_split();
    let node = Arc::new(Mutex::new(node));
    let peer_send = peer.clone();

    let node_r = node.clone();
    let node_w = node.clone();

    let tcp_to_b4ae = async move {
        let mut buf = [0u8; 4096];
        loop {
            match br.read(&mut buf).await {
                Ok(0) => break,
                Ok(len) => {
                    let mut n = node_w.lock().await;
                    if n.send_message(&peer_send, &buf[..len]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    let b4ae_to_tcp = async move {
        loop {
            let (_, plaintext) = match node_r.lock().await.recv_message().await {
                Ok(p) => p,
                Err(_) => break,
            };
            if bw.write_all(&plaintext).await.is_err() {
                break;
            }
        }
    };

    tokio::select! {
        _ = tcp_to_b4ae => {}
        _ = b4ae_to_tcp => {}
    }
    println!("[Gateway] Session ended");
    Ok(())
}
