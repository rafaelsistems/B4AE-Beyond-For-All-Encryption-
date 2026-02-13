//! B4AE Chat Demo
//!
//! Terminal chat via B4AE + ELARA. Dua mode: server (listen) atau client (connect).
//!
//! Usage:
//!   Server: cargo run --example b4ae_chat_demo --features elara -- server [port]
//!   Client: cargo run --example b4ae_chat_demo --features elara -- client <server_addr>
//!
//! Example:
//!   Terminal 1: cargo run --example b4ae_chat_demo --features elara -- server 9000
//!   Terminal 2: cargo run --example b4ae_chat_demo --features elara -- client 127.0.0.1:9000

use b4ae::elara_node::B4aeElaraNode;
use b4ae::protocol::SecurityProfile;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::select;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage:");
        eprintln!("  server: b4ae_chat_demo server [port]");
        eprintln!("  client: b4ae_chat_demo client <server_addr>");
        eprintln!("\nExample:");
        eprintln!("  Terminal 1: b4ae_chat_demo server 9000");
        eprintln!("  Terminal 2: b4ae_chat_demo client 127.0.0.1:9000");
        std::process::exit(1);
    }

    let mode = &args[1];
    match mode.as_str() {
        "server" => run_server(args.get(2).map(|s| s.as_str()).unwrap_or("9000")).await,
        "client" => {
            let addr = args.get(2).ok_or("client requires <server_addr>")?;
            run_client(addr).await
        }
        _ => {
            eprintln!("Unknown mode: {}. Use 'server' or 'client'.", mode);
            std::process::exit(1);
        }
    }
}

async fn run_server(port: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bind = format!("127.0.0.1:{}", port);
    let mut node = B4aeElaraNode::new(&bind, SecurityProfile::Standard).await?;
    node.set_recv_timeout(Duration::from_secs(3600));

    println!("[Server] B4AE Chat - listening on {}", node.local_addr());
    println!("[Server] Waiting for client...\n");

    let peer = node.accept().await?;
    println!("[Server] Client connected from {}\n", peer);
    println!("Type messages and press Enter. Ctrl+C to quit.\n");

    run_chat_loop(&mut node, &peer).await
}

async fn run_client(server_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut node = B4aeElaraNode::new("127.0.0.1:0", SecurityProfile::Standard).await?;
    node.set_recv_timeout(Duration::from_secs(3600));

    println!("[Client] B4AE Chat - connecting to {}...", server_addr);
    node.connect(server_addr).await?;
    println!("[Client] Connected!\n");
    println!("Type messages and press Enter. Ctrl+C to quit.\n");

    run_chat_loop(&mut node, server_addr).await
}

async fn run_chat_loop(
    node: &mut B4aeElaraNode,
    peer: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    loop {
        select! {
            line = lines.next_line() => {
                match line? {
                    Some(text) if !text.trim().is_empty() => {
                        node.send_message(peer, text.as_bytes()).await?;
                        println!("[You] {}", text);
                    }
                    _ => {}
                }
            }
            msg = node.recv_message() => {
                match msg {
                    Ok((from, data)) => {
                        if let Ok(s) = String::from_utf8(data) {
                            println!("[{}] {}", from, s);
                        }
                    }
                    Err(e) => eprintln!("Recv error: {}", e),
                }
            }
        }
    }
}
