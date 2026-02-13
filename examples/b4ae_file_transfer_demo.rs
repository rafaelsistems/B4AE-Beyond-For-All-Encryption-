//! B4AE File Transfer Demo
//!
//! Transfer file aman via B4AE + ELARA.
//!
//! Usage:
//!   Sender: cargo run --example b4ae_file_transfer_demo --features elara -- send <file> <receiver_addr> [bind_port]
//!   Receiver: cargo run --example b4ae_file_transfer_demo --features elara -- recv <output_file> [bind_port]
//!
//! Protocol: Sender listens on bind_port (or 0 for auto), prints "LISTEN addr". Receiver connects, sends filename+size, then chunks.
//! Receiver runs first, prints addr. Sender connects to that addr.

use b4ae::elara_node::B4aeElaraNode;
use b4ae::protocol::SecurityProfile;
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// Wire protocol for file transfer (plaintext over B4AE session)
#[derive(serde::Serialize, serde::Deserialize)]
enum FileTransferMsg {
    /// Sender → Receiver: filename, total bytes
    Header { filename: String, size: u64 },
    /// Sender → Receiver: chunk (index, data)
    Chunk { index: u32, data: Vec<u8> },
    /// Receiver → Sender: ack or ready
    Ack,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("B4AE File Transfer");
        eprintln!("  send: b4ae_file_transfer_demo send <file> <receiver_addr> [port]");
        eprintln!("  recv: b4ae_file_transfer_demo recv <output_file> [port]");
        std::process::exit(1);
    }

    let mode = &args[1];
    match mode.as_str() {
        "send" => {
            let path = args.get(2).ok_or("send requires <file>")?;
            let receiver = args.get(3).ok_or("send requires <receiver_addr>")?;
            let port = args.get(4).map(|s| s.as_str()).unwrap_or("0");
            run_sender(path, receiver, port).await
        }
        "recv" => {
            let path = args.get(2).ok_or("recv requires <output_file>")?;
            let port = args.get(3).map(|s| s.as_str()).unwrap_or("9001");
            run_receiver(path, port).await
        }
        _ => {
            eprintln!("Use 'send' or 'recv'");
            std::process::exit(1);
        }
    }
}

async fn run_receiver(
    output_path: &str,
    port: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let bind = format!("127.0.0.1:{}", port);
    let mut node = B4aeElaraNode::new(&bind, SecurityProfile::Standard).await?;
    node.set_recv_timeout(Duration::from_secs(60));

    println!("[Receiver] Listening on {}", node.local_addr());
    println!("[Receiver] Waiting for sender...");

    let peer = node.accept().await?;
    println!("[Receiver] Sender connected from {}\n", peer);

    // Recv header
    let (_, header_bytes) = node.recv_message().await?;
    let header: FileTransferMsg = bincode::deserialize(&header_bytes)?;
    let (filename, total_size) = match header {
        FileTransferMsg::Header { filename, size } => (filename, size),
        _ => return Err("expected header".into()),
    };

    println!("[Receiver] Receiving: {} ({} bytes)", filename, total_size);

    let out_path = if output_path == "-" {
        Path::new(&filename).file_name().unwrap().to_string_lossy().into_owned()
    } else {
        output_path.to_string()
    };

    let mut file = tokio::fs::File::create(&out_path).await?;
    let mut received: u64 = 0;
    let mut chunks: std::collections::HashMap<u32, Vec<u8>> = std::collections::HashMap::new();
    let mut next_index = 0u32;

    while received < total_size {
        let (_, chunk_bytes) = node.recv_message().await?;
        let chunk: FileTransferMsg = bincode::deserialize(&chunk_bytes)?;
        if let FileTransferMsg::Chunk { index, data } = chunk {
            chunks.insert(index, data);
            while let Some(data) = chunks.remove(&next_index) {
                received += data.len() as u64;
                tokio::io::AsyncWriteExt::write_all(&mut file, &data).await?;
                next_index += 1;
            }
        }
    }

    println!("[Receiver] Done. Saved to {}", out_path);
    Ok(())
}

async fn run_sender(
    file_path: &str,
    receiver_addr: &str,
    port: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let bind = format!("127.0.0.1:{}", port);
    let mut node = B4aeElaraNode::new(&bind, SecurityProfile::Standard).await?;
    node.set_recv_timeout(Duration::from_secs(60));

    let meta = tokio::fs::metadata(file_path).await?;
    let size = meta.len();
    let filename = Path::new(file_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();

    println!("[Sender] Connecting to {}...", receiver_addr);
    node.connect(receiver_addr).await?;
    println!("[Sender] Connected. Sending {} ({} bytes)\n", filename, size);

    let header = FileTransferMsg::Header {
        filename: filename.clone(),
        size,
    };
    let header_bytes = bincode::serialize(&header)?;
    node.send_message(receiver_addr, &header_bytes).await?;

    const CHUNK_SIZE: usize = 8 * 1024;
    let mut f = tokio::fs::File::open(file_path).await?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut index = 0u32;

    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let chunk = FileTransferMsg::Chunk {
            index,
            data: buf[..n].to_vec(),
        };
        let chunk_bytes = bincode::serialize(&chunk)?;
        node.send_message(receiver_addr, &chunk_bytes).await?;
        index += 1;
    }

    println!("[Sender] Done. {} chunks sent.", index);
    Ok(())
}
