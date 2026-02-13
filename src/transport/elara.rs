//! ELARA Transport Adapter untuk B4AE
//!
//! Menggunakan ELARA Protocol UDP transport untuk pengiriman data B4AE.
//! Memberikan NAT traversal, packet delivery, dan graceful degradation.
//!
//! Mendukung chunking untuk payload > 1400 bytes (B4AE handshake, dll).

use crate::error::{B4aeError, B4aeResult};
use crate::transport::MAX_PACKET_SIZE;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CHUNK_HEADER_START: u8 = 0x01;
const CHUNK_HEADER_CONT: u8 = 0x02;
const CHUNK_HEADER_SINGLE: u8 = 0x00;

/// Chunk reassembly state
struct ChunkBuffer {
    total_len: usize,
    chunks: HashMap<u16, Vec<u8>>,
    created: Instant,
}

impl ChunkBuffer {
    fn new(total_len: usize) -> Self {
        Self {
            total_len,
            chunks: HashMap::new(),
            created: Instant::now(),
        }
    }
}

impl ChunkBuffer {
    fn add_chunk(&mut self, chunk_id: u16, data: Vec<u8>) -> bool {
        self.chunks.insert(chunk_id, data);
        let received: usize = self.chunks.values().map(|c| c.len()).sum();
        received >= self.total_len
    }

    fn assemble(mut self) -> B4aeResult<Vec<u8>> {
        let mut keys: Vec<_> = self.chunks.keys().copied().collect();
        keys.sort();
        let result: Vec<u8> = keys
            .into_iter()
            .flat_map(|k| self.chunks.remove(&k).unwrap_or_default())
            .collect();
        Ok(result)
    }
}

/// Transport B4AE via ELARA UDP.
#[derive(Clone)]
pub struct ElaraTransport {
    udp: Arc<elara_transport::UdpTransport>,
    /// Reassembly buffers for chunked receives (addr -> buffer)
    reassembly: Arc<Mutex<HashMap<String, ChunkBuffer>>>,
}

impl ElaraTransport {
    /// Bind ke alamat lokal dan buat transport UDP
    pub async fn bind(addr: impl AsRef<str>) -> B4aeResult<Self> {
        let socket_addr: SocketAddr = addr
            .as_ref()
            .parse()
            .map_err(|e| B4aeError::NetworkError(format!("Invalid bind address: {}", e)))?;

        let udp = elara_transport::UdpTransport::bind(socket_addr)
            .await
            .map_err(|e| B4aeError::NetworkError(e.to_string()))?;

        Ok(Self {
            udp: Arc::new(udp),
            reassembly: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Kirim data ke alamat tujuan. Mendukung chunking untuk data besar.
    pub async fn send_to(&self, dest: impl AsRef<str>, data: &[u8]) -> B4aeResult<()> {
        let addr: SocketAddr = dest
            .as_ref()
            .parse()
            .map_err(|e| B4aeError::NetworkError(format!("Invalid destination: {}", e)))?;

        if data.len() <= MAX_PACKET_SIZE - 7 {
            let mut packet = vec![CHUNK_HEADER_SINGLE];
            packet.extend_from_slice(data);
            self.udp
                .send_bytes_to(&packet, addr)
                .await
                .map_err(|e| B4aeError::NetworkError(e.to_string()))?;
        } else {
            let total_len = data.len() as u32;
            let max_chunk = MAX_PACKET_SIZE - 7;
            let mut offset = 0;
            let mut chunk_id: u16 = 0;

            while offset < data.len() {
                let end = (offset + max_chunk).min(data.len());
                let chunk_data = &data[offset..end];
                let mut packet = if chunk_id == 0 {
                    vec![
                        CHUNK_HEADER_START,
                        (total_len >> 24) as u8,
                        (total_len >> 16) as u8,
                        (total_len >> 8) as u8,
                        total_len as u8,
                        (chunk_id >> 8) as u8,
                        (chunk_id & 0xFF) as u8,
                    ]
                } else {
                    vec![
                        CHUNK_HEADER_CONT,
                        (chunk_id >> 8) as u8,
                        (chunk_id & 0xFF) as u8,
                    ]
                };
                packet.extend_from_slice(chunk_data);

                self.udp
                    .send_bytes_to(&packet, addr)
                    .await
                    .map_err(|e| B4aeError::NetworkError(e.to_string()))?;

                offset = end;
                chunk_id += 1;
            }
        }
        Ok(())
    }

    /// Terima data (blocking). Meng reassembly chunk secara otomatis.
    pub async fn recv_from(&self) -> B4aeResult<(Vec<u8>, String)> {
        const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);

        loop {
            let (data, addr) = self
                .udp
                .recv_bytes_from()
                .await
                .map_err(|e| B4aeError::NetworkError(e.to_string()))?;

            let addr_str = addr.to_string();

            if data.is_empty() {
                continue;
            }

            match data[0] {
                CHUNK_HEADER_SINGLE => {
                    return Ok((data[1..].to_vec(), addr_str));
                }
                CHUNK_HEADER_START => {
                    if data.len() < 7 {
                        continue;
                    }
                    let total_len =
                        u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
                    let chunk_id = u16::from_be_bytes([data[5], data[6]]);
                    let chunk_data = data[7..].to_vec();

                    let complete = {
                        let mut reassembly = self.reassembly.lock().map_err(|e| {
                            B4aeError::InternalError(format!("Mutex poisoned: {}", e))
                        })?;
                        let buffer = reassembly
                            .entry(addr_str.clone())
                            .or_insert_with(|| ChunkBuffer::new(total_len));
                        if buffer.created.elapsed() > REASSEMBLY_TIMEOUT {
                            *buffer = ChunkBuffer::new(total_len);
                        }
                        buffer.add_chunk(chunk_id, chunk_data)
                    };

                    if complete {
                        let buffer = {
                            let mut reassembly = self.reassembly.lock().map_err(|e| {
                                B4aeError::InternalError(format!("Mutex poisoned: {}", e))
                            })?;
                            reassembly.remove(&addr_str).unwrap_or_else(|| ChunkBuffer::new(0))
                        };
                        let result = buffer.assemble()?;
                        return Ok((result, addr_str));
                    }
                }
                CHUNK_HEADER_CONT => {
                    if data.len() < 3 {
                        continue;
                    }
                    let chunk_id = u16::from_be_bytes([data[1], data[2]]);
                    let chunk_data = data[3..].to_vec();

                    let complete = {
                        let mut reassembly = self.reassembly.lock().map_err(|e| {
                            B4aeError::InternalError(format!("Mutex poisoned: {}", e))
                        })?;
                        if let Some(buffer) = reassembly.get_mut(&addr_str) {
                            if buffer.created.elapsed() > REASSEMBLY_TIMEOUT {
                                reassembly.remove(&addr_str);
                                false
                            } else {
                                buffer.add_chunk(chunk_id, chunk_data)
                            }
                        } else {
                            false
                        }
                    };

                    if complete {
                        let buffer = {
                            let mut reassembly = self.reassembly.lock().map_err(|e| {
                                B4aeError::InternalError(format!("Mutex poisoned: {}", e))
                            })?;
                            reassembly.remove(&addr_str).unwrap_or_else(|| {
                                ChunkBuffer::new(0)
                            })
                        };
                        let result = buffer.assemble()?;
                        return Ok((result, addr_str));
                    }
                }
                _ => continue,
            }
        }
    }

    /// Alamat lokal
    pub fn local_addr(&self) -> String {
        self.udp.local_addr().to_string()
    }
}

/// Parse alamat peer ke SocketAddr
pub fn parse_peer_addr(peer_addr: &str) -> B4aeResult<SocketAddr> {
    SocketAddr::from_str(peer_addr)
        .map_err(|e| B4aeError::InvalidInput(format!("Invalid peer address '{}': {}", peer_addr, e)))
}
