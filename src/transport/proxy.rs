//! SOCKS5 proxy transport for B4AE.
//!
//! Routes UDP traffic through SOCKS5 proxy (e.g. Tor at socks5://127.0.0.1:9050).

use crate::error::{B4aeError, B4aeResult};
use crate::transport::MAX_PACKET_SIZE;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CHUNK_HEADER_START: u8 = 0x01;
const CHUNK_HEADER_CONT: u8 = 0x02;
const CHUNK_HEADER_SINGLE: u8 = 0x00;

/// Maximum reassembly size (DoS mitigation; ~90KB)
const MAX_REASSEMBLY_SIZE: usize = MAX_PACKET_SIZE * 64;

/// Chunk reassembly (same as ElaraTransport)
struct ChunkBuffer {
    total_len: usize,
    chunks: HashMap<u16, Vec<u8>>,
    created: Instant,
}

impl ChunkBuffer {
    /// Max payload per chunk (7-byte START or 3-byte CONT header)
    const MAX_CHUNK_PAYLOAD: usize = MAX_PACKET_SIZE - 3;

    fn new(total_len: usize) -> Self {
        Self {
            total_len,
            chunks: HashMap::new(),
            created: Instant::now(),
        }
    }

    fn add_chunk(&mut self, chunk_id: u16, data: Vec<u8>) -> B4aeResult<bool> {
        let max_chunk_id = ((self.total_len + (MAX_PACKET_SIZE - 7) - 1) / (MAX_PACKET_SIZE - 7))
            .min(u16::MAX as usize) as u16;
        if chunk_id > max_chunk_id {
            return Err(B4aeError::InvalidInput(format!(
                "chunk_id {} exceeds max_chunk_id {}",
                chunk_id, max_chunk_id
            )));
        }
        if data.len() > Self::MAX_CHUNK_PAYLOAD {
            return Err(B4aeError::InvalidInput(format!(
                "Chunk payload too large: {} > {}",
                data.len(),
                Self::MAX_CHUNK_PAYLOAD
            )));
        }
        let current_total: usize = self.chunks.values().map(|c| c.len()).sum();
        if current_total + data.len() > MAX_REASSEMBLY_SIZE {
            return Err(B4aeError::InvalidInput(
                "Reassembly buffer would exceed limit".to_string(),
            ));
        }
        self.chunks.insert(chunk_id, data);
        let received: usize = self.chunks.values().map(|c| c.len()).sum();
        Ok(received >= self.total_len)
    }

    fn assemble(mut self) -> B4aeResult<Vec<u8>> {
        let mut keys: Vec<_> = self.chunks.keys().copied().collect();
        keys.sort();
        let result: Vec<u8> = keys
            .into_iter()
            .flat_map(|k| self.chunks.remove(&k).unwrap_or_default())
            .collect();
        if result.len() != self.total_len {
            return Err(B4aeError::InvalidInput(format!(
                "Assembled length {} != expected {}",
                result.len(),
                self.total_len
            )));
        }
        Ok(result)
    }
}

/// Parse proxy URL to (host, port). Supports socks5://host:port
fn parse_proxy_url(url: &str) -> B4aeResult<(String, u16)> {
    let url = url.trim();
    let s = url.strip_prefix("socks5://").unwrap_or(url);
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| B4aeError::InvalidInput(format!("Invalid proxy URL: {}", url)))?;
    let port: u16 = port
        .parse()
        .map_err(|_| B4aeError::InvalidInput(format!("Invalid proxy port: {}", url)))?;
    Ok((host.to_string(), port))
}

/// Transport B4AE via SOCKS5 proxy (UDP ASSOCIATE).
#[cfg(feature = "proxy")]
#[derive(Clone)]
pub struct ProxyElaraTransport {
    datagram: Arc<Mutex<socks::Socks5Datagram>>,
    reassembly: Arc<Mutex<HashMap<String, ChunkBuffer>>>,
}

#[cfg(feature = "proxy")]
impl ProxyElaraTransport {
    /// Bind and route UDP through SOCKS5 proxy.
    pub fn bind(addr: impl AsRef<str>, proxy_url: &str) -> B4aeResult<Self> {
        let (proxy_host, proxy_port) = parse_proxy_url(proxy_url)?;
        let proxy_addr = format!("{}:{}", proxy_host, proxy_port);

        let bind_addr: SocketAddr = addr
            .as_ref()
            .parse()
            .map_err(|e| B4aeError::NetworkError(format!("Invalid bind address: {}", e)))?;

        let datagram = socks::Socks5Datagram::bind(&proxy_addr, bind_addr)
            .map_err(|e| B4aeError::NetworkError(format!("SOCKS5 proxy bind failed: {}", e)))?;

        Ok(Self {
            datagram: Arc::new(Mutex::new(datagram)),
            reassembly: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Send data to destination via proxy
    pub async fn send_to(&self, dest: impl AsRef<str>, data: &[u8]) -> B4aeResult<()> {
        let addr: SocketAddr = dest
            .as_ref()
            .parse()
            .map_err(|e| B4aeError::NetworkError(format!("Invalid destination: {}", e)))?;

        let datagram = self.datagram.lock().map_err(|e| {
            B4aeError::InternalError(format!("Mutex poisoned: {}", e))
        })?;

        if data.len() <= MAX_PACKET_SIZE - 7 {
            let mut packet = vec![CHUNK_HEADER_SINGLE];
            packet.extend_from_slice(data);
            let _ = datagram.send_to(&packet, socks::TargetAddr::Ip(addr))
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

                let _ = datagram.send_to(&packet, socks::TargetAddr::Ip(addr))
                    .map_err(|e| B4aeError::NetworkError(e.to_string()))?;

                offset = end;
                chunk_id += 1;
            }
        }
        Ok(())
    }

    /// Receive data (blocking on sync socket, wrapped for async)
    pub async fn recv_from(&self) -> B4aeResult<(Vec<u8>, String)> {
        const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);
        let mut buf = vec![0u8; MAX_PACKET_SIZE * 2];

        loop {
            let (len, src) = {
                let dg = self.datagram.lock().map_err(|e| {
                    B4aeError::InternalError(format!("Mutex poisoned: {}", e))
                })?;
                let (n, target) = dg.recv_from(&mut buf)
                    .map_err(|e| B4aeError::NetworkError(e.to_string()))?;
                let addr_str = match target {
                    socks::TargetAddr::Ip(ip) => ip.to_string(),
                    socks::TargetAddr::Domain(dom, port) => format!("{}:{}", dom, port),
                };
                (n, addr_str)
            };

            let data = buf[..len].to_vec();
            if data.is_empty() {
                continue;
            }

            match data.get(0).copied() {
                Some(CHUNK_HEADER_SINGLE) => return Ok((data[1..].to_vec(), src)),
                Some(CHUNK_HEADER_START) => {
                    if data.len() < 7 {
                        continue;
                    }
                    let total_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
                    if total_len == 0 || total_len > MAX_REASSEMBLY_SIZE {
                        continue; // Reject malicious/invalid total_len
                    }
                    let chunk_id = u16::from_be_bytes([data[5], data[6]]);
                    let chunk_data = data[7..].to_vec();
                    let max_chunk_id = ((total_len + (MAX_PACKET_SIZE - 7) - 1) / (MAX_PACKET_SIZE - 7))
                        .min(u16::MAX as usize) as u16;
                    if chunk_id > max_chunk_id {
                        continue; // Reject out-of-range chunk_id
                    }

                    let complete = {
                        let mut reassembly = self.reassembly.lock().map_err(|e| {
                            B4aeError::InternalError(format!("Mutex poisoned: {}", e))
                        })?;
                        let buffer = reassembly
                            .entry(src.clone())
                            .or_insert_with(|| ChunkBuffer::new(total_len));
                        if buffer.created.elapsed() > REASSEMBLY_TIMEOUT {
                            *buffer = ChunkBuffer::new(total_len);
                        }
                        buffer.add_chunk(chunk_id, chunk_data).unwrap_or(false)
                    };

                    if complete {
                        let buffer = {
                            let mut reassembly = self.reassembly.lock().map_err(|e| {
                                B4aeError::InternalError(format!("Mutex poisoned: {}", e))
                            })?;
                            match reassembly.remove(&src) {
                                Some(b) => b,
                                None => continue, // Buffer gone (e.g. timeout); wait for next packet
                            }
                        };
                        let result = buffer.assemble()?;
                        return Ok((result, src));
                    }
                }
                Some(CHUNK_HEADER_CONT) => {
                    if data.len() < 3 {
                        continue;
                    }
                    let chunk_id = u16::from_be_bytes([data[1], data[2]]);
                    let chunk_data = data[3..].to_vec();

                    let complete = {
                        let mut reassembly = self.reassembly.lock().map_err(|e| {
                            B4aeError::InternalError(format!("Mutex poisoned: {}", e))
                        })?;
                        if let Some(buffer) = reassembly.get_mut(&src) {
                            if buffer.created.elapsed() > REASSEMBLY_TIMEOUT {
                                reassembly.remove(&src);
                                false
                            } else {
                                buffer.add_chunk(chunk_id, chunk_data).unwrap_or(false)
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
                            match reassembly.remove(&src) {
                                Some(b) => b,
                                None => continue, // Buffer gone (e.g. timeout); wait for next packet
                            }
                        };
                        let result = buffer.assemble()?;
                        return Ok((result, src));
                    }
                }
                _ => continue,
            }
        }
    }

    /// Returns the local socket address (e.g. "127.0.0.1:0" or "0.0.0.0:0" on error).
    pub fn local_addr(&self) -> String {
        self.datagram
            .lock()
            .map_err(|e| B4aeError::InternalError(format!("Mutex poisoned: {}", e)))
            .and_then(|dg| {
                dg.get_ref()
                    .local_addr()
                    .map_err(|e| B4aeError::NetworkError(e.to_string()))
            })
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "0.0.0.0:0".to_string())
    }
}
