//! B4AE + ELARA Node
//!
//! Menggabungkan B4AE (quantum-resistant crypto) dengan ELARA (UDP transport).
//! Handshake dan messaging berjalan melalui ELARA UDP.

use crate::client::B4aeClient;
use crate::error::{B4aeError, B4aeResult};
use crate::protocol::message::EncryptedMessage;
use crate::protocol::SecurityProfile;
use crate::transport::elara::ElaraTransport;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Message types untuk wire protocol B4AE-over-ELARA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum B4aeWireMessage {
    /// Handshake Init
    HandshakeInit(Vec<u8>),
    /// Handshake Response
    HandshakeResponse(Vec<u8>),
    /// Handshake Complete
    HandshakeComplete(Vec<u8>),
    /// Encrypted message
    EncryptedMessage(Vec<u8>),
}

/// Node B4AE yang menggunakan ELARA untuk transport.
///
/// Kombinasi B4AE crypto + ELARA UDP.
pub struct B4aeElaraNode {
    client: B4aeClient,
    transport: ElaraTransport,
    /// Timeout untuk menunggu response
    recv_timeout: Duration,
}

impl B4aeElaraNode {
    /// Buat node baru
    pub async fn new(
        bind_addr: impl AsRef<str>,
        profile: SecurityProfile,
    ) -> B4aeResult<Self> {
        let client = B4aeClient::new(profile)?;
        let transport = ElaraTransport::bind(bind_addr).await?;

        Ok(Self {
            client,
            transport,
            recv_timeout: Duration::from_secs(30),
        })
    }

    /// Set timeout penerimaan
    pub fn set_recv_timeout(&mut self, timeout: Duration) {
        self.recv_timeout = timeout;
    }

    /// Alamat lokal
    pub fn local_addr(&self) -> String {
        self.transport.local_addr()
    }

    /// Inisiasi koneksi ke peer (sebagai initiator)
    pub async fn connect(&mut self, peer_addr: impl AsRef<str>) -> B4aeResult<()> {
        let peer = peer_addr.as_ref();
        let peer_id = peer.as_bytes().to_vec();

        let init = self.client.initiate_handshake(&peer_id)?;
        let init_bytes = bincode::serialize(&init)
            .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;

        let wire = B4aeWireMessage::HandshakeInit(init_bytes);
        let wire_bytes = bincode::serialize(&wire)
            .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;

        self.transport.send_to(peer, &wire_bytes).await?;

        let deadline = tokio::time::Instant::now() + self.recv_timeout;
        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(B4aeError::ProtocolError("Handshake timeout".to_string()));
            }

            let (data, from) = self.transport.recv_from().await?;
            if from != peer {
                continue;
            }

            let wire: B4aeWireMessage = bincode::deserialize(&data)
                .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;

            if let B4aeWireMessage::HandshakeResponse(resp_bytes) = wire {
                let response = bincode::deserialize(&resp_bytes)
                    .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;

                let complete = self.client.process_response(&peer_id, response)?;
                let complete_bytes = bincode::serialize(&complete)
                    .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;

                let wire_out = B4aeWireMessage::HandshakeComplete(complete_bytes);
                let wire_out_bytes = bincode::serialize(&wire_out)
                    .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;

                self.transport.send_to(peer, &wire_out_bytes).await?;
                self.client.finalize_initiator(&peer_id)?;
                return Ok(());
            }
        }
    }

    /// Terima koneksi dari peer mana pun (sebagai responder).
    /// Mengembalikan alamat peer yang terkoneksi.
    pub async fn accept(&mut self) -> B4aeResult<String> {
        let deadline = tokio::time::Instant::now() + self.recv_timeout;
        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(B4aeError::ProtocolError("Accept timeout".to_string()));
            }

            let (data, from) = self.transport.recv_from().await?;
            let peer = from.clone();
            let peer_id = peer.as_bytes().to_vec();

            let wire: B4aeWireMessage = bincode::deserialize(&data)
                .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;

            if let B4aeWireMessage::HandshakeInit(init_bytes) = wire {
                let init = bincode::deserialize(&init_bytes)
                    .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;

                let response = self.client.respond_to_handshake(&peer_id, init)?;
                let resp_bytes = bincode::serialize(&response)
                    .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;

                let wire_out = B4aeWireMessage::HandshakeResponse(resp_bytes);
                let wire_out_bytes = bincode::serialize(&wire_out)
                    .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;

                self.transport.send_to(&peer, &wire_out_bytes).await?;
            } else {
                continue;
            }

            let deadline2 = tokio::time::Instant::now() + self.recv_timeout;
            loop {
                if tokio::time::Instant::now() > deadline2 {
                    return Err(B4aeError::ProtocolError(
                        "Handshake complete timeout".to_string(),
                    ));
                }

                let (data2, from2) = self.transport.recv_from().await?;
                if from2 != peer {
                    continue;
                }

                let wire2: B4aeWireMessage = bincode::deserialize(&data2)
                    .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;

                if let B4aeWireMessage::HandshakeComplete(c) = wire2 {
                    let complete = bincode::deserialize(&c)
                        .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;
                    self.client.complete_handshake(&peer_id, complete)?;
                    return Ok(peer);
                }
            }
        }
    }

    /// Kirim pesan terenkripsi ke peer
    pub async fn send_message(
        &mut self,
        peer_addr: impl AsRef<str>,
        plaintext: &[u8],
    ) -> B4aeResult<()> {
        let peer = peer_addr.as_ref();
        let peer_id = peer.as_bytes().to_vec();

        let encrypted = self.client.encrypt_message(&peer_id, plaintext)?;
        let enc_bytes = bincode::serialize(&encrypted)
            .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;

        let wire = B4aeWireMessage::EncryptedMessage(enc_bytes);
        let wire_bytes = bincode::serialize(&wire)
            .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;

        self.transport.send_to(peer, &wire_bytes).await
    }

    /// Terima pesan (blocking). Abaikan non-EncryptedMessage.
    pub async fn recv_message(&mut self) -> B4aeResult<(String, Vec<u8>)> {
        loop {
            let (data, from) = self.transport.recv_from().await?;

            let wire: B4aeWireMessage = match bincode::deserialize(&data) {
                Ok(w) => w,
                Err(_) => continue,
            };

            if let B4aeWireMessage::EncryptedMessage(enc_bytes) = wire {
                let encrypted: EncryptedMessage = bincode::deserialize(&enc_bytes)
                    .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;

                let peer_id = from.as_bytes().to_vec();
                let plaintext = self.client.decrypt_message(&peer_id, &encrypted)?;

                return Ok((from, plaintext));
            }
        }
    }

    /// Cek apakah ada session dengan peer
    pub fn has_session(&self, peer_addr: impl AsRef<str>) -> bool {
        self.client.has_session(peer_addr.as_ref().as_bytes())
    }
}
