//! B4AE + ELARA Node
//!
//! Menggabungkan B4AE (quantum-resistant crypto) dengan ELARA (UDP transport).
//! Handshake dan messaging berjalan melalui ELARA UDP.

use crate::client::{B4aeClient, B4aeConfig};
use crate::crypto::onion;
use crate::error::{B4aeError, B4aeResult};
use crate::protocol::message::EncryptedMessage;
use crate::protocol::SecurityProfile;
use crate::transport::elara::ElaraTransport;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[cfg(feature = "proxy")]
use crate::transport::proxy::ProxyElaraTransport;

/// Message types untuk wire protocol B4AE-over-ELARA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum B4aeWireMessage {
    /// Handshake Init
    HandshakeInit(Vec<u8>),
    /// Handshake Response
    HandshakeResponse(Vec<u8>),
    /// Handshake Complete
    HandshakeComplete(Vec<u8>),
    /// Encrypted message (plain)
    EncryptedMessage(Vec<u8>),
    /// Onion-wrapped encrypted message (when ProtectionLevel::Maximum)
    OnionWrapped(Vec<u8>),
}

/// Transport backend (direct UDP or via SOCKS5 proxy)
enum TransportBackend {
    Direct(ElaraTransport),
    #[cfg(feature = "proxy")]
    Proxy(ProxyElaraTransport),
}

/// Node B4AE yang menggunakan ELARA untuk transport.
///
/// Kombinasi B4AE crypto + ELARA UDP.
pub struct B4aeElaraNode {
    client: B4aeClient,
    transport: TransportBackend,
    /// Timeout untuk menunggu response
    recv_timeout: Duration,
}

impl B4aeElaraNode {
    /// Buat node baru
    pub async fn new(
        bind_addr: impl AsRef<str>,
        profile: SecurityProfile,
    ) -> B4aeResult<Self> {
        let config = B4aeConfig::from_profile(profile);
        Self::new_with_config(bind_addr, config).await
    }

    /// Buat node dengan config (mendukung proxy via anonymization.proxy_url)
    pub async fn new_with_config(
        bind_addr: impl AsRef<str>,
        config: B4aeConfig,
    ) -> B4aeResult<Self> {
        let client = B4aeClient::with_config(config.clone())?;
        let transport = {
            #[cfg(feature = "proxy")]
            {
                if let Some(ref proxy_url) = config.protocol_config.anonymization.proxy_url {
                    TransportBackend::Proxy(
                        ProxyElaraTransport::bind(bind_addr.as_ref(), proxy_url)?,
                    )
                } else {
                    TransportBackend::Direct(ElaraTransport::bind(bind_addr).await?)
                }
            }
            #[cfg(not(feature = "proxy"))]
            {
                TransportBackend::Direct(ElaraTransport::bind(bind_addr).await?)
            }
        };

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
        match &self.transport {
            TransportBackend::Direct(t) => t.local_addr(),
            #[cfg(feature = "proxy")]
            TransportBackend::Proxy(t) => t.local_addr(),
        }
    }

    async fn transport_send_to(&self, dest: &str, data: &[u8]) -> B4aeResult<()> {
        match &self.transport {
            TransportBackend::Direct(t) => t.send_to(dest, data).await,
            #[cfg(feature = "proxy")]
            TransportBackend::Proxy(t) => t.send_to(dest, data).await,
        }
    }

    async fn transport_recv_from(&self) -> B4aeResult<(Vec<u8>, String)> {
        match &self.transport {
            TransportBackend::Direct(t) => t.recv_from().await,
            #[cfg(feature = "proxy")]
            TransportBackend::Proxy(t) => t.recv_from().await,
        }
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

        self.transport_send_to(peer, &wire_bytes).await?;

        let deadline = tokio::time::Instant::now() + self.recv_timeout;
        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(B4aeError::ProtocolError("Handshake timeout".to_string()));
            }

            let (data, from) = self.transport_recv_from().await?;
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

                self.transport_send_to(peer, &wire_out_bytes).await?;
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

            let (data, from) = self.transport_recv_from().await?;
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

                self.transport_send_to(&peer, &wire_out_bytes).await?;
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

                let (data2, from2) = self.transport_recv_from().await?;
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

        let encrypted_list = self.client.encrypt_message(&peer_id, plaintext)?;
        let level = self.client.get_protection_level();
        let use_onion = level.onion_routing_enabled();

        for encrypted in encrypted_list {
            let enc_bytes = bincode::serialize(&encrypted)
                .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;

            let wire = if use_onion {
                if let Some(layer_key) = self.client.onion_layer_key(&peer_id)? {
                    let path = [(Vec::new(), layer_key)]; // empty next_hop = final destination
                    let layer = onion::onion_encrypt(&path, &enc_bytes)
                        .map_err(|e| B4aeError::CryptoError(e.to_string()))?;
                    B4aeWireMessage::OnionWrapped(layer.as_bytes().to_vec())
                } else {
                    B4aeWireMessage::EncryptedMessage(enc_bytes)
                }
            } else {
                B4aeWireMessage::EncryptedMessage(enc_bytes)
            };

            let wire_bytes = bincode::serialize(&wire)
                .map_err(|e| B4aeError::ProtocolError(e.to_string()))?;

            self.transport_send_to(peer, &wire_bytes).await?;
        }
        Ok(())
    }

    /// Terima pesan (blocking). Abaikan non-EncryptedMessage.
    pub async fn recv_message(&mut self) -> B4aeResult<(String, Vec<u8>)> {
        loop {
            let (data, from) = self.transport_recv_from().await?;

            let wire: B4aeWireMessage = match bincode::deserialize(&data) {
                Ok(w) => w,
                Err(_) => continue,
            };

            let enc_bytes = match &wire {
                B4aeWireMessage::EncryptedMessage(b) => b.clone(),
                B4aeWireMessage::OnionWrapped(onion_bytes) => {
                    let peer_id = from.as_bytes().to_vec();
                    let layer_key = match self.client.onion_layer_key(&peer_id)? {
                        Some(k) => k,
                        None => continue, // no session or onion disabled
                    };
                    let (_, payload) = onion::onion_decrypt_layer(&layer_key, onion_bytes)
                        .map_err(|e| B4aeError::CryptoError(e.to_string()))?;
                    payload
                }
                _ => continue,
            };

            let encrypted: EncryptedMessage = match bincode::deserialize(&enc_bytes) {
                Ok(e) => e,
                Err(_) => continue,
            };

            let peer_id = from.as_bytes().to_vec();
            let plaintext = self.client.decrypt_message(&peer_id, &encrypted)?;

            // Skip dummy traffic (empty plaintext)
            if !plaintext.is_empty() {
                return Ok((from, plaintext));
            }
        }
    }

    /// Cek apakah ada session dengan peer
    pub fn has_session(&self, peer_addr: impl AsRef<str>) -> bool {
        self.client.has_session(peer_addr.as_ref().as_bytes())
    }
}
