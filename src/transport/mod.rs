//! B4AE Transport Layer
//!
//! Abstraksi untuk pengiriman data terenkripsi B4AE.
//! Mendukung integrasi dengan ELARA Protocol untuk transport UDP/NAT traversal.

/// Batas ukuran payload per paket (mengikuti ELARA MAX_FRAME_SIZE).
/// Paket lebih besar dari ini perlu di-chunk.
pub const MAX_PACKET_SIZE: usize = 1400;

#[cfg(feature = "elara")]
pub mod elara;

#[cfg(all(feature = "elara", feature = "proxy"))]
pub mod proxy;
