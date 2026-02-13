// B4AE Prelude Module
// Convenient re-exports for common usage

pub use crate::client::{B4aeClient, B4aeConfig};
pub use crate::protocol::SecurityProfile;
pub use crate::crypto::{CryptoConfig, SecurityLevel};
pub use crate::error::{B4aeError, B4aeResult};
pub use crate::protocol::handshake::{HandshakeInit, HandshakeResponse, HandshakeComplete};
pub use crate::protocol::message::{Message, MessageContent, EncryptedMessage};

// Protocol constants
pub use crate::{VERSION, PROTOCOL_VERSION, PROTOCOL_NAME, PROTOCOL_FULL_NAME};

#[cfg(feature = "elara-transport")]
pub use crate::elara_node::B4aeElaraNode;

#[cfg(feature = "elara-transport")]
pub use crate::transport::elara::ElaraTransport;
