//! Audit logging untuk production compliance
//!
//! Events penting (handshake, key rotation, auth failure) dicatat
//! untuk audit trail tanpa menyimpan data sensitif.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::time::SystemTime;

/// Hash data for audit (privacy-preserving, no raw IDs in logs)
pub fn hash_for_audit(data: &[u8]) -> String {
    hex::encode(&Sha3_256::digest(data)[..8])
}

/// Audit event types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuditEvent {
    /// Handshake initiated
    HandshakeInitiated {
        /// Hash of peer ID (privacy-preserving, no raw ID stored)
        peer_id_hash: String,
    },
    /// Handshake completed
    HandshakeCompleted {
        /// Hash of peer ID
        peer_id_hash: String,
    },
    /// Handshake failed
    HandshakeFailed {
        /// Hash of peer ID
        peer_id_hash: String,
        /// Failure reason (non-sensitive)
        reason: String,
    },
    /// Key rotation triggered
    KeyRotation {
        /// Hash of session ID
        session_id_hash: String,
    },
    /// Authentication failed
    AuthFailed {
        /// Failure reason
        reason: String,
    },
    /// Session created
    SessionCreated {
        /// Hash of session ID
        session_id_hash: String,
    },
    /// Session closed
    SessionClosed {
        /// Hash of session ID
        session_id_hash: String,
    },
}

/// Single audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp (Unix ms)
    pub timestamp_ms: u64,
    /// Event type
    pub event: AuditEvent,
    /// Optional context (non-sensitive)
    pub context: Option<String>,
}

impl AuditEntry {
    /// Create new audit entry
    pub fn new(event: AuditEvent, context: Option<String>) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            timestamp_ms,
            event,
            context,
        }
    }
}

/// Audit logger backend (trait untuk pluggable sink)
pub trait AuditSink: Send + Sync {
    /// Log audit entry
    fn log(&self, entry: AuditEntry);
}

/// In-memory audit sink (untuk testing)
#[derive(Debug, Default)]
pub struct MemoryAuditSink {
    entries: std::sync::Mutex<Vec<AuditEntry>>,
}

impl MemoryAuditSink {
    /// Create new in-memory sink
    pub fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Get all logged entries
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Clear entries (testing only)
    pub fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

impl AuditSink for MemoryAuditSink {
    fn log(&self, entry: AuditEntry) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(entry);
    }
}

/// No-op sink (default when audit disabled)
#[derive(Debug, Default)]
pub struct NoOpAuditSink;

impl AuditSink for NoOpAuditSink {
    fn log(&self, _entry: AuditEntry) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_creation() {
        let entry = AuditEntry::new(
            AuditEvent::HandshakeCompleted {
                peer_id_hash: "abc123".to_string(),
            },
            Some("test".to_string()),
        );
        assert!(entry.timestamp_ms > 0);
        assert_eq!(entry.context.as_deref(), Some("test"));
    }

    #[test]
    fn test_memory_sink() {
        let sink = MemoryAuditSink::new();
        sink.log(AuditEntry::new(
            AuditEvent::SessionCreated {
                session_id_hash: "s1".to_string(),
            },
            None,
        ));
        let entries = sink.entries();
        assert_eq!(entries.len(), 1);
        assert!(matches!(
            entries[0].event,
            AuditEvent::SessionCreated { .. }
        ));
    }
}
