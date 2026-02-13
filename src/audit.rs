//! Audit logging untuk production compliance
//!
//! Events penting (handshake, key rotation, auth failure) dicatat
//! untuk audit trail tanpa menyimpan data sensitif.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Audit event types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuditEvent {
    /// Handshake initiated
    HandshakeInitiated { peer_id_hash: String },
    /// Handshake completed
    HandshakeCompleted { peer_id_hash: String },
    /// Handshake failed
    HandshakeFailed { peer_id_hash: String, reason: String },
    /// Key rotation triggered
    KeyRotation { session_id_hash: String },
    /// Authentication failed
    AuthFailed { reason: String },
    /// Session created
    SessionCreated { session_id_hash: String },
    /// Session closed
    SessionClosed { session_id_hash: String },
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
        self.entries.lock().unwrap().clone()
    }

    /// Clear entries (testing only)
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

impl AuditSink for MemoryAuditSink {
    fn log(&self, entry: AuditEntry) {
        self.entries.lock().unwrap().push(entry);
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
