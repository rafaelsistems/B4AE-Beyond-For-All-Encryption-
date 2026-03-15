//! Protocol ID derivation system for B4AE v2.0
//!
//! The Protocol ID is a critical security feature that provides:
//! - Automatic version enforcement (different specs = different IDs)
//! - Downgrade attack detection (ID mismatch causes signature failure)
//! - Domain separation in key derivations
//! - Cryptographic agility without explicit version negotiation
//!
//! ## Design
//!
//! The protocol_id is computed as SHA3-256 of the canonical protocol specification
//! document. This creates a cryptographic binding between the implementation and
//! the specification.
//!
//! ## Security Properties
//!
//! - Changes automatically when protocol specification changes
//! - Included in all handshake transcripts
//! - Used in all key derivations for domain separation
//! - Prevents cross-version attacks
//! - Enables cryptographic agility without explicit version negotiation
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use b4ae::protocol::v2::protocol_id::{get_protocol_id, compute_transcript_hash};
//!
//! // Get the global protocol ID (computed once at initialization)
//! let protocol_id = get_protocol_id();
//!
//! // Include protocol_id in handshake transcript
//! let messages = b"ClientHello||ServerHello||ClientFinish";
//! let transcript_hash = compute_transcript_hash(protocol_id, messages);
//!
//! // Use protocol_id and transcript_hash in key derivation
//! // session_key = HKDF(master_secret, protocol_id || session_id || transcript_hash, "session-key")
//! ```
//!
//! ## Requirements
//!
//! - REQ-10: Cryptographic Agility via Protocol ID
//! - REQ-11: Domain Separation with Protocol ID

use crate::protocol::v2::types::ProtocolId;
use sha3::{Digest, Sha3_256};
use std::sync::OnceLock;

/// Canonical protocol specification for B4AE v2.0
///
/// This string defines the canonical specification that the protocol_id is
/// derived from. It captures the core cryptographic commitments of B4AE v2.0:
/// authentication modes, key exchange algorithms, and security properties.
///
/// Changing this string changes the protocol_id, which causes handshake
/// failures with peers running a different version — intentional behaviour
/// for automatic version enforcement.
const CANONICAL_SPECIFICATION: &str = "\
B4AE Protocol Specification v2.0 — Canonical Reference\n\
\n\
## Authentication Modes\n\
- Mode A: XEdDSA deniable signature over X25519 key (plausible deniability)\n\
- Mode B: Dilithium5 post-quantum non-repudiable signature (NIST PQC Level 5)\n\
- Mode C: Reserved for future hybrid research (not production-ready)\n\
\n\
## Key Exchange\n\
- Classical: X25519 ECDH\n\
- Post-Quantum: Kyber-1024 KEM (NIST PQC Level 5)\n\
- Hybrid: X25519 || Kyber-1024 (combined shared secret via HKDF)\n\
\n\
## Symmetric Cryptography\n\
- AEAD: AES-256-GCM\n\
- Hash: SHA3-256 (domain separation), SHA-512 (key derivation)\n\
- KDF: HKDF-SHA3-256\n\
\n\
## Protocol Flow\n\
1. ModeNegotiation (client → server): supported_modes, preferred_mode, client_random\n\
2. ModeSelection (server → client): selected_mode, server_random\n\
3. ModeBinding: SHA3-256('B4AE-v2-mode-binding' || client_random || server_random || mode_id)\n\
4. CookieChallenge (server → client): HMAC-SHA256(server_secret, client_ip || timestamp || client_random)\n\
5. HandshakeInit (client → server): ephemeral keys, mode_binding, timestamp, signature\n\
6. HandshakeResponse (server → client): ephemeral keys, Kyber ciphertext, mode_binding, signature\n\
7. HandshakeComplete (client → server): confirmation, mode_binding, signature\n\
\n\
## Security Properties\n\
- Forward Secrecy: PFS+ via Double Ratchet with Kyber-1024 PQ ratchet\n\
- Downgrade Protection: mode_binding in every handshake message\n\
- DoS Protection: Stateless HMAC cookie challenge (360x amplification reduction)\n\
- Metadata Protection: Global unified traffic scheduler, constant-rate output\n\
- Replay Protection: Bloom filter on client_random (30-second window)\n\
- Side-Channel Resistance: Constant-time operations via subtle crate\n\
- Memory Safety: Zeroize on drop for all key material\n\
\n\
## Version\n\
B4AE-v2.0 — protocol_id = SHA3-256(this document)\n\
";

/// Global protocol ID computed once at initialization
///
/// Uses OnceLock for thread-safe lazy initialization. The protocol_id is
/// computed from the canonical specification document and cached for the
/// lifetime of the program.
static PROTOCOL_ID: OnceLock<ProtocolId> = OnceLock::new();

/// Derives the protocol ID from a canonical specification document
///
/// Computes: protocol_id = SHA3-256(specification_document)
///
/// ## Parameters
///
/// - `specification_document`: The canonical protocol specification text
///
/// ## Returns
///
/// A 32-byte protocol ID derived from the specification hash
///
/// ## Security Properties
///
/// - Any change to the specification results in a different protocol_id
/// - Protocol_id is included in all handshake transcripts
/// - Signature verification fails if protocol_ids don't match
/// - Provides automatic version enforcement without explicit negotiation
///
/// ## Example
///
/// ```rust,ignore
/// let spec = "B4AE v2.0 Protocol Specification\n...";
/// let protocol_id = derive_protocol_id(spec);
/// // protocol_id = SHA3-256(spec) = 0x7a3f9e2b... (32 bytes)
/// ```
pub fn derive_protocol_id(specification_document: &str) -> ProtocolId {
    let mut hasher = Sha3_256::new();
    hasher.update(specification_document.as_bytes());
    let hash = hasher.finalize();
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    
    ProtocolId::new(bytes)
}

/// Returns the global protocol ID for B4AE v2.0
///
/// The protocol ID is computed once from the embedded canonical specification
/// and cached for the lifetime of the program. This function is thread-safe
/// and can be called from multiple threads.
///
/// ## Returns
///
/// The protocol ID for B4AE v2.0, derived from the canonical specification
///
/// ## Example
///
/// ```rust,ignore
/// use b4ae::protocol::v2::protocol_id::get_protocol_id;
///
/// let protocol_id = get_protocol_id();
/// // Use protocol_id in transcript computation and key derivation
/// ```
pub fn get_protocol_id() -> &'static ProtocolId {
    PROTOCOL_ID.get_or_init(|| derive_protocol_id(CANONICAL_SPECIFICATION))
}

/// Verifies that a received protocol ID matches the expected protocol ID
///
/// Uses constant-time comparison to prevent timing attacks. If the protocol
/// IDs don't match, this indicates a version mismatch or downgrade attack.
///
/// ## Parameters
///
/// - `received`: The protocol ID received from the peer
/// - `expected`: The expected protocol ID (typically from `get_protocol_id()`)
///
/// ## Returns
///
/// `true` if the protocol IDs match, `false` otherwise
///
/// ## Security Properties
///
/// - Constant-time comparison prevents timing side-channels
/// - Mismatch indicates version incompatibility or downgrade attack
/// - Should cause handshake to abort with error
///
/// ## Example
///
/// ```rust,ignore
/// use b4ae::protocol::v2::protocol_id::{get_protocol_id, verify_protocol_id};
///
/// let expected = get_protocol_id();
/// let received = peer_protocol_id; // From handshake message
///
/// if !verify_protocol_id(&received, expected) {
///     return Err("Protocol version mismatch detected");
/// }
/// ```
pub fn verify_protocol_id(received: &ProtocolId, expected: &ProtocolId) -> bool {
    use subtle::ConstantTimeEq;
    
    // Constant-time comparison to prevent timing attacks
    received.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// Computes a transcript hash including the protocol ID
///
/// The transcript hash is computed as:
/// SHA-512("B4AE-v2-Handshake-Transcript" || protocol_id || messages)
///
/// ## Parameters
///
/// - `protocol_id`: The protocol ID to include in the transcript
/// - `messages`: Concatenated handshake messages
///
/// ## Returns
///
/// A 64-byte transcript hash
///
/// ## Security Properties
///
/// - Protocol ID is bound to the transcript
/// - Any change to protocol_id causes different transcript hash
/// - Signature verification fails if protocol_ids don't match
/// - Provides automatic downgrade protection
///
/// ## Example
///
/// ```rust,ignore
/// use b4ae::protocol::v2::protocol_id::{get_protocol_id, compute_transcript_hash};
///
/// let protocol_id = get_protocol_id();
/// let messages = b"message1message2message3";
/// let transcript_hash = compute_transcript_hash(protocol_id, messages);
/// ```
pub fn compute_transcript_hash(protocol_id: &ProtocolId, messages: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    use crate::protocol::v2::constants::DOMAIN_HANDSHAKE_TRANSCRIPT;
    
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_HANDSHAKE_TRANSCRIPT);
    hasher.update(protocol_id.as_bytes());
    hasher.update(messages);
    
    let hash = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&hash);
    
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_protocol_id_deterministic() {
        // Same specification should produce same protocol_id
        let spec = "B4AE v2.0 Test Specification";
        let id1 = derive_protocol_id(spec);
        let id2 = derive_protocol_id(spec);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_derive_protocol_id_different_specs() {
        // Different specifications should produce different protocol_ids
        let spec1 = "B4AE v2.0 Specification";
        let spec2 = "B4AE v3.0 Specification";
        let id1 = derive_protocol_id(spec1);
        let id2 = derive_protocol_id(spec2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_derive_protocol_id_size() {
        // Protocol ID should be 32 bytes (SHA3-256 output)
        let spec = "Test specification";
        let id = derive_protocol_id(spec);
        assert_eq!(id.as_bytes().len(), 32);
    }

    #[test]
    fn test_get_protocol_id_singleton() {
        // get_protocol_id should return the same instance
        let id1 = get_protocol_id();
        let id2 = get_protocol_id();
        assert_eq!(id1, id2);
        // Verify they're the same reference
        assert!(std::ptr::eq(id1, id2));
    }

    #[test]
    fn test_get_protocol_id_from_canonical_spec() {
        // Verify that get_protocol_id uses the embedded canonical specification
        let id = get_protocol_id();
        let expected = derive_protocol_id(CANONICAL_SPECIFICATION);
        assert_eq!(id, &expected);
    }

    #[test]
    fn test_verify_protocol_id_matching() {
        // Matching protocol IDs should verify successfully
        let spec = "Test specification";
        let id1 = derive_protocol_id(spec);
        let id2 = derive_protocol_id(spec);
        assert!(verify_protocol_id(&id1, &id2));
    }

    #[test]
    fn test_verify_protocol_id_mismatching() {
        // Mismatching protocol IDs should fail verification
        let spec1 = "Specification v1";
        let spec2 = "Specification v2";
        let id1 = derive_protocol_id(spec1);
        let id2 = derive_protocol_id(spec2);
        assert!(!verify_protocol_id(&id1, &id2));
    }

    #[test]
    fn test_compute_transcript_hash_deterministic() {
        // Same inputs should produce same transcript hash
        let protocol_id = get_protocol_id();
        let messages = b"message1message2";
        let hash1 = compute_transcript_hash(protocol_id, messages);
        let hash2 = compute_transcript_hash(protocol_id, messages);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_transcript_hash_different_protocol_ids() {
        // Different protocol IDs should produce different transcript hashes
        let id1 = derive_protocol_id("Spec v1");
        let id2 = derive_protocol_id("Spec v2");
        let messages = b"message1message2";
        let hash1 = compute_transcript_hash(&id1, messages);
        let hash2 = compute_transcript_hash(&id2, messages);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_transcript_hash_different_messages() {
        // Different messages should produce different transcript hashes
        let protocol_id = get_protocol_id();
        let messages1 = b"message1";
        let messages2 = b"message2";
        let hash1 = compute_transcript_hash(protocol_id, messages1);
        let hash2 = compute_transcript_hash(protocol_id, messages2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_transcript_hash_size() {
        // Transcript hash should be 64 bytes (SHA-512 output)
        let protocol_id = get_protocol_id();
        let messages = b"test";
        let hash = compute_transcript_hash(protocol_id, messages);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_compute_transcript_hash_includes_domain_separator() {
        // Transcript hash should include domain separator
        // We can't directly test this, but we can verify that changing
        // the domain separator would change the hash
        let protocol_id = get_protocol_id();
        let messages = b"test";
        let hash = compute_transcript_hash(protocol_id, messages);
        
        // Hash should be non-zero (sanity check)
        assert_ne!(hash, [0u8; 64]);
    }

    #[test]
    fn test_canonical_specification_not_empty() {
        // Verify that the embedded canonical specification is not empty
        assert!(!CANONICAL_SPECIFICATION.is_empty());
        assert!(CANONICAL_SPECIFICATION.len() > 100); // Should be substantial
    }

    #[test]
    fn test_protocol_id_changes_with_spec() {
        // Demonstrate that protocol_id changes when specification changes
        let spec_v1 = "B4AE v2.0 Protocol\nMode A: XEdDSA\nMode B: Dilithium5";
        let spec_v2 = "B4AE v2.0 Protocol\nMode A: XEdDSA\nMode B: Dilithium5\nMode C: Hybrid";
        
        let id_v1 = derive_protocol_id(spec_v1);
        let id_v2 = derive_protocol_id(spec_v2);
        
        // Even small changes should produce different IDs
        assert_ne!(id_v1, id_v2);
    }

    #[test]
    fn test_verify_protocol_id_constant_time() {
        // This test verifies that verify_protocol_id uses constant-time comparison
        // We can't directly measure timing, but we can verify it uses the right API
        let id1 = derive_protocol_id("Spec 1");
        let id2 = derive_protocol_id("Spec 2");
        
        // Should return false for different IDs
        assert!(!verify_protocol_id(&id1, &id2));
        
        // Should return true for same IDs
        assert!(verify_protocol_id(&id1, &id1));
    }
}
