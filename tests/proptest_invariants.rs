//! Property-based invariants untuk formal verification
//!
//! Verifikasi critical paths: encrypt/decrypt roundtrip, handshake completeness.

use b4ae::client::B4aeClient;
use b4ae::crypto::aes_gcm::{decrypt, encrypt, AesKey};
use b4ae::protocol::SecurityProfile;
use proptest::prelude::*;

proptest! {
    /// Encrypt/decrypt roundtrip: decrypt(encrypt(m)) == m
    #[test]
    fn prop_aes_gcm_roundtrip(plaintext in prop::collection::vec(any::<u8>(), 0..2048)) {
        let key = AesKey::generate();
        let aad: &[u8] = &[];
        let (nonce, ciphertext) = encrypt(&key, &plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }

    /// Different plaintext → different ciphertext (with same key, different nonces)
    #[test]
    fn prop_aes_gcm_different_plaintext_different_ciphertext(
        a in prop::collection::vec(any::<u8>(), 1..256),
        b in prop::collection::vec(any::<u8>(), 1..256)
    ) {
        prop_assume!(a != b);
        let key = AesKey::generate();
        let (_, ct_a) = encrypt(&key, &a, &[]).unwrap();
        let (_, ct_b) = encrypt(&key, &b, &[]).unwrap();
        prop_assert_ne!(ct_a, ct_b);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Handshake completeness: both parties get session after valid handshake
    #[test]
    fn prop_handshake_completeness(initiator_id in "[a-z]{1,20}", responder_id in "[a-z]{1,20}") {
        prop_assume!(initiator_id != responder_id);

        let mut alice = B4aeClient::new(SecurityProfile::Standard).unwrap();
        let mut bob = B4aeClient::new(SecurityProfile::Standard).unwrap();

        let init_id = initiator_id.as_bytes().to_vec();
        let resp_id = responder_id.as_bytes().to_vec();

        let init = alice.initiate_handshake(&resp_id).unwrap();
        let response = bob.respond_to_handshake(&init_id, init).unwrap();
        let complete = alice.process_response(&resp_id, response).unwrap();
        bob.complete_handshake(&init_id, complete).unwrap();
        alice.finalize_initiator(&resp_id).unwrap();

        prop_assert!(alice.has_session(&resp_id));
        prop_assert!(bob.has_session(&init_id));
    }

    /// Message roundtrip after handshake
    #[test]
    fn prop_message_roundtrip_after_handshake(
        msg in prop::collection::vec(any::<u8>(), 0..512)
    ) {
        let mut alice = B4aeClient::new(SecurityProfile::Standard).unwrap();
        let mut bob = B4aeClient::new(SecurityProfile::Standard).unwrap();

        let alice_id = b"alice".to_vec();
        let bob_id = b"bob".to_vec();

        let init = alice.initiate_handshake(&bob_id).unwrap();
        let response = bob.respond_to_handshake(&alice_id, init).unwrap();
        let complete = alice.process_response(&bob_id, response).unwrap();
        bob.complete_handshake(&alice_id, complete).unwrap();
        alice.finalize_initiator(&bob_id).unwrap();

        let encrypted_list = alice.encrypt_message(&bob_id, &msg).unwrap();
        let mut decrypted = vec![];
        for enc in &encrypted_list {
            let d = bob.decrypt_message(&alice_id, enc).unwrap();
            if !d.is_empty() {
                decrypted = d;
            }
        }
        prop_assert_eq!(decrypted, msg);
    }
}
