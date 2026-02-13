//! Fuzz target untuk message parsing
#![no_main]

use libfuzzer_sys::fuzz_target;
use b4ae::protocol::message::EncryptedMessage;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<EncryptedMessage>(data);
});
