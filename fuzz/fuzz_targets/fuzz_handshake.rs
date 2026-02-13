//! Fuzz target untuk handshake parsing
#![no_main]

use libfuzzer_sys::fuzz_target;
use b4ae::protocol::handshake::{HandshakeInit, HandshakeResponse, HandshakeComplete};

fuzz_target!(|data: &[u8]| {
    let _ = bincode::deserialize::<HandshakeInit>(data);
    let _ = bincode::deserialize::<HandshakeResponse>(data);
    let _ = bincode::deserialize::<HandshakeComplete>(data);
});
