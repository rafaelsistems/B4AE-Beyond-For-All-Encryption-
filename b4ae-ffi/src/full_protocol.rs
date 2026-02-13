//! B4AE Full Protocol FFI
//!
//! Exposes handshake, encrypt, decrypt via C ABI when built with `full-protocol` feature.

use b4ae::{B4aeClient, SecurityProfile};
use b4ae::protocol::handshake::{HandshakeInit, HandshakeResponse, HandshakeComplete};
use b4ae::protocol::message::EncryptedMessage;
extern crate bincode;

/// Opaque B4AE client handle
pub struct B4aeClientHandle {
    pub client: B4aeClient,
}

/// Security profile ID: 0=Standard, 1=High, 2=Maximum
#[no_mangle]
pub extern "C" fn b4ae_client_new(profile_id: u8) -> *mut B4aeClientHandle {
    let profile = match profile_id {
        1 => SecurityProfile::High,
        2 => SecurityProfile::Maximum,
        _ => SecurityProfile::Standard,
    };
    match B4aeClient::new(profile) {
        Ok(client) => Box::into_raw(Box::new(B4aeClientHandle { client })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free client. Safe to call with null.
#[no_mangle]
pub extern "C" fn b4ae_client_free(handle: *mut B4aeClientHandle) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle)); }
    }
}

/// Initiate handshake. Returns serialized HandshakeInit in out_buf. out_len set to written bytes.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn b4ae_initiate_handshake(
    handle: *mut B4aeClientHandle,
    peer_id: *const u8,
    peer_id_len: usize,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> i32 {
    if handle.is_null() || peer_id.is_null() || out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    let client = unsafe { &mut *handle };
    let peer = unsafe { std::slice::from_raw_parts(peer_id, peer_id_len) };
    let init = match client.client.initiate_handshake(peer) {
        Ok(i) => i,
        Err(_) => return -1,
    };
    let bytes = match bincode::serialize(&init) {
        Ok(b) => b,
        Err(_) => return -1,
    };
    let len = bytes.len();
    if len > unsafe { *out_len } {
        unsafe { *out_len = len; }
        return -2; // buffer too small
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, len);
        *out_len = len;
    }
    0
}

/// Respond to handshake. init_buf/init_len = serialized HandshakeInit.
/// Writes serialized HandshakeResponse to out_buf. Returns 0 on success.
#[no_mangle]
pub extern "C" fn b4ae_respond_to_handshake(
    handle: *mut B4aeClientHandle,
    peer_id: *const u8,
    peer_id_len: usize,
    init_buf: *const u8,
    init_len: usize,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> i32 {
    if handle.is_null() || peer_id.is_null() || init_buf.is_null() || out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    let client = unsafe { &mut *handle };
    let peer = unsafe { std::slice::from_raw_parts(peer_id, peer_id_len) };
    let init: HandshakeInit = match bincode::deserialize(unsafe { std::slice::from_raw_parts(init_buf, init_len) }) {
        Ok(i) => i,
        Err(_) => return -1,
    };
    let response = match client.client.respond_to_handshake(peer, init) {
        Ok(r) => r,
        Err(_) => return -1,
    };
    let bytes = match bincode::serialize(&response) {
        Ok(b) => b,
        Err(_) => return -1,
    };
    let len = bytes.len();
    if len > unsafe { *out_len } {
        unsafe { *out_len = len; }
        return -2;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, len);
        *out_len = len;
    }
    0
}

/// Process response (initiator). response_buf = serialized HandshakeResponse.
/// Writes serialized HandshakeComplete to out_buf. Returns 0 on success.
#[no_mangle]
pub extern "C" fn b4ae_process_response(
    handle: *mut B4aeClientHandle,
    peer_id: *const u8,
    peer_id_len: usize,
    response_buf: *const u8,
    response_len: usize,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> i32 {
    if handle.is_null() || peer_id.is_null() || response_buf.is_null() || out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    let client = unsafe { &mut *handle };
    let peer = unsafe { std::slice::from_raw_parts(peer_id, peer_id_len) };
    let response: HandshakeResponse = match bincode::deserialize(unsafe { std::slice::from_raw_parts(response_buf, response_len) }) {
        Ok(r) => r,
        Err(_) => return -1,
    };
    let complete = match client.client.process_response(peer, response) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    let bytes = match bincode::serialize(&complete) {
        Ok(b) => b,
        Err(_) => return -1,
    };
    let len = bytes.len();
    if len > unsafe { *out_len } {
        unsafe { *out_len = len; }
        return -2;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, len);
        *out_len = len;
    }
    0
}

/// Complete handshake (responder). complete_buf = serialized HandshakeComplete.
#[no_mangle]
pub extern "C" fn b4ae_complete_handshake(
    handle: *mut B4aeClientHandle,
    peer_id: *const u8,
    peer_id_len: usize,
    complete_buf: *const u8,
    complete_len: usize,
) -> i32 {
    if handle.is_null() || peer_id.is_null() || complete_buf.is_null() {
        return -1;
    }
    let client = unsafe { &mut *handle };
    let peer = unsafe { std::slice::from_raw_parts(peer_id, peer_id_len) };
    let complete: HandshakeComplete = match bincode::deserialize(unsafe { std::slice::from_raw_parts(complete_buf, complete_len) }) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    match client.client.complete_handshake(peer, complete) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Finalize initiator.
#[no_mangle]
pub extern "C" fn b4ae_finalize_initiator(
    handle: *mut B4aeClientHandle,
    peer_id: *const u8,
    peer_id_len: usize,
) -> i32 {
    if handle.is_null() || peer_id.is_null() {
        return -1;
    }
    let client = unsafe { &mut *handle };
    let peer = unsafe { std::slice::from_raw_parts(peer_id, peer_id_len) };
    match client.client.finalize_initiator(peer) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Encrypt message. Writes serialized EncryptedMessage to out_buf. Returns 0 on success.
#[no_mangle]
pub extern "C" fn b4ae_encrypt_message(
    handle: *mut B4aeClientHandle,
    peer_id: *const u8,
    peer_id_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> i32 {
    if handle.is_null() || peer_id.is_null() || plaintext.is_null() || out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    let client = unsafe { &mut *handle };
    let peer = unsafe { std::slice::from_raw_parts(peer_id, peer_id_len) };
    let plain = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };
    let enc_list = match client.client.encrypt_message(peer, plain) {
        Ok(e) => e,
        Err(_) => return -1,
    };
    let bytes = match bincode::serialize(&enc_list) {
        Ok(b) => b,
        Err(_) => return -1,
    };
    let len = bytes.len();
    if len > unsafe { *out_len } {
        unsafe { *out_len = len; }
        return -2;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, len);
        *out_len = len;
    }
    0
}

/// Decrypt message. enc_buf = serialized EncryptedMessage.
/// Writes plaintext to out_buf. Returns 0 on success.
#[no_mangle]
pub extern "C" fn b4ae_decrypt_message(
    handle: *mut B4aeClientHandle,
    peer_id: *const u8,
    peer_id_len: usize,
    enc_buf: *const u8,
    enc_len: usize,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> i32 {
    if handle.is_null() || peer_id.is_null() || enc_buf.is_null() || out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    let client = unsafe { &mut *handle };
    let peer = unsafe { std::slice::from_raw_parts(peer_id, peer_id_len) };
    let enc: EncryptedMessage = match bincode::deserialize(unsafe { std::slice::from_raw_parts(enc_buf, enc_len) }) {
        Ok(e) => e,
        Err(_) => return -1,
    };
    let plain = match client.client.decrypt_message(peer, &enc) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    let len = plain.len();
    if len > unsafe { *out_len } {
        unsafe { *out_len = len; }
        return -2;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(plain.as_ptr(), out_buf, len);
        *out_len = len;
    }
    0
}
