//! B4AE C FFI - Minimal AES-GCM API for Swift/Kotlin bindings
//!
//! Exposes generate_key, encrypt, decrypt via C ABI.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm,
};

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

fn fill_random(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom::getrandom(buf)
}

/// Allocate buffer for FFI. Caller must free with b4ae_free.
/// Uses malloc for C interoperability.
#[no_mangle]
pub extern "C" fn b4ae_alloc(size: usize) -> *mut u8 {
    if size == 0 {
        return std::ptr::null_mut();
    }
    unsafe {
        let ptr = libc::malloc(size) as *mut u8;
        if ptr.is_null() {
            return std::ptr::null_mut();
        }
        ptr
    }
}

/// Free buffer allocated by b4ae_alloc or returned from b4ae_*.
#[no_mangle]
pub extern "C" fn b4ae_free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        libc::free(ptr as *mut libc::c_void);
    }
}

/// Generate 32-byte key. Returns ptr (caller frees with b4ae_free), length in *out_len.
#[no_mangle]
pub extern "C" fn b4ae_generate_key(out_len: *mut usize) -> *mut u8 {
    if out_len.is_null() {
        return std::ptr::null_mut();
    }
    let mut key = [0u8; KEY_SIZE];
    if fill_random(&mut key).is_err() {
        return std::ptr::null_mut();
    }
    let ptr = b4ae_alloc(KEY_SIZE);
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        std::ptr::copy_nonoverlapping(key.as_ptr(), ptr, KEY_SIZE);
        *out_len = KEY_SIZE;
    }
    ptr
}

/// Encrypt plaintext. Returns [nonce(12)||ciphertext], caller frees.
/// Returns null on error.
#[no_mangle]
pub extern "C" fn b4ae_encrypt(
    key: *const u8,
    key_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if key.is_null() || plaintext.is_null() || out_len.is_null() || key_len != KEY_SIZE {
        return std::ptr::null_mut();
    }
    let mut nonce = [0u8; NONCE_SIZE];
    if fill_random(&mut nonce).is_err() {
        return std::ptr::null_mut();
    }
    let cipher = match Aes256Gcm::new_from_slice(unsafe {
        std::slice::from_raw_parts(key, key_len)
    }) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    let plain = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };
    let payload = Payload { msg: plain, aad: &[] };
    let ciphertext = match cipher.encrypt((&nonce).into(), payload) {
        Ok(ct) => ct,
        Err(_) => return std::ptr::null_mut(),
    };
    let total_len = NONCE_SIZE + ciphertext.len();
    let ptr = b4ae_alloc(total_len);
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        std::ptr::copy_nonoverlapping(nonce.as_ptr(), ptr, NONCE_SIZE);
        std::ptr::copy_nonoverlapping(
            ciphertext.as_ptr(),
            ptr.add(NONCE_SIZE),
            ciphertext.len(),
        );
        *out_len = total_len;
    }
    ptr
}

/// Decrypt [nonce(12)||ciphertext]. Caller frees result.
#[no_mangle]
pub extern "C" fn b4ae_decrypt(
    key: *const u8,
    key_len: usize,
    encrypted: *const u8,
    encrypted_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if key.is_null()
        || encrypted.is_null()
        || out_len.is_null()
        || key_len != KEY_SIZE
        || encrypted_len < NONCE_SIZE
    {
        return std::ptr::null_mut();
    }
    let encrypted_slice = unsafe { std::slice::from_raw_parts(encrypted, encrypted_len) };
    let (nonce_bytes, ciphertext) = encrypted_slice.split_at(NONCE_SIZE);
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    let cipher = match Aes256Gcm::new_from_slice(unsafe {
        std::slice::from_raw_parts(key, key_len)
    }) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    let payload = Payload {
        msg: ciphertext,
        aad: &[],
    };
    let plaintext = match cipher.decrypt(nonce, payload) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };
    let len = plaintext.len();
    let ptr = b4ae_alloc(len);
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        std::ptr::copy_nonoverlapping(plaintext.as_ptr(), ptr, len);
        *out_len = len;
    }
    ptr
}
