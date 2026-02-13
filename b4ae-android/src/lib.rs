//! B4AE JNI bindings for Android/Kotlin

use jni::objects::{JByteArray, JClass};
use jni::sys::jbyteArray;
use jni::JNIEnv;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

/// Generate 32-byte key. Returns byte array.
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_com_b4ae_B4AE_nativeGenerateKey(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    let key = b4ae_ffi_impl::generate_key();
    let arr = env.byte_array_from_slice(&key).unwrap();
    arr.into_raw()
}

/// Encrypt plaintext. key and plaintext are byte arrays, returns encrypted [nonce||ciphertext].
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_com_b4ae_B4AE_nativeEncrypt(
    env: JNIEnv,
    _class: JClass,
    key: JByteArray,
    plaintext: JByteArray,
) -> jbyteArray {
    let key_vec: Vec<u8> = env.convert_byte_array(key).unwrap();
    let plain_vec: Vec<u8> = env.convert_byte_array(plaintext).unwrap();
    match b4ae_ffi_impl::encrypt(&key_vec, &plain_vec) {
        Ok(enc) => env.byte_array_from_slice(&enc).unwrap().into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Decrypt [nonce||ciphertext]. Returns plaintext or null on error.
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_com_b4ae_B4AE_nativeDecrypt(
    env: JNIEnv,
    _class: JClass,
    key: JByteArray,
    encrypted: JByteArray,
) -> jbyteArray {
    let key_vec: Vec<u8> = env.convert_byte_array(key).unwrap();
    let enc_vec: Vec<u8> = env.convert_byte_array(encrypted).unwrap();
    match b4ae_ffi_impl::decrypt(&key_vec, &enc_vec) {
        Ok(dec) => env.byte_array_from_slice(&dec).unwrap().into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

mod b4ae_ffi_impl {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm,
    };

    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12;

    pub fn generate_key() -> Vec<u8> {
        let mut key = [0u8; KEY_SIZE];
        getrandom::getrandom(&mut key).expect("getrandom");
        key.to_vec()
    }

    pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ()> {
        if key.len() != KEY_SIZE {
            return Err(());
        }
        let mut nonce = [0u8; NONCE_SIZE];
        getrandom::getrandom(&mut nonce).map_err(|_| ())?;
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
        let payload = Payload { msg: plaintext, aad: &[] };
        let ciphertext = cipher.encrypt((&nonce).into(), payload).map_err(|_| ())?;
        let mut result = nonce.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    pub fn decrypt(key: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, ()> {
        if key.len() != KEY_SIZE || encrypted.len() < NONCE_SIZE {
            return Err(());
        }
        let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
        let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
        let payload = Payload {
            msg: ciphertext,
            aad: &[],
        };
        cipher.decrypt(nonce, payload).map_err(|_| ())
    }
}
