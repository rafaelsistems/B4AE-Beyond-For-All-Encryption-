//! Enhanced B4AE Mobile SDK for Android
//! Comprehensive quantum-safe cryptography with full protocol support

use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString, JByteArray};
use jni::sys::{jbyteArray, jint, jlong, jboolean};
use b4ae::prelude::*;
use b4ae::crypto::{CryptoConfig, SecurityLevel};
use b4ae::protocol::SecurityProfile;
use std::sync::{Arc, RwLock};
use std::collections::HashMap;

/// Global client storage for persistent sessions
static CLIENT_STORAGE: RwLock<Option<HashMap<String, Arc<B4aeClient>>>> = RwLock::new(None);

/// Initialize B4AE mobile SDK
#[no_mangle]
pub extern "C" fn Java_com_b4ae_B4AE_nativeInit(
    env: JNIEnv,
    _class: JClass,
    security_profile: jint,
) -> jlong {
    let profile = match security_profile {
        0 => SecurityProfile::Standard,
        1 => SecurityProfile::High,
        2 => SecurityProfile::Maximum,
        _ => SecurityProfile::Standard,
    };

    match B4aeClient::new(profile) {
        Ok(client) => {
            let client_ptr = Arc::into_raw(Arc::new(client)) as jlong;
            client_ptr
        }
        Err(_) => 0,
    }
}

/// Cleanup B4AE client
#[no_mangle]
pub extern "C" fn Java_com_b4ae_B4AE_nativeCleanup(
    _env: JNIEnv,
    _class: JClass,
    client_ptr: jlong,
) {
    if client_ptr != 0 {
        unsafe {
            let _ = Arc::from_raw(client_ptr as *const B4aeClient);
        }
    }
}

/// Generate quantum-safe keypair
#[no_mangle]
pub extern "C" fn Java_com_b4ae_B4AE_nativeGenerateKeypair(
    env: JNIEnv,
    _class: JClass,
    client_ptr: jlong,
) -> jbyteArray {
    if client_ptr == 0 {
        return std::ptr::null_mut();
    }

    let client = unsafe { &*(client_ptr as *const B4aeClient) };
    
    // Generate Kyber keypair
    match b4ae::crypto::kyber::generate_keypair() {
        Ok((public_key, secret_key)) => {
            // Combine public and secret key for storage
            let mut combined = Vec::new();
            combined.extend_from_slice(&public_key);
            combined.extend_from_slice(&secret_key);
            
            match env.byte_array_from_slice(&combined) {
                Ok(array) => array,
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Perform quantum-safe key exchange (encapsulation)
#[no_mangle]
pub extern "C" fn Java_com_b4ae_B4AE_nativeEncapsulate(
    env: JNIEnv,
    _class: JClass,
    client_ptr: jlong,
    public_key: JByteArray,
) -> jbyteArray {
    if client_ptr == 0 {
        return std::ptr::null_mut();
    }

    let client = unsafe { &*(client_ptr as *const B4aeClient) };
    
    match env.convert_byte_array(public_key) {
        Ok(pk_bytes) => {
            match b4ae::crypto::kyber::encapsulate(&pk_bytes) {
                Ok((ciphertext, shared_secret)) => {
                    // Combine ciphertext and shared secret
                    let mut combined = Vec::new();
                    combined.extend_from_slice(&ciphertext);
                    combined.extend_from_slice(&shared_secret);
                    
                    match env.byte_array_from_slice(&combined) {
                        Ok(array) => array,
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Decapsulate shared secret
#[no_mangle]
pub extern "C" fn Java_com_b4ae_B4AE_nativeDecapsulate(
    env: JNIEnv,
    _class: JClass,
    client_ptr: jlong,
    ciphertext: JByteArray,
    secret_key: JByteArray,
) -> jbyteArray {
    if client_ptr == 0 {
        return std::ptr::null_mut();
    }

    let client = unsafe { &*(client_ptr as *const B4aeClient) };
    
    match (env.convert_byte_array(ciphertext), env.convert_byte_array(secret_key)) {
        (Ok(ct), Ok(sk)) => {
            match b4ae::crypto::kyber::decapsulate(&ct, &sk) {
                Ok(shared_secret) => {
                    match env.byte_array_from_slice(&shared_secret) {
                        Ok(array) => array,
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => std::ptr::null_mut(),
            }
        }
        _ => std::ptr::null_mut(),
    }
}

/// Sign data with Dilithium5 (post-quantum signature)
#[no_mangle]
pub extern "C" fn Java_com_b4ae_B4AE_nativeSign(
    env: JNIEnv,
    _class: JClass,
    client_ptr: jlong,
    data: JByteArray,
    secret_key: JByteArray,
) -> jbyteArray {
    if client_ptr == 0 {
        return std::ptr::null_mut();
    }

    let client = unsafe { &*(client_ptr as *const B4aeClient) };
    
    match (env.convert_byte_array(data), env.convert_byte_array(secret_key)) {
        (Ok(data_bytes), Ok(sk_bytes)) => {
            match b4ae::crypto::dilithium::sign(&data_bytes, &sk_bytes) {
                Ok(signature) => {
                    match env.byte_array_from_slice(&signature) {
                        Ok(array) => array,
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => std::ptr::null_mut(),
            }
        }
        _ => std::ptr::null_mut(),
    }
}

/// Verify Dilithium5 signature
#[no_mangle]
pub extern "C" fn Java_com_b4ae_B4AE_nativeVerify(
    env: JNIEnv,
    _class: JClass,
    client_ptr: jlong,
    signature: JByteArray,
    data: JByteArray,
    public_key: JByteArray,
) -> jboolean {
    if client_ptr == 0 {
        return 0;
    }

    let client = unsafe { &*(client_ptr as *const B4aeClient) };
    
    match (
        env.convert_byte_array(signature),
        env.convert_byte_array(data),
        env.convert_byte_array(public_key),
    ) {
        (Ok(sig), Ok(data_bytes), Ok(pk_bytes)) => {
            match b4ae::crypto::dilithium::verify(&sig, &data_bytes, &pk_bytes) {
                Ok(valid) => if valid { 1 } else { 0 },
                Err(_) => 0,
            }
        }
        _ => 0,
    }
}

/// Encrypt message with AES-256-GCM (hybrid encryption)
#[no_mangle]
pub extern "C" fn Java_com_b4ae_B4AE_nativeEncrypt(
    env: JNIEnv,
    _class: JClass,
    client_ptr: jlong,
    key: JByteArray,
    plaintext: JByteArray,
) -> jbyteArray {
    if client_ptr == 0 {
        return std::ptr::null_mut();
    }

    let client = unsafe { &*(client_ptr as *const B4aeClient) };
    
    match (env.convert_byte_array(key), env.convert_byte_array(plaintext)) {
        (Ok(key_bytes), Ok(plaintext_bytes)) => {
            // Generate random nonce
            let nonce = b4ae::crypto::random::generate_random_bytes(12).unwrap_or_else(|_| vec![0u8; 12]);
            
            match b4ae::crypto::aes_gcm::encrypt(&key_bytes, &nonce, &plaintext_bytes, &[]) {
                Ok(ciphertext) => {
                    // Combine nonce and ciphertext
                    let mut combined = Vec::new();
                    combined.extend_from_slice(&nonce);
                    combined.extend_from_slice(&ciphertext);
                    
                    match env.byte_array_from_slice(&combined) {
                        Ok(array) => array,
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => std::ptr::null_mut(),
            }
        }
        _ => std::ptr::null_mut(),
    }
}

/// Decrypt message with AES-256-GCM
#[no_mangle]
pub extern "C" fn Java_com_b4ae_B4AE_nativeDecrypt(
    env: JNIEnv,
    _class: JClass,
    client_ptr: jlong,
    key: JByteArray,
    encrypted: JByteArray,
) -> jbyteArray {
    if client_ptr == 0 {
        return std::ptr::null_mut();
    }

    let client = unsafe { &*(client_ptr as *const B4aeClient) };
    
    match (env.convert_byte_array(key), env.convert_byte_array(encrypted)) {
        (Ok(key_bytes), Ok(encrypted_bytes)) => {
            if encrypted_bytes.len() < 12 {
                return std::ptr::null_mut();
            }
            
            // Split nonce and ciphertext
            let (nonce, ciphertext) = encrypted_bytes.split_at(12);
            
            match b4ae::crypto::aes_gcm::decrypt(&key_bytes, nonce, ciphertext, &[]) {
                Ok(plaintext) => {
                    match env.byte_array_from_slice(&plaintext) {
                        Ok(array) => array,
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => std::ptr::null_mut(),
            }
        }
        _ => std::ptr::null_mut(),
    }
}

/// Perform complete B4AE handshake
#[no_mangle]
pub extern "C" fn Java_com_b4ae_B4AE_nativeHandshake(
    env: JNIEnv,
    _class: JClass,
    client_ptr: jlong,
    peer_id: JByteArray,
) -> jbyteArray {
    if client_ptr == 0 {
        return std::ptr::null_mut();
    }

    let client = unsafe { &mut *(client_ptr as *mut B4aeClient) };
    
    match env.convert_byte_array(peer_id) {
        Ok(peer_id_bytes) => {
            match client.initiate_handshake(&peer_id_bytes) {
                Ok(handshake_data) => {
                    // Serialize handshake data
                    match bincode::serialize(&handshake_data) {
                        Ok(serialized) => {
                            match env.byte_array_from_slice(&serialized) {
                                Ok(array) => array,
                                Err(_) => std::ptr::null_mut(),
                            }
                        }
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Complete handshake response
#[no_mangle]
pub extern "C" fn Java_com_b4ae_B4AE_nativeCompleteHandshake(
    env: JNIEnv,
    _class: JClass,
    client_ptr: jlong,
    peer_id: JByteArray,
    handshake_data: JByteArray,
) -> jboolean {
    if client_ptr == 0 {
        return 0;
    }

    let client = unsafe { &mut *(client_ptr as *mut B4aeClient) };
    
    match (env.convert_byte_array(peer_id), env.convert_byte_array(handshake_data)) {
        (Ok(peer_id_bytes), Ok(handshake_bytes)) => {
            // Deserialize handshake data
            match bincode::deserialize(&handshake_bytes) {
                Ok(handshake) => {
                    match client.process_response(&peer_id_bytes, handshake) {
                        Ok(_) => 1,
                        Err(_) => 0,
                    }
                }
                Err(_) => 0,
            }
        }
        _ => 0,
    }
}

/// Encrypt message with established session
#[no_mangle]
pub extern "C" fn Java_com_b4ae_B4AE_nativeEncryptMessage(
    env: JNIEnv,
    _class: JClass,
    client_ptr: jlong,
    peer_id: JByteArray,
    message: JByteArray,
) -> jbyteArray {
    if client_ptr == 0 {
        return std::ptr::null_mut();
    }

    let client = unsafe { &*(client_ptr as *const B4aeClient) };
    
    match (env.convert_byte_array(peer_id), env.convert_byte_array(message)) {
        (Ok(peer_id_bytes), Ok(message_bytes)) => {
            match client.encrypt_message(&peer_id_bytes, &message_bytes) {
                Ok(encrypted_messages) => {
                    // Serialize encrypted messages
                    match bincode::serialize(&encrypted_messages) {
                        Ok(serialized) => {
                            match env.byte_array_from_slice(&serialized) {
                                Ok(array) => array,
                                Err(_) => std::ptr::null_mut(),
                            }
                        }
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => std::ptr::null_mut(),
            }
        }
        _ => std::ptr::null_mut(),
    }
}

/// Decrypt message with established session
#[no_mangle]
pub extern "C" fn Java_com_b4ae_B4AE_nativeDecryptMessage(
    env: JNIEnv,
    _class: JClass,
    client_ptr: jlong,
    peer_id: JByteArray,
    encrypted_messages: JByteArray,
) -> jbyteArray {
    if client_ptr == 0 {
        return std::ptr::null_mut();
    }

    let client = unsafe { &*(client_ptr as *const B4aeClient) };
    
    match (env.convert_byte_array(peer_id), env.convert_byte_array(encrypted_messages)) {
        (Ok(peer_id_bytes), Ok(encrypted_bytes)) => {
            // Deserialize encrypted messages
            match bincode::deserialize(&encrypted_bytes) {
                Ok(messages) => {
                    match client.decrypt_message(&peer_id_bytes, &messages) {
                        Ok(decrypted) => {
                            match env.byte_array_from_slice(&decrypted) {
                                Ok(array) => array,
                                Err(_) => std::ptr::null_mut(),
                            }
                        }
                        Err(_) => std::ptr::null_mut(),
                    }
                }
                Err(_) => std::ptr::null_mut(),
            }
        }
        _ => std::ptr::null_mut(),
    }
}

/// Get library version
#[no_mangle]
pub extern "C" fn Java_com_b4ae_B4AE_nativeGetVersion(
    env: JNIEnv,
    _class: JClass,
) -> JString {
    let version = env!("CARGO_PKG_VERSION");
    match env.new_string(version) {
        Ok(string) => string,
        Err(_) => JString::default(),
    }
}

/// Get security info
#[no_mangle]
pub extern "C" fn Java_com_b4ae_B4AE_nativeGetSecurityInfo(
    env: JNIEnv,
    _class: JClass,
    client_ptr: jlong,
) -> JString {
    if client_ptr == 0 {
        return JString::default();
    }

    let info = format!(
        "B4AE Mobile SDK\n\
         Version: {}\n\
         Protocol: v{}\n\
         Cryptography: Kyber-1024, Dilithium5, X25519, Ed25519, AES-256-GCM\n\
         Platform: Android (JNI)",
        env!("CARGO_PKG_VERSION"),
        b4ae::protocol::PROTOCOL_VERSION
    );

    match env.new_string(info) {
        Ok(string) => string,
        Err(_) => JString::default(),
    }
}