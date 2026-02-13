package com.b4ae

/**
 * B4AE Kotlin/Android bindings - AES-256-GCM encrypt/decrypt
 * Loads libb4ae_android.so from JNI
 */
object B4AE {

    const val KEY_SIZE = 32

    init {
        System.loadLibrary("b4ae_android")
    }

    external fun nativeGenerateKey(): ByteArray
    external fun nativeEncrypt(key: ByteArray, plaintext: ByteArray): ByteArray?
    external fun nativeDecrypt(key: ByteArray, encrypted: ByteArray): ByteArray?

    fun generateKey(): ByteArray = nativeGenerateKey()

    fun encrypt(key: ByteArray, plaintext: ByteArray): ByteArray {
        require(key.size == KEY_SIZE) { "Key must be 32 bytes" }
        return nativeEncrypt(key, plaintext)
            ?: throw B4AEException("Encryption failed")
    }

    fun decrypt(key: ByteArray, encrypted: ByteArray): ByteArray {
        require(key.size == KEY_SIZE) { "Key must be 32 bytes" }
        require(encrypted.size >= 12) { "Encrypted data too short" }
        return nativeDecrypt(key, encrypted)
            ?: throw B4AEException("Decryption failed")
    }
}

class B4AEException(message: String) : Exception(message)
