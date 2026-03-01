package com.b4ae

/**
 * Enhanced B4AE Android SDK - Full quantum-safe cryptography support
 * 
 * Provides comprehensive quantum-resistant secure communication for Android applications.
 * 
 * Features:
 * - Post-quantum cryptography (Kyber-1024, Dilithium5)
 * - Hybrid cryptography (X25519, Ed25519)
 * - AES-256-GCM encryption
 * - Complete handshake protocol
 * - Session management
 * - Metadata protection
 */
object B4AE {
    
    // Constants
    const val KEY_SIZE = 32
    const val NONCE_SIZE = 12
    const val KYBER_PUBLIC_KEY_SIZE = 1568
    const val KYBER_SECRET_KEY_SIZE = 3168
    const val KYBER_CIPHERTEXT_SIZE = 1568
    const val KYBER_SHARED_SECRET_SIZE = 32
    const val DILITHIUM_PUBLIC_KEY_SIZE = 2592
    const val DILITHIUM_SECRET_KEY_SIZE = 4864
    const val DILITHIUM_SIGNATURE_SIZE = 4595
    
    // Security profiles
    enum class SecurityProfile(val value: Int) {
        STANDARD(0),
        HIGH(1),
        MAXIMUM(2),
        ENTERPRISE(3)
    }
    
    // Exception classes
    class B4AEException(message: String) : Exception(message)
    class B4AEHandshakeException(message: String) : Exception(message)
    class B4AESessionException(message: String) : Exception(message)
    
    // Data classes
    data class Keypair(
        val publicKey: ByteArray,
        val secretKey: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as Keypair
            return publicKey.contentEquals(other.publicKey) && secretKey.contentEquals(other.secretKey)
        }
        
        override fun hashCode(): Int {
            var result = publicKey.contentHashCode()
            result = 31 * result + secretKey.contentHashCode()
            return result
        }
    }
    
    data class EncapsulationResult(
        val ciphertext: ByteArray,
        val sharedSecret: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as EncapsulationResult
            return ciphertext.contentEquals(other.ciphertext) && sharedSecret.contentEquals(other.sharedSecret)
        }
        
        override fun hashCode(): Int {
            var result = ciphertext.contentHashCode()
            result = 31 * result + sharedSecret.contentHashCode()
            return result
        }
    }
    
    data class EncryptedMessage(
        val nonce: ByteArray,
        val ciphertext: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as EncryptedMessage
            return nonce.contentEquals(other.nonce) && ciphertext.contentEquals(other.ciphertext)
        }
        
        override fun hashCode(): Int {
            var result = nonce.contentHashCode()
            result = 31 * result + ciphertext.contentHashCode()
            return result
        }
        
        fun toByteArray(): ByteArray {
            return nonce + ciphertext
        }
        
        companion object {
            fun fromByteArray(data: ByteArray): EncryptedMessage {
                if (data.size < NONCE_SIZE) {
                    throw B4AEException("Invalid encrypted message format")
                }
                val nonce = data.copyOfRange(0, NONCE_SIZE)
                val ciphertext = data.copyOfRange(NONCE_SIZE, data.size)
                return EncryptedMessage(nonce, ciphertext)
            }
        }
    }
    
    data class SessionInfo(
        val peerId: String,
        val isEstablished: Boolean,
        val messagesExchanged: Long,
        val lastActivity: Long
    )
    
    // Native library loading
    init {
        try {
            System.loadLibrary("b4ae_android")
        } catch (e: UnsatisfiedLinkError) {
            throw B4AEException("Failed to load B4AE native library: ${e.message}")
        }
    }
    
    // Native method declarations
    private external fun nativeInit(securityProfile: Int): Long
    private external fun nativeCleanup(clientPtr: Long)
    private external fun nativeGenerateKeypair(clientPtr: Long): ByteArray?
    private external fun nativeEncapsulate(clientPtr: Long, publicKey: ByteArray): ByteArray?
    private external fun nativeDecapsulate(clientPtr: Long, ciphertext: ByteArray, secretKey: ByteArray): ByteArray?
    private external fun nativeSign(clientPtr: Long, data: ByteArray, secretKey: ByteArray): ByteArray?
    private external fun nativeVerify(clientPtr: Long, signature: ByteArray, data: ByteArray, publicKey: ByteArray): Boolean
    private external fun nativeEncrypt(clientPtr: Long, key: ByteArray, plaintext: ByteArray): ByteArray?
    private external fun nativeDecrypt(clientPtr: Long, key: ByteArray, encrypted: ByteArray): ByteArray?
    private external fun nativeHandshake(clientPtr: Long, peerId: ByteArray): ByteArray?
    private external fun nativeCompleteHandshake(clientPtr: Long, peerId: ByteArray, handshakeData: ByteArray): Boolean
    private external fun nativeEncryptMessage(clientPtr: Long, peerId: ByteArray, message: ByteArray): ByteArray?
    private external fun nativeDecryptMessage(clientPtr: Long, peerId: ByteArray, encryptedMessages: ByteArray): ByteArray?
    private external fun nativeGetVersion(): String
    private external fun nativeGetSecurityInfo(clientPtr: Long): String
    
    // Public API methods
    
    /**
     * Initialize B4AE client with security profile
     */
    fun initialize(profile: SecurityProfile = SecurityProfile.STANDARD): B4AEClient {
        val clientPtr = nativeInit(profile.value)
        if (clientPtr == 0L) {
            throw B4AEException("Failed to initialize B4AE client")
        }
        return B4AEClient(clientPtr, profile)
    }
    
    /**
     * Get B4AE library version
     */
    fun getVersion(): String = nativeGetVersion()
    
    /**
     * Get security information
     */
    fun getSecurityInfo(client: B4AEClient): String = nativeGetSecurityInfo(client.clientPtr)
    
    /**
     * Generate quantum-safe keypair (Kyber-1024)
     */
    fun generateKeypair(client: B4AEClient): Keypair {
        val keypairBytes = nativeGenerateKeypair(client.clientPtr)
            ?: throw B4AEException("Failed to generate keypair")
        
        if (keypairBytes.size != KYBER_PUBLIC_KEY_SIZE + KYBER_SECRET_KEY_SIZE) {
            throw B4AEException("Invalid keypair size: ${keypairBytes.size}")
        }
        
        val publicKey = keypairBytes.copyOfRange(0, KYBER_PUBLIC_KEY_SIZE)
        val secretKey = keypairBytes.copyOfRange(KYBER_PUBLIC_KEY_SIZE, keypairBytes.size)
        
        return Keypair(publicKey, secretKey)
    }
    
    /**
     * Perform key encapsulation (Kyber-1024)
     */
    fun encapsulate(client: B4AEClient, publicKey: ByteArray): EncapsulationResult {
        if (publicKey.size != KYBER_PUBLIC_KEY_SIZE) {
            throw B4AEException("Invalid public key size: ${publicKey.size}, expected: $KYBER_PUBLIC_KEY_SIZE")
        }
        
        val resultBytes = nativeEncapsulate(client.clientPtr, publicKey)
            ?: throw B4AEException("Failed to encapsulate")
        
        if (resultBytes.size != KYBER_CIPHERTEXT_SIZE + KYBER_SHARED_SECRET_SIZE) {
            throw B4AEException("Invalid encapsulation result size: ${resultBytes.size}")
        }
        
        val ciphertext = resultBytes.copyOfRange(0, KYBER_CIPHERTEXT_SIZE)
        val sharedSecret = resultBytes.copyOfRange(KYBER_CIPHERTEXT_SIZE, resultBytes.size)
        
        return EncapsulationResult(ciphertext, sharedSecret)
    }
    
    /**
     * Decapsulate shared secret (Kyber-1024)
     */
    fun decapsulate(client: B4AEClient, ciphertext: ByteArray, secretKey: ByteArray): ByteArray {
        if (ciphertext.size != KYBER_CIPHERTEXT_SIZE) {
            throw B4AEException("Invalid ciphertext size: ${ciphertext.size}, expected: $KYBER_CIPHERTEXT_SIZE")
        }
        if (secretKey.size != KYBER_SECRET_KEY_SIZE) {
            throw B4AEException("Invalid secret key size: ${secretKey.size}, expected: $KYBER_SECRET_KEY_SIZE")
        }
        
        return nativeDecapsulate(client.clientPtr, ciphertext, secretKey)
            ?: throw B4AEException("Failed to decapsulate")
    }
    
    /**
     * Sign data with Dilithium5 (post-quantum signature)
     */
    fun sign(client: B4AEClient, data: ByteArray, secretKey: ByteArray): ByteArray {
        if (secretKey.size != DILITHIUM_SECRET_KEY_SIZE) {
            throw B4AEException("Invalid secret key size: ${secretKey.size}, expected: $DILITHIUM_SECRET_KEY_SIZE")
        }
        
        return nativeSign(client.clientPtr, data, secretKey)
            ?: throw B4AEException("Failed to sign data")
    }
    
    /**
     * Verify Dilithium5 signature
     */
    fun verify(client: B4AEClient, signature: ByteArray, data: ByteArray, publicKey: ByteArray): Boolean {
        if (publicKey.size != DILITHIUM_PUBLIC_KEY_SIZE) {
            throw B4AEException("Invalid public key size: ${publicKey.size}, expected: $DILITHIUM_PUBLIC_KEY_SIZE")
        }
        if (signature.size != DILITHIUM_SIGNATURE_SIZE) {
            throw B4AEException("Invalid signature size: ${signature.size}, expected: $DILITHIUM_SIGNATURE_SIZE")
        }
        
        return nativeVerify(client.clientPtr, signature, data, publicKey)
    }
    
    /**
     * Encrypt data with AES-256-GCM
     */
    fun encrypt(client: B4AEClient, key: ByteArray, plaintext: ByteArray): EncryptedMessage {
        if (key.size != KEY_SIZE) {
            throw B4AEException("Invalid key size: ${key.size}, expected: $KEY_SIZE")
        }
        
        val encryptedBytes = nativeEncrypt(client.clientPtr, key, plaintext)
            ?: throw B4AEException("Failed to encrypt data")
        
        return EncryptedMessage.fromByteArray(encryptedBytes)
    }
    
    /**
     * Decrypt data with AES-256-GCM
     */
    fun decrypt(client: B4AEClient, key: ByteArray, encryptedMessage: EncryptedMessage): ByteArray {
        if (key.size != KEY_SIZE) {
            throw B4AEException("Invalid key size: ${key.size}, expected: $KEY_SIZE")
        }
        
        val encryptedBytes = encryptedMessage.toByteArray()
        return nativeDecrypt(client.clientPtr, key, encryptedBytes)
            ?: throw B4AEException("Failed to decrypt data")
    }
    
    /**
     * Perform quantum-safe handshake
     */
    fun performHandshake(client: B4AEClient, peerId: String): ByteArray {
        val peerIdBytes = peerId.toByteArray(Charsets.UTF_8)
        
        return nativeHandshake(client.clientPtr, peerIdBytes)
            ?: throw B4AEHandshakeException("Failed to initiate handshake")
    }
    
    /**
     * Complete handshake response
     */
    fun completeHandshake(client: B4AEClient, peerId: String, handshakeData: ByteArray): Boolean {
        val peerIdBytes = peerId.toByteArray(Charsets.UTF_8)
        
        return nativeCompleteHandshake(client.clientPtr, peerIdBytes, handshakeData)
    }
    
    /**
     * Encrypt message with established session
     */
    fun encryptMessage(client: B4AEClient, peerId: String, message: ByteArray): ByteArray {
        val peerIdBytes = peerId.toByteArray(Charsets.UTF_8)
        
        return nativeEncryptMessage(client.clientPtr, peerIdBytes, message)
            ?: throw B4AESessionException("Failed to encrypt message: session not established or invalid")
    }
    
    /**
     * Decrypt message with established session
     */
    fun decryptMessage(client: B4AEClient, peerId: String, encryptedMessages: ByteArray): ByteArray {
        val peerIdBytes = peerId.toByteArray(Charsets.UTF_8)
        
        return nativeDecryptMessage(client.clientPtr, peerIdBytes, encryptedMessages)
            ?: throw B4AESessionException("Failed to decrypt message: session not established or invalid")
    }
    
    /**
     * B4AE Client wrapper
     */
    class B4AEClient(
        internal val clientPtr: Long,
        val securityProfile: SecurityProfile
    ) {
        private var isDisposed = false
        
        /**
         * Check if client is valid
         */
        fun isValid(): Boolean = !isDisposed && clientPtr != 0L
        
        /**
         * Dispose client and free resources
         */
        fun dispose() {
            if (!isDisposed && clientPtr != 0L) {
                nativeCleanup(clientPtr)
                isDisposed = true
            }
        }
        
        /**
         * Auto-dispose on garbage collection
         */
        protected fun finalize() {
            dispose()
        }
    }
    
    /**
     * Utility functions
     */
    object Utils {
        /**
         * Generate cryptographically secure random bytes
         */
        fun generateRandomBytes(size: Int): ByteArray {
            val bytes = ByteArray(size)
            java.security.SecureRandom().nextBytes(bytes)
            return bytes
        }
        
        /**
         * Convert string to UTF-8 bytes
         */
        fun stringToBytes(text: String): ByteArray = text.toByteArray(Charsets.UTF_8)
        
        /**
         * Convert bytes to UTF-8 string
         */
        fun bytesToString(bytes: ByteArray): String = String(bytes, Charsets.UTF_8)
        
        /**
         * Check if two byte arrays are equal (constant-time)
         */
        fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
            if (a.size != b.size) return false
            var result = 0
            for (i in a.indices) {
                result = result or (a[i].toInt() xor b[i].toInt())
            }
            return result == 0
        }
    }
}