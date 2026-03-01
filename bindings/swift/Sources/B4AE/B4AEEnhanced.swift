//
//  B4AEEnhanced.swift
//  Enhanced B4AE iOS SDK - Full quantum-safe cryptography support
//

import Foundation

/// B4AE Security Profiles
public enum B4AESecurityProfile: Int32 {
    case standard = 0
    case high = 1
    case maximum = 2
    case enterprise = 3
}

/// B4AE Keypair structure
public struct B4AEKeypair {
    public let publicKey: Data
    public let secretKey: Data
    
    public init(publicKey: Data, secretKey: Data) {
        self.publicKey = publicKey
        self.secretKey = secretKey
    }
}

/// B4AE Encapsulation Result
public struct B4AEEncapsulationResult {
    public let ciphertext: Data
    public let sharedSecret: Data
    
    public init(ciphertext: Data, sharedSecret: Data) {
        self.ciphertext = ciphertext
        self.sharedSecret = sharedSecret
    }
}

/// B4AE Encrypted Message
public struct B4AEEncryptedMessage {
    public let nonce: Data
    public let ciphertext: Data
    
    public init(nonce: Data, ciphertext: Data) {
        self.nonce = nonce
        self.ciphertext = ciphertext
    }
    
    public func toData() -> Data {
        return nonce + ciphertext
    }
    
    public static func fromData(_ data: Data) throws -> B4AEEncryptedMessage {
        guard data.count >= B4AEConstants.nonceSize else {
            throw B4AEError.invalidFormat
        }
        
        let nonce = data.prefix(B4AEConstants.nonceSize)
        let ciphertext = data.suffix(from: B4AEConstants.nonceSize)
        
        return B4AEEncryptedMessage(nonce: nonce, ciphertext: ciphertext)
    }
}

/// B4AE Constants
public struct B4AEConstants {
    public static let keySize = 32
    public static let nonceSize = 12
    public static let kyberPublicKeySize = 1568
    public static let kyberSecretKeySize = 3168
    public static let kyberCiphertextSize = 1568
    public static let kyberSharedSecretSize = 32
    public static let dilithiumPublicKeySize = 2592
    public static let dilithiumSecretKeySize = 4864
    public static let dilithiumSignatureSize = 4595
}

/// B4AE Errors
public enum B4AEError: Error {
    case initializationFailed
    case keyGenerationFailed
    case encryptionFailed
    case decryptionFailed
    case handshakeFailed
    case sessionNotEstablished
    case invalidFormat
    case invalidKeySize
    case invalidParameter
    case nativeError(String)
}

/// Enhanced B4AE iOS SDK
public class B4AEEnhanced {
    
    // MARK: - Properties
    
    private var clientPtr: OpaquePointer?
    private let securityProfile: B4AESecurityProfile
    private let queue = DispatchQueue(label: "com.b4ae.enhanced", qos: .userInitiated)
    
    // MARK: - Initialization
    
    private init(clientPtr: OpaquePointer?, securityProfile: B4AESecurityProfile) {
        self.clientPtr = clientPtr
        self.securityProfile = securityProfile
    }
    
    /// Initialize B4AE with security profile
    public static func initialize(profile: B4AESecurityProfile = .standard) throws -> B4AEEnhanced {
        let clientPtr = b4ae_init_enhanced(profile.rawValue)
        
        guard clientPtr != nil else {
            throw B4AEError.initializationFailed
        }
        
        return B4AEEnhanced(clientPtr: clientPtr, securityProfile: profile)
    }
    
    /// Cleanup resources
    deinit {
        if let clientPtr = clientPtr {
            b4ae_cleanup_enhanced(clientPtr)
        }
    }
    
    // MARK: - Public API
    
    /// Get library version
    public static func getVersion() -> String {
        guard let version = b4ae_get_version_enhanced() else {
            return "unknown"
        }
        return String(cString: version)
    }
    
    /// Get security information
    public func getSecurityInfo() -> String {
        guard let clientPtr = clientPtr else {
            return "Client not initialized"
        }
        
        guard let info = b4ae_get_security_info_enhanced(clientPtr) else {
            return "Security info unavailable"
        }
        
        return String(cString: info)
    }
    
    /// Generate quantum-safe keypair (Kyber-1024)
    public func generateKeypair() throws -> B4AEKeypair {
        guard let clientPtr = clientPtr else {
            throw B4AEError.initializationFailed
        }
        
        var publicKeyData = Data()
        var secretKeyData = Data()
        
        let result = publicKeyData.withUnsafeMutableBytes { publicKeyPtr in
            secretKeyData.withUnsafeMutableBytes { secretKeyPtr in
                b4ae_generate_keypair_enhanced(
                    clientPtr,
                    publicKeyPtr.bindMemory(to: UInt8.self).baseAddress,
                    secretKeyPtr.bindMemory(to: UInt8.self).baseAddress
                )
            }
        }
        
        guard result == 0 else {
            throw B4AEError.keyGenerationFailed
        }
        
        return B4AEKeypair(publicKey: publicKeyData, secretKey: secretKeyData)
    }
    
    /// Perform key encapsulation (Kyber-1024)
    public func encapsulate(publicKey: Data) throws -> B4AEEncapsulationResult {
        guard let clientPtr = clientPtr else {
            throw B4AEError.initializationFailed
        }
        
        guard publicKey.count == B4AEConstants.kyberPublicKeySize else {
            throw B4AEError.invalidKeySize
        }
        
        var ciphertextData = Data(count: B4AEConstants.kyberCiphertextSize)
        var sharedSecretData = Data(count: B4AEConstants.kyberSharedSecretSize)
        
        let result = publicKey.withUnsafeBytes { publicKeyPtr in
            ciphertextData.withUnsafeMutableBytes { ciphertextPtr in
                sharedSecretData.withUnsafeMutableBytes { sharedSecretPtr in
                    b4ae_encapsulate_enhanced(
                        clientPtr,
                        publicKeyPtr.bindMemory(to: UInt8.self).baseAddress,
                        ciphertextPtr.bindMemory(to: UInt8.self).baseAddress,
                        sharedSecretPtr.bindMemory(to: UInt8.self).baseAddress
                    )
                }
            }
        }
        
        guard result == 0 else {
            throw B4AEError.encryptionFailed
        }
        
        return B4AEEncapsulationResult(ciphertext: ciphertextData, sharedSecret: sharedSecretData)
    }
    
    /// Decapsulate shared secret (Kyber-1024)
    public func decapsulate(ciphertext: Data, secretKey: Data) throws -> Data {
        guard let clientPtr = clientPtr else {
            throw B4AEError.initializationFailed
        }
        
        guard ciphertext.count == B4AEConstants.kyberCiphertextSize else {
            throw B4AEError.invalidKeySize
        }
        
        guard secretKey.count == B4AEConstants.kyberSecretKeySize else {
            throw B4AEError.invalidKeySize
        }
        
        var sharedSecretData = Data(count: B4AEConstants.kyberSharedSecretSize)
        
        let result = ciphertext.withUnsafeBytes { ciphertextPtr in
            secretKey.withUnsafeBytes { secretKeyPtr in
                sharedSecretData.withUnsafeMutableBytes { sharedSecretPtr in
                    b4ae_decapsulate_enhanced(
                        clientPtr,
                        ciphertextPtr.bindMemory(to: UInt8.self).baseAddress,
                        secretKeyPtr.bindMemory(to: UInt8.self).baseAddress,
                        sharedSecretPtr.bindMemory(to: UInt8.self).baseAddress
                    )
                }
            }
        }
        
        guard result == 0 else {
            throw B4AEError.decryptionFailed
        }
        
        return sharedSecretData
    }
    
    /// Sign data with Dilithium5 (post-quantum signature)
    public func sign(data: Data, secretKey: Data) throws -> Data {
        guard let clientPtr = clientPtr else {
            throw B4AEError.initializationFailed
        }
        
        guard secretKey.count == B4AEConstants.dilithiumSecretKeySize else {
            throw B4AEError.invalidKeySize
        }
        
        var signatureData = Data(count: B4AEConstants.dilithiumSignatureSize)
        
        let result = data.withUnsafeBytes { dataPtr in
            secretKey.withUnsafeBytes { secretKeyPtr in
                signatureData.withUnsafeMutableBytes { signaturePtr in
                    b4ae_sign_enhanced(
                        clientPtr,
                        dataPtr.bindMemory(to: UInt8.self).baseAddress,
                        UInt(data.count),
                        secretKeyPtr.bindMemory(to: UInt8.self).baseAddress,
                        signaturePtr.bindMemory(to: UInt8.self).baseAddress
                    )
                }
            }
        }
        
        guard result == 0 else {
            throw B4AEError.encryptionFailed
        }
        
        return signatureData
    }
    
    /// Verify Dilithium5 signature
    public func verify(signature: Data, data: Data, publicKey: Data) throws -> Bool {
        guard let clientPtr = clientPtr else {
            throw B4AEError.initializationFailed
        }
        
        guard signature.count == B4AEConstants.dilithiumSignatureSize else {
            throw B4AEError.invalidKeySize
        }
        
        guard publicKey.count == B4AEConstants.dilithiumPublicKeySize else {
            throw B4AEError.invalidKeySize
        }
        
        let result = signature.withUnsafeBytes { signaturePtr in
            data.withUnsafeBytes { dataPtr in
                publicKey.withUnsafeBytes { publicKeyPtr in
                    b4ae_verify_enhanced(
                        clientPtr,
                        signaturePtr.bindMemory(to: UInt8.self).baseAddress,
                        dataPtr.bindMemory(to: UInt8.self).baseAddress,
                        UInt(data.count),
                        publicKeyPtr.bindMemory(to: UInt8.self).baseAddress
                    )
                }
            }
        }
        
        return result != 0
    }
    
    /// Encrypt with AES-256-GCM
    public func encrypt(key: Data, plaintext: Data) throws -> B4AEEncryptedMessage {
        guard let clientPtr = clientPtr else {
            throw B4AEError.initializationFailed
        }
        
        guard key.count == B4AEConstants.keySize else {
            throw B4AEError.invalidKeySize
        }
        
        var encryptedData = Data(count: B4AEConstants.nonceSize + plaintext.count + 16) // nonce + ciphertext + tag
        
        let result = key.withUnsafeBytes { keyPtr in
            plaintext.withUnsafeBytes { plaintextPtr in
                encryptedData.withUnsafeMutableBytes { encryptedPtr in
                    b4ae_encrypt_enhanced(
                        clientPtr,
                        keyPtr.bindMemory(to: UInt8.self).baseAddress,
                        plaintextPtr.bindMemory(to: UInt8.self).baseAddress,
                        UInt(plaintext.count),
                        encryptedPtr.bindMemory(to: UInt8.self).baseAddress
                    )
                }
            }
        }
        
        guard result == 0 else {
            throw B4AEError.encryptionFailed
        }
        
        return try B4AEEncryptedMessage.fromData(encryptedData)
    }
    
    /// Decrypt with AES-256-GCM
    public func decrypt(key: Data, encryptedMessage: B4AEEncryptedMessage) throws -> Data {
        guard let clientPtr = clientPtr else {
            throw B4AEError.initializationFailed
        }
        
        guard key.count == B4AEConstants.keySize else {
            throw B4AEError.invalidKeySize
        }
        
        let encryptedData = encryptedMessage.toData()
        guard encryptedData.count > B4AEConstants.nonceSize else {
            throw B4AEError.invalidFormat
        }
        
        var decryptedData = Data(count: encryptedData.count - B4AEConstants.nonceSize - 16) // Remove nonce and tag
        
        let result = key.withUnsafeBytes { keyPtr in
            encryptedData.withUnsafeBytes { encryptedPtr in
                decryptedData.withUnsafeMutableBytes { decryptedPtr in
                    b4ae_decrypt_enhanced(
                        clientPtr,
                        keyPtr.bindMemory(to: UInt8.self).baseAddress,
                        encryptedPtr.bindMemory(to: UInt8.self).baseAddress,
                        UInt(encryptedData.count),
                        decryptedPtr.bindMemory(to: UInt8.self).baseAddress
                    )
                }
            }
        }
        
        guard result == 0 else {
            throw B4AEError.decryptionFailed
        }
        
        return decryptedData
    }
    
    // MARK: - Utility Methods
    
    /// Generate cryptographically secure random bytes
    public static func generateRandomBytes(count: Int) -> Data {
        var bytes = Data(count: count)
        bytes.withUnsafeMutableBytes { bytesPtr in
            SecRandomCopyBytes(kSecRandomDefault, count, bytesPtr.bindMemory(to: UInt8.self).baseAddress!)
        }
        return bytes
    }
    
    /// Convert string to UTF-8 data
    public static func stringToData(_ string: String) -> Data {
        return string.data(using: .utf8) ?? Data()
    }
    
    /// Convert data to UTF-8 string
    public static func dataToString(_ data: Data) -> String {
        return String(data: data, encoding: .utf8) ?? ""
    }
    
    /// Constant-time comparison of data
    public static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        
        var result = 0
        for i in 0..<a.count {
            result |= Int(a[i]) ^ Int(b[i])
        }
        
        return result == 0
    }
}

// MARK: - Native Function Declarations

// Native function declarations would be implemented in the bridging header
// These are placeholder declarations that would link to the actual C implementation

private func b4ae_init_enhanced(_ profile: Int32) -> OpaquePointer? {
    // Implementation would link to native C/Rust code
    return nil
}

private func b4ae_cleanup_enhanced(_ client: OpaquePointer) {
    // Implementation would link to native C/Rust code
}

private func b4ae_get_version_enhanced() -> UnsafePointer<CChar>? {
    // Implementation would link to native C/Rust code
    return nil
}

private func b4ae_get_security_info_enhanced(_ client: OpaquePointer) -> UnsafePointer<CChar>? {
    // Implementation would link to native C/Rust code
    return nil
}

private func b4ae_generate_keypair_enhanced(
    _ client: OpaquePointer,
    _ publicKey: UnsafeMutablePointer<UInt8>,
    _ secretKey: UnsafeMutablePointer<UInt8>
) -> Int32 {
    // Implementation would link to native C/Rust code
    return -1
}

private func b4ae_encapsulate_enhanced(
    _ client: OpaquePointer,
    _ publicKey: UnsafePointer<UInt8>,
    _ ciphertext: UnsafeMutablePointer<UInt8>,
    _ sharedSecret: UnsafeMutablePointer<UInt8>
) -> Int32 {
    // Implementation would link to native C/Rust code
    return -1
}

private func b4ae_decapsulate_enhanced(
    _ client: OpaquePointer,
    _ ciphertext: UnsafePointer<UInt8>,
    _ secretKey: UnsafePointer<UInt8>,
    _ sharedSecret: UnsafeMutablePointer<UInt8>
) -> Int32 {
    // Implementation would link to native C/Rust code
    return -1
}

private func b4ae_sign_enhanced(
    _ client: OpaquePointer,
    _ data: UnsafePointer<UInt8>,
    _ dataLen: UInt,
    _ secretKey: UnsafePointer<UInt8>,
    _ signature: UnsafeMutablePointer<UInt8>
) -> Int32 {
    // Implementation would link to native C/Rust code
    return -1
}

private func b4ae_verify_enhanced(
    _ client: OpaquePointer,
    _ signature: UnsafePointer<UInt8>,
    _ data: UnsafePointer<UInt8>,
    _ dataLen: UInt,
    _ publicKey: UnsafePointer<UInt8>
) -> Int32 {
    // Implementation would link to native C/Rust code
    return -1
}

private func b4ae_encrypt_enhanced(
    _ client: OpaquePointer,
    _ key: UnsafePointer<UInt8>,
    _ plaintext: UnsafePointer<UInt8>,
    _ plaintextLen: UInt,
    _ encrypted: UnsafeMutablePointer<UInt8>
) -> Int32 {
    // Implementation would link to native C/Rust code
    return -1
}

private func b4ae_decrypt_enhanced(
    _ client: OpaquePointer,
    _ key: UnsafePointer<UInt8>,
    _ encrypted: UnsafePointer<UInt8>,
    _ encryptedLen: UInt,
    _ decrypted: UnsafeMutablePointer<UInt8>
) -> Int32 {
    // Implementation would link to native C/Rust code
    return -1
}