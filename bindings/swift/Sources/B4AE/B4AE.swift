// swift-tools-version: 5.9
import Foundation

// C FFI declarations - link with libb4ae_ffi.a
@_silgen_name("b4ae_free")
private func b4ae_free(_ ptr: UnsafeMutablePointer<UInt8>?)

@_silgen_name("b4ae_generate_key")
private func b4ae_generate_key(_ outLen: UnsafeMutablePointer<Int>) -> UnsafeMutablePointer<UInt8>?

@_silgen_name("b4ae_encrypt")
private func b4ae_encrypt(
    _ key: UnsafePointer<UInt8>?,
    _ keyLen: Int,
    _ plaintext: UnsafePointer<UInt8>?,
    _ plaintextLen: Int,
    _ outLen: UnsafeMutablePointer<Int>?
) -> UnsafeMutablePointer<UInt8>?

@_silgen_name("b4ae_decrypt")
private func b4ae_decrypt(
    _ key: UnsafePointer<UInt8>?,
    _ keyLen: Int,
    _ encrypted: UnsafePointer<UInt8>?,
    _ encryptedLen: Int,
    _ outLen: UnsafeMutablePointer<Int>?
) -> UnsafeMutablePointer<UInt8>?

/// B4AE Swift bindings - AES-256-GCM encrypt/decrypt
/// Links against libb4ae_ffi.a (static library from Rust)
public enum B4AE {

    public static let keySize = 32

    /// Generate random 32-byte key for AES-256-GCM
    public static func generateKey() -> Data {
        var outLen: Int = 0
        guard let ptr = b4ae_generate_key(&outLen), outLen > 0 else {
            fatalError("b4ae_generate_key failed")
        }
        defer { b4ae_free(ptr) }
        return Data(bytes: ptr, count: outLen)
    }

    /// Encrypt plaintext. Returns [nonce(12) || ciphertext]
    public static func encrypt(key: Data, plaintext: Data) throws -> Data {
        guard key.count == keySize else {
            throw B4AEError.invalidKeySize
        }
        var outLen: Int = 0
        let result = key.withUnsafeBytes { k in
            plaintext.withUnsafeBytes { p in
                b4ae_encrypt(
                    k.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    key.count,
                    p.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    plaintext.count,
                    &outLen
                )
            }
        }
        guard let result = result, outLen > 0 else {
            throw B4AEError.encryptionFailed
        }
        defer { b4ae_free(result) }
        return Data(bytes: result, count: outLen)
    }

    /// Decrypt [nonce(12) || ciphertext]
    public static func decrypt(key: Data, encrypted: Data) throws -> Data {
        guard key.count == keySize else {
            throw B4AEError.invalidKeySize
        }
        guard encrypted.count >= 12 else {
            throw B4AEError.encryptedTooShort
        }
        var outLen: Int = 0
        let result = key.withUnsafeBytes { k in
            encrypted.withUnsafeBytes { e in
                b4ae_decrypt(
                    k.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    key.count,
                    e.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    encrypted.count,
                    &outLen
                )
            }
        }
        guard let result = result, outLen > 0 else {
            throw B4AEError.decryptionFailed
        }
        defer { b4ae_free(result) }
        return Data(bytes: result, count: outLen)
    }
}

public enum B4AEError: Error {
    case invalidKeySize
    case encryptedTooShort
    case encryptionFailed
    case decryptionFailed
}
