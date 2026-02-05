// B4AE Traffic Padding Implementation
// PKCS#7-style padding with configurable block sizes

use crate::error::{B4aeError, B4aeResult};

/// Apply PKCS#7-style padding to message
/// 
/// Pads the message to the nearest multiple of block_size.
/// The padding bytes contain the number of padding bytes added.
pub fn apply_padding(message: &[u8], block_size: usize) -> B4aeResult<Vec<u8>> {
    if block_size == 0 || block_size > 65536 {
        return Err(B4aeError::InvalidInput("Invalid block size".to_string()));
    }

    let message_len = message.len();
    let padding_needed = block_size - (message_len % block_size);
    
    // Always add at least 1 byte of padding (PKCS#7 requirement)
    let padding_needed = if padding_needed == 0 {
        block_size
    } else {
        padding_needed
    };

    // For large block sizes, use a different padding scheme
    // Store padding length in last 2 bytes (big-endian)
    if padding_needed > 255 {
        let mut padded = Vec::with_capacity(message_len + padding_needed);
        padded.extend_from_slice(message);
        // Fill with zeros
        padded.resize(message_len + padding_needed - 2, 0);
        // Store padding length in last 2 bytes
        padded.extend_from_slice(&(padding_needed as u16).to_be_bytes());
        return Ok(padded);
    }

    // Standard PKCS#7 padding for small block sizes
    let mut padded = Vec::with_capacity(message_len + padding_needed);
    padded.extend_from_slice(message);
    padded.resize(message_len + padding_needed, padding_needed as u8);

    Ok(padded)
}

/// Remove PKCS#7-style padding from message
pub fn remove_padding(padded: &[u8]) -> B4aeResult<Vec<u8>> {
    if padded.len() < 2 {
        return Err(B4aeError::InvalidInput("Padded message too short".to_string()));
    }

    // Check if this is large padding (stored in last 2 bytes)
    let last_byte = *padded.last().unwrap();
    let second_last = padded[padded.len() - 2];
    
    // Try to parse as 2-byte padding length
    let potential_large_padding = u16::from_be_bytes([second_last, last_byte]) as usize;
    
    // If potential padding length is > 255 and valid, it's large padding
    if potential_large_padding > 255 && potential_large_padding <= padded.len() {
        let message_len = padded.len() - potential_large_padding;
        return Ok(padded[..message_len].to_vec());
    }

    // Otherwise, standard PKCS#7 padding
    let padding_len = last_byte as usize;

    if padding_len == 0 || padding_len > padded.len() {
        return Err(B4aeError::InvalidInput("Invalid padding length".to_string()));
    }

    // Verify all padding bytes are correct
    let start = padded.len() - padding_len;
    for &byte in &padded[start..] {
        if byte != padding_len as u8 {
            return Err(B4aeError::InvalidInput("Invalid padding bytes".to_string()));
        }
    }

    Ok(padded[..start].to_vec())
}

/// Apply random padding within a range
/// 
/// Adds random amount of padding between min_size and max_size.
/// This provides additional obfuscation beyond fixed block padding.
pub fn apply_random_padding(message: &[u8], min_size: usize, max_size: usize) -> B4aeResult<Vec<u8>> {
    use crate::crypto::random::random_range;

    if min_size > max_size {
        return Err(B4aeError::InvalidInput("min_size > max_size".to_string()));
    }

    let message_len = message.len();
    let target_size = message_len + min_size + (random_range((max_size - min_size) as u64) as usize);
    let padding_needed = target_size - message_len;

    if padding_needed > 65535 {
        return Err(B4aeError::InvalidInput("Padding size too large".to_string()));
    }

    // Use 2-byte length prefix for random padding
    let mut padded = Vec::with_capacity(message_len + padding_needed + 2);
    padded.extend_from_slice(message);
    
    // Add padding length as 2-byte big-endian
    padded.extend_from_slice(&(padding_needed as u16).to_be_bytes());
    
    // Add random padding bytes
    let mut padding_bytes = vec![0u8; padding_needed];
    crate::crypto::random::fill_random(&mut padding_bytes)
        .map_err(|e| B4aeError::CryptoError(format!("Random generation failed: {}", e)))?;
    padded.extend_from_slice(&padding_bytes);

    Ok(padded)
}

/// Remove random padding
pub fn remove_random_padding(padded: &[u8]) -> B4aeResult<Vec<u8>> {
    if padded.len() < 2 {
        return Err(B4aeError::InvalidInput("Message too short for random padding".to_string()));
    }

    // Find padding length (2 bytes before padding starts)
    let message_len = padded.len();
    
    // Try to find the length marker by scanning backwards
    // The length marker is 2 bytes that indicate how many bytes follow
    for i in (2..message_len).rev() {
        let padding_len = u16::from_be_bytes([padded[i-2], padded[i-1]]) as usize;
        
        if i + padding_len == message_len {
            // Found valid padding length
            return Ok(padded[..i-2].to_vec());
        }
    }

    Err(B4aeError::InvalidInput("Could not find valid padding marker".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7_padding() {
        let message = b"Hello, B4AE!";
        let block_size = 16;

        let padded = apply_padding(message, block_size).unwrap();
        assert_eq!(padded.len() % block_size, 0);
        assert!(padded.len() >= message.len());

        let unpadded = remove_padding(&padded).unwrap();
        assert_eq!(message, unpadded.as_slice());
    }

    #[test]
    fn test_padding_exact_block() {
        let message = b"0123456789ABCDEF"; // Exactly 16 bytes
        let block_size = 16;

        let padded = apply_padding(message, block_size).unwrap();
        // Should add full block of padding
        assert_eq!(padded.len(), 32);

        let unpadded = remove_padding(&padded).unwrap();
        assert_eq!(message, unpadded.as_slice());
    }

    #[test]
    fn test_random_padding() {
        let message = b"Test message";
        let min_size = 10;
        let max_size = 100;

        let padded = apply_random_padding(message, min_size, max_size).unwrap();
        assert!(padded.len() >= message.len() + min_size);
        assert!(padded.len() <= message.len() + max_size + 2); // +2 for length prefix

        let unpadded = remove_random_padding(&padded).unwrap();
        assert_eq!(message, unpadded.as_slice());
    }

    #[test]
    fn test_invalid_padding() {
        let invalid = vec![1, 2, 3, 5]; // Last byte says 5 padding bytes, but only 4 total
        assert!(remove_padding(&invalid).is_err());

        let invalid2 = vec![1, 2, 3, 2, 3]; // Last byte says 3, but previous bytes don't match
        assert!(remove_padding(&invalid2).is_err());
    }

    #[test]
    fn test_empty_message() {
        let empty: &[u8] = &[];
        let padded = apply_padding(empty, 16).unwrap();
        assert_eq!(padded.len(), 16);

        let unpadded = remove_padding(&padded).unwrap();
        assert_eq!(empty, unpadded.as_slice());
    }
}
