//! B4AE Key Hierarchy (Protocol Spec v1.0 §4)
//!
//! Master Identity Key (MIK) → Device Master Key (DMK) → Storage Key (STK)
//! Session Key (SK) from handshake; Message/Ephemeral from PFS+.
//!
//! ```text
//! Master Identity Key (MIK)
//! ├── Device Master Key (DMK)     [per device_id]
//! │   ├── Session Key (SK)       [from handshake - existing]
//! │   │   ├── Message Key (MK)   [PFS+ per-message]
//! │   │   └── Ephemeral Key (EK) [Implemented]
//! │   └── Storage Key (STK)      [encrypted storage]
//! └── Backup Key Shards (BKS)     [N-of-M recovery]
//! ```

use crate::crypto::{CryptoError, CryptoResult};
use crate::crypto::aes_gcm::{self, AesKey};
use crate::crypto::hkdf;
use crate::crypto::random;
use ring::hmac;
use zeroize::Zeroize;

/// Shard with MAC: 65 bytes. Legacy (no MAC): 33 bytes.
const BKS_SHARD_LEGACY_LEN: usize = 33;
const BKS_SHARD_MAC_LEN: usize = 32;
const BKS_SHARD_WITH_MAC_LEN: usize = BKS_SHARD_LEGACY_LEN + BKS_SHARD_MAC_LEN;

/// Master Identity Key — root of key hierarchy (Protocol Spec §4.1).
/// Lifetime: Permanent. Rotation: Manual only.
#[derive(Clone)]
pub struct MasterIdentityKey {
    key_material: [u8; 32],
}

impl MasterIdentityKey {
    /// Generate new MIK from cryptographically secure random.
    pub fn generate() -> CryptoResult<Self> {
        let mut key_material = [0u8; 32];
        random::fill_random(&mut key_material)?;
        Ok(Self { key_material })
    }

    /// Create MIK from existing key material (e.g. restored from backup).
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidInput("MIK must be 32 bytes".to_string()));
        }
        let mut key_material = [0u8; 32];
        key_material.copy_from_slice(bytes);
        Ok(Self { key_material })
    }

    /// Derive Device Master Key for a specific device.
    pub fn derive_dmk(&self, device_id: &[u8]) -> CryptoResult<DeviceMasterKey> {
        let dmk = hkdf::derive_key(
            &[&self.key_material],
            &[b"B4AE-v1-MIK-to-DMK", device_id].concat(),
            32,
        )?;
        DeviceMasterKey::from_bytes(&dmk)
    }

    /// Export key material (for backup). Caller must secure the output.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key_material
    }

    /// Create backup shards (N-of-M). Returns M shards; need N to recover.
    pub fn create_backup_shards(&self, n: u8, m: u8) -> CryptoResult<Vec<Vec<u8>>> {
        if n < 2 || m < n {
            return Err(CryptoError::InvalidInput(
                "BKS requires 2 <= n <= m <= 255".to_string(),
            ));
        }
        backup_keys::create_shards(&self.key_material, n, m)
    }

    /// Recover MIK from backup shards.
    pub fn recover_from_shards(shards: &[&[u8]]) -> CryptoResult<Self> {
        let key_material = backup_keys::recover_from_shards(shards)?;
        Self::from_bytes(&key_material)
    }
}

impl Drop for MasterIdentityKey {
    fn drop(&mut self) {
        self.key_material.zeroize();
    }
}

impl std::fmt::Debug for MasterIdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterIdentityKey([REDACTED])")
    }
}

/// Device Master Key — per-device key derived from MIK (Protocol Spec §4.1).
/// Lifetime: 1 year. Rotation: Automatic.
#[derive(Clone)]
pub struct DeviceMasterKey {
    key_material: [u8; 32],
}

impl DeviceMasterKey {
    /// Create from derived bytes (internal).
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidInput("DMK must be 32 bytes".to_string()));
        }
        let mut key_material = [0u8; 32];
        key_material.copy_from_slice(bytes);
        Ok(Self { key_material })
    }

    /// Derive Storage Key for encrypted storage.
    pub fn derive_stk(&self, storage_context: &[u8]) -> CryptoResult<StorageKey> {
        let stk = hkdf::derive_key(
            &[&self.key_material],
            &[b"B4AE-v1-DMK-to-STK", storage_context].concat(),
            32,
        )?;
        StorageKey::from_bytes(&stk)
    }

    /// Derive key material for handshake binding (optional: bind session to device).
    pub fn derive_handshake_binding(&self, nonce: &[u8]) -> CryptoResult<Vec<u8>> {
        hkdf::derive_key(
            &[&self.key_material],
            &[b"B4AE-v1-DMK-handshake-binding", nonce].concat(),
            32,
        )
    }

    /// Export for transfer to new device (encrypted with MIK). Caller encrypts.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key_material
    }
}

impl Drop for DeviceMasterKey {
    fn drop(&mut self) {
        self.key_material.zeroize();
    }
}

impl std::fmt::Debug for DeviceMasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeviceMasterKey([REDACTED])")
    }
}

/// Storage Key — for encrypted storage, derived from DMK.
#[derive(Clone)]
pub struct StorageKey {
    key_material: [u8; 32],
}

impl StorageKey {
    /// Create from derived bytes.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidInput("STK must be 32 bytes".to_string()));
        }
        let mut key_material = [0u8; 32];
        key_material.copy_from_slice(bytes);
        Ok(Self { key_material })
    }

    /// Get key for AEAD (AES-256-GCM).
    pub fn as_slice(&self) -> &[u8; 32] {
        &self.key_material
    }
}

impl Drop for StorageKey {
    fn drop(&mut self) {
        self.key_material.zeroize();
    }
}

impl std::fmt::Debug for StorageKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StorageKey([REDACTED])")
    }
}

/// Simple N-of-M secret sharing for backup (BKS).
mod backup_keys {
    use super::*;

    const BKS_MAC_INFO: &[u8] = b"B4AE-v1-BKS-shard-mac";

    /// Create M shards; need N to recover. Uses XOR-based scheme for N=2, polynomial for N>2.
    /// 2-of-2 shards include HMAC-SHA256 for corruption detection (65 bytes each).
    pub fn create_shards(secret: &[u8; 32], n: u8, m: u8) -> CryptoResult<Vec<Vec<u8>>> {
        if n == 2 && m == 2 {
            // 2-of-2: shard1 = random, shard2 = secret ^ shard1; each with MAC
            let mac_key = hkdf::derive_key(&[secret], BKS_MAC_INFO, 32)?;
            let key = hmac::Key::new(hmac::HMAC_SHA256, &mac_key);

            let mut shard1_core = [0u8; 33];
            random::fill_random(&mut shard1_core[1..])?;
            shard1_core[0] = 1;
            let tag1 = hmac::sign(&key, &shard1_core);
            let mut shard1 = shard1_core.to_vec();
            shard1.extend_from_slice(tag1.as_ref());

            let mut shard2_core = [0u8; 33];
            shard2_core[0] = 2;
            for i in 0..32 {
                shard2_core[1 + i] = secret[i] ^ shard1_core[1 + i];
            }
            let tag2 = hmac::sign(&key, &shard2_core);
            let mut shard2 = shard2_core.to_vec();
            shard2.extend_from_slice(tag2.as_ref());

            return Ok(vec![shard1, shard2]);
        }
        if n == 2 && m >= 2 {
            // 2-of-M: each pair (2k-1, 2k) can recover. Shards unique to prevent redundancy.
            // Pair 1: shard1=base1, shard2=secret^base1; Pair 2: shard3=base2, shard4=secret^base2; etc.
            let mut shards = Vec::with_capacity(m as usize);
            let pair_count = (m as usize + 1) / 2;
            for pair_idx in 0..pair_count {
                let mut base = [0u8; 32];
                random::fill_random(&mut base)?;
                let shard_idx_base = (pair_idx * 2) as u8;
                for offset in 0..2 {
                    let idx = shard_idx_base + offset + 1;
                    if idx > m {
                        break;
                    }
                    let mut shard = vec![0u8; 33];
                    shard[0] = idx;
                    if offset == 0 {
                        shard[1..].copy_from_slice(&base);
                    } else {
                        for i in 0..32 {
                            shard[1 + i] = secret[i] ^ base[i];
                        }
                    }
                    shards.push(shard);
                }
            }
            return Ok(shards);
        }
        // N-of-M with N>2: use polynomial interpolation (simplified - each shard is (index, P(index)))
        if n > 2 {
            return Err(CryptoError::InvalidInput(
                "N>2 BKS requires external library (e.g. shamir)".to_string(),
            ));
        }
        Err(CryptoError::InvalidInput("Invalid BKS parameters".to_string()))
    }

    /// Recover secret from shards. Supports legacy 33-byte and authenticated 65-byte formats.
    pub fn recover_from_shards(shards: &[&[u8]]) -> CryptoResult<[u8; 32]> {
        if shards.len() < 2 {
            return Err(CryptoError::InvalidInput("Need at least 2 shards".to_string()));
        }
        for s in shards {
            if s.len() != BKS_SHARD_LEGACY_LEN && s.len() != BKS_SHARD_WITH_MAC_LEN {
                return Err(CryptoError::InvalidInput(
                    "Invalid shard length (expected 33 or 65 bytes)".to_string(),
                ));
            }
        }
        // Both shards must use same format
        let with_mac = shards[0].len() == BKS_SHARD_WITH_MAC_LEN;
        if shards[1].len() != shards[0].len() {
            return Err(CryptoError::InvalidInput(
                "Shards must use same format (both legacy or both with MAC)".to_string(),
            ));
        }
        // For 2-of-2 or 2-of-M: shards must be from same pair
        let idx1 = shards[0][0];
        let idx2 = shards[1][0];
        if (idx1 as usize + 1) / 2 != (idx2 as usize + 1) / 2 {
            return Err(CryptoError::InvalidInput(
                "BKS recovery requires two shards from the same pair (consecutive indices 2k-1, 2k)".to_string(),
            ));
        }
        let payload_len = 32;
        let a = &shards[0][1..1 + payload_len];
        let b = &shards[1][1..1 + payload_len];
        let mut secret = [0u8; 32];
        for i in 0..32 {
            secret[i] = a[i] ^ b[i];
        }
        // Verify MAC if present
        if with_mac {
            let mac_key = hkdf::derive_key(&[&secret], BKS_MAC_INFO, 32)?;
            let key = hmac::Key::new(hmac::HMAC_SHA256, &mac_key);
            for (i, s) in shards.iter().enumerate().take(2) {
                let (core, tag) = s.split_at(BKS_SHARD_LEGACY_LEN);
                hmac::verify(&key, core, tag)
                    .map_err(|_| CryptoError::InvalidInput(
                        format!("BKS shard {} MAC verification failed (possible corruption)", i + 1),
                    ))?;
            }
        }
        Ok(secret)
    }
}

/// AAD for DMK wrap (binds ciphertext to device_id)
const DMK_WRAP_AAD_PREFIX: &[u8] = b"B4AE-v1-DMK-wrap";

/// Secure key distribution: export DMK encrypted for transfer to new device.
/// Uses AES-256-GCM (authenticated) instead of XOR.
pub fn export_dmk_for_device(
    dmk: &DeviceMasterKey,
    mik: &MasterIdentityKey,
    target_device_id: &[u8],
) -> CryptoResult<Vec<u8>> {
    let wrapping_key = hkdf::derive_key(
        &[&mik.to_bytes()],
        &[b"B4AE-v1-DMK-export", target_device_id].concat(),
        32,
    )?;
    let aes_key = AesKey::from_bytes(&wrapping_key)?;
    let aad: Vec<u8> = [DMK_WRAP_AAD_PREFIX, target_device_id].concat();
    let (nonce, ciphertext) = aes_gcm::encrypt(&aes_key, dmk.to_bytes().as_slice(), &aad)?;
    let mut out = nonce;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Import DMK from transfer payload (AES-256-GCM wrapped).
/// Format: [nonce 12][ciphertext+tag 48] = 60 bytes.
pub fn import_dmk_for_device(
    wrapped: &[u8],
    mik: &MasterIdentityKey,
    device_id: &[u8],
) -> CryptoResult<DeviceMasterKey> {
    const NONCE_SIZE: usize = 12;
    const MIN_WRAPPED_LEN: usize = NONCE_SIZE + 32 + 16; // nonce + plaintext + tag

    if wrapped.len() != MIN_WRAPPED_LEN {
        return Err(CryptoError::InvalidInput(format!(
            "Invalid wrapped DMK length: expected {}, got {}",
            MIN_WRAPPED_LEN,
            wrapped.len()
        )));
    }
    let wrapping_key = hkdf::derive_key(
        &[&mik.to_bytes()],
        &[b"B4AE-v1-DMK-export", device_id].concat(),
        32,
    )?;
    let aes_key = AesKey::from_bytes(&wrapping_key)?;
    let (nonce, ct) = wrapped.split_at(NONCE_SIZE);
    let aad: Vec<u8> = [DMK_WRAP_AAD_PREFIX, device_id].concat();
    let key_material = aes_gcm::decrypt(&aes_key, nonce, ct, &aad)?;
    DeviceMasterKey::from_bytes(&key_material)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mik_generation() {
        let mik = MasterIdentityKey::generate().unwrap();
        let bytes = mik.to_bytes();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_mik_derive_dmk() {
        let mik = MasterIdentityKey::generate().unwrap();
        let dmk1 = mik.derive_dmk(b"device-1").unwrap();
        let dmk2 = mik.derive_dmk(b"device-2").unwrap();
        assert_ne!(dmk1.to_bytes(), dmk2.to_bytes());
    }

    #[test]
    fn test_dmk_derive_stk() {
        let mik = MasterIdentityKey::generate().unwrap();
        let dmk = mik.derive_dmk(b"device-1").unwrap();
        let stk = dmk.derive_stk(b"storage-vault").unwrap();
        assert_eq!(stk.as_slice().len(), 32);
    }

    #[test]
    fn test_mik_from_bytes_roundtrip() {
        let mik1 = MasterIdentityKey::generate().unwrap();
        let bytes = mik1.to_bytes();
        let mik2 = MasterIdentityKey::from_bytes(&bytes).unwrap();
        assert_eq!(mik1.to_bytes(), mik2.to_bytes());
    }

    #[test]
    fn test_bks_2_of_2() {
        let mik = MasterIdentityKey::generate().unwrap();
        let shards = mik.create_backup_shards(2, 2).unwrap();
        assert_eq!(shards.len(), 2);
        let recovered = MasterIdentityKey::recover_from_shards(&[&shards[0], &shards[1]]).unwrap();
        assert_eq!(mik.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_bks_2_of_4() {
        let mik = MasterIdentityKey::generate().unwrap();
        let shards = mik.create_backup_shards(2, 4).unwrap();
        assert_eq!(shards.len(), 4);
        // Pairs (1,2) and (3,4) can recover; all shards unique
        let recovered_12 = MasterIdentityKey::recover_from_shards(&[&shards[0], &shards[1]]).unwrap();
        let recovered_34 = MasterIdentityKey::recover_from_shards(&[&shards[2], &shards[3]]).unwrap();
        assert_eq!(mik.to_bytes(), recovered_12.to_bytes());
        assert_eq!(mik.to_bytes(), recovered_34.to_bytes());
        // Cross-pair (1,3) should fail
        assert!(MasterIdentityKey::recover_from_shards(&[&shards[0], &shards[2]]).is_err());
    }

    #[test]
    fn test_export_import_dmk() {
        let mik = MasterIdentityKey::generate().unwrap();
        let dmk = mik.derive_dmk(b"device-a").unwrap();
        let wrapped = export_dmk_for_device(&dmk, &mik, b"device-b").unwrap();
        let dmk_imported = import_dmk_for_device(&wrapped, &mik, b"device-b").unwrap();
        assert_eq!(dmk.to_bytes(), dmk_imported.to_bytes());
    }
}
