//! Metadata Encryption Module
//!
//! Handles encryption and decryption of the locker metadata block,
//! which contains the file manifest, directory structure, unlock timestamp,
//! and integrity information.
//!
//! The metadata is serialized to JSON, then encrypted with AES-256-GCM
//! using the dedicated metadata key.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};

use crate::core::error::LockerError;

/// Associated data for metadata encryption
const METADATA_AAD: &[u8] = b"datalocker-metadata-v1";

/// Encrypt a metadata JSON blob.
///
/// # Arguments
/// * `metadata_json` - Serialized metadata as bytes
/// * `key` - 32-byte metadata encryption key
/// * `nonce` - 12-byte unique nonce
///
/// # Returns
/// Encrypted metadata (ciphertext + GCM tag)
pub fn encrypt_metadata(
    metadata_json: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, LockerError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| LockerError::Encryption(format!("Cipher init failed: {}", e)))?;

    let gcm_nonce = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: metadata_json,
        aad: METADATA_AAD,
    };

    cipher
        .encrypt(gcm_nonce, payload)
        .map_err(|e| LockerError::Encryption(format!("Metadata encryption failed: {}", e)))
}

/// Decrypt a metadata blob and return the JSON bytes.
///
/// If decryption fails (wrong key or tampered data), returns an error.
/// This serves as both decryption AND password verification — if the
/// GCM tag validates, the password was correct.
pub fn decrypt_metadata(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, LockerError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| LockerError::Decryption(format!("Cipher init failed: {}", e)))?;

    let gcm_nonce = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext,
        aad: METADATA_AAD,
    };

    cipher.decrypt(gcm_nonce, payload).map_err(|_| {
        LockerError::WrongPassword(
            "Metadata decryption failed: incorrect password or corrupted locker".into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::kdf::generate_nonce;

    #[test]
    fn test_metadata_round_trip() {
        let key = [0xCC; 32];
        let nonce = generate_nonce();
        let metadata = br#"{"version":1,"files":[],"unlock_at":"2026-12-01T00:00:00Z"}"#;

        let encrypted = encrypt_metadata(metadata, &key, &nonce).unwrap();
        let decrypted = decrypt_metadata(&encrypted, &key, &nonce).unwrap();

        assert_eq!(metadata.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_returns_wrong_password_error() {
        let key = [0xCC; 32];
        let wrong_key = [0xDD; 32];
        let nonce = generate_nonce();
        let metadata = b"test metadata";

        let encrypted = encrypt_metadata(metadata, &key, &nonce).unwrap();
        let result = decrypt_metadata(&encrypted, &wrong_key, &nonce);

        assert!(matches!(result, Err(LockerError::WrongPassword(_))));
    }

    #[test]
    fn test_tampered_metadata_fails() {
        let key = [0xCC; 32];
        let nonce = generate_nonce();
        let metadata = b"important metadata";

        let mut encrypted = encrypt_metadata(metadata, &key, &nonce).unwrap();
        encrypted[5] ^= 0xFF; // Tamper

        let result = decrypt_metadata(&encrypted, &key, &nonce);
        assert!(result.is_err());
    }
}
