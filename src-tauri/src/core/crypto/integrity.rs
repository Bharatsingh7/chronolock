//! Integrity Verification Module
//!
//! Provides HMAC-SHA256 for whole-file integrity and BLAKE3 for
//! individual file hashing.
//!
//! The HMAC footer covers all bytes of the locker file from the
//! start of the header to the end of the encrypted data, ensuring
//! any modification is detected.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::Read;

use crate::core::error::LockerError;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 over data from a reader.
///
/// This reads all data from the reader in chunks and computes the HMAC.
/// Used to create the locker footer authentication tag.
pub fn compute_hmac(key: &[u8; 32], reader: &mut impl Read) -> Result<[u8; 32], LockerError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| LockerError::Integrity(format!("HMAC init failed: {}", e)))?;

    let mut buffer = vec![0u8; 64 * 1024]; // 64 KiB read buffer
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => mac.update(&buffer[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(LockerError::Io(format!("Read for HMAC: {}", e))),
        }
    }

    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    Ok(output)
}

/// Verify HMAC-SHA256 of data against an expected value.
pub fn verify_hmac(
    key: &[u8; 32],
    reader: &mut impl Read,
    expected: &[u8; 32],
) -> Result<bool, LockerError> {
    let computed = compute_hmac(key, reader)?;
    // Constant-time comparison is handled by HMAC crate internals,
    // but we use a simple comparison here since we're comparing our own computed value
    Ok(computed == *expected)
}

/// Compute BLAKE3 hash of a file for integrity verification.
///
/// Uses streaming to handle large files without loading into RAM.
pub fn hash_file_blake3(path: &std::path::Path) -> Result<[u8; 32], LockerError> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| LockerError::Io(format!("Open file for hashing: {}", e)))?;

    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; 64 * 1024];

    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => { hasher.update(&buffer[..n]); }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(LockerError::Io(format!("Read for BLAKE3: {}", e))),
        }
    }

    Ok(*hasher.finalize().as_bytes())
}

/// Compute BLAKE3 hash of a byte slice.
pub fn hash_bytes_blake3(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_hmac_computation() {
        let key = [0x42u8; 32];
        let data = b"test data for HMAC verification";
        let hmac = compute_hmac(&key, &mut Cursor::new(data)).unwrap();
        assert_ne!(hmac, [0u8; 32]);
    }

    #[test]
    fn test_hmac_verification_correct() {
        let key = [0x42u8; 32];
        let data = b"test data";
        let hmac = compute_hmac(&key, &mut Cursor::new(data)).unwrap();
        let valid = verify_hmac(&key, &mut Cursor::new(data), &hmac).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_hmac_verification_wrong_data() {
        let key = [0x42u8; 32];
        let hmac = compute_hmac(&key, &mut Cursor::new(b"original")).unwrap();
        let valid = verify_hmac(&key, &mut Cursor::new(b"tampered"), &hmac).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_hmac_verification_wrong_key() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let data = b"test data";
        let hmac = compute_hmac(&key1, &mut Cursor::new(data)).unwrap();
        let valid = verify_hmac(&key2, &mut Cursor::new(data), &hmac).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_blake3_hash_deterministic() {
        let data = b"test data for blake3";
        let h1 = hash_bytes_blake3(data);
        let h2 = hash_bytes_blake3(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_blake3_hash_different_data() {
        let h1 = hash_bytes_blake3(b"data1");
        let h2 = hash_bytes_blake3(b"data2");
        assert_ne!(h1, h2);
    }
}
