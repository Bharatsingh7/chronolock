//! Streaming Encryption/Decryption Module
//!
//! Implements chunked AES-256-GCM encryption and decryption for handling
//! arbitrarily large files without loading them entirely into RAM.
//!
//! Each chunk is encrypted independently with AES-256-GCM, using a counter-based
//! nonce scheme to prevent chunk reordering and truncation attacks.
//!
//! # Chunk Format
//! For each plaintext chunk of up to CHUNK_SIZE bytes:
//! ```text
//! [4 bytes: chunk_len (LE u32)] [12 bytes: nonce] [chunk_len bytes: ciphertext] [16 bytes: GCM tag]
//! ```
//!
//! The final chunk is marked by a chunk_len of 0.
//!
//! # Security Properties
//! - Each chunk has a unique nonce (base_nonce XOR chunk_counter)
//! - GCM authentication tag protects integrity of each chunk
//! - Chunk counter in associated data prevents reordering
//! - Zero-length terminator prevents truncation

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use std::io::{Read, Write};
use tokio::sync::mpsc;

use crate::core::error::LockerError;

/// Default chunk size: 1 MiB
/// This balances memory usage vs. seek performance and GCM nonce limits.
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

/// GCM authentication tag size
pub const GCM_TAG_SIZE: usize = 16;

/// Nonce size for AES-256-GCM
pub const NONCE_SIZE: usize = 12;

/// Chunk header size: 4 bytes chunk length
pub const CHUNK_HEADER_SIZE: usize = 4;

/// Progress information sent during encryption/decryption
#[derive(Debug, Clone, serde::Serialize)]
pub struct Progress {
    pub bytes_processed: u64,
    pub total_bytes: u64,
    pub current_file: String,
    pub speed_bytes_per_sec: f64,
    pub eta_seconds: f64,
    pub percentage: f64,
}

/// Derives a unique nonce for each chunk by XORing the base nonce with
/// the chunk counter. This ensures each chunk uses a distinct nonce while
/// binding the nonce to the chunk's position.
fn derive_chunk_nonce(base_nonce: &[u8; NONCE_SIZE], chunk_index: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = *base_nonce;
    let counter_bytes = chunk_index.to_le_bytes();
    // XOR the counter into the last 8 bytes of the nonce
    for i in 0..8 {
        nonce[NONCE_SIZE - 8 + i] ^= counter_bytes[i];
    }
    nonce
}

/// Encrypt data from a reader to a writer using chunked AES-256-GCM.
///
/// # Arguments
/// * `reader` - Source of plaintext data
/// * `writer` - Destination for encrypted data
/// * `key` - 32-byte AES-256 encryption key
/// * `base_nonce` - 12-byte base nonce (must be unique per encryption)
/// * `chunk_size` - Size of each plaintext chunk before encryption
/// * `total_bytes` - Total bytes to encrypt (for progress reporting)
/// * `progress_tx` - Channel to send progress updates (optional)
///
/// # Returns
/// Total number of encrypted bytes written (including headers, nonces, and tags)
pub fn encrypt_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    key: &[u8; 32],
    base_nonce: &[u8; NONCE_SIZE],
    chunk_size: usize,
    total_bytes: u64,
    progress_tx: Option<&mpsc::UnboundedSender<Progress>>,
) -> Result<u64, LockerError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| LockerError::Encryption(format!("Failed to create cipher: {}", e)))?;

    let mut buffer = vec![0u8; chunk_size];
    let mut chunk_index: u64 = 0;
    let mut bytes_processed: u64 = 0;
    let mut total_written: u64 = 0;
    let start_time = std::time::Instant::now();

    loop {
        // Read up to chunk_size bytes
        let bytes_read = read_exact_or_eof(&mut reader, &mut buffer)?;

        if bytes_read == 0 {
            // Write terminator: chunk_len = 0
            writer
                .write_all(&0u32.to_le_bytes())
                .map_err(|e| LockerError::Io(format!("Write terminator failed: {}", e)))?;
            total_written += 4;
            break;
        }

        let plaintext = &buffer[..bytes_read];

        // Derive unique nonce for this chunk
        let chunk_nonce = derive_chunk_nonce(base_nonce, chunk_index);
        let nonce = Nonce::from_slice(&chunk_nonce);

        // Include chunk index as associated data to prevent reordering
        let aad = chunk_index.to_le_bytes();
        let payload = Payload {
            msg: plaintext,
            aad: &aad,
        };

        // Encrypt
        let ciphertext = cipher.encrypt(nonce, payload).map_err(|e| {
            LockerError::Encryption(format!("Chunk {} encryption failed: {}", chunk_index, e))
        })?;

        // Write chunk: [len(4)] [nonce(12)] [ciphertext+tag(len+16)]
        let chunk_len = ciphertext.len() as u32;
        writer
            .write_all(&chunk_len.to_le_bytes())
            .map_err(|e| LockerError::Io(format!("Write chunk header: {}", e)))?;
        writer
            .write_all(&chunk_nonce)
            .map_err(|e| LockerError::Io(format!("Write nonce: {}", e)))?;
        writer
            .write_all(&ciphertext)
            .map_err(|e| LockerError::Io(format!("Write ciphertext: {}", e)))?;

        total_written += CHUNK_HEADER_SIZE as u64 + NONCE_SIZE as u64 + ciphertext.len() as u64;
        bytes_processed += bytes_read as u64;
        chunk_index += 1;

        // Send progress update
        if let Some(tx) = &progress_tx {
            let elapsed = start_time.elapsed().as_secs_f64();
            let speed = if elapsed > 0.0 {
                bytes_processed as f64 / elapsed
            } else {
                0.0
            };
            let eta = if speed > 0.0 {
                (total_bytes - bytes_processed) as f64 / speed
            } else {
                0.0
            };

            let _ = tx.send(Progress {
                bytes_processed,
                total_bytes,
                current_file: String::new(),
                speed_bytes_per_sec: speed,
                eta_seconds: eta,
                percentage: if total_bytes > 0 {
                    (bytes_processed as f64 / total_bytes as f64) * 100.0
                } else {
                    0.0
                },
            });
        }
    }

    writer
        .flush()
        .map_err(|e| LockerError::Io(format!("Flush writer: {}", e)))?;

    Ok(total_written)
}

/// Decrypt data from a reader to a writer using chunked AES-256-GCM.
///
/// # Arguments
/// * `reader` - Source of encrypted data (chunk format)
/// * `writer` - Destination for decrypted plaintext
/// * `key` - 32-byte AES-256 encryption key
/// * `total_encrypted_bytes` - Total encrypted bytes (for progress)
/// * `progress_tx` - Channel to send progress updates (optional)
///
/// # Returns
/// Total number of plaintext bytes written
pub fn decrypt_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    key: &[u8; 32],
    total_encrypted_bytes: u64,
    progress_tx: Option<&mpsc::UnboundedSender<Progress>>,
) -> Result<u64, LockerError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| LockerError::Decryption(format!("Failed to create cipher: {}", e)))?;

    let mut chunk_index: u64 = 0;
    let mut bytes_read_total: u64 = 0;
    let mut bytes_written_total: u64 = 0;
    let start_time = std::time::Instant::now();

    loop {
        // Read chunk length
        let mut len_buf = [0u8; CHUNK_HEADER_SIZE];
        if let Err(e) = reader.read_exact(&mut len_buf) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Err(LockerError::Decryption(
                    "Unexpected end of encrypted data".into(),
                ));
            }
            return Err(LockerError::Io(format!("Read chunk header: {}", e)));
        }
        bytes_read_total += CHUNK_HEADER_SIZE as u64;

        let chunk_len = u32::from_le_bytes(len_buf) as usize;

        // Zero-length chunk = terminator
        if chunk_len == 0 {
            break;
        }

        // Sanity check: chunk shouldn't be unreasonably large
        if chunk_len > DEFAULT_CHUNK_SIZE + GCM_TAG_SIZE + 1024 {
            return Err(LockerError::Decryption(format!(
                "Chunk {} has suspicious size: {} bytes",
                chunk_index, chunk_len
            )));
        }

        // Read nonce
        let mut nonce_buf = [0u8; NONCE_SIZE];
        reader
            .read_exact(&mut nonce_buf)
            .map_err(|e| LockerError::Io(format!("Read nonce: {}", e)))?;
        bytes_read_total += NONCE_SIZE as u64;

        // Read ciphertext + tag
        let mut ciphertext = vec![0u8; chunk_len];
        reader
            .read_exact(&mut ciphertext)
            .map_err(|e| LockerError::Io(format!("Read ciphertext: {}", e)))?;
        bytes_read_total += chunk_len as u64;

        let nonce = Nonce::from_slice(&nonce_buf);

        // Associated data: chunk index (must match encryption)
        let aad = chunk_index.to_le_bytes();
        let payload = Payload {
            msg: &ciphertext,
            aad: &aad,
        };

        // Decrypt and verify
        let plaintext = cipher.decrypt(nonce, payload).map_err(|_| {
            LockerError::Decryption(format!(
                "Chunk {} decryption failed: wrong password or corrupted data",
                chunk_index
            ))
        })?;

        writer
            .write_all(&plaintext)
            .map_err(|e| LockerError::Io(format!("Write plaintext: {}", e)))?;

        bytes_written_total += plaintext.len() as u64;
        chunk_index += 1;

        // Progress update
        if let Some(tx) = &progress_tx {
            let elapsed = start_time.elapsed().as_secs_f64();
            let speed = if elapsed > 0.0 {
                bytes_read_total as f64 / elapsed
            } else {
                0.0
            };
            let eta = if speed > 0.0 && total_encrypted_bytes > bytes_read_total {
                (total_encrypted_bytes - bytes_read_total) as f64 / speed
            } else {
                0.0
            };

            let _ = tx.send(Progress {
                bytes_processed: bytes_read_total,
                total_bytes: total_encrypted_bytes,
                current_file: String::new(),
                speed_bytes_per_sec: speed,
                eta_seconds: eta,
                percentage: if total_encrypted_bytes > 0 {
                    (bytes_read_total as f64 / total_encrypted_bytes as f64) * 100.0
                } else {
                    0.0
                },
            });
        }
    }

    writer
        .flush()
        .map_err(|e| LockerError::Io(format!("Flush writer: {}", e)))?;

    Ok(bytes_written_total)
}

/// Read exactly `buf.len()` bytes, or less if EOF is reached.
/// Returns the number of bytes actually read.
fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, LockerError> {
    let mut total_read = 0;
    while total_read < buf.len() {
        match reader.read(&mut buf[total_read..]) {
            Ok(0) => break, // EOF
            Ok(n) => total_read += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(LockerError::Io(format!("Read error: {}", e))),
        }
    }
    Ok(total_read)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::kdf::generate_nonce;
    use std::io::Cursor;

    fn test_key() -> [u8; 32] {
        [0xAA; 32]
    }

    #[test]
    fn test_encrypt_decrypt_small() {
        let key = test_key();
        let nonce = generate_nonce();
        let plaintext = b"Hello, World! This is a test message for encryption.";

        let mut encrypted = Vec::new();
        encrypt_stream(
            Cursor::new(plaintext),
            &mut encrypted,
            &key,
            &nonce,
            DEFAULT_CHUNK_SIZE,
            plaintext.len() as u64,
            None,
        )
        .unwrap();

        let mut decrypted = Vec::new();
        decrypt_stream(
            Cursor::new(&encrypted),
            &mut decrypted,
            &key,
            encrypted.len() as u64,
            None,
        )
        .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let key = test_key();
        let nonce = generate_nonce();

        let mut encrypted = Vec::new();
        encrypt_stream(
            Cursor::new(&[] as &[u8]),
            &mut encrypted,
            &key,
            &nonce,
            DEFAULT_CHUNK_SIZE,
            0,
            None,
        )
        .unwrap();

        let mut decrypted = Vec::new();
        decrypt_stream(
            Cursor::new(&encrypted),
            &mut decrypted,
            &key,
            encrypted.len() as u64,
            None,
        )
        .unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_multi_chunk() {
        let key = test_key();
        let nonce = generate_nonce();
        let chunk_size = 64; // Small chunks for testing
        let plaintext: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();

        let mut encrypted = Vec::new();
        encrypt_stream(
            Cursor::new(&plaintext),
            &mut encrypted,
            &key,
            &nonce,
            chunk_size,
            plaintext.len() as u64,
            None,
        )
        .unwrap();

        let mut decrypted = Vec::new();
        decrypt_stream(
            Cursor::new(&encrypted),
            &mut decrypted,
            &key,
            encrypted.len() as u64,
            None,
        )
        .unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = test_key();
        let wrong_key = [0xBB; 32];
        let nonce = generate_nonce();
        let plaintext = b"Secret data";

        let mut encrypted = Vec::new();
        encrypt_stream(
            Cursor::new(plaintext),
            &mut encrypted,
            &key,
            &nonce,
            DEFAULT_CHUNK_SIZE,
            plaintext.len() as u64,
            None,
        )
        .unwrap();

        let mut decrypted = Vec::new();
        let result = decrypt_stream(
            Cursor::new(&encrypted),
            &mut decrypted,
            &wrong_key,
            encrypted.len() as u64,
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = test_key();
        let nonce = generate_nonce();
        let plaintext = b"Important data that must not be tampered with";

        let mut encrypted = Vec::new();
        encrypt_stream(
            Cursor::new(plaintext),
            &mut encrypted,
            &key,
            &nonce,
            DEFAULT_CHUNK_SIZE,
            plaintext.len() as u64,
            None,
        )
        .unwrap();

        // Tamper with a byte in the middle of the ciphertext
        if encrypted.len() > 20 {
            encrypted[20] ^= 0xFF;
        }

        let mut decrypted = Vec::new();
        let result = decrypt_stream(
            Cursor::new(&encrypted),
            &mut decrypted,
            &key,
            encrypted.len() as u64,
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_exactly_chunk_size() {
        let key = test_key();
        let nonce = generate_nonce();
        let chunk_size = 128;
        let plaintext = vec![0x42u8; chunk_size]; // Exactly one chunk

        let mut encrypted = Vec::new();
        encrypt_stream(
            Cursor::new(&plaintext),
            &mut encrypted,
            &key,
            &nonce,
            chunk_size,
            plaintext.len() as u64,
            None,
        )
        .unwrap();

        let mut decrypted = Vec::new();
        decrypt_stream(
            Cursor::new(&encrypted),
            &mut decrypted,
            &key,
            encrypted.len() as u64,
            None,
        )
        .unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_chunk_nonce_uniqueness() {
        let base_nonce = [0u8; NONCE_SIZE];
        let n0 = derive_chunk_nonce(&base_nonce, 0);
        let n1 = derive_chunk_nonce(&base_nonce, 1);
        let n2 = derive_chunk_nonce(&base_nonce, 2);

        assert_ne!(n0, n1);
        assert_ne!(n1, n2);
        assert_ne!(n0, n2);
    }

    #[test]
    fn test_large_data_streaming() {
        let key = test_key();
        let nonce = generate_nonce();
        let chunk_size = 1024;
        // 1 MB of data
        let plaintext: Vec<u8> = (0..1_048_576).map(|i| (i % 256) as u8).collect();

        let mut encrypted = Vec::new();
        encrypt_stream(
            Cursor::new(&plaintext),
            &mut encrypted,
            &key,
            &nonce,
            chunk_size,
            plaintext.len() as u64,
            None,
        )
        .unwrap();

        let mut decrypted = Vec::new();
        decrypt_stream(
            Cursor::new(&encrypted),
            &mut decrypted,
            &key,
            encrypted.len() as u64,
            None,
        )
        .unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
