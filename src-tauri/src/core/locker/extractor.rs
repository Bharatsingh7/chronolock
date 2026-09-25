//! Locker Extractor
//!
//! Handles opening and extracting files from a `.locker` file:
//! 1. Read and validate header
//! 2. Derive keys from password
//! 3. Verify HMAC integrity
//! 4. Decrypt metadata
//! 5. Check timer
//! 6. Stream-decrypt file data
//! 7. Verify extracted files with BLAKE3
//!
//! The locker file is never modified during extraction.

use chrono::{DateTime, Utc};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use tokio::sync::mpsc;

use crate::core::crypto::{
    integrity,
    kdf,
    metadata as meta_crypto,
    stream::{self, Progress},
};
use crate::core::error::LockerError;
use crate::core::locker::format::{LockerHeader, HEADER_SIZE, HMAC_SIZE};
use crate::core::locker::manifest::LockerMetadata;

/// Information about a locker, retrieved without full decryption.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LockerInfo {
    pub file_count: u32,
    pub dir_count: u32,
    pub total_original_size: u64,
    pub encrypted_size: u64,
    pub unlock_at: Option<String>,
    pub locker_name: Option<String>,
    pub is_unlockable: bool,
    pub remaining_seconds: i64,
}

/// Read the header from a locker file (no password needed).
pub fn read_locker_header(locker_path: &Path) -> Result<LockerHeader, LockerError> {
    let mut file = File::open(locker_path)
        .map_err(|e| LockerError::Io(format!("Open locker: {}", e)))?;
    LockerHeader::read_from(&mut file)
}

/// Get basic info about a locker without decrypting.
pub fn get_locker_info(locker_path: &Path) -> Result<LockerInfo, LockerError> {
    let header = read_locker_header(locker_path)?;
    let encrypted_size = fs::metadata(locker_path)
        .map_err(|e| LockerError::Io(format!("File size: {}", e)))?
        .len();

    Ok(LockerInfo {
        file_count: header.file_count,
        dir_count: header.dir_count,
        total_original_size: header.total_original_size,
        encrypted_size,
        unlock_at: None, // Requires password to decrypt metadata
        locker_name: None,
        is_unlockable: false,
        remaining_seconds: -1,
    })
}

/// Verify a password against a locker by attempting to decrypt the metadata.
/// Also returns the decrypted metadata if successful.
pub fn verify_and_read_metadata(
    locker_path: &Path,
    password: &[u8],
) -> Result<(LockerHeader, LockerMetadata), LockerError> {
    let mut file = File::open(locker_path)
        .map_err(|e| LockerError::Io(format!("Open locker: {}", e)))?;

    let header = LockerHeader::read_from(&mut file)?;

    // Derive keys
    let keys = kdf::derive_keys(password, &header.salt, &header.argon2_params)?;

    // Read encrypted metadata
    let mut encrypted_metadata = vec![0u8; header.metadata_length as usize];
    file.read_exact(&mut encrypted_metadata)
        .map_err(|e| LockerError::Io(format!("Read encrypted metadata: {}", e)))?;

    // Decrypt metadata (this verifies the password)
    let metadata_json =
        meta_crypto::decrypt_metadata(&encrypted_metadata, &keys.metadata_key, &header.metadata_nonce)?;

    let metadata = LockerMetadata::from_json(&metadata_json)?;

    Ok((header, metadata))
}

/// Extract all files from a locker.
///
/// # Arguments
/// * `locker_path` - Path to the `.locker` file
/// * `output_dir` - Directory to extract files into
/// * `password` - User's password
/// * `progress_tx` - Progress reporting channel
///
/// # Flow
/// 1. Read header → derive keys → verify HMAC → decrypt metadata → check timer
/// 2. Stream-decrypt data → split into individual files → verify BLAKE3 hashes
pub fn extract_locker(
    locker_path: &Path,
    output_dir: &Path,
    password: &[u8],
    now: &DateTime<Utc>,
    progress_tx: Option<mpsc::UnboundedSender<Progress>>,
) -> Result<(), LockerError> {
    tracing::info!("Extracting locker: {:?}", locker_path);

    // --- Step 1: Read header and decrypt metadata ---
    let (header, metadata) = verify_and_read_metadata(locker_path, password)?;

    // --- Step 2: Check timer ---
    if !metadata.is_unlockable(now) {
        let remaining = metadata.remaining_duration(now);
        return Err(LockerError::TimerNotExpired(format!(
            "Locker is still locked. {} seconds remaining.",
            remaining.num_seconds()
        )));
    }

    // --- Step 3: Verify HMAC integrity ---
    tracing::info!("Verifying locker integrity...");
    let keys = kdf::derive_keys(password, &header.salt, &header.argon2_params)?;

    let file_size = fs::metadata(locker_path)
        .map_err(|e| LockerError::Io(format!("File size: {}", e)))?
        .len();

    {
        let mut file = File::open(locker_path)
            .map_err(|e| LockerError::Io(format!("Open for HMAC: {}", e)))?;

        // Read the stored HMAC from the last 32 bytes
        let mut stored_hmac = [0u8; HMAC_SIZE];
        file.seek(SeekFrom::End(-(HMAC_SIZE as i64)))
            .map_err(|e| LockerError::Io(format!("Seek to HMAC: {}", e)))?;
        file.read_exact(&mut stored_hmac)
            .map_err(|e| LockerError::Io(format!("Read HMAC: {}", e)))?;

        // Compute HMAC over everything except the HMAC itself
        file.seek(SeekFrom::Start(0))
            .map_err(|e| LockerError::Io(format!("Seek to start: {}", e)))?;
        let mut limited = file.take(file_size - HMAC_SIZE as u64);
        let valid = integrity::verify_hmac(&keys.authentication_key, &mut limited, &stored_hmac)?;

        if !valid {
            return Err(LockerError::Integrity(
                "HMAC verification failed: locker file has been tampered with".into(),
            ));
        }
    }
    tracing::info!("HMAC verification passed");

    // --- Step 4: Create output directories ---
    fs::create_dir_all(output_dir)
        .map_err(|e| LockerError::Io(format!("Create output dir: {}", e)))?;

    for dir in &metadata.directories {
        let dir_path = output_dir.join(&dir.path);
        fs::create_dir_all(&dir_path)
            .map_err(|e| LockerError::Io(format!("Create dir {:?}: {}", dir_path, e)))?;
    }

    // --- Step 5: Stream-decrypt data ---
    tracing::info!("Decrypting {} files...", metadata.files.len());

    let mut file = File::open(locker_path)
        .map_err(|e| LockerError::Io(format!("Open for decrypt: {}", e)))?;

    // Seek past header + encrypted metadata to the data section
    let data_offset = HEADER_SIZE as u64 + header.metadata_length;
    file.seek(SeekFrom::Start(data_offset))
        .map_err(|e| LockerError::Io(format!("Seek to data: {}", e)))?;

    let reader = BufReader::with_capacity(256 * 1024, file);

    // Decrypt the entire data stream into a temporary file first
    let temp_data_path = output_dir.join(".chronolock_temp_extract");
    let temp_file = File::create(&temp_data_path)
        .map_err(|e| LockerError::Io(format!("Create temp extract: {}", e)))?;
    let temp_writer = BufWriter::with_capacity(256 * 1024, temp_file);

    stream::decrypt_stream(
        reader,
        temp_writer,
        &keys.data_encryption_key,
        header.data_length,
        progress_tx.as_ref(),
    )?;

    // --- Step 6: Split decrypted data into individual files ---
    let mut data_reader = BufReader::new(
        File::open(&temp_data_path)
            .map_err(|e| LockerError::Io(format!("Open temp data: {}", e)))?,
    );

    for file_entry in &metadata.files {
        let out_path = output_dir.join(&file_entry.path);

        // Ensure parent directory exists
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| LockerError::Io(format!("Create parent dir: {}", e)))?;
        }

        let mut out_file = BufWriter::new(
            File::create(&out_path)
                .map_err(|e| LockerError::Io(format!("Create {:?}: {}", out_path, e)))?,
        );

        // Copy exactly file_entry.data_length bytes
        let mut remaining = file_entry.data_length;
        let mut buf = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let to_read = std::cmp::min(remaining as usize, buf.len());
            data_reader
                .read_exact(&mut buf[..to_read])
                .map_err(|e| LockerError::Io(format!("Read file data: {}", e)))?;
            out_file
                .write_all(&buf[..to_read])
                .map_err(|e| LockerError::Io(format!("Write file: {}", e)))?;
            remaining -= to_read as u64;
        }

        out_file
            .flush()
            .map_err(|e| LockerError::Io(format!("Flush: {}", e)))?;

        tracing::debug!("Extracted: {}", file_entry.path);
    }

    // --- Step 7: Clean up temp file ---
    let _ = fs::remove_file(&temp_data_path);

    // --- Step 8: Verify extracted files ---
    tracing::info!("Verifying extracted files...");
    for file_entry in &metadata.files {
        let out_path = output_dir.join(&file_entry.path);
        let hash = integrity::hash_file_blake3(&out_path)?;
        let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

        if hash_hex != file_entry.blake3_hash {
            return Err(LockerError::Integrity(format!(
                "File {:?} hash mismatch: expected {}, got {}",
                file_entry.path, file_entry.blake3_hash, hash_hex
            )));
        }
    }

    tracing::info!("Extraction complete and verified!");
    Ok(())
}
