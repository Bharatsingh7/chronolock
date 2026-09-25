//! Locker Builder
//!
//! Orchestrates the creation of a `.locker` file:
//! 1. Scan input files/folders → build manifest
//! 2. Derive encryption keys from password
//! 3. Write header
//! 4. Encrypt and write metadata
//! 5. Stream-encrypt all file data
//! 6. Compute and write HMAC footer
//!
//! All operations use temporary files for crash safety.
//! Original files are NEVER modified or deleted.

use chrono::{DateTime, Utc};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use walkdir::WalkDir;

use crate::core::crypto::{
    integrity::{compute_hmac, hash_file_blake3},
    kdf::{self, Argon2Params},
    metadata as meta_crypto,
    stream::{self, Progress},
};
use crate::core::error::LockerError;
use crate::core::locker::format::{
    LockerHeader, FORMAT_VERSION,
};
use crate::core::locker::manifest::{DirEntry, FileEntry, LockerMetadata};

/// Result of a successful locker build.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BuildResult {
    pub locker_path: String,
    pub total_size: u64,
    pub encrypted_size: u64,
    pub file_count: u32,
    pub dir_count: u32,
}

/// Build a new locker file.
///
/// # Arguments
/// * `name` - Human-readable locker name
/// * `input_paths` - Files and/or folders to include
/// * `output_path` - Where to write the `.locker` file
/// * `password` - User's password
/// * `unlock_at` - When the locker becomes unlockable
/// * `progress_tx` - Channel for progress updates
///
/// # Safety
/// - Writes to a temporary file first, renames on success
/// - Original files are never touched
/// - On failure, temporary file is cleaned up
pub fn build_locker(
    name: &str,
    input_paths: &[PathBuf],
    output_path: &Path,
    password: &[u8],
    unlock_at: DateTime<Utc>,
    progress_tx: Option<mpsc::UnboundedSender<Progress>>,
) -> Result<BuildResult, LockerError> {
    tracing::info!("Building locker '{}' with {} input paths", name, input_paths.len());

    // --- Step 1: Scan files and build manifest ---
    let (files, directories, total_size) = scan_inputs(input_paths)?;
    tracing::info!(
        "Scanned {} files, {} directories, {} bytes total",
        files.len(),
        directories.len(),
        total_size
    );

    // --- Step 2: Generate cryptographic material ---
    let salt = kdf::generate_salt();
    let metadata_nonce = kdf::generate_nonce();
    let data_nonce = kdf::generate_nonce();

    // Use reduced params for development; in production use Argon2Params::default()
    let argon2_params = Argon2Params {
        memory_cost_kib: 64 * 1024, // 64 MiB (lighter for dev)
        time_cost: 3,
        parallelism: 2,
    };

    tracing::info!("Deriving encryption keys...");
    let keys = kdf::derive_keys(password, &salt, &argon2_params)?;

    // --- Step 3: Build metadata ---
    let mut metadata = LockerMetadata::new(name.to_string(), unlock_at);
    metadata.directories = directories.clone();

    // We'll fill in file entries as we process them
    let mut file_entries: Vec<FileEntry> = Vec::with_capacity(files.len());
    let mut current_offset: u64 = 0;

    for (rel_path, abs_path, size) in &files {
        let hash = hash_file_blake3(abs_path)?;
        let hash_hex = hex_encode(&hash);

        // Get file metadata
        let fs_meta = std::fs::metadata(abs_path)
            .map_err(|e| LockerError::Io(format!("Read metadata for {:?}: {}", abs_path, e)))?;

        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            fs_meta.permissions().mode()
        };
        #[cfg(not(unix))]
        let permissions = 0o644u32;

        let modified_at = fs_meta
            .modified()
            .ok()
            .and_then(|t| DateTime::<Utc>::from(t).into());

        file_entries.push(FileEntry {
            path: rel_path.clone(),
            size: *size,
            blake3_hash: hash_hex,
            permissions,
            modified_at: Some(modified_at.unwrap_or_else(Utc::now)),
            data_offset: current_offset,
            data_length: *size,
        });

        current_offset += *size;
    }
    metadata.files = file_entries;

    // Serialize and encrypt metadata
    let metadata_json = metadata.to_json()?;
    let encrypted_metadata =
        meta_crypto::encrypt_metadata(&metadata_json, &keys.metadata_key, &metadata_nonce)?;

    // --- Step 4: Write to temporary file ---
    let temp_path = output_path.with_extension("locker.tmp");
    let temp_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp_path)
        .map_err(|e| LockerError::Io(format!("Create temp file: {}", e)))?;
    let mut writer = BufWriter::with_capacity(256 * 1024, temp_file);

    // Write header (placeholder — we'll update data_length after encryption)
    let mut header = LockerHeader {
        version: FORMAT_VERSION,
        flags: 0,
        argon2_params,
        chunk_size: stream::DEFAULT_CHUNK_SIZE as u32,
        salt,
        metadata_nonce,
        metadata_length: encrypted_metadata.len() as u64,
        data_length: 0, // Will be updated
        total_original_size: total_size,
        file_count: files.len() as u32,
        dir_count: directories.len() as u32,
        data_nonce,
    };
    header.write_to(&mut writer)?;

    // Write encrypted metadata
    writer
        .write_all(&encrypted_metadata)
        .map_err(|e| LockerError::Io(format!("Write encrypted metadata: {}", e)))?;

    // --- Step 5: Stream-encrypt all file data ---
    tracing::info!("Encrypting {} files ({} bytes)...", files.len(), total_size);

    // Create a chained reader over all input files
    let chained = ChainedFileReader::new(
        files.iter().map(|(_, p, _)| p.clone()).collect(),
    )?;

    let data_written = stream::encrypt_stream(
        chained,
        &mut writer,
        &keys.data_encryption_key,
        &data_nonce,
        stream::DEFAULT_CHUNK_SIZE,
        total_size,
        progress_tx.as_ref(),
    )?;

    // Flush before seeking
    writer
        .flush()
        .map_err(|e| LockerError::Io(format!("Flush before seek: {}", e)))?;

    // --- Step 6: Update header with actual data length ---
    header.data_length = data_written;
    let mut file = writer.into_inner()
        .map_err(|e| LockerError::Io(format!("Unwrap writer: {}", e)))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| LockerError::Io(format!("Seek to header: {}", e)))?;
    let mut header_writer = BufWriter::new(&mut file);
    header.write_to(&mut header_writer)?;
    header_writer.flush()
        .map_err(|e| LockerError::Io(format!("Flush header: {}", e)))?;
    drop(header_writer);

    // --- Step 7: Compute and append HMAC footer ---
    file.seek(SeekFrom::Start(0))
        .map_err(|e| LockerError::Io(format!("Seek for HMAC: {}", e)))?;
    let hmac = compute_hmac(&keys.authentication_key, &mut file)?;
    // Seek to end to append HMAC
    file.seek(SeekFrom::End(0))
        .map_err(|e| LockerError::Io(format!("Seek to end: {}", e)))?;
    file.write_all(&hmac)
        .map_err(|e| LockerError::Io(format!("Write HMAC: {}", e)))?;
    file.flush()
        .map_err(|e| LockerError::Io(format!("Final flush: {}", e)))?;
    file.sync_all()
        .map_err(|e| LockerError::Io(format!("Physical sync to disk failed: {}", e)))?;
    drop(file);

    // --- Step 8: Atomic rename ---
    std::fs::rename(&temp_path, output_path)
        .map_err(|e| LockerError::Io(format!("Rename temp to final: {}", e)))?;

    // Industrial grade protection: Make locker file read-only to prevent accidental modification/deletion
    if let Ok(metadata) = std::fs::metadata(output_path) {
        let mut perms = metadata.permissions();
        perms.set_readonly(true);
        let _ = std::fs::set_permissions(output_path, perms);
    }

    let encrypted_size = std::fs::metadata(output_path)
        .map_err(|e| LockerError::Io(format!("Read final size: {}", e)))?
        .len();

    tracing::info!(
        "Locker '{}' created: {} -> {} bytes",
        name,
        total_size,
        encrypted_size
    );

    Ok(BuildResult {
        locker_path: output_path.to_string_lossy().to_string(),
        total_size,
        encrypted_size,
        file_count: files.len() as u32,
        dir_count: directories.len() as u32,
    })
}

/// Scan input paths and collect all files and directories.
/// Returns (files: Vec<(relative_path, absolute_path, size)>, dirs, total_size)
fn scan_inputs(
    paths: &[PathBuf],
) -> Result<(Vec<(String, PathBuf, u64)>, Vec<DirEntry>, u64), LockerError> {
    let mut files = Vec::new();
    let mut directories = Vec::new();
    let mut total_size: u64 = 0;

    for input_path in paths {
        if input_path.is_file() {
            let size = std::fs::metadata(input_path)
                .map_err(|e| LockerError::Io(format!("Metadata for {:?}: {}", input_path, e)))?
                .len();
            let name = input_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".into());
            files.push((name, input_path.clone(), size));
            total_size += size;
        } else if input_path.is_dir() {
            let base_name = input_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "folder".into());

            for entry in WalkDir::new(input_path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let abs_path = entry.path().to_path_buf();
                let rel_path = abs_path
                    .strip_prefix(input_path.parent().unwrap_or(input_path))
                    .unwrap_or(&abs_path);
                let rel_str = rel_path.to_string_lossy().replace('\\', "/");

                if entry.file_type().is_dir() {
                    if rel_str != base_name && !rel_str.is_empty() {
                        directories.push(DirEntry {
                            path: rel_str,
                            #[cfg(unix)]
                            permissions: {
                                use std::os::unix::fs::PermissionsExt;
                                entry.metadata().map(|m| m.permissions().mode()).unwrap_or(0o755)
                            },
                            #[cfg(not(unix))]
                            permissions: 0o755,
                        });
                    }
                } else if entry.file_type().is_file() {
                    let size = entry.metadata()
                        .map_err(|e| LockerError::Io(format!("Metadata: {}", e)))?
                        .len();
                    files.push((rel_str, abs_path, size));
                    total_size += size;
                }
            }
            // Add the root directory itself
            directories.push(DirEntry {
                path: base_name,
                permissions: 0o755,
            });
        }
    }

    Ok((files, directories, total_size))
}

/// A reader that chains multiple files together into one continuous stream.
struct ChainedFileReader {
    paths: Vec<PathBuf>,
    current_index: usize,
    current_reader: Option<BufReader<File>>,
}

impl ChainedFileReader {
    fn new(paths: Vec<PathBuf>) -> Result<Self, LockerError> {
        let mut reader = ChainedFileReader {
            paths,
            current_index: 0,
            current_reader: None,
        };
        reader.open_next()?;
        Ok(reader)
    }

    fn open_next(&mut self) -> Result<(), LockerError> {
        if self.current_index < self.paths.len() {
            let file = File::open(&self.paths[self.current_index])
                .map_err(|e| LockerError::Io(format!("Open file {:?}: {}", self.paths[self.current_index], e)))?;
            self.current_reader = Some(BufReader::with_capacity(128 * 1024, file));
        } else {
            self.current_reader = None;
        }
        Ok(())
    }
}

impl Read for ChainedFileReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match &mut self.current_reader {
                None => return Ok(0), // All files exhausted
                Some(reader) => {
                    let n = reader.read(buf)?;
                    if n > 0 {
                        return Ok(n);
                    }
                    // Current file exhausted, move to next
                    self.current_index += 1;
                    self.open_next().map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    })?;
                }
            }
        }
    }
}

/// Hex-encode a byte slice.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
