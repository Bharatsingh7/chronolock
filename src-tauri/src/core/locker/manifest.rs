//! File Manifest Module
//!
//! Defines the metadata structures that describe the contents of a locker:
//! file entries, directory entries, and the overall locker metadata.
//! This metadata is serialized to JSON and encrypted.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents a single file inside the locker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Relative path within the locker (e.g., "documents/secret.pdf")
    pub path: String,
    /// Original file size in bytes
    pub size: u64,
    /// BLAKE3 hash of the original file (hex-encoded)
    pub blake3_hash: String,
    /// File permissions (Unix mode, e.g., 0o644)
    #[serde(default)]
    pub permissions: u32,
    /// Last modified timestamp
    #[serde(default)]
    pub modified_at: Option<DateTime<Utc>>,
    /// Offset of this file's data within the encrypted data stream
    pub data_offset: u64,
    /// Length of this file's original data
    pub data_length: u64,
}

/// Represents a directory inside the locker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    /// Relative path
    pub path: String,
    /// Directory permissions
    #[serde(default)]
    pub permissions: u32,
}

/// Complete locker metadata — serialized to JSON, then encrypted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockerMetadata {
    /// Format version
    pub version: u16,
    /// Human-readable locker name
    pub locker_name: String,
    /// Locker creation timestamp
    pub created_at: DateTime<Utc>,
    /// When the locker becomes unlockable
    pub unlock_at: DateTime<Utc>,
    /// List of all files
    pub files: Vec<FileEntry>,
    /// List of all directories
    pub directories: Vec<DirEntry>,
    /// Application version that created this locker
    pub app_version: String,
    /// NTP-verified time at lock creation (for clock drift detection)
    #[serde(default)]
    pub ntp_lock_time: Option<DateTime<Utc>>,
    /// Seconds remaining at the time of locking (for timer persistence)
    pub lock_duration_seconds: i64,
}

impl LockerMetadata {
    /// Create a new metadata instance.
    pub fn new(name: String, unlock_at: DateTime<Utc>) -> Self {
        let now = Utc::now();
        let duration = (unlock_at - now).num_seconds().max(0);
        Self {
            version: 1,
            locker_name: name,
            created_at: now,
            unlock_at,
            files: Vec::new(),
            directories: Vec::new(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            ntp_lock_time: None,
            lock_duration_seconds: duration,
        }
    }

    /// Serialize to JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, crate::core::error::LockerError> {
        serde_json::to_vec(self).map_err(|e| {
            crate::core::error::LockerError::Serialization(format!(
                "Metadata serialization failed: {}",
                e
            ))
        })
    }

    /// Deserialize from JSON bytes.
    pub fn from_json(data: &[u8]) -> Result<Self, crate::core::error::LockerError> {
        serde_json::from_slice(data).map_err(|e| {
            crate::core::error::LockerError::Serialization(format!(
                "Metadata deserialization failed: {}",
                e
            ))
        })
    }

    /// Check if the timer has expired (unlock time has passed).
    pub fn is_unlockable(&self, now: &DateTime<Utc>) -> bool {
        *now >= self.unlock_at
    }

    /// Get remaining time until unlock.
    pub fn remaining_duration(&self, now: &DateTime<Utc>) -> chrono::Duration {
        if *now >= self.unlock_at {
            chrono::Duration::zero()
        } else {
            self.unlock_at - *now
        }
    }

    /// Total size of all files.
    pub fn total_size(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }

    /// Total file count.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_json_round_trip() {
        let unlock = Utc::now() + chrono::Duration::hours(24);
        let mut meta = LockerMetadata::new("Test Vault".into(), unlock);
        meta.files.push(FileEntry {
            path: "test.txt".into(),
            size: 1024,
            blake3_hash: "abcdef".into(),
            permissions: 0o644,
            modified_at: Some(Utc::now()),
            data_offset: 0,
            data_length: 1024,
        });
        meta.directories.push(DirEntry {
            path: "subdir".into(),
            permissions: 0o755,
        });

        let json = meta.to_json().unwrap();
        let parsed = LockerMetadata::from_json(&json).unwrap();

        assert_eq!(parsed.locker_name, "Test Vault");
        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.directories.len(), 1);
        assert_eq!(parsed.files[0].path, "test.txt");
    }

    #[test]
    fn test_is_unlockable() {
        let past = Utc::now() - chrono::Duration::hours(1);
        let meta = LockerMetadata::new("Test".into(), past);
        assert!(meta.is_unlockable(&Utc::now()));

        let future = Utc::now() + chrono::Duration::hours(1);
        let meta2 = LockerMetadata::new("Test2".into(), future);
        assert!(!meta2.is_unlockable(&Utc::now()));
    }
}
