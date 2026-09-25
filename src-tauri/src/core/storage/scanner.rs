//! Directory scanner for calculating total size and file counts.

use std::path::Path;
use walkdir::WalkDir;

use crate::core::error::LockerError;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanResult {
    pub total_size: u64,
    pub file_count: u32,
    pub dir_count: u32,
    pub files: Vec<String>,
}

/// Scan paths and return total size, file count, etc.
pub fn scan_paths(paths: &[String]) -> Result<ScanResult, LockerError> {
    let mut total_size: u64 = 0;
    let mut file_count: u32 = 0;
    let mut dir_count: u32 = 0;
    let mut files = Vec::new();

    for path_str in paths {
        let path = Path::new(path_str);
        if path.is_file() {
            let meta = std::fs::metadata(path)
                .map_err(|e| LockerError::Io(format!("Metadata for {:?}: {}", path, e)))?;
            total_size += meta.len();
            file_count += 1;
            files.push(path_str.clone());
        } else if path.is_dir() {
            for entry in WalkDir::new(path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    if let Ok(meta) = entry.metadata() {
                        total_size += meta.len();
                        file_count += 1;
                        files.push(entry.path().to_string_lossy().to_string());
                    }
                } else if entry.file_type().is_dir() {
                    dir_count += 1;
                }
            }
        }
    }

    Ok(ScanResult {
        total_size,
        file_count,
        dir_count,
        files,
    })
}
