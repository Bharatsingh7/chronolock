//! Recovery module — crash recovery, cleanup, verification.
//! Handles incomplete operations on startup.

/// Clean up any temp files from interrupted operations.
pub fn cleanup_temp_files(app_data_dir: &std::path::Path) {
    // Look for .locker.tmp files
    if let Ok(entries) = std::fs::read_dir(app_data_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "tmp" {
                    tracing::warn!("Cleaning up incomplete operation: {:?}", path);
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }
}
