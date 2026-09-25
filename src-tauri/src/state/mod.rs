//! Application State
//!
//! Shared state managed by Tauri, providing access to the registry
//! and tracking active operations.

use crate::core::locker::registry::Registry;
use crate::core::error::LockerError;
use std::path::PathBuf;

pub struct AppState {
    pub registry: Registry,
    pub app_data_dir: PathBuf,
    pub default_locker_dir: PathBuf,
}

impl AppState {
    pub async fn new() -> Result<Self, LockerError> {
        // Determine app data directory
        let app_data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("com.chronolock.vault");

        std::fs::create_dir_all(&app_data_dir)
            .map_err(|e| LockerError::Io(format!("Create app data dir: {}", e)))?;

        // Default locker storage directory
        let default_locker_dir = dirs::document_dir()
            .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")))
            .join("ChronoLock");

        std::fs::create_dir_all(&default_locker_dir)
            .map_err(|e| LockerError::Io(format!("Create locker dir: {}", e)))?;

        // Open registry
        let db_path = app_data_dir.join("lockers.db");
        let registry = Registry::open(&db_path)?;

        // Cleanup any temp files from previous crashes
        crate::core::recovery::cleanup_temp_files(&default_locker_dir);

        Ok(AppState {
            registry,
            app_data_dir,
            default_locker_dir,
        })
    }
}
