//! Settings-related Tauri commands

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub theme: String,
    pub default_locker_dir: String,
}

#[tauri::command]
pub async fn get_settings() -> Result<AppSettings, String> {
    let default_dir = dirs::document_dir()
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from(".")))
        .join("ChronoLock");

    Ok(AppSettings {
        theme: "dark".to_string(),
        default_locker_dir: default_dir.to_string_lossy().to_string(),
    })
}

#[tauri::command]
pub async fn update_theme(theme: String) -> Result<(), String> {
    // Theme is managed in frontend localStorage
    tracing::info!("Theme updated to: {}", theme);
    Ok(())
}
