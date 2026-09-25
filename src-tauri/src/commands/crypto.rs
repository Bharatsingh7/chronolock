//! Crypto-related Tauri commands

use crate::state::AppState;
use std::sync::Arc;
use tokio::sync::Mutex;

type State = Arc<Mutex<AppState>>;

#[tauri::command]
pub async fn encrypt_locker(
    state: tauri::State<'_, State>,
    id: String,
) -> Result<(), String> {
    // Encryption happens during create_locker
    // This command is for re-encryption or status updates
    let state = state.lock().await;
    state
        .registry
        .update_status(&id, "locked")
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn decrypt_locker(
    state: tauri::State<'_, State>,
    id: String,
    password: String,
    output_dir: String,
) -> Result<(), String> {
    let state = state.lock().await;

    let record = state
        .registry
        .get(&id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Locker not found".to_string())?;

    let locker_path = std::path::Path::new(&record.file_path);
    let output_path = std::path::Path::new(&output_dir);
    let (now, _) = crate::core::timer::get_verified_time();

    crate::core::locker::extractor::extract_locker(
        locker_path,
        output_path,
        password.as_bytes(),
        &now,
        None,
    )
    .map_err(|e| e.to_string())?;

    state
        .registry
        .update_status(&id, "unlocked")
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub async fn verify_password(
    state: tauri::State<'_, State>,
    id: String,
    password: String,
) -> Result<bool, String> {
    let state = state.lock().await;

    let record = state
        .registry
        .get(&id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Locker not found".to_string())?;

    let locker_path = std::path::Path::new(&record.file_path);

    match crate::core::locker::extractor::verify_and_read_metadata(
        locker_path,
        password.as_bytes(),
    ) {
        Ok(_) => Ok(true),
        Err(crate::core::error::LockerError::WrongPassword(_)) => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}
