//! Locker CRUD commands — Tauri command handlers

use crate::core::locker::registry::LockerRecord;
use crate::state::AppState;
use std::sync::Arc;
use tokio::sync::Mutex;

type State = Arc<Mutex<AppState>>;

#[tauri::command]
pub async fn create_locker(
    state: tauri::State<'_, State>,
    name: String,
    file_paths: Vec<String>,
    password: String,
    unlock_at: String,
) -> Result<LockerRecord, String> {
    let state = state.lock().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Parse unlock time
    let unlock_time: chrono::DateTime<chrono::Utc> = unlock_at
        .parse()
        .map_err(|e| format!("Invalid unlock time: {}", e))?;

    // Build the locker file path
    let sanitized_name = name
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .collect::<String>();
    let locker_filename = format!("{}.locker", sanitized_name);
    let locker_path = state.default_locker_dir.join(&locker_filename);

    // Convert string paths to PathBuf
    let input_paths: Vec<std::path::PathBuf> = file_paths
        .iter()
        .map(|p| std::path::PathBuf::from(p))
        .collect();

    // Build the locker (this does the actual encryption)
    let result = crate::core::locker::builder::build_locker(
        &name,
        &input_paths,
        &locker_path,
        password.as_bytes(),
        unlock_time,
        None,
    )
    .map_err(|e| e.to_string())?;

    // Register in the database
    let record = LockerRecord {
        id: id.clone(),
        name: name.clone(),
        file_path: locker_path.to_string_lossy().to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        unlock_at: unlock_time.to_rfc3339(),
        total_size: result.total_size as i64,
        encrypted_size: result.encrypted_size as i64,
        file_count: result.file_count as i32,
        dir_count: result.dir_count as i32,
        status: "locked".to_string(),
    };

    state.registry.add(&record).map_err(|e| e.to_string())?;

    Ok(record)
}

#[tauri::command]
pub async fn list_lockers(
    state: tauri::State<'_, State>,
) -> Result<Vec<LockerRecord>, String> {
    let state = state.lock().await;
    state.registry.list().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_locker(
    state: tauri::State<'_, State>,
    id: String,
) -> Result<Option<LockerRecord>, String> {
    let state = state.lock().await;
    state.registry.get(&id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_locker(
    state: tauri::State<'_, State>,
    id: String,
    delete_file: bool,
    password: Option<String>,
) -> Result<(), String> {
    let state = state.lock().await;

    let record = state
        .registry
        .get(&id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Locker not found".to_string())?;

    // Check timer status
    let unlock_at: chrono::DateTime<chrono::Utc> = record
        .unlock_at
        .parse()
        .map_err(|e| format!("Parse unlock time: {}", e))?;

    let timer_status = crate::core::timer::check_timer(&unlock_at);

    // If timer is NOT expired, user MUST provide the correct password to authorize deletion
    if !timer_status.is_unlockable {
        let pw = password.ok_or_else(|| {
            format!(
                "Locker is time-sealed until {}. Enter master password to authorize deletion.",
                record.unlock_at
            )
        })?;

        let locker_path = std::path::Path::new(&record.file_path);
        if locker_path.exists() {
            crate::core::locker::extractor::verify_and_read_metadata(locker_path, pw.as_bytes())
                .map_err(|e| match e {
                    crate::core::error::LockerError::WrongPassword(_) => {
                        "Authentication failed: Incorrect password. Deletion of sealed locker is forbidden.".to_string()
                    }
                    other => format!("Authentication error: {}", other),
                })?;
        }
    }

    if delete_file {
        let locker_path = std::path::Path::new(&record.file_path);
        if locker_path.exists() {
            // If file was set read-only for protection, clear read-only flag first
            if let Ok(metadata) = std::fs::metadata(locker_path) {
                let mut perms = metadata.permissions();
                #[allow(clippy::permissions_set_readonly_false)]
                perms.set_readonly(false);
                let _ = std::fs::set_permissions(locker_path, perms);
            }
            std::fs::remove_file(locker_path)
                .map_err(|e| format!("Failed to delete locker file: {}", e))?;
        }
    }

    state.registry.delete(&id).map_err(|e| e.to_string())
}
