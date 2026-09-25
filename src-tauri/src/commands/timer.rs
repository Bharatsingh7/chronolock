//! Timer-related Tauri commands

use crate::core::timer;
use crate::state::AppState;
use std::sync::Arc;
use tokio::sync::Mutex;

type State = Arc<Mutex<AppState>>;

#[tauri::command]
pub async fn get_timer_status(
    state: tauri::State<'_, State>,
    id: String,
) -> Result<timer::TimerStatus, String> {
    let state = state.lock().await;

    let record = state
        .registry
        .get(&id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Locker not found".to_string())?;

    let unlock_at: chrono::DateTime<chrono::Utc> = record
        .unlock_at
        .parse()
        .map_err(|e| format!("Parse unlock time: {}", e))?;

    Ok(timer::check_timer(&unlock_at))
}
