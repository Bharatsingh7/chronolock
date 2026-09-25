pub mod commands;
pub mod core;
pub mod state;

use state::AppState;
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    runtime.block_on(async {
        let app_state = AppState::new().await.expect("Failed to initialize app state");
        let app_state = Arc::new(Mutex::new(app_state));

        tauri::Builder::default()
            .plugin(tauri_plugin_opener::init())
            .plugin(tauri_plugin_dialog::init())
            .plugin(tauri_plugin_fs::init())
            .manage(app_state)
            .invoke_handler(tauri::generate_handler![
                commands::locker::create_locker,
                commands::locker::list_lockers,
                commands::locker::get_locker,
                commands::locker::delete_locker,
                commands::crypto::encrypt_locker,
                commands::crypto::decrypt_locker,
                commands::crypto::verify_password,
                commands::timer::get_timer_status,
                commands::settings::get_settings,
                commands::settings::update_theme,
            ])
            .setup(|app| {
                // Perform startup recovery - clean up any incomplete operations
                let _handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    tracing::info!("ChronoLock starting up...");
                    // Recovery will be performed here
                });
                Ok(())
            })
            .run(tauri::generate_context!())
            .expect("error while running tauri application");
    });
}
