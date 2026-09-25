//! Core Error Types
//!
//! All errors in the ChronoLock core are represented by the `LockerError` enum,
//! which provides structured error information for the frontend to display.

use serde::Serialize;

#[derive(Debug, thiserror::Error, Serialize)]
pub enum LockerError {
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Wrong password: {0}")]
    WrongPassword(String),

    #[error("Integrity check failed: {0}")]
    Integrity(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("Invalid locker format: {0}")]
    InvalidFormat(String),

    #[error("Timer not expired: {0}")]
    TimerNotExpired(String),

    #[error("Locker not found: {0}")]
    NotFound(String),

    #[error("Operation cancelled")]
    Cancelled,

    #[error("Database error: {0}")]
    Database(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Disk full: {0}")]
    DiskFull(String),

    #[error("Recovery needed: {0}")]
    RecoveryNeeded(String),
}

// LockerError implements Serialize, so Tauri auto-converts it to InvokeError
// via the blanket impl. No manual From impl needed.
