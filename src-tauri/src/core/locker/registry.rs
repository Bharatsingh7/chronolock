//! Locker Registry (SQLite)
//!
//! Persists locker metadata for the dashboard. The actual encrypted data
//! lives in .locker files; this is just a local index.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::core::error::LockerError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockerRecord {
    pub id: String,
    pub name: String,
    pub file_path: String,
    pub created_at: String,
    pub unlock_at: String,
    pub total_size: i64,
    pub encrypted_size: i64,
    pub file_count: i32,
    pub dir_count: i32,
    pub status: String, // "locked", "unlockable", "unlocked", "encrypting", "decrypting"
}

pub struct Registry {
    conn: Connection,
}

impl Registry {
    /// Open or create the registry database.
    pub fn open(db_path: &Path) -> Result<Self, LockerError> {
        let conn = Connection::open(db_path)
            .map_err(|e| LockerError::Database(format!("Open DB: {}", e)))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS lockers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                unlock_at TEXT NOT NULL,
                total_size INTEGER NOT NULL DEFAULT 0,
                encrypted_size INTEGER NOT NULL DEFAULT 0,
                file_count INTEGER NOT NULL DEFAULT 0,
                dir_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'locked'
            );",
        )
        .map_err(|e| LockerError::Database(format!("Create table: {}", e)))?;

        Ok(Registry { conn })
    }

    /// Add a new locker record.
    pub fn add(&self, record: &LockerRecord) -> Result<(), LockerError> {
        self.conn
            .execute(
                "INSERT INTO lockers (id, name, file_path, created_at, unlock_at, total_size, encrypted_size, file_count, dir_count, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    record.id,
                    record.name,
                    record.file_path,
                    record.created_at,
                    record.unlock_at,
                    record.total_size,
                    record.encrypted_size,
                    record.file_count,
                    record.dir_count,
                    record.status,
                ],
            )
            .map_err(|e| LockerError::Database(format!("Insert: {}", e)))?;
        Ok(())
    }

    /// List all lockers.
    pub fn list(&self) -> Result<Vec<LockerRecord>, LockerError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, file_path, created_at, unlock_at, total_size, encrypted_size, file_count, dir_count, status FROM lockers ORDER BY created_at DESC")
            .map_err(|e| LockerError::Database(format!("Prepare: {}", e)))?;

        let records = stmt
            .query_map([], |row| {
                Ok(LockerRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    file_path: row.get(2)?,
                    created_at: row.get(3)?,
                    unlock_at: row.get(4)?,
                    total_size: row.get(5)?,
                    encrypted_size: row.get(6)?,
                    file_count: row.get(7)?,
                    dir_count: row.get(8)?,
                    status: row.get(9)?,
                })
            })
            .map_err(|e| LockerError::Database(format!("Query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(records)
    }

    /// Get a locker by ID.
    pub fn get(&self, id: &str) -> Result<Option<LockerRecord>, LockerError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, file_path, created_at, unlock_at, total_size, encrypted_size, file_count, dir_count, status FROM lockers WHERE id = ?1")
            .map_err(|e| LockerError::Database(format!("Prepare: {}", e)))?;

        let mut rows = stmt
            .query_map(params![id], |row| {
                Ok(LockerRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    file_path: row.get(2)?,
                    created_at: row.get(3)?,
                    unlock_at: row.get(4)?,
                    total_size: row.get(5)?,
                    encrypted_size: row.get(6)?,
                    file_count: row.get(7)?,
                    dir_count: row.get(8)?,
                    status: row.get(9)?,
                })
            })
            .map_err(|e| LockerError::Database(format!("Query: {}", e)))?;

        match rows.next() {
            Some(Ok(record)) => Ok(Some(record)),
            Some(Err(e)) => Err(LockerError::Database(format!("Row: {}", e))),
            None => Ok(None),
        }
    }

    /// Update locker status.
    pub fn update_status(&self, id: &str, status: &str) -> Result<(), LockerError> {
        self.conn
            .execute(
                "UPDATE lockers SET status = ?1 WHERE id = ?2",
                params![status, id],
            )
            .map_err(|e| LockerError::Database(format!("Update: {}", e)))?;
        Ok(())
    }

    /// Delete a locker record.
    pub fn delete(&self, id: &str) -> Result<(), LockerError> {
        self.conn
            .execute("DELETE FROM lockers WHERE id = ?1", params![id])
            .map_err(|e| LockerError::Database(format!("Delete: {}", e)))?;
        Ok(())
    }
}
