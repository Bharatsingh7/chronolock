// Tauri API wrappers — type-safe invoke calls to Rust backend
import { invoke } from '@tauri-apps/api/core';
import type { LockerRecord, TimerStatus, AppSettings } from './types';

/**
 * Returns true if running within the native Tauri desktop environment.
 */
export function isTauri(): boolean {
  return typeof window !== 'undefined' && Boolean((window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__);
}

async function safeInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri()) {
    console.info(`[Browser Dev Mode] Mock fallback for '${cmd}'`);
    if (cmd === 'list_lockers') {
      return [] as unknown as T;
    }
    if (cmd === 'get_settings') {
      return { theme: 'dark', default_locker_dir: '', check_ntp_on_startup: true } as unknown as T;
    }
    if (cmd === 'get_timer_status') {
      return {
        is_locked: true,
        is_unlockable: false,
        remaining_seconds: 3600,
        remaining_days: 0,
        remaining_hours: 1,
        remaining_minutes: 0,
        remaining_secs: 0,
        unlock_at: new Date(Date.now() + 3600000).toISOString(),
        clock_verified: false,
      } as unknown as T;
    }
    throw new Error(`Command '${cmd}' requires native desktop environment`);
  }
  return invoke<T>(cmd, args);
}

// === Locker Commands ===

export async function createLocker(
  name: string,
  filePaths: string[],
  password: string,
  unlockAt: string
): Promise<LockerRecord> {
  return safeInvoke('create_locker', {
    name,
    filePaths,
    password,
    unlockAt,
  });
}

export async function listLockers(): Promise<LockerRecord[]> {
  return safeInvoke('list_lockers');
}

export async function getLocker(id: string): Promise<LockerRecord | null> {
  return safeInvoke('get_locker', { id });
}

export async function deleteLocker(id: string, deleteFile: boolean, password?: string): Promise<void> {
  return safeInvoke('delete_locker', { id, deleteFile, password });
}

// === Crypto Commands ===

export async function decryptLocker(
  id: string,
  password: string,
  outputDir: string
): Promise<void> {
  return safeInvoke('decrypt_locker', { id, password, outputDir });
}

export async function verifyPassword(id: string, password: string): Promise<boolean> {
  return safeInvoke('verify_password', { id, password });
}

// === Timer Commands ===

export async function getTimerStatus(id: string): Promise<TimerStatus> {
  return safeInvoke('get_timer_status', { id });
}

// === Settings ===

export async function getSettings(): Promise<AppSettings> {
  return safeInvoke('get_settings');
}

export async function updateTheme(theme: string): Promise<void> {
  return safeInvoke('update_theme', { theme });
}
