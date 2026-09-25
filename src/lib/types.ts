// TypeScript type definitions matching Rust backend structures

export interface LockerRecord {
  id: string;
  name: string;
  file_path: string;
  created_at: string;
  unlock_at: string;
  total_size: number;
  encrypted_size: number;
  file_count: number;
  dir_count: number;
  status: 'locked' | 'unlockable' | 'unlocked' | 'encrypting' | 'decrypting';
}

export interface TimerStatus {
  is_locked: boolean;
  is_unlockable: boolean;
  remaining_seconds: number;
  remaining_days: number;
  remaining_hours: number;
  remaining_minutes: number;
  remaining_secs: number;
  unlock_at: string;
  clock_verified: boolean;
}

export interface Progress {
  bytes_processed: number;
  total_bytes: number;
  current_file: string;
  speed_bytes_per_sec: number;
  eta_seconds: number;
  percentage: number;
}

export interface AppSettings {
  theme: string;
  default_locker_dir: string;
}

export interface ScanResult {
  total_size: number;
  file_count: number;
  dir_count: number;
  files: string[];
}

export type Theme = 'dark' | 'light';

export interface SelectedFile {
  path: string;
  name: string;
  size: number;
  isDir: boolean;
}
