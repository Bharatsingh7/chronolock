import { useState, useEffect, useCallback } from 'react';
import { Shield, Plus, Lock, Unlock, Sun, Moon, Trash2, Eye, FolderOpen, File, X, ArrowLeft, ArrowRight, Check, KeyRound, AlertTriangle } from 'lucide-react';
import { useTheme } from './hooks/useTheme';
import { useCountdown } from './hooks/useCountdown';
import * as api from './lib/api';
import { formatSize, formatFileCount, formatDate } from './lib/format';
import type { LockerRecord, SelectedFile } from './lib/types';

// ─── App Root ─────────────────────────────────────────────
export default function App() {
  const { theme, toggleTheme } = useTheme();
  const [page, setPage] = useState<'dashboard' | 'create' | 'detail'>('dashboard');
  const [lockers, setLockers] = useState<LockerRecord[]>([]);
  const [selectedLockerId, setSelectedLockerId] = useState<string | null>(null);
  const [toasts, setToasts] = useState<{ id: number; msg: string; type: 'success' | 'error' | 'info' }[]>([]);
  const [deleteTarget, setDeleteTarget] = useState<LockerRecord | null>(null);
  const [deletePassword, setDeletePassword] = useState('');
  const [deleteError, setDeleteError] = useState('');
  const [isDeleting, setIsDeleting] = useState(false);

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    setIsDeleting(true);
    setDeleteError('');
    try {
      await api.deleteLocker(deleteTarget.id, true, deletePassword || undefined);
      addToast('Locker securely deleted', 'success');
      setDeleteTarget(null);
      setDeletePassword('');
      refreshLockers();
    } catch (err) {
      setDeleteError(String(err));
    } finally {
      setIsDeleting(false);
    }
  };

  const addToast = useCallback((msg: string, type: 'success' | 'error' | 'info' = 'info') => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, msg, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000);
  }, []);

  const refreshLockers = useCallback(async () => {
    try {
      const list = await api.listLockers();
      setLockers(list);
    } catch (err) {
      console.error('Failed to list lockers:', err);
    }
  }, []);

  useEffect(() => {
    refreshLockers();
  }, [refreshLockers]);

  const openDetail = (id: string) => {
    setSelectedLockerId(id);
    setPage('detail');
  };

  const goToDashboard = () => {
    setPage('dashboard');
    setSelectedLockerId(null);
    refreshLockers();
  };

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="sidebar-logo-icon"><Shield size={20} /></div>
          <span className="sidebar-logo-text">ChronoLock</span>
        </div>
        <nav className="sidebar-nav">
          <button
            className={`sidebar-nav-item ${page === 'dashboard' ? 'active' : ''}`}
            onClick={goToDashboard}
          >
            <Lock size={18} /> My Lockers
          </button>
          <button
            className={`sidebar-nav-item ${page === 'create' ? 'active' : ''}`}
            onClick={() => setPage('create')}
          >
            <Plus size={18} /> Create Locker
          </button>
        </nav>
        <div className="sidebar-footer">
          <button className="sidebar-nav-item" onClick={toggleTheme}>
            {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
            {theme === 'dark' ? 'Light Mode' : 'Dark Mode'}
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        {page === 'dashboard' && (
          <Dashboard
            lockers={lockers}
            onCreateClick={() => setPage('create')}
            onLockerClick={openDetail}
            onDelete={(target) => {
              setDeleteTarget(target);
              setDeletePassword('');
              setDeleteError('');
            }}
          />
        )}
        {page === 'create' && (
          <CreateWizard
            onComplete={() => {
              addToast('Locker created successfully!', 'success');
              goToDashboard();
            }}
            onCancel={goToDashboard}
            addToast={addToast}
          />
        )}
        {page === 'detail' && selectedLockerId && (
          <LockerDetail
            lockerId={selectedLockerId}
            onBack={goToDashboard}
            addToast={addToast}
          />
        )}
      </main>

      {/* Delete Confirmation & Password Authorization Modal */}
      {deleteTarget && (
        <div className="modal-overlay" onClick={() => { if (!isDeleting) { setDeleteTarget(null); setDeletePassword(''); setDeleteError(''); } }}>
          <div className="modal-content" onClick={e => e.stopPropagation()} style={{ maxWidth: '500px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-3)' }}>
              <div style={{
                width: '42px', height: '42px', borderRadius: '50%',
                backgroundColor: 'rgba(239, 68, 68, 0.15)', color: '#ef4444',
                display: 'flex', alignItems: 'center', justifyContent: 'center'
              }}>
                <Trash2 size={20} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: 'var(--font-size-lg)', fontWeight: 600 }}>Delete Locker</h3>
                <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-text-secondary)' }}>
                  {deleteTarget.name}
                </div>
              </div>
            </div>

            {new Date(deleteTarget.unlock_at) > new Date() ? (
              <div style={{
                backgroundColor: 'rgba(239, 68, 68, 0.08)',
                border: '1px solid rgba(239, 68, 68, 0.25)',
                borderRadius: 'var(--radius-md)',
                padding: 'var(--space-3)',
                marginBottom: 'var(--space-4)',
                fontSize: 'var(--font-size-sm)',
                color: 'var(--color-text-primary)'
              }}>
                <div style={{ fontWeight: 600, color: '#ef4444', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Lock size={15} /> Time-Lock Security Enforcement Active
                </div>
                This locker is time-sealed until <strong>{new Date(deleteTarget.unlock_at).toLocaleString()}</strong>.
                Industrial security policy prevents deletion before timer expiration unless authorized with the correct master password.
              </div>
            ) : (
              <p style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-text-secondary)', marginBottom: 'var(--space-4)' }}>
                The time lock has expired. Are you sure you want to permanently delete this vault and its encrypted file?
              </p>
            )}

            {new Date(deleteTarget.unlock_at) > new Date() && (
              <div className="input-group" style={{ marginBottom: 'var(--space-4)' }}>
                <label className="input-label">Master Password Required</label>
                <input
                  type="password"
                  className="input-field"
                  placeholder="Enter master password to authorize deletion"
                  value={deletePassword}
                  onChange={e => setDeletePassword(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') confirmDelete(); }}
                  autoFocus
                />
              </div>
            )}

            {deleteError && (
              <div style={{
                color: '#ef4444', fontSize: 'var(--font-size-sm)',
                marginBottom: 'var(--space-3)', fontWeight: 500,
                display: 'flex', alignItems: 'center', gap: '6px'
              }}>
                <AlertTriangle size={15} /> {deleteError}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-3)', marginTop: 'var(--space-4)' }}>
              <button
                className="btn btn-ghost"
                type="button"
                onClick={() => { setDeleteTarget(null); setDeletePassword(''); setDeleteError(''); }}
                disabled={isDeleting}
              >
                Cancel
              </button>
              <button
                className="btn btn-danger"
                type="button"
                onClick={confirmDelete}
                disabled={isDeleting || (new Date(deleteTarget.unlock_at) > new Date() && !deletePassword.trim())}
                style={{ backgroundColor: '#dc2626', color: 'white', border: 'none' }}
              >
                {isDeleting ? 'Verifying & Deleting...' : 'Authorize & Delete'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toasts */}
      <div className="toast-container">
        {toasts.map(t => (
          <div key={t.id} className={`toast toast-${t.type}`}>
            {t.type === 'success' && <Check size={16} />}
            {t.type === 'error' && <X size={16} />}
            {t.msg}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Dashboard Page ──────────────────────────────────────
function Dashboard({ lockers, onCreateClick, onLockerClick, onDelete }: {
  lockers: LockerRecord[];
  onCreateClick: () => void;
  onLockerClick: (id: string) => void;
  onDelete: (locker: LockerRecord) => void;
}) {
  return (
    <>
      <header className="page-header">
        <h1>My Lockers</h1>
        <button className="btn btn-primary" onClick={onCreateClick}>
          <Plus size={16} /> Create Locker
        </button>
      </header>
      <div className="page-body">
        {lockers.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon"><Shield size={36} /></div>
            <h2>No Lockers Yet</h2>
            <p>Create your first encrypted locker to securely protect your files with a time-lock.</p>
            <button className="btn btn-primary btn-lg" onClick={onCreateClick}>
              <Plus size={18} /> Create Your First Locker
            </button>
          </div>
        ) : (
          <div className="locker-grid">
            {lockers.map(locker => (
              <LockerCard
                key={locker.id}
                locker={locker}
                onClick={() => onLockerClick(locker.id)}
                onDelete={() => onDelete(locker)}
              />
            ))}
          </div>
        )}
      </div>
    </>
  );
}

// ─── Locker Card ─────────────────────────────────────────
function LockerCard({ locker, onClick, onDelete }: {
  locker: LockerRecord;
  onClick: () => void;
  onDelete: () => void;
}) {
  const { remaining, days, hours, minutes, seconds, isExpired } = useCountdown(locker.id);
  const status = isExpired ? 'unlockable' : locker.status === 'unlocked' ? 'unlocked' : 'locked';

  const pad = (n: number) => n.toString().padStart(2, '0');

  return (
    <div className="card card-clickable locker-card" onClick={onClick}>
      <div className="locker-card-header">
        <div className={`locker-card-icon ${status}`}>
          {status === 'locked' ? <Lock size={22} /> : status === 'unlockable' ? <Unlock size={22} /> : <Check size={22} />}
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span className={`locker-card-status ${status}`}>
            {status === 'locked' && '🔒 Locked'}
            {status === 'unlockable' && '🔓 Ready'}
            {status === 'unlocked' && '✓ Unlocked'}
          </span>
          <button
            className="btn btn-ghost btn-icon btn-sm"
            onClick={(e) => { e.stopPropagation(); onDelete(); }}
            title="Delete locker"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      <div className="locker-card-name">{locker.name}</div>
      <div className="locker-card-meta">
        <span>{formatSize(locker.total_size)}</span>
        <span className="locker-card-meta-dot" />
        <span>{formatFileCount(locker.file_count)}</span>
      </div>

      {status === 'locked' && remaining > 0 && (
        <>
          <div className="locker-card-timer">
            {days > 0 && `${pad(days)}:`}{pad(hours)}:{pad(minutes)}:{pad(seconds)}
          </div>
          <div className="locker-card-timer-label">
            {days > 0 ? 'Days : Hours : Min : Sec' : 'Hours : Min : Sec'}
          </div>
        </>
      )}

      {status === 'unlockable' && (
        <div className="locker-card-timer" style={{ color: 'var(--color-success)', fontSize: 'var(--text-lg)' }}>
          Ready to Unlock
        </div>
      )}
    </div>
  );
}

// ─── Create Wizard ────────────────────────────────────────
function CreateWizard({ onComplete, onCancel, addToast }: {
  onComplete: () => void;
  onCancel: () => void;
  addToast: (msg: string, type: 'success' | 'error' | 'info') => void;
}) {
  const [step, setStep] = useState(0);
  const [name, setName] = useState('');
  const [files, setFiles] = useState<SelectedFile[]>([]);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [unlockPreset, setUnlockPreset] = useState('');
  const [customDate, setCustomDate] = useState('');
  const [customTime, setCustomTime] = useState('');
  const [manualPath, setManualPath] = useState('');
  const [, setIsEncrypting] = useState(false);
  const [encryptProgress, setEncryptProgress] = useState(0);
  const totalSteps = 6;

  const addManualPath = () => {
    const p = manualPath.trim();
    if (!p) return;
    const name = p.split(/[\\/]/).filter(Boolean).pop() || p;
    setFiles(prev => {
      if (prev.some(f => f.path === p)) return prev;
      return [...prev, {
        path: p,
        name,
        size: 0,
        isDir: !p.includes('.') || p.endsWith('/') || p.endsWith('\\'),
      }];
    });
    setManualPath('');
  };

  const addFiles = async () => {
    try {
      const { open } = await import('@tauri-apps/plugin-dialog');
      const selected = await open({ multiple: true, title: 'Select Files' });
      if (selected) {
        const paths = Array.isArray(selected) ? selected : [selected];
        const newFiles: SelectedFile[] = paths.map(p => ({
          path: p as string,
          name: (p as string).split(/[\\/]/).pop() || '',
          size: 0,
          isDir: false,
        }));
        setFiles(prev => [...prev, ...newFiles]);
      }
    } catch (err) {
      addToast(`File picker error: ${err}`, 'error');
    }
  };

  const addFolder = async () => {
    try {
      const { open } = await import('@tauri-apps/plugin-dialog');
      const selected = await open({ directory: true, title: 'Select Folder' });
      if (selected) {
        setFiles(prev => [...prev, {
          path: selected as string,
          name: (selected as string).split(/[\\/]/).pop() || 'folder',
          size: 0,
          isDir: true,
        }]);
      }
    } catch (err) {
      addToast(`Folder picker error: ${err}`, 'error');
    }
  };

  const removeFile = (index: number) => {
    setFiles(prev => prev.filter((_, i) => i !== index));
  };

  const getUnlockDate = (): string => {
    const now = new Date();
    switch (unlockPreset) {
      case '5min': return new Date(now.getTime() + 5 * 60000).toISOString();
      case '1hour': return new Date(now.getTime() + 3600000).toISOString();
      case '1day': return new Date(now.getTime() + 86400000).toISOString();
      case '1week': return new Date(now.getTime() + 7 * 86400000).toISOString();
      case '1month': return new Date(now.getTime() + 30 * 86400000).toISOString();
      case 'custom':
        if (customDate && customTime) {
          return new Date(`${customDate}T${customTime}:00`).toISOString();
        }
        return new Date(now.getTime() + 3600000).toISOString();
      default: return new Date(now.getTime() + 3600000).toISOString();
    }
  };

  const startEncryption = async () => {
    setIsEncrypting(true);
    setStep(4);
    try {
      // Simulate progress (real progress comes from Tauri events)
      let progress = 0;
      const interval = setInterval(() => {
        progress += Math.random() * 15;
        if (progress > 95) progress = 95;
        setEncryptProgress(progress);
      }, 500);

      const filePaths = files.map(f => f.path);
      const unlockAt = getUnlockDate();

      await api.createLocker(name, filePaths, password, unlockAt);

      clearInterval(interval);
      setEncryptProgress(100);
      setTimeout(() => {
        setStep(5);
        setIsEncrypting(false);
      }, 500);
    } catch (err) {
      setIsEncrypting(false);
      addToast(`Encryption failed: ${err}`, 'error');
      setStep(3);
    }
  };

  const passwordStrength = (() => {
    if (!password) return 0;
    let score = 0;
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    return Math.min(score, 4);
  })();

  const strengthLabel = ['', 'Weak', 'Fair', 'Good', 'Strong'][passwordStrength];
  const strengthClass = ['', 'weak', 'fair', 'good', 'strong'][passwordStrength];

  const canProceed = (() => {
    switch (step) {
      case 0: return name.trim().length >= 2;
      case 1: return files.length > 0;
      case 2: return password.length >= 8 && password === confirmPassword;
      case 3: return unlockPreset !== '';
      default: return false;
    }
  })();

  return (
    <>
      <header className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)' }}>
          <button className="btn btn-ghost btn-icon" onClick={onCancel}>
            <ArrowLeft size={18} />
          </button>
          <h1>Create Locker</h1>
        </div>
      </header>
      <div className="page-body">
        <div className="wizard">
          {/* Step Indicators */}
          <div className="wizard-steps">
            {Array.from({ length: totalSteps }).map((_, i) => (
              <div
                key={i}
                className={`wizard-step-indicator ${i === step ? 'active' : ''} ${i < step ? 'completed' : ''}`}
              />
            ))}
          </div>

          {/* Step 0: Name */}
          {step === 0 && (
            <div className="wizard-content">
              <h2 className="wizard-title">Name Your Locker</h2>
              <p className="wizard-subtitle">Give your encrypted vault a memorable name</p>
              <div className="input-group">
                <label className="input-label">Locker Name</label>
                <input
                  className="input-field"
                  type="text"
                  placeholder="e.g., Project Vault"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  maxLength={64}
                  autoFocus
                />
              </div>
            </div>
          )}

          {/* Step 1: Files */}
          {step === 1 && (
            <div className="wizard-content">
              <h2 className="wizard-title">Select Files & Folders</h2>
              <p className="wizard-subtitle">Choose what to protect inside your locker</p>
              <div style={{ display: 'flex', gap: 'var(--space-3)', marginBottom: 'var(--space-3)' }}>
                <button className="btn btn-secondary" onClick={addFiles} type="button">
                  <File size={16} /> Browse Files
                </button>
                <button className="btn btn-secondary" onClick={addFolder} type="button">
                  <FolderOpen size={16} /> Browse Folder
                </button>
              </div>
              <div style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-4)' }}>
                <input
                  className="input-field"
                  type="text"
                  placeholder="Or enter path directly: e.g. /home/user/document.pdf"
                  value={manualPath}
                  onChange={e => setManualPath(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      addManualPath();
                    }
                  }}
                  style={{ flex: 1 }}
                />
                <button
                  className="btn btn-secondary"
                  type="button"
                  onClick={addManualPath}
                  disabled={!manualPath.trim()}
                >
                  <Plus size={16} /> Add
                </button>
              </div>
              {files.length > 0 ? (
                <div className="file-list">
                  {files.map((f, i) => (
                    <div key={i} className="file-item">
                      <span className="file-item-icon">{f.isDir ? <FolderOpen size={16} /> : <File size={16} />}</span>
                      <span className="file-item-name" title={f.path}>{f.name} <small style={{ opacity: 0.6, marginLeft: '6px' }}>({f.path})</small></span>
                      <button className="file-item-remove" onClick={() => removeFile(i)} type="button">
                        <X size={14} />
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <p style={{ color: 'var(--color-text-muted)', fontSize: 'var(--font-size-sm)', fontStyle: 'italic' }}>
                  No files or folders selected yet. Use the buttons above to browse or enter a path.
                </p>
              )}
            </div>
          )}

          {/* Step 2: Password */}
          {step === 2 && (
            <div className="wizard-content">
              <h2 className="wizard-title">Set Password</h2>
              <p className="wizard-subtitle">Choose a strong password — your data cannot be recovered without it</p>
              <div className="input-group" style={{ marginBottom: 'var(--space-4)' }}>
                <label className="input-label">Password</label>
                <div style={{ position: 'relative' }}>
                  <input
                    className="input-field"
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Enter a strong password"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    autoFocus
                  />
                  <button
                    className="btn btn-ghost btn-icon"
                    style={{ position: 'absolute', right: '4px', top: '50%', transform: 'translateY(-50%)' }}
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    <Eye size={16} />
                  </button>
                </div>
                {password && (
                  <>
                    <div className="password-strength">
                      {[1, 2, 3, 4].map(i => (
                        <div key={i} className={`password-strength-bar ${i <= passwordStrength ? strengthClass : ''}`} />
                      ))}
                    </div>
                    <span style={{ fontSize: 'var(--text-xs)', color: `var(--color-${strengthClass === 'weak' ? 'danger' : strengthClass === 'fair' ? 'warning' : strengthClass === 'good' ? 'info' : 'success'})` }}>
                      {strengthLabel}
                    </span>
                  </>
                )}
              </div>
              <div className="input-group">
                <label className="input-label">Confirm Password</label>
                <input
                  className={`input-field ${confirmPassword && password !== confirmPassword ? 'input-error' : ''}`}
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Confirm your password"
                  value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)}
                />
                {confirmPassword && password !== confirmPassword && (
                  <span className="input-error-text">Passwords do not match</span>
                )}
              </div>
            </div>
          )}

          {/* Step 3: Timer */}
          {step === 3 && (
            <div className="wizard-content">
              <h2 className="wizard-title">Set Unlock Time</h2>
              <p className="wizard-subtitle">The locker will remain sealed until the timer expires</p>
              <div className="datetime-presets">
                {[
                  { value: '5min', label: '5 Minutes' },
                  { value: '1hour', label: '1 Hour' },
                  { value: '1day', label: '1 Day' },
                  { value: '1week', label: '1 Week' },
                  { value: '1month', label: '1 Month' },
                  { value: 'custom', label: 'Custom' },
                ].map(preset => (
                  <button
                    key={preset.value}
                    className={`datetime-preset ${unlockPreset === preset.value ? 'active' : ''}`}
                    onClick={() => setUnlockPreset(preset.value)}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
              {unlockPreset === 'custom' && (
                <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
                  <div className="input-group" style={{ flex: 1 }}>
                    <label className="input-label">Date</label>
                    <input
                      className="input-field"
                      type="date"
                      value={customDate}
                      onChange={e => setCustomDate(e.target.value)}
                    />
                  </div>
                  <div className="input-group" style={{ flex: 1 }}>
                    <label className="input-label">Time</label>
                    <input
                      className="input-field"
                      type="time"
                      value={customTime}
                      onChange={e => setCustomTime(e.target.value)}
                    />
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step 4: Encrypting */}
          {step === 4 && (
            <div className="wizard-content">
              <div className="encrypt-progress">
                <h2 className="wizard-title">Encrypting</h2>
                <p className="wizard-subtitle">Your data is being encrypted with AES-256-GCM</p>
                <div className="encrypt-progress-percentage gradient-text">
                  {Math.round(encryptProgress)}%
                </div>
                <div className="progress-bar" style={{ marginTop: 'var(--space-4)' }}>
                  <div className="progress-bar-fill" style={{ width: `${encryptProgress}%` }} />
                </div>
                <div className="encrypt-progress-stats">
                  <div className="encrypt-progress-stat">
                    <span className="encrypt-progress-stat-value">AES-256-GCM</span>
                    <span>Encryption</span>
                  </div>
                  <div className="encrypt-progress-stat">
                    <span className="encrypt-progress-stat-value">Argon2id</span>
                    <span>Key Derivation</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Step 5: Complete */}
          {step === 5 && (
            <div className="wizard-content" style={{ textAlign: 'center' }}>
              <div style={{
                width: '80px', height: '80px', borderRadius: '50%',
                background: 'var(--color-success-muted)', display: 'flex',
                alignItems: 'center', justifyContent: 'center', margin: '0 auto var(--space-6)',
                color: 'var(--color-success)', fontSize: 'var(--text-3xl)'
              }}>
                <Check size={40} />
              </div>
              <h2 className="wizard-title">Locker Sealed! 🔒</h2>
              <p className="wizard-subtitle">
                Your data is now encrypted and protected.
                <br />
                The locker will unlock at the scheduled time.
              </p>
              <button className="btn btn-primary btn-lg" onClick={onComplete} style={{ marginTop: 'var(--space-4)' }}>
                Go to Dashboard
              </button>
            </div>
          )}

          {/* Navigation */}
          {step < 4 && (
            <div className="wizard-actions">
              <button
                className="btn btn-secondary"
                onClick={() => step === 0 ? onCancel() : setStep(step - 1)}
              >
                <ArrowLeft size={16} /> {step === 0 ? 'Cancel' : 'Back'}
              </button>
              <button
                className="btn btn-primary"
                disabled={!canProceed}
                onClick={() => step === 3 ? startEncryption() : setStep(step + 1)}
              >
                {step === 3 ? (
                  <><Lock size={16} /> Encrypt & Lock</>
                ) : (
                  <><ArrowRight size={16} /> Next</>
                )}
              </button>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// ─── Locker Detail / Unlock Screen ──────────────────────
function LockerDetail({ lockerId, onBack, addToast }: {
  lockerId: string;
  onBack: () => void;
  addToast: (msg: string, type: 'success' | 'error' | 'info') => void;
}) {
  const [locker, setLocker] = useState<LockerRecord | null>(null);
  const { days, hours, minutes, seconds, isExpired, isLocked } = useCountdown(lockerId);
  const [password, setPassword] = useState('');
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [passwordError, setPasswordError] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  useEffect(() => {
    api.getLocker(lockerId).then(l => setLocker(l || null)).catch(() => {});
  }, [lockerId]);

  const pad = (n: number) => n.toString().padStart(2, '0');

  const handleUnlock = async () => {
    if (!password) return;
    setIsUnlocking(true);
    setPasswordError('');
    try {
      // First verify password
      const valid = await api.verifyPassword(lockerId, password);
      if (!valid) {
        setPasswordError('Incorrect password');
        setIsUnlocking(false);
        return;
      }

      // Pick output directory
      const { open } = await import('@tauri-apps/plugin-dialog');
      const outputDir = await open({ directory: true, title: 'Choose extraction folder' });
      if (!outputDir) {
        setIsUnlocking(false);
        return;
      }

      await api.decryptLocker(lockerId, password, outputDir as string);
      addToast('Locker unlocked! Files extracted.', 'success');
      onBack();
    } catch (err) {
      setPasswordError(`${err}`);
    }
    setIsUnlocking(false);
  };

  if (!locker) {
    return (
      <div className="page-body">
        <div className="empty-state"><p>Loading...</p></div>
      </div>
    );
  }

  const isUnlocked = locker.status === 'unlocked';

  return (
    <>
      <header className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)' }}>
          <button className="btn btn-ghost btn-icon" onClick={onBack}>
            <ArrowLeft size={18} />
          </button>
          <h1>{locker.name}</h1>
        </div>
        <span className={`locker-card-status ${isUnlocked ? 'unlocked' : isExpired ? 'unlockable' : 'locked'}`}>
          {isUnlocked ? '✓ Unlocked' : isExpired ? '🔓 Ready to Unlock' : '🔒 Locked'}
        </span>
      </header>

      <div className="page-body">
        <div className="unlock-screen">
          {/* Lock Icon */}
          <div className={`unlock-lock-icon ${isExpired || isUnlocked ? 'unlockable' : 'locked'}`}>
            {isExpired || isUnlocked ? <Unlock size={44} /> : <Lock size={44} />}
          </div>

          {/* Title */}
          <h2 className="unlock-title">
            {isUnlocked ? 'LOCKER UNLOCKED' : isExpired ? 'READY TO UNLOCK' : 'LOCKER SEALED'}
          </h2>
          <p className="unlock-subtitle">
            {isUnlocked
              ? 'Your files have been successfully extracted.'
              : isExpired
                ? 'Enter your password to decrypt and extract your files.'
                : 'Your encrypted data is protected.'}
          </p>

          {/* Countdown */}
          {isLocked && !isUnlocked && (
            <>
              <div className="unlock-countdown">
                {pad(days)}:{pad(hours)}:{pad(minutes)}:{pad(seconds)}
              </div>
              <div className="unlock-countdown-label">
                <span>Days</span>
                <span>Hours</span>
                <span>Minutes</span>
                <span>Seconds</span>
              </div>
            </>
          )}

          {/* Info */}
          <div style={{
            display: 'flex', gap: 'var(--space-8)', marginBottom: 'var(--space-8)',
            color: 'var(--color-text-secondary)', fontSize: 'var(--text-sm)'
          }}>
            <div><strong>{formatSize(locker.total_size)}</strong><br />Size</div>
            <div><strong>{locker.file_count}</strong><br />Files</div>
            <div><strong>{formatDate(locker.unlock_at)}</strong><br />Unlock Date</div>
          </div>

          {/* Password / Unlock */}
          {(isExpired && !isUnlocked) && (
            <div className="unlock-password-section">
              <div className="input-group" style={{ marginBottom: 'var(--space-4)' }}>
                <div style={{ position: 'relative' }}>
                  <input
                    className={`input-field ${passwordError ? 'input-error' : ''}`}
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Enter password"
                    value={password}
                    onChange={e => { setPassword(e.target.value); setPasswordError(''); }}
                    onKeyDown={e => e.key === 'Enter' && handleUnlock()}
                    disabled={isUnlocking}
                    autoFocus
                    style={{ textAlign: 'center', fontSize: 'var(--text-lg)', paddingRight: '48px' }}
                  />
                  <button
                    className="btn btn-ghost btn-icon"
                    style={{ position: 'absolute', right: '4px', top: '50%', transform: 'translateY(-50%)' }}
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    <Eye size={16} />
                  </button>
                </div>
                {passwordError && <span className="input-error-text">{passwordError}</span>}
              </div>
              <button
                className="btn btn-primary btn-lg"
                onClick={handleUnlock}
                disabled={isUnlocking || !password}
                style={{ width: '100%' }}
              >
                {isUnlocking ? 'Decrypting...' : <><KeyRound size={18} /> Unlock & Extract</>}
              </button>
            </div>
          )}

          {/* Locked state - disabled password */}
          {isLocked && !isUnlocked && (
            <div className="unlock-password-section" style={{ opacity: 0.4 }}>
              <div className="input-group">
                <input
                  className="input-field"
                  type="password"
                  placeholder="Password available when timer expires"
                  disabled
                  style={{ textAlign: 'center', cursor: 'not-allowed' }}
                />
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
