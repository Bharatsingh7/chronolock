# ChronoLock

[![Build Status](https://github.com/Bharatsingh7/chronolock/actions/workflows/release.yml/badge.svg)](https://github.com/Bharatsingh7/chronolock/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-brightgreen.svg)](#-releases--packages)
[![Cryptography](https://img.shields.io/badge/Crypto-AES--256--GCM%20%7C%20Argon2id-blueviolet.svg)](#-cryptography--security-architecture)
[![Streaming](https://img.shields.io/badge/Capacity-50GB%2B%20Streaming-orange.svg)](#-high-throughput-streaming-engine)

**ChronoLock** is an industrial-grade, cross-platform encrypted time vault application built for **Windows 10/11** and **modern Linux distributions**.

It empowers users to seal sensitive files, folders, and entire directories inside tamper-resistant, authenticated cryptographic containers locked against an immutable countdown timer. Until the designated expiration timestamp has elapsed, unlock attempts are strictly rejected by the cryptographic engine—even when supplied with the master password.

---

## 📦 Releases & Packages

Pre-compiled binary packages and full source code archives are published directly under [**GitHub Releases**](https://github.com/Bharatsingh7/chronolock/releases).

| Operating System | Package Type | Artifact | Description / Installation |
|:---|:---|:---|:---|
| **Windows 10 / 11** | **NSIS Setup Installer** | `ChronoLock-setup.exe` | Complete desktop setup wizard with start menu shortcuts |
| **Windows 10 / 11** | **MSI Package** | `ChronoLock.msi` | Enterprise Windows installer for silent or system deployment |
| **Linux (Universal)** | **AppImage** | `ChronoLock.AppImage` | Portable standalone package (`chmod +x ChronoLock*.AppImage && ./ChronoLock*.AppImage`) |
| **Linux (Ubuntu / Debian)** | **Debian Package** | `ChronoLock_amd64.deb` | Standard package (`sudo dpkg -i ChronoLock*.deb`) |
| **Linux (Fedora / RHEL)** | **RPM Package** | `ChronoLock.x86_64.rpm` | RedHat / Fedora package (`sudo rpm -i ChronoLock*.rpm`) |
| **All Platforms** | **Source Code Archive** | `Source code (zip / tar.gz)` | Complete source tree for auditing and local compilation |

👉 **Download all packages and source archives directly from the [Releases page](https://github.com/Bharatsingh7/chronolock/releases).**

---

## ⚡ Core Highlights

### 1. Authenticated Cryptographic Protection
- **AES-256-GCM Encryption**: All payload files, directories, and manifests are sealed using authenticated 256-bit AES in Galois/Counter Mode with sequential chunk-level nonces.
- **Argon2id Key Derivation**: High-entropy master key derived with memory-hard Argon2id (isolated 32-byte CSPRNG salt per vault).
- **HKDF Subkey Separation**: Master key material is expanded via HKDF-SHA256 into isolated subkeys:
  - Data Encryption Key (`DEK`)
  - Metadata Encryption Key (`MEK`)
  - Authentication Footer Key (`AuthKey`)
- **Strict Key Zeroization**: Ephemeral key buffers and sensitive cryptographic structures implement Rust's `Zeroize` on drop to prevent residue in volatile memory.

### 2. Cryptographically Enforced Time-Lock
- **Live Countdown Timers**: Real-time visualization with active duration counters down to the second.
- **Anti-Clock-Tampering Network Verification**: Synchronizes against RFC 4330 SNTP network time servers (`pool.ntp.org`, `time.google.com`, `time.cloudflare.com`) to detect manual adjustments to the system clock. If local clock manipulation is detected, access remains locked.
- **Engine-Level Rejection**: Early decryption requests are halted and rejected at the backend core before attempting any decryption operations.

### 3. Industrial Deletion Security
- **Protected Active Vaults**: Time-sealed vaults cannot be deleted from the system or registry before timer expiration unless authorized with the valid master password.
- **Physical Write-Protection**: Vault files on disk have their write permissions restricted (`set_readonly(true)`) to mitigate accidental deletion or truncation by third-party processes.

### 4. 50GB+ Memory-Bounded Streaming Engine
- **Chunked AEAD Pipeline**: Files are streamed in 1 MB chunks, maintaining a constant low memory footprint (<50 MB RAM) even when processing containers exceeding 50 GB.
- **Power-Loss & Crash Resilience**: All writes are committed to temporary scratch locations and committed atomically with full hardware disk synchronization (`file.sync_all()`).
- **Integrity Verification**: HMAC-SHA256 footers and BLAKE3 file checksums validate every byte during extraction. Source files remain untouched.

---

## 🛡️ Architecture & Cryptographic Specification

### Key Derivation Flow
```
User Password + 32-Byte CSPRNG Salt
                  │
                  ▼
         ┌──────────────────┐
         │     Argon2id     │ (Memory-hard password KDF)
         └────────┬─────────┘
                  │
                  ▼ Master Key (32 bytes)
         ┌──────────────────┐
         │   HKDF-SHA256    │ (Context separation)
         └────────┬─────────┘
                  ├───► Data Encryption Key (DEK)
                  ├───► Metadata Encryption Key (MEK)
                  └───► Integrity Authentication Key (AuthKey)
```

### Container Binary Specification
```
┌──────────────────────────────────────────────────────────┐
│ Magic Identifier ("TLOCKER\0", 8 bytes)                  │
├──────────────────────────────────────────────────────────┤
│ Format Version (2 bytes, Little Endian)                  │
├──────────────────────────────────────────────────────────┤
│ Salt (32 bytes, CSPRNG)                                  │
├──────────────────────────────────────────────────────────┤
│ KDF Configuration Parameters (Memory, Iterations, Lanes) │
├──────────────────────────────────────────────────────────┤
│ Lock Expiration Timestamp (i64 UTC, 8 bytes)             │
├──────────────────────────────────────────────────────────┤
│ Metadata Length (u64, 8 bytes)                           │
├──────────────────────────────────────────────────────────┤
│ Encrypted Metadata Block (AES-256-GCM + 12-byte Nonce)   │
├──────────────────────────────────────────────────────────┤
│ Encrypted Data Stream (Sequential 1MB Chunks + Nonces)   │
├──────────────────────────────────────────────────────────┤
│ Container Verification Footer (HMAC-SHA256, 32 bytes)    │
└──────────────────────────────────────────────────────────┘
```

---

## 🛠️ Building from Source

### Prerequisites
- **Node.js**: `v20.x` or later
- **Rust**: `1.75.0` or later
- **System Dependencies**:
  - **Ubuntu / Debian**:
    ```bash
    sudo apt-get update
    sudo apt-get install -y build-essential libwebkit2gtk-4.1-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
    ```
  - **Fedora / RHEL**:
    ```bash
    sudo dnf install webkit2gtk4.1-devel openssl-devel libappindicator-gtk3-devel librsvg2-devel
    ```
  - **Arch Linux**:
    ```bash
    sudo pacman -S --needed base-devel webkit2gtk-4.1 openssl libappindicator-gtk3 librsvg
    ```

### Build Commands

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Bharatsingh7/chronolock.git
   cd chronolock
   ```

2. **Install frontend dependencies**:
   ```bash
   npm install
   ```

3. **Run test suites**:
   ```bash
   cd src-tauri
   cargo test
   cd ..
   ```

4. **Launch development mode**:
   ```bash
   npm run tauri dev
   ```

5. **Compile release binaries and installers**:
   ```bash
   npm run tauri build
   ```
   Built packages will be placed in `src-tauri/target/release/bundle/`:
   - **Linux**: `bundle/appimage/`, `bundle/deb/`, `bundle/rpm/`
   - **Windows**: `bundle/msi/`, `bundle/nsis/`

---

## 📄 License

This project is licensed under the terms of the [MIT License](LICENSE).
