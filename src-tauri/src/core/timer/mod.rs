//! Timer enforcement module
//!
//! Provides time verification using system clock with NTP validation.
//! Detects clock manipulation and enforces unlock timing.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Timer status for a locker.
#[derive(Debug, Clone, Serialize)]
pub struct TimerStatus {
    pub is_locked: bool,
    pub is_unlockable: bool,
    pub remaining_seconds: i64,
    pub remaining_days: i64,
    pub remaining_hours: i64,
    pub remaining_minutes: i64,
    pub remaining_secs: i64,
    pub unlock_at: String,
    pub clock_verified: bool,
}

/// Query an NTP server using standard SNTP protocol (RFC 4330).
pub fn query_ntp(server: &str) -> Option<DateTime<Utc>> {
    let addr = format!("{}:123", server).to_socket_addrs().ok()?.next()?;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_millis(1500))).ok()?;
    socket.set_write_timeout(Some(Duration::from_millis(1500))).ok()?;

    // 48-byte request packet: LI=0, VN=3, Mode=3 (Client)
    let mut request = [0u8; 48];
    request[0] = 0x1B;

    socket.send_to(&request, addr).ok()?;

    let mut response = [0u8; 48];
    let (len, _) = socket.recv_from(&mut response).ok()?;
    if len < 48 {
        return None;
    }

    // Transmit timestamp seconds are at bytes 40..44 (big-endian)
    let secs_since_1900 = u32::from_be_bytes([
        response[40],
        response[41],
        response[42],
        response[43],
    ]) as u64;

    // Difference between 1900-01-01 and 1970-01-01 in seconds: 2,208,988,800
    if secs_since_1900 < 2_208_988_800 {
        return None;
    }
    let unix_secs = (secs_since_1900 - 2_208_988_800) as i64;
    DateTime::from_timestamp(unix_secs, 0)
}

/// Query network time from multiple public NTP servers.
pub fn get_network_time() -> Option<DateTime<Utc>> {
    let servers = [
        "pool.ntp.org",
        "time.google.com",
        "time.cloudflare.com",
    ];
    for server in &servers {
        if let Some(t) = query_ntp(server) {
            return Some(t);
        }
    }
    None
}

/// Returns the trustworthy current time and whether it was network-verified.
///
/// If network time is available and system clock is ahead of network time by > 2 minutes,
/// clock manipulation is detected and network time is used.
pub fn get_verified_time() -> (DateTime<Utc>, bool) {
    let sys_now = Utc::now();
    if let Some(net_now) = get_network_time() {
        if sys_now > net_now + chrono::Duration::minutes(2) {
            tracing::warn!(
                "Clock manipulation detected! System clock: {}, Real network time: {}",
                sys_now,
                net_now
            );
            return (net_now, true);
        }
        return (net_now, true);
    }
    // Offline fallback to system clock
    (sys_now, false)
}

/// Check timer status for a given unlock time.
pub fn check_timer(unlock_at: &DateTime<Utc>) -> TimerStatus {
    let (now, clock_verified) = get_verified_time();

    if now >= *unlock_at {
        return TimerStatus {
            is_locked: false,
            is_unlockable: true,
            remaining_seconds: 0,
            remaining_days: 0,
            remaining_hours: 0,
            remaining_minutes: 0,
            remaining_secs: 0,
            unlock_at: unlock_at.to_rfc3339(),
            clock_verified,
        };
    }

    let remaining = *unlock_at - now;
    let total_seconds = remaining.num_seconds();
    let days = total_seconds / 86400;
    let hours = (total_seconds % 86400) / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let secs = total_seconds % 60;

    TimerStatus {
        is_locked: true,
        is_unlockable: false,
        remaining_seconds: total_seconds,
        remaining_days: days,
        remaining_hours: hours,
        remaining_minutes: minutes,
        remaining_secs: secs,
        unlock_at: unlock_at.to_rfc3339(),
        clock_verified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_timer_future_and_past() {
        let future = Utc::now() + Duration::days(2) + Duration::hours(5);
        let status = check_timer(&future);
        assert!(status.is_locked);
        assert!(!status.is_unlockable);
        assert!(status.remaining_seconds > 0);

        let past = Utc::now() - Duration::hours(1);
        let status_past = check_timer(&past);
        assert!(!status_past.is_locked);
        assert!(status_past.is_unlockable);
        assert_eq!(status_past.remaining_seconds, 0);
    }
}
