import { useState, useEffect, useRef, useCallback } from 'react';
import type { TimerStatus } from '../lib/types';
import * as api from '../lib/api';

/**
 * Hook for live countdown timer that updates every second.
 */
export function useCountdown(lockerId: string | null) {
  const [status, setStatus] = useState<TimerStatus | null>(null);
  const [remaining, setRemaining] = useState(0);
  const intervalRef = useRef<number | null>(null);

  const fetchStatus = useCallback(async () => {
    if (!lockerId) return;
    try {
      const s = await api.getTimerStatus(lockerId);
      setStatus(s);
      setRemaining(s.remaining_seconds);
    } catch (err) {
      console.error('Timer fetch failed:', err);
    }
  }, [lockerId]);

  useEffect(() => {
    fetchStatus();

    // Refresh from backend every 60 seconds for accuracy
    const refreshInterval = setInterval(fetchStatus, 60000);

    return () => clearInterval(refreshInterval);
  }, [fetchStatus]);

  useEffect(() => {
    if (remaining <= 0) {
      if (intervalRef.current) clearInterval(intervalRef.current);
      return;
    }

    intervalRef.current = window.setInterval(() => {
      setRemaining((prev) => {
        if (prev <= 1) {
          if (intervalRef.current) clearInterval(intervalRef.current);
          // Refresh status from backend
          fetchStatus();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [remaining, fetchStatus]);

  const days = Math.floor(remaining / 86400);
  const hours = Math.floor((remaining % 86400) / 3600);
  const minutes = Math.floor((remaining % 3600) / 60);
  const seconds = Math.floor(remaining % 60);

  return {
    status,
    remaining,
    days,
    hours,
    minutes,
    seconds,
    isExpired: remaining <= 0 && status?.is_unlockable === true,
    isLocked: remaining > 0,
  };
}
