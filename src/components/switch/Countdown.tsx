'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { Clock, AlertTriangle } from 'lucide-react';
import { SwitchStatus } from '@/types/switch';

export interface CountdownProps {
  targetDate: string;
  status: SwitchStatus;
  showLabels?: boolean;
}

interface TimeRemaining {
  days: number;
  hours: number;
  minutes: number;
  seconds: number;
}

export const Countdown: React.FC<CountdownProps> = ({ 
  targetDate, 
  status,
  showLabels = true 
}) => {
  const calculateTimeLeft = useCallback((): TimeRemaining => {
    const difference = +new Date(targetDate) - +new Date();
    if (difference <= 0) {
      return { days: 0, hours: 0, minutes: 0, seconds: 0 };
    }

    return {
      days: Math.floor(difference / (1000 * 60 * 60 * 24)),
      hours: Math.floor((difference / (1000 * 60 * 60)) % 24),
      minutes: Math.floor((difference / 1000 / 60) % 60),
      seconds: Math.floor((difference / 1000) % 60)
    };
  }, [targetDate]);

  const [timeLeft, setTimeLeft] = useState<TimeRemaining>(calculateTimeLeft());

  useEffect(() => {
    const timer = setInterval(() => {
      setTimeLeft(calculateTimeLeft());
    }, 1000);
    return () => clearInterval(timer);
  }, [calculateTimeLeft]);

  if (status === 'TRIGGERED') {
    return (
      <div className="flex items-center gap-1.5 text-red-400 text-xs font-medium">
        <AlertTriangle className="w-3.5 h-3.5" />
        <span>Triggered & Released</span>
      </div>
    );
  }

  if (status === 'CANCELLED') {
    return (
      <div className="flex items-center gap-1.5 text-zinc-500 text-xs">
        <Clock className="w-3.5 h-3.5" />
        <span>Switch Inactive</span>
      </div>
    );
  }

  if (status === 'PAUSED') {
    return (
      <div className="flex items-center gap-1.5 text-blue-400 text-xs font-medium">
        <Clock className="w-3.5 h-3.5" />
        <span>Switch Paused (Timer Frozen)</span>
      </div>
    );
  }

  return (
    <div className="space-y-1">
      {showLabels && (
        <div className="flex items-center gap-1 text-[11px] text-zinc-400">
          <Clock className="w-3.5 h-3.5 text-zinc-400" />
          <span>Next check-in due in</span>
        </div>
      )}
      <div className="flex items-center gap-1 text-sm font-semibold font-mono text-zinc-200">
        <span>{timeLeft.days}d</span>
        <span className="text-zinc-500">:</span>
        <span>{String(timeLeft.hours).padStart(2, '0')}h</span>
        <span className="text-zinc-500">:</span>
        <span>{String(timeLeft.minutes).padStart(2, '0')}m</span>
        <span className="text-zinc-500">:</span>
        <span>{String(timeLeft.seconds).padStart(2, '0')}s</span>
      </div>
    </div>
  );
};
