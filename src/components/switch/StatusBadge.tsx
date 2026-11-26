import React from 'react';
import { SwitchStatus } from '@/types/switch';

export interface StatusBadgeProps {
  status: SwitchStatus;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'md' }) => {
  const config = {
    ACTIVE: {
      label: 'Active',
      bg: 'bg-emerald-950/60',
      text: 'text-emerald-400',
      border: 'border-emerald-800/60',
      dot: 'bg-emerald-400'
    },
    PENDING_GRACE: {
      label: 'Grace Period',
      bg: 'bg-amber-950/60',
      text: 'text-amber-400',
      border: 'border-amber-800/60',
      dot: 'bg-amber-400'
    },
    TRIGGERED: {
      label: 'Triggered',
      bg: 'bg-red-950/60',
      text: 'text-red-400',
      border: 'border-red-800/60',
      dot: 'bg-red-400'
    },
    CANCELLED: {
      label: 'Cancelled',
      bg: 'bg-zinc-900',
      text: 'text-zinc-400',
      border: 'border-zinc-800',
      dot: 'bg-zinc-500'
    },
    PAUSED: {
      label: 'Paused',
      bg: 'bg-blue-950/60',
      text: 'text-blue-400',
      border: 'border-blue-800/60',
      dot: 'bg-blue-400'
    }
  };

  const current = config[status] || config.ACTIVE;
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-1 text-xs';

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md font-medium border ${current.bg} ${current.text} ${current.border} ${sizeClasses}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${current.dot}`} />
      {current.label}
    </span>
  );
};
