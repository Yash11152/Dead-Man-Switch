'use client';

import React, { useState } from 'react';
import { CheckCircle2 } from 'lucide-react';
import { Button } from '@/components/ui/Button';

export interface CheckInButtonProps {
  switchId: string;
  switchTitle?: string;
  disabled?: boolean;
  onCheckInSuccess?: (switchId: string) => Promise<void> | void;
  size?: 'sm' | 'md' | 'lg';
}

export const CheckInButton: React.FC<CheckInButtonProps> = ({
  switchId,
  disabled = false,
  onCheckInSuccess,
  size = 'sm'
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [justCheckedIn, setJustCheckedIn] = useState(false);

  const handleCheckIn = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();

    if (disabled || isLoading) return;
    setIsLoading(true);

    try {
      if (onCheckInSuccess) {
        await onCheckInSuccess(switchId);
      }
      setJustCheckedIn(true);
      setTimeout(() => {
        setJustCheckedIn(false);
      }, 3000);
    } catch (err) {
      console.error('Check-in button caught error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  if (justCheckedIn) {
    return (
      <Button
        variant="secondary"
        size={size}
        disabled
        leftIcon={<CheckCircle2 className="w-4 h-4 text-emerald-400" />}
      >
        Checked In!
      </Button>
    );
  }

  return (
    <Button
      variant="primary"
      size={size}
      isLoading={isLoading}
      disabled={disabled || isLoading}
      onClick={handleCheckIn}
    >
      Check In
    </Button>
  );
};
