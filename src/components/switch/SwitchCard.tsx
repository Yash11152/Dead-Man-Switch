'use client';

import React from 'react';
import Link from 'next/link';
import { Eye, User, FileText, Trash2 } from 'lucide-react';
import { DeadManSwitch } from '@/types/switch';
import { StatusBadge } from './StatusBadge';
import { Countdown } from './Countdown';
import { CheckInButton } from './CheckInButton';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';

export interface SwitchCardProps {
  switchItem: DeadManSwitch;
  onCheckIn?: (id: string) => Promise<void> | void;
  onDelete?: (switchItem: DeadManSwitch) => void;
}

export const SwitchCard: React.FC<SwitchCardProps> = ({ switchItem, onCheckIn, onDelete }) => {
  const primaryRecipient = switchItem.recipients[0];
  const isInactive = switchItem.status === 'TRIGGERED' || switchItem.status === 'CANCELLED' || switchItem.status === 'PAUSED';
  const canDelete = switchItem.status === 'CANCELLED' || switchItem.status === 'TRIGGERED';

  const formatDate = (isoString: string) => {
    try {
      const date = new Date(isoString);
      return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric'
      });
    } catch {
      return isoString;
    }
  };

  return (
    <Card className="flex flex-col justify-between hover:border-zinc-700 transition-colors">
      
      {/* Top Header */}
      <CardHeader className="flex flex-row items-start justify-between gap-3">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <StatusBadge status={switchItem.status} size="sm" />
          </div>
          <CardTitle className="text-base text-zinc-100 hover:underline">
            <Link href={`/dashboard/${switchItem.id}`}>
              {switchItem.title}
            </Link>
          </CardTitle>
          <CardDescription className="line-clamp-2">
            {switchItem.description}
          </CardDescription>
        </div>
      </CardHeader>

      {/* Main Body */}
      <CardContent className="space-y-3 py-3">
        
        {/* Countdown */}
        <div className="p-2.5 rounded bg-zinc-950/60 border border-zinc-800">
          <Countdown targetDate={switchItem.nextCheckIn} status={switchItem.status} />
        </div>

        {/* Timestamps */}
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div className="p-2 rounded bg-zinc-950/40 border border-zinc-800/60">
            <span className="text-[11px] text-zinc-500 block">Last Check-In</span>
            <span className="text-zinc-200 font-medium">{formatDate(switchItem.lastCheckIn)}</span>
          </div>
          <div className="p-2 rounded bg-zinc-950/40 border border-zinc-800/60">
            <span className="text-[11px] text-zinc-500 block">Next Check-In</span>
            <span className="text-zinc-200 font-medium">{formatDate(switchItem.nextCheckIn)}</span>
          </div>
        </div>

        {/* Recipient */}
        <div className="flex items-center justify-between p-2 rounded bg-zinc-950/40 border border-zinc-800/60 text-xs">
          <div className="flex items-center gap-2 text-zinc-300">
            <User className="w-3.5 h-3.5 text-zinc-400" />
            <div>
              <span className="text-[10px] text-zinc-500 block">Recipient</span>
              <span className="font-medium text-zinc-200">{primaryRecipient ? primaryRecipient.name : 'None'}</span>
            </div>
          </div>
          {switchItem.recipients.length > 1 && (
            <span className="text-[10px] text-zinc-400">
              +{switchItem.recipients.length - 1} recipient(s)
            </span>
          )}
        </div>

      </CardContent>

      {/* Footer Buttons */}
      <CardFooter className="flex items-center justify-between gap-2 pt-3">
        <div className="flex items-center gap-2">
          <CheckInButton 
            switchId={switchItem.id} 
            switchTitle={switchItem.title} 
            disabled={isInactive}
            onCheckInSuccess={onCheckIn}
            size="sm"
          />

          <Link href={`/dashboard/${switchItem.id}`}>
            <Button variant="outline" size="sm" leftIcon={<Eye className="w-3.5 h-3.5" />}>
              View
            </Button>
          </Link>
        </div>

        {canDelete && onDelete && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => onDelete(switchItem)}
            leftIcon={<Trash2 className="w-3.5 h-3.5" />}
            className="text-red-400 border-red-900/40 hover:bg-red-950/40 hover:border-red-800 hover:text-red-300"
          >
            Delete
          </Button>
        )}
      </CardFooter>

    </Card>
  );
};
