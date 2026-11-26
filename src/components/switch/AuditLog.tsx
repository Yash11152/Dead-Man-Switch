import React from 'react';
import { AuditLogEntry } from '@/types/switch';
import { Activity, CheckCircle2, AlertTriangle, XCircle, Clock, Shield, FileText, Key, Bell, User, Trash2 } from 'lucide-react';

export interface AuditLogProps {
  logs: AuditLogEntry[];
  title?: string;
  isLoading?: boolean;
  error?: string | null;
}

const EVENT_CONFIG: Record<string, { icon: React.ElementType; color: string; label: string }> = {
  CHECK_IN: { icon: CheckCircle2, color: 'text-emerald-400', label: 'Check-In' },
  SWITCH_CREATED: { icon: Shield, color: 'text-emerald-400', label: 'Switch Created' },
  CONFIG_UPDATED: { icon: Activity, color: 'text-blue-400', label: 'Config Updated' },
  SWITCH_CANCELLED: { icon: XCircle, color: 'text-zinc-400', label: 'Cancelled' },
  GRACE_PERIOD_STARTED: { icon: AlertTriangle, color: 'text-amber-400', label: 'Grace Period' },
  SWITCH_TRIGGERED: { icon: AlertTriangle, color: 'text-red-400', label: 'Triggered' },
  FILE_UPLOADED: { icon: FileText, color: 'text-blue-400', label: 'File Uploaded' },
  FILE_DELETED: { icon: FileText, color: 'text-zinc-400', label: 'File Deleted' },
  CLAIM_TOKEN_ISSUED: { icon: Key, color: 'text-emerald-400', label: 'Token Issued' },
  CLAIM_TOKEN_ROTATED: { icon: Key, color: 'text-amber-400', label: 'Token Rotated' },
  CLAIM_REDEEMED: { icon: Key, color: 'text-emerald-400', label: 'Claim Redeemed' },
  CLAIM_REJECTED: { icon: XCircle, color: 'text-red-400', label: 'Claim Rejected' },
  PROFILE_UPDATED: { icon: User, color: 'text-blue-400', label: 'Profile Updated' },
  NOTIFICATION_QUEUED: { icon: Bell, color: 'text-zinc-400', label: 'Notification Queued' },
  SWITCH_DELETED: { icon: Trash2, color: 'text-red-400', label: 'Switch Deleted' },
};

function getEventConfig(eventType: string) {
  return EVENT_CONFIG[eventType] ?? { icon: Activity, color: 'text-zinc-400', label: eventType };
}

function formatDetails(details?: Record<string, unknown>): string | null {
  if (!details || Object.keys(details).length === 0) return null;
  // Surface the most useful fields
  const parts: string[] = [];
  if (details.switch_title) parts.push(String(details.switch_title));
  if (details.reason) parts.push(`Reason: ${String(details.reason).replace(/_/g, ' ')}`);
  if (details.recipient_email) parts.push(`Recipient: ${String(details.recipient_email)}`);
  if (details.files_released != null) parts.push(`Files released: ${String(details.files_released)}`);
  if (details.grace_period_hours) parts.push(`Grace: ${String(details.grace_period_hours)}h`);
  return parts.length > 0 ? parts.join(' · ') : null;
}

export const AuditLog: React.FC<AuditLogProps> = ({
  logs,
  title = 'Recent Activity',
  isLoading = false,
  error = null,
}) => {
  const formatDate = (isoString: string) => {
    try {
      return new Date(isoString).toLocaleString('en-US', {
        month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit',
      });
    } catch {
      return isoString;
    }
  };

  return (
    <div className="rounded-lg bg-zinc-900/60 border border-zinc-800 p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
        <h3 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
          <Activity className="w-4 h-4 text-zinc-400" />
          {title}
        </h3>
        {isLoading && (
          <div className="w-4 h-4 border-2 border-zinc-600 border-t-emerald-400 rounded-full animate-spin" />
        )}
      </div>

      {error && (
        <p className="text-xs text-red-400 py-2 text-center">{error}</p>
      )}

      {!isLoading && !error && (
        <div className="space-y-2 text-xs">
          {logs.map((log) => {
            const { icon: Icon, color, label } = getEventConfig(log.eventType);
            const detailText = formatDetails(log.details);
            return (
              <div
                key={log.id}
                className="p-3 rounded bg-zinc-950/60 border border-zinc-800/80 flex flex-col sm:flex-row sm:items-start justify-between gap-2"
              >
                <div className="flex items-start gap-2.5 min-w-0">
                  <Icon className={`w-3.5 h-3.5 mt-0.5 shrink-0 ${color}`} />
                  <div className="min-w-0">
                    <span className="font-medium text-zinc-200">{label}</span>
                    {detailText && (
                      <p className="text-zinc-400 text-[11px] mt-0.5 truncate">{detailText}</p>
                    )}
                    {log.actor && (
                      <p className="text-zinc-600 text-[10px] font-mono mt-0.5">{log.actor}</p>
                    )}
                  </div>
                </div>
                <div className="text-[11px] text-zinc-500 font-mono shrink-0 whitespace-nowrap">
                  {formatDate(log.createdAt)}
                </div>
              </div>
            );
          })}

          {logs.length === 0 && !isLoading && (
            <div className="flex flex-col items-center gap-2 py-6 text-zinc-600">
              <Clock className="w-5 h-5" />
              <p className="text-center text-xs">No audit events recorded yet.</p>
            </div>
          )}
        </div>
      )}

      {isLoading && logs.length === 0 && (
        <div className="py-6 flex justify-center">
          <div className="w-5 h-5 border-2 border-zinc-700 border-t-emerald-400 rounded-full animate-spin" />
        </div>
      )}
    </div>
  );
};
