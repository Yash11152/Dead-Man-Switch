export type SwitchStatus = 'ACTIVE' | 'PENDING_GRACE' | 'TRIGGERED' | 'CANCELLED' | 'PAUSED';

export interface Recipient {
  id: string;
  name: string;
  email: string;
  phone?: string;
  relation?: string;
}

export interface PayloadFile {
  id: string;
  name: string;
  size: string;
  mimeType: string;
  uploadedAt: string;
  storagePath?: string;
  fileHash?: string | null;
  encrypted?: boolean;
  iv?: string;
  encryptedDekOwner?: string;
  encryptedDekRecipient?: string;
  encryptionVersion?: string;
}

export interface RecipientClaimToken {
  id: string;
  switchId: string;
  recipientId: string;
  tokenHash: string;
  expiresAt: string;
  redeemedAt?: string | null;
  revokedAt?: string | null;
  redemptionCount: number;
  maxRedemptions: number;
  createdAt: string;
}

export interface NotificationOutboxItem {
  id: string;
  switchId: string;
  recipientEmail: string;
  notificationType: 'CHECK_IN_REMINDER' | 'GRACE_PERIOD_WARNING' | 'SWITCH_TRIGGERED';
  subject: string;
  bodyPreview: string;
  idempotencyKey: string;
  status: 'QUEUED' | 'DELIVERED' | 'DRY_RUN' | 'PENDING_CONFIG' | 'FAILED';
  errorMessage?: string | null;
  createdAt: string;
  sentAt?: string | null;
}

export interface DeadManSwitch {
  id: string;
  title: string;
  description: string;
  status: SwitchStatus;
  lastCheckIn: string;
  nextCheckIn: string;
  checkInIntervalDays: number;
  gracePeriodHours: number;
  recipients: Recipient[];
  payloadFiles: PayloadFile[];
  createdAt: string;
}

export type AuditEventType =
  | 'CHECK_IN'
  | 'SWITCH_CREATED'
  | 'CONFIG_UPDATED'
  | 'SWITCH_CANCELLED'
  | 'GRACE_PERIOD_STARTED'
  | 'SWITCH_TRIGGERED'
  | 'FILE_UPLOADED'
  | 'FILE_DELETED'
  | 'CLAIM_TOKEN_ISSUED'
  | 'CLAIM_TOKEN_ROTATED'
  | 'CLAIM_REDEEMED'
  | 'CLAIM_REJECTED'
  | 'PROFILE_UPDATED'
  | 'NOTIFICATION_QUEUED'
  | 'SWITCH_DELETED'
  | string; // allow future/system event types

// Matches the real public.audit_logs DB schema
export interface AuditLogEntry {
  id: string;
  userId?: string;
  switchId?: string;
  eventType: AuditEventType;
  actor?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  createdAt: string;
}

export interface UserProfile {
  name: string;
  email: string;
  role: string;
  twoFactorEnabled: boolean;
  securityTier: string;
  lastLoginIp: string;
  joinedDate: string;
}
