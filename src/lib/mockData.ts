import { DeadManSwitch, AuditLogEntry, UserProfile } from '@/types/switch';

export const MOCK_USER: UserProfile = {
  name: 'Alex Vance',
  email: 'alex.vance@secnet.io',
  role: 'System Administrator & Crypto Vault Owner',
  twoFactorEnabled: true,
  securityTier: 'Tier 3 (Zero-Trust Master)',
  lastLoginIp: '192.168.1.104 (TLS 1.3)',
  joinedDate: '2025-01-15'
};

export const MOCK_SWITCHES: DeadManSwitch[] = [
  {
    id: 'switch-01',
    title: 'Primary Crypto Asset Vault Access',
    description: 'Master seed phrases, offline hardware wallet recovery keys, and encrypted cold storage credentials.',
    status: 'ACTIVE',
    lastCheckIn: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
    nextCheckIn: new Date(Date.now() + 4 * 24 * 60 * 60 * 1000).toISOString(),
    checkInIntervalDays: 7,
    gracePeriodHours: 48,
    recipients: [
      {
        id: 'rec-1',
        name: 'Sarah Vance',
        email: 'sarah.vance@emergency-contact.org',
        phone: '+1 (555) 019-2834',
        relation: 'Spouse / Executor'
      },
      {
        id: 'rec-2',
        name: 'Marcus Brody',
        email: 'm.brody@legalpartners.com',
        phone: '+1 (555) 018-9900',
        relation: 'Legal Counsel'
      }
    ],
    payloadFiles: [
      {
        id: 'file-101',
        name: 'btc_hardware_wallet_backup.enc',
        size: '2.4 MB',
        mimeType: 'application/octet-stream',
        uploadedAt: '2026-02-10'
      },
      {
        id: 'file-102',
        name: 'password_vault_export_gpg.asc',
        size: '840 KB',
        mimeType: 'text/plain',
        uploadedAt: '2026-02-12'
      }
    ],
    createdAt: '2026-01-10T14:30:00Z'
  },
  {
    id: 'switch-02',
    title: 'Cloud Infrastructure Root Credentials',
    description: 'AWS root access keys, Kubernetes cluster master credentials, and production database emergency credentials.',
    status: 'ACTIVE',
    lastCheckIn: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString(),
    nextCheckIn: new Date(Date.now() + 13.5 * 24 * 60 * 60 * 1000).toISOString(),
    checkInIntervalDays: 14,
    gracePeriodHours: 72,
    recipients: [
      {
        id: 'rec-3',
        name: 'David Chen',
        email: 'dchen@secops-team.com',
        phone: '+1 (555) 014-4455',
        relation: 'Lead SecOps Engineer'
      }
    ],
    payloadFiles: [
      {
        id: 'file-201',
        name: 'k8s_prod_cluster_admin.conf.gpg',
        size: '18 KB',
        mimeType: 'application/x-gpg',
        uploadedAt: '2026-01-20'
      }
    ],
    createdAt: '2026-01-15T09:00:00Z'
  },
  {
    id: 'switch-03',
    title: 'Whistleblower Research Data & Whistle Archives',
    description: 'Documented audit findings, telemetry dumps, and investigation notes for legal disclosure.',
    status: 'TRIGGERED',
    lastCheckIn: new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString(),
    nextCheckIn: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
    checkInIntervalDays: 30,
    gracePeriodHours: 24,
    recipients: [
      {
        id: 'rec-4',
        name: 'Elena Rostova',
        email: 'elena@pressfreedom-journal.org',
        phone: '+1 (555) 017-7722',
        relation: 'Investigative Journalist'
      }
    ],
    payloadFiles: [
      {
        id: 'file-301',
        name: 'audit_investigation_dossier.zip.aes',
        size: '142 MB',
        mimeType: 'application/zip',
        uploadedAt: '2025-11-01'
      }
    ],
    createdAt: '2025-11-01T11:20:00Z'
  },
  {
    id: 'switch-04',
    title: 'Deprecated Server Backup Encryption Keys',
    description: 'Legacy database archive keys for 2024 compliance records.',
    status: 'CANCELLED',
    lastCheckIn: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
    nextCheckIn: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString(),
    checkInIntervalDays: 30,
    gracePeriodHours: 48,
    recipients: [
      {
        id: 'rec-5',
        name: 'Compliance Department',
        email: 'archive-compliance@firm.org',
        phone: '+1 (555) 012-0000',
        relation: 'Department Archive'
      }
    ],
    payloadFiles: [],
    createdAt: '2024-06-01T08:00:00Z'
  }
];

export const MOCK_AUDIT_LOGS: AuditLogEntry[] = [
  {
    id: 'log-101',
    switchId: 'switch-01',
    eventType: 'CHECK_IN',
    createdAt: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
    ipAddress: '192.168.1.104',
    details: { message: 'User authenticated via WebAuthn hardware token and performed manual check-in.', switch_title: 'Primary Crypto Asset Vault Access' }
  },
  {
    id: 'log-102',
    switchId: 'switch-02',
    eventType: 'CHECK_IN',
    createdAt: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString(),
    ipAddress: '192.168.1.104',
    details: { message: 'Manual check-in confirmation received. Reset countdown timer to 14 days.', switch_title: 'Cloud Infrastructure Root Credentials' }
  },
  {
    id: 'log-103',
    switchId: 'switch-03',
    eventType: 'SWITCH_TRIGGERED',
    createdAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
    ipAddress: 'System Core (Cron Automation)',
    details: { message: 'Grace period (24 hours) expired without check-in response.', switch_title: 'Whistleblower Research Data & Whistle Archives', files_released: 1 }
  },
  {
    id: 'log-104',
    switchId: 'switch-03',
    eventType: 'GRACE_PERIOD_STARTED',
    createdAt: new Date(Date.now() - 11 * 24 * 60 * 60 * 1000).toISOString(),
    ipAddress: 'System Core',
    details: { message: 'Check-in interval elapsed. Initiated 24-hour emergency countdown.', switch_title: 'Whistleblower Research Data & Whistle Archives', grace_period_hours: 24 }
  },
  {
    id: 'log-105',
    switchId: 'switch-01',
    eventType: 'CONFIG_UPDATED',
    createdAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
    ipAddress: '192.168.1.104',
    details: { message: 'Added recipient Sarah Vance.', switch_title: 'Primary Crypto Asset Vault Access', recipient_email: 'sarah.vance@emergency-contact.org' }
  },
  {
    id: 'log-106',
    switchId: 'switch-01',
    eventType: 'SWITCH_CREATED',
    createdAt: '2026-01-10T14:30:00Z',
    ipAddress: '192.168.1.104',
    details: { message: 'Created Dead Man Switch with 7-day check-in interval and AES-256 encrypted payload.', switch_title: 'Primary Crypto Asset Vault Access' }
  }
];
