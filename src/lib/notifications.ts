// src/lib/notifications.ts
// Server-side notification handler with Resend integration, dry-run support,
// concurrent worker locking, and idempotency tracking for Dead Man's Switch alerts.

import { createClient } from '@supabase/supabase-js';

export interface NotificationRecord {
  id: string;
  switch_id: string;
  recipient_email: string;
  notification_type: 'CHECK_IN_REMINDER' | 'GRACE_PERIOD_WARNING' | 'SWITCH_TRIGGERED';
  subject: string;
  body_preview: string;
  idempotency_key: string;
  status: 'QUEUED' | 'PROCESSING' | 'DELIVERED' | 'DRY_RUN' | 'PENDING_CONFIG' | 'FAILED';
  error_message?: string | null;
  created_at: string;
  sent_at?: string | null;
}

export interface DispatchResult {
  totalProcessed: number;
  delivered: number;
  dryRun: number;
  pendingConfig: number;
  failed: number;
  providerStatus: 'ACTIVE' | 'NOT_ACTIVE';
  message: string;
}

export async function processOutboxNotifications(isDryRun: boolean = false): Promise<DispatchResult> {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
  const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';
  const resendApiKey = process.env.RESEND_API_KEY || '';

  const supabase = createClient(supabaseUrl, supabaseKey);

  // 1. Atomically claim QUEUED notifications from outbox using FOR UPDATE SKIP LOCKED
  const { data: notifications, error } = await supabase.rpc('claim_queued_notifications', {
    p_limit: 50,
  });

  if (error || !notifications || notifications.length === 0) {
    return {
      totalProcessed: 0,
      delivered: 0,
      dryRun: 0,
      pendingConfig: 0,
      failed: 0,
      providerStatus: resendApiKey ? 'ACTIVE' : 'NOT_ACTIVE',
      message: error ? `Database error claiming notifications: ${error.message}` : 'No queued notifications found.',
    };
  }

  let delivered = 0;
  let dryRunCount = 0;
  let pendingConfigCount = 0;
  let failed = 0;

  const hasApiKey = Boolean(resendApiKey && resendApiKey.startsWith('re_'));

  for (const notif of notifications) {
    const shouldDryRun = isDryRun || !hasApiKey;

    if (shouldDryRun) {
      const newStatus = hasApiKey && isDryRun ? 'DRY_RUN' : 'PENDING_CONFIG';
      const reason = !hasApiKey
        ? 'RESEND_API_KEY is not configured in server environment. Notification logged in database outbox without external delivery.'
        : 'Dispatched in requested test DRY_RUN mode. Real email delivery skipped.';

      await supabase.rpc('record_notification_outcome', {
        p_notification_id: notif.id,
        p_status: newStatus,
        p_error_message: reason,
      });

      if (newStatus === 'DRY_RUN') {
        dryRunCount++;
      } else {
        pendingConfigCount++;
      }
    } else {
      // Real dispatch via Resend REST API
      try {
        const siteUrl = process.env.NEXT_PUBLIC_APP_URL || (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : 'http://localhost:3000');
        const formattedBody = notif.body_preview.replace(/\/claim\?grant=/g, `${siteUrl}/claim?grant=`);

        const response = await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${resendApiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            from: 'Dead Man Switch <alerts@resend.dev>',
            to: [notif.recipient_email],
            subject: notif.subject,
            text: formattedBody,
          }),
        });

        if (response.ok) {
          await supabase.rpc('record_notification_outcome', {
            p_notification_id: notif.id,
            p_status: 'DELIVERED',
            p_error_message: null,
          });
          delivered++;
        } else {
          const errData = await response.text();
          await supabase.rpc('record_notification_outcome', {
            p_notification_id: notif.id,
            p_status: 'FAILED',
            p_error_message: `Resend API Error (${response.status}): ${errData}`,
          });
          failed++;
        }
      } catch (err: any) {
        await supabase.rpc('record_notification_outcome', {
          p_notification_id: notif.id,
          p_status: 'FAILED',
          p_error_message: `Network failure: ${err?.message || 'Unknown error'}`,
        });
        failed++;
      }
    }
  }

  return {
    totalProcessed: notifications.length,
    delivered,
    dryRun: dryRunCount,
    pendingConfig: pendingConfigCount,
    failed,
    providerStatus: hasApiKey ? 'ACTIVE' : 'NOT_ACTIVE',
    message: hasApiKey
      ? `Processed ${notifications.length} notification(s). (${delivered} delivered, ${dryRunCount} dry-run)`
      : `Processed ${notifications.length} notification(s) in safe PENDING_CONFIG mode. Configure RESEND_API_KEY in server environment for live delivery.`,
  };
}
