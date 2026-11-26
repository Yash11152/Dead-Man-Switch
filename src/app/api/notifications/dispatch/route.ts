// src/app/api/notifications/dispatch/route.ts
// Server-side endpoint to trigger processing of queued outbox notifications with authentication check

import { NextResponse, type NextRequest } from 'next/server';
import { processOutboxNotifications } from '@/lib/notifications';

export async function POST(request: NextRequest) {
  try {
    const cronSecret = process.env.CRON_SECRET || process.env.CRON_DISPATCH_KEY;
    const providedKey = request.headers.get('x-cron-key') ||
      request.headers.get('authorization')?.replace(/^Bearer\s+/i, '');

    // If a server cron key is configured, enforce authentication
    if (cronSecret && providedKey !== cronSecret) {
      return NextResponse.json(
        { error: 'Unauthorized: invalid or missing cron dispatch key.' },
        { status: 401 }
      );
    }

    let isDryRun = false;

    // Check query params or body
    const searchParams = request.nextUrl.searchParams;
    if (searchParams.get('dryRun') === 'true') {
      isDryRun = true;
    } else {
      try {
        const body = await request.json();
        if (body?.dryRun === true) {
          isDryRun = true;
        }
      } catch {
        // empty body is acceptable
      }
    }

    const result = await processOutboxNotifications(isDryRun);
    return NextResponse.json(result);
  } catch (error: any) {
    console.error('Notification dispatch error:', error);
    return NextResponse.json(
      { error: error?.message || 'Failed to dispatch notifications.' },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  const hasResend = Boolean(process.env.RESEND_API_KEY && process.env.RESEND_API_KEY.startsWith('re_'));
  const hasCronKey = Boolean(process.env.CRON_SECRET || process.env.CRON_DISPATCH_KEY);

  return NextResponse.json({
    status: hasResend ? 'ACTIVE' : 'NOT_ACTIVE',
    provider: 'Resend',
    configured: hasResend,
    authRequired: hasCronKey,
    message: hasResend
      ? 'Resend API key is configured and active for live email delivery.'
      : 'Resend API key is not configured in server environment. Notifications will be recorded in database outbox and processed in safe PENDING_CONFIG mode.',
  });
}
