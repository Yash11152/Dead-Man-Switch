// src/app/api/claim/route.ts
// Server-side endpoint to validate recipient access grant or claim token, verify identity, and issue short-lived signed URLs

import { NextResponse, type NextRequest } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import { decryptKeyMaterial } from '@/lib/serverCrypto';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { grant, token, email } = body;

    if (!grant && !token) {
      return NextResponse.json(
        { error: 'An emergency download grant link or claim token is required.' },
        { status: 400 }
      );
    }

    if (!email || typeof email !== 'string') {
      return NextResponse.json(
        { error: 'Recipient email is required for identity verification.' },
        { status: 400 }
      );
    }

    const cleanEmail = email.trim().toLowerCase();
    const cleanGrant = typeof grant === 'string' ? grant.trim() : null;
    const cleanToken = typeof token === 'string' ? token.trim() : null;

    let pGrantId: string | null = null;
    let pTokenHash: string | null = null;

    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

    if (cleanGrant && uuidRegex.test(cleanGrant)) {
      pGrantId = cleanGrant;
    } else if (cleanGrant) {
      // If grant was passed as a hex token or raw string
      pTokenHash = crypto.createHash('sha256').update(cleanGrant).digest('hex');
    }

    if (!pGrantId && cleanToken) {
      pTokenHash = crypto.createHash('sha256').update(cleanToken).digest('hex');
    }

    if (!pGrantId && !pTokenHash) {
      return NextResponse.json(
        { error: 'Invalid access grant identifier or token format.' },
        { status: 400 }
      );
    }

    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
    const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';
    const supabase = createClient(supabaseUrl, supabaseAnonKey);

    // Invoke atomic server-side RPC redeem_recipient_claim
    const { data: claimResult, error: claimError } = await supabase.rpc('redeem_recipient_claim', {
      p_recipient_email: cleanEmail,
      p_grant_id: pGrantId,
      p_token_hash: pTokenHash,
    });

    if (claimError) {
      console.error('Claim redemption error:', claimError);
      return NextResponse.json(
        { error: claimError.message || 'Authorization failed. Access link is invalid, expired, or switch is not triggered.' },
        { status: 403 }
      );
    }

    if (!claimResult || !claimResult.success) {
      return NextResponse.json(
        { error: claimResult?.error || 'Failed to verify emergency claim authorization.' },
        { status: 403 }
      );
    }

    // For each released file, create a short-lived (60 seconds) private signed URL
    const filesWithSignedUrls = await Promise.all(
      (claimResult.files || []).map(async (file: any) => {
        let signedUrl: string | null = null;

        if (file.storage_path) {
          const { data: urlData, error: signErr } = await supabase.storage
            .from('dead-man-files')
            .createSignedUrl(file.storage_path, 60, {
              download: file.original_filename || 'confidential_payload',
            });

          if (!signErr && urlData?.signedUrl) {
            signedUrl = urlData.signedUrl;
          }
        }

        return {
          id: file.id,
          name: file.original_filename || 'Unnamed File',
          size: file.file_size,
          encrypted: Boolean(file.encrypted),
          fileHash: file.file_hash,
          iv: file.iv,
          encryptedDekRecipient: file.encrypted_dek_recipient,
          encryptionVersion: file.encryption_version || 'AES-256-GCM-v1',
          mimeType: file.mime_type || 'application/octet-stream',
          downloadUrl: signedUrl,
        };
      })
    );

    let deliveredKeyMaterial: string | null = null;
    if (claimResult.key_material) {
      try {
        deliveredKeyMaterial = decryptKeyMaterial(claimResult.key_material);
      } catch (err) {
        console.warn('Fallback to raw key material:', err);
        deliveredKeyMaterial = claimResult.key_material;
      }
    } else if (cleanToken) {
      deliveredKeyMaterial = cleanToken;
    }

    return NextResponse.json({
      success: true,
      switchTitle: claimResult.switch_title,
      switchDescription: claimResult.switch_description,
      recipientName: claimResult.recipient_name,
      recipientEmail: claimResult.recipient_email,
      triggeredAt: claimResult.triggered_at,
      keyMaterial: deliveredKeyMaterial,
      files: filesWithSignedUrls,
    });

  } catch (error: any) {
    console.error('Claim route error:', error);
    return NextResponse.json(
      { error: error?.message || 'Internal server error while processing emergency claim.' },
      { status: 500 }
    );
  }
}
