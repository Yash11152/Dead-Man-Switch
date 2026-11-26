-- Migration: 20261022_batch4_recipient_delivery.sql
-- Batch 4: Simplify Recipient Delivery: Automatic Email + Secure Download Link
-- Adds key_material & encrypted_token_owner to recipient_claim_tokens
-- Updates process_switch_expirations to include secure download link in notifications
-- Updates redeem_recipient_claim to support secure grant identifiers with email identity verification

-- 1. Schema update: recipient_claim_tokens
ALTER TABLE public.recipient_claim_tokens
ADD COLUMN IF NOT EXISTS key_material text,
ADD COLUMN IF NOT EXISTS encrypted_token_owner text;

ALTER TABLE public.recipient_claim_tokens
ALTER COLUMN max_redemptions SET DEFAULT 10;

CREATE INDEX IF NOT EXISTS idx_claim_tokens_switch_rec
ON public.recipient_claim_tokens(switch_id, recipient_id);

-- 2. Update process_switch_expirations with secure download link in notification preview
CREATE OR REPLACE FUNCTION public.process_switch_expirations()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_now timestamptz := clock_timestamp();
  v_grace_count integer := 0;
  v_triggered_count integer := 0;
  v_switch record;
  v_rec record;
  v_owner_email text;
  v_token_id uuid;
BEGIN
  PERFORM set_config('deadman.internal_transaction', 'true', true);

  -- 1. ACTIVE → PENDING_GRACE or TRIGGERED
  FOR v_switch IN
    SELECT s.id, s.title, s.user_id, s.next_check_in, s.grace_period_hours
    FROM public.switches s
    WHERE s.status = 'ACTIVE' AND s.next_check_in <= v_now
    FOR UPDATE SKIP LOCKED
  LOOP
    IF v_switch.grace_period_hours > 0
       AND v_now < (v_switch.next_check_in + (v_switch.grace_period_hours * INTERVAL '1 hour')) THEN

      UPDATE public.switches SET status = 'PENDING_GRACE', updated_at = v_now WHERE id = v_switch.id;
      v_grace_count := v_grace_count + 1;

      SELECT email INTO v_owner_email FROM auth.users WHERE id = v_switch.user_id;
      IF v_owner_email IS NOT NULL THEN
        INSERT INTO public.notifications (switch_id, recipient_email, notification_type, subject, body_preview, idempotency_key)
        VALUES (v_switch.id, v_owner_email, 'GRACE_PERIOD_WARNING',
          'URGENT: Dead Man Switch in Grace Period - Check In Required (' || v_switch.title || ')',
          'Your dead man switch "' || v_switch.title || '" missed its check-in deadline. You have ' || v_switch.grace_period_hours || ' hours remaining to check in before payload release.',
          v_switch.id || ':GRACE_PERIOD_WARNING')
        ON CONFLICT (idempotency_key) DO NOTHING;
      END IF;

      INSERT INTO public.audit_logs (user_id, switch_id, action, metadata, created_at)
      SELECT v_switch.user_id, v_switch.id, 'GRACE_PERIOD_STARTED',
        jsonb_build_object('actor', 'system_cron', 'switch_title', v_switch.title, 'grace_period_hours', v_switch.grace_period_hours),
        v_now
      WHERE NOT EXISTS (
        SELECT 1 FROM public.audit_logs
        WHERE switch_id = v_switch.id AND action = 'GRACE_PERIOD_STARTED'
          AND created_at > (v_switch.next_check_in - INTERVAL '5 minutes')
      );

    ELSE
      UPDATE public.switches SET status = 'TRIGGERED', triggered_at = v_now, updated_at = v_now WHERE id = v_switch.id;
      v_triggered_count := v_triggered_count + 1;

      FOR v_rec IN SELECT id, recipient_email FROM public.switch_recipients WHERE switch_id = v_switch.id LOOP
        SELECT id INTO v_token_id
        FROM public.recipient_claim_tokens
        WHERE switch_id = v_switch.id AND recipient_id = v_rec.id AND revoked_at IS NULL
        ORDER BY created_at DESC LIMIT 1;

        IF v_token_id IS NULL THEN
          INSERT INTO public.recipient_claim_tokens (switch_id, recipient_id, token_hash, expires_at)
          VALUES (v_switch.id, v_rec.id, encode(sha256(gen_random_bytes(32)), 'hex'), v_now + INTERVAL '30 days')
          RETURNING id INTO v_token_id;
        END IF;

        INSERT INTO public.notifications (switch_id, recipient_email, notification_type, subject, body_preview, idempotency_key)
        VALUES (v_switch.id, v_rec.recipient_email, 'SWITCH_TRIGGERED',
          'Emergency Access Released: Dead Man Switch Triggered (' || v_switch.title || ')',
          'Emergency notification: Dead Man Switch "' || v_switch.title || '" has reached triggered status.' || E'\n\n' ||
          'Confidential payload files have been released to your emergency custody.' || E'\n\n' ||
          'Secure Download Link: /claim?grant=' || COALESCE(v_token_id::text, '') || E'\n\n' ||
          'Security Note: When opening this link, you will be required to confirm your authorized email address (' || v_rec.recipient_email || ') before files are decrypted.',
          v_switch.id || ':' || v_rec.id || ':SWITCH_TRIGGERED')
        ON CONFLICT (idempotency_key) DO NOTHING;
      END LOOP;

      INSERT INTO public.audit_logs (user_id, switch_id, action, metadata, created_at)
      SELECT v_switch.user_id, v_switch.id, 'SWITCH_TRIGGERED',
        jsonb_build_object('actor', 'system_cron', 'switch_title', v_switch.title, 'triggered_at', v_now),
        v_now
      WHERE NOT EXISTS (
        SELECT 1 FROM public.audit_logs
        WHERE switch_id = v_switch.id AND action = 'SWITCH_TRIGGERED'
      );
    END IF;
  END LOOP;

  -- 2. PENDING_GRACE → TRIGGERED
  FOR v_switch IN
    SELECT s.id, s.title, s.user_id, s.next_check_in, s.grace_period_hours
    FROM public.switches s
    WHERE s.status = 'PENDING_GRACE'
      AND v_now >= (s.next_check_in + (s.grace_period_hours * INTERVAL '1 hour'))
    FOR UPDATE SKIP LOCKED
  LOOP
    UPDATE public.switches SET status = 'TRIGGERED', triggered_at = v_now, updated_at = v_now WHERE id = v_switch.id;
    v_triggered_count := v_triggered_count + 1;

    FOR v_rec IN SELECT id, recipient_email FROM public.switch_recipients WHERE switch_id = v_switch.id LOOP
      SELECT id INTO v_token_id
      FROM public.recipient_claim_tokens
      WHERE switch_id = v_switch.id AND recipient_id = v_rec.id AND revoked_at IS NULL
      ORDER BY created_at DESC LIMIT 1;

      IF v_token_id IS NULL THEN
        INSERT INTO public.recipient_claim_tokens (switch_id, recipient_id, token_hash, expires_at)
        VALUES (v_switch.id, v_rec.id, encode(sha256(gen_random_bytes(32)), 'hex'), v_now + INTERVAL '30 days')
        RETURNING id INTO v_token_id;
      END IF;

      INSERT INTO public.notifications (switch_id, recipient_email, notification_type, subject, body_preview, idempotency_key)
      VALUES (v_switch.id, v_rec.recipient_email, 'SWITCH_TRIGGERED',
        'Emergency Access Released: Dead Man Switch Triggered (' || v_switch.title || ')',
        'Emergency notification: Dead Man Switch "' || v_switch.title || '" has reached triggered status.' || E'\n\n' ||
        'Confidential payload files have been released to your emergency custody.' || E'\n\n' ||
        'Secure Download Link: /claim?grant=' || COALESCE(v_token_id::text, '') || E'\n\n' ||
        'Security Note: When opening this link, you will be required to confirm your authorized email address (' || v_rec.recipient_email || ') before files are decrypted.',
        v_switch.id || ':' || v_rec.id || ':SWITCH_TRIGGERED')
      ON CONFLICT (idempotency_key) DO NOTHING;
    END LOOP;

    INSERT INTO public.audit_logs (user_id, switch_id, action, metadata, created_at)
    SELECT v_switch.user_id, v_switch.id, 'SWITCH_TRIGGERED',
      jsonb_build_object('actor', 'system_cron', 'switch_title', v_switch.title, 'triggered_at', v_now),
      v_now
    WHERE NOT EXISTS (
      SELECT 1 FROM public.audit_logs
      WHERE switch_id = v_switch.id AND action = 'SWITCH_TRIGGERED'
    );
  END LOOP;

  -- 3. CHECK_IN_REMINDER for switches due within 24 hours
  FOR v_switch IN
    SELECT s.id, s.title, s.user_id, s.next_check_in
    FROM public.switches s
    WHERE s.status = 'ACTIVE'
      AND s.next_check_in > v_now
      AND s.next_check_in <= (v_now + INTERVAL '24 hours')
  LOOP
    SELECT email INTO v_owner_email FROM auth.users WHERE id = v_switch.user_id;
    IF v_owner_email IS NOT NULL THEN
      INSERT INTO public.notifications (switch_id, recipient_email, notification_type, subject, body_preview, idempotency_key)
      VALUES (v_switch.id, v_owner_email, 'CHECK_IN_REMINDER',
        'Upcoming Check-In Reminder: ' || v_switch.title,
        'Your dead man switch "' || v_switch.title || '" is due for check-in on ' || to_char(v_switch.next_check_in, 'YYYY-MM-DD HH24:MI TZ') || '. Please check in to prevent emergency payload release.',
        v_switch.id || ':' || to_char(v_switch.next_check_in, 'YYYY-MM-DD-HH24') || ':CHECK_IN_REMINDER')
      ON CONFLICT (idempotency_key) DO NOTHING;
    END IF;
  END LOOP;

  RETURN jsonb_build_object(
    'processed_at', v_now,
    'transitioned_to_grace', v_grace_count,
    'transitioned_to_triggered', v_triggered_count
  );
END;
$$;

-- 3. Update redeem_recipient_claim to support secure grant identifiers with email identity verification
CREATE OR REPLACE FUNCTION public.redeem_recipient_claim(
    p_recipient_email text,
    p_grant_id uuid DEFAULT NULL,
    p_token_hash text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_token public.recipient_claim_tokens%ROWTYPE;
    v_switch public.switches%ROWTYPE;
    v_recipient public.switch_recipients%ROWTYPE;
    v_files jsonb;
    v_now timestamptz := clock_timestamp();
BEGIN
    -- 1. Lookup token by grant_id or token_hash
    IF p_grant_id IS NOT NULL THEN
        SELECT * INTO v_token FROM public.recipient_claim_tokens WHERE id = p_grant_id FOR UPDATE;
    ELSIF p_token_hash IS NOT NULL THEN
        SELECT * INTO v_token FROM public.recipient_claim_tokens WHERE token_hash = p_token_hash FOR UPDATE;
    ELSE
        RETURN jsonb_build_object('success', false, 'error', 'Missing access grant or claim token.');
    END IF;

    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'error', 'Invalid or unissued access link.');
    END IF;

    -- 2. Revocation check
    IF v_token.revoked_at IS NOT NULL THEN
        INSERT INTO public.audit_logs (switch_id, action, metadata, created_at)
        VALUES (v_token.switch_id, 'CLAIM_REJECTED',
          jsonb_build_object('actor', p_recipient_email, 'reason', 'token_revoked'), v_now);
        RETURN jsonb_build_object('success', false, 'error', 'This access link has been revoked.');
    END IF;

    -- 3. Expiration check
    IF v_token.expires_at < v_now THEN
        INSERT INTO public.audit_logs (switch_id, action, metadata, created_at)
        VALUES (v_token.switch_id, 'CLAIM_REJECTED',
          jsonb_build_object('actor', p_recipient_email, 'reason', 'token_expired'), v_now);
        RETURN jsonb_build_object('success', false, 'error', 'This access link has expired.');
    END IF;

    -- 4. Redemption limit check
    IF v_token.redeemed_at IS NOT NULL AND v_token.redemption_count >= v_token.max_redemptions THEN
        INSERT INTO public.audit_logs (switch_id, action, metadata, created_at)
        VALUES (v_token.switch_id, 'CLAIM_REJECTED',
          jsonb_build_object('actor', p_recipient_email, 'reason', 'redemption_limit_reached'), v_now);
        RETURN jsonb_build_object('success', false, 'error', 'Maximum access limit reached for this emergency link.');
    END IF;

    -- 5. Switch status check (Must be TRIGGERED)
    SELECT * INTO v_switch FROM public.switches WHERE id = v_token.switch_id;
    IF v_switch.status <> 'TRIGGERED' THEN
        INSERT INTO public.audit_logs (switch_id, action, metadata, created_at)
        VALUES (v_token.switch_id, 'CLAIM_REJECTED',
          jsonb_build_object('actor', p_recipient_email, 'reason', 'switch_not_triggered', 'status', v_switch.status), v_now);
        RETURN jsonb_build_object('success', false, 'error', 'Switch is not in TRIGGERED state (current status: ' || v_switch.status || '). Files remain locked.');
    END IF;

    -- 6. Recipient identity verification check (Email must match authorized recipient)
    SELECT * INTO v_recipient FROM public.switch_recipients WHERE id = v_token.recipient_id;
    IF LOWER(TRIM(v_recipient.recipient_email)) <> LOWER(TRIM(p_recipient_email)) THEN
        INSERT INTO public.audit_logs (switch_id, action, metadata, created_at)
        VALUES (v_token.switch_id, 'CLAIM_REJECTED',
          jsonb_build_object('actor', p_recipient_email, 'reason', 'email_mismatch'), v_now);
        RETURN jsonb_build_object('success', false, 'error', 'Recipient identity verification failed. Provided email does not match authorization.');
    END IF;

    -- 7. Update redemption metadata
    UPDATE public.recipient_claim_tokens
    SET redeemed_at = COALESCE(redeemed_at, v_now), redemption_count = redemption_count + 1
    WHERE id = v_token.id;

    -- 8. Fetch switch files metadata
    SELECT jsonb_agg(jsonb_build_object(
        'id', f.id, 'original_filename', f.original_filename,
        'file_size', f.file_size, 'encrypted', f.encrypted,
        'file_hash', f.file_hash, 'iv', f.iv,
        'storage_path', f.storage_path,
        'encrypted_dek_recipient', f.encrypted_dek_recipient,
        'encryption_version', f.encryption_version,
        'mime_type', f.mime_type
    )) INTO v_files FROM public.files f WHERE f.switch_id = v_switch.id;

    -- 9. Audit log
    INSERT INTO public.audit_logs (switch_id, action, metadata, created_at)
    VALUES (
        v_switch.id, 'CLAIM_REDEEMED',
        jsonb_build_object(
            'actor', p_recipient_email,
            'recipient_name', v_recipient.recipient_name,
            'files_released', jsonb_array_length(COALESCE(v_files, '[]'::jsonb)),
            'grant_id', v_token.id
        ),
        v_now
    );

    RETURN jsonb_build_object(
        'success', true,
        'switch_title', v_switch.title,
        'switch_description', v_switch.description,
        'recipient_name', v_recipient.recipient_name,
        'recipient_email', v_recipient.recipient_email,
        'triggered_at', v_switch.triggered_at,
        'key_material', v_token.key_material,
        'files', COALESCE(v_files, '[]'::jsonb)
    );
END;
$$;

-- 4. Backward-compatible wrapper for redeem_recipient_claim(text, text)
CREATE OR REPLACE FUNCTION public.redeem_recipient_claim(
    p_token_hash text,
    p_recipient_email text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN public.redeem_recipient_claim(
        p_recipient_email := p_recipient_email,
        p_grant_id := NULL,
        p_token_hash := p_token_hash
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION public.redeem_recipient_claim(text, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.redeem_recipient_claim(text, uuid, text) TO anon, authenticated, service_role;

REVOKE EXECUTE ON FUNCTION public.redeem_recipient_claim(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.redeem_recipient_claim(text, text) TO anon, authenticated, service_role;


-- 5. Updated rotate_claim_token supporting key_material & encrypted_token_owner
DROP FUNCTION IF EXISTS public.rotate_claim_token(uuid, uuid, text, timestamptz);

CREATE OR REPLACE FUNCTION public.rotate_claim_token(
    p_switch_id uuid,
    p_recipient_id uuid,
    p_new_token_hash text,
    p_expires_at timestamptz,
    p_key_material text DEFAULT NULL,
    p_encrypted_token_owner text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_user_id uuid := auth.uid();
    v_switch public.switches%ROWTYPE;
    v_recipient public.switch_recipients%ROWTYPE;
    v_new_token_id uuid;
    v_user_email text;
    v_now timestamptz := clock_timestamp();
BEGIN
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Not authenticated' USING ERRCODE = '42501';
    END IF;

    SELECT * INTO v_switch FROM public.switches WHERE id = p_switch_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Switch not found' USING ERRCODE = 'P0002'; END IF;
    IF v_switch.user_id <> v_user_id THEN
        RAISE EXCEPTION 'Unauthorized' USING ERRCODE = '42501';
    END IF;
    IF v_switch.status = 'TRIGGERED' THEN
        RAISE EXCEPTION 'Cannot rotate token on a triggered switch' USING ERRCODE = '22000';
    END IF;
    IF v_switch.status = 'CANCELLED' THEN
        RAISE EXCEPTION 'Cannot rotate token on a cancelled switch' USING ERRCODE = '22000';
    END IF;

    SELECT * INTO v_recipient FROM public.switch_recipients
    WHERE id = p_recipient_id AND switch_id = p_switch_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Recipient not found' USING ERRCODE = 'P0002'; END IF;

    UPDATE public.recipient_claim_tokens
    SET revoked_at = v_now
    WHERE switch_id = p_switch_id
      AND recipient_id = p_recipient_id
      AND revoked_at IS NULL
      AND redeemed_at IS NULL;

    INSERT INTO public.recipient_claim_tokens (switch_id, recipient_id, token_hash, expires_at, key_material, encrypted_token_owner)
    VALUES (p_switch_id, p_recipient_id, p_new_token_hash, p_expires_at, p_key_material, p_encrypted_token_owner)
    RETURNING id INTO v_new_token_id;

    SELECT email INTO v_user_email FROM auth.users WHERE id = v_user_id;

    INSERT INTO public.audit_logs (user_id, switch_id, action, metadata, created_at)
    VALUES (
        v_user_id, p_switch_id, 'CLAIM_TOKEN_ROTATED',
        jsonb_build_object('actor', v_user_email, 'recipient_email', v_recipient.recipient_email),
        v_now
    );

    RETURN jsonb_build_object('success', true, 'token_id', v_new_token_id);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.rotate_claim_token(uuid, uuid, text, timestamptz, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rotate_claim_token(uuid, uuid, text, timestamptz, text, text) TO authenticated;
