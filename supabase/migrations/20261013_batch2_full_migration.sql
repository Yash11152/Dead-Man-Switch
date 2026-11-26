-- Migration: 20261013_batch2_full_migration.sql
-- Description: Batch 2 - File encryption metadata, recipient claim tokens, notifications outbox, and timestamp hardening.

-- 1. Add Encryption Metadata columns to public.files
ALTER TABLE public.files 
ADD COLUMN IF NOT EXISTS iv text,
ADD COLUMN IF NOT EXISTS encrypted_dek_owner text,
ADD COLUMN IF NOT EXISTS encrypted_dek_recipient text,
ADD COLUMN IF NOT EXISTS encryption_version text DEFAULT 'AES-256-GCM-v1',
ADD COLUMN IF NOT EXISTS mime_type text;

-- 2. Create Recipient Claim Tokens table
CREATE TABLE IF NOT EXISTS public.recipient_claim_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    switch_id uuid NOT NULL REFERENCES public.switches(id) ON DELETE CASCADE,
    recipient_id uuid NOT NULL REFERENCES public.switch_recipients(id) ON DELETE CASCADE,
    token_hash text NOT NULL,
    expires_at timestamptz NOT NULL,
    redeemed_at timestamptz,
    revoked_at timestamptz,
    redemption_count integer NOT NULL DEFAULT 0,
    max_redemptions integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_recipient_claim_tokens_hash UNIQUE (token_hash)
);

CREATE INDEX IF NOT EXISTS idx_claim_tokens_hash ON public.recipient_claim_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_claim_tokens_switch ON public.recipient_claim_tokens(switch_id);

ALTER TABLE public.recipient_claim_tokens ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'recipient_claim_tokens' AND policyname = 'Users can view own switch claim tokens') THEN
    CREATE POLICY "Users can view own switch claim tokens" ON public.recipient_claim_tokens
    FOR SELECT USING (EXISTS (
        SELECT 1 FROM public.switches WHERE switches.id = recipient_claim_tokens.switch_id AND switches.user_id = auth.uid()
    ));
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'recipient_claim_tokens' AND policyname = 'Users can insert own switch claim tokens') THEN
    CREATE POLICY "Users can insert own switch claim tokens" ON public.recipient_claim_tokens
    FOR INSERT WITH CHECK (EXISTS (
        SELECT 1 FROM public.switches WHERE switches.id = recipient_claim_tokens.switch_id AND switches.user_id = auth.uid()
    ));
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'recipient_claim_tokens' AND policyname = 'Users can update own switch claim tokens') THEN
    CREATE POLICY "Users can update own switch claim tokens" ON public.recipient_claim_tokens
    FOR UPDATE USING (EXISTS (
        SELECT 1 FROM public.switches WHERE switches.id = recipient_claim_tokens.switch_id AND switches.user_id = auth.uid()
    ));
  END IF;
END $$;

-- 3. Create Notifications Outbox table
CREATE TABLE IF NOT EXISTS public.notifications (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    switch_id uuid NOT NULL REFERENCES public.switches(id) ON DELETE CASCADE,
    recipient_email text NOT NULL,
    notification_type text NOT NULL,
    subject text NOT NULL,
    body_preview text NOT NULL,
    idempotency_key text NOT NULL,
    status text NOT NULL DEFAULT 'QUEUED',
    error_message text,
    created_at timestamptz NOT NULL DEFAULT now(),
    sent_at timestamptz,
    CONSTRAINT uq_notifications_idempotency UNIQUE (idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_notifications_switch ON public.notifications(switch_id);
CREATE INDEX IF NOT EXISTS idx_notifications_idempotency ON public.notifications(idempotency_key);

ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'notifications' AND policyname = 'Users can view own switch notifications') THEN
    CREATE POLICY "Users can view own switch notifications" ON public.notifications
    FOR SELECT USING (EXISTS (
        SELECT 1 FROM public.switches WHERE switches.id = notifications.switch_id AND switches.user_id = auth.uid()
    ));
  END IF;
END $$;

-- 4. RPC: Cancel Switch
CREATE OR REPLACE FUNCTION public.cancel_switch(p_switch_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_user_id uuid := auth.uid();
  v_switch public.switches%ROWTYPE;
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'Not authenticated' USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_switch
  FROM public.switches
  WHERE id = p_switch_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Switch not found' USING ERRCODE = 'P0002';
  END IF;

  IF v_switch.user_id <> v_user_id THEN
    RAISE EXCEPTION 'Unauthorized: switch does not belong to user' USING ERRCODE = '42501';
  END IF;

  PERFORM set_config('deadman.internal_transaction', 'true', true);

  UPDATE public.switches
  SET status = 'CANCELLED', updated_at = clock_timestamp()
  WHERE id = p_switch_id
  RETURNING * INTO v_switch;

  -- Revoke any unused claim tokens for this switch
  UPDATE public.recipient_claim_tokens
  SET revoked_at = clock_timestamp()
  WHERE switch_id = p_switch_id AND redeemed_at IS NULL AND revoked_at IS NULL;

  RETURN jsonb_build_object('success', true, 'id', v_switch.id, 'status', v_switch.status);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.cancel_switch(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.cancel_switch(uuid) TO authenticated;

-- 5. RPC: Redeem Recipient Claim
CREATE OR REPLACE FUNCTION public.redeem_recipient_claim(
    p_token_hash text,
    p_recipient_email text
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
    SELECT * INTO v_token
    FROM public.recipient_claim_tokens
    WHERE token_hash = p_token_hash
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invalid claim token.' USING ERRCODE = 'P0002';
    END IF;

    IF v_token.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'This claim token has been revoked.' USING ERRCODE = '22000';
    END IF;

    IF v_token.expires_at < v_now THEN
        RAISE EXCEPTION 'This claim token has expired.' USING ERRCODE = '22000';
    END IF;

    IF v_token.redeemed_at IS NOT NULL OR v_token.redemption_count >= v_token.max_redemptions THEN
        RAISE EXCEPTION 'This claim token has already been redeemed. Single-use tokens cannot be replayed.' USING ERRCODE = '22000';
    END IF;

    SELECT * INTO v_switch
    FROM public.switches
    WHERE id = v_token.switch_id;

    IF v_switch.status <> 'TRIGGERED' THEN
        RAISE EXCEPTION 'Switch is not in TRIGGERED state (current status: %). Files remain locked.', v_switch.status USING ERRCODE = '42501';
    END IF;

    SELECT * INTO v_recipient
    FROM public.switch_recipients
    WHERE id = v_token.recipient_id;

    IF LOWER(TRIM(v_recipient.recipient_email)) <> LOWER(TRIM(p_recipient_email)) THEN
        RAISE EXCEPTION 'Recipient identity verification failed. Provided email does not match token authorization.' USING ERRCODE = '42501';
    END IF;

    UPDATE public.recipient_claim_tokens
    SET 
        redeemed_at = v_now,
        redemption_count = v_token.redemption_count + 1
    WHERE id = v_token.id;

    SELECT jsonb_agg(
        jsonb_build_object(
            'id', f.id,
            'original_filename', f.original_filename,
            'file_size', f.file_size,
            'encrypted', f.encrypted,
            'file_hash', f.file_hash,
            'iv', f.iv,
            'storage_path', f.storage_path,
            'encrypted_dek_recipient', f.encrypted_dek_recipient,
            'encryption_version', f.encryption_version,
            'mime_type', f.mime_type
        )
    ) INTO v_files
    FROM public.files f
    WHERE f.switch_id = v_switch.id;

    RETURN jsonb_build_object(
        'success', true,
        'switch_title', v_switch.title,
        'switch_description', v_switch.description,
        'recipient_name', v_recipient.recipient_name,
        'recipient_email', v_recipient.recipient_email,
        'triggered_at', v_switch.triggered_at,
        'files', COALESCE(v_files, '[]'::jsonb)
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION public.redeem_recipient_claim(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.redeem_recipient_claim(text, text) TO anon, authenticated;

-- 6. Direct Timestamp Hardening Trigger on switches
CREATE OR REPLACE FUNCTION public.validate_switch_update()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF current_setting('deadman.internal_transaction', true) = 'true' THEN
    RETURN NEW;
  END IF;

  IF NEW.last_check_in IS DISTINCT FROM OLD.last_check_in THEN
    RAISE EXCEPTION 'Direct modification of last_check_in is prohibited. Use perform_check_in RPC.' USING ERRCODE = '42501';
  END IF;

  IF NEW.triggered_at IS DISTINCT FROM OLD.triggered_at THEN
    RAISE EXCEPTION 'Direct modification of triggered_at is prohibited.' USING ERRCODE = '42501';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF OLD.status IN ('ACTIVE', 'PENDING_GRACE') AND NEW.status = 'CANCELLED' THEN
      NULL;
    ELSE
      RAISE EXCEPTION 'Direct modification of switch status to % is prohibited.', NEW.status USING ERRCODE = '42501';
    END IF;
  END IF;

  IF NEW.interval_days IS DISTINCT FROM OLD.interval_days THEN
    NEW.next_check_in := OLD.last_check_in + (NEW.interval_days * INTERVAL '1 day');
  ELSIF NEW.next_check_in IS DISTINCT FROM OLD.next_check_in THEN
    RAISE EXCEPTION 'Direct modification of next_check_in is prohibited.' USING ERRCODE = '42501';
  END IF;

  RETURN NEW;
END;
$$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_validate_switch_update') THEN
    CREATE TRIGGER trg_validate_switch_update
    BEFORE UPDATE ON public.switches
    FOR EACH ROW
    EXECUTE FUNCTION public.validate_switch_update();
  END IF;
END $$;

-- 7. Update perform_check_in with internal transaction flag
CREATE OR REPLACE FUNCTION public.perform_check_in(p_switch_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_user_id uuid;
  v_switch public.switches%ROWTYPE;
  v_now timestamptz;
  v_next timestamptz;
BEGIN
  v_user_id := auth.uid();
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'Not authenticated' USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_switch
  FROM public.switches
  WHERE id = p_switch_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Switch not found' USING ERRCODE = 'P0002';
  END IF;

  IF v_switch.user_id <> v_user_id THEN
    RAISE EXCEPTION 'Unauthorized: switch does not belong to user' USING ERRCODE = '42501';
  END IF;

  IF v_switch.status NOT IN ('ACTIVE', 'PENDING_GRACE') THEN
    RAISE EXCEPTION 'Cannot check in: switch is not active (current status: %)', v_switch.status USING ERRCODE = '22000';
  END IF;

  v_now := clock_timestamp();
  v_next := v_now + (v_switch.interval_days * INTERVAL '1 day');

  PERFORM set_config('deadman.internal_transaction', 'true', true);

  INSERT INTO public.check_ins (switch_id, user_id, checked_in_at, created_at)
  VALUES (p_switch_id, v_user_id, v_now, v_now);

  UPDATE public.switches
  SET
    status = 'ACTIVE',
    last_check_in = v_now,
    next_check_in = v_next,
    updated_at = v_now
  WHERE id = p_switch_id
  RETURNING * INTO v_switch;

  RETURN jsonb_build_object(
    'success', true,
    'id', v_switch.id,
    'status', v_switch.status,
    'last_check_in', v_switch.last_check_in,
    'next_check_in', v_switch.next_check_in
  );
END;
$$;

-- 8. Update process_switch_expirations with notification outbox queuing
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
BEGIN
  PERFORM set_config('deadman.internal_transaction', 'true', true);

  -- 1. Active switches whose deadline passed
  FOR v_switch IN
    SELECT s.id, s.title, s.user_id, s.next_check_in, s.grace_period_hours
    FROM public.switches s
    WHERE s.status = 'ACTIVE'
      AND s.next_check_in <= v_now
    FOR UPDATE SKIP LOCKED
  LOOP
    IF v_switch.grace_period_hours > 0 AND v_now < (v_switch.next_check_in + (v_switch.grace_period_hours * INTERVAL '1 hour')) THEN
      UPDATE public.switches
      SET status = 'PENDING_GRACE', updated_at = v_now
      WHERE id = v_switch.id;
      v_grace_count := v_grace_count + 1;

      -- Queue Grace Warning Notification
      SELECT email INTO v_owner_email FROM auth.users WHERE id = v_switch.user_id;
      IF v_owner_email IS NOT NULL THEN
        INSERT INTO public.notifications (
          switch_id, recipient_email, notification_type, subject, body_preview, idempotency_key
        ) VALUES (
          v_switch.id,
          v_owner_email,
          'GRACE_PERIOD_WARNING',
          'URGENT: Dead Man Switch in Grace Period - Check In Required',
          'Your dead man switch "' || v_switch.title || '" missed its check-in deadline. You have ' || v_switch.grace_period_hours || ' hours remaining before emergency access is triggered.',
          v_switch.id || ':GRACE_PERIOD_WARNING'
        ) ON CONFLICT (idempotency_key) DO NOTHING;
      END IF;

    ELSE
      UPDATE public.switches
      SET status = 'TRIGGERED', triggered_at = v_now, updated_at = v_now
      WHERE id = v_switch.id;
      v_triggered_count := v_triggered_count + 1;

      -- Queue Triggered Notifications for Recipients
      FOR v_rec IN SELECT id, recipient_name, recipient_email FROM public.switch_recipients WHERE switch_id = v_switch.id LOOP
        INSERT INTO public.notifications (
          switch_id, recipient_email, notification_type, subject, body_preview, idempotency_key
        ) VALUES (
          v_switch.id,
          v_rec.recipient_email,
          'SWITCH_TRIGGERED',
          'Emergency Access Released: Dead Man Switch Triggered',
          'A dead man switch "' || v_switch.title || '" has triggered. Confidential payload files are available for claim with your designated credentials.',
          v_switch.id || ':' || v_rec.id || ':SWITCH_TRIGGERED'
        ) ON CONFLICT (idempotency_key) DO NOTHING;
      END LOOP;
    END IF;
  END LOOP;

  -- 2. Pending Grace switches whose grace expired
  FOR v_switch IN
    SELECT s.id, s.title, s.next_check_in, s.grace_period_hours
    FROM public.switches s
    WHERE s.status = 'PENDING_GRACE'
      AND v_now >= (s.next_check_in + (s.grace_period_hours * INTERVAL '1 hour'))
    FOR UPDATE SKIP LOCKED
  LOOP
    UPDATE public.switches
    SET status = 'TRIGGERED', triggered_at = v_now, updated_at = v_now
    WHERE id = v_switch.id;
    v_triggered_count := v_triggered_count + 1;

    FOR v_rec IN SELECT id, recipient_name, recipient_email FROM public.switch_recipients WHERE switch_id = v_switch.id LOOP
      INSERT INTO public.notifications (
        switch_id, recipient_email, notification_type, subject, body_preview, idempotency_key
      ) VALUES (
        v_switch.id,
        v_rec.recipient_email,
        'SWITCH_TRIGGERED',
        'Emergency Access Released: Dead Man Switch Triggered',
        'A dead man switch "' || v_switch.title || '" has triggered. Confidential payload files are available for claim with your designated credentials.',
        v_switch.id || ':' || v_rec.id || ':SWITCH_TRIGGERED'
      ) ON CONFLICT (idempotency_key) DO NOTHING;
    END LOOP;
  END LOOP;

  -- 3. Check-In Reminders for upcoming deadlines (within 24 hours)
  FOR v_switch IN
    SELECT s.id, s.title, s.user_id, s.next_check_in
    FROM public.switches s
    WHERE s.status = 'ACTIVE'
      AND s.next_check_in > v_now
      AND s.next_check_in <= (v_now + INTERVAL '24 hours')
  LOOP
    SELECT email INTO v_owner_email FROM auth.users WHERE id = v_switch.user_id;
    IF v_owner_email IS NOT NULL THEN
      INSERT INTO public.notifications (
        switch_id, recipient_email, notification_type, subject, body_preview, idempotency_key
      ) VALUES (
        v_switch.id,
        v_owner_email,
        'CHECK_IN_REMINDER',
        'Upcoming Check-In Reminder for Switch: ' || v_switch.title,
        'Your dead man switch "' || v_switch.title || '" is due for check-in soon. Please check in to keep your switch active.',
        v_switch.id || ':' || to_char(v_switch.next_check_in, 'YYYY-MM-DD-HH24') || ':CHECK_IN_REMINDER'
      ) ON CONFLICT (idempotency_key) DO NOTHING;
    END IF;
  END LOOP;

  RETURN jsonb_build_object(
    'processed_at', v_now,
    'transitioned_to_grace', v_grace_count,
    'transitioned_to_triggered', v_triggered_count
  );
END;
$$;

-- 9. Storage policy allowing claimed files of triggered switches
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'storage' AND tablename = 'objects' AND policyname = 'Recipients can view claimed files of triggered switches'
  ) THEN
    CREATE POLICY "Recipients can view claimed files of triggered switches"
    ON storage.objects FOR SELECT
    USING (
      bucket_id = 'dead-man-files' AND EXISTS (
        SELECT 1 
        FROM public.switches s
        JOIN public.recipient_claim_tokens t ON t.switch_id = s.id
        WHERE s.id::text = (storage.foldername(name))[2]
          AND s.status = 'TRIGGERED'
          AND t.redeemed_at IS NOT NULL
          AND (t.redeemed_at + INTERVAL '24 hours') > clock_timestamp()
      )
    );
  END IF;
END $$;
