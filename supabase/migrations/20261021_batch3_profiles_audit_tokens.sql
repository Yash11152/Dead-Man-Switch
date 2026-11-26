-- Migration: 20261021_batch3_profiles_audit_tokens.sql
-- Batch 3: Profiles, Real Audit Logging, Token Rotation, Recipient DEK Update, Notification Outbox Dispatch

-- ============================================================
-- 1. PROFILES TABLE & COLUMNS
-- ============================================================
CREATE TABLE IF NOT EXISTS public.profiles (
    id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    full_name text,
    email_alerts boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS email_alerts boolean NOT NULL DEFAULT true;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'profiles' AND policyname = 'Users can view own profile') THEN
    CREATE POLICY "Users can view own profile" ON public.profiles FOR SELECT USING (id = auth.uid());
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'profiles' AND policyname = 'Users can insert own profile') THEN
    CREATE POLICY "Users can insert own profile" ON public.profiles FOR INSERT WITH CHECK (id = auth.uid());
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'profiles' AND policyname = 'Users can update own profile') THEN
    CREATE POLICY "Users can update own profile" ON public.profiles FOR UPDATE USING (id = auth.uid()) WITH CHECK (id = auth.uid());
  END IF;
END $$;

-- Auto-provision profile row on user signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  INSERT INTO public.profiles (id, full_name, email_alerts, created_at, updated_at)
  VALUES (
    NEW.id,
    COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.email),
    true,
    now(),
    now()
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'on_auth_user_created') THEN
    CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();
  END IF;
END $$;

-- Backfill profile rows for any existing users that lack one
INSERT INTO public.profiles (id, full_name, email_alerts, created_at, updated_at)
SELECT u.id, COALESCE(u.raw_user_meta_data->>'full_name', u.email), true, now(), now()
FROM auth.users u
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- 2. AUDIT LOGS TABLE & POLICIES (Matches live schema: id, user_id, switch_id, action, metadata, created_at)
-- ============================================================
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
    switch_id uuid REFERENCES public.switches(id) ON DELETE SET NULL,
    action text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON public.audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_switch ON public.audit_logs(switch_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON public.audit_logs(created_at DESC);

ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- Drop direct client INSERT policy: clients cannot directly insert audit logs (prevents forging privileged events)
DROP POLICY IF EXISTS "Users can insert own audit logs" ON public.audit_logs;
REVOKE INSERT ON public.audit_logs FROM PUBLIC, anon, authenticated;

-- Switch owners can view audit logs for themselves OR for switches they own (even system/cron or recipient actions)
DROP POLICY IF EXISTS "Users can view own audit logs" ON public.audit_logs;
CREATE POLICY "Users can view own audit logs" ON public.audit_logs
FOR SELECT USING (
  user_id = auth.uid()
  OR EXISTS (
    SELECT 1 FROM public.switches
    WHERE switches.id = audit_logs.switch_id
      AND switches.user_id = auth.uid()
  )
);

-- ============================================================
-- 3. CLIENT-TRUSTED AUDIT EVENT RPC (whitelisted client-safe actions only)
-- ============================================================
CREATE OR REPLACE FUNCTION public.insert_client_audit_event(
    p_event_type text,
    p_switch_id uuid DEFAULT NULL,
    p_details jsonb DEFAULT '{}'::jsonb,
    p_ip_address text DEFAULT NULL
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_user_id uuid := auth.uid();
    v_user_email text;
    v_log_id uuid;
    v_allowed_events text[] := ARRAY[
        'SWITCH_CREATED', 'CONFIG_UPDATED', 'FILE_UPLOADED',
        'FILE_DELETED', 'CLAIM_TOKEN_ISSUED', 'CLAIM_TOKEN_ROTATED',
        'PROFILE_UPDATED', 'NOTIFICATION_QUEUED'
    ];
    v_meta jsonb;
BEGIN
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Not authenticated' USING ERRCODE = '42501';
    END IF;

    IF NOT (p_event_type = ANY(v_allowed_events)) THEN
        RAISE EXCEPTION 'Event type % is not permitted from client context.', p_event_type USING ERRCODE = '42501';
    END IF;

    IF p_switch_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM public.switches
            WHERE id = p_switch_id AND user_id = v_user_id
        ) THEN
            RAISE EXCEPTION 'Unauthorized: switch does not belong to user' USING ERRCODE = '42501';
        END IF;
    END IF;

    SELECT email INTO v_user_email FROM auth.users WHERE id = v_user_id;

    v_meta := COALESCE(p_details, '{}'::jsonb);
    IF v_user_email IS NOT NULL THEN
        v_meta := jsonb_set(v_meta, '{actor}', to_jsonb(v_user_email), true);
    END IF;
    IF p_ip_address IS NOT NULL THEN
        v_meta := jsonb_set(v_meta, '{ip_address}', to_jsonb(p_ip_address), true);
    END IF;

    INSERT INTO public.audit_logs (user_id, switch_id, action, metadata, created_at)
    VALUES (v_user_id, p_switch_id, p_event_type, v_meta, clock_timestamp())
    RETURNING id INTO v_log_id;

    RETURN v_log_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.insert_client_audit_event(text, uuid, jsonb, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.insert_client_audit_event(text, uuid, jsonb, text) TO authenticated;

-- ============================================================
-- 4. UPDATE perform_check_in — AUDIT LOGGING
-- ============================================================
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
  v_user_email text;
BEGIN
  v_user_id := auth.uid();
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'Not authenticated' USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_switch FROM public.switches WHERE id = p_switch_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Switch not found' USING ERRCODE = 'P0002'; END IF;
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
  SET status = 'ACTIVE', last_check_in = v_now, next_check_in = v_next, updated_at = v_now
  WHERE id = p_switch_id
  RETURNING * INTO v_switch;

  SELECT email INTO v_user_email FROM auth.users WHERE id = v_user_id;

  INSERT INTO public.audit_logs (user_id, switch_id, action, metadata, created_at)
  VALUES (
    v_user_id,
    p_switch_id,
    'CHECK_IN',
    jsonb_build_object(
      'actor', v_user_email,
      'switch_title', v_switch.title,
      'new_next_check_in', v_next
    ),
    v_now
  );

  RETURN jsonb_build_object(
    'success', true,
    'id', v_switch.id,
    'status', v_switch.status,
    'last_check_in', v_switch.last_check_in,
    'next_check_in', v_switch.next_check_in
  );
END;
$$;

REVOKE EXECUTE ON FUNCTION public.perform_check_in(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.perform_check_in(uuid) TO authenticated;

-- ============================================================
-- 5. UPDATE cancel_switch — AUDIT LOGGING
-- ============================================================
CREATE OR REPLACE FUNCTION public.cancel_switch(p_switch_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_user_id uuid := auth.uid();
  v_switch public.switches%ROWTYPE;
  v_user_email text;
  v_now timestamptz := clock_timestamp();
BEGIN
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'Not authenticated' USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_switch FROM public.switches WHERE id = p_switch_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Switch not found' USING ERRCODE = 'P0002'; END IF;
  IF v_switch.user_id <> v_user_id THEN
    RAISE EXCEPTION 'Unauthorized: switch does not belong to user' USING ERRCODE = '42501';
  END IF;

  PERFORM set_config('deadman.internal_transaction', 'true', true);

  UPDATE public.switches SET status = 'CANCELLED', updated_at = v_now
  WHERE id = p_switch_id RETURNING * INTO v_switch;

  UPDATE public.recipient_claim_tokens
  SET revoked_at = v_now
  WHERE switch_id = p_switch_id AND redeemed_at IS NULL AND revoked_at IS NULL;

  SELECT email INTO v_user_email FROM auth.users WHERE id = v_user_id;

  INSERT INTO public.audit_logs (user_id, switch_id, action, metadata, created_at)
  VALUES (
    v_user_id,
    p_switch_id,
    'SWITCH_CANCELLED',
    jsonb_build_object('actor', v_user_email, 'switch_title', v_switch.title),
    v_now
  );

  RETURN jsonb_build_object('success', true, 'id', v_switch.id, 'status', v_switch.status);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.cancel_switch(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.cancel_switch(uuid) TO authenticated;

-- ============================================================
-- 6. UPDATE process_switch_expirations — IDEMPOTENT AUDIT LOGGING
-- ============================================================
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
          'URGENT: Dead Man Switch in Grace Period - Check In Required',
          'Your switch "' || v_switch.title || '" missed its deadline. ' || v_switch.grace_period_hours || ' hours remaining.',
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
        INSERT INTO public.notifications (switch_id, recipient_email, notification_type, subject, body_preview, idempotency_key)
        VALUES (v_switch.id, v_rec.recipient_email, 'SWITCH_TRIGGERED',
          'Emergency Access Released: Dead Man Switch Triggered',
          'Switch "' || v_switch.title || '" has triggered. Payload files are available for claim.',
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
      INSERT INTO public.notifications (switch_id, recipient_email, notification_type, subject, body_preview, idempotency_key)
      VALUES (v_switch.id, v_rec.recipient_email, 'SWITCH_TRIGGERED',
        'Emergency Access Released: Dead Man Switch Triggered',
        'Switch "' || v_switch.title || '" has triggered.',
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
        'Your switch "' || v_switch.title || '" is due for check-in soon.',
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

REVOKE EXECUTE ON FUNCTION public.process_switch_expirations() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.process_switch_expirations() TO postgres, service_role, authenticated;

-- ============================================================
-- 7. UPDATE redeem_recipient_claim — AUDIT LOGGING & SAFE REJECTIONS
-- ============================================================
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
    SELECT * INTO v_token FROM public.recipient_claim_tokens WHERE token_hash = p_token_hash FOR UPDATE;

    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'error', 'Invalid claim token.');
    END IF;

    IF v_token.revoked_at IS NOT NULL THEN
        INSERT INTO public.audit_logs (switch_id, action, metadata, created_at)
        VALUES (v_token.switch_id, 'CLAIM_REJECTED',
          jsonb_build_object('actor', p_recipient_email, 'reason', 'token_revoked'), v_now);
        RETURN jsonb_build_object('success', false, 'error', 'This claim token has been revoked.');
    END IF;

    IF v_token.expires_at < v_now THEN
        INSERT INTO public.audit_logs (switch_id, action, metadata, created_at)
        VALUES (v_token.switch_id, 'CLAIM_REJECTED',
          jsonb_build_object('actor', p_recipient_email, 'reason', 'token_expired'), v_now);
        RETURN jsonb_build_object('success', false, 'error', 'This claim token has expired.');
    END IF;

    IF v_token.redeemed_at IS NOT NULL OR v_token.redemption_count >= v_token.max_redemptions THEN
        INSERT INTO public.audit_logs (switch_id, action, metadata, created_at)
        VALUES (v_token.switch_id, 'CLAIM_REJECTED',
          jsonb_build_object('actor', p_recipient_email, 'reason', 'already_redeemed'), v_now);
        RETURN jsonb_build_object('success', false, 'error', 'This claim token has already been redeemed. Single-use tokens cannot be replayed.');
    END IF;

    SELECT * INTO v_switch FROM public.switches WHERE id = v_token.switch_id;

    IF v_switch.status <> 'TRIGGERED' THEN
        INSERT INTO public.audit_logs (switch_id, action, metadata, created_at)
        VALUES (v_token.switch_id, 'CLAIM_REJECTED',
          jsonb_build_object('actor', p_recipient_email, 'reason', 'switch_not_triggered', 'status', v_switch.status), v_now);
        RETURN jsonb_build_object('success', false, 'error', 'Switch is not in TRIGGERED state (current status: ' || v_switch.status || '). Files remain locked.');
    END IF;

    SELECT * INTO v_recipient FROM public.switch_recipients WHERE id = v_token.recipient_id;

    IF LOWER(TRIM(v_recipient.recipient_email)) <> LOWER(TRIM(p_recipient_email)) THEN
        INSERT INTO public.audit_logs (switch_id, action, metadata, created_at)
        VALUES (v_token.switch_id, 'CLAIM_REJECTED',
          jsonb_build_object('actor', p_recipient_email, 'reason', 'email_mismatch'), v_now);
        RETURN jsonb_build_object('success', false, 'error', 'Recipient identity verification failed. Provided email does not match token authorization.');
    END IF;

    UPDATE public.recipient_claim_tokens
    SET redeemed_at = v_now, redemption_count = v_token.redemption_count + 1
    WHERE id = v_token.id;

    SELECT jsonb_agg(jsonb_build_object(
        'id', f.id, 'original_filename', f.original_filename,
        'file_size', f.file_size, 'encrypted', f.encrypted,
        'file_hash', f.file_hash, 'iv', f.iv,
        'storage_path', f.storage_path,
        'encrypted_dek_recipient', f.encrypted_dek_recipient,
        'encryption_version', f.encryption_version,
        'mime_type', f.mime_type
    )) INTO v_files FROM public.files f WHERE f.switch_id = v_switch.id;

    INSERT INTO public.audit_logs (switch_id, action, metadata, created_at)
    VALUES (
        v_switch.id, 'CLAIM_REDEEMED',
        jsonb_build_object(
            'actor', p_recipient_email,
            'recipient_name', v_recipient.recipient_name,
            'files_released', jsonb_array_length(COALESCE(v_files, '[]'::jsonb))
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
        'files', COALESCE(v_files, '[]'::jsonb)
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION public.redeem_recipient_claim(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.redeem_recipient_claim(text, text) TO anon, authenticated;

-- ============================================================
-- 8. ROTATE CLAIM TOKEN RPC
-- ============================================================
CREATE OR REPLACE FUNCTION public.rotate_claim_token(
    p_switch_id uuid,
    p_recipient_id uuid,
    p_new_token_hash text,
    p_expires_at timestamptz
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

    INSERT INTO public.recipient_claim_tokens (switch_id, recipient_id, token_hash, expires_at)
    VALUES (p_switch_id, p_recipient_id, p_new_token_hash, p_expires_at)
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

REVOKE EXECUTE ON FUNCTION public.rotate_claim_token(uuid, uuid, text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rotate_claim_token(uuid, uuid, text, timestamptz) TO authenticated;

-- ============================================================
-- 9. UPDATE FILE RECIPIENT DEK RPC
-- ============================================================
CREATE OR REPLACE FUNCTION public.update_file_recipient_dek(
    p_switch_id uuid,
    p_file_id uuid,
    p_encrypted_dek_recipient text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_user_id uuid := auth.uid();
BEGIN
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Not authenticated' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.switches WHERE id = p_switch_id AND user_id = v_user_id
    ) THEN
        RAISE EXCEPTION 'Unauthorized' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.files WHERE id = p_file_id AND switch_id = p_switch_id
    ) THEN
        RAISE EXCEPTION 'File not found' USING ERRCODE = 'P0002';
    END IF;

    UPDATE public.files
    SET encrypted_dek_recipient = p_encrypted_dek_recipient
    WHERE id = p_file_id AND switch_id = p_switch_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.update_file_recipient_dek(uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.update_file_recipient_dek(uuid, uuid, text) TO authenticated;

-- ============================================================
-- 10. NOTIFICATION OUTBOX CONCURRENT CLAIM & OUTCOME RECORDING
-- ============================================================
CREATE OR REPLACE FUNCTION public.claim_queued_notifications(p_limit int DEFAULT 50)
RETURNS TABLE (
    id uuid,
    switch_id uuid,
    recipient_email text,
    notification_type text,
    subject text,
    body_preview text,
    idempotency_key text,
    status text,
    created_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN QUERY
    WITH locked_rows AS (
        SELECT n.id
        FROM public.notifications n
        WHERE n.status = 'QUEUED'
           OR (n.status = 'PROCESSING' AND n.created_at < clock_timestamp() - INTERVAL '10 minutes')
        ORDER BY n.created_at ASC
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    )
    UPDATE public.notifications n
    SET status = 'PROCESSING'
    FROM locked_rows lr
    WHERE n.id = lr.id
    RETURNING n.id, n.switch_id, n.recipient_email, n.notification_type, n.subject, n.body_preview, n.idempotency_key, n.status, n.created_at;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.claim_queued_notifications(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.claim_queued_notifications(int) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.record_notification_outcome(
    p_notification_id uuid,
    p_status text,
    p_error_message text DEFAULT NULL
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_notif public.notifications%ROWTYPE;
    v_switch_owner uuid;
    v_now timestamptz := clock_timestamp();
BEGIN
    UPDATE public.notifications
    SET status = p_status,
        error_message = p_error_message,
        sent_at = v_now
    WHERE id = p_notification_id
    RETURNING * INTO v_notif;

    IF NOT FOUND THEN
        RETURN false;
    END IF;

    SELECT user_id INTO v_switch_owner FROM public.switches WHERE id = v_notif.switch_id;

    INSERT INTO public.audit_logs (user_id, switch_id, action, metadata, created_at)
    VALUES (
        v_switch_owner,
        v_notif.switch_id,
        'NOTIFICATION_DISPATCHED',
        jsonb_build_object(
            'actor', 'notification_worker',
            'recipient', v_notif.recipient_email,
            'type', v_notif.notification_type,
            'status', p_status,
            'error', p_error_message
        ),
        v_now
    );

    RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.record_notification_outcome(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.record_notification_outcome(uuid, text, text) TO anon, authenticated, service_role;
