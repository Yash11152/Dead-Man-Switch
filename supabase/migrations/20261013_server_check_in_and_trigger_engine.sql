-- Migration: 20261013_server_check_in_and_trigger_engine.sql
-- Description: Implement server-side check-in RPC, switch expiry/grace-period detection, and pg_cron scheduling

-- 1. Ensure PENDING_GRACE exists in switch_status enum
ALTER TYPE public.switch_status ADD VALUE IF NOT EXISTS 'PENDING_GRACE' BEFORE 'TRIGGERED';

-- 2. Secure Server-Side Check-In RPC Function
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
  -- 1. Verify user authentication
  v_user_id := auth.uid();
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'Not authenticated' USING ERRCODE = '42501';
  END IF;

  -- 2. Lock switch row for update and check ownership
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

  -- 3. Only allow check-ins for active or pending_grace switches
  IF v_switch.status NOT IN ('ACTIVE', 'PENDING_GRACE') THEN
    RAISE EXCEPTION 'Cannot check in: switch is not active (current status: %)', v_switch.status USING ERRCODE = '22000';
  END IF;

  -- 4. Authoritative server timestamps
  v_now := clock_timestamp();
  v_next := v_now + (v_switch.interval_days * INTERVAL '1 day');

  -- 5. Insert check-in record atomically
  INSERT INTO public.check_ins (switch_id, user_id, checked_in_at, created_at)
  VALUES (p_switch_id, v_user_id, v_now, v_now);

  -- 6. Update switch timestamps and set status to ACTIVE
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

REVOKE EXECUTE ON FUNCTION public.perform_check_in(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.perform_check_in(uuid) TO authenticated;

-- 3. Automatic Expiry and Trigger Engine Function
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
BEGIN
  -- 1. Transition eligible ACTIVE switches whose next_check_in deadline has passed
  FOR v_switch IN
    SELECT id, next_check_in, grace_period_hours
    FROM public.switches
    WHERE status = 'ACTIVE'
      AND next_check_in <= v_now
    FOR UPDATE SKIP LOCKED
  LOOP
    IF v_switch.grace_period_hours > 0 AND v_now < (v_switch.next_check_in + (v_switch.grace_period_hours * INTERVAL '1 hour')) THEN
      UPDATE public.switches
      SET status = 'PENDING_GRACE',
          updated_at = v_now
      WHERE id = v_switch.id;
      v_grace_count := v_grace_count + 1;
    ELSE
      UPDATE public.switches
      SET status = 'TRIGGERED',
          triggered_at = v_now,
          updated_at = v_now
      WHERE id = v_switch.id;
      v_triggered_count := v_triggered_count + 1;
    END IF;
  END LOOP;

  -- 2. Transition eligible PENDING_GRACE switches whose grace period has expired
  FOR v_switch IN
    SELECT id, next_check_in, grace_period_hours
    FROM public.switches
    WHERE status = 'PENDING_GRACE'
      AND v_now >= (next_check_in + (grace_period_hours * INTERVAL '1 hour'))
    FOR UPDATE SKIP LOCKED
  LOOP
    UPDATE public.switches
    SET status = 'TRIGGERED',
        triggered_at = v_now,
        updated_at = v_now
    WHERE id = v_switch.id;
    v_triggered_count := v_triggered_count + 1;
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

-- 4. Enable pg_cron and configure scheduled job (every minute)
CREATE EXTENSION IF NOT EXISTS pg_cron;

DO $$
BEGIN
  -- Unschedule existing job if it already exists to be idempotent
  IF EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'process-dead-man-switches') THEN
    PERFORM cron.unschedule('process-dead-man-switches');
  END IF;

  -- Schedule job every minute
  PERFORM cron.schedule(
    'process-dead-man-switches',
    '* * * * *',
    'SELECT public.process_switch_expirations();'
  );
END $$;
