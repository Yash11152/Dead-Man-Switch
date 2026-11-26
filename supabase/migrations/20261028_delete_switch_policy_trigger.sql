-- Migration: 20261028_delete_switch_policy_trigger.sql
-- Focused Task: Secure Deletion of CANCELLED and TRIGGERED Switches
-- 1. Updates RLS DELETE policy on public.switches to permit deletion only for CANCELLED or TRIGGERED switches
-- 2. Adds BEFORE DELETE trigger to guarantee that ACTIVE or PENDING_GRACE switches cannot be deleted via direct calls
-- 3. Adds SWITCH_DELETED to allowed client audit events in insert_client_audit_event

-- 1. RLS DELETE policy on public.switches
ALTER POLICY "Users can delete own switches" ON public.switches
USING (auth.uid() = user_id AND status IN ('CANCELLED', 'TRIGGERED'));

-- 2. Trigger function to enforce status restriction at database engine level
CREATE OR REPLACE FUNCTION public.validate_switch_delete()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF current_setting('deadman.internal_transaction', true) = 'true' THEN
    RETURN OLD;
  END IF;

  IF OLD.status NOT IN ('CANCELLED', 'TRIGGERED') THEN
    RAISE EXCEPTION 'Cannot delete switch with status %. Only CANCELLED and TRIGGERED switches may be deleted.', OLD.status
      USING ERRCODE = '22000';
  END IF;

  RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS trg_validate_switch_delete ON public.switches;
CREATE TRIGGER trg_validate_switch_delete
BEFORE DELETE ON public.switches
FOR EACH ROW
EXECUTE FUNCTION public.validate_switch_delete();

-- 3. Whitelist SWITCH_DELETED in insert_client_audit_event
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
        'PROFILE_UPDATED', 'NOTIFICATION_QUEUED', 'SWITCH_DELETED'
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
