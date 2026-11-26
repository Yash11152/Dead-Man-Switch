-- ============================================================================
-- MIGRATION: 20261117_p3_paused_status_rpc.sql
-- DESCRIPTION: P3 PAUSED Switch Lifecycle Management
--   1. RPC public.pause_switch(uuid)
--   2. RPC public.resume_switch(uuid)
-- ============================================================================

CREATE OR REPLACE FUNCTION public.pause_switch(p_switch_id uuid)
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
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Switch not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_switch.user_id <> v_user_id THEN
        RAISE EXCEPTION 'Unauthorized: switch does not belong to user' USING ERRCODE = '42501';
    END IF;
    IF v_switch.status NOT IN ('ACTIVE', 'PENDING_GRACE') THEN
        RAISE EXCEPTION 'Cannot pause switch with status %', v_switch.status USING ERRCODE = '22000';
    END IF;

    UPDATE public.switches
    SET status = 'PAUSED', updated_at = v_now
    WHERE id = p_switch_id
    RETURNING * INTO v_switch;

    SELECT email INTO v_user_email FROM auth.users WHERE id = v_user_id;

    INSERT INTO public.audit_logs (user_id, switch_id, action, metadata, created_at)
    VALUES (
        v_user_id, p_switch_id, 'SWITCH_PAUSED',
        jsonb_build_object('actor', v_user_email, 'switch_title', v_switch.title),
        v_now
    );

    RETURN jsonb_build_object(
        'success', true,
        'id', v_switch.id,
        'status', v_switch.status
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.resume_switch(p_switch_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_user_id uuid := auth.uid();
    v_switch public.switches%ROWTYPE;
    v_new_next_check_in timestamptz;
    v_user_email text;
    v_now timestamptz := clock_timestamp();
BEGIN
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Not authenticated' USING ERRCODE = '42501';
    END IF;

    SELECT * INTO v_switch FROM public.switches WHERE id = p_switch_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Switch not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_switch.user_id <> v_user_id THEN
        RAISE EXCEPTION 'Unauthorized: switch does not belong to user' USING ERRCODE = '42501';
    END IF;
    IF v_switch.status <> 'PAUSED' THEN
        RAISE EXCEPTION 'Cannot resume switch with status %', v_switch.status USING ERRCODE = '22000';
    END IF;

    v_new_next_check_in := v_now + (v_switch.interval_days * INTERVAL '1 day');

    UPDATE public.switches
    SET status = 'ACTIVE',
        last_check_in = v_now,
        next_check_in = v_new_next_check_in,
        updated_at = v_now
    WHERE id = p_switch_id
    RETURNING * INTO v_switch;

    SELECT email INTO v_user_email FROM auth.users WHERE id = v_user_id;

    INSERT INTO public.audit_logs (user_id, switch_id, action, metadata, created_at)
    VALUES (
        v_user_id, p_switch_id, 'SWITCH_RESUMED',
        jsonb_build_object('actor', v_user_email, 'switch_title', v_switch.title, 'new_next_check_in', v_new_next_check_in),
        v_now
    );

    RETURN jsonb_build_object(
        'success', true,
        'id', v_switch.id,
        'status', v_switch.status,
        'next_check_in', v_switch.next_check_in
    );
END;
$$;

REVOKE ALL ON FUNCTION public.pause_switch FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.pause_switch TO authenticated, service_role;

REVOKE ALL ON FUNCTION public.resume_switch FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.resume_switch TO authenticated, service_role;
