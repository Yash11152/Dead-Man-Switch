-- ============================================================================
-- MIGRATION: 20261117_p1_atomic_rotation_and_locking.sql
-- DESCRIPTION: P1 Atomic Token Rotation, Invariant File Locking & Idempotency
--   1. File mutation lock trigger: locks parent switch row, blocks cross-switch movements
--   2. Token rotation operations table for idempotent transaction fencing
--   3. Constant-time bytea comparison helper
--   4. Atomic token rotation RPC: execute_staged_token_rotation
--   5. Safe idempotency failure recorder: record_operation_failure
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. File Mutation Trigger: Universal Level-1 Parent Switch Row Locking
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.lock_parent_switch_on_file_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_switch_id uuid;
    v_parent_exists boolean;
BEGIN
    -- 1. Strictly forbid reassigning a file to a different switch
    IF TG_OP = 'UPDATE' AND OLD.switch_id IS DISTINCT FROM NEW.switch_id THEN
        RAISE EXCEPTION 'Cross-switch file reassignment is strictly prohibited' USING ERRCODE = '22000';
    END IF;

    v_switch_id := COALESCE(NEW.switch_id, OLD.switch_id);

    -- 2. Acquire exclusive row lock on parent switch (Level 1 in Lock Hierarchy)
    SELECT true INTO v_parent_exists
    FROM public.switches
    WHERE id = v_switch_id
    FOR UPDATE;

    -- 3. Verify parent switch exists
    IF v_parent_exists IS NOT TRUE THEN
        RAISE EXCEPTION 'Parent switch % does not exist', v_switch_id USING ERRCODE = '23503';
    END IF;

    -- 4. Correct Trigger Return Handling
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS trg_lock_switch_on_file_mutation ON public.files;
CREATE TRIGGER trg_lock_switch_on_file_mutation
BEFORE INSERT OR UPDATE OR DELETE ON public.files
FOR EACH ROW
EXECUTE FUNCTION public.lock_parent_switch_on_file_mutation();

-- ----------------------------------------------------------------------------
-- 2. Token Rotation Operations Table (Idempotent Fencing & Operation Lease)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.token_rotation_operations (
    operation_id uuid PRIMARY KEY,
    switch_id uuid NOT NULL REFERENCES public.switches(id) ON DELETE CASCADE,
    recipient_id uuid NOT NULL REFERENCES public.switch_recipients(id) ON DELETE CASCADE,
    request_fingerprint text NOT NULL,
    status text NOT NULL CHECK (status IN ('PROCESSING', 'COMMITTED', 'FAILED')),
    fencing_token integer NOT NULL DEFAULT 1,
    response_payload jsonb,
    error_payload jsonb,
    locked_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_token_rotation_ops_switch_recipient
ON public.token_rotation_operations(switch_id, recipient_id);

ALTER TABLE public.token_rotation_operations ENABLE ROW LEVEL SECURITY;

-- Only switch owner can view operation status
DROP POLICY IF EXISTS "Users can view own rotation operations" ON public.token_rotation_operations;
CREATE POLICY "Users can view own rotation operations" ON public.token_rotation_operations
FOR SELECT USING (EXISTS (
    SELECT 1 FROM public.switches
    WHERE switches.id = token_rotation_operations.switch_id
      AND switches.user_id = (SELECT auth.uid())
));

-- ----------------------------------------------------------------------------
-- 3. Helper: Bytea Constant-Time Comparison Function
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.constant_time_bytes_eq(a bytea, b bytea)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    v_len_a integer;
    v_len_b integer;
    v_diff integer := 0;
    i integer;
BEGIN
    IF a IS NULL OR b IS NULL THEN
        RETURN false;
    END IF;

    v_len_a := octet_length(a);
    v_len_b := octet_length(b);

    IF v_len_a <> v_len_b THEN
        RETURN false;
    END IF;

    FOR i IN 0..(v_len_a - 1) LOOP
        v_diff := v_diff | (get_byte(a, i) # get_byte(b, i));
    END LOOP;

    RETURN v_diff = 0;
END;
$$;

-- ----------------------------------------------------------------------------
-- 4. Atomic Staged Token Rotation RPC (Design B v3.7 Invariant Hierarchy)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.execute_staged_token_rotation(
    p_operation_id uuid,
    p_switch_id uuid,
    p_recipient_id uuid,
    p_request_fingerprint text,
    p_token_hash text,
    p_encrypted_key_material text,
    p_encrypted_token_owner text,
    p_expires_at timestamptz,
    p_file_deks jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_user_id uuid := auth.uid();
    v_op public.token_rotation_operations%ROWTYPE;
    v_switch public.switches%ROWTYPE;
    v_recipient public.switch_recipients%ROWTYPE;
    v_db_file_ids uuid[];
    v_submitted_file_ids uuid[];
    v_elem jsonb;
    v_file_id uuid;
    v_enc_dek text;
    v_rows_updated integer;
    v_new_token_id uuid;
    v_user_email text;
    v_now timestamptz := clock_timestamp();
    v_response jsonb;
    UUID_REGEX text := '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
    HEX64_REGEX text := '^[0-9a-f]{64}$';
BEGIN
    -- 1. Authentication check
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Not authenticated' USING ERRCODE = '42501';
    END IF;

    -- 2. Input validation
    IF p_operation_id IS NULL THEN
        RAISE EXCEPTION 'p_operation_id is required' USING ERRCODE = '22023';
    END IF;
    IF p_request_fingerprint IS NULL OR NOT (p_request_fingerprint ~* HEX64_REGEX) THEN
        RAISE EXCEPTION 'Invalid request fingerprint format' USING ERRCODE = '22023';
    END IF;
    IF p_token_hash IS NULL OR NOT (p_token_hash ~* HEX64_REGEX) THEN
        RAISE EXCEPTION 'Invalid token hash format' USING ERRCODE = '22023';
    END IF;
    IF p_encrypted_key_material IS NULL OR length(trim(p_encrypted_key_material)) = 0 THEN
        RAISE EXCEPTION 'p_encrypted_key_material is required' USING ERRCODE = '22023';
    END IF;
    IF p_expires_at IS NULL OR p_expires_at <= v_now THEN
        RAISE EXCEPTION 'p_expires_at must be in the future' USING ERRCODE = '22023';
    END IF;
    IF p_file_deks IS NULL OR jsonb_typeof(p_file_deks) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'p_file_deks must be a JSON array' USING ERRCODE = '22023';
    END IF;

    -- 3. Lock Level 1: Parent Switch (Root Lock)
    SELECT * INTO v_switch FROM public.switches WHERE id = p_switch_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Switch not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_switch.user_id <> v_user_id THEN
        RAISE EXCEPTION 'Unauthorized: switch does not belong to caller' USING ERRCODE = '42501';
    END IF;
    IF v_switch.status IN ('TRIGGERED', 'CANCELLED') THEN
        RAISE EXCEPTION 'Cannot rotate token on switch with status %', v_switch.status USING ERRCODE = '22000';
    END IF;

    -- 4. Lock Level 2: Files (Ordered by Primary Key)
    PERFORM 1 FROM public.files WHERE switch_id = p_switch_id ORDER BY id ASC FOR UPDATE;

    -- 5. Lock Level 3: Recipient
    SELECT * INTO v_recipient FROM public.switch_recipients
    WHERE id = p_recipient_id AND switch_id = p_switch_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Recipient not found' USING ERRCODE = 'P0002';
    END IF;

    -- 6. Lock Level 4: Active Claim Tokens
    PERFORM 1 FROM public.recipient_claim_tokens
    WHERE switch_id = p_switch_id AND recipient_id = p_recipient_id
    FOR UPDATE;

    -- 7. Lock Level 6: Operation Row (Idempotency check)
    SELECT * INTO v_op
    FROM public.token_rotation_operations
    WHERE operation_id = p_operation_id
    FOR UPDATE;

    IF FOUND THEN
        IF v_op.request_fingerprint <> p_request_fingerprint THEN
            RAISE EXCEPTION 'IDEMPOTENCY_PAYLOAD_MISMATCH' USING ERRCODE = '23505';
        END IF;

        IF v_op.status = 'COMMITTED' THEN
            RETURN v_op.response_payload;
        END IF;

        IF v_op.status = 'FAILED' THEN
            RAISE EXCEPTION 'IDEMPOTENCY_OPERATION_FAILED: %', (v_op.error_payload->>'message')
                USING ERRCODE = '22000';
        END IF;

        IF v_op.status = 'PROCESSING' AND v_now <= v_op.locked_until THEN
            RAISE EXCEPTION 'OPERATION_CONCURRENTLY_PROCESSING' USING ERRCODE = '40001';
        END IF;

        -- Lease renewal
        UPDATE public.token_rotation_operations
        SET fencing_token = fencing_token + 1,
            locked_until = v_now + INTERVAL '30 seconds',
            updated_at = v_now
        WHERE operation_id = p_operation_id;
    ELSE
        INSERT INTO public.token_rotation_operations (
            operation_id, switch_id, recipient_id, request_fingerprint,
            status, fencing_token, locked_until, created_at, updated_at
        ) VALUES (
            p_operation_id, p_switch_id, p_recipient_id, p_request_fingerprint,
            'PROCESSING', 1, v_now + INTERVAL '30 seconds', v_now, v_now
        );
    END IF;

    -- 8. Verify File Set Equality
    SELECT COALESCE(array_agg(id ORDER BY id), ARRAY[]::uuid[]) INTO v_db_file_ids
    FROM public.files WHERE switch_id = p_switch_id;

    -- Collect and validate submitted IDs
    FOR v_elem IN SELECT * FROM jsonb_array_elements(p_file_deks) LOOP
        IF jsonb_typeof(v_elem) IS DISTINCT FROM 'object' THEN
            RAISE EXCEPTION 'Each file DEK entry must be a JSON object' USING ERRCODE = '22023';
        END IF;
        IF NOT (v_elem->>'fileId' ~* UUID_REGEX) THEN
            RAISE EXCEPTION 'Invalid UUID in fileId: %', (v_elem->>'fileId') USING ERRCODE = '22023';
        END IF;
        v_enc_dek := v_elem->>'encryptedDekRecipient';
        IF v_enc_dek IS NULL OR length(trim(v_enc_dek)) = 0 THEN
            RAISE EXCEPTION 'Missing encryptedDekRecipient for file %', (v_elem->>'fileId') USING ERRCODE = '22023';
        END IF;
    END LOOP;

    SELECT COALESCE(array_agg(id ORDER BY id), ARRAY[]::uuid[]) INTO v_submitted_file_ids
    FROM (SELECT (elem->>'fileId')::uuid AS id FROM jsonb_array_elements(p_file_deks) AS elem) s;

    IF jsonb_array_length(p_file_deks) <> array_length(v_submitted_file_ids, 1) AND jsonb_array_length(p_file_deks) > 0 THEN
        RAISE EXCEPTION 'Duplicate fileId detected in submission' USING ERRCODE = '22000';
    END IF;

    IF v_db_file_ids IS DISTINCT FROM v_submitted_file_ids THEN
        RAISE EXCEPTION 'File set mismatch: submitted file DEKs do not exactly match active switch files'
            USING ERRCODE = '22000';
    END IF;

    -- 9. Atomic File DEK updates
    FOR v_elem IN SELECT * FROM jsonb_array_elements(p_file_deks) LOOP
        v_file_id := (v_elem->>'fileId')::uuid;
        v_enc_dek := v_elem->>'encryptedDekRecipient';

        UPDATE public.files
        SET encrypted_dek_recipient = v_enc_dek
        WHERE id = v_file_id AND switch_id = p_switch_id;

        GET DIAGNOSTICS v_rows_updated = ROW_COUNT;
        IF v_rows_updated <> 1 THEN
            RAISE EXCEPTION 'Atomic invariant violated for file %: updated % rows', v_file_id, v_rows_updated
                USING ERRCODE = '22000';
        END IF;
    END LOOP;

    -- 10. Revoke Prior Active Grants
    UPDATE public.recipient_claim_tokens
    SET revoked_at = v_now, updated_at = v_now
    WHERE switch_id = p_switch_id
      AND recipient_id = p_recipient_id
      AND revoked_at IS NULL
      AND redeemed_at IS NULL;

    -- 11. Insert New Delivery Grant
    INSERT INTO public.recipient_claim_tokens (
        switch_id, recipient_id, token_hash, encrypted_key_material,
        encrypted_token_owner, expires_at, created_at, updated_at
    ) VALUES (
        p_switch_id, p_recipient_id, p_token_hash, p_encrypted_key_material,
        p_encrypted_token_owner, p_expires_at, v_now, v_now
    ) RETURNING id INTO v_new_token_id;

    -- 12. Build Response Payload & Transition Operation to COMMITTED
    v_response := jsonb_build_object(
        'success', true,
        'tokenId', v_new_token_id,
        'switchId', p_switch_id,
        'recipientId', p_recipient_id,
        'filesRotated', jsonb_array_length(p_file_deks),
        'committedAt', v_now
    );

    UPDATE public.token_rotation_operations
    SET status = 'COMMITTED',
        response_payload = v_response,
        updated_at = v_now
    WHERE operation_id = p_operation_id;

    -- 13. Audit Log
    SELECT email INTO v_user_email FROM auth.users WHERE id = v_user_id;
    INSERT INTO public.audit_logs (user_id, switch_id, action, metadata, created_at)
    VALUES (
        v_user_id, p_switch_id, 'CLAIM_TOKEN_ROTATED',
        jsonb_build_object(
            'actor', v_user_email,
            'recipient_email', v_recipient.recipient_email,
            'token_id', v_new_token_id,
            'files_rotated', jsonb_array_length(p_file_deks)
        ),
        v_now
    );

    RETURN v_response;
END;
$$;

-- ----------------------------------------------------------------------------
-- 5. Safe Idempotency Failure Recording Function (Never overwrites COMMITTED)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.record_operation_failure(
    p_operation_id uuid,
    p_switch_id uuid,
    p_recipient_id uuid,
    p_request_fingerprint text,
    p_error_message text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_op public.token_rotation_operations%ROWTYPE;
    v_now timestamptz := clock_timestamp();
BEGIN
    SELECT * INTO v_op
    FROM public.token_rotation_operations
    WHERE operation_id = p_operation_id
    FOR UPDATE;

    IF FOUND THEN
        IF v_op.request_fingerprint <> p_request_fingerprint THEN
            RAISE EXCEPTION 'IDEMPOTENCY_PAYLOAD_MISMATCH' USING ERRCODE = '23505';
        END IF;

        -- NEVER overwrite a COMMITTED operation!
        IF v_op.status = 'COMMITTED' THEN
            RETURN;
        END IF;

        IF v_op.status = 'FAILED' THEN
            RETURN;
        END IF;

        UPDATE public.token_rotation_operations
        SET status = 'FAILED',
            error_payload = jsonb_build_object('message', p_error_message, 'failed_at', v_now),
            updated_at = v_now
        WHERE operation_id = p_operation_id
          AND status = 'PROCESSING';
    ELSE
        INSERT INTO public.token_rotation_operations (
            operation_id, switch_id, recipient_id, request_fingerprint,
            status, fencing_token, error_payload, locked_until, created_at, updated_at
        ) VALUES (
            p_operation_id, p_switch_id, p_recipient_id, p_request_fingerprint,
            'FAILED', 1, jsonb_build_object('message', p_error_message, 'failed_at', v_now),
            v_now, v_now, v_now
        );
    END IF;
END;
$$;

-- Execution permissions: authenticated only
REVOKE ALL ON FUNCTION public.execute_staged_token_rotation FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.execute_staged_token_rotation TO authenticated, service_role;

REVOKE ALL ON FUNCTION public.record_operation_failure FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.record_operation_failure TO authenticated, service_role;
