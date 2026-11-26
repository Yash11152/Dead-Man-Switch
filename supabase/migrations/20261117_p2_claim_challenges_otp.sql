-- ============================================================================
-- MIGRATION: 20261117_p2_claim_challenges_otp.sql
-- DESCRIPTION: P2 Recipient Claim Security (Two-Tier OTP Challenge & Fail-Closed Redemption)
--   1. Provision claim_challenges table
--   2. Permanent active unique index on recipient_claim_tokens
--   3. Fail-closed atomic OTP redemption RPC: redeem_claim_otp_atomic
--   4. Challenge dispatch acknowledgment RPC: acknowledge_otp_dispatch
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Claim Challenges Table
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.claim_challenges (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    grant_id uuid NOT NULL REFERENCES public.recipient_claim_tokens(id) ON DELETE CASCADE,
    recipient_email text NOT NULL,
    hmac_digest text NOT NULL,
    status text NOT NULL CHECK (status IN ('PENDING_DISPATCH', 'DISPATCHED', 'VERIFIED', 'LOCKED', 'EXPIRED')),
    attempts integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 3,
    dispatch_deadline timestamptz NOT NULL,
    dispatched_at timestamptz,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_claim_challenges_grant ON public.claim_challenges(grant_id);
CREATE INDEX IF NOT EXISTS idx_claim_challenges_status ON public.claim_challenges(status);

ALTER TABLE public.claim_challenges ENABLE ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------------
-- 2. Permanent Active Unique Index on Recipient Claim Tokens
-- ----------------------------------------------------------------------------
DROP INDEX IF EXISTS public.idx_single_active_grant_per_recipient;
CREATE UNIQUE INDEX IF NOT EXISTS idx_single_active_grant_per_recipient
ON public.recipient_claim_tokens (switch_id, recipient_id)
WHERE revoked_at IS NULL AND redeemed_at IS NULL;

-- ----------------------------------------------------------------------------
-- 3. Fail-Closed Atomic OTP Redemption Function
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.redeem_claim_otp_atomic(
    p_grant_id uuid,
    p_submitted_hmac text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_grant public.recipient_claim_tokens%ROWTYPE;
    v_switch public.switches%ROWTYPE;
    v_recipient public.switch_recipients%ROWTYPE;
    v_challenge public.claim_challenges%ROWTYPE;
    v_files jsonb;
    v_now timestamptz := clock_timestamp();
    v_is_hmac_valid boolean;
    HMAC_HEX_REGEX text := '^[0-9a-f]{64}$';
BEGIN
    -- 1. Parameter format validation
    IF p_grant_id IS NULL THEN
        RETURN jsonb_build_object('success', false, 'code', 'INVALID_PARAM', 'message', 'Grant ID is required.');
    END IF;
    IF p_submitted_hmac IS NULL OR length(p_submitted_hmac) <> 64 OR NOT (p_submitted_hmac ~* HMAC_HEX_REGEX) THEN
        RETURN jsonb_build_object('success', false, 'code', 'INVALID_HMAC_FORMAT', 'message', 'Malformed verification digest.');
    END IF;

    -- 2. Level 1: Lock Parent Switch
    SELECT * INTO v_grant FROM public.recipient_claim_tokens WHERE id = p_grant_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'code', 'GRANT_NOT_FOUND', 'message', 'Emergency grant link not found.');
    END IF;

    SELECT * INTO v_switch FROM public.switches WHERE id = v_grant.switch_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'code', 'SWITCH_NOT_FOUND', 'message', 'Switch not found.');
    END IF;

    IF v_switch.status <> 'TRIGGERED' THEN
        RETURN jsonb_build_object('success', false, 'code', 'SWITCH_NOT_TRIGGERED', 'message', 'Switch has not been triggered. Vault files remain locked.');
    END IF;

    -- 3. Level 3: Lock Recipient
    SELECT * INTO v_recipient FROM public.switch_recipients WHERE id = v_grant.recipient_id;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'code', 'RECIPIENT_NOT_FOUND', 'message', 'Recipient not found.');
    END IF;

    -- 4. Level 4: Validate Grant State
    IF v_grant.revoked_at IS NOT NULL THEN
        RETURN jsonb_build_object('success', false, 'code', 'GRANT_REVOKED', 'message', 'This emergency link has been revoked.');
    END IF;
    IF v_grant.expires_at <= v_now THEN
        RETURN jsonb_build_object('success', false, 'code', 'GRANT_EXPIRED', 'message', 'This emergency link has expired.');
    END IF;
    IF v_grant.redemption_count >= v_grant.max_redemptions THEN
        RETURN jsonb_build_object('success', false, 'code', 'MAX_REDEMPTIONS_EXCEEDED', 'message', 'Maximum redemption attempts exceeded.');
    END IF;
    IF v_grant.locked_until IS NOT NULL AND v_now <= v_grant.locked_until THEN
        RETURN jsonb_build_object(
            'success', false,
            'code', 'GRANT_LOCKED_OUT',
            'message', 'Grant is temporarily locked due to multiple failed verification attempts.',
            'locked_until', v_grant.locked_until
        );
    END IF;

    -- 5. Level 5: Lock Claim Challenge
    SELECT * INTO v_challenge
    FROM public.claim_challenges
    WHERE grant_id = p_grant_id
      AND status = 'DISPATCHED'
      AND expires_at > v_now
    ORDER BY created_at DESC
    LIMIT 1
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'code', 'NO_ACTIVE_CHALLENGE', 'message', 'No active challenge found. Please request a new verification code.');
    END IF;

    -- 6. Stored digest validation
    IF v_challenge.hmac_digest IS NULL OR length(v_challenge.hmac_digest) <> 64 OR NOT (v_challenge.hmac_digest ~* HMAC_HEX_REGEX) THEN
        UPDATE public.claim_challenges SET status = 'LOCKED', updated_at = v_now WHERE id = v_challenge.id;
        INSERT INTO public.audit_logs (switch_id, action, metadata, created_at)
        VALUES (v_switch.id, 'CHALLENGE_DIGEST_CORRUPTED', jsonb_build_object('challenge_id', v_challenge.id), v_now);
        RETURN jsonb_build_object('success', false, 'code', 'INTERNAL_CORRUPTION', 'message', 'Challenge integrity check failed. Access locked.');
    END IF;

    -- 7. Execute Best-Effort Constant-Time Bytea Comparison
    v_is_hmac_valid := public.constant_time_bytes_eq(
        decode(v_challenge.hmac_digest, 'hex'),
        decode(p_submitted_hmac, 'hex')
    );

    -- 8. STRICT FAIL-CLOSED BRANCHING (Must explicitly evaluate to TRUE)
    IF v_is_hmac_valid IS NOT TRUE THEN
        UPDATE public.claim_challenges
        SET attempts = attempts + 1, updated_at = v_now
        WHERE id = v_challenge.id;

        IF (v_challenge.attempts + 1) >= v_challenge.max_attempts THEN
            UPDATE public.claim_challenges SET status = 'LOCKED', updated_at = v_now WHERE id = v_challenge.id;
            UPDATE public.recipient_claim_tokens SET locked_until = v_now + INTERVAL '1 hour', updated_at = v_now WHERE id = p_grant_id;
            RETURN jsonb_build_object('success', false, 'code', 'MAX_ATTEMPTS_EXCEEDED', 'message', 'Maximum attempts reached. Locked for 1 hour.');
        END IF;

        RETURN jsonb_build_object(
            'success', false,
            'code', 'INVALID_OTP',
            'remaining_attempts', v_challenge.max_attempts - (v_challenge.attempts + 1)
        );
    END IF;

    -- 9. VERIFICATION SUCCEEDED: Mark challenge VERIFIED & Grant REDEEMED
    UPDATE public.claim_challenges
    SET status = 'VERIFIED', updated_at = v_now
    WHERE id = v_challenge.id;

    UPDATE public.recipient_claim_tokens
    SET redeemed_at = COALESCE(v_grant.redeemed_at, v_now),
        redemption_count = redemption_count + 1,
        locked_until = NULL,
        updated_at = v_now
    WHERE id = p_grant_id;

    -- 10. Fetch Released File Metadata
    SELECT jsonb_agg(jsonb_build_object(
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
    )) INTO v_files
    FROM public.files f
    WHERE f.switch_id = v_switch.id;

    -- 11. Audit Log
    INSERT INTO public.audit_logs (switch_id, action, metadata, created_at)
    VALUES (
        v_switch.id,
        'CLAIM_REDEEMED',
        jsonb_build_object(
            'actor', v_recipient.recipient_email,
            'recipient_name', v_recipient.recipient_name,
            'files_released', jsonb_array_length(COALESCE(v_files, '[]'::jsonb)),
            'grant_id', p_grant_id,
            'challenge_id', v_challenge.id
        ),
        v_now
    );

    -- 12. Return Payload (Dual-Read: provides encrypted_key_material or legacy key_material)
    RETURN jsonb_build_object(
        'success', true,
        'switch_title', v_switch.title,
        'switch_description', v_switch.description,
        'recipient_name', v_recipient.recipient_name,
        'recipient_email', v_recipient.recipient_email,
        'triggered_at', v_switch.triggered_at,
        'encrypted_key_material', v_grant.encrypted_key_material,
        'key_material', COALESCE(v_grant.encrypted_key_material, v_grant.key_material),
        'files', COALESCE(v_files, '[]'::jsonb)
    );
END;
$$;

-- ----------------------------------------------------------------------------
-- 4. Worker Challenge Acknowledgment RPC
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.acknowledge_otp_dispatch(
    p_challenge_id uuid,
    p_notification_id text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_now timestamptz := clock_timestamp();
    v_challenge public.claim_challenges%ROWTYPE;
BEGIN
    SELECT * INTO v_challenge FROM public.claim_challenges
    WHERE id = p_challenge_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN false;
    END IF;

    -- Reject late dispatches
    IF v_now > v_challenge.dispatch_deadline THEN
        UPDATE public.claim_challenges SET status = 'EXPIRED', updated_at = v_now WHERE id = p_challenge_id;
        RETURN false;
    END IF;

    UPDATE public.claim_challenges
    SET status = 'DISPATCHED',
        dispatched_at = v_now,
        updated_at = v_now
    WHERE id = p_challenge_id;

    RETURN true;
END;
$$;

-- Permissions
REVOKE ALL ON FUNCTION public.redeem_claim_otp_atomic FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.redeem_claim_otp_atomic TO anon, authenticated, service_role;

REVOKE ALL ON FUNCTION public.acknowledge_otp_dispatch FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.acknowledge_otp_dispatch TO service_role;
