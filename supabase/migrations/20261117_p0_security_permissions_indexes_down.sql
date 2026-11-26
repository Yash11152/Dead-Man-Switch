-- ============================================================================
-- ROLLBACK SCRIPT: 20261117_p0_security_permissions_indexes_down.sql
-- DESCRIPTION: Reverts P0 permissions and index changes if needed.
-- ============================================================================

-- Re-grant execute on functions to PUBLIC/anon (legacy state)
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO anon, authenticated, service_role, postgres;

-- Drop foreign key index if needed
DROP INDEX IF EXISTS public.idx_recipient_claim_tokens_recipient_id;

-- Recreate old 4-argument overload if required by legacy client
CREATE OR REPLACE FUNCTION public.rotate_claim_token(
    p_switch_id uuid,
    p_recipient_id uuid,
    p_new_token_hash text,
    p_expires_at timestamp with time zone
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN public.rotate_claim_token(
        p_switch_id := p_switch_id,
        p_recipient_id := p_recipient_id,
        p_new_token_hash := p_new_token_hash,
        p_expires_at := p_expires_at,
        p_key_material := NULL,
        p_encrypted_token_owner := NULL
    );
END;
$$;
