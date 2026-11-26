-- ============================================================================
-- MIGRATION: 20261117_p0_security_permissions_indexes.sql
-- DESCRIPTION: P0 Security Remediation:
--   1. Fix mutable search_path on handle_updated_at and handle_new_user
--   2. Restrict EXECUTE privileges on SECURITY DEFINER functions (least privilege)
--   3. Safely resolve rotate_claim_token overload ambiguity
--   4. Add missing foreign key index on recipient_claim_tokens(recipient_id)
--   5. Add encrypted_key_material, locked_until, updated_at to recipient_claim_tokens
--   6. Optimize RLS policies using (SELECT auth.uid()) for subquery initplan caching
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Fix Mutable search_path on System Trigger Functions
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.handle_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, pg_temp
AS $$
BEGIN
  NEW.updated_at = clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  INSERT INTO public.profiles (id, full_name, email_alerts)
  VALUES (
    NEW.id,
    COALESCE(NEW.raw_user_meta_data->>'full_name', ''),
    true
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

-- ----------------------------------------------------------------------------
-- 2. Schema Additions for recipient_claim_tokens (Non-destructive, backward-compatible)
-- ----------------------------------------------------------------------------
ALTER TABLE public.recipient_claim_tokens
ADD COLUMN IF NOT EXISTS encrypted_key_material text,
ADD COLUMN IF NOT EXISTS locked_until timestamptz,
ADD COLUMN IF NOT EXISTS updated_at timestamptz DEFAULT clock_timestamp();

-- Missing Covering Index for Foreign Key (Supabase Advisor Linter finding)
CREATE INDEX IF NOT EXISTS idx_recipient_claim_tokens_recipient_id
ON public.recipient_claim_tokens(recipient_id);

-- ----------------------------------------------------------------------------
-- 3. Resolve rotate_claim_token Overload Ambiguity Safely
-- ----------------------------------------------------------------------------
-- Drop the legacy 4-argument overload from batch3 that conflicts with batch4
DROP FUNCTION IF EXISTS public.rotate_claim_token(uuid, uuid, text, timestamp with time zone);

-- ----------------------------------------------------------------------------
-- 4. Restrict Execution Privileges on SECURITY DEFINER Functions (Least Privilege)
-- ----------------------------------------------------------------------------

-- A. Revoke default PUBLIC execution on all sensitive functions
REVOKE ALL ON FUNCTION public.cancel_switch(uuid) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.claim_queued_notifications(integer) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.handle_new_user() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.handle_updated_at() FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.insert_client_audit_event(text, uuid, jsonb, text) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.perform_check_in(uuid) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.process_switch_expirations() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.record_notification_outcome(uuid, text, text) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.update_file_recipient_dek(uuid, uuid, text) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.validate_switch_delete() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.validate_switch_update() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.rls_auto_enable() FROM PUBLIC, anon, authenticated;

-- Revoke rotate_claim_token from anon
REVOKE ALL ON FUNCTION public.rotate_claim_token(uuid, uuid, text, timestamp with time zone, text, text) FROM PUBLIC, anon;

-- B. Grant to appropriate authorized roles

-- Internal/Cron Workers: service_role only
GRANT EXECUTE ON FUNCTION public.claim_queued_notifications(integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.record_notification_outcome(uuid, text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.process_switch_expirations() TO service_role, postgres;

-- Authenticated Users (Owner actions) + service_role
GRANT EXECUTE ON FUNCTION public.cancel_switch(uuid) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.perform_check_in(uuid) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.insert_client_audit_event(text, uuid, jsonb, text) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.update_file_recipient_dek(uuid, uuid, text) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.rotate_claim_token(uuid, uuid, text, timestamp with time zone, text, text) TO authenticated, service_role;

-- Claim Redemption: anon and authenticated (recipients are unauthenticated public users claiming via emergency token)
GRANT EXECUTE ON FUNCTION public.redeem_recipient_claim(text, uuid, text) TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.redeem_recipient_claim(text, text) TO anon, authenticated, service_role;

-- ----------------------------------------------------------------------------
-- 5. RLS Policies Optimization: Use (SELECT auth.uid()) for InitPlan Performance
-- ----------------------------------------------------------------------------

-- PROFILES
DROP POLICY IF EXISTS "Users can view own profile" ON public.profiles;
CREATE POLICY "Users can view own profile" ON public.profiles
FOR SELECT USING ((SELECT auth.uid()) = id);

DROP POLICY IF EXISTS "Users can insert own profile" ON public.profiles;
CREATE POLICY "Users can insert own profile" ON public.profiles
FOR INSERT WITH CHECK ((SELECT auth.uid()) = id);

DROP POLICY IF EXISTS "Users can update own profile" ON public.profiles;
CREATE POLICY "Users can update own profile" ON public.profiles
FOR UPDATE USING ((SELECT auth.uid()) = id) WITH CHECK ((SELECT auth.uid()) = id);

-- SWITCHES
DROP POLICY IF EXISTS "Users can view own switches" ON public.switches;
CREATE POLICY "Users can view own switches" ON public.switches
FOR SELECT USING ((SELECT auth.uid()) = user_id);

DROP POLICY IF EXISTS "Users can insert own switches" ON public.switches;
CREATE POLICY "Users can insert own switches" ON public.switches
FOR INSERT WITH CHECK ((SELECT auth.uid()) = user_id);

DROP POLICY IF EXISTS "Users can update own switches" ON public.switches;
CREATE POLICY "Users can update own switches" ON public.switches
FOR UPDATE USING ((SELECT auth.uid()) = user_id) WITH CHECK ((SELECT auth.uid()) = user_id);

DROP POLICY IF EXISTS "Users can delete own switches" ON public.switches;
CREATE POLICY "Users can delete own switches" ON public.switches
FOR DELETE USING ((SELECT auth.uid()) = user_id AND status IN ('CANCELLED', 'TRIGGERED'));

-- SWITCH RECIPIENTS
DROP POLICY IF EXISTS "Users can view own switch recipients" ON public.switch_recipients;
CREATE POLICY "Users can view own switch recipients" ON public.switch_recipients
FOR SELECT USING (EXISTS (
  SELECT 1 FROM public.switches
  WHERE switches.id = switch_recipients.switch_id AND switches.user_id = (SELECT auth.uid())
));

DROP POLICY IF EXISTS "Users can insert own switch recipients" ON public.switch_recipients;
CREATE POLICY "Users can insert own switch recipients" ON public.switch_recipients
FOR INSERT WITH CHECK (EXISTS (
  SELECT 1 FROM public.switches
  WHERE switches.id = switch_recipients.switch_id AND switches.user_id = (SELECT auth.uid())
));

DROP POLICY IF EXISTS "Users can update own switch recipients" ON public.switch_recipients;
CREATE POLICY "Users can update own switch recipients" ON public.switch_recipients
FOR UPDATE USING (EXISTS (
  SELECT 1 FROM public.switches
  WHERE switches.id = switch_recipients.switch_id AND switches.user_id = (SELECT auth.uid())
)) WITH CHECK (EXISTS (
  SELECT 1 FROM public.switches
  WHERE switches.id = switch_recipients.switch_id AND switches.user_id = (SELECT auth.uid())
));

DROP POLICY IF EXISTS "Users can delete own switch recipients" ON public.switch_recipients;
CREATE POLICY "Users can delete own switch recipients" ON public.switch_recipients
FOR DELETE USING (EXISTS (
  SELECT 1 FROM public.switches
  WHERE switches.id = switch_recipients.switch_id AND switches.user_id = (SELECT auth.uid())
));

-- FILES
DROP POLICY IF EXISTS "Users can view own switch files" ON public.files;
CREATE POLICY "Users can view own switch files" ON public.files
FOR SELECT USING (EXISTS (
  SELECT 1 FROM public.switches
  WHERE switches.id = files.switch_id AND switches.user_id = (SELECT auth.uid())
));

DROP POLICY IF EXISTS "Users can insert own switch files" ON public.files;
CREATE POLICY "Users can insert own switch files" ON public.files
FOR INSERT WITH CHECK (EXISTS (
  SELECT 1 FROM public.switches
  WHERE switches.id = files.switch_id AND switches.user_id = (SELECT auth.uid())
));

DROP POLICY IF EXISTS "Users can update own switch files" ON public.files;
CREATE POLICY "Users can update own switch files" ON public.files
FOR UPDATE USING (EXISTS (
  SELECT 1 FROM public.switches
  WHERE switches.id = files.switch_id AND switches.user_id = (SELECT auth.uid())
)) WITH CHECK (EXISTS (
  SELECT 1 FROM public.switches
  WHERE switches.id = files.switch_id AND switches.user_id = (SELECT auth.uid())
));

DROP POLICY IF EXISTS "Users can delete own switch files" ON public.files;
CREATE POLICY "Users can delete own switch files" ON public.files
FOR DELETE USING (EXISTS (
  SELECT 1 FROM public.switches
  WHERE switches.id = files.switch_id AND switches.user_id = (SELECT auth.uid())
));

-- CHECK INS
DROP POLICY IF EXISTS "Users can view own check-ins" ON public.check_ins;
CREATE POLICY "Users can view own check-ins" ON public.check_ins
FOR SELECT USING ((SELECT auth.uid()) = user_id AND EXISTS (
  SELECT 1 FROM public.switches
  WHERE switches.id = check_ins.switch_id AND switches.user_id = (SELECT auth.uid())
));

DROP POLICY IF EXISTS "Users can insert own check-ins" ON public.check_ins;
CREATE POLICY "Users can insert own check-ins" ON public.check_ins
FOR INSERT WITH CHECK ((SELECT auth.uid()) = user_id AND EXISTS (
  SELECT 1 FROM public.switches
  WHERE switches.id = check_ins.switch_id AND switches.user_id = (SELECT auth.uid())
));

-- AUDIT LOGS
DROP POLICY IF EXISTS "Users can view own audit logs" ON public.audit_logs;
CREATE POLICY "Users can view own audit logs" ON public.audit_logs
FOR SELECT USING (
  user_id = (SELECT auth.uid()) OR EXISTS (
    SELECT 1 FROM public.switches
    WHERE switches.id = audit_logs.switch_id AND switches.user_id = (SELECT auth.uid())
  )
);

-- RECIPIENT CLAIM TOKENS
DROP POLICY IF EXISTS "Users can view own switch claim tokens" ON public.recipient_claim_tokens;
CREATE POLICY "Users can view own switch claim tokens" ON public.recipient_claim_tokens
FOR SELECT USING (EXISTS (
  SELECT 1 FROM public.switches
  WHERE switches.id = recipient_claim_tokens.switch_id AND switches.user_id = (SELECT auth.uid())
));

DROP POLICY IF EXISTS "Users can insert own switch claim tokens" ON public.recipient_claim_tokens;
CREATE POLICY "Users can insert own switch claim tokens" ON public.recipient_claim_tokens
FOR INSERT WITH CHECK (EXISTS (
  SELECT 1 FROM public.switches
  WHERE switches.id = recipient_claim_tokens.switch_id AND switches.user_id = (SELECT auth.uid())
));

DROP POLICY IF EXISTS "Users can update own switch claim tokens" ON public.recipient_claim_tokens;
CREATE POLICY "Users can update own switch claim tokens" ON public.recipient_claim_tokens
FOR UPDATE USING (EXISTS (
  SELECT 1 FROM public.switches
  WHERE switches.id = recipient_claim_tokens.switch_id AND switches.user_id = (SELECT auth.uid())
));

-- NOTIFICATIONS
DROP POLICY IF EXISTS "Users can view own switch notifications" ON public.notifications;
CREATE POLICY "Users can view own switch notifications" ON public.notifications
FOR SELECT USING (EXISTS (
  SELECT 1 FROM public.switches
  WHERE switches.id = notifications.switch_id AND switches.user_id = (SELECT auth.uid())
));
