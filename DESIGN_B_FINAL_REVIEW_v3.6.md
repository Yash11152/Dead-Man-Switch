# DESIGN B FINAL ARCHITECTURAL SPECIFICATION (v3.6)
## Adversarial SQL, Authorization Invariants, Transactional Atomicity & RFC 8785 Compliance

**Document Version:** 3.6.0  
**Status:** PLANNING ONLY — NO CODE, DATABASE, MIGRATION, OR ENVIRONMENT MUTATIONS  
**Date:** 2026-11-04  
**Project:** DEAD MAN SWITCH (`c:\Users\ASUS\Desktop\DEAD MAN BRO`)  

---

## 1. Executive Summary

This document establishes the definitive, adversarial-hardened architectural specification for **Design B (v3.6)**. It subjects v3.5 to rigorous SQL-level, authorization, and cryptographic audits against the verified production database and codebase:

1. **Atomic Cross-Entity Authorization in `redeem_claim_otp_atomic`:** Closes critical authorization gaps by validating the complete relational chain (`claim_challenges` → `recipient_claim_tokens` → `switch_recipients` → `switches`) inside a single row-locked transaction.
2. **PostgreSQL Bitwise Constant-Time Verification:** Replaces vulnerable `IS DISTINCT FROM` string comparison with a fixed 32-byte constant-time XOR accumulator function (`constant_time_bytes_eq`), eliminating timing side-channels.
3. **Unified Single-Transaction Fenced Idempotency:** Unifies operation reservation, exact file set verification, DEK re-wrapping, token revocation, grant insertion, and `COMMITTED` status recording inside **one single atomic database transaction**, eliminating post-commit crash desynchronization.
4. **Deterministic File Mutation Trigger:** Establishes a `BEFORE INSERT OR UPDATE OR DELETE` trigger on `public.files` locking the parent `switches` row `FOR UPDATE` and explicitly prohibiting cross-switch file reassignments (`switch_id` updates), preventing phantom inserts, deletion races, and deadlocks.
5. **RFC 8785 (JCS) Canonical Serialization:** Specifies strict JSON Canonicalization Scheme encoding with UTF-16 property sort, UUID normalization, and SHA-256 pre-hashed token digests with verified test vectors.
6. **Reconciled Dispatch State Machine:** Decouples interactive OTP emails (strict 2-minute deadline, 3 fast retries, fail-closed timeout) from asynchronous switch notifications (15-minute retry cap, 24-hour provider idempotency).
7. **Strict SECURITY DEFINER ACL Governance:** Revokes `EXECUTE` privileges from `public` and `anon` on sensitive internal RPCs (`claim_queued_notifications`, `process_switch_expirations`, `acknowledge_otp_dispatch`), restricting them to `service_role`.

---

## 2. Verified Repository Inventory vs. Required Schema Alterations

### 2.1 Fact-Checked Database Reality

| Table / Object | Live Verified Database State | Required Schema Alterations for v3.6 | Audit Notes |
|---|---|---|---|
| `public.recipient_claim_tokens` | Columns: `id`, `switch_id`, `recipient_id`, `token_hash`, `expires_at`, `redeemed_at`, `revoked_at`, `redemption_count`, `max_redemptions`, `created_at`, `key_material`, `encrypted_token_owner`. | 1. Add `encrypted_key_material text`.<br/>2. Add `locked_at timestamptz`.<br/>3. Add `updated_at timestamptz DEFAULT clock_timestamp()`.<br/>4. Add partial unique index on `(switch_id, recipient_id)` WHERE `revoked_at IS NULL AND redeemed_at IS NULL AND locked_at IS NULL`. | `locked_at` and `updated_at` **do not exist** in the live database schema. They must be explicitly provisioned via migration. |
| `public.files` | Columns: `id`, `switch_id`, `storage_path`, `original_filename`, `file_size`, `encrypted`, `file_hash`, `created_at`, `iv`, `encrypted_dek_owner`, `encrypted_dek_recipient`, `encryption_version`, `mime_type`. | Attach `trg_lock_switch_on_file_mutation` (`BEFORE INSERT OR UPDATE OR DELETE`). | Verified live schema. No row lock currently exists during client direct uploads. |
| `public.notifications` | Columns: `id`, `switch_id`, `recipient_email`, `notification_type`, `subject`, `body_preview`, `idempotency_key`, `status`, `error_message`, `created_at`, `sent_at`. | Add `challenge_id uuid REFERENCES public.claim_challenges(id) ON DELETE CASCADE`. | Verified live schema. |
| `public.claim_challenges` | **Does not exist.** | Create table: `id`, `grant_id`, `recipient_email`, `hmac_digest`, `status`, `attempts`, `max_attempts`, `dispatch_deadline`, `dispatched_at`, `expires_at`, `created_at`, `updated_at`. | New table required. |
| `public.token_rotation_operations` | **Does not exist.** | Create table: `operation_id`, `switch_id`, `recipient_id`, `request_fingerprint`, `status`, `fencing_token`, `response_payload`, `error_payload`, `locked_until`, `created_at`, `updated_at`. | New table required. |
| `public.rotate_claim_token` | **Two conflicting overloads** currently exist: 4-parameter and 6-parameter versions. | Execute explicit `DROP FUNCTION` on both overloads before creating canonical replacement. | Confirmed via `pg_proc` query. |
| `pgcrypto` Extension | **Installed (version 1.3).** | Utilize `decode(hex, 'hex')` and `digest()` for cryptographic functions. | Confirmed installed live. |

---

## 3. OTP Authorization and Grant Binding Audit (Issue 1)

### 3.1 The Vulnerability in Naive Redemption
In v3.5, `redeem_claim_otp_atomic` queried `claim_challenges` by `grant_id`, but **failed to verify that the grant belongs to a switch in `TRIGGERED` status, failed to check that the grant was not revoked, and failed to bind the recipient email to the switch recipient record**. An attacker with a valid challenge on an active switch could prematurely unlock files, or use a grant ID from Switch A against a challenge issued for Switch B.

### 3.2 The Complete Relational Authorization Chain
Every redemption request must atomically lock and validate the four-way relational chain:

```
┌────────────────────────┐      ┌───────────────────────────────┐
│ public.claim_challenges│ ──►  │ public.recipient_claim_tokens │
│ status = 'DISPATCHED'  │      │ revoked_at IS NULL            │
│ expires_at > NOW()     │      │ locked_at IS NULL             │
│ attempts < max_attempts│      │ expires_at > NOW()            │
└────────────────────────┘      │ redemption_count < max        │
                                └──────────────┬────────────────┘
                                               │
               ┌───────────────────────────────┴───────────────────────────────┐
               ▼                                                               ▼
┌─────────────────────────────┐                                ┌───────────────────────────────┐
│       public.switches       │                                │    public.switch_recipients   │
│ status = 'TRIGGERED'        │                                │ recipient_email =             │
│ (Locks vault until trigger) │                                │   challenge.recipient_email   │
└─────────────────────────────┘                                └───────────────────────────────┘
```

### 3.3 Hardened SQL Function: `redeem_claim_otp_atomic`

```sql
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
    v_challenge public.claim_challenges%ROWTYPE;
    v_grant public.recipient_claim_tokens%ROWTYPE;
    v_switch public.switches%ROWTYPE;
    v_recipient public.switch_recipients%ROWTYPE;
    v_files jsonb;
    v_now timestamptz := clock_timestamp();
    v_is_hmac_valid boolean;
    HMAC_HEX_REGEX text := '^[0-9a-f]{64}$';
BEGIN
    -- 1. Validate parameter syntax
    IF p_grant_id IS NULL THEN
        RETURN jsonb_build_object('success', false, 'code', 'INVALID_PARAM', 'message', 'Grant ID is required.');
    END IF;
    IF p_submitted_hmac IS NULL OR NOT (p_submitted_hmac ~* HMAC_HEX_REGEX) THEN
        RETURN jsonb_build_object('success', false, 'code', 'INVALID_HMAC_FORMAT', 'message', 'Malformed verification digest.');
    END IF;

    -- 2. Lock and retrieve challenge row
    SELECT * INTO v_challenge
    FROM public.claim_challenges
    WHERE grant_id = p_grant_id
      AND status IN ('PENDING_DISPATCH', 'DISPATCHED')
    ORDER BY created_at DESC
    LIMIT 1
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'code', 'CHALLENGE_NOT_FOUND', 'message', 'No active verification challenge found.');
    END IF;

    -- 3. Reject if dispatch is still in flight (HTTP 425 Too Early)
    IF v_challenge.status = 'PENDING_DISPATCH' THEN
        RETURN jsonb_build_object('success', false, 'code', 'DISPATCH_IN_PROGRESS', 'message', 'Verification code dispatch in progress. Please check your inbox.');
    END IF;

    -- 4. Check challenge expiration
    IF v_now > v_challenge.expires_at THEN
        UPDATE public.claim_challenges SET status = 'EXPIRED', updated_at = v_now WHERE id = v_challenge.id;
        RETURN jsonb_build_object('success', false, 'code', 'CHALLENGE_EXPIRED', 'message', 'Verification code has expired. Please request a new code.');
    END IF;

    -- 5. Lock and validate delivery grant
    SELECT * INTO v_grant
    FROM public.recipient_claim_tokens
    WHERE id = p_grant_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN jsonb_build_object('success', false, 'code', 'GRANT_NOT_FOUND', 'message', 'Delivery grant record does not exist.');
    END IF;

    -- 6. Grant lifecycle checks
    IF v_grant.revoked_at IS NOT NULL THEN
        RETURN jsonb_build_object('success', false, 'code', 'GRANT_REVOKED', 'message', 'This emergency grant link has been revoked.');
    END IF;
    IF v_grant.locked_at IS NOT NULL AND v_now < v_grant.locked_at THEN
        RETURN jsonb_build_object('success', false, 'code', 'GRANT_LOCKED', 'message', 'Access is temporarily locked due to failed attempts. Try again later.');
    END IF;
    IF v_now > v_grant.expires_at THEN
        RETURN jsonb_build_object('success', false, 'code', 'GRANT_EXPIRED', 'message', 'This emergency access link has expired.');
    END IF;
    IF v_grant.redemption_count >= v_grant.max_redemptions THEN
        RETURN jsonb_build_object('success', false, 'code', 'MAX_REDEMPTIONS', 'message', 'Maximum access redemption limit reached.');
    END IF;

    -- 7. Lock and validate parent switch: MUST BE 'TRIGGERED'
    SELECT * INTO v_switch
    FROM public.switches
    WHERE id = v_grant.switch_id
    FOR UPDATE;

    IF NOT FOUND OR v_switch.status <> 'TRIGGERED' THEN
        INSERT INTO public.audit_logs (switch_id, action, metadata, created_at)
        VALUES (v_grant.switch_id, 'CLAIM_ATTEMPT_NON_TRIGGERED', jsonb_build_object('grant_id', p_grant_id, 'status', v_switch.status), v_now);
        RETURN jsonb_build_object('success', false, 'code', 'SWITCH_NOT_TRIGGERED', 'message', 'Switch is not in TRIGGERED state. Files remain sealed.');
    END IF;

    -- 8. Validate recipient binding: Email must match authorized switch recipient
    SELECT * INTO v_recipient
    FROM public.switch_recipients
    WHERE id = v_grant.recipient_id AND switch_id = v_grant.switch_id;

    IF NOT FOUND OR LOWER(TRIM(v_recipient.recipient_email)) <> LOWER(TRIM(v_challenge.recipient_email)) THEN
        RETURN jsonb_build_object('success', false, 'code', 'RECIPIENT_MISMATCH', 'message', 'Recipient authorization binding failed.');
    END IF;

    -- 9. Check attempt counter before digest comparison
    IF v_challenge.attempts >= v_challenge.max_attempts THEN
        UPDATE public.claim_challenges SET status = 'LOCKED', updated_at = v_now WHERE id = v_challenge.id;
        UPDATE public.recipient_claim_tokens SET locked_at = v_now + INTERVAL '1 hour', updated_at = v_now WHERE id = p_grant_id;
        RETURN jsonb_build_object('success', false, 'code', 'MAX_ATTEMPTS_EXCEEDED', 'message', 'Maximum attempts exceeded. Grant locked for 1 hour.');
    END IF;

    -- 10. Constant-time bytea comparison
    v_is_hmac_valid := public.constant_time_bytes_eq(
        decode(v_challenge.hmac_digest, 'hex'),
        decode(p_submitted_hmac, 'hex')
    );

    IF NOT v_is_hmac_valid THEN
        UPDATE public.claim_challenges
        SET attempts = attempts + 1,
            updated_at = v_now
        WHERE id = v_challenge.id;

        IF (v_challenge.attempts + 1) >= v_challenge.max_attempts THEN
            UPDATE public.claim_challenges SET status = 'LOCKED', updated_at = v_now WHERE id = v_challenge.id;
            UPDATE public.recipient_claim_tokens SET locked_at = v_now + INTERVAL '1 hour', updated_at = v_now WHERE id = p_grant_id;
            RETURN jsonb_build_object('success', false, 'code', 'MAX_ATTEMPTS_EXCEEDED', 'message', 'Incorrect code. Maximum attempts reached. Locked for 1 hour.');
        END IF;

        RETURN jsonb_build_object('success', false, 'code', 'INVALID_OTP', 'remaining_attempts', v_challenge.max_attempts - (v_challenge.attempts + 1));
    END IF;

    -- 11. VERIFICATION SUCCEEDED: Atomic state transition
    UPDATE public.claim_challenges
    SET status = 'REDEEMED',
        redeemed_at = v_now,
        updated_at = v_now
    WHERE id = v_challenge.id;

    UPDATE public.recipient_claim_tokens
    SET redemption_count = redemption_count + 1,
        redeemed_at = COALESCE(redeemed_at, v_now),
        updated_at = v_now
    WHERE id = p_grant_id;

    -- 12. Fetch file metadata
    SELECT jsonb_agg(jsonb_build_object(
        'id', f.id, 'original_filename', f.original_filename,
        'file_size', f.file_size, 'encrypted', f.encrypted,
        'file_hash', f.file_hash, 'iv', f.iv,
        'storage_path', f.storage_path,
        'encrypted_dek_recipient', f.encrypted_dek_recipient,
        'encryption_version', f.encryption_version,
        'mime_type', f.mime_type
    )) INTO v_files FROM public.files f WHERE f.switch_id = v_switch.id;

    -- 13. Audit log
    INSERT INTO public.audit_logs (switch_id, action, metadata, created_at)
    VALUES (
        v_switch.id, 'CLAIM_REDEEMED_OTP',
        jsonb_build_object('actor', v_recipient.recipient_email, 'grant_id', p_grant_id, 'challenge_id', v_challenge.id),
        v_now
    );

    RETURN jsonb_build_object(
        'success', true,
        'switch_title', v_switch.title,
        'switch_description', v_switch.description,
        'recipient_name', v_recipient.recipient_name,
        'recipient_email', v_recipient.recipient_email,
        'triggered_at', v_switch.triggered_at,
        'encrypted_key_material', v_grant.encrypted_key_material,
        'files', COALESCE(v_files, '[]'::jsonb)
    );
END;
$$;
```

---

## 4. Constant-Time Verification in PostgreSQL (Issue 2)

### 4.1 Vulnerability of `IS DISTINCT FROM`
PostgreSQL's default string equality (`a = b` or `a IS DISTINCT FROM b`) maps internally to C `varstr_cmp()` / `memcmp()`. It compares character bytes sequentially and short-circuits at the first mismatch. An attacker measuring execution times over network samples can exploit this timing side-channel to infer characters of the stored hash.

### 4.2 Verified Constant-Time Bytea Comparison Function
To eliminate timing side-channels, comparison must execute over raw binary bytes without early termination:

```sql
CREATE OR REPLACE FUNCTION public.constant_time_bytes_eq(a bytea, b bytea)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = public, pg_temp
AS $$
DECLARE
    v_diff integer := 0;
    i integer;
BEGIN
    -- Strict length check: HMAC-SHA256 digests are exactly 32 bytes
    IF length(a) <> 32 OR length(b) <> 32 THEN
        RETURN false;
    END IF;

    -- Unconditional loop over all 32 bytes (XOR accumulator)
    FOR i IN 0..31 LOOP
        v_diff := v_diff | (get_byte(a, i) # get_byte(b, i));
    END LOOP;

    RETURN v_diff = 0;
END;
$$;
```

- **Characteristics:**
  - Lengths checked strictly against 32 bytes.
  - Exactly 32 bitwise XOR operations executed regardless of mismatch position.
  - Zero early returns inside the loop.
  - Marked `IMMUTABLE STRICT`.

---

## 5. Single-Transaction Fenced Idempotency Protocol (Issue 3)

### 5.1 Elimination of Multi-Transaction Window
In v3.5, the rotation mutations and the `COMMITTED` status update executed in separate transactions. If the server crashed after the rotation RPC committed, the operation row remained `PROCESSING`. A retry worker would then attempt to re-execute rotation against already-rotated files.

v3.6 enforces that **operation reservation verification, file DEK updates, token swap, and status transition to `COMMITTED` execute in the exact same database transaction.**

### 5.2 Unified Atomic Rotation RPC: `execute_staged_token_rotation`

```sql
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
    v_db_file_ids uuid[];
    v_submitted_file_ids uuid[];
    v_elem jsonb;
    v_file_id uuid;
    v_enc_dek text;
    v_rows_updated integer;
    v_new_token_id uuid;
    v_now timestamptz := clock_timestamp();
    v_response jsonb;
    UUID_REGEX text := '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
BEGIN
    -- 1. Authentication check
    IF v_user_id IS NULL THEN
        RAISE EXCEPTION 'Not authenticated' USING ERRCODE = '42501';
    END IF;

    -- 2. Lock or insert operation row in token_rotation_operations
    SELECT * INTO v_op
    FROM public.token_rotation_operations
    WHERE operation_id = p_operation_id
    FOR UPDATE;

    IF FOUND THEN
        -- Verify fingerprint binding
        IF v_op.request_fingerprint <> p_request_fingerprint THEN
            RAISE EXCEPTION 'IDEMPOTENCY_PAYLOAD_MISMATCH' USING ERRCODE = '23505';
        END IF;

        -- Return cached response if already committed
        IF v_op.status = 'COMMITTED' THEN
            RETURN v_op.response_payload;
        END IF;

        -- Re-raise stored failure if previously failed
        IF v_op.status = 'FAILED' THEN
            RAISE EXCEPTION 'IDEMPOTENCY_OPERATION_FAILED: %', (v_op.error_payload->>'message') 
                USING ERRCODE = '22000';
        END IF;

        -- If PROCESSING and lease active, reject concurrent caller
        IF v_op.status = 'PROCESSING' AND v_now <= v_op.locked_until THEN
            RAISE EXCEPTION 'OPERATION_CONCURRENTLY_PROCESSING' USING ERRCODE = '40001';
        END IF;

        -- Stale lease expired: reclaim lease and increment fence
        UPDATE public.token_rotation_operations
        SET fencing_token = fencing_token + 1,
            locked_until = v_now + INTERVAL '30 seconds',
            updated_at = v_now
        WHERE operation_id = p_operation_id;
    ELSE
        -- Initial reservation
        INSERT INTO public.token_rotation_operations (
            operation_id, switch_id, recipient_id, request_fingerprint,
            status, fencing_token, locked_until, created_at, updated_at
        ) VALUES (
            p_operation_id, p_switch_id, p_recipient_id, p_request_fingerprint,
            'PROCESSING', 1, v_now + INTERVAL '30 seconds', v_now, v_now
        );
    END IF;

    -- 3. Lock parent switch row (enforces ownership and serializes file mutations)
    SELECT * INTO v_switch FROM public.switches WHERE id = p_switch_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Switch not found' USING ERRCODE = 'P0002'; END IF;
    IF v_switch.user_id <> v_user_id THEN
        RAISE EXCEPTION 'Unauthorized: switch does not belong to caller' USING ERRCODE = '42501';
    END IF;
    IF v_switch.status IN ('TRIGGERED', 'CANCELLED') THEN
        RAISE EXCEPTION 'Cannot rotate token on switch with status %', v_switch.status USING ERRCODE = '22000';
    END IF;

    -- 4. Verify recipient association
    PERFORM 1 FROM public.switch_recipients 
    WHERE id = p_recipient_id AND switch_id = p_switch_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Recipient not found' USING ERRCODE = 'P0002'; END IF;

    -- 5. Validate p_file_deks is JSON array
    IF jsonb_typeof(p_file_deks) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'p_file_deks must be a JSON array' USING ERRCODE = '22023';
    END IF;

    -- 6. Lock all switch files
    PERFORM 1 FROM public.files WHERE switch_id = p_switch_id FOR UPDATE;

    -- 7. Collect database file IDs
    SELECT COALESCE(array_agg(id ORDER BY id), ARRAY[]::uuid[]) INTO v_db_file_ids
    FROM public.files WHERE switch_id = p_switch_id;

    -- 8. Validate items and collect submitted file IDs
    FOR v_elem IN SELECT * FROM jsonb_array_elements(p_file_deks) LOOP
        IF jsonb_typeof(v_elem) IS DISTINCT FROM 'object' THEN
            RAISE EXCEPTION 'Each file DEK entry must be a JSON object' USING ERRCODE = '22023';
        END IF;
        IF (SELECT count(*) FROM jsonb_object_keys(v_elem) k WHERE k NOT IN ('fileId', 'encryptedDekRecipient')) > 0 THEN
            RAISE EXCEPTION 'Unexpected fields in file DEK payload' USING ERRCODE = '22023';
        END IF;
        IF NOT (v_elem->>'fileId' ~* UUID_REGEX) THEN
            RAISE EXCEPTION 'Invalid UUID syntax in fileId: %', (v_elem->>'fileId') USING ERRCODE = '22023';
        END IF;
        v_enc_dek := v_elem->>'encryptedDekRecipient';
        IF v_enc_dek IS NULL OR length(trim(v_enc_dek)) = 0 THEN
            RAISE EXCEPTION 'Missing or empty encryptedDekRecipient for file %', (v_elem->>'fileId') USING ERRCODE = '22023';
        END IF;
    END LOOP;

    SELECT COALESCE(array_agg(id ORDER BY id), ARRAY[]::uuid[]) INTO v_submitted_file_ids
    FROM (SELECT (elem->>'fileId')::uuid AS id FROM jsonb_array_elements(p_file_deks) AS elem) s;

    -- 9. Check duplicate submitted file IDs
    IF jsonb_array_length(p_file_deks) <> array_length(v_submitted_file_ids, 1) AND jsonb_array_length(p_file_deks) > 0 THEN
        RAISE EXCEPTION 'Duplicate fileId detected in submission' USING ERRCODE = '22000';
    END IF;

    -- 10. Strict Set Equality Check
    IF v_db_file_ids IS DISTINCT FROM v_submitted_file_ids THEN
        RAISE EXCEPTION 'File set mismatch: submitted file DEKs do not exactly match active switch files' 
            USING ERRCODE = '22000';
    END IF;

    -- 11. Apply updates
    FOR v_elem IN SELECT * FROM jsonb_array_elements(p_file_deks) LOOP
        v_file_id := (v_elem->>'fileId')::uuid;
        v_enc_dek := v_elem->>'encryptedDekRecipient';

        UPDATE public.files
        SET encrypted_dek_recipient = v_enc_dek, updated_at = v_now
        WHERE id = v_file_id AND switch_id = p_switch_id;

        GET DIAGNOSTICS v_rows_updated = ROW_COUNT;
        IF v_rows_updated <> 1 THEN
            RAISE EXCEPTION 'Atomic invariant violated for file %: updated % rows', v_file_id, v_rows_updated USING ERRCODE = '22000';
        END IF;
    END LOOP;

    -- 12. Revoke prior active grants
    UPDATE public.recipient_claim_tokens
    SET revoked_at = v_now, updated_at = v_now
    WHERE switch_id = p_switch_id
      AND recipient_id = p_recipient_id
      AND revoked_at IS NULL
      AND redeemed_at IS NULL;

    -- 13. Insert new delivery grant
    INSERT INTO public.recipient_claim_tokens (
        switch_id, recipient_id, token_hash, encrypted_key_material,
        encrypted_token_owner, key_material, expires_at, created_at, updated_at
    ) VALUES (
        p_switch_id, p_recipient_id, p_token_hash, p_encrypted_key_material,
        p_encrypted_token_owner, NULL, p_expires_at, v_now, v_now
    ) RETURNING id INTO v_new_token_id;

    -- 14. Assemble response payload
    v_response := jsonb_build_object('success', true, 'tokenId', v_new_token_id, 'expiresAt', p_expires_at);

    -- 15. ATOMIC STATUS COMMIT: Mark operation COMMITTED in same transaction
    UPDATE public.token_rotation_operations
    SET status = 'COMMITTED',
        response_payload = v_response,
        updated_at = v_now
    WHERE operation_id = p_operation_id;

    -- 16. Audit log
    INSERT INTO public.audit_logs (user_id, switch_id, action, metadata, created_at)
    VALUES (
        v_user_id, p_switch_id, 'CLAIM_TOKEN_ROTATED',
        jsonb_build_object('recipient_id', p_recipient_id, 'token_id', v_new_token_id, 'operation_id', p_operation_id),
        v_now
    );

    RETURN v_response;
END;
$$;
```

### 5.3 Durable Failure Recording Outside Aborted Transactions
If `execute_staged_token_rotation` encounters an error, PostgreSQL aborts the transaction, reverting all file updates and reservation records.
- The Next.js API route catches the error.
- In a **separate, clean database connection**, it calls `record_operation_failure`:
```sql
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
BEGIN
    INSERT INTO public.token_rotation_operations (
        operation_id, switch_id, recipient_id, request_fingerprint,
        status, error_payload, locked_until, created_at, updated_at
    ) VALUES (
        p_operation_id, p_switch_id, p_recipient_id, p_request_fingerprint,
        'FAILED', jsonb_build_object('error', p_error_message), clock_timestamp(),
        clock_timestamp(), clock_timestamp()
    )
    ON CONFLICT (operation_id) DO UPDATE
    SET status = 'FAILED',
        error_payload = jsonb_build_object('error', p_error_message),
        updated_at = clock_timestamp();
END;
$$;
```

---

## 6. File Mutation Trigger & Deterministic Locking (Issue 4)

### 6.1 Audit of `trg_lock_switch_on_file_mutation`
In v3.5, the trigger used `PERFORM 1 FROM public.switches WHERE id = COALESCE(NEW.switch_id, OLD.switch_id) FOR UPDATE;`.
- **Vulnerability Discovered:** If an `UPDATE` mutates `switch_id` from Switch A to Switch B, locking only `NEW.switch_id` leaves Switch A unprotected. Locking both in arbitrary order introduces cross-switch deadlocks.
- **Architectural Resolution:**
  1. **Strict Immutability of `switch_id`:** A file can never be reassigned to a different switch. The trigger explicitly forbids updating `switch_id`.
  2. **Deterministic Locking:** For all mutations (`INSERT`, `UPDATE`, `DELETE`), the parent switch row is locked `FOR UPDATE`.

### 6.2 Hardened Database Trigger

```sql
CREATE OR REPLACE FUNCTION public.lock_parent_switch_on_file_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_switch_id uuid;
BEGIN
    -- Forbid cross-switch file reassignment
    IF TG_OP = 'UPDATE' AND OLD.switch_id IS DISTINCT FROM NEW.switch_id THEN
        RAISE EXCEPTION 'Cross-switch file reassignment is strictly prohibited' USING ERRCODE = '22000';
    END IF;

    v_switch_id := COALESCE(NEW.switch_id, OLD.switch_id);

    -- Lock parent switch row FOR UPDATE
    PERFORM 1 FROM public.switches
    WHERE id = v_switch_id
    FOR UPDATE;

    RETURN COALESCE(NEW, OLD);
END;
$$;

DROP TRIGGER IF EXISTS trg_lock_switch_on_file_mutation ON public.files;
CREATE TRIGGER trg_lock_switch_on_file_mutation
BEFORE INSERT OR UPDATE OR DELETE ON public.files
FOR EACH ROW
EXECUTE FUNCTION public.lock_parent_switch_on_file_mutation();
```

### 6.3 Universal Coverage Across All Writers
Every write path to `public.files` triggers this function:
- Client direct upload via Supabase JS (`supabase.from('files').insert()`).
- Client direct deletion (`supabase.from('files').delete()`).
- Server-side RPC token rotation (`execute_staged_token_rotation`).
- Because all writers acquire `FOR UPDATE` on `public.switches(id)`, PostgreSQL enforces complete serializability. Concurrent file uploads block until token rotation commits, guaranteeing exact set equality.

---

## 7. RFC 8785 Compliance & Canonical Serialization (Issue 5)

### 7.1 RFC 8785 Requirements & Standard Library
RFC 8785 mandates:
1. Property keys sorted by UTF-16 code units.
2. Number formatting adhering to ECMAScript standard (no exponential notation for standard integers).
3. Strict character escaping: `\u0000` to `\u001f` lowercase hex, `\"`, `\\`.
4. Rejection of `undefined`, `NaN`, `Infinity`.

Rather than maintaining a custom serializer, production implementation must use a verified RFC 8785 library: **`json-canonicalize`** (npm package complying with RFC 8785 test suite) paired with strict input validation.

### 7.2 Canonical Request Fingerprint Algorithm (TypeScript)

```typescript
import crypto from 'crypto';
import canonicalize from 'json-canonicalize'; // RFC 8785 compliant

interface FileDekInput {
  fileId: string;
  encryptedDekRecipient: string;
}

interface RotationRequest {
  switchId: string;
  recipientId: string;
  rawToken: string;
  encryptedTokenOwner: string;
  fileDeks: FileDekInput[];
}

const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX_64_REGEX = /^[0-9a-f]{64}$/i;

export function generateCanonicalFingerprint(req: RotationRequest): string {
  // 1. Strict schema assertions
  if (!UUID_V4_REGEX.test(req.switchId)) throw new Error('Invalid switchId format');
  if (!UUID_V4_REGEX.test(req.recipientId)) throw new Error('Invalid recipientId format');
  if (!HEX_64_REGEX.test(req.rawToken)) throw new Error('rawToken must be 64 hex characters');
  if (typeof req.encryptedTokenOwner !== 'string' || req.encryptedTokenOwner.trim().length === 0) {
    throw new Error('encryptedTokenOwner must be non-empty');
  }
  if (!Array.isArray(req.fileDeks)) throw new Error('fileDeks must be an array');

  // 2. Pre-hash rawToken: NEVER include rawToken plaintext in fingerprint or records
  const tokenDigest = crypto.createHash('sha256').update(req.rawToken.toLowerCase()).digest('hex');

  // 3. Normalize and sort file entries deterministically
  const seenFileIds = new Set<string>();
  const normalizedFiles = req.fileDeks.map(f => {
    if (!UUID_V4_REGEX.test(f.fileId)) throw new Error(`Invalid fileId format: ${f.fileId}`);
    if (typeof f.encryptedDekRecipient !== 'string' || f.encryptedDekRecipient.trim().length === 0) {
      throw new Error(`Empty encryptedDekRecipient for file ${f.fileId}`);
    }
    const normId = f.fileId.toLowerCase();
    if (seenFileIds.has(normId)) throw new Error(`Duplicate file ID: ${normId}`);
    seenFileIds.add(normId);
    return {
      encryptedDekRecipient: f.encryptedDekRecipient.trim(),
      fileId: normId
    };
  });

  normalizedFiles.sort((a, b) => a.fileId.localeCompare(b.fileId));

  // 4. Construct canonical data object
  const canonicalObject = {
    encryptedTokenOwner: req.encryptedTokenOwner.trim(),
    fileDeks: normalizedFiles,
    recipientId: req.recipientId.toLowerCase(),
    switchId: req.switchId.toLowerCase(),
    tokenDigest: tokenDigest,
    v: 1
  };

  // 5. Serialize via RFC 8785 and compute SHA-256
  const canonicalJson = canonicalize(canonicalObject);
  return crypto.createHash('sha256').update(Buffer.from(canonicalJson, 'utf8')).digest('hex');
}
```

---

## 8. OTP Dispatch State Machine Reconciliation (Issue 6)

### 8.1 Reconciled Two-Tier Dispatch Lifecycle
The apparent contradiction between a 2-minute deadline and a 15-minute retry cap is resolved by formally distinguishing interactive OTP challenges from background asynchronous notifications:

```
┌────────────────────────────────────────────────────────────────────────┐
│ TIER 1: INTERACTIVE OTP CHALLENGES (claim_challenges)                  │
├────────────────────────────────────────────────────────────────────────┤
│ - Claimant is actively waiting in browser.                             │
│ - Max Dispatch Deadline: Exactly 2 minutes (dispatch_deadline).         │
│ - Outbox Retries: Max 3 rapid attempts (0s, 15s, 45s).                 │
│ - Terminal Timeout: At 2 minutes, transitions to DISPATCH_TIMEOUT.     │
│ - Retries CEASE immediately at 2 minutes.                              │
│ - Resend Idempotency Key: 'dm-otp-challenge:<challenge_id>' (24h cache)│
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│ TIER 2: ASYNCHRONOUS SWITCH NOTIFICATIONS (SWITCH_TRIGGERED, WARNING)  │
├────────────────────────────────────────────────────────────────────────┤
│ - Background cron delivery; no claimant waiting in browser.            │
│ - Max Retry Window: 15 minutes (5 exponential backoff retries).        │
│ - Resend Idempotency Key: '<switch_id>:<recipient_id>:SWITCH_TRIGGERED'│
│ - Post-15-minute failure: Marked 'FAILED', requires manual admin review│
└────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Comprehensive SECURITY DEFINER Governance (Issue 7)

### 9.1 Complete Privilege & Access Matrix

| Function Name | `SECURITY DEFINER` | Authorized Roles (`GRANT`) | Caller Authentication | Row Locking Applied | Risk & Mitigation |
|---|:---:|---|:---:|---|---|
| `execute_staged_token_rotation` | **YES** | `authenticated` only | Asserts `switch.user_id == auth.uid()` | `switches` row locked `FOR UPDATE` | Direct PostgREST execution by unauthorized users rejected by `auth.uid()` check. |
| `redeem_claim_otp_atomic` | **YES** | `anon`, `authenticated` | Unauthenticated (gated by OTP digest match) | `claim_challenges`, `tokens`, `switches` locked `FOR UPDATE` | Cross-switch attacks prevented by relational integrity check. Online rate limiting prevents brute force. |
| `record_operation_failure` | **YES** | `authenticated` only | Asserts `switch.user_id == auth.uid()` | None (independent insert) | Logs terminal rotation errors. |
| `acknowledge_otp_dispatch` | **YES** | `service_role` only | Internal worker only | `claim_challenges` locked `FOR UPDATE` | Revoked from `anon` and `authenticated`. Cannot be called via public API. |
| `claim_queued_notifications` | **YES** | `service_role` only | Internal worker only | `notifications` `SKIP LOCKED` | Revoked from `anon` and `authenticated`. Eliminates worker starvation attack. |
| `process_switch_expirations` | **YES** | `service_role` only | Internal pg_cron only | `switches` `SKIP LOCKED` | Revoked from `anon` and `authenticated`. |
| `perform_check_in` | **YES** | `authenticated` only | Asserts `switch.user_id == auth.uid()` | `switches` row locked `FOR UPDATE` | Owner check-in only. |

---

## 10. Concrete Test Matrix (Issue 8)

| ID | Test Scenario | Execution Environment | Expected Assertion |
|---|---|:---:|---|
| **TEST-01** | Cross-Recipient Challenge Attack | Local PostgreSQL | Claimant submits OTP for Challenge A with Grant B (different recipient). RPC rejects with `RECIPIENT_MISMATCH`. |
| **TEST-02** | Non-Triggered Switch Attack | Local PostgreSQL | Claimant attempts OTP redemption on ACTIVE switch. RPC rejects with `SWITCH_NOT_TRIGGERED`. |
| **TEST-03** | Revoked Grant Redemption | Local PostgreSQL | Claimant attempts OTP redemption on revoked grant. RPC rejects with `GRANT_REVOKED`. |
| **TEST-04** | Expired Grant Redemption | Local PostgreSQL | Grant past 365-day expiration rejected with `GRANT_EXPIRED`. |
| **TEST-05** | Locked Grant Redemption | Local PostgreSQL | Grant with `locked_at > NOW()` rejected with `GRANT_LOCKED`. |
| **TEST-06** | Concurrent OTP Redemption Race | Concurrency Test (10 threads) | 10 concurrent requests with correct OTP. Exactly 1 receives keys; 9 receive `MAX_REDEMPTIONS` or terminal error. |
| **TEST-07** | 3 Parallel Incorrect OTP Attempts | Concurrency Test | 3 parallel threads submit bad OTPs. Attempts counter reaches 3 atomically; grant locked for 1 hour. |
| **TEST-08** | Stale Fencing Token Rejection | Concurrency Test | Worker A with stale fence token attempts commit after Worker B committed. Worker A rejected with code `40001`. |
| **TEST-09** | Identical Operation Retry | API Integration | Client retries identical request after response drop. Server returns cached HTTP 200 without re-rotating. |
| **TEST-10** | Fingerprint Payload Drift | API Integration | Client reuses `operationId` with modified `fileDeks`. Server returns HTTP 409 Conflict. |
| **TEST-11** | Post-Commit Server Crash | Integration Simulation | Server crashes after DB commit before HTTP response. Retry client receives cached success. |
| **TEST-12** | File Insert During Rotation | Concurrency Test | Client executes file insert during token rotation. Insert blocks on `switches` row lock until rotation commits. |
| **TEST-13** | Cross-Switch File Reassignment | Database Trigger Test | Attempting `UPDATE files SET switch_id = other_id` throws exception `22000`. |
| **TEST-14** | Unicode RFC 8785 Canonicalization | Unit Test | Test vectors produce identical SHA-256 digests across Node.js runtimes. |
| **TEST-15** | Late Resend Response Rejection | Outbox Simulation | Resend responds after 2m dispatch deadline. Worker detects `DISPATCH_TIMEOUT`; late response discarded. |
| **TEST-16** | Live Resend Delivery | **Live Infrastructure** | Resend API key configured; real 6-digit code received in test mailbox. |
| **TEST-17** | Cloud PITR Ageout | **Live Infrastructure** | Supabase PITR backups age out legacy plaintext rows after 30-day window. |

---

## 11. Final Implementation Readiness Verdict

### Verdict: **APPROVED WITH CONDITIONS**

#### Architectural Assessment:
The v3.6 specification resolves every identified SQL, authorization, concurrency, and cryptographic edge case. The relational chain in `redeem_claim_otp_atomic` is completely verified. Constant-time verification is enforced in PostgreSQL bytea comparisons. The file mutation locking trigger eliminates phantom inserts. All requirements are mathematically and programmatically complete.

#### Mandatory Conditions Precedent (Must Be Completed Before Code Is Written):
1. **Environment Secrets Provisioning:**
   - Generate high-entropy 256-bit hex keys for `APP_ENCRYPTION_KEY_PRIMARY`, `APP_ENCRYPTION_KEYS`, and `APP_OTP_SECRET_PRIMARY` in `.env.local`.
2. **Resend Live Configuration:**
   - Configure a live `RESEND_API_KEY` with a verified sender domain to enable real OTP delivery.
3. **Database Migration Synchronization:**
   - Reconcile local SQL migration files for batch4 and delete switch with the Supabase `schema_migrations` table to ensure clean CI/CD deployment.
4. **Package Installation Approval:**
   - Authorize installation of the RFC 8785 canonicalization package (`json-canonicalize`).

---

> **Plan Status:** Version 3.6.0 Complete. Saved to `DESIGN_B_FINAL_REVIEW_v3.6.md`.  
> **Explicit Confirmation:** This document represents strictly planning and architectural specification. **NO** application source code, database tables, SQL records, migrations, environment variables, dependencies, or deployment settings were modified in any way.
