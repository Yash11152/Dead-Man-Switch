# DESIGN B FINAL ARCHITECTURAL SPECIFICATION & AUDIT (v3.3)
## Post-Dispatch OTP Timers, At-Least-Once Outbox, Fingerprinted Idempotency & Exact Set Validation

**Document Version:** 3.3.0  
**Status:** PLANNING ONLY — NO CODE, DATABASE, MIGRATION, OR ENVIRONMENT MUTATIONS  
**Date:** 2026-11-04  
**Project:** DEAD MAN SWITCH (`c:\Users\ASUS\Desktop\DEAD MAN BRO`)  

---

## 1. Executive Summary & Explicit Security Boundary

### 1.1 Scope & Purpose
This document provides the definitive, production-grade architectural specification for **Design B (v3.3)**. It refines v3.2 by resolving distributed systems and cryptographic edge cases:
1. Aligning recipient OTP expiration to post-dispatch confirmation with strict dispatch timeouts.
2. Acknowledging at-least-once email delivery reality with provider-level deduplication.
3. Explicitly auditing and constraining `rawToken` transmission over HTTPS to the application server.
4. Binding idempotency operation IDs to cryptographic request fingerprints with independent failure recording.
5. Replacing crude file-count checks with strict mathematical set-equality validation across payload files.

### 1.2 Unchanged Threat Model & Security Boundary

```
┌────────────────────────────────────────────────────────────────────────┐
│ WHAT THIS ARCHITECTURE DEFENDS AGAINST                                 │
├────────────────────────────────────────────────────────────────────────┤
│ ✓ Stolen Database / Storage Backups: An attacker possessing complete   │
│   SQL dumps, WAL archives, or Storage snapshots cannot decrypt files.  │
│ ✓ Passive Database Leaks (SQLi / Read Replicas): Read access yields   │
│   only encrypted DEKs and encrypted key envelopes.                     │
│ ✓ Cloud / Storage Bucket Leaks: Storage objects are AES-256-GCM cipher-│
│   text under unique, random 256-bit DEKs.                              │
│ ✓ Rogue Database Administrators: DB superusers cannot decrypt files    │
│   without both the external application key and client-side secrets.   │
│ ✓ Recipient Email Spoofing & Rainbow Tables: Claiming requires proof of│
│   inbox access via server-keyed HMAC-authenticated OTP challenges.     │
│ ✓ Replay Attacks & Payload Mutations: Request-fingerprinted operation  │
│   IDs and database row locks prevent replay, desync, and payload drift.│
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│ WHAT THIS ARCHITECTURE DOES NOT PROTECT AGAINST (APPLICATION BOUNDARY) │
├────────────────────────────────────────────────────────────────────────┤
│ ✗ Active Application Server Compromise: If an attacker attains Remote  │
│   Code Execution (RCE) on the Next.js server, they possess             │
│   APP_ENCRYPTION_KEY and APP_OTP_SECRET. They can unwrap recipient     │
│   grants as they are claimed and decrypt files in transit.             │
│ ✗ Compromised Host Environment: Server memory dumps, malicious build   │
│   dependencies (supply chain attacks), or rogue server administrators  │
│   can capture rawToken or decrypted keys during execution.             │
│ ✗ Client-Side Malware / Rogue Browser Extensions: An attacker with DOM │
│   or JavaScript execution rights in the browser can exfiltrate keys     │
│   from WebCrypto memory while a session is active.                     │
└────────────────────────────────────────────────────────────────────────┘
```

> **Fundamental Principle:** Client-side file encryption paired with server-side envelope encryption provides defense-in-depth against data-layer and storage-layer breaches. It **does not and cannot** provide full zero-knowledge confidentiality against compromise of the active application server executing the API.

---

## 2. Post-Dispatch OTP Expiry & Dispatch-Wait Protocol (Correction 1)

### 2.1 The Distributed Latency Problem
In previous versions, the 10-minute OTP expiration clock began when the challenge record was created. However, in transactional outbox architectures, email queuing, worker scheduling, and external provider processing (Resend / AWS SES) introduce variable latency (often 30 to 180 seconds). Under queue congestion, a claimant could receive an email with an OTP that has already expired or has an unfairly truncated window.

### 2.2 Post-Dispatch Timer Architecture
The OTP lifespan is decoupled into two distinct phases:
1. **Phase 1: Dispatch-Wait Window (`max_dispatch_wait`):** Maximum 2 minutes allowed for the background outbox worker to deliver the email to Resend.
2. **Phase 2: Active Claim Window (`claim_window`):** Exactly 10 minutes, commencing **only after** Resend confirms message acceptance.

```
CHALLENGE CREATION (t = 0)
┌────────────────────────────────────────────────────────────────────────┐
│ status = 'PENDING_DISPATCH'                                            │
│ dispatch_deadline = clock_timestamp() + INTERVAL '2 minutes'           │
│ expires_at = NULL (Timer NOT started yet)                              │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    │ Worker executes POST /emails to Resend
                                    ▼
RESEND ACCEPTS (t = t_dispatch <= 2m)
┌────────────────────────────────────────────────────────────────────────┐
│ status = 'DISPATCHED'                                                  │
│ dispatched_at = clock_timestamp()                                      │
│ expires_at = clock_timestamp() + INTERVAL '10 minutes'                 │
│ (Active 10-minute countdown starts NOW)                                │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.3 State Transitions & Delayed Delivery Handling
The table `public.claim_challenges` manages these lifecycle timestamps:

```sql
ALTER TABLE public.claim_challenges
ADD COLUMN IF NOT EXISTS dispatch_deadline timestamptz NOT NULL,
ADD COLUMN IF NOT EXISTS dispatched_at timestamptz,
ALTER COLUMN expires_at DROP NOT NULL; -- Nullable until dispatched
```

```
                  ┌──────────────────────┐
                  │   PENDING_DISPATCH   │
                  └──────────┬───────────┘
                             │
            ┌────────────────┴────────────────┐
            ▼                                 ▼
   [Resend 200 within 2m]          [NOW() > dispatch_deadline]
            │                                 │
            ▼                                 ▼
    ┌──────────────┐                 ┌──────────────────┐
    │  DISPATCHED  │                 │ DISPATCH_TIMEOUT │
    └───────┬──────┘                 └──────────────────┘
            │
    ┌───────┴───────┬───────────────┐
    ▼               ▼               ▼
[Verified]     [10m Expired]   [3 Bad Attempts]
    │               │               │
    ▼               ▼               ▼
┌──────────┐   ┌─────────┐     ┌──────────┐
│ REDEEMED │   │ EXPIRED │     │  LOCKED  │
└──────────┘   └─────────┘     └──────────┘
```

- **Delayed Delivery (> 2 minutes):** If the worker cannot dispatch the message within 2 minutes (e.g., persistent Resend 500 errors or worker starvation), a sweeper or the worker transitions the challenge to `DISPATCH_TIMEOUT`. The queued notification is marked `CANCELLED`.
- **Claimant Experience:** If the claimant attempts to submit an OTP on a timed-out challenge, the API returns HTTP 410 Gone:  
  `"Verification email delivery exceeded the maximum wait time. Please request a fresh code."`

### 2.4 Acceptance Criteria & Failure Scenarios (Correction 1)
- **AC-1.1 (Expiry Commences Post-Dispatch):** `claim_challenges.expires_at` must remain `NULL` while `status = 'PENDING_DISPATCH'`, and must be set to `dispatched_at + INTERVAL '10 minutes'` upon worker confirmation.
- **AC-1.2 (Strict 2-Minute Dispatch Deadline):** A challenge remaining in `PENDING_DISPATCH` for longer than 2 minutes must be rejected by `/api/claim/redeem` and marked `DISPATCH_TIMEOUT`.
- **Failure Scenario 1.1 (Severe Provider Outage):** Resend API drops offline for 5 minutes. Challenges created during this window hit `dispatch_deadline` and transition to `DISPATCH_TIMEOUT`. The recipient never receives an active code with a broken timer.
- **Security Implications:** Eliminates timing attacks where an adversary exploits email delays to redeem expired challenges, and eliminates claimant confusion from expired emails.

---

## 2. At-Least-Once Dispatch & Challenge Deduplication (Correction 2)

### 2.1 The Reality of Distributed Email Delivery
Network partitions and crash-recovery semantics dictate that message queues connecting to external APIs (Resend) operate on **at-least-once delivery**. A worker can dispatch an email to Resend, receive a connection drop before storing the acknowledgement, and retry. True exactly-once delivery across external networks is provably impossible.

### 2.2 Provider Idempotency & Single-Challenge Invariant
To prevent at-least-once retries from flooding the recipient with divergent OTP codes or creating multiple conflicting challenge rows:

1. **Provider-Level Idempotency Key:**
   When the outbox worker invokes Resend, it transmits a deterministic idempotency header:
   ```
   Idempotency-Key: dm-otp-challenge:<challenge_id>
   ```
   If the worker retries due to a dropped socket, Resend recognizes the key and does not emit a second email.
2. **Single Active Challenge Constraint:**
   A recipient grant can have **at most one non-terminal challenge** in flight at any time. This is enforced via a partial unique index:
   ```sql
   CREATE UNIQUE INDEX idx_single_pending_challenge_per_grant
   ON public.claim_challenges (grant_id)
   WHERE status IN ('PENDING_DISPATCH', 'DISPATCHED');
   ```
3. **Challenge Request Deduplication:**
   If a recipient repeatedly clicks "Send Code", the API checks for an existing active challenge:
   - If an active challenge exists and was created less than 60 seconds ago, the request is rate-limited (HTTP 429 `"Please wait 60 seconds before requesting another code."`).
   - If older than 60 seconds, the previous challenge is marked `SUPERSEDED`, and a fresh challenge row is created.

### 2.3 Acceptance Criteria & Failure Scenarios (Correction 2)
- **AC-2.1 (Single Active Challenge Invariant):** The database must reject any attempt to insert a second challenge for the same `grant_id` while an existing challenge is in `PENDING_DISPATCH` or `DISPATCHED`.
- **AC-2.2 (Provider Idempotency Key):** All HTTP requests from the outbox worker to Resend must include `Idempotency-Key: dm-otp-challenge:<challenge_id>`.
- **Failure Scenario 2.1 (Worker Timeout Retry):** Worker sends OTP `738192` to Resend. Resend sends the email, but TCP ACK is lost. Worker retries 5 seconds later with identical idempotency key. Resend acknowledges without sending a second email. One email received, one code valid.
- **Security Implications:** Prevents recipient inbox confusion and prevents race conditions where multiple OTPs are concurrently valid for the same unlock grant.

---

## 3. Explicit `rawToken` Transmission Boundary & Server Hygiene (Correction 3)

### 3.1 Transparent Architectural Disclosure
Under Design B, client-side zero-knowledge is maintained for **payload files**, but the recipient delivery grant secret (`rawToken`, 32 bytes CSPRNG hex) is **transmitted to the Next.js application server over HTTPS** during switch creation (`POST /api/switches/create`) and token rotation (`POST /api/switches/provision-token`).

```
┌────────────────────────────────────────────────────────────────────────┐
│ WHY rawToken MUST REACH THE APPLICATION SERVER                         │
├────────────────────────────────────────────────────────────────────────┤
│ The core requirement of Design B is that the PostgreSQL database, WAL  │
│ logs, and storage backups NEVER hold rawToken in plaintext.            │
│ The server holds the root secret (APP_ENCRYPTION_KEY).                 │
│ Therefore, rawToken must be transmitted to the application server so   │
│ the server can envelope-encrypt it into encrypted_key_material.        │
└────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Server-Side Memory Hygiene & Plaintext Persistence Prohibition
To minimize the exposure window of `rawToken` on the server:

1. **Ephemeral RAM Only:** `rawToken` must exist strictly in ephemeral execution memory for the duration of the cryptographic cipher call (typically < 5 milliseconds).
2. **Explicit Buffer Zeroing:**
   ```typescript
   // src/lib/server/crypto.ts
   export function encryptKeyMaterial(rawToken: string): EncryptedEnvelope {
     const tokenBuf = Buffer.from(rawToken, 'hex');
     try {
       const iv = crypto.randomBytes(12);
       const cipher = crypto.createCipheriv('aes-256-gcm', PRIMARY_KEY, iv);
       const ct = Buffer.concat([cipher.update(tokenBuf), cipher.final()]);
       const tag = cipher.getAuthTag();
       return { v: 1, kid: PRIMARY_KID, alg: 'A256GCM', iv: iv.toString('base64'), tag: tag.toString('base64'), ct: ct.toString('base64') };
     } finally {
       tokenBuf.fill(0); // Best-effort zeroing of the memory buffer
     }
   }
   ```
3. **Strict Plaintext Persistence Prohibition:**
   - Under no circumstances may `rawToken` be written to PostgreSQL tables, temporary disk files, Redis caches, serverless session stores, or cookies.
   - The database column `recipient_claim_tokens.key_material` must be set to `NULL` for all new rows.
4. **Structured Logging Redaction:**
   - Next.js logging middleware and error handlers must sanitize request bodies:
     ```typescript
     // Middleware / Logger sanitization
     const sanitizedBody = { ...reqBody };
     if (sanitizedBody.rawToken) sanitizedBody.rawToken = '[REDACTED_SECRET]';
     ```
5. **Exception Sanitization:**
   - If encryption or database commit fails, the error thrown must be generic:
     `throw new Error("Failed to provision delivery grant.")`
   - The raw token must never be concatenated into error messages, stack traces, or APM metadata.

### 3.3 Acceptance Criteria & Failure Scenarios (Correction 3)
- **AC-3.1 (Buffer Zeroing):** Unit tests must verify that `tokenBuf.fill(0)` executes in the `finally` block even when cipher initialization throws.
- **AC-3.2 (Log Audit):** Integration test logs inspecting `console.log`, `console.error`, and network APM outputs during switch creation must assert zero occurrences of the 64-character hex `rawToken`.
- **AC-3.3 (Zero Plaintext DB Writes):** Database inspection after provisioning must assert `key_material IS NULL` and `encrypted_key_material IS NOT NULL`.
- **Failure Scenario 3.1 (Process Heap Dump):** An attacker obtains an un-sanitized Node.js heap dump. *Risk Analysis:* If captured within the 5ms cipher window, the token may be visible; post-execution, `fill(0)` minimizes residuals, but V8 garbage collection behavior cannot guarantee physical erasure. Documented as an accepted residual risk.
- **Security Implications:** Clarifies the exact trust model: users must trust the Next.js runtime host and environment configuration, while remaining protected against database, backup, and storage breaches.

---

## 4. Request-Fingerprinted Idempotency & Terminal Failure Recording (Correction 4)

### 4.1 The Payload Drift Vulnerability
If an idempotency key (`operation_id`) is reused by a client or malicious caller with a **different** payload (e.g., targeting a different recipient or submitting altered file DEKs), returning the cached result of the original operation leads to state corruption or security bypass.

### 4.2 Cryptographic Request Fingerprinting
Every operation is cryptographically bound to its canonical payload:

$$\text{RequestFingerprint} = \text{SHA-256}\Big(\text{CanonicalJSON}\big(\{ \text{switchId}, \text{recipientId}, \text{SHA-256}(\text{rawToken}), \text{fileDeksSorted} \}\big)\Big)$$

```typescript
// Computing the canonical request fingerprint
const canonicalPayload = JSON.stringify({
  switchId: body.switchId,
  recipientId: body.recipientId,
  tokenHash: crypto.createHash('sha256').update(body.rawToken).digest('hex'),
  fileDeks: body.fileDeks.sort((a, b) => a.fileId.localeCompare(b.fileId))
});
const fingerprint = crypto.createHash('sha256').update(canonicalPayload).digest('hex');
```

### 4.3 Idempotency Protocol & Conflict Rejection
When `POST /api/switches/provision-token` is invoked with `operation_id`:

```
POST /api/switches/provision-token { operationId, payload... }
                        │
                        ▼
           Query token_rotation_operations
                        │
         ┌──────────────┴──────────────┐
         ▼                             ▼
[operation_id Exists]         [operation_id Not Found]
         │                             │
    Compare Stored Fingerprint         │ Proceed with Atomic
    vs Current Fingerprint             │ Rotation RPC
         │                             │
    ┌────┴────┐                        │
    ▼         ▼                        │
[Matches]  [Mismatches]                ▼
    │         │               Insert token_rotation_operations
    │         ▼               (status: 'COMMITTED', fingerprint)
    │      HTTP 409 Conflict           │
    ▼                                  ▼
Return Cached 200 OK             Return 200 OK
```
- **If Fingerprints Match:** Return cached response payload with HTTP 200 (safe retry).
- **If Fingerprints Differ:** Reject with **HTTP 409 Conflict**:  
  `"Idempotency collision: operation ID was previously used with different parameters."`

### 4.4 Autonomous Recording of Terminal Failures
If the atomic database rotation RPC encounters a terminal constraint failure (e.g., switch status invalid, foreign recipient mismatch), the main transaction rolls back. 

To prevent transaction rollback from erasing the failure record:
1. The Next.js API route catches the RPC exception.
2. In an **independent, autocommit database query** (outside the failed transaction), the server inserts the failure record:
   ```sql
   INSERT INTO public.token_rotation_operations (
       operation_id, switch_id, recipient_id, request_fingerprint, 
       status, response_payload, created_at
   ) VALUES (
       $1, $2, $3, $4, 
       'FAILED', jsonb_build_object('error', $5, 'code', $6), clock_timestamp()
   ) ON CONFLICT (operation_id) DO NOTHING;
   ```
3. Subsequent retries with the same `operation_id` receive the cached failure response immediately without re-triggering expensive, failing database operations.

### 4.5 Acceptance Criteria & Failure Scenarios (Correction 4)
- **AC-4.1 (Payload Drift Rejection):** Reusing an `operationId` with a modified `fileDeks` array must be rejected with HTTP 409 Conflict.
- **AC-4.2 (Terminal Failure Persistence):** When rotation fails due to an invalid switch status, the failure must be persisted in `token_rotation_operations` and returned on retry.
- **Failure Scenario 4.1 (Retry with Altered Key):** Client generates token A, network drops, client re-generates token B but reuses `operationId`. Server detects fingerprint mismatch, rejects with HTTP 409, preventing corrupted grant creation.
- **Security Implications:** Guarantees strong idempotency semantics, eliminates payload drift, and prevents denial-of-service loops on failing operations.

---

## 5. Exact File-ID Set Validation (Correction 5)

### 5.1 The Inadequacy of File-Count Checks
In v3.2, token rotation verified that `fileDeks.length === fileCount`. This check is vulnerable to:
1. **Duplicate IDs:** Client sends `[fileA, fileA, fileA]` (length 3) for a switch with files `[fileA, fileB, fileC]` (count 3). File B and C lose access keys.
2. **Foreign-Switch Files:** Client includes a `fileId` belonging to an entirely different switch or user.
3. **Displaced Files:** Client omits `fileB` and injects an unrecognized UUID `fileX`. Count matches, but `fileB` becomes permanently un-decryptable.

### 5.2 Mathematical Set-Equality Specification
Token rotation must enforce strict set equality between the set of file IDs configured on the switch in PostgreSQL and the set of file IDs submitted in the rotation payload:

$$\text{SubmittedSet} \equiv \text{DatabaseSet}$$

$$\big\{ \text{fileId} \mid \text{fileId} \in \text{SubmittedPayload} \big\} = \big\{ \text{id} \mid \text{id} \in \text{public.files} \text{ WHERE } \text{switch\_id} = p\_switch\_id \big\}$$

### 5.3 PostgreSQL Set Validation Implementation
Inside the atomic RPC `execute_staged_token_rotation()`:

```sql
DECLARE
    v_db_file_ids uuid[];
    v_submitted_file_ids uuid[];
    v_duplicate_count integer;
BEGIN
    -- 1. Extract sorted array of all active file IDs belonging to this switch
    SELECT array_agg(id ORDER BY id) INTO v_db_file_ids
    FROM public.files
    WHERE switch_id = p_switch_id;

    -- 2. Extract submitted file IDs from JSONB payload
    SELECT array_agg((item->>'fileId')::uuid ORDER BY (item->>'fileId')::uuid)
    INTO v_submitted_file_ids
    FROM jsonb_array_elements(p_file_deks) AS item;

    -- 3. Check for duplicates in submitted list
    SELECT count(*) - count(DISTINCT (item->>'fileId')::uuid)
    INTO v_duplicate_count
    FROM jsonb_array_elements(p_file_deks) AS item;

    IF v_duplicate_count > 0 THEN
        RAISE EXCEPTION 'Validation failed: duplicate file IDs present in rotation payload' 
            USING ERRCODE = '22000';
    END IF;

    -- 4. Enforce strict set equality (handles missing files, extra files, and foreign files)
    IF v_db_file_ids IS DISTINCT FROM v_submitted_file_ids THEN
        RAISE EXCEPTION 'Validation failed: submitted file DEK set does not exactly match switch files' 
            USING ERRCODE = '22000';
    END IF;

    -- 5. Set equality passed: apply updates to encrypted_dek_recipient
    FOR r IN SELECT * FROM jsonb_array_elements(p_file_deks) LOOP
        UPDATE public.files
        SET encrypted_dek_recipient = (r->>'encryptedDekRecipient'),
            updated_at = clock_timestamp()
        WHERE id = (r->>'fileId')::uuid
          AND switch_id = p_switch_id;
    END LOOP;
END;
```

### 5.4 Acceptance Criteria & Failure Scenarios (Correction 5)
- **AC-5.1 (Duplicate ID Rejection):** Submitting identical file IDs in `fileDeks` must trigger an immediate exception and roll back the transaction.
- **AC-5.2 (Foreign ID Rejection):** Submitting a `fileId` belonging to another switch must be rejected by the set-equality assertion.
- **AC-5.3 (Missing ID Rejection):** Omitting any single switch file from `fileDeks` must be rejected with error code `22000`.
- **Failure Scenario 5.1 (Rogue Client Injection):** A malicious actor modifies frontend script to submit a foreign `fileId` during rotation to attempt unauthorized key association. Set comparison detects `v_db_file_ids IS DISTINCT FROM v_submitted_file_ids`, aborts transaction with zero database changes.
- **Security Implications:** Guarantees complete cryptographic coverage: every payload file is verified to have an updated recipient key before the old grant is revoked.

---

## 6. Comprehensive Acceptance Criteria Matrix

| Area | Requirement / Correction | Acceptance Criteria |
|:---:|---|---|
| **OTP Timing** | AC-1.1: Post-Dispatch Expiry | `claim_challenges.expires_at` computed strictly as `dispatched_at + INTERVAL '10 minutes'`. |
| **OTP Timing** | AC-1.2: Dispatch Deadline | Challenges pending dispatch for > 2 minutes marked `DISPATCH_TIMEOUT` and rejected. |
| **Outbox** | AC-2.1: Single Active Challenge | Partial unique index enforces at most one pending/dispatched challenge per grant. |
| **Outbox** | AC-2.2: Provider Idempotency | Worker transmits `Idempotency-Key: dm-otp-challenge:<challenge_id>` to Resend. |
| **Security** | AC-3.1: Server Memory Hygiene | `rawToken` buffer explicitly zeroed in `finally` block; excluded from logs and errors. |
| **Security** | AC-3.2: Plaintext DB Prohibition | Post-provisioning database asserts `key_material IS NULL` across all newly created rows. |
| **Idempotency** | AC-4.1: Fingerprint Binding | Reusing `operation_id` with modified parameters rejected with HTTP 409 Conflict. |
| **Idempotency** | AC-4.2: Terminal Failure Logging | Autonomous logging preserves failure records in `token_rotation_operations` upon RPC error. |
| **Set Validation**| AC-5.1: Strict Set Equality | Database RPC asserts `v_db_file_ids = v_submitted_file_ids`; rejects duplicates, foreign IDs, and omissions. |

---

## 7. Unresolved Residual Risks (Transparent Risk Acceptance)

The following risks are inherent to the selected architecture and are explicitly documented rather than silently assumed to be resolved:

1. **Application Server Custody of `APP_ENCRYPTION_KEY` and `APP_OTP_SECRET`:**
   - Because `APP_ENCRYPTION_KEY` and `APP_OTP_SECRET` reside on the Next.js production host, root compromise of the Next.js runtime environment allows an attacker to intercept recipient keys during active claim redemptions.
2. **Third-Party Email Relay Vulnerability (Resend):**
   - The security of recipient inbox verification relies on DNS MX records, SMTP TLS transit, and Resend API integrity. Compromise of the recipient's mail provider allows OTP interception.
3. **Owner Passphrase & Recovery Sheet Loss:**
   - If the switch owner loses both their master passphrase and their 24-word recovery sheet, their personal access to files is unrecoverable. (Recipient delivery remains intact via `encrypted_key_material`).
4. **Cloud Database WAL Retention:**
   - Historical WAL archives in Supabase managed infrastructure retain deleted rows until the Point-in-Time Recovery (PITR) window (7 to 30 days) expires. Physical erasure of legacy plaintext rows occurs only after WAL recycling.

---

## 8. Summary of Version 3.3 Corrections

1. **Post-Dispatch OTP Expiry & 2-Minute Deadline:** Corrected timer mechanics so the 10-minute claim clock begins strictly after Resend confirms delivery. Enforced a maximum 2-minute dispatch deadline, timing out stalled outbox items cleanly.
2. **At-Least-Once Outbox with Provider Deduplication:** Formally acknowledged distributed email realities. Added provider idempotency headers (`dm-otp-challenge:<challenge_id>`) and a database partial unique index preventing duplicate concurrent challenges.
3. **Explicit `rawToken` Transmission Boundary & Memory Hygiene:** Documented that `rawToken` travels over HTTPS to the application server for envelope encryption. Enforced ephemeral memory-only residency, `buf.fill(0)` zeroing, logging redaction, and strict database plaintext prohibition.
4. **Fingerprinted Idempotency & Terminal Failure Persistence:** Bound every operation ID to an immutable SHA-256 canonical request fingerprint, rejecting payload mutations with HTTP 409 Conflict. Defined autonomous recording of terminal errors when transactions roll back.
5. **Exact File-ID Set Validation:** Replaced file-count checks with mathematical array/set equality inside the PostgreSQL RPC. Guaranteed rejection of duplicate IDs, foreign-switch files, omitted files, and injected IDs before rotation commits.

---

> **Plan Status:** Version 3.3.0 Complete. Saved to `DESIGN_B_FINAL_REVIEW_v3.3.md`.  
> **Explicit Confirmation:** This document is strictly an architectural specification and plan. **NO** source code, database tables, SQL records, migrations, environment variables, or deployment settings were modified in any way. Awaiting explicit user approval before proceeding to implementation.
