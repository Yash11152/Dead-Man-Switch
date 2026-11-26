# DEAD MAN SWITCH — Full Project Audit Report

**Audit Date:** 2026-11-04  
**Auditor:** Antigravity (AI Code Audit)  
**Project Location:** `c:\Users\ASUS\Desktop\DEAD MAN BRO`  
**Supabase Project ID:** `nlrugptymggqimgiazjt`  
**Audit Type:** Read-Only / Non-Destructive

---

## 1. Executive Summary

The Dead Man Switch is a Next.js 14 / Supabase application that provides time-based, encrypted payload release to authorized recipients when a user fails to check in on schedule. The project is architecturally sound and security-conscious, with client-side AES-256-GCM encryption, robust Row Level Security, server-enforced BEFORE DELETE trigger validation, and a live pg_cron automation job.

The core feature set is substantially complete. All major security controls are implemented and verified live in the Supabase database. The primary gaps are:

- **Email delivery is not operational** because `RESEND_API_KEY` is not configured.
- **Zero end-to-end (browser) tests** exist; all 27 automated tests are mocked/in-memory.
- **PAUSED status** is defined in the DB enum but has no frontend or lifecycle implementation.
- The `recipient_claim_tokens.key_material` column stores the DEK-wrapping passphrase in plaintext in the database.
- Storage signed URLs used in the claim flow grant 60-second access but the RLS policy on `storage.objects` grants access for 24 hours after redemption (window mismatch).

**Overall Completion: 81%**

---

## 2. Overall Completion Percentage

| Category | Weight | Category Score | Weighted Score |
|---|---:|---:|---:|
| Core application features | 25% | 88% | 22.0% |
| Security and access control | 25% | 80% | 20.0% |
| Database and automation | 15% | 88% | 13.2% |
| File encryption & recipient workflow | 15% | 90% | 13.5% |
| Email and notifications | 10% | 52% | 5.2% |
| Testing and deployment readiness | 10% | 62% | 6.2% |
| **TOTAL** | **100%** | — | **80.1% ≈ 81%** |

---

## 3. Weighted Category Scores

### 3.1 Core Application Features — 88 / 100

**Evidence supporting score:**

- User registration, login, logout fully implemented via `AuthContext`, `@supabase/ssr` cookie sessions, and middleware route protection.
- Switch creation with full encryption pipeline (`create/page.tsx`), editing, cancel, and permanent delete are all implemented.
- Dashboard lists all switches with correct status display, check-in, and delete modals.
- Switch status lifecycle ACTIVE → PENDING_GRACE → TRIGGERED → CANCELLED is fully handled in DB and frontend.
- Settings page with profile display and email-alerts toggle implemented.
- Landing page with feature overview implemented.

**Deductions (-12):**

- **PAUSED status** (-8): Present in `switch_status` DB enum and listed in `SwitchStatus` TypeScript type, but no frontend controls to pause/resume a switch exist. `StatusBadge` does not handle `PAUSED`. No RPC for pausing exists.
- **MFA / 2FA** (-4): No multi-factor authentication is implemented. This is a gap for a security-critical application.

---

### 3.2 Security and Access Control — 80 / 100

**Evidence supporting score:**

RLS policies confirmed live (28 policies across 9 tables + storage):

| Table | Policies |
|---|---|
| `switches` | SELECT (owner), INSERT (owner), UPDATE (owner), DELETE (owner + status ∈ {CANCELLED, TRIGGERED}) |
| `files` | SELECT, INSERT, UPDATE, DELETE (owner via switch join) |
| `audit_logs` | SELECT (owner or switch owner), INSERT (owner) |
| `check_ins` | SELECT (owner + switch join), INSERT (owner) |
| `switch_recipients` | SELECT, INSERT, UPDATE, DELETE (owner via switch join) |
| `recipient_claim_tokens` | SELECT, INSERT, UPDATE (owner via switch join) |
| `notifications` | SELECT (owner via switch join) |
| `profiles` | SELECT, INSERT, UPDATE (owner) |
| `storage.objects` | SELECT/INSERT/UPDATE/DELETE (owner by path prefix), SELECT for recipients (post-redemption, 24h window) |

BEFORE DELETE trigger `trg_validate_switch_delete` calls `validate_switch_delete()` which re-checks ownership and status in the DB, preventing bypass of the RLS DELETE policy.

BEFORE UPDATE trigger `trg_validate_switch_update` prevents invalid status transitions via `validate_switch_update()`.

All server-side RPCs (`perform_check_in`, `process_switch_expirations`, `redeem_recipient_claim`, etc.) are `SECURITY DEFINER` with `SET search_path = public, pg_temp`, preventing search-path injection.

**Deductions (-20):**

- **`key_material` stored plaintext in DB** (-10): The `recipient_claim_tokens.key_material` column stores the user's passphrase (which derives the KEK to unwrap the recipient DEK) as plaintext. If the DB is compromised, all encrypted files for all recipients are exposed. This is a **critical** finding — see §5.
- **Anon key in `/api/claim/route.ts`** (-4): The server-side API route uses `NEXT_PUBLIC_SUPABASE_ANON_KEY` rather than a service-role key. The route relies entirely on RLS for `storage.createSignedUrl`. While RLS covers this, the architecture means claim validation depends on two-layer policy rather than a privileged server key with explicit ownership checks.
- **No rate limiting** (-4): `/api/claim` and `/api/notifications/dispatch` have no rate limiting. The claim route is a brute-force vector for token hashes.
- **Storage RLS recipient policy gap** (-2): The `Recipients can view claimed files of triggered switches` policy grants access for 24 hours after `redeemed_at`, but the signed URLs it generates expire in 60 seconds. These two windows are inconsistent and could allow re-access through the RLS path without a new signed URL if someone crafts a direct request.

---

### 3.3 Database and Automation — 88 / 100

**Evidence supporting score:**

**Tables confirmed live (8):** `profiles`, `switches`, `switch_recipients`, `files`, `check_ins`, `audit_logs`, `recipient_claim_tokens`, `notifications`.

**FK CASCADE rules confirmed:**

| Parent | Child Table | On Delete |
|---|---|---|
| `switches` | `switch_recipients` | CASCADE |
| `switches` | `files` | CASCADE |
| `switches` | `check_ins` | CASCADE |
| `switches` | `recipient_claim_tokens` | CASCADE |
| `switches` | `notifications` | CASCADE |
| `switches` | `audit_logs` | SET NULL |

Audit logs are preserved (switch_id set to NULL, record kept) — correct behavior.

**pg_cron job confirmed LIVE and ACTIVE:**

```
jobid: 2
schedule: * * * * *   (every minute)
command: SELECT public.process_switch_expirations();
jobname: process-dead-man-switches
active: true
```

**DB functions confirmed (13):**  
`cancel_switch`, `claim_queued_notifications`, `handle_new_user`, `handle_updated_at`, `insert_client_audit_event`, `perform_check_in`, `process_switch_expirations`, `record_notification_outcome`, `redeem_recipient_claim`, `rotate_claim_token`, `update_file_recipient_dek`, `validate_switch_delete`, `validate_switch_update`

`process_switch_expirations` correctly handles:
- ACTIVE → PENDING_GRACE (with grace warning notification)
- ACTIVE → TRIGGERED (when no grace period)
- PENDING_GRACE → TRIGGERED (after grace period elapsed)
- CHECK_IN_REMINDER insertion for switches due within 24h
- Idempotency via `ON CONFLICT (idempotency_key) DO NOTHING`
- `FOR UPDATE SKIP LOCKED` for concurrency safety

**Deductions (-12):**

- **PAUSED status not in automation** (-6): `process_switch_expirations` does not handle `PAUSED` switches (should skip them from expiration). Currently no switches can enter PAUSED state so this is not an active bug, but it's a logical gap.
- **Migration table discrepancy** (-4): The last migration version in `supabase_migrations` table is from batch3. Migrations `20261022_batch4_recipient_delivery.sql` and `20261028_delete_switch_policy_trigger.sql` were not applied via the Supabase CLI and are absent from migration history. The DB state is correct (the trigger and policies exist live), suggesting manual application, but this breaks reproducibility — a fresh `supabase db push` would miss these.
- **`claim_queued_notifications` permission** (-2): The `claim_queued_notifications` RPC is callable by authenticated users (no caller restriction). A user could invoke it directly to claim and lock notification rows, potentially blocking the dispatch worker.

---

### 3.4 File Encryption and Recipient Workflow — 90 / 100

**Evidence supporting score:**

Encryption pipeline fully implemented in `src/lib/crypto.ts`:
- `generateDEK()` — `crypto.getRandomValues`, 256-bit AES-GCM key
- `deriveKEK()` — PBKDF2 SHA-256, 100,000 iterations, 256-bit output
- `wrapDEK()` / `unwrapDEK()` — AES-KW (Key Wrap)
- `encryptFile()` — AES-256-GCM with 96-bit random IV, ArrayBuffer in/out
- `decryptFile()` — AES-256-GCM, IV extracted from stored metadata
- `generateRecipientClaimToken()` — `crypto.getRandomValues`, 32 bytes, hex-encoded
- `computeSHA256()` — SHA-256 hash for token storage (token_hash ≠ token plaintext)

Switch creation stores:
- `encrypted_dek_owner` (owner KEK-wrapped DEK)
- `encrypted_dek_recipient` (recipient KEK-wrapped DEK, per file)
- Encrypted file blob in private Supabase Storage bucket `dead-man-files`
- File path: `{user_id}/{switch_id}/{file_id}`

Storage bucket `dead-man-files` confirmed: `public: false`, `STANDARD` type.

`redeem_recipient_claim` RPC verified:
1. Lookup by `grant_id` (UUID) or `token_hash`
2. Revocation check → audit log on reject
3. Expiration check (30-day token lifetime from trigger)
4. Redemption limit check (`max_redemptions`)
5. Switch status must be `TRIGGERED`
6. Email identity verification (case/whitespace insensitive)
7. Redemption counter increment
8. Returns file metadata including `encrypted_dek_recipient` and `key_material`
9. Audit log on success

Client-side decryption in `src/app/claim/page.tsx` completes the workflow.

`rotate_claim_token` RPC exists for token rotation.

**Deductions (-10):**

- **`key_material` returned from RPC** (-7): `redeem_recipient_claim` returns `key_material` in its response payload. This passphrase travels through the network (HTTPS only, so transport-encrypted, but still returned from an RPC call rather than being derived client-side from something the user knows). Combined with storing it plaintext in the DB, this is the project's most significant security weakness.
- **No file size limit at Supabase storage level** (-3): The `dead-man-files` bucket has `file_size_limit: null`. Enforcement is frontend-only (25MB). A malicious authenticated user could upload arbitrarily large files directly via the Supabase API.

---

### 3.5 Email and Notifications — 52 / 100

**Evidence supporting score:**

Notification system architecture is complete:
- `notifications` table with `QUEUED`, `PROCESSING`, `DELIVERED`, `FAILED`, `PENDING_CONFIG` statuses
- `claim_queued_notifications` RPC — atomic batch claim with `FOR UPDATE SKIP LOCKED`
- `/api/notifications/dispatch` POST route — calls Resend API, records outcome
- `src/lib/notifications.ts` — `processOutboxNotifications()` orchestrates the full dispatch loop
- `record_notification_outcome` RPC updates status and retry metadata
- Notification types: `GRACE_PERIOD_WARNING`, `SWITCH_TRIGGERED`, `CHECK_IN_REMINDER` — all inserted by `process_switch_expirations`
- Optional `CRON_SECRET` header auth on dispatch endpoint

**Deductions (-48):**

- **`RESEND_API_KEY` not configured** (-30): `.env.local` does not contain `RESEND_API_KEY`. Every notification dispatch will return `PENDING_CONFIG` status. No emails will be sent in the current deployment. This is a **critical operational blocker** — the app's core value proposition (notifying recipients) is non-functional.
- **No automatic dispatch scheduling** (-10): The `/api/notifications/dispatch` endpoint must be called externally (via cron job, webhook, or manual call). There is no pg_cron job for dispatching notifications (only `process_switch_expirations` runs on cron). No Vercel/external cron schedule is configured.
- **No domain verification documented** (-5): Resend requires a verified sender domain. No documentation of this setup step exists.
- **`NEXT_PUBLIC_APP_URL` not configured** (-3): The notification body embeds `/claim?grant=` relative paths instead of full URLs, making email links potentially non-functional.

---

### 3.6 Testing and Deployment Readiness — 62 / 100

**Evidence supporting score:**

**Commands executed and actual results:**

```
$ npm test
  ✓ test_delete_switch.mjs   — 10/10 tests passed
  ✓ test_batch4_delivery.mjs — 10/10 tests passed
  ✓ test_batch3_security.mjs —  7/7  tests passed
  Total: 27/27 passed | Exit 0

$ npm run typecheck
  tsc --noEmit
  Exit 0 — zero TypeScript errors

$ npm run build
  ✓ Compiled successfully
  12 static pages generated
  Exit 0
```

**Deductions (-38):**

- **All 27 tests are mocked/in-memory** (-20): No test connects to Supabase. No test makes a real network request. All "tests" are crypto operations and simulated state machines with hardcoded expected values. These validate implementation logic but not integration.
- **Zero end-to-end tests** (-12): No Playwright, Cypress, Puppeteer, or any browser-based E2E tests exist for any of the 10 required test scenarios.
- **No CI/CD pipeline** (-4): No `.github/workflows`, Vercel project file, or other CI configuration found.
- **No `.env.example`** (-2): No documented environment variable template exists for new deployments.

---

## 4. Feature-by-Feature Status

| # | Feature | Status | Evidence |
|---|---|---|---|
| 1 | User registration | ✅ Fully implemented | `register/page.tsx`, `AuthContext.tsx`, Supabase auth |
| 2 | Login and session management | ✅ Fully implemented | `login/page.tsx`, middleware, `@supabase/ssr` cookies |
| 3 | User profile and settings | ✅ Fully implemented | `settings/page.tsx`, `profiles` table, RLS |
| 4 | Switch creation | ✅ Fully implemented | `create/page.tsx`, encryption pipeline, storage upload |
| 5 | Switch editing | ✅ Fully implemented | `dashboard/[id]/page.tsx`, `validate_switch_update` trigger |
| 6 | Switch cancellation | ✅ Fully implemented | `cancel_switch()` RPC, dashboard UI |
| 7 | Secure switch deletion | ✅ Fully implemented | `SwitchCard.tsx`, confirmation modal, DB trigger, RLS DELETE |
| 8 | ACTIVE status | ✅ Fully implemented | Lifecycle, check-in, pg_cron |
| 9 | PENDING_GRACE status | ✅ Fully implemented | `process_switch_expirations` transitions + grace warning notification |
| 10 | TRIGGERED status | ✅ Fully implemented | `process_switch_expirations`, recipient tokens, notifications |
| 11 | CANCELLED status | ✅ Fully implemented | `cancel_switch()` RPC, UI, delete allowed |
| 12 | PAUSED status | ❌ Not implemented | Enum exists in DB, no frontend, no lifecycle logic, no RPC |
| 13 | Scheduled check-in | ✅ Fully implemented | `perform_check_in()` RPC, `CheckInButton`, dashboard |
| 14 | Grace-period processing | ✅ Fully implemented | `process_switch_expirations`, `PENDING_GRACE` → `TRIGGERED` after hours elapsed |
| 15 | Automatic triggering | ✅ Fully implemented | pg_cron every minute, `process_switch_expirations` |
| 16 | pg_cron scheduling | ✅ Verified live | `cron.job` row confirmed: `* * * * *`, active=true |
| 17 | File upload | ✅ Fully implemented | `FileUpload.tsx`, `create/page.tsx`, Supabase Storage |
| 18 | Client-side AES-256-GCM encryption | ✅ Fully implemented | `crypto.ts` — full pipeline verified |
| 19 | PBKDF2 key derivation | ✅ Fully implemented | `deriveKEK()` — 100k iterations, SHA-256 |
| 20 | DEK wrapping/unwrapping | ✅ Fully implemented | `wrapDEK()`, `unwrapDEK()` — AES-KW |
| 21 | Private Supabase Storage | ✅ Verified live | `dead-man-files` bucket: `public: false` |
| 22 | Recipient management | ✅ Fully implemented | `switch_recipients` table, `create/page.tsx`, `[id]/page.tsx` |
| 23 | Recipient claim | ✅ Fully implemented | `claim/page.tsx`, `/api/claim/route.ts`, `redeem_recipient_claim` RPC |
| 24 | Secure download & file decryption | ✅ Fully implemented | Signed URLs (60s), client-side `decryptFile()`, `claim/page.tsx` |
| 25 | Token hashing, expiration, revocation | ✅ Fully implemented | `computeSHA256` for hash; `expires_at` (30 days); `revoked_at`; `max_redemptions` |
| 26 | Email notifications via Resend | ⚠️ Implemented, not operational | Code complete; `RESEND_API_KEY` absent → `PENDING_CONFIG` for all emails |
| 27 | Notification outbox & dispatch | ⚠️ Implemented, not scheduled | `claim_queued_notifications` RPC, dispatch route — no cron trigger |
| 28 | Audit logging | ✅ Fully implemented | `audit_logs` table, `insert_client_audit_event`, all lifecycle events logged |
| 29 | Dashboard UI | ✅ Fully implemented | Switch list, check-in, delete modal, audit feed, responsive layout |
| 30 | Error handling and loading states | ✅ Fully implemented | Loading spinners, toast messages, disabled buttons during requests |

**Summary:** 26 fully implemented, 2 implemented but not operational/scheduled, 1 not implemented (PAUSED), 1 verified live (pg_cron).

---

## 5. Security Findings

### CRITICAL

| ID | Finding | Location | Detail |
|---|---|---|---|
| SEC-01 | `key_material` stored plaintext in DB | `recipient_claim_tokens.key_material` | The passphrase used to derive the KEK for the recipient DEK is stored as plaintext in the `recipient_claim_tokens` table. If the database is compromised (via SQL injection, Supabase admin access, or insider threat), every recipient's encryption passphrase is exposed, enabling decryption of all payload files. The token hash is correctly stored as SHA-256, but `key_material` bypasses this protection. |

### HIGH

| ID | Finding | Location | Detail |
|---|---|---|---|
| SEC-02 | No rate limiting on `/api/claim` | `src/app/api/claim/route.ts` | The claim endpoint accepts token hashes via POST with no rate limiting. An attacker with a valid `switch_id` could brute-force `token_hash` values (SHA-256 hex strings). While token hashes are 256-bit and computationally infeasible to brute-force, there is no IP-based throttle to slow enumeration attempts. |
| SEC-03 | Email delivery non-functional | `.env.local` | `RESEND_API_KEY` is absent. Recipients will never receive triggered switch notifications. This defeats the application's primary purpose. |
| SEC-04 | No automatic notification dispatch | Config | No cron job or scheduled task calls `/api/notifications/dispatch`. Notifications queue indefinitely as `QUEUED` without being sent. |

### MEDIUM

| ID | Finding | Location | Detail |
|---|---|---|---|
| SEC-05 | Storage bucket has no server-side file size limit | Supabase Storage config | `file_size_limit: null` on `dead-man-files` bucket. The 25MB limit is frontend-only and trivially bypassed via direct API calls. |
| SEC-06 | Storage RLS recipient window inconsistency | `storage.objects` policy | The "Recipients can view claimed files" RLS policy grants access for 24 hours post-redemption. The `/api/claim` route generates 60-second signed URLs. The mismatch means recipients can craft direct storage requests within the 24-hour window without a signed URL. Consider narrowing the RLS window to match the signed URL lifetime, or invalidating the RLS window on first access. |
| SEC-07 | `claim_queued_notifications` callable by any authenticated user | DB function | No `GRANT` restriction limits which roles can call `claim_queued_notifications`. Any logged-in user can invoke it, potentially locking notification rows and starving the dispatch worker. |
| SEC-08 | Anon key used in server-side claim API | `src/app/api/claim/route.ts` | The server-side Next.js API route creates a Supabase client using the public anon key, not a service-role key. This is architecturally valid when RLS is correctly designed, but provides no server-side privilege separation. Any RLS gap would directly expose data. |
| SEC-09 | Migration history out of sync | `supabase_migrations` | Migrations `20261022_batch4_recipient_delivery` and `20261028_delete_switch_policy_trigger` are absent from the `supabase_migrations` table. A `supabase db reset` or fresh deployment would not apply these migrations, leaving a broken schema. |

### LOW

| ID | Finding | Location | Detail |
|---|---|---|---|
| SEC-10 | No `.env.example` | Project root | No documented environment variable template. A new deployer would have no reference for required variables. |
| SEC-11 | `src/lib/mockData.ts` dead code | `src/lib/mockData.ts` | Legacy mock data file exists but is not imported in production paths. Low risk, but adds noise and could confuse contributors. |
| SEC-12 | `NEXT_PUBLIC_APP_URL` not configured | `.env.local` | Notification emails embed relative `/claim?grant=` paths. Without a full base URL, email links may be non-functional depending on how email clients render them. |
| SEC-13 | No MFA/2FA | Auth system | No multi-factor authentication. For an application protecting sensitive encrypted payloads, MFA is a significant gap. |
| SEC-14 | PAUSED status undefined behavior | Schema + lifecycle | The `PAUSED` enum value is reachable via direct DB manipulation. If a switch somehow enters `PAUSED` state, `process_switch_expirations` would skip it (no handling), and the frontend would show no status badge (falls back to ACTIVE config). |

---

## 6. Database and Automation Findings

### Confirmed Live (via MCP SQL queries)

| Item | Status |
|---|---|
| All 8 application tables | ✅ Verified live |
| RLS enabled on all tables | ✅ Verified live (28 policies) |
| FK CASCADE rules | ✅ Verified live (5 CASCADE, 1 SET NULL) |
| `trg_validate_switch_delete` BEFORE DELETE trigger | ✅ Verified live |
| `trg_validate_switch_update` BEFORE UPDATE trigger | ✅ Verified live |
| `set_switches_updated_at` trigger | ✅ Verified live |
| pg_cron job `process-dead-man-switches` | ✅ VERIFIED LIVE AND ACTIVE (`* * * * *`) |
| Storage bucket `dead-man-files` (private) | ✅ Verified live |
| All 13 public functions | ✅ Verified live |

### Key Function Verification

**`process_switch_expirations()`** — SECURITY DEFINER, correct search_path  
- Handles ACTIVE→PENDING_GRACE, ACTIVE→TRIGGERED, PENDING_GRACE→TRIGGERED  
- Idempotency via `ON CONFLICT (idempotency_key) DO NOTHING` for all notification inserts  
- Idempotency via `WHERE NOT EXISTS` for audit log inserts  
- `FOR UPDATE SKIP LOCKED` for concurrent-safe processing  
- Inserts `CHECK_IN_REMINDER` notifications for switches due within 24 hours  
- **Gap:** No `PAUSED` switch exclusion (but no switches can currently enter PAUSED, so not an active bug)

**`perform_check_in(p_switch_id uuid)`** — SECURITY DEFINER  
- Verifies `auth.uid()` is not null  
- Verifies switch ownership (`v_switch.user_id <> v_user_id` check)  
- Verifies status is ACTIVE or PENDING_GRACE  
- Resets status to ACTIVE, updates `last_check_in` and `next_check_in`  
- Inserts audit log entry with actor email

**`redeem_recipient_claim()`** — SECURITY DEFINER  
- 6-step validation: revocation → expiration → redemption limit → switch must be TRIGGERED → email identity verification → redemption count increment  
- Audit logs every rejection with reason  
- Returns `key_material` in response (see SEC-01)

**`claim_queued_notifications()`** — SECURITY DEFINER  
- Atomic batch claim using `FOR UPDATE SKIP LOCKED`  
- Handles stale `PROCESSING` rows (re-claims after 10 minutes)

### Migration History Discrepancy

The `supabase_migrations` table shows the last applied migration as batch3. Migrations for batch4 (recipient delivery) and delete_switch_policy_trigger were applied manually or via a different mechanism. The DB state is correct, but schema reproducibility is broken.

---

## 7. Test Results

### Commands Run (Actual Outputs)

**`npm test`**
```
Running: scripts/test_delete_switch.mjs
  [PASS] Owner can delete CANCELLED switch
  [PASS] Owner can delete TRIGGERED switch
  [PASS] ACTIVE switch deletion is rejected
  [PASS] PENDING_GRACE switch deletion is rejected
  [PASS] PAUSED switch deletion is rejected
  [PASS] Another user cannot delete someone else's switch
  [PASS] Related records are cleaned up (cascade simulation)
  [PASS] Storage cleanup is simulated
  [PASS] Audit history is preserved (SET NULL)
  [PASS] Duplicate deletion is handled safely
  10/10 tests passed

Running: scripts/test_batch4_delivery.mjs
  [PASS] Generate 32-byte claim token
  [PASS] SHA-256 hash of token (hex)
  [PASS] Token uniqueness across 100 tokens
  [PASS] Recipient email verification simulation
  [PASS] Token expiration simulation (30 days)
  [PASS] Token revocation simulation
  [PASS] Max redemptions enforcement simulation
  [PASS] TRIGGERED-only access check simulation
  [PASS] File metadata assembly simulation
  [PASS] Signed URL lifecycle simulation
  10/10 tests passed

Running: scripts/test_batch3_security.mjs
  [PASS] AES-256-GCM encryption/decryption roundtrip
  [PASS] PBKDF2 key derivation (100k iterations)
  [PASS] AES-KW DEK wrap/unwrap roundtrip
  [PASS] Wrong password fails DEK unwrap
  [PASS] SHA-256 token hash
  [PASS] File hash integrity check
  [PASS] Dual DEK wrapping (owner + recipient)
  7/7 tests passed

EXIT CODE: 0
Total: 27/27 passed
```

**`npm run typecheck`**
```
tsc --noEmit
EXIT CODE: 0
Zero TypeScript errors
```

**`npm run build`**
```
✓ Compiled successfully
Route (app) | Size | First Load JS
├── / | 4.2 kB | 102 kB
├── /dashboard | 8.1 kB | 156 kB
├── /dashboard/create | 12.4 kB | 171 kB
├── /dashboard/settings | 3.8 kB | 112 kB
├── /claim | 7.2 kB | 148 kB
...
EXIT CODE: 0
12 static/dynamic routes generated
```

### Test Quality Assessment

| Test File | Type | Live DB? | Assessment |
|---|---|---|---|
| `test_delete_switch.mjs` | In-memory simulation | No | Tests logic only, not actual DB trigger/RLS |
| `test_batch4_delivery.mjs` | Crypto + simulation | No | Crypto tests valid; delivery tests are mock state machines |
| `test_batch3_security.mjs` | Crypto unit tests | No | Genuine crypto validation; correct and meaningful |

**All 27 tests are mocked or in-memory.** None make network requests. None test against the actual Supabase instance.

---

## 8. Missing Environment Configuration

| Variable | Required | Present in `.env.local` | Impact if Missing |
|---|---|---|---|
| `NEXT_PUBLIC_SUPABASE_URL` | Yes | ✅ Present | — |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Yes | ✅ Present | — |
| `RESEND_API_KEY` | Yes | ❌ Missing | All email notifications silently fail (PENDING_CONFIG) |
| `CRON_SECRET` / `CRON_DISPATCH_KEY` | Recommended | ❌ Missing | Dispatch endpoint unprotected (no auth required) |
| `NEXT_PUBLIC_APP_URL` | Yes | ❌ Missing | Email claim links may be relative URLs |
| `SUPABASE_SERVICE_ROLE_KEY` | Optional | ❌ Not present | Not used in code; not required |

No `.env.example` file exists in the project.

---

## 9. Pending End-to-End Tests

None of the following E2E tests exist. All require browser automation (Playwright / Cypress / Puppeteer):

| # | Test Scenario | Priority |
|---|---|---|
| 1 | User registration and email confirmation | High |
| 2 | User login and dashboard access | High |
| 3 | Switch creation with file upload and encryption | Critical |
| 4 | Scheduled check-in resets timer | High |
| 5 | Automatic triggering via pg_cron (time mock or manual RPC call) | Critical |
| 6 | File upload and AES-256-GCM encryption verification | Critical |
| 7 | Recipient authorization and claim link flow | Critical |
| 8 | File download and client-side decryption | Critical |
| 9 | Token expiration and revocation rejection | High |
| 10 | Secure switch deletion for CANCELLED/TRIGGERED status | High |

---

## 10. Critical Blockers

| Priority | Blocker | Impact |
|---|---|---|
| P0 | `RESEND_API_KEY` not configured | Email notifications never sent; app's core value proposition non-functional |
| P0 | No automatic notification dispatch job | Even with Resend configured, notifications queue indefinitely |
| P1 | `key_material` stored plaintext in DB | All recipient decryption passphrases exposed if DB is compromised |
| P1 | Migration history out of sync | Fresh deployment would have broken schema; batch4 and delete migrations not in migration table |
| P2 | No end-to-end tests | Full workflow correctness is unverified in a real browser/network environment |
| P2 | PAUSED status not implemented | Enum value is a dead end; no way to pause/resume switches |
| P3 | No `.env.example` | Deployment documentation gap |
| P3 | No rate limiting on claim endpoint | Enumeration attack surface (low practical risk due to 256-bit hashes, but best practice) |

---

## 11. Recommended Fixes (Priority Order)

### Immediate (P0 — Operational Blockers)

1. **Configure `RESEND_API_KEY`**: Add to `.env.local` and document in `.env.example`. Verify sender domain in Resend dashboard. Test with a real triggered switch.

2. **Add notification dispatch scheduling**: Either add a pg_cron job (`SELECT net.http_post(...)` to call `/api/notifications/dispatch`) or configure a Vercel cron job in `vercel.json`. Protect the endpoint with `CRON_SECRET`.

3. **Set `NEXT_PUBLIC_APP_URL`**: Required for full claim URLs in notification emails.

### High Priority (P1 — Security)

4. **Fix `key_material` storage**: Replace plaintext `key_material` storage with one of:
   - Have the recipient derive the KEK from something only they know (e.g., their own passphrase typed at claim time).
   - Encrypt `key_material` with a server-side symmetric key stored in environment variables (not the DB).
   - Remove `key_material` from the DB entirely and use a separate key-distribution channel.

5. **Apply missing migrations via CLI**: Re-apply batch4 and delete migrations via `supabase migration repair` or re-run them, then confirm they appear in `supabase_migrations`. Commit the corrected migration state.

### Medium Priority (P2)

6. **Add rate limiting to `/api/claim`**: Use Upstash Redis + `@upstash/ratelimit`, or Vercel's built-in rate limit header, to limit claim attempts per IP.

7. **Set Supabase storage bucket file size limit**: Set `file_size_limit: 26214400` (25MB in bytes) on `dead-man-files` bucket.

8. **Implement PAUSED status**: Add `pause_switch()` and `resume_switch()` RPCs, frontend toggle button on switch detail page, and exclude PAUSED switches from `process_switch_expirations` expiration logic.

9. **Restrict `claim_queued_notifications` EXECUTE permission**: REVOKE from `anon` and `authenticated` roles; GRANT only to `service_role` or a dedicated internal role.

### Low Priority (P3)

10. **Create `.env.example`**: Document all required and optional environment variables.

11. **Add end-to-end tests**: Set up Playwright with test Supabase environment. Implement all 10 E2E scenarios from §9.

12. **Add CI/CD pipeline**: GitHub Actions workflow for lint, typecheck, build, unit tests, and (eventually) E2E tests on PR.

13. **Remove `src/lib/mockData.ts`**: Delete dead code.

14. **Add MFA support**: Integrate Supabase TOTP MFA for accounts protecting sensitive payloads.

---

## 12. Final Verdict

> **Feature complete, testing pending — but with critical operational blockers.**

The application is architecturally sound and functionally complete for its core security-sensitive operations (encryption, DB-enforced access control, lifecycle automation). The pg_cron job is live. RLS is comprehensive. The encryption pipeline is correctly implemented.

However, **the application cannot fulfill its primary purpose** (notifying recipients when a switch triggers) because email delivery is not configured. Additionally, the `key_material` plaintext storage represents a significant security design issue that should be resolved before any production deployment.

The project is **not production-ready** until at minimum:
1. `RESEND_API_KEY` is configured and notification dispatch is scheduled.
2. The `key_material` plaintext storage issue is resolved.
3. Missing migrations are re-applied and tracked correctly.
4. At least basic integration tests (not mocked) verify the complete trigger-to-claim flow.

---

*This report was generated from a read-only audit. No code, database, or environment changes were made during the audit process.*
