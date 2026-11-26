# DESIGN B FINAL ARCHITECTURAL SPECIFICATION & AUDIT (v3.1)
## Zero-Knowledge Owner Vault, Keyed-HMAC Claim Protocol & Hardened Lifecycle

**Document Version:** 3.1.0  
**Status:** PLANNING ONLY — NO CODE, DATABASE, MIGRATION, OR ENVIRONMENT MUTATIONS  
**Date:** 2026-11-04  
**Project:** DEAD MAN SWITCH (`c:\Users\ASUS\Desktop\DEAD MAN BRO`)  

---

## 1. Executive Summary & Explicit Security Boundary

### 1.1 Scope & Purpose
This document provides the definitive, production-grade architectural specification for **Design B (v3.1)**. It addresses all feedback from technical audits, eliminating baseline security defects, resolving cryptographic vulnerabilities, establishing a robust token state machine, and defining precise operational safety boundaries.

### 1.2 Explicit Threat Model & Security Boundary

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
│ ✓ Replay Attacks & Concurrent Claims: Database row-level locks and     │
│   single-use OTP semantics prevent duplicate redemptions.              │
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
│   can capture decrypted keys during claim execution.                   │
│ ✗ Client-Side Malware / Rogue Browser Extensions: An attacker with DOM │
│   or JavaScript execution rights in the browser can exfiltrate keys     │
│   from WebCrypto memory while a session is active.                     │
└────────────────────────────────────────────────────────────────────────┘
```

> **Fundamental Principle:** Client-side file encryption paired with server-side envelope encryption provides defense-in-depth against data-layer and storage-layer breaches. It **does not and cannot** provide full zero-knowledge confidentiality against compromise of the active application server executing the API.

---

## 2. Owner Vault Key Hierarchy & Unification (Item 1)

### 2.1 The Problem in Baseline Code
The baseline codebase repeatedly calls `deriveKEK(user.id, 'owner-vault-salt')`. Because `user.id` is a public UUID and the salt is static, anyone with database access can derive the owner KEK with zero secret knowledge.

### 2.2 Unified Master Vault Key (MVK) Architecture
To guarantee zero-knowledge owner privacy, the owner vault uses a single, random 256-bit **Master Vault Key (MVK)** that is never stored in plaintext. Both the owner's **Master Passphrase** and the **24-word Recovery Code** independently unlock this same MVK.

```
                  ┌───────────────────────────────┐
                  │ 256-bit CSPRNG Entropy (MVK)  │
                  │   Master Vault Key (Root)     │
                  └──────────────┬────────────────┘
                                 │
         ┌───────────────────────┴───────────────────────┐
         ▼                                               ▼
┌───────────────────────────────┐               ┌───────────────────────────────┐
│ Wrapped with Passphrase KEK   │               │ Wrapped with Recovery KEK     │
│ (vault_key_envelope_primary)  │               │ (vault_key_envelope_recovery) │
└───────────────────────────────┘               └───────────────────────────────┘
         ▲                                               ▲
         │ AES-KW / AES-GCM                              │ AES-KW / AES-GCM
┌───────────────────────────────┐               ┌───────────────────────────────┐
│ Passphrase KEK                │               │ Recovery KEK                  │
│ PBKDF2-SHA512 (600,000 iter)  │               │ PBKDF2-SHA512 (600,000 iter)  │
│ + random passphrase_salt      │               │ + random recovery_salt        │
└───────────────────────────────┘               └───────────────────────────────┘
         ▲                                               ▲
         │                                               │
┌───────────────────────────────┐               ┌───────────────────────────────┐
│ Owner Master Passphrase       │               │ 24-Word Recovery Code         │
│ (User memory only)            │               │ (256 bits CSPRNG entropy)     │
└───────────────────────────────┘               └───────────────────────────────┘
```

### 2.3 What the MVK Protects
Once unlocked into WebCrypto session memory (non-extractable `CryptoKey`), the **MVK** directly protects two distinct cryptographic branches:

1. **Owner-Side File DEKs (`encrypted_dek_owner`):**
   - When a file is uploaded, a random 256-bit AES-GCM Data Encryption Key (DEK) is generated to encrypt the file.
   - The DEK is wrapped using the MVK: `encrypted_dek_owner = wrapDEK(dek, MVK)`.
   - When the owner previews or downloads their own file, the browser unwraps the DEK using the MVK.
2. **Recipient Delivery Token (`encrypted_token_owner`):**
   - When a switch is created or rotated, a 32-byte random delivery token (`rawToken`) is generated.
   - The `rawToken` is wrapped using the MVK: `encrypted_token_owner = wrapDEK(rawToken, MVK)`.
   - **Post-Creation Uploads:** When the owner uploads new files to an existing switch, the browser unwraps `rawToken` using the MVK, derives `recipientKek = deriveKEK(rawToken, 'recipient-claim-salt')`, and wraps the new file's DEK for the recipient without requiring server interaction or plaintext database lookups.

### 2.4 Passphrase Change vs. Recovery Flows
- **Passphrase Change:** With the session unlocked (MVK in memory), user supplies a new passphrase. The browser generates a fresh random `passphrase_salt`, derives a new `passphrase_kek`, wraps the existing MVK, and updates `vault_key_envelope_primary`. File DEKs and recipient tokens remain unchanged.
- **Lost Passphrase Recovery:** User inputs the 24-word recovery code. The browser derives `recovery_kek`, unwraps MVK from `vault_key_envelope_recovery`, prompts for a new passphrase, re-wraps MVK into a new `vault_key_envelope_primary`, and restores full access.

---

## 3. Recovery-Code Entropy & Canonical Encoding (Item 2)

### 3.1 Strict Entropy Definition
A 24-word mnemonic does not automatically guarantee high entropy if improperly sourced. The recovery code specification requires:
- **Entropy Source:** Exactly 256 bits (32 bytes) of CSPRNG entropy generated via `crypto.getRandomValues(new Uint8Array(32))`.
- **Wordlist:** The standard English BIP-39 wordlist (2,048 distinct words, exactly 11 bits per word).
- **Checksum:** 8 bits derived from `SHA-256(entropy)[0..7]`.
- **Total Bits:** $256 + 8 = 264\text{ bits} = 24 \times 11\text{ bits} = 24\text{ words}$.

### 3.2 Canonical Formatting & Normalization
To prevent validation failures due to whitespace or case discrepancies:
1. Words are lowercased and trimmed.
2. Whitespace is collapsed to single ASCII spaces.
3. Checksum verification is executed client-side before any key derivation:
   ```typescript
   export function validateAndNormalizeRecoveryWords(mnemonic: string): Uint8Array {
     const words = mnemonic.trim().toLowerCase().split(/\s+/);
     if (words.length !== 24) throw new Error('Recovery code must be exactly 24 words.');
     // Validate each word against BIP-39 English dictionary
     // Verify 8-bit checksum against the first 256 bits of entropy
     // Return 32-byte entropy buffer
   }
   ```
4. **Acceptance Criteria:** A recovery code with less than 256 bits of CSPRNG entropy or an invalid checksum must be rejected at input validation.

---

## 4. Keyed-HMAC Recipient Email Verification Protocol (Item 3)

### 4.1 Vulnerability of Plain SHA-256 OTP Storage
A 6-digit numeric OTP has only $10^6$ ($900,000$ valid 6-digit) possibilities. If stored as `SHA-256(otp)` in PostgreSQL, an attacker with read access to the database can compute all 900,000 hashes in under 15 milliseconds on a consumer CPU, trivializing inbox verification.

### 4.2 Keyed-HMAC Challenge Storage Specification
All OTP challenges are authenticated using a high-entropy server secret `APP_OTP_SECRET` (256-bit key from environment variables):

```
Server-Side Storage:
hmac_digest = HMAC-SHA256(APP_OTP_SECRET, otp || ":" || grant_id || ":" || recipient_email)
```
- Without `APP_OTP_SECRET`, an attacker possessing a database dump cannot brute-force or verify OTP values.

### 4.3 Challenge Protocol Lifecycle & State Machine
The challenge flow is managed in `public.claim_challenges`:

```sql
CREATE TABLE public.claim_challenges (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    grant_id uuid NOT NULL REFERENCES public.recipient_claim_tokens(id) ON DELETE CASCADE,
    recipient_email text NOT NULL,
    hmac_digest text NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 3,
    expires_at timestamptz NOT NULL,
    redeemed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
```

| Parameter | Specification | Purpose |
|---|---|---|
| **Challenge Expiry** | 10 minutes (`clock_timestamp() + INTERVAL '10 minutes'`) | Limits intercept window. |
| **Max Attempts** | 3 attempts | Prevents online brute-force ($3 / 900,000 = 0.00033\%$ probability). |
| **Single-Use** | Atomic row update sets `redeemed_at = NOW()` immediately upon verification | Prevents OTP replay. |
| **Rate Limiting** | Max 3 challenge creations per 15 minutes per `grant_id` and IP | Prevents email bombarding / spam. |
| **Lockout** | On 3rd failed verification attempt, challenge is invalidated and `grant_id` is locked for 1 hour | Halts automated attacks. |

### 4.4 Resend Delivery Failure & Resilience Protocol
If the email delivery provider (Resend) fails or is unconfigured:
1. `POST /api/claim/challenge` executes in an atomic transaction: the challenge row is rolled back if `resend.emails.send()` throws or returns an error status.
2. The endpoint returns `503 Service Unavailable`:
   ```json
   { "error": "Emergency notification service is temporarily unavailable. Please retry in 2 minutes." }
   ```
3. An audit log event `NOTIFICATION_DISPATCH_FAILED` is recorded with error diagnostics (without leaking recipient tokens).
4. No half-open challenge rows remain in the database.

---

## 5. Token Lifecycle Semantics & Database Consistency (Item 4)

### 5.1 Token Lifecycle States
A recipient delivery grant progresses through well-defined, mutually exclusive lifecycle states:

```
                  ┌──────────────┐
                  │    ACTIVE    │
                  └──────┬───────┘
                         │
         ┌───────────────┼───────────────┬───────────────┐
         ▼               ▼               ▼               ▼
  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
  │   EXPIRED   │ │   LOCKED    │ │   REVOKED   │ │  REDEEMED   │
  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
```

| State | Formal Condition | Inbound Claim Allowed? | Transition Triggers |
|---|---|:---:|---|
| **ACTIVE** | `revoked_at IS NULL` AND `redeemed_at IS NULL` AND `locked_at IS NULL` AND `expires_at > NOW()` | **YES** | Initial creation, rotation replacement. |
| **EXPIRED** | `expires_at <= NOW()` AND `revoked_at IS NULL` AND `redeemed_at IS NULL` | **NO** | Wall-clock time exceeds `expires_at` (365 days after creation). |
| **LOCKED** | `locked_at IS NOT NULL` AND `revoked_at IS NULL` | **NO** | 3 failed OTP attempts (1-hour backoff) or manual admin lock. |
| **REVOKED** | `revoked_at IS NOT NULL` | **NO** | Switch cancelled, token rotated, or switch deleted. |
| **REDEEMED** | `redeemed_at IS NOT NULL` AND `redemption_count >= max_redemptions` | **NO** | Recipient consumed allocated redemptions (default 10). |

### 5.2 Partial Unique Index & Index Agreement
To guarantee that **never more than one active delivery grant exists** per recipient while handling historical, locked, or expired rows correctly:

#### PostgreSQL Indexing Constraint
In PostgreSQL, partial index predicates must be `IMMUTABLE`. Functions such as `NOW()` or `clock_timestamp()` cannot be used in a `WHERE` clause. Therefore, the partial unique index governs structural validity (`revoked_at`, `redeemed_at`, `locked_at`), while temporal validity (`expires_at`) is strictly evaluated by atomic RPCs.

```sql
CREATE UNIQUE INDEX idx_single_active_grant_per_recipient
ON public.recipient_claim_tokens (switch_id, recipient_id)
WHERE revoked_at IS NULL AND redeemed_at IS NULL AND locked_at IS NULL;
```

#### RPC Synchronization Guarantee
The atomic creation RPC `provision_claim_grant_atomic()` explicitly sets `revoked_at = clock_timestamp()` on all rows matching `(switch_id, recipient_id)` where `revoked_at IS NULL AND redeemed_at IS NULL AND locked_at IS NULL` **before** inserting the new row. This guarantees the partial index is never violated.

---

## 6. Safe Token Rotation with Staged Verification & Rollback (Item 6)

### 6.1 The Failure Risk
If an owner initiates token rotation and the system revokes the active grant before verifying that all payload file DEKs have been successfully re-wrapped for the new grant, a network or database error leaves files **permanently un-decryptable** by the recipient.

### 6.2 The Staged 4-Phase Rotation Protocol

```mermaid
sequenceDiagram
    autonumber
    participant Client as Owner Browser
    participant API as Next.js API (/api/switches/provision-token)
    participant DB as PostgreSQL Database

    Note over Client,DB: PHASE 1: CLIENT PREPARATION
    Client->>Client: Generate new rawToken (32 bytes CSPRNG)
    Client->>Client: Derive newRecipientKek = deriveKEK(rawToken, 'recipient-claim-salt')
    Client->>Client: For each file: Unwrap DEK using MVK, Re-wrap with newRecipientKek
    Client->>Client: Wrap rawToken using MVK -> encryptedTokenOwner

    Note over Client,DB: PHASE 2: ATOMIC PROVISION (STAGED)
    Client->>API: POST /api/switches/provision-token { switchId, recipientId, rawToken, fileDeks: [...] }
    API->>API: Server envelope encryption of rawToken -> encrypted_key_material
    API->>DB: RPC execute_staged_token_rotation(...)
    DB->>DB: Begin Transaction
    DB->>DB: Verify switch ownership & status = ACTIVE
    DB->>DB: Update all files.encrypted_dek_recipient with new wrapped DEKs
    DB->>DB: Verify update count matches total switch files exactly
    DB->>DB: Mark prior active token revoked_at = NOW()
    DB->>DB: Insert new token row with encrypted_key_material & encrypted_token_owner
    DB->>DB: Commit Transaction

    Note over Client,DB: PHASE 3: VERIFICATION OR ROLLBACK
    alt Any Database or Network Step Fails
        DB-->>API: Error / Rollback
        API-->>Client: 500 Rotation Failed
        Client->>Client: Old token remains active; file DEKs untouched in DB
    else Success
        DB-->>API: 200 OK { tokenId }
        API-->>Client: 200 OK
        Client->>Client: Confirm rotation in UI; wipe rawToken from memory
    end
```

### 6.3 Rollback Guarantees
- If updating `encrypted_dek_recipient` fails on file 4 of 5, the entire SQL transaction rolls back.
- The prior token row is **not** revoked.
- The recipient can still decrypt all existing files using their existing delivery grant.

---

## 7. Memory Hygiene & Operational Reality (Item 5)

### 7.1 Best-Effort Buffer Hygiene vs. Guaranteed Erasure
In managed runtimes such as Node.js (V8 engine) and browser engines (Blink/V8, Gecko, WebKit):
- **String Immutability:** Strings cannot be overwritten in place; allocating a string creates an immutable heap object that persists until garbage collection.
- **Heap Compaction & Moving Collectors:** V8 frequently relocates objects in memory during generational garbage collection, leaving orphaned copies in unallocated heap memory.
- **JIT & Register Spills:** Optimizing compilers (Turbofan) may copy cryptographic values into CPU registers or stack frames.

> **Operational Clarification:** Overwriting `Buffer` instances via `buf.fill(0)` is **best-effort memory hygiene** to minimize the window of exposure in process heap dumps. It **does not guarantee immediate physical memory erasure**.

### 7.2 Actionable Log, Error & Crash Dump Hardening
To prevent accidental key leakage across operational surfaces:

1. **Structured Exception Scrubbing:**
   - Error handlers in `src/lib/server/crypto.ts` and API routes must catch exceptions and throw standardized domain errors (`CryptoOperationError`) with zero payload reflection:
     ```typescript
     try {
       // crypto operations
     } catch (err) {
       // NEVER log err.message if it might contain inspected buffers
       console.error('[CRYPTO_ERROR] Decryption failure occurred on grant envelope.');
       throw new Error('Cryptographic processing failed.');
     }
     ```
2. **HTTP Payload Scrubbing in Middleware:**
   - Logging middleware must explicitly exclude `rawToken`, `passphrase`, `otp`, `encrypted_key_material`, and `Authorization` headers from request logging.
3. **Core Dump Suppression:**
   - Production Docker / server environments must enforce `ulimit -c 0` and configure Node.js with `--no-warnings` to prevent core dumps on unhandled process panics.

---

## 8. Comprehensive Acceptance Criteria Matrix

| Item | Requirement Area | Strict Acceptance Criteria |
|:---:|---|---|
| **AC-01** | Owner Vault Hierarchy | `deriveKEK(user.id, ...)` is completely removed from all source files. Owner MVK is 256-bit CSPRNG, unlocked via passphrase or recovery code. |
| **AC-02** | Recovery Code Entropy | Recovery code generation asserts exactly 256 bits of CSPRNG entropy, validated against the 2,048-word BIP-39 English dictionary with an 8-bit SHA-256 checksum (24 words). |
| **AC-03** | Keyed-HMAC OTP | `claim_challenges` stores `HMAC-SHA256(APP_OTP_SECRET, ...)`. Plain SHA-256 OTP storage is strictly prohibited. Max 3 attempts, 10-minute expiry, single-use enforcement. |
| **AC-04** | Resend Resilience | If email dispatch returns 5xx or fails, the challenge transaction rolls back cleanly, returning HTTP 503 without residual database rows. |
| **AC-05** | Token Lifecycle & Partial Index | `idx_single_active_grant_per_recipient` enforces uniqueness on `(switch_id, recipient_id)` for active rows. State transitions for `ACTIVE`, `EXPIRED`, `LOCKED`, `REVOKED`, `REDEEMED` are strictly enforced by RPCs. |
| **AC-06** | Staged Rotation & Rollback | Token rotation updates file DEKs and swaps token rows inside a single atomic transaction. Any failure preserves the prior active grant and original file DEKs. |
| **AC-07** | Memory & Logging Hygiene | `buf.fill(0)` executed on all temporary server buffers. Exceptions sanitized. Core dumps disabled. Logging middleware strips sensitive fields. |
| **AC-08** | Security Boundary Acknowledgment | Documentation clearly affirms that client-side encryption does not defend against active Next.js application server compromise. |

---

## 9. Unresolved Residual Risks (Transparent Risk Acceptance)

The following risks are inherent to the selected architecture and are explicitly documented rather than silently assumed to be resolved:

1. **Application Server Custody of `APP_ENCRYPTION_KEY` and `APP_OTP_SECRET`:**
   - If an adversary achieves root-level compromise or code execution on the Next.js runtime host, they can intercept recipient keys during the `/api/claim` redemption window.
   - *Alternative Considered:* Full client-to-client asymmetric key exchange (Design A). *Reason Rejected:* Requires out-of-band pre-registration and public key exchange by recipients, conflicting with zero-friction emergency delivery requirements.
2. **Third-Party Email Relay Vulnerability (Resend):**
   - The security of recipient inbox verification relies on the security of DNS MX records, SMTP TLS transit, and the Resend API infrastructure. Compromise of the recipient's mail provider allows OTP interception.
3. **Owner Passphrase Irrecoverability:**
   - If the switch owner loses both their master passphrase and their 24-word recovery sheet, their personal access to files is unrecoverable. (Recipient delivery remains intact via `encrypted_key_material`).
4. **Cloud Managed Database WAL Retention:**
   - Historical WAL archives in Supabase managed cloud infrastructure retain deleted rows until the Point-in-Time Recovery (PITR) window (typically 7 to 30 days) expires. Physical erasure of legacy plaintext rows occurs only after WAL recycling.

---

> **Plan Status:** Version 3.1.0 Complete. Saved to `DESIGN_B_FINAL_REVIEW_v3.1.md`.  
> **Strict Confirmation:** This document represents planning only. **NO** source code, migrations, database records, environment variables, or deployment settings were modified. Awaiting explicit user approval before proceeding to implementation.
