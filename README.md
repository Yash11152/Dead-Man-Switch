# DEAD MAN SWITCH

A zero-knowledge, cryptographically secure Dead Man's Switch web application built with **Next.js 14 (App Router)**, **TypeScript**, **Tailwind CSS**, and **Supabase (PostgreSQL + RLS + Storage)**.

The system ensures that confidential files and instructions are securely encrypted and automatically dispatched to designated beneficiaries only if the switch owner fails to check in before the expiration deadline.

---

## 🔒 Security Architecture & Cryptographic Design

The application implements a multi-tier envelope encryption and defense-in-depth security model:

1. **Client-Side Zero-Knowledge Encryption**:
   - Files are encrypted in the owner's browser using AES-256-GCM.
   - Data Encryption Keys (DEKs) are generated client-side with CSPRNG (`crypto.getRandomValues`).
   - The server never receives or stores plaintext DEKs or unencrypted file contents.

2. **Dual-Key Wrapping Envelope**:
   - The DEK is wrapped using an owner Key Encryption Key (KEK) derived via PBKDF2 (100,000 iterations of SHA-256).
   - An independent recipient token is generated per beneficiary, with the DEK wrapped under a recipient KEK.

3. **Server-Side Envelope Encryption**:
   - Key material stored in Supabase is encrypted at rest using server-side AES-256-GCM (`APP_ENCRYPTION_KEY_PRIMARY`).
   - Supports seamless key rotation via the `APP_ENCRYPTION_KEYS` keyring.

4. **Claim Challenge & OTP Verification**:
   - Recipient claim links require an out-of-band verification challenge with HMAC-SHA256 signed OTPs (`APP_OTP_SECRET_PRIMARY`).
   - Built-in rate limiting, 3-attempt lockouts, and single-use challenge verification prevent brute-force attacks.

5. **Row Level Security (RLS) & Strict Access Control**:
   - Postgres RLS guarantees tenant isolation: users can only inspect, modify, or delete their own switches.
   - Deletion is restricted to `CANCELLED` or `TRIGGERED` states; active or grace-period switches cannot be deleted.
   - Recipient files are stored in private Supabase Storage buckets, accessed only via short-lived signed URLs.

6. **Automated Trigger & Notification Engine**:
   - Scheduled cron dispatch via authenticated `/api/notifications/dispatch` with `CRON_SECRET`.
   - Transactional notification delivery powered by Resend with idempotent delivery guards.

---

## 🛠️ Tech Stack

- **Framework**: [Next.js 14 (App Router)](https://nextjs.org/)
- **Language**: [TypeScript 5](https://www.typescriptlang.org/)
- **Styling**: [Tailwind CSS](https://tailwindcss.com/)
- **Database & Auth**: [Supabase](https://supabase.com/) (PostgreSQL 15, Auth, RLS, Storage)
- **Email Service**: [Resend](https://resend.com/)
- **Icons**: [Lucide React](https://lucide.dev/)

---

## 🚀 Getting Started

### Prerequisites

- **Node.js**: v18.17+ (v20+ or v22 LTS recommended)
- **npm**: v9+
- A [Supabase](https://supabase.com) project with database and storage enabled.
- A [Resend](https://resend.com) account (for transactional email dispatch).

### 1. Clone & Install

```bash
git clone https://github.com/<your-username>/dead-man-switch.git
cd dead-man-switch
npm install
```

### 2. Configure Environment Variables

Copy the example environment configuration:

```bash
cp .env.example .env.local
```

Edit `.env.local` and configure your credentials:

```ini
# Supabase Configuration
NEXT_PUBLIC_SUPABASE_URL=https://<your-project-ref>.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Server-Side Envelope Encryption (AES-256-GCM)
# Format: <kid>:<64-hex-characters>
# Generate: openssl rand -hex 4 (for kid), openssl rand -hex 32 (for key)
APP_ENCRYPTION_KEY_PRIMARY=v1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# OTP Challenge HMAC Signing
# Format: <kid>:<64-hex-characters>
APP_OTP_SECRET_PRIMARY=otp1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Email Notification Delivery (Resend)
RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
RESEND_FROM_EMAIL=notifications@yourdomain.com

# Public Application URL
NEXT_PUBLIC_APP_URL=https://yourdomain.com

# Cron Dispatch Authentication
CRON_SECRET=your-random-32-character-secret
```

> **Warning**: Never commit `.env.local` or any file containing real secret keys to source control.

### 3. Database Setup (Supabase)

Apply the SQL migrations located in `supabase/migrations/` in chronological order to your Supabase SQL editor or via the Supabase CLI:

```bash
supabase db push
```

Key migrations include:
- `20261013_batch2_full_migration.sql` — Core schema, switches, check-ins, notifications
- `20261021_batch3_profiles_audit_tokens.sql` — Profiles, audit logs, recipient claim tokens
- `20261022_batch4_recipient_delivery.sql` — Encrypted token envelopes and delivery
- `20261028_delete_switch_policy_trigger.sql` — Safe cascading delete policies and audit trails
- `20261117_p0_security_permissions_indexes.sql` — Security hardening and indexing
- `20261117_p1_atomic_rotation_and_locking.sql` — Token rotation lease locking
- `20261117_p2_claim_challenges_otp.sql` — OTP challenge tables and validation functions
- `20261117_p3_paused_status_rpc.sql` — Switch pause/resume RPC handlers

### 4. Running Locally

```bash
# Start local development server
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000) to access the application.

---

## 🧪 Testing & Quality Assurance

The codebase features a comprehensive automated test suite covering crypto operations, access control, adversarial scenarios, and lifecycle state machines:

```bash
# Run TypeScript compilation check
npm run typecheck

# Run Next.js code linter
npm run lint

# Run all automated test suites
npm test

# Build for production
npm run build
```

### Test Suite Breakdown

- **Secure Delete Switch Suite** (`scripts/test_delete_switch.mjs`): 10 tests verifying status restrictions, RLS cross-user isolation, cascade deletes, and storage purging.
- **Batch 4 Delivery Suite** (`scripts/test_batch4_delivery.mjs`): 10 tests covering PBKDF2 KEK derivation, AES-256-GCM file encryption, signed URL lifetimes, and tamper protection.
- **Batch 3 Security Suite** (`scripts/test_batch3_security.mjs`): 7 tests verifying token hashing, dual-wrapping envelopes, and backward compatibility.
- **Server Crypto Suite** (`scripts/test_server_crypto.mjs`): 5 tests validating AES-256-GCM server envelope encryption, HMAC-SHA256 OTP verification, and RFC 8785 canonical JSON formatting.
- **P0-P4 Adversarial Suite** (`scripts/test_p0_p4_comprehensive.mjs`): 6 tests verifying concurrent rotation locks, OTP single-use replay protection, lockout lifecycle, and pre/post migration byte fidelity.

---

## 📁 Repository Structure

```
DEAD MAN SWITCH/
├── .env.example             # Sanitized environment variable template
├── .eslintrc.json           # ESLint configuration
├── .gitignore               # Strict source control ignore patterns
├── README.md                # Project documentation & setup guide
├── package.json             # Dependencies and scripts
├── tsconfig.json            # TypeScript configuration
├── scripts/                 # Cryptographic verification & integration test suites
│   ├── serverCrypto.mjs
│   ├── migrate_key_material.mjs
│   ├── test_delete_switch.mjs
│   ├── test_batch4_delivery.mjs
│   ├── test_batch3_security.mjs
│   ├── test_server_crypto.mjs
│   ├── test_p0_p4_comprehensive.mjs
│   └── test_supabase_integration.mjs
├── src/
│   ├── app/                 # Next.js App Router pages and API routes
│   │   ├── (auth)/          # Login & registration
│   │   ├── api/claim/       # Recipient claim verification route
│   │   ├── api/notifications/dispatch/ # Cron notification worker
│   │   ├── claim/           # Recipient portal
│   │   └── dashboard/       # Switch owner management dashboard
│   ├── components/          # Reusable UI components
│   ├── context/             # React authentication context
│   ├── lib/                 # Core utilities (crypto, serverCrypto, supabase)
│   └── types/               # TypeScript interfaces and definitions
└── supabase/
    └── migrations/          # Versioned PostgreSQL database migrations
```

---

## 🛡️ DevSecOps & Deployment Checklist

Before deploying or pushing to GitHub:

1. **Secrets Isolation**: Confirm `.env.local` is never committed. Only `.env.example` belongs in source control.
2. **Key Generation**: Generate high-entropy keys for `APP_ENCRYPTION_KEY_PRIMARY` and `APP_OTP_SECRET_PRIMARY` in your production hosting platform (e.g., Vercel / Cloudflare).
3. **Cron Protection**: Ensure `CRON_SECRET` is set in both the dispatch scheduler (Vercel Cron / GitHub Actions) and environment variables.
4. **Storage Policies**: Ensure the Supabase Storage bucket for encrypted files is set to **Private** and accessed solely via server-generated signed URLs.
5. **Database RLS**: Verify that Row Level Security is enabled on all tables in Supabase.

---

## 📄 License

This project is licensed under the MIT License.
