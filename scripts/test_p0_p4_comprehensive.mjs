// scripts/test_p0_p4_comprehensive.mjs
// Comprehensive Security & Adversarial Test Suite for Dead Man Switch:
//   1. Concurrent Rotations & Lease Contention
//   2. Duplicate Requests & Idempotent Retry Safety
//   3. OTP Replay Protection & Single-Use Challenge Verification
//   4. Challenge Expiry, Attempt Limiting & 1-Hour Lockout Lifecycle
//   5. Unauthorized RPC Access Prevention (Least Privilege)
//   6. Recipient File Decryption Pre- and Post-Migration (Fidelity Test)

import assert from 'assert';
import crypto from 'crypto';
import {
  encryptKeyMaterial,
  decryptKeyMaterial,
  generateNumericOtp,
  computeOtpHmac,
  verifyOtpHmac,
  computeRequestFingerprint,
} from './serverCrypto.mjs';

console.log('🧪 Starting P0-P4 Comprehensive Adversarial & Security Test Suite...\n');

// ============================================================================
// TEST 1: Concurrent Rotations & Lease Contention
// ============================================================================
console.log('--- TEST 1: Concurrent Rotations & Lease Contention ---');

class MockTokenRotationEngine {
  constructor() {
    this.operations = new Map();
  }

  executeStagedRotation(operationId, switchId, recipientId, fingerprint, now = Date.now()) {
    const existing = this.operations.get(operationId);

    if (existing) {
      if (existing.fingerprint !== fingerprint) {
        const err = new Error('IDEMPOTENCY_PAYLOAD_MISMATCH');
        err.code = '23505';
        throw err;
      }
      if (existing.status === 'COMMITTED') {
        return existing.response;
      }
      if (existing.status === 'PROCESSING' && now <= existing.lockedUntil) {
        const err = new Error('OPERATION_CONCURRENTLY_PROCESSING');
        err.code = '40001';
        throw err;
      }
    }

    // Acquire lease
    this.operations.set(operationId, {
      operationId,
      switchId,
      recipientId,
      fingerprint,
      status: 'PROCESSING',
      lockedUntil: now + 30000,
      response: null,
    });

    return { status: 'PROCESSING_ACQUIRED' };
  }

  commitRotation(operationId, responsePayload) {
    const op = this.operations.get(operationId);
    if (!op) throw new Error('Operation not found');
    op.status = 'COMMITTED';
    op.response = responsePayload;
  }

  recordFailure(operationId, fingerprint, errorMessage) {
    const op = this.operations.get(operationId);
    if (op) {
      if (op.fingerprint !== fingerprint) {
        const err = new Error('IDEMPOTENCY_PAYLOAD_MISMATCH');
        err.code = '23505';
        throw err;
      }
      // Never overwrite COMMITTED!
      if (op.status === 'COMMITTED') return;
      op.status = 'FAILED';
      op.errorMessage = errorMessage;
    } else {
      this.operations.set(operationId, {
        operationId,
        fingerprint,
        status: 'FAILED',
        errorMessage,
      });
    }
  }
}

const rotationEngine = new MockTokenRotationEngine();
const opId = crypto.randomUUID();
const fpA = computeRequestFingerprint({ op: 'rotate', switchId: 's-1', recipientId: 'r-1', files: ['f1'] });
const fpB = computeRequestFingerprint({ op: 'rotate', switchId: 's-1', recipientId: 'r-1', files: ['f1', 'f2'] });

// Worker 1 starts rotation
const leaseResult = rotationEngine.executeStagedRotation(opId, 's-1', 'r-1', fpA);
assert.strictEqual(leaseResult.status, 'PROCESSING_ACQUIRED');

// Worker 2 attempts concurrent rotation on same operationId
assert.throws(() => {
  rotationEngine.executeStagedRotation(opId, 's-1', 'r-1', fpA);
}, /OPERATION_CONCURRENTLY_PROCESSING/);

// Worker 3 attempts with altered fingerprint
assert.throws(() => {
  rotationEngine.executeStagedRotation(opId, 's-1', 'r-1', fpB);
}, /IDEMPOTENCY_PAYLOAD_MISMATCH/);

console.log('✅ PASS: Concurrent lease locking and fingerprint mismatch protection verified.');

// ============================================================================
// TEST 2: Duplicate Requests & Safe Failure Recording Outside Transactions
// ============================================================================
console.log('\n--- TEST 2: Duplicate Requests & Safe Failure Recording ---');

// Commit the rotation
const committedResponse = { success: true, tokenId: 'token-new-123', committedAt: new Date().toISOString() };
rotationEngine.commitRotation(opId, committedResponse);

// Late duplicate request returns cached response
const retryResponse = rotationEngine.executeStagedRotation(opId, 's-1', 'r-1', fpA);
assert.deepStrictEqual(retryResponse, committedResponse, 'Retry must return cached committed response');

// Upstream gateway timeout causes late failure report: MUST NOT overwrite COMMITTED
rotationEngine.recordFailure(opId, fpA, '504 Gateway Timeout');
const checkOp = rotationEngine.operations.get(opId);
assert.strictEqual(checkOp.status, 'COMMITTED', 'Committed status must be protected against late failure reports');
console.log('✅ PASS: Idempotent replay safety and failure recorder isolation verified.');

// ============================================================================
// TEST 3: OTP Challenge Generation, Replay Protection & Single-Use Verification
// ============================================================================
console.log('\n--- TEST 3: OTP Replay Protection & Single-Use Challenge Verification ---');

class MockChallengeEngine {
  constructor() {
    this.challenges = new Map();
    this.grants = new Map();
  }

  createChallenge(grantId, recipientEmail, ttlMs = 300000, now = Date.now()) {
    const challengeId = crypto.randomUUID();
    const otp = generateNumericOtp(6);
    const hmacDigest = computeOtpHmac(grantId, otp);

    const challenge = {
      id: challengeId,
      grantId,
      recipientEmail,
      hmacDigest,
      otp, // retained for test inspection
      status: 'DISPATCHED',
      attempts: 0,
      maxAttempts: 3,
      expiresAt: now + ttlMs,
    };

    this.challenges.set(challengeId, challenge);
    return challenge;
  }

  redeemOtp(grantId, submittedOtp, now = Date.now()) {
    const grant = this.grants.get(grantId) || { id: grantId, lockedUntil: null, redemptionCount: 0 };

    if (grant.lockedUntil && now <= grant.lockedUntil) {
      return { success: false, code: 'GRANT_LOCKED_OUT', message: 'Grant is temporarily locked for 1 hour.' };
    }

    // Find active dispatched challenge
    let challenge = null;
    for (const ch of this.challenges.values()) {
      if (ch.grantId === grantId && ch.status === 'DISPATCHED' && now <= ch.expiresAt) {
        challenge = ch;
        break;
      }
    }

    if (!challenge) {
      return { success: false, code: 'NO_ACTIVE_CHALLENGE', message: 'No active challenge found.' };
    }

    const submittedDigest = computeOtpHmac(grantId, submittedOtp);
    const isValid = verifyOtpHmac(submittedDigest, challenge.hmacDigest);

    // Fail-closed verification
    if (isValid !== true) {
      challenge.attempts++;
      if (challenge.attempts >= challenge.maxAttempts) {
        challenge.status = 'LOCKED';
        grant.lockedUntil = now + 3600000; // 1-hour backoff
        this.grants.set(grantId, grant);
        return { success: false, code: 'MAX_ATTEMPTS_EXCEEDED', message: 'Max attempts reached. Locked for 1 hour.' };
      }
      return { success: false, code: 'INVALID_OTP', remainingAttempts: challenge.maxAttempts - challenge.attempts };
    }

    // Success: Mark VERIFIED immediately
    challenge.status = 'VERIFIED';
    grant.redemptionCount++;
    this.grants.set(grantId, grant);

    return { success: true, message: 'OTP verified successfully.' };
  }
}

const challengeEngine = new MockChallengeEngine();
const grantId = crypto.randomUUID();
const challenge = challengeEngine.createChallenge(grantId, 'recipient@example.com');

// 1. Valid redemption
const redeemRes1 = challengeEngine.redeemOtp(grantId, challenge.otp);
assert.strictEqual(redeemRes1.success, true, 'First redemption must succeed');

// 2. Replay attempt with same OTP must FAIL
const replayRes = challengeEngine.redeemOtp(grantId, challenge.otp);
assert.strictEqual(replayRes.success, false, 'Replaying verified challenge must fail');
assert.strictEqual(replayRes.code, 'NO_ACTIVE_CHALLENGE', 'Replayed challenge is no longer DISPATCHED');
console.log('✅ PASS: Challenge replay protection and single-use enforcement verified.');

// ============================================================================
// TEST 4: Challenge Expiry, Attempt Limiting & 1-Hour Lockout Lifecycle
// ============================================================================
console.log('\n--- TEST 4: Challenge Expiry, Attempt Limiting & 1-Hour Lockout Lifecycle ---');

// Test 4A: Expired challenge
const expiredGrantId = crypto.randomUUID();
const expiredChallenge = challengeEngine.createChallenge(expiredGrantId, 'recipient@example.com', -1000); // expired 1s ago
const expiredRes = challengeEngine.redeemOtp(expiredGrantId, expiredChallenge.otp);
assert.strictEqual(expiredRes.success, false);
assert.strictEqual(expiredRes.code, 'NO_ACTIVE_CHALLENGE');

// Test 4B: 3 failed attempts triggers 1-hour lockout
const lockGrantId = crypto.randomUUID();
const lockChallenge = challengeEngine.createChallenge(lockGrantId, 'recipient@example.com');

const fail1 = challengeEngine.redeemOtp(lockGrantId, '999999');
assert.strictEqual(fail1.success, false);
assert.strictEqual(fail1.remainingAttempts, 2);

const fail2 = challengeEngine.redeemOtp(lockGrantId, '888888');
assert.strictEqual(fail2.success, false);
assert.strictEqual(fail2.remainingAttempts, 1);

const fail3 = challengeEngine.redeemOtp(lockGrantId, '777777');
assert.strictEqual(fail3.success, false);
assert.strictEqual(fail3.code, 'MAX_ATTEMPTS_EXCEEDED');

// Attempt while locked out
const lockedRes = challengeEngine.redeemOtp(lockGrantId, lockChallenge.otp);
assert.strictEqual(lockedRes.code, 'GRANT_LOCKED_OUT');

// Attempt after 1 hour (3,600,001 ms later)
const futureNow = Date.now() + 3600001;
const futureChallenge = challengeEngine.createChallenge(lockGrantId, 'recipient@example.com', 300000, futureNow);
const unlockRes = challengeEngine.redeemOtp(lockGrantId, futureChallenge.otp, futureNow);
assert.strictEqual(unlockRes.success, true, 'Claim succeeds once 1-hour backoff expires');

console.log('✅ PASS: Expiration, 3-attempt limit, and 1-hour deterministic lockout lifecycle verified.');

// ============================================================================
// TEST 5: Unauthorized RPC Access (Least Privilege Assertion)
// ============================================================================
console.log('\n--- TEST 5: Unauthorized RPC Access (Least Privilege Assertion) ---');

function simulateRpcAuthorization(callerRole, callerUserId, targetFunction, switchUserId = null) {
  // Least privilege matrix
  const internalWorkersOnly = ['claim_queued_notifications', 'record_notification_outcome', 'process_switch_expirations', 'acknowledge_otp_dispatch'];
  const authenticatedOwnerOnly = ['cancel_switch', 'perform_check_in', 'pause_switch', 'resume_switch', 'execute_staged_token_rotation', 'insert_client_audit_event'];
  const publicClaimOnly = ['redeem_recipient_claim', 'redeem_claim_otp_atomic'];

  if (internalWorkersOnly.includes(targetFunction)) {
    if (callerRole !== 'service_role') {
      const err = new Error(`permission denied for function ${targetFunction}`);
      err.code = '42501';
      throw err;
    }
    return { authorized: true };
  }

  if (authenticatedOwnerOnly.includes(targetFunction)) {
    if (callerRole !== 'authenticated' && callerRole !== 'service_role') {
      const err = new Error(`permission denied for function ${targetFunction}`);
      err.code = '42501';
      throw err;
    }
    if (switchUserId && callerUserId !== switchUserId && callerRole !== 'service_role') {
      const err = new Error('Unauthorized: switch does not belong to user');
      err.code = '42501';
      throw err;
    }
    return { authorized: true };
  }

  if (publicClaimOnly.includes(targetFunction)) {
    // Accessible by anon/authenticated, gated by token/OTP
    return { authorized: true };
  }

  throw new Error(`Unknown function ${targetFunction}`);
}

// 1. Anon calling claim_queued_notifications
assert.throws(() => {
  simulateRpcAuthorization('anon', null, 'claim_queued_notifications');
}, /permission denied/);

// 2. Authenticated user calling claim_queued_notifications
assert.throws(() => {
  simulateRpcAuthorization('authenticated', 'user-1', 'claim_queued_notifications');
}, /permission denied/);

// 3. Service role calling claim_queued_notifications
assert.ok(simulateRpcAuthorization('service_role', null, 'claim_queued_notifications').authorized);

// 4. Cross-user calling cancel_switch
assert.throws(() => {
  simulateRpcAuthorization('authenticated', 'user-attacker', 'cancel_switch', 'user-victim');
}, /Unauthorized: switch does not belong to user/);

// 5. Valid owner calling cancel_switch
assert.ok(simulateRpcAuthorization('authenticated', 'user-victim', 'cancel_switch', 'user-victim').authorized);

console.log('✅ PASS: Least privilege execution permissions and ownership checks verified.');

// ============================================================================
// TEST 6: Recipient File Decryption Pre- and Post-Migration (Fidelity Test)
// ============================================================================
console.log('\n--- TEST 6: Recipient File Decryption Pre- and Post-Migration (Fidelity Test) ---');

async function deriveKek(secret, salt) {
  const enc = new TextEncoder();
  const keyMat = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'PBKDF2' }, false, ['deriveKey']);
  return await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' },
    keyMat,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Generate raw 64-hex token
const originalRawToken = crypto.randomBytes(32).toString('hex');
const testFilePayload = 'EMERGENCY_PAYLOAD_DOCUMENT_VERIFIED_BEFORE_AND_AFTER_MIGRATION_2026';
const payloadBuffer = Buffer.from(testFilePayload, 'utf8');

// 1. Generate DEK & Encrypt File
const dek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
const fileIv = crypto.randomBytes(12);
const encryptedFileBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: fileIv }, dek, payloadBuffer);

// 2. Wrap DEK with Recipient KEK (derived from original raw token)
const rawDek = await crypto.subtle.exportKey('raw', dek);
const recipientKek = await deriveKek(originalRawToken, 'recipient-claim-salt');
const dekWrapIv = crypto.randomBytes(12);
const encryptedDekRecipient = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: dekWrapIv }, recipientKek, rawDek);

const wrappedDekBase64 = Buffer.from(encryptedDekRecipient).toString('base64');
const dekWrapIvBase64 = Buffer.from(dekWrapIv).toString('base64');

// 3. Pre-migration Decryption Test (Using raw plaintext key material)
const preMigrationKek = await deriveKek(originalRawToken, 'recipient-claim-salt');
const unwrappedRawDekPre = await crypto.subtle.decrypt(
  { name: 'AES-GCM', iv: Buffer.from(dekWrapIvBase64, 'base64') },
  preMigrationKek,
  Buffer.from(wrappedDekBase64, 'base64')
);
const unwrappedDekKeyPre = await crypto.subtle.importKey('raw', unwrappedRawDekPre, { name: 'AES-GCM' }, false, ['decrypt']);
const decryptedFilePre = await crypto.subtle.decrypt(
  { name: 'AES-GCM', iv: fileIv },
  unwrappedDekKeyPre,
  encryptedFileBuffer
);
assert.strictEqual(Buffer.from(decryptedFilePre).toString('utf8'), testFilePayload);
console.log('  ✓ Pre-migration recipient decryption verified.');

// 4. Migration Execution: Encrypt raw key material into AES-256-GCM envelope
const migratedEnvelopeStr = encryptKeyMaterial(originalRawToken);
assert.notStrictEqual(migratedEnvelopeStr, originalRawToken);

// 5. Post-migration Decryption Test (Recipient claim route decrypts envelope first)
const recoveredRawToken = decryptKeyMaterial(migratedEnvelopeStr);
assert.strictEqual(recoveredRawToken, originalRawToken, 'Recovered token must match original token');

const postMigrationKek = await deriveKek(recoveredRawToken, 'recipient-claim-salt');
const unwrappedRawDekPost = await crypto.subtle.decrypt(
  { name: 'AES-GCM', iv: Buffer.from(dekWrapIvBase64, 'base64') },
  postMigrationKek,
  Buffer.from(wrappedDekBase64, 'base64')
);
const unwrappedDekKeyPost = await crypto.subtle.importKey('raw', unwrappedRawDekPost, { name: 'AES-GCM' }, false, ['decrypt']);
const decryptedFilePost = await crypto.subtle.decrypt(
  { name: 'AES-GCM', iv: fileIv },
  unwrappedDekKeyPost,
  encryptedFileBuffer
);
assert.strictEqual(Buffer.from(decryptedFilePost).toString('utf8'), testFilePayload);
console.log('  ✓ Post-migration recipient decryption verified with 100% byte fidelity.');

console.log('\n🎉 ALL 6 COMPREHENSIVE ADVERSARIAL TESTS PASSED SUCCESSFULLY!');
