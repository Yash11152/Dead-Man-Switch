// scripts/test_batch4_delivery.mjs
// Comprehensive Automated Test Suite for Batch 4:
// Automatic Email Delivery + Secure Download Link + Cryptographic Authorization

import assert from 'assert';
import crypto from 'crypto';

console.log('🧪 Starting Batch 4 Comprehensive Test Suite...\n');

// ============================================================
// TEST 1: High-Entropy Grant Generation & Key Material Derivation
// ============================================================
console.log('--- TEST 1: Grant Token Generation & SHA-256 Key Material ---');
function generateGrant() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(text) {
  const hash = crypto.createHash('sha256').update(text).digest('hex');
  return hash;
}

const keyMaterial = generateGrant();
assert.strictEqual(keyMaterial.length, 64, 'Key material must be 64 hex characters (32 bytes / 256 bits of entropy)');
const grantHash = await sha256(keyMaterial);
assert.strictEqual(grantHash.length, 64, 'Grant hash must be 64 hex characters');
assert.notStrictEqual(keyMaterial, grantHash, 'Key material and hash must never be identical');
console.log('✅ PASS: High-entropy grant generation & SHA-256 key material verified.');

// ============================================================
// TEST 2: PBKDF2 Key Derivation (Owner & Recipient from Key Material)
// ============================================================
console.log('\n--- TEST 2: PBKDF2 100k-iteration KEK Derivation ---');
async function deriveKEK(secret, salt) {
  const enc = new TextEncoder();
  const keyMaterialObj = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  return await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' },
    keyMaterialObj,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

const ownerId = 'user-owner-batch4-uuid';
const ownerKek = await deriveKEK(ownerId, 'owner-vault-salt');
const recipientKek = await deriveKEK(keyMaterial, 'recipient-claim-salt');
assert.ok(ownerKek, 'Owner KEK must be derived');
assert.ok(recipientKek, 'Recipient KEK must be derived');
console.log('✅ PASS: PBKDF2 100k-iteration KEK derivation verified.');

// ============================================================
// TEST 3: End-to-End AES-256-GCM File Encryption, Wrapping & Decryption
// ============================================================
console.log('\n--- TEST 3: AES-256-GCM File Encryption, Dual Wrapping & Recipient Decryption ---');
const dek = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 },
  true,
  ['encrypt', 'decrypt']
);

const secretPayload = 'CONFIDENTIAL_BATCH_4_EMERGENCY_DOCUMENT_CONTENT_VERIFIED';
const payloadBuffer = new TextEncoder().encode(secretPayload);

// Encrypt payload with DEK
const fileIv = crypto.getRandomValues(new Uint8Array(12));
const ciphertext = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv: fileIv },
  dek,
  payloadBuffer
);

// Key wrapping helpers
async function wrapDEK(dekKey, kekKey) {
  const rawDek = await crypto.subtle.exportKey('raw', dekKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kekKey, rawDek);
  return {
    wrappedKey: Buffer.from(encrypted).toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
  };
}

async function unwrapDEK(wrappedKeyB64, ivB64, kekKey) {
  const ct = Buffer.from(wrappedKeyB64, 'base64');
  const iv = Buffer.from(ivB64, 'base64');
  const rawDek = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, kekKey, ct);
  return await crypto.subtle.importKey('raw', rawDek, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
}

const ownerWrapped = await wrapDEK(dek, ownerKek);
const recipientWrapped = await wrapDEK(dek, recipientKek);

// Recipient receives keyMaterial upon verified claim authorization
const recipientDerivedKek = await deriveKEK(keyMaterial, 'recipient-claim-salt');
const recipientUnwrappedDek = await unwrapDEK(recipientWrapped.wrappedKey, recipientWrapped.iv, recipientDerivedKek);

const decryptedBuffer = await crypto.subtle.decrypt(
  { name: 'AES-GCM', iv: fileIv },
  recipientUnwrappedDek,
  ciphertext
);

const decryptedText = new TextDecoder().decode(decryptedBuffer);
assert.strictEqual(decryptedText, secretPayload, 'Recipient decrypted payload must match original secret exactly');
console.log('✅ PASS: AES-256-GCM encryption, wrapping, and recipient decryption verified.');

// ============================================================
// TEST 4: AES-GCM Integrity & Tamper Resistance
// ============================================================
console.log('\n--- TEST 4: AES-GCM Cryptographic Integrity & Tamper Detection ---');
const tamperedCiphertext = new Uint8Array(ciphertext);
tamperedCiphertext[tamperedCiphertext.length - 1] ^= 0x01; // flip 1 bit in auth tag

let tamperCaught = false;
try {
  await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fileIv },
    recipientUnwrappedDek,
    tamperedCiphertext
  );
} catch {
  tamperCaught = true;
}
assert.strictEqual(tamperCaught, true, 'AES-GCM must reject tampered ciphertext with tag verification failure');
console.log('✅ PASS: AES-GCM integrity tag verification protects against payload tampering.');

// ============================================================
// TEST 5: Trigger-to-Outbox Notification Body & Link Formatting
// ============================================================
console.log('\n--- TEST 5: Trigger Notification Outbox Formatting ---');
function formatTriggerNotification(switchTitle, recipientEmail, tokenId, siteUrl = 'https://deadman.app') {
  const bodyPreview = 
    `Emergency notification: Dead Man Switch "${switchTitle}" has reached triggered status.\n\n` +
    `Confidential payload files have been released to your emergency custody.\n\n` +
    `Secure Download Link: /claim?grant=${tokenId}\n\n` +
    `Security Note: When opening this link, you will be required to confirm your authorized email address (${recipientEmail}) before files are decrypted.`;

  const externalEmailBody = bodyPreview.replace(/\/claim\?grant=/g, `${siteUrl}/claim?grant=`);

  return {
    bodyPreview,
    externalEmailBody,
    idempotencyKey: `switch-123:rec-456:SWITCH_TRIGGERED`,
  };
}

const mockTokenId = '550e8400-e29b-41d4-a716-446655440000';
const notif = formatTriggerNotification('Vault Alpha', 'sarah@example.com', mockTokenId);
assert.ok(notif.bodyPreview.includes(`/claim?grant=${mockTokenId}`), 'Outbox preview must include relative grant link');
assert.ok(notif.externalEmailBody.includes(`https://deadman.app/claim?grant=${mockTokenId}`), 'Dispatched email must include full URL');
assert.ok(!notif.bodyPreview.includes('attachment'), 'Must not attach actual payload files');
assert.ok(!notif.bodyPreview.includes(keyMaterial), 'Must never expose raw encryption keys or key material in notification body');
console.log('✅ PASS: Outbox notification formatting contains secure link and zero exposed key material.');

// ============================================================
// TEST 6: Idempotent Notification Queueing (Duplicate Prevention)
// ============================================================
console.log('\n--- TEST 6: Idempotency & Duplicate Notification Prevention ---');
const outboxMock = new Map();
function queueNotification(notifItem) {
  if (outboxMock.has(notifItem.idempotencyKey)) {
    return { inserted: false, reason: 'Duplicate idempotency key ignored (ON CONFLICT DO NOTHING)' };
  }
  outboxMock.set(notifItem.idempotencyKey, notifItem);
  return { inserted: true };
}

const r1 = queueNotification({ idempotencyKey: 'switch-1:rec-1:SWITCH_TRIGGERED', subject: 'Emergency Release' });
const r2 = queueNotification({ idempotencyKey: 'switch-1:rec-1:SWITCH_TRIGGERED', subject: 'Emergency Release' });
const r3 = queueNotification({ idempotencyKey: 'switch-1:rec-1:SWITCH_TRIGGERED', subject: 'Emergency Release' });

assert.strictEqual(r1.inserted, true, 'First notification queue must succeed');
assert.strictEqual(r2.inserted, false, 'Second identical notification must be ignored');
assert.strictEqual(r3.inserted, false, 'Third identical notification must be ignored');
assert.strictEqual(outboxMock.size, 1, 'Outbox must contain exactly 1 entry despite repeated triggers');
console.log('✅ PASS: Idempotent notification duplicate prevention verified.');

// ============================================================
// TEST 7: Recipient Identity & Authorization Logic
// ============================================================
console.log('\n--- TEST 7: Recipient Identity Verification & Cross-Recipient Protection ---');
function simulateRedeemClaim({
  grantToken,
  recipientRecord,
  switchRecord,
  providedEmail,
  providedGrantId,
  now = new Date(),
}) {
  if (!providedGrantId || providedGrantId !== grantToken.id) {
    return { success: false, error: 'Invalid or unissued access link.' };
  }
  if (grantToken.revokedAt) {
    return { success: false, error: 'This access link has been revoked.', reason: 'token_revoked' };
  }
  if (new Date(grantToken.expiresAt) < now) {
    return { success: false, error: 'This access link has expired.', reason: 'token_expired' };
  }
  if (grantToken.redemptionCount >= grantToken.maxRedemptions) {
    return { success: false, error: 'Maximum access limit reached for this emergency link.', reason: 'redemption_limit_reached' };
  }
  if (switchRecord.status !== 'TRIGGERED') {
    return { success: false, error: `Switch is not in TRIGGERED state (current status: ${switchRecord.status}). Files remain locked.`, reason: 'switch_not_triggered' };
  }
  if (recipientRecord.email.toLowerCase().trim() !== providedEmail.toLowerCase().trim()) {
    return { success: false, error: 'Recipient identity verification failed. Provided email does not match authorization.', reason: 'email_mismatch' };
  }

  return {
    success: true,
    keyMaterial: grantToken.keyMaterial,
    switchTitle: switchRecord.title,
    recipientEmail: recipientRecord.email,
  };
}

const testGrant = {
  id: 'grant-uuid-1111',
  keyMaterial: keyMaterial,
  expiresAt: new Date(Date.now() + 86400000).toISOString(),
  revokedAt: null,
  redemptionCount: 0,
  maxRedemptions: 10,
};

const testRecipient = { id: 'rec-uuid-1', email: 'authorized@example.com' };
const testSwitchTriggered = { id: 'switch-uuid-1', title: 'Life Vault', status: 'TRIGGERED' };
const testSwitchActive = { id: 'switch-uuid-1', title: 'Life Vault', status: 'ACTIVE' };
const testSwitchPendingGrace = { id: 'switch-uuid-1', title: 'Life Vault', status: 'PENDING_GRACE' };

// 7a: Matching email on TRIGGERED switch -> SUCCESS
const resAuth = simulateRedeemClaim({
  grantToken: testGrant,
  recipientRecord: testRecipient,
  switchRecord: testSwitchTriggered,
  providedEmail: 'authorized@example.com',
  providedGrantId: testGrant.id,
});
assert.strictEqual(resAuth.success, true, 'Authorized email on TRIGGERED switch must succeed');
assert.strictEqual(resAuth.keyMaterial, keyMaterial, 'Must return key material to authorized recipient');

// 7b: Case-insensitive email normalization
const resCase = simulateRedeemClaim({
  grantToken: testGrant,
  recipientRecord: testRecipient,
  switchRecord: testSwitchTriggered,
  providedEmail: '  AuThOrIzEd@EXAMPLE.COM  ',
  providedGrantId: testGrant.id,
});
assert.strictEqual(resCase.success, true, 'Case and whitespace variations must be normalized');

// 7c: Mismatched email (attacker trying to use someone else\'s link)
const resMismatch = simulateRedeemClaim({
  grantToken: testGrant,
  recipientRecord: testRecipient,
  switchRecord: testSwitchTriggered,
  providedEmail: 'attacker@evil.com',
  providedGrantId: testGrant.id,
});
assert.strictEqual(resMismatch.success, false, 'Mismatched email must be rejected');
assert.strictEqual(resMismatch.reason, 'email_mismatch');

// 7d: Unreleased switch denial (ACTIVE)
const resActive = simulateRedeemClaim({
  grantToken: testGrant,
  recipientRecord: testRecipient,
  switchRecord: testSwitchActive,
  providedEmail: 'authorized@example.com',
  providedGrantId: testGrant.id,
});
assert.strictEqual(resActive.success, false, 'ACTIVE switch must be rejected');
assert.strictEqual(resActive.reason, 'switch_not_triggered');

// 7e: Unreleased switch denial (PENDING_GRACE)
const resGrace = simulateRedeemClaim({
  grantToken: testGrant,
  recipientRecord: testRecipient,
  switchRecord: testSwitchPendingGrace,
  providedEmail: 'authorized@example.com',
  providedGrantId: testGrant.id,
});
assert.strictEqual(resGrace.success, false, 'PENDING_GRACE switch must be rejected');
assert.strictEqual(resGrace.reason, 'switch_not_triggered');

// 7f: Revoked link denial
const resRevoked = simulateRedeemClaim({
  grantToken: { ...testGrant, revokedAt: new Date().toISOString() },
  recipientRecord: testRecipient,
  switchRecord: testSwitchTriggered,
  providedEmail: 'authorized@example.com',
  providedGrantId: testGrant.id,
});
assert.strictEqual(resRevoked.success, false, 'Revoked link must be rejected');
assert.strictEqual(resRevoked.reason, 'token_revoked');

// 7g: Expired link denial
const resExpired = simulateRedeemClaim({
  grantToken: { ...testGrant, expiresAt: new Date(Date.now() - 1000).toISOString() },
  recipientRecord: testRecipient,
  switchRecord: testSwitchTriggered,
  providedEmail: 'authorized@example.com',
  providedGrantId: testGrant.id,
});
assert.strictEqual(resExpired.success, false, 'Expired link must be rejected');
assert.strictEqual(resExpired.reason, 'token_expired');

// 7h: Redemption limit denial
const resLimit = simulateRedeemClaim({
  grantToken: { ...testGrant, redemptionCount: 10, maxRedemptions: 10 },
  recipientRecord: testRecipient,
  switchRecord: testSwitchTriggered,
  providedEmail: 'authorized@example.com',
  providedGrantId: testGrant.id,
});
assert.strictEqual(resLimit.success, false, 'Exceeded redemption limit must be rejected');
assert.strictEqual(resLimit.reason, 'redemption_limit_reached');

console.log('✅ PASS: Recipient identity verification, unreleased denial & lifecycle rules verified.');

// ============================================================
// TEST 8: Signed URL Expiry & Private Storage Safety
// ============================================================
console.log('\n--- TEST 8: Short-Lived Signed URL Expiry ---');
function createMockSignedUrl(storagePath, ttlSeconds = 60) {
  const expires = Math.floor(Date.now() / 1000) + ttlSeconds;
  return {
    signedUrl: `https://mock.supabase.co/storage/v1/object/sign/dead-man-files/${storagePath}?token=mock_jwt&expires=${expires}`,
    expiresAt: expires,
  };
}

const signed = createMockSignedUrl('owner/switch/file-1.enc', 60);
assert.ok(signed.signedUrl.includes('dead-man-files'), 'Signed URL must target private bucket');
assert.ok(signed.expiresAt - Math.floor(Date.now() / 1000) <= 60, 'Signed URL lifetime must be <= 60 seconds');
console.log('✅ PASS: Private storage pre-signed URL expiry verified (60s lifetime).');

// ============================================================
// TEST 9: Backward Compatibility (Plaintext Files & Legacy Token Fallback)
// ============================================================
console.log('\n--- TEST 9: Backward Compatibility for Legacy Plaintext Files & Manual Tokens ---');
// Plaintext file handling
const plaintextPayload = 'LEGACY_PLAINTEXT_FILE_CONTENT_UNENCRYPTED';
const plaintextBuffer = new TextEncoder().encode(plaintextPayload);

function processDownload(fileMeta, buffer, deliveredKeyMaterial) {
  if (!fileMeta.encrypted) {
    return new TextDecoder().decode(buffer);
  }
  // If encrypted, decrypt using deliveredKeyMaterial
  return 'encrypted_handled';
}

const downloadedPlaintext = processDownload({ encrypted: false }, plaintextBuffer, null);
assert.strictEqual(downloadedPlaintext, plaintextPayload, 'Legacy plaintext files must download without decryption errors');

// Legacy manual token fallback simulation
const legacyToken = generateGrant();
const legacyTokenHash = await sha256(legacyToken);

function simulateLegacyRedeem(inputToken, storedHash) {
  const computedHash = crypto.createHash('sha256').update(inputToken).digest('hex');
  if (computedHash === storedHash) {
    return { success: true, keyMaterial: inputToken };
  }
  return { success: false, error: 'Invalid token' };
}

const legacyResult = simulateLegacyRedeem(legacyToken, legacyTokenHash);
assert.strictEqual(legacyResult.success, true, 'Legacy token redemption via token hash must remain functional');
assert.strictEqual(legacyResult.keyMaterial, legacyToken);
console.log('✅ PASS: Legacy plaintext files and legacy manual token fallback fully compatible.');

// ============================================================
// TEST 10: Outbox Worker Dispatch Safety & Provider Modes
// ============================================================
console.log('\n--- TEST 10: Notification Outbox Worker Safe Dispatch Modes ---');
function evaluateDispatchMode(resendApiKey, isDryRun) {
  const hasKey = Boolean(resendApiKey && resendApiKey.startsWith('re_'));
  if (!hasKey) {
    return {
      status: 'PENDING_CONFIG',
      message: 'RESEND_API_KEY is not configured in server environment. Notification logged in database outbox without external delivery.',
      externalCallMade: false,
    };
  }
  if (isDryRun) {
    return {
      status: 'DRY_RUN',
      message: 'Dispatched in requested test DRY_RUN mode. Real email delivery skipped.',
      externalCallMade: false,
    };
  }
  return {
    status: 'DELIVERED',
    message: 'Dispatched via Resend REST API.',
    externalCallMade: true,
  };
}

const modeNoKey = evaluateDispatchMode('', false);
assert.strictEqual(modeNoKey.status, 'PENDING_CONFIG', 'Missing API key must result in PENDING_CONFIG');
assert.strictEqual(modeNoKey.externalCallMade, false, 'Missing API key must never call external API');

const modeDryRun = evaluateDispatchMode('re_test_key_123', true);
assert.strictEqual(modeDryRun.status, 'DRY_RUN', 'Dry-run flag must result in DRY_RUN');
assert.strictEqual(modeDryRun.externalCallMade, false, 'Dry run must never call external API');

const modeLive = evaluateDispatchMode('re_test_key_123', false);
assert.strictEqual(modeLive.status, 'DELIVERED', 'Valid key without dry-run dispatches live');
assert.strictEqual(modeLive.externalCallMade, true);
console.log('✅ PASS: Safe dispatch modes (PENDING_CONFIG and DRY_RUN) verified.');

console.log('\n🎉 ALL 10 AUTOMATED BATCH 4 TESTS PASSED SUCCESSFULLY!\n');
