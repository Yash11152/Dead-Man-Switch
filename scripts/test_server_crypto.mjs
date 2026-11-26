// scripts/test_server_crypto.mjs
// Comprehensive Unit Test Suite for src/lib/serverCrypto.ts

import assert from 'assert';
import {
  encryptKeyMaterial,
  decryptKeyMaterial,
  generateNumericOtp,
  computeOtpHmac,
  verifyOtpHmac,
  canonicalizeJson,
  computeRequestFingerprint,
} from './serverCrypto.mjs';

console.log('🧪 Starting Server Crypto Unit Test Suite...\n');

// 1. Envelope Encryption & Decryption
console.log('--- TEST 1: AES-256-GCM Envelope Encryption & Decryption ---');
const rawKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const encryptedEnvelopeStr = encryptKeyMaterial(rawKey);
assert.ok(encryptedEnvelopeStr.startsWith('{'), 'Envelope must be JSON string');

const envelope = JSON.parse(encryptedEnvelopeStr);
assert.strictEqual(envelope.v, 1, 'Version must be 1');
assert.strictEqual(envelope.alg, 'A256GCM', 'Alg must be A256GCM');
assert.ok(envelope.iv, 'IV must exist');
assert.ok(envelope.tag, 'Tag must exist');
assert.ok(envelope.ct, 'Ciphertext must exist');

const decrypted = decryptKeyMaterial(encryptedEnvelopeStr);
assert.strictEqual(decrypted, rawKey, 'Decrypted key must match original rawKey byte-for-byte');
console.log('✅ PASS: AES-256-GCM envelope encryption and decryption verified.');

// 2. Dual-Read Backward Compatibility
console.log('\n--- TEST 2: Dual-Read Compatibility (Legacy Plaintext) ---');
const legacyKey = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';
const legacyDecrypted = decryptKeyMaterial(legacyKey);
assert.strictEqual(legacyDecrypted, legacyKey, 'Legacy plaintext must pass through unaltered');
console.log('✅ PASS: Dual-read compatibility verified for legacy plaintext keys.');

// 3. Cryptographic Tamper Protection
console.log('\n--- TEST 3: Cryptographic Tamper Protection ---');
const tamperedEnvelope = { ...envelope };
// Corrupt the ciphertext slightly
const ctBuf = Buffer.from(tamperedEnvelope.ct, 'base64');
ctBuf[0] ^= 0xff;
tamperedEnvelope.ct = ctBuf.toString('base64');

assert.throws(() => {
  decryptKeyMaterial(JSON.stringify(tamperedEnvelope));
}, /Unsupported state or unable to authenticate data|Decryption failed/, 'Tampered envelope must fail authentication');
console.log('✅ PASS: GCM auth tag rejects tampered envelope ciphertext.');

// 4. OTP Generation & Verification
console.log('\n--- TEST 4: OTP Generation & HMAC-SHA256 Verification ---');
const otp = generateNumericOtp(6);
assert.strictEqual(otp.length, 6, 'OTP must be 6 digits');
assert.ok(/^\d{6}$/.test(otp), 'OTP must be numeric');

const grantId = '11111111-2222-3333-4444-555555555555';
const digestA = computeOtpHmac(grantId, otp);
const digestB = computeOtpHmac(grantId, otp);
assert.strictEqual(digestA.length, 64, 'Digest must be 64-char hex');
assert.strictEqual(digestA, digestB, 'Same OTP and grantId must yield identical digest');

assert.ok(verifyOtpHmac(digestA, digestB), 'Digest verification must succeed');
assert.strictEqual(verifyOtpHmac(digestA, computeOtpHmac(grantId, '000000')), false, 'Wrong OTP digest must fail');
console.log('✅ PASS: OTP generation, HMAC calculation, and timing-safe verification verified.');

// 5. Canonical JSON & Request Fingerprint (RFC 8785)
console.log('\n--- TEST 5: Canonical JSON & Request Fingerprinting (RFC 8785) ---');
const payload1 = { b: 2, a: 1, c: { y: 'test', x: 10 } };
const payload2 = { a: 1, c: { x: 10, y: 'test' }, b: 2 };

const canon1 = canonicalizeJson(payload1);
const canon2 = canonicalizeJson(payload2);
assert.strictEqual(canon1, canon2, 'Key ordering must normalize to exact same canonical string');

const fp1 = computeRequestFingerprint(payload1);
const fp2 = computeRequestFingerprint(payload2);
assert.strictEqual(fp1.length, 64, 'Fingerprint must be 64 hex characters');
assert.strictEqual(fp1, fp2, 'Fingerprints must match across key permutations');

const fpAltered = computeRequestFingerprint({ ...payload1, a: 2 });
assert.notStrictEqual(fp1, fpAltered, 'Altered payload must produce different fingerprint');
console.log('✅ PASS: Canonical JSON and request fingerprinting verified.');

console.log('\n🎉 ALL 5 SERVER CRYPTO TESTS PASSED SUCCESSFULLY!');
