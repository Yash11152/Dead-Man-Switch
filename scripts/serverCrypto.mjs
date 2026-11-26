// scripts/serverCrypto.mjs
// Node.js server-side cryptographic envelope encryption, key-ring management,
// server-secret HMAC OTP generation/verification, and RFC 8785 request fingerprinting.

import crypto from 'crypto';

export function parseKeyEntry(entry, defaultKid = 'dm-k1-2026') {
  const parts = entry.trim().split(':');
  let kid = defaultKid;
  let hexKey = entry.trim();

  if (parts.length === 2) {
    kid = parts[0].trim();
    hexKey = parts[1].trim();
  }

  if (!/^[0-9a-f]{64}$/i.test(hexKey)) {
    throw new Error(`Invalid encryption key format for kid "${kid}". Must be 64 hex characters (32 bytes).`);
  }

  return {
    kid,
    keyBytes: Buffer.from(hexKey, 'hex'),
  };
}

export function getKeyRing() {
  const primaryEnv = process.env.APP_ENCRYPTION_KEY_PRIMARY;
  const keyringEnv = process.env.APP_ENCRYPTION_KEYS;

  const keyring = new Map();
  let primary;

  if (primaryEnv) {
    primary = parseKeyEntry(primaryEnv, 'dm-k1-2026');
    keyring.set(primary.kid, primary.keyBytes);
  } else {
    const devHex = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    primary = { kid: 'dm-dev-fallback', keyBytes: Buffer.from(devHex, 'hex') };
    keyring.set(primary.kid, primary.keyBytes);
  }

  if (keyringEnv) {
    const entries = keyringEnv.split(',');
    for (const entry of entries) {
      if (entry.trim()) {
        const parsed = parseKeyEntry(entry.trim());
        keyring.set(parsed.kid, parsed.keyBytes);
      }
    }
  }

  return { primary, keyring };
}

export function encryptKeyMaterial(plaintext) {
  const { primary } = getKeyRing();
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', primary.keyBytes, iv);
  const ctBuffer = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  const envelope = {
    v: 1,
    kid: primary.kid,
    alg: 'A256GCM',
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ct: ctBuffer.toString('base64'),
  };

  return JSON.stringify(envelope);
}

export function decryptKeyMaterial(input) {
  if (!input || typeof input !== 'string') {
    throw new Error('Invalid input to decryptKeyMaterial');
  }

  const trimmed = input.trim();

  if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) {
    return trimmed;
  }

  let envelope;
  try {
    envelope = JSON.parse(trimmed);
  } catch {
    return trimmed;
  }

  if (envelope.v !== 1 || envelope.alg !== 'A256GCM' || !envelope.kid || !envelope.iv || !envelope.tag || !envelope.ct) {
    return trimmed;
  }

  const { keyring } = getKeyRing();
  const keyBytes = keyring.get(envelope.kid);

  if (!keyBytes) {
    throw new Error(`Decryption failed: Key identifier "${envelope.kid}" not found in server keyring.`);
  }

  const iv = Buffer.from(envelope.iv, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  const ct = Buffer.from(envelope.ct, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBytes, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([decipher.update(ct), decipher.final()]);
  return decrypted.toString('utf8');
}

export function getOtpSecret() {
  const envSecret = process.env.APP_OTP_SECRET_PRIMARY;
  if (envSecret) {
    const parts = envSecret.trim().split(':');
    const hex = parts.length === 2 ? parts[1].trim() : parts[0].trim();
    if (/^[0-9a-f]{64}$/i.test(hex)) {
      return Buffer.from(hex, 'hex');
    }
  }
  const fallbackHex = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';
  return Buffer.from(fallbackHex, 'hex');
}

export function generateNumericOtp(digits = 6) {
  const min = Math.pow(10, digits - 1);
  const max = Math.pow(10, digits) - 1;
  const range = max - min + 1;
  const randomVal = crypto.randomInt(0, range);
  return String(min + randomVal);
}

export function computeOtpHmac(grantId, otpCode) {
  const secret = getOtpSecret();
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(`${grantId}:${otpCode.trim()}`);
  return hmac.digest('hex');
}

export function verifyOtpHmac(submittedDigest, expectedDigest) {
  if (!submittedDigest || !expectedDigest) return false;
  if (submittedDigest.length !== 64 || expectedDigest.length !== 64) return false;

  const bufA = Buffer.from(submittedDigest, 'hex');
  const bufB = Buffer.from(expectedDigest, 'hex');

  if (bufA.length !== 32 || bufB.length !== 32) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

export function canonicalizeJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return '[' + value.map(canonicalizeJson).join(',') + ']';
  }

  const sortedKeys = Object.keys(value).sort();
  const pairs = sortedKeys
    .filter(k => value[k] !== undefined)
    .map(k => `${JSON.stringify(k)}:${canonicalizeJson(value[k])}`);

  return '{' + pairs.join(',') + '}';
}

export function computeRequestFingerprint(payload) {
  const canonicalString = canonicalizeJson(payload);
  return crypto.createHash('sha256').update(canonicalString, 'utf8').digest('hex');
}
