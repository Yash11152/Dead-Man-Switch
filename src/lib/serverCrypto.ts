// src/lib/serverCrypto.ts
// Node.js server-side cryptographic envelope encryption, key-ring management,
// server-secret HMAC OTP generation/verification, and RFC 8785 request fingerprinting.

import crypto from 'crypto';

export interface EncryptionEnvelope {
  v: 1;
  kid: string;
  alg: 'A256GCM';
  iv: string;   // base64 12 bytes
  tag: string;  // base64 16 bytes
  ct: string;   // base64 ciphertext
}

export interface KeyRingEntry {
  kid: string;
  keyBytes: Buffer;
}

/**
 * Parse an environment key entry in the format "kid:64-hex-chars" or raw 64-hex string.
 */
function parseKeyEntry(entry: string, defaultKid: string = 'dm-k1-2026'): KeyRingEntry {
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

/**
 * Load the server's configured encryption keyring from environment variables.
 * Falls back to an in-memory deterministic development key if not configured.
 */
export function getKeyRing(): { primary: KeyRingEntry; keyring: Map<string, Buffer> } {
  const primaryEnv = process.env.APP_ENCRYPTION_KEY_PRIMARY;
  const keyringEnv = process.env.APP_ENCRYPTION_KEYS;

  const keyring = new Map<string, Buffer>();

  let primary: KeyRingEntry;

  if (primaryEnv) {
    primary = parseKeyEntry(primaryEnv, 'dm-k1-2026');
    keyring.set(primary.kid, primary.keyBytes);
  } else {
    // Development fallback key (strictly for local dev / unconfigured environments)
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

/**
 * Encrypt plaintext key material into a tamper-proof AES-256-GCM JSON envelope.
 */
export function encryptKeyMaterial(plaintext: string): string {
  const { primary } = getKeyRing();
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', primary.keyBytes, iv);
  const ctBuffer = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  const envelope: EncryptionEnvelope = {
    v: 1,
    kid: primary.kid,
    alg: 'A256GCM',
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ct: ctBuffer.toString('base64'),
  };

  return JSON.stringify(envelope);
}

/**
 * Decrypt an AES-256-GCM envelope, seamlessly supporting keyring rotation.
 * If input is raw legacy plaintext (dual-read fallback), returns the plaintext verbatim.
 */
export function decryptKeyMaterial(input: string): string {
  if (!input || typeof input !== 'string') {
    throw new Error('Invalid input to decryptKeyMaterial');
  }

  const trimmed = input.trim();

  // Dual-read backward compatibility: check if input is a valid JSON envelope
  if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) {
    // Legacy plaintext token
    return trimmed;
  }

  let envelope: EncryptionEnvelope;
  try {
    envelope = JSON.parse(trimmed);
  } catch {
    // Not valid JSON, return as legacy string
    return trimmed;
  }

  if (envelope.v !== 1 || envelope.alg !== 'A256GCM' || !envelope.kid || !envelope.iv || !envelope.tag || !envelope.ct) {
    // Legacy JSON or unexpected format; fallback to raw
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

/**
 * Retrieve the server-side HMAC secret for OTP hashing.
 */
export function getOtpSecret(): Buffer {
  const envSecret = process.env.APP_OTP_SECRET_PRIMARY;
  if (envSecret) {
    const parts = envSecret.trim().split(':');
    const hex = parts.length === 2 ? parts[1].trim() : parts[0].trim();
    if (/^[0-9a-f]{64}$/i.test(hex)) {
      return Buffer.from(hex, 'hex');
    }
  }
  // Deterministic local dev fallback secret
  const fallbackHex = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';
  return Buffer.from(fallbackHex, 'hex');
}

/**
 * Generate a cryptographically secure 6-digit numeric OTP code.
 */
export function generateNumericOtp(digits: number = 6): string {
  const min = Math.pow(10, digits - 1);
  const max = Math.pow(10, digits) - 1;
  const range = max - min + 1;
  const randomVal = crypto.randomInt(0, range);
  return String(min + randomVal);
}

/**
 * Compute the server-secret HMAC-SHA256 digest of an OTP code.
 * The output is 64 hex characters (32 bytes).
 */
export function computeOtpHmac(grantId: string, otpCode: string): string {
  const secret = getOtpSecret();
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(`${grantId}:${otpCode.trim()}`);
  return hmac.digest('hex');
}

/**
 * Timing-safe comparison of two 64-hex HMAC digests.
 */
export function verifyOtpHmac(submittedDigest: string, expectedDigest: string): boolean {
  if (!submittedDigest || !expectedDigest) return false;
  if (submittedDigest.length !== 64 || expectedDigest.length !== 64) return false;

  const bufA = Buffer.from(submittedDigest, 'hex');
  const bufB = Buffer.from(expectedDigest, 'hex');

  if (bufA.length !== 32 || bufB.length !== 32) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * RFC 8785 Canonical JSON Stringifier
 * Ensures deterministic, sorted object serialization for request fingerprinting.
 */
export function canonicalizeJson(value: any): string {
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

/**
 * Compute RFC 8785 SHA-256 request fingerprint for idempotent operation tracking.
 */
export function computeRequestFingerprint(payload: Record<string, any>): string {
  const canonicalString = canonicalizeJson(payload);
  return crypto.createHash('sha256').update(canonicalString, 'utf8').digest('hex');
}
