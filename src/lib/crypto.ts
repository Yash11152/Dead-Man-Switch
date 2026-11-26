// src/lib/crypto.ts
// Client-side Web Crypto API implementation for AES-256-GCM encryption,
// key wrapping, and integrity hashing for Dead Man's Switch confidential files.

// Helper to convert Uint8Array / ArrayBuffer to Base64
export function bufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Helper to convert Base64 to Uint8Array
export function base64ToBuffer(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Helper to convert ArrayBuffer / Uint8Array to Hex string
export function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// Compute SHA-256 integrity hash of an ArrayBuffer, Blob, or Uint8Array
export async function computeSHA256(data: ArrayBuffer | Blob | Uint8Array): Promise<string> {
  let buffer: ArrayBuffer;
  if (data instanceof Blob) {
    buffer = await data.arrayBuffer();
  } else if (data instanceof Uint8Array) {
    buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  } else {
    buffer = data;
  }
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return bufferToHex(hashBuffer);
}

// Generate a random 256-bit AES-GCM Data Encryption Key (DEK)
export async function generateDEK(): Promise<CryptoKey> {
  return await crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true, // extractable for key wrapping
    ['encrypt', 'decrypt']
  );
}

// Derive a 256-bit Key Encryption Key (KEK) using PBKDF2 from a secret/passphrase
export async function deriveKEK(secret: string, salt: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: enc.encode(salt),
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Wrap (encrypt) the DEK using a KEK
export async function wrapDEK(
  dek: CryptoKey,
  kek: CryptoKey
): Promise<{ wrappedKey: string; iv: string }> {
  const rawDek = await crypto.subtle.exportKey('raw', dek);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedDek = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    kek,
    rawDek
  );

  return {
    wrappedKey: bufferToBase64(encryptedDek),
    iv: bufferToBase64(iv),
  };
}

// Unwrap (decrypt) the DEK using a KEK
export async function unwrapDEK(
  wrappedKeyBase64: string,
  ivBase64: string,
  kek: CryptoKey
): Promise<CryptoKey> {
  const ciphertext = base64ToBuffer(wrappedKeyBase64);
  const iv = base64ToBuffer(ivBase64);

  const rawDek = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    kek,
    ciphertext as unknown as BufferSource
  );

  return await crypto.subtle.importKey(
    'raw',
    rawDek,
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt']
  );
}

// Encrypt a file using AES-256-GCM
export async function encryptFile(
  file: File,
  dek: CryptoKey
): Promise<{
  ciphertextBlob: Blob;
  iv: string;
  fileHash: string;
}> {
  const fileBuffer = await file.arrayBuffer();
  // Unique 12-byte IV for every encryption operation
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    dek,
    fileBuffer
  );

  const ciphertextBlob = new Blob([encryptedBuffer], {
    type: 'application/octet-stream',
  });

  // Calculate SHA-256 hash of the ciphertext
  const fileHash = await computeSHA256(encryptedBuffer);

  return {
    ciphertextBlob,
    iv: bufferToBase64(iv),
    fileHash,
  };
}

// Decrypt a file buffer using AES-256-GCM
export async function decryptFile(
  encryptedBuffer: ArrayBuffer,
  ivBase64: string,
  dek: CryptoKey,
  mimeType?: string
): Promise<Blob> {
  const iv = base64ToBuffer(ivBase64);

  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv as unknown as BufferSource,
    },
    dek,
    encryptedBuffer
  );

  return new Blob([decryptedBuffer], {
    type: mimeType || 'application/octet-stream',
  });
}

// Generate a cryptographically random, high-entropy 32-byte hex claim token
export function generateRecipientClaimToken(): {
  rawToken: string;
  tokenHashPromise: Promise<string>;
} {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  const rawToken = bufferToHex(randomBytes);
  const tokenHashPromise = computeSHA256(new TextEncoder().encode(rawToken));

  return { rawToken, tokenHashPromise };
}
