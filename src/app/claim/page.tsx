'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { 
  Shield, 
  Lock, 
  Unlock, 
  Download, 
  AlertCircle, 
  CheckCircle2, 
  FileText, 
  Loader2, 
  Mail, 
  Key,
  Link as LinkIcon
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { decryptFile, unwrapDEK, deriveKEK } from '@/lib/crypto';

interface ReleasedFile {
  id: string;
  name: string;
  size: number;
  encrypted: boolean;
  fileHash: string;
  iv?: string;
  encryptedDekRecipient?: string;
  encryptionVersion?: string;
  mimeType?: string;
  downloadUrl?: string;
}

function ClaimContent() {
  const searchParams = useSearchParams();
  const grantParam = searchParams.get('grant') || searchParams.get('id') || '';
  const tokenParam = searchParams.get('token') || '';

  const [grantId, setGrantId] = useState(grantParam);
  const [token, setToken] = useState(tokenParam);
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [showManualFallback, setShowManualFallback] = useState(false);

  const [claimedSwitch, setClaimedSwitch] = useState<{
    switchTitle: string;
    switchDescription: string;
    recipientName: string;
    recipientEmail: string;
    triggeredAt: string;
    keyMaterial?: string | null;
    files: ReleasedFile[];
  } | null>(null);

  const [decryptingFileId, setDecryptingFileId] = useState<string | null>(null);
  const [downloadSuccessMap, setDownloadSuccessMap] = useState<Record<string, string>>({});

  useEffect(() => {
    if (grantParam) {
      setGrantId(grantParam);
    }
    if (tokenParam) {
      setToken(tokenParam);
    }
  }, [grantParam, tokenParam]);

  const hasGrantLink = Boolean(grantId.trim());

  const handleClaim = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!hasGrantLink && !token.trim()) {
      setErrorMessage('Please provide your secure access link identifier or claim token.');
      return;
    }

    if (!email.trim() || !email.includes('@')) {
      setErrorMessage('Please enter the recipient email authorized for this switch.');
      return;
    }

    setIsLoading(true);

    try {
      const res = await fetch('/api/claim', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          grant: hasGrantLink ? grantId.trim() : undefined,
          token: !hasGrantLink && token.trim() ? token.trim() : undefined,
          email: email.trim().toLowerCase(),
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Claim authorization failed.');
      }

      setClaimedSwitch(data);
    } catch (err: any) {
      console.error('Claim error:', err);
      setErrorMessage(err?.message || 'Failed to claim switch. Please check your credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDownloadAndDecrypt = async (file: ReleasedFile) => {
    if (!file.downloadUrl) {
      alert('Download URL not available for this file.');
      return;
    }

    setDecryptingFileId(file.id);

    try {
      // 1. Fetch ciphertext/file buffer from temporary signed URL
      const response = await fetch(file.downloadUrl);
      if (!response.ok) {
        throw new Error('Failed to retrieve file from secure vault storage. The signed link may have expired.');
      }

      const fileBuffer = await response.arrayBuffer();
      let finalBlob: Blob;

      // 2. Decrypt if file is marked encrypted
      if (file.encrypted && file.iv && file.encryptedDekRecipient) {
        // Derive KEK using keyMaterial delivered server-side upon verified authorization (or legacy token)
        const decryptionKey = claimedSwitch?.keyMaterial || token.trim();
        if (!decryptionKey) {
          throw new Error('Decryption key material was not delivered for this session.');
        }

        const recipientKek = await deriveKEK(decryptionKey, 'recipient-claim-salt');

        // Parse wrapped DEK envelope
        const envelope = JSON.parse(atob(file.encryptedDekRecipient));
        const dek = await unwrapDEK(envelope.wrappedKey, envelope.iv, recipientKek);

        // Decrypt ciphertext using DEK and unique IV
        finalBlob = await decryptFile(fileBuffer, file.iv, dek, file.mimeType);
      } else {
        // Plaintext file (legacy / unencrypted)
        finalBlob = new Blob([fileBuffer], { type: file.mimeType || 'application/octet-stream' });
      }

      // 3. Trigger browser download
      const downloadUrl = URL.createObjectURL(finalBlob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = file.name;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(downloadUrl);

      setDownloadSuccessMap((prev) => ({ ...prev, [file.id]: 'Decrypted & Downloaded' }));
    } catch (err: any) {
      console.error('Decryption error:', err);
      alert(`Failed to decrypt and download file: ${err?.message || 'Decryption error'}`);
    } finally {
      setDecryptingFileId(null);
    }
  };

  const formatFileSize = (bytes: number) => {
    if (!bytes) return 'Unknown size';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="min-h-screen flex flex-col justify-center items-center p-4 bg-[#09090b] text-zinc-100">
      <div className="w-full max-w-xl space-y-6">

        {/* Brand Header */}
        <div className="text-center space-y-2">
          <Link href="/" className="inline-flex items-center gap-2">
            <div className="p-2 rounded bg-zinc-900 border border-zinc-800 text-emerald-400">
              <Shield className="w-5 h-5" />
            </div>
            <span className="font-semibold text-lg text-zinc-100">
              Dead Man&apos;s Switch
            </span>
          </Link>
          <p className="text-xs text-zinc-400">
            Secure Emergency Recipient Portal
          </p>
        </div>

        {!claimedSwitch ? (
          /* Step 1: Token & Identity Verification Form */
          <Card className="shadow-xl">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <Lock className="w-4 h-4 text-emerald-400" />
                  {hasGrantLink ? 'Emergency Release Verification' : 'Claim Emergency Release'}
                </CardTitle>
                {hasGrantLink && (
                  <span className="text-[11px] px-2 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-800/80 text-emerald-400 font-medium">
                    Secure Link Verified
                  </span>
                )}
              </div>
              <CardDescription>
                {hasGrantLink
                  ? 'Your secure download link has been detected. Confirm your authorized recipient email below to verify your identity and unlock your files.'
                  : 'Enter your designated emergency grant link or claim token and verified email to unlock confidential files.'}
              </CardDescription>
            </CardHeader>

            <CardContent className="pt-2">
              {errorMessage && (
                <div className="mb-4 p-3 rounded bg-red-950/60 border border-red-800/60 text-red-400 text-xs flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{errorMessage}</span>
                </div>
              )}

              <form onSubmit={handleClaim} className="space-y-4">
                {/* When grant link is NOT provided in URL, allow entering link ID or token */}
                {!hasGrantLink && (
                  <Input
                    label="Access Grant ID or Claim Token"
                    placeholder="Enter grant link ID or 64-character token"
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    leftIcon={<Key className="w-4 h-4 text-zinc-400" />}
                    required
                    disabled={isLoading}
                    helperText="Provided in your emergency email notification."
                  />
                )}

                <Input
                  label="Authorized Recipient Email"
                  type="email"
                  placeholder="recipient@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  leftIcon={<Mail className="w-4 h-4 text-zinc-400" />}
                  required
                  disabled={isLoading}
                  helperText="Must match the emergency contact email on record for cryptographic authorization."
                />

                {hasGrantLink && showManualFallback && (
                  <Input
                    label="Override Claim Token (Optional / Legacy)"
                    placeholder="Paste 64-character token if using legacy switch"
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    leftIcon={<Key className="w-4 h-4 text-zinc-400" />}
                    disabled={isLoading}
                    helperText="Only required if this switch was created with a legacy manual claim token."
                  />
                )}

                <Button
                  type="submit"
                  variant="primary"
                  size="md"
                  isLoading={isLoading}
                  className="w-full mt-2"
                >
                  Verify Email & Unlock Vault
                </Button>
              </form>

              {hasGrantLink && !showManualFallback && (
                <div className="mt-3 text-center">
                  <button
                    type="button"
                    onClick={() => setShowManualFallback(true)}
                    className="text-[11px] text-zinc-500 hover:text-zinc-400 underline"
                  >
                    Using a legacy manual claim token?
                  </button>
                </div>
              )}
            </CardContent>

            <CardFooter className="justify-center bg-zinc-950/40 border-t border-zinc-800 py-3">
              <p className="text-[11px] text-zinc-500 text-center">
                Access is cryptographically released only when the associated switch reaches TRIGGERED status.
              </p>
            </CardFooter>
          </Card>
        ) : (
          /* Step 2: Released Files & Client-Side Decryption */
          <Card className="shadow-xl">
            <CardHeader className="border-b border-zinc-800 pb-4">
              <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold uppercase tracking-wider mb-1">
                <Unlock className="w-4 h-4" />
                Emergency Access Authorized
              </div>
              <CardTitle className="text-lg text-zinc-100">
                {claimedSwitch.switchTitle}
              </CardTitle>
              {claimedSwitch.switchDescription && (
                <CardDescription className="text-zinc-300 whitespace-pre-wrap">
                  {claimedSwitch.switchDescription}
                </CardDescription>
              )}
            </CardHeader>

            <CardContent className="pt-4 space-y-4">
              <div className="p-3 rounded bg-zinc-950/60 border border-zinc-800 text-xs space-y-1">
                <div className="flex justify-between text-zinc-400">
                  <span>Authorized Recipient:</span>
                  <span className="font-medium text-zinc-200">{claimedSwitch.recipientName} ({claimedSwitch.recipientEmail})</span>
                </div>
                <div className="flex justify-between text-zinc-400">
                  <span>Triggered At:</span>
                  <span className="font-mono text-zinc-300">
                    {new Date(claimedSwitch.triggeredAt).toLocaleString()}
                  </span>
                </div>
              </div>

              <div className="space-y-2">
                <p className="text-xs font-semibold text-zinc-300">
                  Released Payload Files ({claimedSwitch.files.length})
                </p>

                {claimedSwitch.files.map((file) => (
                  <div
                    key={file.id}
                    className="flex flex-col sm:flex-row sm:items-center justify-between p-3 rounded bg-zinc-950/60 border border-zinc-800 gap-3"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="p-2 rounded bg-zinc-900 border border-zinc-800 text-emerald-400 shrink-0">
                        <FileText className="w-4 h-4" />
                      </div>
                      <div className="min-w-0">
                        <p className="font-medium text-zinc-200 text-xs truncate">{file.name}</p>
                        <div className="flex items-center gap-2 text-[10px] text-zinc-500 mt-0.5">
                          <span>{formatFileSize(file.size)}</span>
                          <span>•</span>
                          <span className={file.encrypted ? 'text-amber-400 font-medium' : 'text-zinc-400'}>
                            {file.encrypted ? 'AES-256-GCM Encrypted' : 'Plaintext'}
                          </span>
                          {file.fileHash && (
                            <>
                              <span>•</span>
                              <span className="font-mono text-[9px] text-zinc-600 truncate max-w-[100px]" title={file.fileHash}>
                                Hash: {file.fileHash.slice(0, 8)}...
                              </span>
                            </>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      {downloadSuccessMap[file.id] && (
                        <span className="text-emerald-400 text-xs flex items-center gap-1 font-medium">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          Downloaded
                        </span>
                      )}
                      <Button
                        variant="primary"
                        size="sm"
                        isLoading={decryptingFileId === file.id}
                        onClick={() => handleDownloadAndDecrypt(file)}
                        leftIcon={<Download className="w-3.5 h-3.5" />}
                      >
                        {file.encrypted ? 'Decrypt & Save' : 'Download'}
                      </Button>
                    </div>
                  </div>
                ))}

                {claimedSwitch.files.length === 0 && (
                  <p className="text-xs text-zinc-500 text-center py-6">
                    No files were attached to this dead man switch.
                  </p>
                )}
              </div>
            </CardContent>

            <CardFooter className="justify-between bg-zinc-950/40 border-t border-zinc-800 py-3">
              <p className="text-[11px] text-zinc-500">
                Identity verified. Files are decrypted locally inside your browser sandbox.
              </p>
              <Link href="/">
                <Button variant="ghost" size="sm">
                  Return Home
                </Button>
              </Link>
            </CardFooter>
          </Card>
        )}

      </div>
    </div>
  );
}

export default function RecipientClaimPage() {
  return (
    <Suspense fallback={
      <div className="min-h-[80vh] flex items-center justify-center p-4">
        <div className="flex items-center gap-2 text-zinc-400">
          <Loader2 className="w-5 h-5 animate-spin text-emerald-500" />
          <span>Loading secure claim portal...</span>
        </div>
      </div>
    }>
      <ClaimContent />
    </Suspense>
  );
}
