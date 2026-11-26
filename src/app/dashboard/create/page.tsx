'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { ArrowLeft, Clock, AlertCircle, Loader2, Key, CheckCircle2, ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/Card';
import { FileUpload } from '@/components/switch/FileUpload';
import { useAuth } from '@/context/AuthContext';
import {
  generateDEK,
  encryptFile,
  deriveKEK,
  wrapDEK,
  generateRecipientClaimToken
} from '@/lib/crypto';

export default function CreateSwitchPage() {
  const router = useRouter();
  const { user, supabase } = useAuth();

  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [intervalDays, setIntervalDays] = useState<number>(7);
  const [graceHours, setGraceHours] = useState<number>(48);
  const [recipientName, setRecipientName] = useState('');
  const [recipientEmail, setRecipientEmail] = useState('');
  const [payloadFiles, setPayloadFiles] = useState<File[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [uploadStatusText, setUploadStatusText] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setUploadStatusText(null);

    if (!title.trim()) { setErrorMessage('Switch title is required.'); return; }
    if (intervalDays <= 0 || !Number.isInteger(intervalDays)) { setErrorMessage('Check-in interval must be an integer greater than 0.'); return; }
    if (graceHours < 0 || !Number.isInteger(graceHours)) { setErrorMessage('Grace period cannot be negative.'); return; }
    if (!recipientName.trim()) { setErrorMessage('Recipient name is required.'); return; }
    if (!recipientEmail.trim() || !recipientEmail.includes('@')) { setErrorMessage('A valid recipient email is required.'); return; }
    if (!user) { setErrorMessage('You must be logged in to create a switch.'); return; }

    setIsLoading(true);
    let createdSwitchId: string | null = null;
    const uploadedStoragePaths: string[] = [];

    try {
      setUploadStatusText('Creating switch configuration...');

      const now = new Date();
      const nextCheckIn = new Date(now.getTime() + intervalDays * 24 * 60 * 60 * 1000);

      const { data: newSwitch, error: switchError } = await supabase
        .from('switches')
        .insert({
          user_id: user.id,
          title: title.trim(),
          description: description.trim() || null,
          interval_days: intervalDays,
          grace_period_hours: graceHours,
          last_check_in: now.toISOString(),
          next_check_in: nextCheckIn.toISOString(),
          status: 'ACTIVE',
        })
        .select('id')
        .single();

      if (switchError) throw switchError;
      if (!newSwitch?.id) throw new Error('Failed to retrieve the new switch ID.');
      createdSwitchId = newSwitch.id;

      const { data: newRecipient, error: recipientError } = await supabase
        .from('switch_recipients')
        .insert({
          switch_id: createdSwitchId,
          recipient_name: recipientName.trim(),
          recipient_email: recipientEmail.trim(),
        })
        .select('id')
        .single();

      if (recipientError) throw recipientError;
      if (!newRecipient?.id) throw new Error('Failed to retrieve recipient ID.');

      // Generate cryptographically random 32-byte delivery key
      const { rawToken, tokenHashPromise } = generateRecipientClaimToken();
      const tokenHash = await tokenHashPromise;
      const tokenExpiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

      // Store recipient claim token & key material in database
      const { error: tokenInsertErr } = await supabase
        .from('recipient_claim_tokens')
        .insert({
          switch_id: createdSwitchId,
          recipient_id: newRecipient.id,
          token_hash: tokenHash,
          key_material: rawToken,
          expires_at: tokenExpiresAt,
        });

      if (tokenInsertErr) throw tokenInsertErr;

      // Derive Key Encryption Keys for owner and recipient
      const ownerKek = await deriveKEK(user.id, 'owner-vault-salt');
      const recipientKek = await deriveKEK(rawToken, 'recipient-claim-salt');

      if (payloadFiles.length > 0) {
        for (let i = 0; i < payloadFiles.length; i++) {
          const file = payloadFiles[i];
          setUploadStatusText(`Encrypting & uploading file ${i + 1} of ${payloadFiles.length}: ${file.name}...`);

          const dek = await generateDEK();
          const { ciphertextBlob, iv, fileHash } = await encryptFile(file, dek);
          const ownerWrapped = await wrapDEK(dek, ownerKek);
          const recipientWrapped = await wrapDEK(dek, recipientKek);

          const fileId = crypto.randomUUID();
          const storagePath = `${user.id}/${createdSwitchId}/${fileId}`;

          const { error: storageError } = await supabase.storage
            .from('dead-man-files')
            .upload(storagePath, ciphertextBlob, {
              cacheControl: '3600',
              upsert: false,
              contentType: 'application/octet-stream',
            });

          if (storageError) throw new Error(`Storage upload failed for ${file.name}: ${storageError.message}`);
          uploadedStoragePaths.push(storagePath);

          const { error: fileDbError } = await supabase
            .from('files')
            .insert({
              switch_id: createdSwitchId,
              storage_path: storagePath,
              original_filename: file.name,
              file_size: file.size,
              encrypted: true,
              file_hash: fileHash,
              iv: iv,
              encrypted_dek_owner: btoa(JSON.stringify(ownerWrapped)),
              encrypted_dek_recipient: btoa(JSON.stringify(recipientWrapped)),
              encryption_version: 'AES-256-GCM-v1',
              mime_type: file.type || 'application/octet-stream',
            });

          if (fileDbError) {
            await supabase.storage.from('dead-man-files').remove([storagePath]);
            throw new Error(`Database error for ${file.name}: ${fileDbError.message}`);
          }
        }
      }

      // Audit log: SWITCH_CREATED
      await supabase.rpc('insert_client_audit_event', {
        p_event_type: 'SWITCH_CREATED',
        p_switch_id: createdSwitchId,
        p_details: {
          title: title.trim(),
          interval_days: intervalDays,
          grace_period_hours: graceHours,
          file_count: payloadFiles.length,
          recipient_email: recipientEmail.trim(),
          delivery_mode: 'AUTOMATIC_EMAIL_LINK',
        },
      });

      setUploadStatusText('Switch created successfully! Redirecting...');
      router.push(`/dashboard/${createdSwitchId}`);

    } catch (error: any) {
      console.error('Error creating switch:', error);
      setErrorMessage(error?.message || 'Failed to create switch. Please try again.');

      if (uploadedStoragePaths.length > 0) {
        try { await supabase.storage.from('dead-man-files').remove(uploadedStoragePaths); } catch { }
      }
      if (createdSwitchId) {
        try { await supabase.from('switches').delete().eq('id', createdSwitchId); } catch { }
      }
    } finally {
      setIsLoading(false);
      setUploadStatusText(null);
    }
  };

  return (
    <div className="space-y-6 max-w-3xl mx-auto">

      {/* Header */}
      <div className="flex items-center gap-3 border-b border-zinc-800 pb-4">
        <Link href="/dashboard">
          <button className="p-1.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-white transition-colors">
            <ArrowLeft className="w-4 h-4" />
          </button>
        </Link>
        <div>
          <h1 className="text-xl font-bold text-zinc-100">Create Dead Man&apos;s Switch</h1>
          <p className="text-xs text-zinc-400">Configure check-in intervals, recipient email, and confidential files.</p>
        </div>
      </div>

      {errorMessage && (
        <div className="p-3 rounded bg-red-950/60 border border-red-800/60 text-red-400 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {uploadStatusText && (
        <div className="p-3 rounded bg-emerald-950/40 border border-emerald-800/60 text-emerald-400 text-xs flex items-center gap-2">
          <Loader2 className="w-4 h-4 shrink-0 animate-spin" />
          <span>{uploadStatusText}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">

        <Card>
          <CardHeader>
            <CardTitle>1. General Details</CardTitle>
            <CardDescription>Name and description for your dead man&apos;s switch.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Input
              label="Switch Title"
              placeholder="e.g. Password Vault & Wallet Keys Backup"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              required
              disabled={isLoading}
            />
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-zinc-300">Description / Instructions</label>
              <textarea
                rows={3}
                className="w-full rounded-md bg-zinc-900 border border-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-1 focus:border-zinc-500 focus:ring-zinc-500 transition-colors disabled:opacity-50"
                placeholder="Explain what this switch is for and instructions for your recipient upon release."
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                disabled={isLoading}
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>2. Check-In Schedule</CardTitle>
            <CardDescription>Determine check-in frequency and emergency grace period.</CardDescription>
          </CardHeader>
          <CardContent className="grid sm:grid-cols-2 gap-4">
            <Input
              label="Check-In Interval (Days)"
              type="number" min={1} max={365}
              value={intervalDays}
              onChange={(e) => setIntervalDays(Number(e.target.value))}
              required disabled={isLoading}
              helperText={`You must check in every ${intervalDays} days.`}
            />
            <Input
              label="Grace Period (Hours)"
              type="number" min={0} max={168}
              value={graceHours}
              onChange={(e) => setGraceHours(Number(e.target.value))}
              required disabled={isLoading}
              helperText={`Wait ${graceHours} hours after deadline before triggering.`}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>3. Emergency Recipient</CardTitle>
            <CardDescription>Who should receive access if check-in is missed?</CardDescription>
          </CardHeader>
          <CardContent className="grid sm:grid-cols-2 gap-4">
            <Input
              label="Recipient Name"
              placeholder="e.g. Sarah Vance"
              value={recipientName}
              onChange={(e) => setRecipientName(e.target.value)}
              required disabled={isLoading}
            />
            <Input
              label="Recipient Email"
              type="email"
              placeholder="sarah@example.com"
              value={recipientEmail}
              onChange={(e) => setRecipientEmail(e.target.value)}
              required disabled={isLoading}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>4. Attach Files</CardTitle>
            <CardDescription>
              Confidential payload files. Each file is encrypted client-side with a unique AES-256-GCM key before upload.
              A recipient-accessible wrapped key is stored so your designated recipient can decrypt after triggering.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <FileUpload
              files={payloadFiles}
              onFilesChange={(files) => setPayloadFiles(files)}
              disabled={isLoading}
            />
          </CardContent>
        </Card>

        {/* Automatic Delivery Notice */}
        <div className="p-3 rounded bg-zinc-900/60 border border-zinc-800 flex items-start gap-2.5 text-xs text-zinc-400">
          <ShieldCheck className="w-4 h-4 shrink-0 mt-0.5 text-emerald-400" />
          <p>
            <strong className="text-zinc-200">Automatic Emergency Delivery:</strong> If you miss your check-in deadline and grace period, an automated emergency email containing a secure, single-use download link will be dispatched directly to your designated recipient. No manual token delivery required.
          </p>
        </div>

        <div className="flex items-center justify-end gap-3 pt-2">
          <Link href="/dashboard">
            <Button variant="ghost" size="md" type="button" disabled={isLoading}>Cancel</Button>
          </Link>
          <Button type="submit" variant="primary" size="md" isLoading={isLoading}>
            Create Switch
          </Button>
        </div>

      </form>
    </div>
  );
}
