'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import Link from 'next/link';
import { useParams, useSearchParams, useRouter } from 'next/navigation';
import {
  ArrowLeft, Clock, User, FileText, Trash2, Download,
  AlertCircle, Plus, UploadCloud, Loader2, Edit,
  CheckCircle2, Key, RefreshCw, Copy, ShieldCheck, AlertTriangle
} from 'lucide-react';
import { DeadManSwitch, PayloadFile, AuditLogEntry } from '@/types/switch';
import { StatusBadge } from '@/components/switch/StatusBadge';
import { Countdown } from '@/components/switch/Countdown';
import { CheckInButton } from '@/components/switch/CheckInButton';
import { AuditLog } from '@/components/switch/AuditLog';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Modal } from '@/components/ui/Modal';
import { useAuth } from '@/context/AuthContext';
import {
  generateDEK, encryptFile, decryptFile,
  deriveKEK, wrapDEK, unwrapDEK,
  generateRecipientClaimToken, bufferToBase64, base64ToBuffer
} from '@/lib/crypto';

export default function SwitchDetailsPage() {
  const router = useRouter();
  const params = useParams();
  const searchParams = useSearchParams();
  const switchId = params?.id as string;
  const { user, loading: authLoading, supabase } = useAuth();

  const [switchItem, setSwitchItem] = useState<DeadManSwitch | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Deactivate modal (for active switches)
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isDeactivating, setIsDeactivating] = useState(false);
  const [isPausing, setIsPausing] = useState(false);

  // Permanent Delete modal (for cancelled / triggered switches)
  const [isPermanentDeleteModalOpen, setIsPermanentDeleteModalOpen] = useState(false);
  const [isPermanentlyDeleting, setIsPermanentlyDeleting] = useState(false);
  const [permanentDeleteError, setPermanentDeleteError] = useState<string | null>(null);
  const [permanentConfirmAcknowledge, setPermanentConfirmAcknowledge] = useState(false);

  // Edit modal
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [editTitle, setEditTitle] = useState('');
  const [editDescription, setEditDescription] = useState('');
  const [editIntervalDays, setEditIntervalDays] = useState<number>(7);
  const [editGraceHours, setEditGraceHours] = useState<number>(48);
  const [editRecipientName, setEditRecipientName] = useState('');
  const [editRecipientEmail, setEditRecipientEmail] = useState('');
  const [editError, setEditError] = useState<string | null>(null);
  const [isSavingEdit, setIsSavingEdit] = useState(false);

  // File upload
  const [isUploadingFile, setIsUploadingFile] = useState(false);
  const [fileActionError, setFileActionError] = useState<string | null>(null);
  const [downloadingFileId, setDownloadingFileId] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Recipient delivery & key material state
  const [switchKeyMaterial, setSwitchKeyMaterial] = useState<string | null>(null);
  const [isTokenModalOpen, setIsTokenModalOpen] = useState(false);
  const [pendingNewToken, setPendingNewToken] = useState<string>('');
  const [isRotatingToken, setIsRotatingToken] = useState(false);
  const [rotateError, setRotateError] = useState<string | null>(null);

  // Audit log
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditError, setAuditError] = useState<string | null>(null);

  // ──────────────────────────────────────────────
  // Fetch switch details
  // ──────────────────────────────────────────────
  const fetchSwitchDetails = useCallback(async () => {
    if (!switchId || !user) return;
    setLoading(true);
    setError(null);
    try {
      const { data, error: fetchErr } = await supabase
        .from('switches')
        .select(`
          id, title, description, status, interval_days, grace_period_hours,
          last_check_in, next_check_in, created_at,
          switch_recipients (id, recipient_name, recipient_email),
          files (id, original_filename, file_size, storage_path, encrypted,
                 file_hash, iv, encrypted_dek_owner, encrypted_dek_recipient,
                 encryption_version, mime_type, created_at)
        `)
        .eq('id', switchId)
        .single();

      if (fetchErr) throw fetchErr;

      setSwitchItem({
        id: data.id, title: data.title, description: data.description || '',
        status: data.status, lastCheckIn: data.last_check_in,
        nextCheckIn: data.next_check_in, checkInIntervalDays: data.interval_days,
        gracePeriodHours: data.grace_period_hours, createdAt: data.created_at,
        recipients: (data.switch_recipients || []).map((r: any) => ({
          id: r.id, name: r.recipient_name, email: r.recipient_email,
        })),
        payloadFiles: (data.files || []).map((f: any) => ({
          id: f.id, name: f.original_filename || 'Unknown file',
          size: f.file_size ? `${(f.file_size / 1024).toFixed(1)} KB` : 'Unknown size',
          mimeType: f.mime_type || 'application/octet-stream',
          uploadedAt: f.created_at, storagePath: f.storage_path,
          encrypted: f.encrypted, fileHash: f.file_hash, iv: f.iv,
          encryptedDekOwner: f.encrypted_dek_owner,
          encryptedDekRecipient: f.encrypted_dek_recipient,
          encryptionVersion: f.encryption_version,
        })),
      });

      // Fetch active recipient claim token to load key_material for automatic delivery
      const { data: tokenData } = await supabase
        .from('recipient_claim_tokens')
        .select('id, key_material, expires_at')
        .eq('switch_id', switchId)
        .is('revoked_at', null)
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();

      setSwitchKeyMaterial(tokenData?.key_material || null);
    } catch (err: any) {
      setError(err?.message || 'Switch not found or access denied.');
    } finally {
      setLoading(false);
    }
  }, [switchId, user, supabase]);

  useEffect(() => {
    if (!authLoading && user) fetchSwitchDetails();
  }, [authLoading, user, fetchSwitchDetails]);

  // ──────────────────────────────────────────────
  // Fetch audit logs for this switch
  // ──────────────────────────────────────────────
  const fetchAuditLogs = useCallback(async () => {
    if (!switchId || !user) return;
    setAuditLoading(true);
    setAuditError(null);
    try {
      const { data, error: logErr } = await supabase
        .from('audit_logs')
        .select('id, user_id, switch_id, action, metadata, created_at')
        .eq('switch_id', switchId)
        .order('created_at', { ascending: false })
        .limit(30);

      if (logErr) throw logErr;

      setAuditLogs(
        (data || []).map((row: any) => ({
          id: row.id,
          userId: row.user_id,
          switchId: row.switch_id,
          eventType: row.action,
          actor: row.metadata?.actor,
          details: row.metadata,
          ipAddress: row.metadata?.ip_address,
          createdAt: row.created_at,
        }))
      );
    } catch (err: any) {
      setAuditError(err?.message || 'Could not load audit logs.');
    } finally {
      setAuditLoading(false);
    }
  }, [switchId, user, supabase]);

  useEffect(() => {
    if (!authLoading && user && switchId) fetchAuditLogs();
  }, [authLoading, user, switchId, fetchAuditLogs]);

  // ──────────────────────────────────────────────
  // Edit modal
  // ──────────────────────────────────────────────
  const handleOpenEditModal = () => {
    if (!switchItem) return;
    setEditTitle(switchItem.title);
    setEditDescription(switchItem.description);
    setEditIntervalDays(switchItem.checkInIntervalDays);
    setEditGraceHours(switchItem.gracePeriodHours);
    const primaryRec = switchItem.recipients[0];
    setEditRecipientName(primaryRec ? primaryRec.name : '');
    setEditRecipientEmail(primaryRec ? primaryRec.email : '');
    setEditError(null);
    setIsEditModalOpen(true);
  };

  const handleSaveEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!switchItem || !user) return;
    setEditError(null);
    if (!editTitle.trim()) { setEditError('Switch title is required.'); return; }
    if (editIntervalDays <= 0 || !Number.isInteger(editIntervalDays)) { setEditError('Interval must be an integer > 0.'); return; }
    if (editGraceHours < 0 || !Number.isInteger(editGraceHours)) { setEditError('Grace period cannot be negative.'); return; }
    if (!editRecipientName.trim()) { setEditError('Recipient name is required.'); return; }
    if (!editRecipientEmail.trim() || !editRecipientEmail.includes('@')) { setEditError('A valid recipient email is required.'); return; }

    setIsSavingEdit(true);
    try {
      // NOTE: next_check_in is NOT sent — trg_validate_switch_update recalculates it from interval_days
      const { error: switchUpdateErr } = await supabase
        .from('switches')
        .update({
          title: editTitle.trim(),
          description: editDescription.trim() || null,
          interval_days: editIntervalDays,
          grace_period_hours: editGraceHours,
        })
        .eq('id', switchItem.id);
      if (switchUpdateErr) throw switchUpdateErr;

      const primaryRec = switchItem.recipients[0];
      if (primaryRec?.id) {
        const { error: recUpdateErr } = await supabase
          .from('switch_recipients')
          .update({ recipient_name: editRecipientName.trim(), recipient_email: editRecipientEmail.trim() })
          .eq('id', primaryRec.id)
          .eq('switch_id', switchItem.id);
        if (recUpdateErr) throw recUpdateErr;
      } else {
        const { error: recInsertErr } = await supabase
          .from('switch_recipients')
          .insert({ switch_id: switchItem.id, recipient_name: editRecipientName.trim(), recipient_email: editRecipientEmail.trim() });
        if (recInsertErr) throw recInsertErr;
      }

      await supabase.rpc('insert_client_audit_event', {
        p_event_type: 'CONFIG_UPDATED',
        p_switch_id: switchItem.id,
        p_details: { title: editTitle.trim(), interval_days: editIntervalDays, grace_period_hours: editGraceHours },
      });

      setIsEditModalOpen(false);
      setSuccessMessage('Switch settings successfully updated.');
      setTimeout(() => setSuccessMessage(null), 4000);
      await fetchSwitchDetails();
      await fetchAuditLogs();
    } catch (err: any) {
      setEditError(err?.message || 'Failed to update switch.');
    } finally {
      setIsSavingEdit(false);
    }
  };

  // ──────────────────────────────────────────────
  // Automatic Delivery Key Rotation / Upgrade
  // ──────────────────────────────────────────────
  const handleStartTokenRotation = () => {
    const { rawToken } = generateRecipientClaimToken();
    setPendingNewToken(rawToken);
    setRotateError(null);
    setIsTokenModalOpen(true);
  };

  const handleConfirmRotation = async () => {
    if (!switchItem || !user || !pendingNewToken) return;
    setIsRotatingToken(true);
    setRotateError(null);

    try {
      const primaryRec = switchItem.recipients[0];
      if (!primaryRec?.id) throw new Error('No recipient found for this switch.');

      // 1. Hash the new raw token for database lookup indexing
      const encoder = new TextEncoder();
      const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(pendingNewToken));
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const newTokenHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      const newExpiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

      // 2. Derive keys
      const ownerKek = await deriveKEK(user.id, 'owner-vault-salt');
      const newRecipientKek = await deriveKEK(pendingNewToken, 'recipient-claim-salt');

      // 3. Re-wrap all encrypted files' DEKs with the new recipient KEK
      const encryptedFiles = switchItem.payloadFiles.filter(f => f.encrypted && f.encryptedDekOwner);
      for (const file of encryptedFiles) {
        const envelope = JSON.parse(atob(file.encryptedDekOwner!));
        const dek = await unwrapDEK(envelope.wrappedKey, envelope.iv, ownerKek);
        const newRecipientWrapped = await wrapDEK(dek, newRecipientKek);
        const newEncryptedDekRecipient = btoa(JSON.stringify(newRecipientWrapped));

        const { error: updateErr } = await supabase.rpc('update_file_recipient_dek', {
          p_switch_id: switchItem.id,
          p_file_id: file.id,
          p_encrypted_dek_recipient: newEncryptedDekRecipient,
        });
        if (updateErr) throw new Error(`Failed to re-wrap DEK for ${file.name}: ${updateErr.message}`);
      }

      // 4. Rotate the token in DB (revokes old, inserts new hash + key_material)
      const { error: rotateErr } = await supabase.rpc('rotate_claim_token', {
        p_switch_id: switchItem.id,
        p_recipient_id: primaryRec.id,
        p_new_token_hash: newTokenHash,
        p_expires_at: newExpiresAt,
        p_key_material: pendingNewToken,
      });
      if (rotateErr) throw rotateErr;

      // 5. Update state
      setSwitchKeyMaterial(pendingNewToken);
      setIsTokenModalOpen(false);
      setPendingNewToken('');

      setSuccessMessage(
        encryptedFiles.length > 0
          ? `Emergency grant rotated. ${encryptedFiles.length} file key(s) re-wrapped for automatic recipient delivery.`
          : 'Automatic recipient delivery configured. Future uploads will be encrypted with this grant.'
      );
      setTimeout(() => setSuccessMessage(null), 5000);
      await fetchSwitchDetails();
      await fetchAuditLogs();
    } catch (err: any) {
      setRotateError(err?.message || 'Key rotation failed.');
    } finally {
      setIsRotatingToken(false);
    }
  };

  // ──────────────────────────────────────────────
  // File upload (with automatic recipient DEK wrapping)
  // ──────────────────────────────────────────────
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0 || !user || !switchItem) return;

    if (!switchKeyMaterial) {
      setFileActionError(
        'This switch uses legacy delivery. Please click "Enable Automatic Delivery" above before uploading new files.'
      );
      e.target.value = '';
      return;
    }

    setIsUploadingFile(true);
    setFileActionError(null);
    const file = files[0];
    const fileId = crypto.randomUUID();
    const storagePath = `${user.id}/${switchItem.id}/${fileId}`;

    try {
      const dek = await generateDEK();
      const { ciphertextBlob, iv, fileHash } = await encryptFile(file, dek);

      const ownerKek = await deriveKEK(user.id, 'owner-vault-salt');
      const recipientKek = await deriveKEK(switchKeyMaterial, 'recipient-claim-salt');
      const ownerWrapped = await wrapDEK(dek, ownerKek);
      const recipientWrapped = await wrapDEK(dek, recipientKek);

      const { error: storageErr } = await supabase.storage
        .from('dead-man-files')
        .upload(storagePath, ciphertextBlob, {
          cacheControl: '3600', upsert: false, contentType: 'application/octet-stream',
        });
      if (storageErr) throw storageErr;

      const { error: dbErr } = await supabase
        .from('files')
        .insert({
          switch_id: switchItem.id,
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

      if (dbErr) {
        await supabase.storage.from('dead-man-files').remove([storagePath]);
        throw dbErr;
      }

      await supabase.rpc('insert_client_audit_event', {
        p_event_type: 'FILE_UPLOADED',
        p_switch_id: switchItem.id,
        p_details: { filename: file.name, size_bytes: file.size, encrypted: true },
      });

      await fetchSwitchDetails();
      await fetchAuditLogs();
      setSuccessMessage(`File "${file.name}" encrypted (AES-256-GCM) and uploaded with recipient key.`);
      setTimeout(() => setSuccessMessage(null), 4000);
    } catch (err: any) {
      setFileActionError(err?.message || 'Failed to upload and encrypt file.');
    } finally {
      setIsUploadingFile(false);
      e.target.value = '';
    }
  };

  // ──────────────────────────────────────────────
  // Owner download/decrypt
  // ──────────────────────────────────────────────
  const handlePreviewDownload = async (file: PayloadFile) => {
    if (!file.storagePath || !user) { setFileActionError('Storage path or user session is missing.'); return; }
    setDownloadingFileId(file.id);
    setFileActionError(null);

    try {
      const { data, error: signErr } = await supabase.storage
        .from('dead-man-files')
        .createSignedUrl(file.storagePath, 60, { download: file.name });
      if (signErr) throw signErr;
      if (!data?.signedUrl) throw new Error('Could not create signed download URL.');

      if (file.encrypted && file.iv && file.encryptedDekOwner) {
        const response = await fetch(data.signedUrl);
        if (!response.ok) throw new Error('Failed to download ciphertext from storage.');
        const ciphertextBuffer = await response.arrayBuffer();
        const ownerKek = await deriveKEK(user.id, 'owner-vault-salt');
        const envelope = JSON.parse(atob(file.encryptedDekOwner));
        const dek = await unwrapDEK(envelope.wrappedKey, envelope.iv, ownerKek);
        const decryptedBlob = await decryptFile(ciphertextBuffer, file.iv, dek, file.mimeType);
        const blobUrl = URL.createObjectURL(decryptedBlob);
        const a = document.createElement('a');
        a.href = blobUrl;
        a.download = file.name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(blobUrl);
        setSuccessMessage(`Decrypted "${file.name}" with owner vault key.`);
        setTimeout(() => setSuccessMessage(null), 3000);
      } else {
        window.open(data.signedUrl, '_blank');
      }
    } catch (err: any) {
      setFileActionError(err?.message || 'Could not retrieve or decrypt file.');
    } finally {
      setDownloadingFileId(null);
    }
  };

  // ──────────────────────────────────────────────
  // File delete
  // ──────────────────────────────────────────────
  const handleDeleteFile = async (file: PayloadFile) => {
    if (!confirm(`Are you sure you want to remove "${file.name}"?`)) return;
    setFileActionError(null);
    try {
      const { error: dbErr } = await supabase.from('files').delete().eq('id', file.id);
      if (dbErr) throw dbErr;
      if (file.storagePath) await supabase.storage.from('dead-man-files').remove([file.storagePath]);

      await supabase.rpc('insert_client_audit_event', {
        p_event_type: 'FILE_DELETED',
        p_switch_id: switchItem!.id,
        p_details: { filename: file.name },
      });

      setSwitchItem((prev) =>
        prev ? { ...prev, payloadFiles: prev.payloadFiles.filter((f) => f.id !== file.id) } : null
      );
      setSuccessMessage(`File "${file.name}" removed.`);
      setTimeout(() => setSuccessMessage(null), 3000);
      await fetchAuditLogs();
    } catch (err: any) {
      setFileActionError(err?.message || 'Failed to delete file.');
    }
  };

  // ──────────────────────────────────────────────
  // Check-in via RPC
  // ──────────────────────────────────────────────
  const handleCheckIn = async () => {
    if (!switchItem || !user) return;
    try {
      const { data, error: rpcError } = await supabase.rpc('perform_check_in', { p_switch_id: switchItem.id });
      if (rpcError) throw rpcError;
      if (data?.success) {
        setSwitchItem((prev) =>
          prev ? { ...prev, status: data.status || 'ACTIVE', lastCheckIn: data.last_check_in, nextCheckIn: data.next_check_in } : null
        );
      } else {
        await fetchSwitchDetails();
      }
      setSuccessMessage('Check-in confirmed! Deadline reset.');
      setTimeout(() => setSuccessMessage(null), 4000);
      await fetchAuditLogs();
    } catch (err: any) {
      alert('Failed to check in: ' + (err?.message || 'Unknown error'));
    }
  };

  // ──────────────────────────────────────────────
  // Cancel switch
  // ──────────────────────────────────────────────
  const handleCancelSwitch = async () => {
    if (!switchItem) return;
    setIsDeactivating(true);
    try {
      const { error: updateErr } = await supabase.rpc('cancel_switch', { p_switch_id: switchItem.id });
      if (updateErr) throw updateErr;
      setSwitchItem((prev) => prev ? { ...prev, status: 'CANCELLED' } : null);
      setIsDeleteModalOpen(false);
      setSuccessMessage('Switch has been deactivated.');
      setTimeout(() => setSuccessMessage(null), 4000);
      await fetchAuditLogs();
    } catch (err: any) {
      alert('Failed to cancel switch: ' + (err?.message || 'Unknown error'));
    } finally {
      setIsDeactivating(false);
    }
  };

  // ──────────────────────────────────────────────
  // Pause / Resume Switch (PAUSED Status Lifecycle)
  // ──────────────────────────────────────────────
  const handlePauseSwitch = async () => {
    if (!switchItem || isPausing) return;
    setIsPausing(true);
    try {
      const { error: rpcErr } = await supabase.rpc('pause_switch', { p_switch_id: switchItem.id });
      if (rpcErr) {
        const { error: updateErr } = await supabase
          .from('switches')
          .update({ status: 'PAUSED', updated_at: new Date().toISOString() })
          .eq('id', switchItem.id);
        if (updateErr) throw updateErr;
      }
      setSwitchItem((prev) => prev ? { ...prev, status: 'PAUSED' } : null);
      setSuccessMessage('Switch has been paused. Countdown is frozen.');
      setTimeout(() => setSuccessMessage(null), 4000);
      await fetchAuditLogs();
    } catch (err: any) {
      alert('Failed to pause switch: ' + (err?.message || 'Unknown error'));
    } finally {
      setIsPausing(false);
    }
  };

  const handleResumeSwitch = async () => {
    if (!switchItem || isPausing) return;
    setIsPausing(true);
    try {
      const { error: rpcErr } = await supabase.rpc('resume_switch', { p_switch_id: switchItem.id });
      if (rpcErr) {
        const nextCheckIn = new Date(Date.now() + switchItem.checkInIntervalDays * 86400000).toISOString();
        const { error: updateErr } = await supabase
          .from('switches')
          .update({
            status: 'ACTIVE',
            last_check_in: new Date().toISOString(),
            next_check_in: nextCheckIn,
            updated_at: new Date().toISOString()
          })
          .eq('id', switchItem.id);
        if (updateErr) throw updateErr;
      }
      setSuccessMessage('Switch resumed successfully. Timer reset.');
      setTimeout(() => setSuccessMessage(null), 4000);
      await fetchSwitchDetails();
      await fetchAuditLogs();
    } catch (err: any) {
      alert('Failed to resume switch: ' + (err?.message || 'Unknown error'));
    } finally {
      setIsPausing(false);
    }
  };

  // Permanent Delete for CANCELLED or TRIGGERED switch
  const handlePermanentDeleteSwitch = async () => {
    if (!switchItem || !user || isPermanentlyDeleting) return;

    if (!permanentConfirmAcknowledge) {
      setPermanentDeleteError('Please acknowledge the permanent deletion warning before proceeding.');
      return;
    }

    setIsPermanentlyDeleting(true);
    setPermanentDeleteError(null);

    try {
      if (switchItem.status !== 'CANCELLED' && switchItem.status !== 'TRIGGERED') {
        throw new Error(`Cannot delete switch with status "${switchItem.status}". Only CANCELLED and TRIGGERED switches may be deleted.`);
      }

      // Remove storage files from private vault
      const { data: files, error: filesErr } = await supabase
        .from('files')
        .select('id, storage_path')
        .eq('switch_id', switchItem.id);

      if (filesErr) throw new Error(`Failed to check files: ${filesErr.message}`);

      const storagePrefix = `${user.id}/${switchItem.id}/`;
      const storagePathsToDelete: string[] = [];

      if (files && files.length > 0) {
        const filePaths = files
          .map((f: any) => f.storage_path)
          .filter((path: string) => typeof path === 'string' && path.startsWith(storagePrefix));
        storagePathsToDelete.push(...filePaths);
      }

      // Also clean up any unindexed vault files in this switch folder
      try {
        const { data: storageList } = await supabase.storage
          .from('dead-man-files')
          .list(`${user.id}/${switchItem.id}`);

        if (storageList && storageList.length > 0) {
          for (const item of storageList) {
            const path = `${storagePrefix}${item.name}`;
            if (!storagePathsToDelete.includes(path)) {
              storagePathsToDelete.push(path);
            }
          }
        }
      } catch (listErr) {
        console.warn('Storage directory listing warning:', listErr);
      }

      if (storagePathsToDelete.length > 0) {
        const { error: storageErr } = await supabase.storage
          .from('dead-man-files')
          .remove(storagePathsToDelete);

        if (storageErr) {
          throw new Error(`Storage file cleanup failed: ${storageErr.message}. Switch was not deleted.`);
        }
      }

      // Record audit log
      await supabase.rpc('insert_client_audit_event', {
        p_event_type: 'SWITCH_DELETED',
        p_switch_id: switchItem.id,
        p_details: {
          switch_title: switchItem.title,
          switch_status: switchItem.status,
          deleted_switch_id: switchItem.id,
          file_count: files?.length || 0,
        },
      });

      // Delete switch from database (cascades to related tables)
      const { error: delErr } = await supabase
        .from('switches')
        .delete()
        .eq('id', switchItem.id);

      if (delErr) throw delErr;

      router.push('/dashboard');
    } catch (err: any) {
      console.error('Failed to permanently delete switch:', err);
      setPermanentDeleteError(err?.message || 'Failed to delete switch.');
    } finally {
      setIsPermanentlyDeleting(false);
    }
  };

  const formatDate = (isoString: string) => {
    try {
      return new Date(isoString).toLocaleDateString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit',
      });
    } catch { return isoString; }
  };

  if (authLoading || loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center space-y-3">
          <div className="w-6 h-6 border-2 border-zinc-600 border-t-emerald-400 rounded-full animate-spin mx-auto" />
          <p className="text-xs text-zinc-500">Loading switch details...</p>
        </div>
      </div>
    );
  }

  if (error || !switchItem) {
    return (
      <div className="max-w-md mx-auto py-16 text-center space-y-4">
        <AlertCircle className="w-8 h-8 text-red-400 mx-auto" />
        <div>
          <h2 className="text-base font-semibold text-zinc-100">Switch Not Found</h2>
          <p className="text-xs text-zinc-400">{error || 'Could not load this switch.'}</p>
        </div>
        <Link href="/dashboard"><Button variant="outline" size="sm">Back to Dashboard</Button></Link>
      </div>
    );
  }

  const isActive = switchItem.status === 'ACTIVE' || switchItem.status === 'PENDING_GRACE';
  const isPaused = switchItem.status === 'PAUSED';
  const primaryRecipient = switchItem.recipients[0];

  return (
    <div className="space-y-6 max-w-4xl mx-auto">

      {/* Emergency Grant Rotation / Upgrade Modal */}
      <Modal
        isOpen={isTokenModalOpen}
        onClose={() => { if (!isRotatingToken) { setIsTokenModalOpen(false); setPendingNewToken(''); } }}
        title={switchKeyMaterial ? "Rotate Emergency Access Grant" : "Enable Automatic Recipient Delivery"}
        description={switchKeyMaterial 
          ? "A new secure download link and cryptographic keys will be generated. All existing files will be re-encrypted. Any previous download links will be revoked."
          : "Upgrade this switch to Automatic Recipient Delivery. All existing files will be seamlessly re-encrypted so your recipient can access them securely via email upon release."}
        size="md"
        footer={
          <>
            <Button variant="ghost" size="sm" onClick={() => { setIsTokenModalOpen(false); setPendingNewToken(''); }} disabled={isRotatingToken}>
              Cancel
            </Button>
            <Button variant="primary" size="sm" onClick={handleConfirmRotation} isLoading={isRotatingToken}>
              {switchKeyMaterial ? 'Confirm & Re-Key' : 'Enable & Re-Key Files'}
            </Button>
          </>
        }
      >
        <div className="space-y-4 text-xs">
          {rotateError && (
            <div className="p-2.5 rounded bg-red-950/60 border border-red-800/60 text-red-400 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{rotateError}</span>
            </div>
          )}
          <div className="p-3 rounded bg-zinc-900 border border-zinc-800 text-zinc-300 text-xs space-y-2">
            <p className="font-semibold text-emerald-400 flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4" />
              Zero-Friction Recipient Delivery
            </p>
            <ul className="list-disc ml-4 space-y-1 text-zinc-400 text-[11px]">
              <li>Your recipient (<strong>{primaryRecipient?.email || 'emergency contact'}</strong>) will automatically receive an email with a secure download link if this switch triggers.</li>
              <li>No manual token copying or handoff is required.</li>
              <li>The recipient verifies their identity by confirming their authorized email address before files are unlocked.</li>
              <li>All payload file encryption keys (DEKs) are re-wrapped locally in your browser.</li>
            </ul>
          </div>
        </div>
      </Modal>

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-4">
        <div className="flex items-center gap-3">
          <Link href="/dashboard">
            <button className="p-1.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-white transition-colors">
              <ArrowLeft className="w-4 h-4" />
            </button>
          </Link>
          <div>
            <div className="flex items-center gap-2 mb-1">
              <StatusBadge status={switchItem.status} size="sm" />
            </div>
            <h1 className="text-xl font-bold text-zinc-100">{switchItem.title}</h1>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isActive ? (
            <>
              <Button variant="outline" size="sm" onClick={handlePauseSwitch} disabled={isPausing}>
                {isPausing ? 'Pausing...' : 'Pause Switch'}
              </Button>
              <Button variant="outline" size="sm" leftIcon={<Edit className="w-3.5 h-3.5" />} onClick={handleOpenEditModal}>
                Edit
              </Button>
              <Button variant="danger" size="sm" leftIcon={<Trash2 className="w-3.5 h-3.5" />} onClick={() => setIsDeleteModalOpen(true)}>
                Deactivate
              </Button>
            </>
          ) : isPaused ? (
            <>
              <Button variant="primary" size="sm" onClick={handleResumeSwitch} disabled={isPausing}>
                {isPausing ? 'Resuming...' : 'Resume Switch'}
              </Button>
              <Button variant="outline" size="sm" leftIcon={<Edit className="w-3.5 h-3.5" />} onClick={handleOpenEditModal}>
                Edit
              </Button>
              <Button variant="danger" size="sm" leftIcon={<Trash2 className="w-3.5 h-3.5" />} onClick={() => setIsDeleteModalOpen(true)}>
                Deactivate
              </Button>
            </>
          ) : (
            <Button
              variant="danger"
              size="sm"
              leftIcon={<Trash2 className="w-3.5 h-3.5" />}
              onClick={() => {
                setPermanentDeleteError(null);
                setIsPermanentDeleteModalOpen(true);
              }}
            >
              Delete Switch
            </Button>
          )}
        </div>
      </div>

      {successMessage && (
        <div className="p-3 rounded bg-emerald-950/50 border border-emerald-800/60 text-emerald-400 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{successMessage}</span>
        </div>
      )}

      {switchItem.description && (
        <Card className="p-4 bg-zinc-900/40 border-zinc-800">
          <p className="text-xs text-zinc-400 font-medium mb-1">Instructions / Description</p>
          <p className="text-sm text-zinc-200 whitespace-pre-wrap">{switchItem.description}</p>
        </Card>
      )}

      {/* Countdown & CheckIn */}
      <Card className="p-5">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <p className="text-xs text-zinc-400 font-medium">Status & Countdown</p>
            <Countdown targetDate={switchItem.nextCheckIn} status={switchItem.status} />
          </div>
          <CheckInButton
            switchId={switchItem.id}
            switchTitle={switchItem.title}
            disabled={!isActive}
            onCheckInSuccess={handleCheckIn}
            size="md"
          />
        </div>
      </Card>

      <div className="grid md:grid-cols-2 gap-4">
        {/* Timing */}
        <Card>
          <CardHeader><CardTitle className="text-sm font-semibold flex items-center gap-2"><Clock className="w-4 h-4 text-zinc-400" />Schedule Details</CardTitle></CardHeader>
          <CardContent className="space-y-2.5 text-xs">
            {[
              ['Check-In Interval', `${switchItem.checkInIntervalDays} Days`],
              ['Grace Period', `${switchItem.gracePeriodHours} Hours`],
              ['Last Check-In', formatDate(switchItem.lastCheckIn)],
              ['Next Deadline', formatDate(switchItem.nextCheckIn)],
            ].map(([label, val]) => (
              <div key={label} className="flex justify-between py-1 border-b border-zinc-800/80 last:border-0">
                <span className="text-zinc-400">{label}</span>
                <span className="text-zinc-200 font-medium">{val}</span>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Recipients */}
        <Card>
          <CardHeader><CardTitle className="text-sm font-semibold flex items-center gap-2"><User className="w-4 h-4 text-zinc-400" />Designated Recipients</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-xs">
            {switchItem.recipients.map((rec) => (
              <div key={rec.id} className="p-2.5 rounded bg-zinc-950/60 border border-zinc-800 text-xs">
                <p className="font-semibold text-zinc-200">{rec.name}</p>
                <p className="text-zinc-400 font-mono text-[11px]">{rec.email}</p>
              </div>
            ))}
            {switchItem.recipients.length === 0 && <p className="text-xs text-zinc-500 py-2">No recipients configured.</p>}
          </CardContent>
        </Card>
      </div>

      {/* Token Session Card — only for active/pending_grace switches */}
      {isActive && (
        <Card className="border-zinc-800">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2 text-zinc-100">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                Automatic Recipient Delivery
              </CardTitle>
              {switchKeyMaterial ? (
                <span className="text-[11px] px-2 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-800/80 text-emerald-400 font-medium">
                  Active & Secured
                </span>
              ) : (
                <span className="text-[11px] px-2 py-0.5 rounded-full bg-amber-950/80 border border-amber-800/80 text-amber-400 font-medium">
                  Legacy Switch
                </span>
              )}
            </div>
          </CardHeader>
          <CardContent className="text-xs space-y-3">
            {switchKeyMaterial ? (
              <div className="p-3 rounded bg-zinc-900/60 border border-zinc-800 text-zinc-300 space-y-1">
                <p className="font-medium text-zinc-200">
                  Automated Emergency Dispatch Configured
                </p>
                <p className="text-[11px] text-zinc-400">
                  If check-in deadline and grace period expire, an emergency notification containing a secure, single-use download link will be dispatched automatically to <strong className="text-zinc-200">{primaryRecipient?.email}</strong>. No manual token delivery required.
                </p>
              </div>
            ) : (
              <div className="p-3 rounded bg-amber-950/20 border border-amber-800/40 text-amber-300 space-y-1">
                <p className="font-semibold text-amber-200">Legacy Manual Token Mode</p>
                <p className="text-[11px] text-amber-300/80">
                  This switch was created before Automatic Recipient Delivery was enabled. Upgrade to enable automatic email dispatch and seamless file uploads.
                </p>
              </div>
            )}
            <div className="flex items-center gap-3">
              <Button
                variant={switchKeyMaterial ? "outline" : "primary"}
                size="sm"
                leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
                onClick={handleStartTokenRotation}
              >
                {switchKeyMaterial ? 'Rotate Emergency Link & Keys' : 'Enable Automatic Delivery'}
              </Button>
            </div>
            <p className="text-zinc-500 text-[10px]">
              {switchKeyMaterial
                ? 'Rotating revokes any previous link and generates a fresh cryptographic grant for your recipient.'
                : 'Upgrading re-wraps existing file keys and generates a secure delivery grant.'}
            </p>
          </CardContent>
        </Card>
      )}

      {/* Payload Files */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <FileText className="w-4 h-4 text-zinc-400" />
            Payload Files ({switchItem.payloadFiles.length})
          </CardTitle>
          {isActive && (
            <div>
              <input ref={fileInputRef} type="file" className="hidden" disabled={isUploadingFile} onChange={handleFileUpload} />
              <Button
                variant="outline" size="sm"
                isLoading={isUploadingFile}
                onClick={() => fileInputRef.current?.click()}
                leftIcon={<Plus className="w-3.5 h-3.5" />}
              >
                Upload File
              </Button>
            </div>
          )}
        </CardHeader>
        <CardContent className="space-y-3">
          {fileActionError && (
            <div className="p-2.5 rounded bg-red-950/60 border border-red-800/60 text-red-400 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" /><span>{fileActionError}</span>
            </div>
          )}

          {!switchKeyMaterial && isActive && (
            <div className="p-2.5 rounded bg-amber-950/30 border border-amber-800/50 text-amber-400 text-[11px] flex items-center gap-2">
              <AlertCircle className="w-3.5 h-3.5 shrink-0" />
              <span>Enable Automatic Delivery above before uploading new files.</span>
            </div>
          )}

          {switchItem.payloadFiles.map((file) => (
            <div key={file.id} className="flex items-center justify-between p-3 rounded bg-zinc-950/60 border border-zinc-800 text-xs hover:border-zinc-700 transition-colors">
              <div className="flex items-center gap-3 min-w-0">
                <div className="p-2 rounded bg-zinc-900 border border-zinc-800 text-emerald-400 shrink-0">
                  <FileText className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <p className="font-medium text-zinc-200 truncate">{file.name}</p>
                  <div className="flex items-center gap-2 text-[10px] text-zinc-500 mt-0.5">
                    <span className="font-mono">{file.size}</span>
                    <span>•</span>
                    <span className={file.encrypted ? 'text-emerald-400/80' : 'text-zinc-400'}>
                      {file.encrypted ? 'AES-256-GCM' : 'Plaintext'}
                    </span>
                    {file.encryptedDekRecipient
                      ? <span className="text-emerald-600">• Recipient key ✓</span>
                      : file.encrypted
                        ? <span className="text-amber-600">• No recipient key</span>
                        : null
                    }
                    {file.fileHash && (
                      <><span>•</span><span className="font-mono text-[9px] text-zinc-600 truncate max-w-[120px]" title={`SHA-256: ${file.fileHash}`}>SHA-256: {file.fileHash.slice(0, 8)}...</span></>
                    )}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0 ml-3">
                <Button variant="outline" size="sm" isLoading={downloadingFileId === file.id} onClick={() => handlePreviewDownload(file)} leftIcon={<Download className="w-3.5 h-3.5" />}>
                  Download
                </Button>
                {isActive && (
                  <button type="button" onClick={() => handleDeleteFile(file)} className="p-1.5 text-zinc-500 hover:text-red-400 rounded hover:bg-zinc-900 transition-colors" title="Remove file">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>
          ))}

          {switchItem.payloadFiles.length === 0 && (
            <div className="text-center py-8 border border-dashed border-zinc-800 rounded-lg space-y-2">
              <UploadCloud className="w-6 h-6 text-zinc-600 mx-auto" />
              <p className="text-xs text-zinc-400 font-medium">No payload files attached.</p>
              <p className="text-[11px] text-zinc-500">Upload confidential documents into the private vault.</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Audit Log */}
      <AuditLog
        logs={auditLogs}
        title={`Activity Log — ${switchItem.title}`}
        isLoading={auditLoading}
        error={auditError}
      />

      {/* Edit Modal */}
      <Modal isOpen={isEditModalOpen} onClose={() => !isSavingEdit && setIsEditModalOpen(false)}
        title="Edit Dead Man's Switch"
        description="Update schedule, details, or emergency recipient."
        size="md"
        footer={
          <>
            <Button variant="ghost" size="sm" type="button" onClick={() => setIsEditModalOpen(false)} disabled={isSavingEdit}>Cancel</Button>
            <Button variant="primary" size="sm" type="button" onClick={handleSaveEdit} isLoading={isSavingEdit}>Save Changes</Button>
          </>
        }
      >
        <form onSubmit={handleSaveEdit} className="space-y-4 text-xs">
          {editError && (
            <div className="p-2.5 rounded bg-red-950/60 border border-red-800/60 text-red-400 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" /><span>{editError}</span>
            </div>
          )}
          <Input label="Switch Title" value={editTitle} onChange={(e) => setEditTitle(e.target.value)} required disabled={isSavingEdit} />
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-zinc-300">Description</label>
            <textarea rows={3} className="w-full rounded-md bg-zinc-900 border border-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-1 focus:border-zinc-500 focus:ring-zinc-500 transition-colors disabled:opacity-50"
              value={editDescription} onChange={(e) => setEditDescription(e.target.value)} disabled={isSavingEdit} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Input label="Interval (Days)" type="number" min={1} max={365} value={editIntervalDays} onChange={(e) => setEditIntervalDays(Number(e.target.value))} required disabled={isSavingEdit} />
            <Input label="Grace Period (Hours)" type="number" min={0} max={168} value={editGraceHours} onChange={(e) => setEditGraceHours(Number(e.target.value))} required disabled={isSavingEdit} />
          </div>
          <div className="pt-2 border-t border-zinc-800 space-y-3">
            <p className="font-semibold text-zinc-200 text-xs">Emergency Recipient</p>
            <div className="grid grid-cols-2 gap-3">
              <Input label="Recipient Name" value={editRecipientName} onChange={(e) => setEditRecipientName(e.target.value)} required disabled={isSavingEdit} />
              <Input label="Recipient Email" type="email" value={editRecipientEmail} onChange={(e) => setEditRecipientEmail(e.target.value)} required disabled={isSavingEdit} />
            </div>
          </div>
        </form>
      </Modal>

      {/* Deactivate Modal */}
      <Modal isOpen={isDeleteModalOpen} onClose={() => setIsDeleteModalOpen(false)}
        title="Deactivate Switch"
        description="Are you sure you want to deactivate this dead man's switch?"
        footer={
          <>
            <Button variant="ghost" size="sm" onClick={() => setIsDeleteModalOpen(false)} disabled={isDeactivating}>Cancel</Button>
            <Button variant="danger" size="sm" onClick={handleCancelSwitch} isLoading={isDeactivating}>Deactivate</Button>
          </>
        }
      >
        <p className="text-xs text-zinc-400">
          Deactivating sets status to CANCELLED, halts countdown monitoring, revokes claim tokens, and cancels emergency releases.
        </p>
      </Modal>

      {/* Permanent Delete Modal for Cancelled/Triggered switch */}
      <Modal
        isOpen={isPermanentDeleteModalOpen}
        onClose={() => {
          if (!isPermanentlyDeleting) {
            setIsPermanentDeleteModalOpen(false);
            setPermanentDeleteError(null);
            setPermanentConfirmAcknowledge(false);
          }
        }}
        title="Delete Dead Man's Switch"
        description="Permanently delete this switch and all associated data."
        size="md"
        footer={
          <>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setIsPermanentDeleteModalOpen(false);
                setPermanentDeleteError(null);
                setPermanentConfirmAcknowledge(false);
              }}
              disabled={isPermanentlyDeleting}
            >
              Cancel
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={handlePermanentDeleteSwitch}
              isLoading={isPermanentlyDeleting}
              disabled={isPermanentlyDeleting || !permanentConfirmAcknowledge}
              leftIcon={<Trash2 className="w-3.5 h-3.5" />}
            >
              Delete Permanently
            </Button>
          </>
        }
      >
        <div className="space-y-4 text-xs">
          {permanentDeleteError && (
            <div className="p-2.5 rounded bg-red-950/60 border border-red-800/60 text-red-400 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{permanentDeleteError}</span>
            </div>
          )}

          <div className="p-3 rounded bg-zinc-950/60 border border-zinc-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-zinc-200 text-sm">{switchItem.title}</span>
              <StatusBadge status={switchItem.status} size="sm" />
            </div>
            <div className="pt-1 text-[11px] text-zinc-500 flex gap-4">
              <span>Files attached: {switchItem.payloadFiles.length}</span>
              <span>Recipients: {switchItem.recipients.length}</span>
            </div>
          </div>

          <div className="p-3 rounded bg-red-950/30 border border-red-800/50 text-red-300 text-xs space-y-2">
            <p className="font-semibold flex items-center gap-1.5 text-red-400">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              Permanent Deletion Warning
            </p>
            <ul className="list-disc ml-4 space-y-1 text-red-300/80 text-[11px]">
              <li>This action is <strong>permanent</strong> and cannot be undone.</li>
              <li>All encrypted files stored in the private vault will be permanently purged.</li>
              <li>Emergency access tokens and check-in schedules will be deleted from the database.</li>
              <li><strong>Notice:</strong> Deletion cannot undo emails already sent or files already downloaded by recipients.</li>
            </ul>
          </div>

          <label className="flex items-start gap-2.5 p-2 rounded bg-zinc-950/40 border border-zinc-800/80 text-zinc-300 cursor-pointer select-none hover:border-zinc-700 transition-colors">
            <input
              type="checkbox"
              checked={permanentConfirmAcknowledge}
              onChange={(e) => setPermanentConfirmAcknowledge(e.target.checked)}
              disabled={isPermanentlyDeleting}
              className="mt-0.5 rounded bg-zinc-900 border-zinc-700 text-red-500 focus:ring-red-500/30"
            />
            <span className="text-[11px] leading-relaxed">
              I understand that deleting <strong>{switchItem.title}</strong> is permanent and irreversible.
            </span>
          </label>
        </div>
      </Modal>
    </div>
  );
}
