'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { Plus, Search, Layers, ShieldCheck, AlertCircle, Slash, RefreshCw, Trash2, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/Modal';
import { SwitchCard } from '@/components/switch/SwitchCard';
import { StatusBadge } from '@/components/switch/StatusBadge';
import { AuditLog } from '@/components/switch/AuditLog';
import { DeadManSwitch, AuditLogEntry } from '@/types/switch';
import { useAuth } from '@/context/AuthContext';

export default function DashboardPage() {
  const { user, loading: authLoading, supabase } = useAuth();
  const [switches, setSwitches] = useState<DeadManSwitch[]>([]);
  const [loadingSwitches, setLoadingSwitches] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedFilter, setSelectedFilter] = useState<string>('ALL');

  // Audit logs state
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [loadingLogs, setLoadingLogs] = useState<boolean>(true);
  const [logError, setLogError] = useState<string | null>(null);

  // Deletion state
  const [switchToDelete, setSwitchToDelete] = useState<DeadManSwitch | null>(null);
  const [isDeletingSwitch, setIsDeletingSwitch] = useState<boolean>(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [confirmAcknowledge, setConfirmAcknowledge] = useState<boolean>(false);

  const userName = user?.user_metadata?.full_name || user?.email?.split('@')[0] || 'Operator';

  // Fetch switches belonging to authenticated user
  const fetchSwitches = useCallback(async () => {
    if (!user) return;
    setLoadingSwitches(true);
    setError(null);

    try {
      const { data, error: fetchError } = await supabase
        .from('switches')
        .select(`
          id,
          title,
          description,
          status,
          interval_days,
          grace_period_hours,
          last_check_in,
          next_check_in,
          created_at,
          switch_recipients (
            id,
            recipient_name,
            recipient_email
          ),
          files (
            id,
            original_filename,
            file_size,
            encrypted,
            created_at
          )
        `)
        .order('created_at', { ascending: false });

      if (fetchError) {
        throw fetchError;
      }

      // Map Supabase relational rows into DeadManSwitch UI structure
      const formattedSwitches: DeadManSwitch[] = (data || []).map((row: any) => ({
        id: row.id,
        title: row.title,
        description: row.description || '',
        status: row.status,
        lastCheckIn: row.last_check_in,
        nextCheckIn: row.next_check_in,
        checkInIntervalDays: row.interval_days,
        gracePeriodHours: row.grace_period_hours,
        recipients: (row.switch_recipients || []).map((r: any) => ({
          id: r.id,
          name: r.recipient_name,
          email: r.recipient_email,
        })),
        payloadFiles: (row.files || []).map((f: any) => ({
          id: f.id,
          name: f.original_filename || 'Unknown file',
          size: f.file_size ? `${Math.round(f.file_size / 1024)} KB` : 'Unknown size',
          mimeType: 'application/octet-stream',
          uploadedAt: f.created_at,
          encrypted: Boolean(f.encrypted),
        })),
        createdAt: row.created_at,
      }));

      setSwitches(formattedSwitches);
    } catch (err: any) {
      console.error('Failed to load switches:', err);
      setError(err?.message || 'Could not load switches from database.');
    } finally {
      setLoadingSwitches(false);
    }
  }, [user, supabase]);

  // Fetch recent authorized audit logs across all user's switches
  const fetchRecentLogs = useCallback(async () => {
    if (!user) return;
    setLoadingLogs(true);
    setLogError(null);
    try {
      const { data, error: fetchErr } = await supabase
        .from('audit_logs')
        .select('id, user_id, switch_id, action, metadata, created_at')
        .order('created_at', { ascending: false })
        .limit(10);

      if (fetchErr) throw fetchErr;

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
      console.error('Failed to load audit logs:', err);
      setLogError(err?.message || 'Could not load recent activity.');
    } finally {
      setLoadingLogs(false);
    }
  }, [user, supabase]);

  useEffect(() => {
    if (!authLoading && user) {
      fetchSwitches();
      fetchRecentLogs();
    }
  }, [authLoading, user, fetchSwitches, fetchRecentLogs]);

  // Handle Check-in update to database via secure server-side RPC function
  const handleCheckIn = async (switchId: string) => {
    try {
      // 1. Execute secure database RPC
      const { data, error: rpcError } = await supabase.rpc('perform_check_in', {
        p_switch_id: switchId,
      });

      if (rpcError) throw rpcError;

      // 2. Refresh switch in state using authoritative server timestamps
      if (data && data.success) {
        setSwitches((prev) =>
          prev.map((s) => {
            if (s.id === switchId) {
              return {
                ...s,
                status: data.status || 'ACTIVE',
                lastCheckIn: data.last_check_in,
                nextCheckIn: data.next_check_in,
              };
            }
            return s;
          })
        );
      } else {
        await fetchSwitches();
      }
      await fetchRecentLogs();
    } catch (err: any) {
      console.error('Check-in error:', err);
      alert('Failed to process check-in: ' + (err?.message || 'Unknown error'));
    }
  };

  // Handle permanent deletion of CANCELLED or TRIGGERED switch
  const handleConfirmDelete = async () => {
    if (!switchToDelete || !user || isDeletingSwitch) return;

    if (!confirmAcknowledge) {
      setDeleteError('Please acknowledge the permanent deletion warning before proceeding.');
      return;
    }

    setIsDeletingSwitch(true);
    setDeleteError(null);

    try {
      // 1. Client-side status guard: Only CANCELLED and TRIGGERED switches allowed
      if (switchToDelete.status !== 'CANCELLED' && switchToDelete.status !== 'TRIGGERED') {
        throw new Error(`Cannot delete switch with status "${switchToDelete.status}". Only CANCELLED and TRIGGERED switches may be deleted.`);
      }

      // 2. Fetch all storage files belonging to this switch
      const { data: files, error: filesErr } = await supabase
        .from('files')
        .select('id, storage_path')
        .eq('switch_id', switchToDelete.id);

      if (filesErr) {
        throw new Error(`Failed to check switch files: ${filesErr.message}`);
      }

      // 3. Remove associated files from secure Storage (dead-man-files)
      // Safety guard: Ensure paths strictly belong to current user and target switch
      const storagePrefix = `${user.id}/${switchToDelete.id}/`;
      const storagePathsToDelete: string[] = [];

      if (files && files.length > 0) {
        const filePaths = files
          .map((f: any) => f.storage_path)
          .filter((path: string) => typeof path === 'string' && path.startsWith(storagePrefix));
        storagePathsToDelete.push(...filePaths);
      }

      // Also clean up any unindexed vault files in this switch folder to prevent orphaned objects
      try {
        const { data: storageList } = await supabase.storage
          .from('dead-man-files')
          .list(`${user.id}/${switchToDelete.id}`);

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

      // 4. Record audit log: SWITCH_DELETED before database deletion
      await supabase.rpc('insert_client_audit_event', {
        p_event_type: 'SWITCH_DELETED',
        p_switch_id: switchToDelete.id,
        p_details: {
          switch_title: switchToDelete.title,
          switch_status: switchToDelete.status,
          deleted_switch_id: switchToDelete.id,
          file_count: files?.length || 0,
        },
      });

      // 5. Delete switch from database (cascades to related tables, audit_logs.switch_id set null)
      const { error: deleteErr } = await supabase
        .from('switches')
        .delete()
        .eq('id', switchToDelete.id);

      if (deleteErr) {
        throw deleteErr;
      }

      const deletedTitle = switchToDelete.title;
      setSwitchToDelete(null);
      setConfirmAcknowledge(false);
      setSuccessMessage(`Switch "${deletedTitle}" has been permanently deleted.`);
      setTimeout(() => setSuccessMessage(null), 5000);

      // Refresh dashboard switches and audit log feed
      await fetchSwitches();
      await fetchRecentLogs();
    } catch (err: any) {
      console.error('Delete switch error:', err);
      setDeleteError(err?.message || 'Failed to delete switch.');
    } finally {
      setIsDeletingSwitch(false);
    }
  };

  // Auth loading guard
  if (authLoading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center space-y-3">
          <div className="w-6 h-6 border-2 border-zinc-600 border-t-emerald-400 rounded-full animate-spin mx-auto" />
          <p className="text-xs text-zinc-500">Loading session...</p>
        </div>
      </div>
    );
  }

  const totalSwitches = switches.length;
  const activeSwitches = switches.filter((s) => s.status === 'ACTIVE').length;
  const triggeredSwitches = switches.filter((s) => s.status === 'TRIGGERED' || s.status === 'PENDING_GRACE').length;
  const cancelledSwitches = switches.filter((s) => s.status === 'CANCELLED').length;

  const filteredSwitches = switches.filter((s) => {
    const matchesFilter =
      selectedFilter === 'ALL'
        ? true
        : selectedFilter === 'ACTIVE'
        ? s.status === 'ACTIVE'
        : selectedFilter === 'TRIGGERED'
        ? s.status === 'TRIGGERED' || s.status === 'PENDING_GRACE'
        : selectedFilter === 'CANCELLED'
        ? s.status === 'CANCELLED'
        : true;

    const matchesSearch =
      s.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.description.toLowerCase().includes(searchQuery.toLowerCase());

    return matchesFilter && matchesSearch;
  });

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-zinc-100">
            Welcome, {userName}
          </h1>
          <p className="text-xs text-zinc-500 mt-0.5 font-mono">
            {user?.email}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => { fetchSwitches(); fetchRecentLogs(); }}
            isLoading={loadingSwitches || loadingLogs}
            leftIcon={<RefreshCw className="w-3.5 h-3.5" />}
          >
            Refresh
          </Button>
          <Link href="/dashboard/create">
            <Button variant="primary" size="sm" leftIcon={<Plus className="w-4 h-4" />}>
              New Switch
            </Button>
          </Link>
        </div>
      </div>

      {successMessage && (
        <div className="p-3 rounded bg-emerald-950/60 border border-emerald-800/60 text-emerald-400 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{successMessage}</span>
        </div>
      )}

      {error && (
        <div className="p-3 rounded bg-red-950/60 border border-red-800/60 text-red-400 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={fetchSwitches}
            className="underline hover:text-red-300 ml-2"
          >
            Retry
          </button>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="p-4 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-1">
          <div className="flex items-center justify-between text-zinc-400">
            <span className="text-xs font-medium uppercase tracking-wider">Total</span>
            <Layers className="w-4 h-4 text-zinc-500" />
          </div>
          <p className="text-2xl font-bold text-zinc-100">{totalSwitches}</p>
        </div>

        <div className="p-4 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-1">
          <div className="flex items-center justify-between text-emerald-400">
            <span className="text-xs font-medium uppercase tracking-wider">Active</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-2xl font-bold text-emerald-400">{activeSwitches}</p>
        </div>

        <div className="p-4 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-1">
          <div className="flex items-center justify-between text-red-400">
            <span className="text-xs font-medium uppercase tracking-wider">Triggered</span>
            <AlertCircle className="w-4 h-4 text-red-400" />
          </div>
          <p className="text-2xl font-bold text-red-400">{triggeredSwitches}</p>
        </div>

        <div className="p-4 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-1">
          <div className="flex items-center justify-between text-zinc-500">
            <span className="text-xs font-medium uppercase tracking-wider">Cancelled</span>
            <Slash className="w-4 h-4 text-zinc-500" />
          </div>
          <p className="text-2xl font-bold text-zinc-400">{cancelledSwitches}</p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 justify-between items-center bg-zinc-900/40 p-3 rounded-lg border border-zinc-800">
        <div className="w-full sm:w-64">
          <Input
            placeholder="Search switches..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            leftIcon={<Search className="w-4 h-4" />}
          />
        </div>

        <div className="flex items-center gap-1 bg-zinc-950 p-1 rounded-md border border-zinc-800 w-full sm:w-auto">
          {['ALL', 'ACTIVE', 'TRIGGERED', 'CANCELLED'].map((tab) => (
            <button
              key={tab}
              onClick={() => setSelectedFilter(tab)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                selectedFilter === tab
                  ? 'bg-zinc-800 text-zinc-100'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              {tab.charAt(0) + tab.slice(1).toLowerCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Loading state for switches */}
      {loadingSwitches ? (
        <div className="py-16 text-center space-y-3">
          <div className="w-6 h-6 border-2 border-zinc-600 border-t-emerald-400 rounded-full animate-spin mx-auto" />
          <p className="text-xs text-zinc-500">Loading your switches from Supabase...</p>
        </div>
      ) : filteredSwitches.length > 0 ? (
        /* Switch Grid */
        <div className="grid md:grid-cols-2 gap-4">
          {filteredSwitches.map((switchItem) => (
            <SwitchCard
              key={switchItem.id}
              switchItem={switchItem}
              onCheckIn={handleCheckIn}
              onDelete={(s) => {
                setDeleteError(null);
                setConfirmAcknowledge(false);
                setSwitchToDelete(s);
              }}
            />
          ))}
        </div>
      ) : switches.length === 0 ? (
        /* Empty State */
        <div className="rounded-lg border border-zinc-800 border-dashed bg-zinc-900/20 py-16 text-center space-y-4">
          <div className="flex justify-center">
            <div className="p-3 rounded-full bg-zinc-900 border border-zinc-800">
              <ShieldCheck className="w-6 h-6 text-zinc-600" />
            </div>
          </div>
          <div className="space-y-1">
            <p className="text-sm font-medium text-zinc-300">No switches yet</p>
            <p className="text-xs text-zinc-500">Create your first dead man&apos;s switch to get started.</p>
          </div>
          <Link href="/dashboard/create">
            <Button variant="primary" size="sm" leftIcon={<Plus className="w-4 h-4" />}>
              Create First Switch
            </Button>
          </Link>
        </div>
      ) : (
        /* Filter returned empty */
        <div className="text-center py-12 rounded-lg border border-zinc-800 text-zinc-500 text-xs">
          No switches found matching your filter or search query.
        </div>
      )}

      {/* Real Database-Backed Audit Log Section */}
      <AuditLog
        logs={auditLogs}
        title="Recent Security & System Activity"
        isLoading={loadingLogs}
        error={logError}
      />

      {/* Delete Switch Confirmation Modal */}
      <Modal
        isOpen={Boolean(switchToDelete)}
        onClose={() => {
          if (!isDeletingSwitch) {
            setSwitchToDelete(null);
            setDeleteError(null);
            setConfirmAcknowledge(false);
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
              type="button"
              onClick={() => {
                setSwitchToDelete(null);
                setDeleteError(null);
                setConfirmAcknowledge(false);
              }}
              disabled={isDeletingSwitch}
            >
              Cancel
            </Button>
            <Button
              variant="danger"
              size="sm"
              type="button"
              onClick={handleConfirmDelete}
              isLoading={isDeletingSwitch}
              disabled={isDeletingSwitch || !confirmAcknowledge}
              leftIcon={<Trash2 className="w-3.5 h-3.5" />}
            >
              Delete Permanently
            </Button>
          </>
        }
      >
        <div className="space-y-4 text-xs">
          {deleteError && (
            <div className="p-2.5 rounded bg-red-950/60 border border-red-800/60 text-red-400 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{deleteError}</span>
            </div>
          )}

          {switchToDelete && (
            <div className="p-3 rounded bg-zinc-950/60 border border-zinc-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-zinc-200 text-sm">{switchToDelete.title}</span>
                <StatusBadge status={switchToDelete.status} size="sm" />
              </div>
              {switchToDelete.description && (
                <p className="text-zinc-400 line-clamp-2 text-[11px]">{switchToDelete.description}</p>
              )}
              <div className="pt-1 text-[11px] text-zinc-500 flex gap-4">
                <span>Files attached: {switchToDelete.payloadFiles.length}</span>
                <span>Recipients: {switchToDelete.recipients.length}</span>
              </div>
            </div>
          )}

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
              checked={confirmAcknowledge}
              onChange={(e) => setConfirmAcknowledge(e.target.checked)}
              disabled={isDeletingSwitch}
              className="mt-0.5 rounded bg-zinc-900 border-zinc-700 text-red-500 focus:ring-red-500/30"
            />
            <span className="text-[11px] leading-relaxed">
              I understand that deleting <strong>{switchToDelete?.title}</strong> is permanent and irreversible.
            </span>
          </label>
        </div>
      </Modal>

    </div>
  );
}
