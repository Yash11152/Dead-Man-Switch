'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { User, Lock, Bell, CheckCircle2, Database, Loader2, AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '@/components/ui/Card';
import { checkSupabaseInitialization, SupabaseInitStatus } from '@/lib/supabase/checkConnection';
import { useAuth } from '@/context/AuthContext';

interface ProfileData {
  fullName: string;
  emailAlerts: boolean;
}

export default function SettingsPage() {
  const { user, supabase } = useAuth();

  const [profile, setProfile] = useState<ProfileData>({ fullName: '', emailAlerts: true });
  const [isFetching, setIsFetching] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [saveState, setSaveState] = useState<'idle' | 'saved' | 'error'>('idle');
  const [saveError, setSaveError] = useState<string | null>(null);
  const [supabaseStatus, setSupabaseStatus] = useState<SupabaseInitStatus | null>(null);

  useEffect(() => {
    setSupabaseStatus(checkSupabaseInitialization());
  }, []);

  const loadProfile = useCallback(async () => {
    if (!user) return;
    setIsFetching(true);
    try {
      const { data, error } = await supabase
        .from('profiles')
        .select('full_name, email_alerts')
        .eq('id', user.id)
        .single();

      if (error && error.code !== 'PGRST116') {
        // PGRST116 = no row found — first-time user with no profile row yet
        console.error('Failed to load profile:', error);
      }

      setProfile({
        fullName: data?.full_name ?? (user.user_metadata?.full_name || ''),
        emailAlerts: data?.email_alerts ?? true,
      });
    } catch (err) {
      console.error('Profile load error:', err);
    } finally {
      setIsFetching(false);
    }
  }, [user, supabase]);

  useEffect(() => {
    loadProfile();
  }, [loadProfile]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return;
    setIsSaving(true);
    setSaveState('idle');
    setSaveError(null);

    try {
      // UPSERT profile — the trigger auto-creates the row on signup but may not exist for legacy users
      const { error: upsertError } = await supabase
        .from('profiles')
        .upsert({
          id: user.id,
          full_name: profile.fullName.trim() || null,
          email_alerts: profile.emailAlerts,
          updated_at: new Date().toISOString(),
        }, { onConflict: 'id' });

      if (upsertError) throw upsertError;

      // Log profile update to audit log via server-side RPC
      await supabase.rpc('insert_client_audit_event', {
        p_event_type: 'PROFILE_UPDATED',
        p_details: { fields_updated: ['full_name', 'email_alerts'] },
      });

      setSaveState('saved');
      setTimeout(() => setSaveState('idle'), 3000);
    } catch (err: any) {
      console.error('Settings save error:', err);
      setSaveError(err?.message || 'Failed to save settings.');
      setSaveState('error');
    } finally {
      setIsSaving(false);
    }
  };

  if (isFetching) {
    return (
      <div className="flex items-center justify-center min-h-[40vh]">
        <div className="flex items-center gap-2 text-zinc-400">
          <Loader2 className="w-5 h-5 animate-spin text-emerald-400" />
          <span className="text-sm">Loading your settings...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-3xl mx-auto">

      <div className="border-b border-zinc-800 pb-4">
        <h1 className="text-xl font-bold text-zinc-100">Account Settings</h1>
        <p className="text-xs text-zinc-400 mt-0.5">
          Manage your profile and notification preferences
        </p>
      </div>

      {/* Supabase Connection Status */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Database className="w-4 h-4 text-emerald-400" />
            Supabase Client Status
          </CardTitle>
          <CardDescription>Status of the local Supabase client initialization.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-xs">
          <div className="p-3 rounded bg-zinc-950/60 border border-zinc-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-zinc-200">Supabase Client Initialized</span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-medium border ${supabaseStatus?.initialized
                  ? 'bg-emerald-950 text-emerald-400 border-emerald-800/60'
                  : 'bg-amber-950 text-amber-400 border-amber-800/60'
                }`}>
                {supabaseStatus?.initialized ? 'READY' : 'PENDING'}
              </span>
            </div>
            <p className="text-zinc-400 text-[11px]">{supabaseStatus?.message}</p>
          </div>

          <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
            <div className="p-2 rounded bg-zinc-950/40 border border-zinc-800/80">
              <span className="text-zinc-500 block">NEXT_PUBLIC_SUPABASE_URL</span>
              <span className={supabaseStatus?.hasUrl ? 'text-emerald-400' : 'text-zinc-400'}>
                {supabaseStatus?.hasUrl ? 'Configured' : 'Placeholder'}
              </span>
            </div>
            <div className="p-2 rounded bg-zinc-950/40 border border-zinc-800/80">
              <span className="text-zinc-500 block">NEXT_PUBLIC_SUPABASE_ANON_KEY</span>
              <span className={supabaseStatus?.hasAnonKey ? 'text-emerald-400' : 'text-zinc-400'}>
                {supabaseStatus?.hasAnonKey ? 'Configured' : 'Placeholder'}
              </span>
            </div>
          </div>
        </CardContent>
      </Card>

      <form onSubmit={handleSave} className="space-y-6">

        {/* Profile */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <User className="w-4 h-4 text-zinc-400" />
              Profile Details
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Input
              label="Display Name"
              value={profile.fullName}
              onChange={(e) => setProfile({ ...profile, fullName: e.target.value })}
              placeholder="Your name"
              disabled={isSaving}
            />
            {/* Email is read-only — controlled by Supabase Auth */}
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-zinc-300">Email Address</label>
              <div className="px-3 py-2 rounded-md bg-zinc-900/60 border border-zinc-800 text-sm text-zinc-400 font-mono">
                {user?.email ?? '—'}
              </div>
              <p className="text-[11px] text-zinc-500">
                Email is managed by your authentication provider and cannot be changed here.
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Security — honest 2FA status */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Lock className="w-4 h-4 text-zinc-400" />
              Security
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            <div className="flex items-center justify-between p-3 rounded bg-zinc-950/60 border border-zinc-800">
              <div>
                <p className="font-semibold text-zinc-200">Two-Factor Authentication</p>
                <p className="text-zinc-400 text-[11px]">
                  Configure 2FA via your Supabase Auth account settings.
                </p>
              </div>
              <span className="px-2 py-0.5 rounded bg-zinc-900 text-zinc-400 text-[10px] font-medium border border-zinc-700">
                {user?.factors && user.factors.length > 0 ? 'ENABLED' : 'NOT CONFIGURED'}
              </span>
            </div>
            <div className="flex items-center justify-between p-3 rounded bg-zinc-950/60 border border-zinc-800">
              <div>
                <p className="font-semibold text-zinc-200">Auth Provider</p>
                <p className="text-zinc-400 text-[11px]">
                  {user?.app_metadata?.provider ?? 'email'}
                </p>
              </div>
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 text-[10px] font-medium border border-emerald-800/60">
                ACTIVE
              </span>
            </div>
          </CardContent>
        </Card>

        {/* Notifications — email only, SMS removed (not implemented) */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Bell className="w-4 h-4 text-zinc-400" />
              Notifications
            </CardTitle>
            <CardDescription>
              Controls which automated alerts you receive from the system.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            <label className="flex items-center justify-between p-3 rounded bg-zinc-950/60 border border-zinc-800 cursor-pointer">
              <div>
                <p className="font-semibold text-zinc-200">Email Alerts</p>
                <p className="text-zinc-400 text-[11px]">
                  Receive check-in reminders and grace-period warnings via email.
                  Requires <span className="font-mono text-zinc-300">RESEND_API_KEY</span> to be configured on the server.
                </p>
              </div>
              <input
                type="checkbox"
                checked={profile.emailAlerts}
                onChange={(e) => setProfile({ ...profile, emailAlerts: e.target.checked })}
                className="w-4 h-4 rounded bg-zinc-900 border-zinc-700 accent-emerald-500"
                disabled={isSaving}
              />
            </label>

            <div className="p-3 rounded bg-zinc-950/60 border border-zinc-800/50 text-zinc-500 text-[11px]">
              <span className="font-semibold text-zinc-400">SMS alerts</span> are not currently supported.
              Only email delivery via Resend is implemented.
            </div>
          </CardContent>

          <CardFooter className="flex flex-col items-end gap-2">
            {saveState === 'error' && saveError && (
              <div className="flex items-center gap-2 text-red-400 text-xs w-full">
                <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                <span>{saveError}</span>
              </div>
            )}
            <Button
              type="submit"
              variant="primary"
              size="md"
              isLoading={isSaving}
              leftIcon={saveState === 'saved' ? <CheckCircle2 className="w-4 h-4" /> : undefined}
            >
              {saveState === 'saved' ? 'Saved!' : 'Save Settings'}
            </Button>
          </CardFooter>
        </Card>

      </form>
    </div>
  );
}
