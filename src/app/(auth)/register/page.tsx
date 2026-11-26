'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Shield, Mail, Lock, User, AlertCircle, CheckCircle2 } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { useAuth } from '@/context/AuthContext';

export default function RegisterPage() {
  const router = useRouter();
  const { signUp } = useAuth();

  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const [validationError, setValidationError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [needsEmailConfirmation, setNeedsEmailConfirmation] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);

    // Client-side validation
    if (!fullName.trim()) {
      setValidationError('Full name is required.');
      return;
    }

    if (!email.trim() || !email.includes('@')) {
      setValidationError('Please enter a valid email address.');
      return;
    }

    if (!password || password.length < 6) {
      setValidationError('Password must be at least 6 characters long.');
      return;
    }

    if (password !== confirmPassword) {
      setValidationError('Passwords do not match.');
      return;
    }

    setIsLoading(true);

    const { error, needsConfirmation } = await signUp(fullName.trim(), email.trim(), password);

    setIsLoading(false);

    if (error) {
      setValidationError(error.message || 'Failed to create account. Please try again.');
      return;
    }

    if (needsConfirmation) {
      // Supabase email confirmation is enabled — show confirmation message
      setNeedsEmailConfirmation(true);
    } else {
      // Auto-confirmed or confirmation disabled — go straight to dashboard
      router.push('/dashboard');
    }
  };

  // Email confirmation screen
  if (needsEmailConfirmation) {
    return (
      <div className="min-h-screen flex flex-col justify-center items-center p-4 bg-[#09090b]">
        <div className="w-full max-w-sm space-y-6">
          <div className="text-center space-y-2">
            <Link href="/" className="inline-flex items-center gap-2">
              <div className="p-2 rounded bg-zinc-900 border border-zinc-800 text-emerald-400">
                <Shield className="w-5 h-5" />
              </div>
              <span className="font-semibold text-lg text-zinc-100">
                Dead Man&apos;s Switch
              </span>
            </Link>
          </div>

          <Card className="shadow-lg">
            <CardContent className="pt-6 pb-6 text-center space-y-4">
              <div className="flex justify-center">
                <div className="p-3 rounded-full bg-emerald-950/60 border border-emerald-800/60">
                  <CheckCircle2 className="w-7 h-7 text-emerald-400" />
                </div>
              </div>
              <div className="space-y-1">
                <h2 className="font-semibold text-zinc-100 text-sm">Check your email</h2>
                <p className="text-xs text-zinc-400">
                  We sent a confirmation link to{' '}
                  <span className="text-zinc-200 font-medium">{email}</span>.
                  Click the link to activate your account.
                </p>
              </div>
              <p className="text-xs text-zinc-500">
                After confirming, you can{' '}
                <Link href="/login" className="text-zinc-300 hover:underline font-medium">
                  sign in here
                </Link>.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col justify-center items-center p-4 bg-[#09090b]">
      <div className="w-full max-w-sm space-y-6">

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
            Create your account
          </p>
        </div>

        <Card className="shadow-lg">
          <CardHeader className="border-b-0 pb-0">
            <CardTitle>Register Account</CardTitle>
            <CardDescription>Enter your details to create an account.</CardDescription>
          </CardHeader>

          <CardContent className="pt-4">
            {validationError && (
              <div className="mb-4 p-3 rounded bg-red-950/60 border border-red-800/60 text-red-400 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{validationError}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">

              <Input
                label="Full Name"
                type="text"
                placeholder="Alex Vance"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                leftIcon={<User className="w-4 h-4" />}
                required
                disabled={isLoading}
              />

              <Input
                label="Email"
                type="email"
                placeholder="alex@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                leftIcon={<Mail className="w-4 h-4" />}
                required
                disabled={isLoading}
              />

              <Input
                label="Password"
                type="password"
                placeholder="At least 6 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                leftIcon={<Lock className="w-4 h-4" />}
                required
                disabled={isLoading}
              />

              <Input
                label="Confirm Password"
                type="password"
                placeholder="Re-enter your password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                leftIcon={<Lock className="w-4 h-4" />}
                required
                disabled={isLoading}
              />

              <Button
                type="submit"
                variant="primary"
                size="md"
                isLoading={isLoading}
                className="w-full mt-2"
              >
                Create Account
              </Button>

            </form>
          </CardContent>

          <CardFooter className="justify-center bg-zinc-950/40 border-t border-zinc-800">
            <p className="text-xs text-zinc-400">
              Already have an account?{' '}
              <Link href="/login" className="text-zinc-200 font-medium hover:underline">
                Sign In
              </Link>
            </p>
          </CardFooter>

        </Card>

      </div>
    </div>
  );
}
