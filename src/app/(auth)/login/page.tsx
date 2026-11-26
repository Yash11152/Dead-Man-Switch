'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Shield, Mail, Lock, AlertCircle } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { useAuth } from '@/context/AuthContext';

export default function LoginPage() {
  const router = useRouter();
  const { signIn } = useAuth();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);

    if (!email.trim()) {
      setAuthError('Email is required.');
      return;
    }

    if (!password) {
      setAuthError('Password is required.');
      return;
    }

    setIsLoading(true);

    const { error } = await signIn(email.trim(), password);

    setIsLoading(false);

    if (error) {
      // Provide a clean error message without exposing internal details
      if (error.message?.toLowerCase().includes('invalid login') ||
          error.message?.toLowerCase().includes('invalid credentials') ||
          error.message?.toLowerCase().includes('email not confirmed')) {
        setAuthError('Invalid email or password. Please try again.');
      } else {
        setAuthError(error.message || 'Sign in failed. Please try again.');
      }
    } else {
      router.push('/dashboard');
    }
  };

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
            Sign in to manage your switches
          </p>
        </div>

        <Card className="shadow-lg">
          <CardHeader className="border-b-0 pb-0">
            <CardTitle>Sign In</CardTitle>
            <CardDescription>Enter your account email and password.</CardDescription>
          </CardHeader>

          <CardContent className="pt-4">
            {authError && (
              <div className="mb-4 p-3 rounded bg-red-950/60 border border-red-800/60 text-red-400 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{authError}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">

              <Input
                label="Email"
                type="email"
                placeholder="name@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                leftIcon={<Mail className="w-4 h-4" />}
                required
                disabled={isLoading}
              />

              <Input
                label="Password"
                type="password"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
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
                Sign In
              </Button>

            </form>
          </CardContent>

          <CardFooter className="justify-center bg-zinc-950/40 border-t border-zinc-800">
            <p className="text-xs text-zinc-400">
              Don&apos;t have an account?{' '}
              <Link href="/register" className="text-zinc-200 font-medium hover:underline">
                Register
              </Link>
            </p>
          </CardFooter>

        </Card>

      </div>
    </div>
  );
}
