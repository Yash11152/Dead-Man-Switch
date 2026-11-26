'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Shield, Menu, X, LogOut, User as UserIcon } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { useAuth } from '@/context/AuthContext';

export interface NavbarProps {
  isDashboardLayout?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({ isDashboardLayout = false }) => {
  const router = useRouter();
  const { user, signOut } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const displayName = user?.user_metadata?.full_name || user?.email?.split('@')[0] || 'Operator';
  const displayEmail = user?.email || '';

  const handleSignOut = async () => {
    await signOut();
    router.push('/login');
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-zinc-800 bg-zinc-950/80 backdrop-blur-md">
      <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4 sm:px-6">
        
        {/* Brand Logo */}
        <Link href="/" className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-zinc-900 border border-zinc-800 text-emerald-400">
            <Shield className="h-4 h-4" />
          </div>
          <span className="font-semibold text-zinc-100 text-sm tracking-tight">
            Dead Man&apos;s Switch
          </span>
        </Link>

        {/* Desktop Navigation */}
        {!isDashboardLayout ? (
          <nav className="hidden md:flex items-center gap-6 text-xs font-medium text-zinc-400">
            <Link href="/" className="hover:text-zinc-100 transition-colors">
              Overview
            </Link>
            <a href="#how-it-works" className="hover:text-zinc-100 transition-colors">
              How It Works
            </a>
            
            {user ? (
              <Link href="/dashboard" className="hover:text-zinc-100 transition-colors">
                Dashboard
              </Link>
            ) : (
              <Link href="/login" className="hover:text-zinc-100 transition-colors">
                Sign In
              </Link>
            )}
          </nav>
        ) : (
          <div className="hidden md:flex items-center gap-3">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-950/50 border border-emerald-800/60 text-emerald-400 text-xs font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              Authenticated Session
            </span>
          </div>
        )}

        {/* Action Buttons */}
        <div className="hidden md:flex items-center gap-3">
          {!user ? (
            <>
              <Link href="/login">
                <Button variant="ghost" size="sm">
                  Sign In
                </Button>
              </Link>
              <Link href="/register">
                <Button variant="primary" size="sm">
                  Get Started
                </Button>
              </Link>
            </>
          ) : (
            <div className="flex items-center gap-3">
              <Link href="/dashboard/settings">
                <div className="flex items-center gap-2 p-1 pl-2 pr-3 rounded-md bg-zinc-900 border border-zinc-800 hover:border-zinc-700 transition-colors cursor-pointer text-xs">
                  <div className="w-5 h-5 rounded-full bg-zinc-800 flex items-center justify-center font-bold text-[10px] text-zinc-200">
                    {displayName.charAt(0).toUpperCase()}
                  </div>
                  <div className="text-left">
                    <span className="font-medium text-zinc-200 block truncate max-w-[120px]">{displayName}</span>
                  </div>
                </div>
              </Link>
              <Button
                variant="outline"
                size="sm"
                onClick={handleSignOut}
                leftIcon={<LogOut className="w-3.5 h-3.5" />}
              >
                Sign Out
              </Button>
            </div>
          )}
        </div>

        {/* Mobile Menu Button */}
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="md:hidden p-1.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-white"
        >
          {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>
      </div>

      {/* Mobile Menu */}
      {mobileMenuOpen && (
        <div className="md:hidden border-b border-zinc-800 bg-zinc-950 p-4 space-y-3">
          <Link href="/" className="block text-sm font-medium text-zinc-300" onClick={() => setMobileMenuOpen(false)}>
            Overview
          </Link>
          {user ? (
            <>
              <Link href="/dashboard" className="block text-sm font-medium text-zinc-300" onClick={() => setMobileMenuOpen(false)}>
                Dashboard
              </Link>
              <Link href="/dashboard/create" className="block text-sm font-medium text-zinc-300" onClick={() => setMobileMenuOpen(false)}>
                Create Switch
              </Link>
              <Link href="/dashboard/settings" className="block text-sm font-medium text-zinc-300" onClick={() => setMobileMenuOpen(false)}>
                Settings
              </Link>
              <div className="pt-2 border-t border-zinc-800">
                <Button variant="outline" size="sm" className="w-full" onClick={() => { handleSignOut(); setMobileMenuOpen(false); }}>
                  Sign Out ({displayEmail})
                </Button>
              </div>
            </>
          ) : (
            <div className="pt-2 border-t border-zinc-800 flex gap-2">
              <Link href="/login" className="w-full" onClick={() => setMobileMenuOpen(false)}>
                <Button variant="outline" size="sm" className="w-full">
                  Sign In
                </Button>
              </Link>
              <Link href="/register" className="w-full" onClick={() => setMobileMenuOpen(false)}>
                <Button variant="primary" size="sm" className="w-full">
                  Register
                </Button>
              </Link>
            </div>
          )}
        </div>
      )}
    </header>
  );
};
