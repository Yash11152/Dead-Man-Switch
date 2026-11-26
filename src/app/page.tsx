'use client';

import React from 'react';
import Link from 'next/link';
import { Shield, Clock, Lock, Send, ArrowRight } from 'lucide-react';
import { Navbar } from '@/components/layout/Navbar';
import { Footer } from '@/components/layout/Footer';
import { Button } from '@/components/ui/Button';

export default function LandingPage() {
  return (
    <div className="min-h-screen flex flex-col bg-[#09090b] text-zinc-100">
      
      <Navbar />

      <main className="flex-1">
        
        {/* Hero Section */}
        <section className="py-20 md:py-28 border-b border-zinc-800/80 text-center px-4">
          <div className="max-w-3xl mx-auto space-y-6">
            
        

            <h1 className="text-4xl sm:text-5xl font-bold tracking-tight text-white leading-tight">
              Digital Dead Man&apos;s Switch
            </h1>

            <p className="text-base sm:text-lg text-zinc-400 max-w-xl mx-auto leading-relaxed">
              Automated time-based access control system. Periodically check in to keep confidential data locked. If a check-in is missed, access is released to authorized recipients.
            </p>

            <div className="pt-4 flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link href="/dashboard">
                <Button variant="primary" size="lg" rightIcon={<ArrowRight className="w-4 h-4" />}>
                  Open Dashboard
                </Button>
              </Link>
              <Link href="/register">
                <Button variant="outline" size="lg">
                  Create Account
                </Button>
              </Link>
            </div>

          </div>
        </section>

        {/* Features */}
        <section id="features" className="py-16 border-b border-zinc-800/80 bg-zinc-950/40 px-4">
          <div className="max-w-5xl mx-auto">
            <div className="text-center mb-12">
              <h2 className="text-xl font-bold text-zinc-100">Core Features</h2>
              <p className="text-xs text-zinc-400 mt-1">Built with zero-trust access principles</p>
            </div>

            <div className="grid md:grid-cols-3 gap-6">
              
              <div className="p-5 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-2.5">
                <Clock className="w-5 h-5 text-emerald-400" />
                <h3 className="text-sm font-semibold text-zinc-200">Time-Based Check-In</h3>
                <p className="text-xs text-zinc-400 leading-relaxed">
                  Configure custom check-in intervals and grace periods to fit your schedule.
                </p>
              </div>

              <div className="p-5 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-2.5">
                <Lock className="w-5 h-5 text-emerald-400" />
                <h3 className="text-sm font-semibold text-zinc-200">Secure Payload Storage</h3>
                <p className="text-xs text-zinc-400 leading-relaxed">
                  Keep critical files and information protected until trigger conditions are met.
                </p>
              </div>

              <div className="p-5 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-2.5">
                <Send className="w-5 h-5 text-emerald-400" />
                <h3 className="text-sm font-semibold text-zinc-200">Recipient Dispatch</h3>
                <p className="text-xs text-zinc-400 leading-relaxed">
                  Automatically notify emergency recipients if a check-in deadline expires.
                </p>
              </div>

            </div>
          </div>
        </section>

        {/* Workflow */}
        <section id="how-it-works" className="py-16 px-4">
          <div className="max-w-5xl mx-auto">
            <div className="text-center mb-12">
              <h2 className="text-xl font-bold text-zinc-100">How It Works</h2>
            </div>

            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
              
              <div className="p-4 rounded-lg bg-zinc-900/40 border border-zinc-800 space-y-2">
                <span className="text-xs font-mono font-bold text-zinc-500">STEP 1</span>
                <h4 className="text-sm font-semibold text-zinc-200">Create Switch</h4>
                <p className="text-xs text-zinc-400">Set interval, grace period, and payload files.</p>
              </div>

              <div className="p-4 rounded-lg bg-zinc-900/40 border border-zinc-800 space-y-2">
                <span className="text-xs font-mono font-bold text-zinc-500">STEP 2</span>
                <h4 className="text-sm font-semibold text-zinc-200">Set Recipients</h4>
                <p className="text-xs text-zinc-400">Designate contacts to receive access upon trigger.</p>
              </div>

              <div className="p-4 rounded-lg bg-zinc-900/40 border border-zinc-800 space-y-2">
                <span className="text-xs font-mono font-bold text-emerald-400">STEP 3</span>
                <h4 className="text-sm font-semibold text-zinc-200">Regular Check-In</h4>
                <p className="text-xs text-zinc-400">Click &quot;Check In&quot; periodically to reset the timer.</p>
              </div>

              <div className="p-4 rounded-lg bg-zinc-900/40 border border-zinc-800 space-y-2">
                <span className="text-xs font-mono font-bold text-red-400">STEP 4</span>
                <h4 className="text-sm font-semibold text-zinc-200">Automatic Trigger</h4>
                <p className="text-xs text-zinc-400">If missed, recipients receive access credentials.</p>
              </div>

            </div>
          </div>
        </section>

      </main>

      <Footer />

    </div>
  );
}
