'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { LayoutDashboard, PlusCircle, Settings, ShieldCheck } from 'lucide-react';

export const Sidebar: React.FC = () => {
  const pathname = usePathname();

  const navItems = [
    {
      name: 'Dashboard',
      href: '/dashboard',
      icon: LayoutDashboard,
      active: pathname === '/dashboard'
    },
    {
      name: 'Create Switch',
      href: '/dashboard/create',
      icon: PlusCircle,
      active: pathname === '/dashboard/create'
    },
    {
      name: 'Settings',
      href: '/dashboard/settings',
      icon: Settings,
      active: pathname === '/dashboard/settings'
    }
  ];

  return (
    <aside className="w-56 shrink-0 hidden lg:block border-r border-zinc-800 bg-zinc-950/40 min-h-[calc(100vh-3.5rem)] p-4 space-y-6">
      <div className="space-y-1">
        <p className="px-3 text-[11px] font-medium text-zinc-500 uppercase tracking-wider mb-2">
          Navigation
        </p>
        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium transition-colors ${
                  item.active
                    ? 'bg-zinc-800 text-zinc-100'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{item.name}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      <div className="rounded-lg bg-zinc-900/60 border border-zinc-800 p-3 space-y-2 text-xs">
        <div className="flex items-center gap-1.5 font-medium text-zinc-200">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          <span>Security Protocol</span>
        </div>
        <p className="text-[11px] text-zinc-400 leading-relaxed">
          Time-based check-in monitoring active.
        </p>
      </div>
    </aside>
  );
};
