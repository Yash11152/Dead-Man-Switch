import React from 'react';

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-zinc-800 bg-zinc-950 text-zinc-500 text-xs py-6 px-4">
      <div className="mx-auto max-w-6xl flex flex-col sm:flex-row items-center justify-between gap-3">
        <p className="font-medium text-zinc-400">Dead Man&apos;s Switch</p>
        <p>&copy; {new Date().getFullYear()} Dead Man&apos;s Switch Project. Built for Academic Research.</p>
      </div>
    </footer>
  );
};
