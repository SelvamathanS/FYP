import React from 'react';
import { Sun, Moon } from 'lucide-react';
import { ThemeMode } from '../types/threatGraph';

interface ThemeToggleProps {
  theme: ThemeMode;
  onToggle: () => void;
}

export const ThemeToggle: React.FC<ThemeToggleProps> = ({ theme, onToggle }) => {
  const isDark = theme === 'dark';

  return (
    <button
      onClick={onToggle}
      className={`relative inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-semibold tracking-wider transition-all duration-300 shadow-sm ${
        isDark
          ? 'bg-neutral-900/90 border-neutral-700 text-yellow-400 hover:bg-neutral-800 hover:border-yellow-500/50'
          : 'bg-white border-slate-300 text-indigo-700 hover:bg-slate-50 hover:border-indigo-400'
      }`}
      title={isDark ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
      aria-label="Toggle Theme"
    >
      <div className="relative w-4 h-4 flex items-center justify-center">
        {isDark ? (
          <Moon className="w-4 h-4 text-yellow-400 transition-transform duration-300 rotate-0" />
        ) : (
          <Sun className="w-4 h-4 text-amber-500 transition-transform duration-300 rotate-90" />
        )}
      </div>
      <span className="uppercase text-[11px] font-bold">
        {isDark ? 'Dark' : 'Light'}
      </span>
    </button>
  );
};
