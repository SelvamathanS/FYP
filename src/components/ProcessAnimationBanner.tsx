import React from 'react';
import { Flame, CheckCircle2, Search, Activity, Terminal, X, ShieldAlert, Cpu } from 'lucide-react';
import { ProcessAnimationState, ThemeMode } from '../types/threatGraph';

interface ProcessAnimationBannerProps {
  state: ProcessAnimationState;
  onDismiss: () => void;
  theme: ThemeMode;
}

export const ProcessAnimationBanner: React.FC<ProcessAnimationBannerProps> = ({
  state,
  onDismiss,
  theme
}) => {
  if (!state.active) return null;
  const isDark = theme === 'dark';

  const isHacker = state.stage.includes('BUG') || state.stage.includes('INSTALL');
  const isFix = state.stage.includes('FIX') || state.stage.includes('RESTORE') || state.stage.includes('HEALTHY');
  const isDiagnostic = state.stage.includes('DIAGNOS') || state.stage.includes('ANALYZ') || state.stage.includes('SOLUTION');

  return (
    <div className="absolute bottom-6 left-1/2 transform -translate-x-1/2 z-30 w-[92%] max-w-2xl pointer-events-auto animate-in slide-in-from-bottom-4 duration-300">
      <div className={`p-3.5 rounded-xl border shadow-2xl backdrop-blur-xl transition-all ${
        isHacker
          ? isDark ? 'bg-black/90 border-red-500/40 text-red-200' : 'bg-white/95 border-red-400 text-red-950'
          : isFix
          ? isDark ? 'bg-black/90 border-emerald-500/40 text-emerald-200' : 'bg-white/95 border-emerald-400 text-emerald-950'
          : isDiagnostic
          ? isDark ? 'bg-black/90 border-amber-500/40 text-amber-200' : 'bg-white/95 border-amber-400 text-amber-950'
          : isDark ? 'bg-black/90 border-blue-500/40 text-blue-200' : 'bg-white/95 border-blue-400 text-blue-950'
      }`}>
        <div className="flex items-center justify-between gap-3 mb-2">
          {/* Status Badge & Title */}
          <div className="flex items-center space-x-2.5 min-w-0">
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border ${
              isHacker
                ? 'bg-red-500/20 border-red-500/50 text-red-400'
                : isFix
                ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-400'
                : isDiagnostic
                ? 'bg-amber-500/20 border-amber-500/50 text-amber-400'
                : 'bg-blue-500/20 border-blue-500/50 text-blue-400'
            }`}>
              {isHacker ? (
                <Flame className="w-4 h-4 animate-pulse" />
              ) : isFix ? (
                <CheckCircle2 className="w-4 h-4" />
              ) : isDiagnostic ? (
                <Cpu className="w-4 h-4 animate-spin" />
              ) : (
                <Activity className="w-4 h-4" />
              )}
            </div>

            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-serif font-semibold text-xs tracking-normal truncate">{state.title}</span>
                <span className={`text-[9px] font-mono px-2 py-0.5 rounded uppercase font-bold border shrink-0 ${
                  isHacker
                    ? (isDark ? 'bg-red-900/30 border-red-700/50 text-red-300' : 'bg-red-100 border-red-300 text-red-800')
                    : isFix
                    ? (isDark ? 'bg-emerald-900/30 border-emerald-700/50 text-emerald-300' : 'bg-emerald-100 border-emerald-300 text-emerald-800')
                    : (isDark ? 'bg-blue-900/30 border-blue-700/50 text-blue-300' : 'bg-blue-100 border-blue-300 text-blue-800')
                }`}>
                  {state.stage.replace(/_/g, ' ')}
                </span>
              </div>
              <p className="text-[11px] opacity-75 truncate">{state.subtitle}</p>
            </div>
          </div>

          {/* Progress & Dismiss */}
          <div className="flex items-center gap-2 shrink-0">
            <span className="font-mono text-xs font-bold">{state.progress}%</span>
            {state.progress >= 100 && (
              <button
                onClick={onDismiss}
                className="p-1 rounded-md hover:bg-neutral-800/60 transition-colors"
                title="Dismiss"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        {/* Micro Progress Bar */}
        <div className="w-full h-1.5 rounded-full overflow-hidden bg-black/40 border border-white/10 mb-2">
          <div 
            className={`h-full transition-all duration-300 rounded-full ${
              isHacker
                ? 'bg-gradient-to-r from-red-600 to-amber-500'
                : isFix
                ? 'bg-gradient-to-r from-emerald-600 to-teal-400'
                : 'bg-gradient-to-r from-blue-600 to-cyan-400'
            }`}
            style={{ width: `${Math.max(state.progress, 5)}%` }}
          />
        </div>

        {/* Latest Console Output Ticker */}
        {state.logs.length > 0 && (
          <div className={`text-[10px] font-mono px-2.5 py-1 rounded border flex items-center justify-between ${
            isDark ? 'bg-black/60 border-neutral-800 text-neutral-400' : 'bg-slate-100 border-slate-300 text-slate-700'
          }`}>
            <span className="flex items-center gap-1.5 truncate">
              <Terminal className="w-3 h-3 text-blue-400 shrink-0" />
              <span className="truncate">{state.logs[state.logs.length - 1]}</span>
            </span>
            <span className="text-[9px] opacity-60 shrink-0 ml-2">SOC RUNTIME</span>
          </div>
        )}
      </div>
    </div>
  );
};
