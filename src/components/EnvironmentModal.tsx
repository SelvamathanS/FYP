import React, { useState } from 'react';
import { X, Server, Cpu, HardDrive, Terminal, Layers, Box, Check, Copy, ShieldCheck } from 'lucide-react';
import { ENVIRONMENT_SPEC } from '../data/systemsAndBugsCatalog';
import { ThemeMode } from '../types/threatGraph';

interface EnvironmentModalProps {
  isOpen: boolean;
  onClose: () => void;
  theme: ThemeMode;
}

export const EnvironmentModal: React.FC<EnvironmentModalProps> = ({ isOpen, onClose, theme }) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const isDark = theme === 'dark';

  if (!isOpen) return null;

  const handleCopy = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div 
        className={`w-full max-w-4xl max-h-[90vh] rounded-2xl border shadow-2xl flex flex-col overflow-hidden transition-all duration-300 ${
          isDark 
            ? 'bg-[#0a0f18] border-blue-900/60 text-neutral-200' 
            : 'bg-white border-slate-300 text-slate-800'
        }`}
      >
        {/* Header */}
        <div 
          className={`px-6 py-4 border-b flex items-center justify-between ${
            isDark ? 'bg-black/60 border-neutral-800' : 'bg-slate-100 border-slate-200'
          }`}
        >
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-blue-600/20 text-blue-500 border border-blue-500/30">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold tracking-wide flex items-center gap-2">
                System Specifications & Setup Guide
                <span className="text-[10px] px-2 py-0.5 rounded-full font-mono bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  Verified
                </span>
              </h2>
              <p className={`text-xs ${isDark ? 'text-neutral-400' : 'text-slate-500'}`}>
                Computer hardware requirements, operating system, and step-by-step setup guide
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className={`p-2 rounded-lg transition-colors ${
              isDark ? 'hover:bg-neutral-800 text-neutral-400 hover:text-white' : 'hover:bg-slate-200 text-slate-500 hover:text-slate-900'
            }`}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body content */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs">
          
          {/* Top Quick Badges */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className={`p-3 rounded-xl border ${isDark ? 'bg-neutral-900/60 border-neutral-800' : 'bg-slate-50 border-slate-200'}`}>
              <div className="text-[10px] uppercase font-bold text-neutral-500 mb-1 flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-blue-400" /> Language
              </div>
              <div className="font-semibold text-sm">{ENVIRONMENT_SPEC.programmingLanguage}</div>
            </div>

            <div className={`p-3 rounded-xl border ${isDark ? 'bg-neutral-900/60 border-neutral-800' : 'bg-slate-50 border-slate-200'}`}>
              <div className="text-[10px] uppercase font-bold text-neutral-500 mb-1 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-emerald-400" /> Runtime Engine
              </div>
              <div className="font-semibold text-sm">{ENVIRONMENT_SPEC.runtimeVersion}</div>
            </div>

            <div className={`p-3 rounded-xl border ${isDark ? 'bg-neutral-900/60 border-neutral-800' : 'bg-slate-50 border-slate-200'}`}>
              <div className="text-[10px] uppercase font-bold text-neutral-500 mb-1 flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-purple-400" /> Port Binding
              </div>
              <div className="font-semibold text-sm">TCP Port 3000 (HTTP)</div>
            </div>

            <div className={`p-3 rounded-xl border ${isDark ? 'bg-neutral-900/60 border-neutral-800' : 'bg-slate-50 border-slate-200'}`}>
              <div className="text-[10px] uppercase font-bold text-neutral-500 mb-1 flex items-center gap-1.5">
                <HardDrive className="w-3.5 h-3.5 text-amber-400" /> Graph Engine
              </div>
              <div className="font-semibold text-sm">Neo4j Aura / Memory</div>
            </div>
          </div>

          {/* Section 1: OS & Hardware Requirements */}
          <div className={`p-4 rounded-xl border space-y-3 ${isDark ? 'bg-neutral-950/60 border-neutral-800/80' : 'bg-slate-50/70 border-slate-200'}`}>
            <h3 className="font-bold text-sm flex items-center gap-2 text-blue-400">
              <HardDrive className="w-4 h-4" /> Operating System & Hardware Requirements
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <span className="text-[11px] font-bold text-neutral-500 uppercase tracking-wider block mb-1">Supported Operating Systems</span>
                <p className={`leading-relaxed ${isDark ? 'text-neutral-300' : 'text-slate-700'}`}>
                  {ENVIRONMENT_SPEC.osDetails}
                </p>
              </div>
              <div className="space-y-1.5">
                <span className="text-[11px] font-bold text-neutral-500 uppercase tracking-wider block mb-1">Compute & Network Footprint</span>
                <div className="flex items-center justify-between py-0.5 border-b border-neutral-800/40">
                  <span className="text-neutral-500">Processor:</span>
                  <span className="font-mono font-medium">{ENVIRONMENT_SPEC.hardwareRequirements.cpu}</span>
                </div>
                <div className="flex items-center justify-between py-0.5 border-b border-neutral-800/40">
                  <span className="text-neutral-500">Memory (RAM):</span>
                  <span className="font-mono font-medium">{ENVIRONMENT_SPEC.hardwareRequirements.ram}</span>
                </div>
                <div className="flex items-center justify-between py-0.5 border-b border-neutral-800/40">
                  <span className="text-neutral-500">Disk Space:</span>
                  <span className="font-mono font-medium">{ENVIRONMENT_SPEC.hardwareRequirements.disk}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Section 2: Frameworks & Core Libraries */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className={`p-4 rounded-xl border space-y-2.5 ${isDark ? 'bg-neutral-950/60 border-neutral-800/80' : 'bg-slate-50/70 border-slate-200'}`}>
              <h3 className="font-bold text-sm flex items-center gap-2 text-emerald-400">
                <Box className="w-4 h-4" /> Frameworks
              </h3>
              <div className="space-y-2">
                {ENVIRONMENT_SPEC.frameworks.map((fw) => (
                  <div key={fw.name} className={`p-2.5 rounded-lg border flex items-center justify-between ${isDark ? 'bg-neutral-900/40 border-neutral-800' : 'bg-white border-slate-200'}`}>
                    <div>
                      <div className="font-bold flex items-center gap-2">
                        {fw.name}
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">{fw.version}</span>
                      </div>
                      <div className="text-[10px] text-neutral-500 mt-0.5">{fw.role}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className={`p-4 rounded-xl border space-y-2.5 ${isDark ? 'bg-neutral-950/60 border-neutral-800/80' : 'bg-slate-50/70 border-slate-200'}`}>
              <h3 className="font-bold text-sm flex items-center gap-2 text-purple-400">
                <Layers className="w-4 h-4" /> Key Libraries & Modules
              </h3>
              <div className="space-y-2">
                {ENVIRONMENT_SPEC.libraries.map((lib) => (
                  <div key={lib.name} className={`p-2.5 rounded-lg border flex items-center justify-between ${isDark ? 'bg-neutral-900/40 border-neutral-800' : 'bg-white border-slate-200'}`}>
                    <div>
                      <div className="font-bold flex items-center gap-2">
                        {lib.name}
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">{lib.version}</span>
                      </div>
                      <div className="text-[10px] text-neutral-500 mt-0.5">{lib.purpose}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Section 3: Step-by-Step Setup & Reproducibility Guide */}
          <div className={`p-4 rounded-xl border space-y-3 ${isDark ? 'bg-neutral-950/60 border-neutral-800/80' : 'bg-slate-50/70 border-slate-200'}`}>
            <h3 className="font-bold text-sm flex items-center gap-2 text-amber-400">
              <Terminal className="w-4 h-4" /> Installation & Setup Workflow
            </h3>
            <div className="space-y-2.5">
              {ENVIRONMENT_SPEC.setupInstructions.map((inst, idx) => (
                <div 
                  key={inst.step}
                  className={`p-3 rounded-lg border flex flex-col md:flex-row md:items-center justify-between gap-3 ${
                    isDark ? 'bg-neutral-900/50 border-neutral-800' : 'bg-white border-slate-200'
                  }`}
                >
                  <div className="flex items-start gap-2.5">
                    <span className="w-5 h-5 rounded-full bg-blue-600/20 text-blue-400 font-bold flex items-center justify-center text-[10px] shrink-0 mt-0.5">
                      {inst.step}
                    </span>
                    <div>
                      <div className="font-semibold text-xs">{inst.title}</div>
                      <div className="text-[11px] text-neutral-500">{inst.description}</div>
                    </div>
                  </div>
                  {inst.command && (
                    <div className="flex items-center gap-2 shrink-0">
                      <code className={`px-2.5 py-1 rounded text-[11px] font-mono border ${isDark ? 'bg-black border-neutral-800 text-blue-300' : 'bg-slate-100 border-slate-300 text-slate-800'}`}>
                        {inst.command}
                      </code>
                      <button
                        onClick={() => handleCopy(inst.command!, idx)}
                        className={`p-1.5 rounded transition-colors ${
                          copiedIndex === idx
                            ? 'bg-emerald-500/20 text-emerald-400'
                            : isDark ? 'hover:bg-neutral-800 text-neutral-400' : 'hover:bg-slate-200 text-slate-600'
                        }`}
                        title="Copy command"
                      >
                        {copiedIndex === idx ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

        </div>

        {/* Footer */}
        <div 
          className={`px-6 py-3 border-t flex items-center justify-between ${
            isDark ? 'bg-black/60 border-neutral-800' : 'bg-slate-100 border-slate-200'
          }`}
        >
          <div className="flex items-center gap-2 text-[11px] text-neutral-500 font-mono">
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
            <span>Environment compliant with Node.js 22 LTS & Neo4j Aura Graph DB</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-lg text-xs tracking-wider uppercase transition-colors"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
};
