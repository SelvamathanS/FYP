import React, { useState } from 'react';
import { Plus, Minus, Server, Trash2, X, PlusCircle, Sparkles } from 'lucide-react';
import { PRESET_SYSTEM_TEMPLATES } from '../data/systemsAndBugsCatalog';
import { ThemeMode, GraphNode, SystemConfigData } from '../types/threatGraph';

interface DynamicSystemControlsProps {
  systemCount: number;
  onAddSystem: (template?: Partial<SystemConfigData>) => Promise<void>;
  onRemoveSystem: (systemId: string) => Promise<void>;
  systems: GraphNode[];
  theme: ThemeMode;
}

export const DynamicSystemControls: React.FC<DynamicSystemControlsProps> = ({
  systemCount,
  onAddSystem,
  onRemoveSystem,
  systems,
  theme
}) => {
  const [showAddModal, setShowAddModal] = useState(false);
  const [showRemoveModal, setShowRemoveModal] = useState(false);
  const [customName, setCustomName] = useState('');
  const [customPort, setCustomPort] = useState(8080);
  const [customOs, setCustomOs] = useState('Linux Ubuntu 22.04 LTS');
  const [customPurpose, setCustomPurpose] = useState('');
  const isDark = theme === 'dark';

  const handleCreateCustom = async () => {
    if (!customName.trim()) return;
    await onAddSystem({
      name: customName.trim(),
      id: customName.trim(),
      port: customPort,
      os: customOs,
      purpose: customPurpose || 'Custom Microservice Endpoint',
      status: 'HEALTHY'
    });
    setCustomName('');
    setCustomPurpose('');
    setShowAddModal(false);
  };

  return (
    <>
      {/* Header Compact Dynamic Stepper Controls */}
      <div className={`inline-flex items-center gap-1 px-1.5 py-1 rounded-lg border transition-colors shadow-xs ${
        isDark ? 'bg-slate-900/90 border-slate-800 text-slate-200' : 'bg-slate-100 border-slate-200 text-slate-700'
      }`}>
        {/* Minus Button */}
        <button
          onClick={() => setShowRemoveModal(true)}
          disabled={systemCount <= 1}
          className={`p-1 rounded-md border transition-all ${
            systemCount <= 1
              ? 'opacity-30 cursor-not-allowed border-transparent'
              : isDark
              ? 'bg-slate-800/80 border-slate-700 hover:bg-rose-950/60 hover:border-rose-700 text-rose-400'
              : 'bg-white border-slate-200 hover:bg-rose-50 hover:border-rose-300 text-rose-600'
          }`}
          title="Remove workload from network topology"
          aria-label="Remove Computer"
        >
          <Minus className="w-3 h-3" />
        </button>

        {/* Dynamic Count Badge */}
        <div className="px-1.5 text-center flex items-center gap-1.5 select-none">
          <Server className="w-3.5 h-3.5 text-cyan-400" />
          <span className="font-mono font-bold text-xs tracking-tight">
            {systemCount}
          </span>
          <span className="text-[10px] font-sans font-medium text-slate-400 hidden sm:inline">
            Nodes
          </span>
        </div>

        {/* Plus Button */}
        <button
          onClick={() => setShowAddModal(true)}
          className={`p-1 rounded-md border transition-all ${
            isDark
              ? 'bg-slate-800/80 border-slate-700 hover:bg-cyan-950/60 hover:border-cyan-700 text-cyan-400'
              : 'bg-white border-slate-200 hover:bg-blue-50 hover:border-blue-300 text-blue-600'
          }`}
          title="Provision and add new system to network"
          aria-label="Add Computer"
        >
          <Plus className="w-3 h-3" />
        </button>
      </div>

      {/* MODAL 1: ADD SYSTEM (Template or Custom) */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div 
            className={`w-full max-w-2xl max-h-[85vh] rounded-2xl border shadow-2xl flex flex-col overflow-hidden ${
              isDark ? 'bg-[#0a0f18] border-blue-900/60 text-neutral-200' : 'bg-white border-slate-300 text-slate-800'
            }`}
          >
            <div className={`px-6 py-4 border-b flex items-center justify-between ${
              isDark ? 'bg-black/60 border-neutral-800' : 'bg-slate-100 border-slate-200'
            }`}>
              <div className="flex items-center space-x-2">
                <PlusCircle className="w-5 h-5 text-blue-500" />
                <h3 className="font-bold text-sm tracking-wide">Add a Computer / System to Network</h3>
              </div>
              <button 
                onClick={() => setShowAddModal(false)} 
                className={`p-1.5 rounded-lg transition-colors ${
                  isDark ? 'text-neutral-400 hover:text-white hover:bg-neutral-800' : 'text-slate-500 hover:text-slate-900 hover:bg-slate-200'
                }`}
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-5 text-xs">
              {/* Presets Catalog */}
              <div>
                <span className="text-[10px] font-bold uppercase tracking-wider text-neutral-500 block mb-2">
                  Choose from Ready-to-Use Computer Templates
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {PRESET_SYSTEM_TEMPLATES.map(tmpl => {
                    const alreadyExists = systems.some(s => s.name === tmpl.name || s.id === tmpl.id);

                    return (
                      <div
                        key={tmpl.id}
                        className={`p-3 rounded-xl border flex flex-col justify-between transition-all ${
                          alreadyExists
                            ? 'opacity-40 bg-neutral-900/20 border-neutral-800/40 cursor-not-allowed'
                            : isDark
                            ? 'bg-neutral-900/50 border-neutral-800 hover:border-blue-500/60 cursor-pointer'
                            : 'bg-slate-50 border-slate-200 hover:border-blue-400 cursor-pointer'
                        }`}
                        onClick={() => {
                          if (!alreadyExists) {
                            onAddSystem(tmpl);
                            setShowAddModal(false);
                          }
                        }}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-bold text-xs">{tmpl.name}</span>
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-blue-500/10 text-blue-400">
                            Port {tmpl.port}
                          </span>
                        </div>
                        <p className="text-[10px] text-neutral-500 line-clamp-1 mb-2">
                          {tmpl.purpose}
                        </p>
                        <div className="flex items-center justify-between text-[10px]">
                          <span className="text-neutral-500">{tmpl.os.split(' ')[0]}</span>
                          <span className={`font-bold ${alreadyExists ? 'text-neutral-500' : 'text-blue-400'}`}>
                            {alreadyExists ? 'Added' : '+ Add Server'}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Custom System Creation */}
              <div className={`p-4 rounded-xl border space-y-3 ${
                isDark ? 'bg-black/40 border-neutral-800' : 'bg-slate-50 border-slate-200'
              }`}>
                <span className="text-[10px] font-bold uppercase tracking-wider text-neutral-500 flex items-center gap-1.5">
                  <Sparkles className="w-3.5 h-3.5 text-amber-400" /> Or Set Up a Custom Server
                </span>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[10px] text-neutral-500 uppercase font-bold mb-1">Server Name</label>
                    <input
                      type="text"
                      placeholder="e.g. Payment Gateway"
                      value={customName}
                      onChange={e => setCustomName(e.target.value)}
                      className={`w-full p-2 rounded-lg border text-xs ${
                        isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-100' : 'bg-white border-slate-300 text-slate-800'
                      }`}
                    />
                  </div>

                  <div>
                    <label className="block text-[10px] text-neutral-500 uppercase font-bold mb-1">Network Port (e.g. 80, 443, 3306)</label>
                    <input
                      type="number"
                      value={customPort}
                      onChange={e => setCustomPort(Number(e.target.value))}
                      className={`w-full p-2 rounded-lg border text-xs font-mono ${
                        isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-100' : 'bg-white border-slate-300 text-slate-800'
                      }`}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[10px] text-neutral-500 uppercase font-bold mb-1">Operating System</label>
                    <input
                      type="text"
                      value={customOs}
                      onChange={e => setCustomOs(e.target.value)}
                      className={`w-full p-2 rounded-lg border text-xs ${
                        isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-100' : 'bg-white border-slate-300 text-slate-800'
                      }`}
                    />
                  </div>

                  <div>
                    <label className="block text-[10px] text-neutral-500 uppercase font-bold mb-1">Server Purpose (What this does)</label>
                    <input
                      type="text"
                      placeholder="e.g. Processes credit card transactions"
                      value={customPurpose}
                      onChange={e => setCustomPurpose(e.target.value)}
                      className={`w-full p-2 rounded-lg border text-xs ${
                        isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-100' : 'bg-white border-slate-300 text-slate-800'
                      }`}
                    />
                  </div>
                </div>

                <button
                  onClick={handleCreateCustom}
                  disabled={!customName.trim()}
                  className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-lg text-xs uppercase tracking-wider transition-colors disabled:opacity-40"
                >
                  Add Custom Server to Network
                </button>
              </div>
            </div>

            <div className={`px-6 py-3 border-t flex justify-end ${
              isDark ? 'bg-black/60 border-neutral-800' : 'bg-slate-100 border-slate-200'
            }`}>
              <button
                onClick={() => setShowAddModal(false)}
                className={`px-4 py-1.5 rounded-lg text-xs font-bold ${
                  isDark ? 'hover:bg-neutral-800 text-neutral-400' : 'hover:bg-slate-200 text-slate-600'
                }`}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 2: REMOVE SYSTEM */}
      {showRemoveModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div 
            className={`w-full max-w-lg rounded-2xl border shadow-2xl flex flex-col overflow-hidden ${
              isDark ? 'bg-[#0a0f18] border-red-900/60 text-neutral-200' : 'bg-white border-slate-300 text-slate-800'
            }`}
          >
            <div className={`px-6 py-4 border-b flex items-center justify-between ${
              isDark ? 'bg-black/60 border-neutral-800' : 'bg-slate-100 border-slate-200'
            }`}>
              <div className="flex items-center space-x-2">
                <Trash2 className="w-5 h-5 text-red-500" />
                <h3 className="font-bold text-sm tracking-wide">Remove a Server from Network</h3>
              </div>
              <button 
                onClick={() => setShowRemoveModal(false)} 
                className={`p-1.5 rounded-lg transition-colors ${
                  isDark ? 'text-neutral-400 hover:text-white hover:bg-neutral-800' : 'text-slate-500 hover:text-slate-900 hover:bg-slate-200'
                }`}
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-3 text-xs max-h-[60vh]">
              <p className={`text-xs ${isDark ? 'text-neutral-400' : 'text-slate-600'}`}>
                Choose a server to disconnect and safely remove from your network:
              </p>

              <div className="space-y-2">
                {systems.map(sys => (
                  <div
                    key={sys.id}
                    className={`p-3 rounded-xl border flex items-center justify-between transition-colors ${
                      isDark ? 'bg-neutral-900/50 border-neutral-800 hover:border-red-900/60' : 'bg-slate-50 border-slate-200 hover:border-red-300'
                    }`}
                  >
                    <div>
                      <div className="font-bold flex items-center gap-2">
                        {sys.name}
                        <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded uppercase font-bold border ${
                          sys.status === 'HEALTHY' 
                            ? (isDark ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-emerald-100 text-emerald-800 border-emerald-300') 
                            : (isDark ? 'bg-red-500/10 text-red-400 border-red-500/30' : 'bg-red-100 text-red-800 border-red-300')
                        }`}>
                          {sys.status === 'HEALTHY' ? 'Safe' : 'Under Attack'}
                        </span>
                      </div>
                      <div className={`text-[10px] mt-0.5 ${isDark ? 'text-neutral-400' : 'text-slate-600'}`}>
                        Port: {sys.port || 80} &bull; IP: {sys.ip || '10.0.1.X'}
                      </div>
                    </div>

                    <button
                      onClick={() => {
                        onRemoveSystem(sys.id);
                        setShowRemoveModal(false);
                      }}
                      className={`px-3 py-1 rounded-lg text-xs font-bold uppercase transition-all border ${
                        isDark 
                          ? 'bg-red-600/20 hover:bg-red-600 text-red-400 hover:text-white border-red-500/30' 
                          : 'bg-red-50 hover:bg-red-600 text-red-700 hover:text-white border-red-300'
                      }`}
                    >
                      Remove Server
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div className={`px-6 py-3 border-t flex justify-end ${
              isDark ? 'bg-black/60 border-neutral-800' : 'bg-slate-100 border-slate-200'
            }`}>
              <button
                onClick={() => setShowRemoveModal(false)}
                className={`px-4 py-1.5 rounded-lg text-xs font-bold ${
                  isDark ? 'hover:bg-neutral-800 text-neutral-400' : 'hover:bg-slate-200 text-slate-600'
                }`}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
