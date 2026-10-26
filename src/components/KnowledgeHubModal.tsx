import React, { useState } from 'react';
import { 
  X, BookOpen, Server, Search, Download, Shield, Cpu, HardDrive, 
  Network, Activity, Terminal, Layers, Database, Globe, CheckCircle2,
  ExternalLink, ChevronRight, FileText
} from 'lucide-react';
import { ThemeMode, GraphNode, GraphEdge } from '../types/threatGraph';
import { SystemTechnicalViewer } from './TechnicalCodeViewer';

interface KnowledgeHubModalProps {
  isOpen: boolean;
  onClose: () => void;
  nodes: GraphNode[];
  edges: GraphEdge[];
  theme: ThemeMode;
  onDownloadReport?: () => void;
  onSelectSystemForTesting?: (systemId: string) => void;
}

export const KnowledgeHubModal: React.FC<KnowledgeHubModalProps> = ({
  isOpen,
  onClose,
  nodes,
  edges,
  theme,
  onDownloadReport,
  onSelectSystemForTesting
}) => {
  const [activeTab, setActiveTab] = useState<'systems' | 'enclaves' | 'cti'>('systems');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSystemId, setSelectedSystemId] = useState<string | null>(null);
  const [selectedEnclave, setSelectedEnclave] = useState<string>('all');
  const isDark = theme === 'dark';

  if (!isOpen) return null;

  const systemNodes = nodes.filter(n => n.label === 'Software');

  // Categorize systems into real architectural enclaves
  const enclaves = [
    {
      id: 'dmz',
      name: 'DMZ Web Ingress Tier',
      subnet: '192.168.10.101 - 105',
      systems: systemNodes.filter(s => ['Computer 01', 'Computer 02', 'Computer 03', 'Computer 04', 'Computer 05', 'Apache Web Server', 'Nginx Reverse Proxy'].some(id => s.id.includes(id) || s.name.includes(id))),
      purpose: 'Public-facing reverse proxies, SSL termination, and web ingress controllers.'
    },
    {
      id: 'app',
      name: 'Application Cluster Tier',
      subnet: '192.168.10.106 - 112',
      systems: systemNodes.filter(s => ['Computer 06', 'Computer 08', 'Computer 09', 'Computer 10', 'Computer 11', 'Computer 12', 'Payment Gateway'].some(id => s.id.includes(id) || s.name.includes(id))),
      purpose: 'Microservices, business logic engines, API gateways, and payment processing daemons.'
    },
    {
      id: 'data',
      name: 'Internal Database & Settlement Enclave',
      subnet: '192.168.10.113 - 118',
      systems: systemNodes.filter(s => ['Computer 07', 'Computer 13', 'Computer 14', 'Computer 15', 'Computer 16', 'Computer 17', 'Computer 18', 'Database-Cluster'].some(id => s.id.includes(id) || s.name.includes(id))),
      purpose: 'PostgreSQL clusters, Redis cache nodes, employee management, and customer data stores.'
    },
    {
      id: 'scada',
      name: 'Industrial & SCADA Control Enclave',
      subnet: '192.168.10.119 - 121',
      systems: systemNodes.filter(s => ['Computer 19', 'Computer 20', 'Computer 21', 'SCADA-Controller'].some(id => s.id.includes(id) || s.name.includes(id))),
      purpose: 'Telemetry daemons, Modbus protocol bridges, and critical infrastructure automation.'
    },
    {
      id: 'core',
      name: 'Core Infrastructure & Active Directory Domain',
      subnet: '192.168.10.122 - 125',
      systems: systemNodes.filter(s => ['Computer 22', 'Computer 23', 'Computer 24', 'Computer 25', 'Active Directory Domain Controller', 'DNS Server'].some(id => s.id.includes(id) || s.name.includes(id))),
      purpose: 'Kerberos domain authentication, enterprise DNS resolvers, and network management.'
    },
    {
      id: 'dynamic',
      name: 'Dynamic Scenario & Autonomous Fleet',
      subnet: '192.168.10.126+',
      systems: systemNodes.filter(s => ['Computer 26', 'Service-'].some(prefix => s.id.startsWith(prefix) || s.name.startsWith(prefix))),
      purpose: 'On-demand provisioned systems, GraphRAG experimental workloads, and automated validation nodes.'
    }
  ];

  const filteredSystems = systemNodes.filter(s => {
    const matchesSearch = s.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (s.purpose && s.purpose.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (s.technology && s.technology.toLowerCase().includes(searchQuery.toLowerCase()));

    if (selectedEnclave === 'all') return matchesSearch;
    const enclaveObj = enclaves.find(e => e.id === selectedEnclave);
    return matchesSearch && (enclaveObj ? enclaveObj.systems.some(sys => sys.id === s.id) : true);
  });

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-200">
      <div 
        className={`w-full max-w-6xl rounded-2xl border shadow-2xl flex flex-col max-h-[92vh] overflow-hidden transition-all ${
          isDark ? 'bg-[#080d19] border-slate-800 text-slate-100' : 'bg-white border-slate-200 text-slate-800'
        }`}
      >
        {/* Header */}
        <div className={`px-6 py-4 border-b flex items-center justify-between shrink-0 ${
          isDark 
            ? 'bg-gradient-to-r from-amber-950/40 via-slate-900 to-slate-950 border-amber-800/30' 
            : 'bg-gradient-to-r from-amber-50 via-slate-50 to-orange-50 border-amber-200'
        }`}>
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-400 shadow-md">
              <BookOpen className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="font-sans font-bold text-base tracking-tight text-white dark:text-slate-100">
                  Enterprise Knowledge Hub & Systems Architecture
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  Authoritative Directory
                </span>
              </div>
              <p className="text-xs text-slate-400 font-sans">
                Comprehensive directory of 25 enterprise computer systems, network enclaves, monitored service daemons, and CTI intelligence.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {onDownloadReport && (
              <button
                onClick={onDownloadReport}
                className={`px-3 py-1.5 rounded-lg border text-xs font-sans font-semibold flex items-center gap-1.5 transition-all shadow-xs ${
                  isDark 
                    ? 'bg-emerald-950/40 border-emerald-700/60 text-emerald-300 hover:text-white hover:bg-emerald-900/50' 
                    : 'bg-emerald-50 border-emerald-300 text-emerald-900 hover:bg-emerald-100 font-bold'
                }`}
                title="Download JSON Summary Report of all systems, vulnerabilities, and graph topology"
              >
                <Download className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Export Architecture JSON</span>
              </button>
            )}

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Navigation & Filter Bar */}
        <div className={`px-6 py-3 border-b flex flex-col md:flex-row items-center justify-between gap-3 ${
          isDark ? 'bg-slate-950/60 border-slate-800/80' : 'bg-slate-50 border-slate-200'
        }`}>
          {/* Main Knowledge Hub Tabs */}
          <div className="flex items-center space-x-1.5 w-full md:w-auto">
            <button
              onClick={() => setActiveTab('systems')}
              className={`px-3.5 py-1.5 rounded-lg font-sans font-bold text-xs uppercase tracking-wider transition-all flex items-center gap-1.5 ${
                activeTab === 'systems'
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
                  : isDark ? 'text-slate-400 hover:bg-slate-800' : 'text-slate-600 hover:bg-slate-200'
              }`}
            >
              <Server className="w-3.5 h-3.5" /> Computer Systems ({systemNodes.length})
            </button>

            <button
              onClick={() => setActiveTab('enclaves')}
              className={`px-3.5 py-1.5 rounded-lg font-sans font-bold text-xs uppercase tracking-wider transition-all flex items-center gap-1.5 ${
                activeTab === 'enclaves'
                  ? 'bg-amber-600 text-white shadow-md shadow-amber-600/30'
                  : isDark ? 'text-slate-400 hover:bg-slate-800' : 'text-slate-600 hover:bg-slate-200'
              }`}
            >
              <Network className="w-3.5 h-3.5" /> Network Enclaves ({enclaves.length})
            </button>

            <button
              onClick={() => setActiveTab('cti')}
              className={`px-3.5 py-1.5 rounded-lg font-sans font-bold text-xs uppercase tracking-wider transition-all flex items-center gap-1.5 ${
                activeTab === 'cti'
                  ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30'
                  : isDark ? 'text-slate-400 hover:bg-slate-800' : 'text-slate-600 hover:bg-slate-200'
              }`}
            >
              <Database className="w-3.5 h-3.5" /> CTI & Threat Actors
            </button>
          </div>

          {/* Search Box */}
          <div className="relative w-full md:w-64">
            <Search className="w-4 h-4 absolute left-3 top-2 text-slate-500" />
            <input
              type="text"
              placeholder="Search systems, ports, daemons..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className={`w-full pl-9 pr-3 py-1.5 rounded-lg border text-xs focus:outline-none transition-colors ${
                isDark ? 'bg-slate-900 border-slate-800 text-slate-200 focus:border-amber-500' : 'bg-white border-slate-300 text-slate-800 focus:border-amber-500'
              }`}
            />
          </div>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4 text-xs">
          {/* TAB 1: COMPUTER SYSTEMS CATALOG */}
          {activeTab === 'systems' && (
            <div className="space-y-4">
              {/* Enclave Sub-filter Pills */}
              <div className="flex items-center gap-1.5 flex-wrap pb-2 border-b border-slate-800/60 text-[11px]">
                <span className="text-slate-400 font-semibold mr-1">Filter Enclave:</span>
                <button
                  onClick={() => setSelectedEnclave('all')}
                  className={`px-2 py-0.5 rounded-md font-mono transition-colors ${
                    selectedEnclave === 'all'
                      ? 'bg-blue-600 text-white'
                      : isDark ? 'bg-slate-900 text-slate-400 hover:text-white' : 'bg-slate-100 text-slate-600'
                  }`}
                >
                  All ({systemNodes.length})
                </button>
                {enclaves.map(enc => (
                  <button
                    key={enc.id}
                    onClick={() => setSelectedEnclave(enc.id)}
                    className={`px-2 py-0.5 rounded-md font-mono transition-colors ${
                      selectedEnclave === enc.id
                        ? 'bg-amber-600 text-white'
                        : isDark ? 'bg-slate-900 text-slate-400 hover:text-white' : 'bg-slate-100 text-slate-600'
                    }`}
                  >
                    {enc.name.split(' ')[0]} ({enc.systems.length})
                  </button>
                ))}
              </div>

              {/* Grid of System Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
                {filteredSystems.map(system => {
                  const connectedBugs = edges
                    .filter(e => e.to === system.id && (e.label === 'AFFECTS' || e.label === 'EXPLOITS'))
                    .map(e => nodes.find(n => n.id === e.from))
                    .filter(Boolean);

                  const unmitigatedBugs = connectedBugs.filter(b => b?.status !== 'SELF_HEALED' && b?.status !== 'APPROVED' && b?.status !== 'CLEAN');
                  const isSelected = selectedSystemId === system.id;

                  return (
                    <div
                      key={system.id}
                      onClick={() => setSelectedSystemId(isSelected ? null : system.id)}
                      className={`p-3.5 rounded-xl border transition-all cursor-pointer flex flex-col justify-between ${
                        isSelected
                          ? isDark ? 'bg-blue-950/30 border-blue-500 shadow-lg' : 'bg-blue-50/80 border-blue-500 shadow-lg'
                          : isDark ? 'bg-slate-900/50 border-slate-800 hover:border-slate-700' : 'bg-slate-50 border-slate-200 hover:border-slate-300'
                      }`}
                    >
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <Server className="w-4 h-4 text-blue-400 shrink-0" />
                            <h3 className="font-bold text-xs text-white truncate max-w-[170px]">{system.name}</h3>
                          </div>
                          <span className={`text-[9px] font-mono px-2 py-0.5 rounded-full font-bold uppercase ${
                            system.status === 'HEALTHY'
                              ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                              : system.status === 'COMPROMISED'
                              ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                              : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                          }`}>
                            {system.status || 'HEALTHY'}
                          </span>
                        </div>

                        <p className="text-[11px] text-slate-400 line-clamp-2 mb-2.5">
                          {system.purpose || system.description || 'Enterprise microservice & daemon host'}
                        </p>

                        <div className="space-y-1 text-[10px] font-mono text-slate-400 bg-black/30 p-2 rounded-lg mb-2">
                          <div className="flex justify-between">
                            <span className="text-slate-500">Service:</span>
                            <span className="text-cyan-300 font-bold">{system.service || `${system.id.toLowerCase().replace(/\s+/g, '-')}.service`}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Socket:</span>
                            <span className="text-slate-300">{system.ip || '192.168.10.100'}:{system.port || 80}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Stack:</span>
                            <span className="text-slate-300 truncate max-w-[140px]">{system.technology || 'Linux / Service'}</span>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center justify-between pt-2 border-t border-slate-800/60 text-[10px]">
                        <span className={`font-mono ${unmitigatedBugs.length > 0 ? 'text-rose-400 font-bold' : 'text-emerald-400'}`}>
                          {unmitigatedBugs.length > 0 ? `${unmitigatedBugs.length} Open Exploit${unmitigatedBugs.length > 1 ? 's' : ''}` : '0 Active Exploits'}
                        </span>
                        <span className="text-blue-400 flex items-center gap-0.5">
                          <span>{isSelected ? 'Collapse' : 'Details'}</span>
                          <ChevronRight className={`w-3 h-3 transition-transform ${isSelected ? 'rotate-90' : ''}`} />
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Expanded Technical View if a system is selected */}
              {selectedSystemId && (
                <div className="p-4 rounded-xl border border-blue-500/40 bg-slate-900/80 space-y-3 animate-in fade-in duration-150">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <span className="font-bold text-xs text-blue-300 flex items-center gap-2">
                      <Terminal className="w-4 h-4" />
                      <span>Technical Architecture & Runtime Diagnostics: {selectedSystemId}</span>
                    </span>
                    <button
                      onClick={() => setSelectedSystemId(null)}
                      className="text-xs text-slate-400 hover:text-white"
                    >
                      Close Details ✕
                    </button>
                  </div>
                  <SystemTechnicalViewer
                    systemId={selectedSystemId}
                    theme={theme}
                  />
                </div>
              )}
            </div>
          )}

          {/* TAB 2: NETWORK ENCLAVES */}
          {activeTab === 'enclaves' && (
            <div className="space-y-4">
              <p className="text-xs text-slate-400 font-sans">
                The enterprise topology is segmented into 5 isolated network security zones with dedicated egress filtering and gateway boundaries:
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {enclaves.map((enc, idx) => (
                  <div 
                    key={enc.id} 
                    className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 space-y-3"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className="w-7 h-7 rounded-lg bg-amber-500/20 text-amber-400 flex items-center justify-center font-bold text-xs font-mono">
                          Z{idx + 1}
                        </div>
                        <div>
                          <h4 className="font-bold text-xs text-white">{enc.name}</h4>
                          <span className="text-[10px] font-mono text-cyan-400">{enc.subnet}</span>
                        </div>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {enc.systems.length} Nodes
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-300 leading-relaxed">
                      {enc.purpose}
                    </p>

                    <div className="space-y-1.5 pt-2 border-t border-slate-800/80">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                        Assigned Computer Systems:
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {enc.systems.map(s => (
                          <span 
                            key={s.id}
                            className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                              s.status === 'COMPROMISED'
                                ? 'bg-rose-950/40 border-rose-800 text-rose-300'
                                : 'bg-slate-950 border-slate-800 text-slate-300'
                            }`}
                          >
                            {s.id}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 3: CTI THREAT INTELLIGENCE & STIX */}
          {activeTab === 'cti' && (
            <div className="space-y-4">
              <div className="p-3.5 rounded-xl bg-purple-950/20 border border-purple-800/40 text-xs text-purple-300 flex items-start gap-2.5">
                <Database className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold block">Cross-Document CTI Knowledge Store</span>
                  <span className="text-slate-400 text-[11px] block mt-0.5">
                    Threat actors, attack patterns, and MITRE ATT&CK techniques correlated with mathematical temporal decay scoring.
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/50 space-y-2">
                  <div className="font-bold text-xs text-amber-400 flex items-center gap-1.5">
                    <Activity className="w-3.5 h-3.5" />
                    <span>Tracked Threat Actors</span>
                  </div>
                  <div className="space-y-2 text-[11px]">
                    <div className="p-2 rounded bg-black/40 border border-slate-800 flex justify-between items-center">
                      <div>
                        <span className="font-bold text-rose-400 block">APT29 (Cozy Bear)</span>
                        <span className="text-[10px] text-slate-400">Techniques: T1190 Exploit Public-Facing, T1059 Command Scripting</span>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300">ACTIVE</span>
                    </div>

                    <div className="p-2 rounded bg-black/40 border border-slate-800 flex justify-between items-center">
                      <div>
                        <span className="font-bold text-amber-400 block">Sandworm Team</span>
                        <span className="text-[10px] text-slate-400">Techniques: T1083 File Discovery, SCADA protocol manipulation</span>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300">AGING</span>
                    </div>

                    <div className="p-2 rounded bg-black/40 border border-slate-800 flex justify-between items-center">
                      <div>
                        <span className="font-bold text-blue-400 block">Lazarus Group</span>
                        <span className="text-[10px] text-slate-400">Techniques: T1203 Client Execution, Cryptocurrency Ledger Exploits</span>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/20 text-blue-300">ACTIVE</span>
                    </div>
                  </div>
                </div>

                <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/50 space-y-2">
                  <div className="font-bold text-xs text-cyan-400 flex items-center gap-1.5">
                    <FileText className="w-3.5 h-3.5" />
                    <span>Temporal Decay Engine Specifications</span>
                  </div>
                  <div className="text-[11px] text-slate-300 space-y-2 font-mono bg-black/40 p-3 rounded-lg">
                    <div>• Half-Life Decay Formula: W = W₀ · 2^(-Δt / t_half)</div>
                    <div>• Active Window: 0 - 30 days (100% confidence weight)</div>
                    <div>• Aging Window: 30 - 90 days (70% confidence weight)</div>
                    <div>• Stale Threshold: 90 - 180 days (35% confidence weight)</div>
                    <div>• Corroboration Multiplier: +5% per independent source</div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className={`px-6 py-3 border-t flex items-center justify-between shrink-0 text-xs ${
          isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'
        }`}>
          <span className="text-[11px] text-slate-400 font-sans">
            Enterprise Knowledge Hub · Authoritative Network Topology & Architecture Directory
          </span>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-200 font-sans text-xs transition-colors"
          >
            Close Knowledge Hub
          </button>
        </div>
      </div>
    </div>
  );
};
