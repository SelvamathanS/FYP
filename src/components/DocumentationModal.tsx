import React, { useState } from 'react';
import { X, BookOpen, Bug, Server, Search, AlertTriangle, ShieldCheck, CheckCircle2, Code, Download } from 'lucide-react';
import { PRESET_BUGS_CATALOG } from '../data/systemsAndBugsCatalog';
import { ThemeMode, GraphNode, GraphEdge } from '../types/threatGraph';
import { SystemTechnicalViewer, BugTechnicalViewer } from './TechnicalCodeViewer';

interface DocumentationModalProps {
  isOpen: boolean;
  onClose: () => void;
  nodes: GraphNode[];
  edges: GraphEdge[];
  theme: ThemeMode;
  onSelectSystemForInjection?: (systemId: string) => void;
  initialTab?: 'systems' | 'bugs';
  customCodes?: Record<string, any>;
  onUpdateCode?: (bugId: string, updated: any) => void;
  onDownloadReport?: () => void;
  onLiveBugFix?: (vulnId: string, systemId?: string) => void;
}

export const DocumentationModal: React.FC<DocumentationModalProps> = ({
  isOpen,
  onClose,
  nodes,
  edges,
  theme,
  onSelectSystemForInjection,
  initialTab = 'systems',
  customCodes = {},
  onUpdateCode,
  onDownloadReport,
  onLiveBugFix
}) => {
  const [activeTab, setActiveTab] = useState<'systems' | 'bugs'>(initialTab);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedBugId, setSelectedBugId] = useState<string | null>(null);
  const [selectedSystemId, setSelectedSystemId] = useState<string | null>(null);
  const isDark = theme === 'dark';

  // Synchronize active tab with initialTab when opening modal
  React.useEffect(() => {
    if (isOpen && initialTab) {
      setActiveTab(initialTab);
    }
  }, [isOpen, initialTab]);

  if (!isOpen) return null;

  const systemNodes = nodes.filter(n => n.label === 'Software');
  const vulnerabilityNodes = nodes.filter(n => n.label === 'Vulnerability');

  // Enrich bugs catalog with current live status from graph
  const allBugs = PRESET_BUGS_CATALOG.map(catalogBug => {
    const liveNode = vulnerabilityNodes.find(n => n.id === catalogBug.id);
    const affectedEdge = edges.find(e => e.from === catalogBug.id && e.label === 'AFFECTS');
    const affectedSystem = affectedEdge ? affectedEdge.to : catalogBug.targetSoftwareId;
    return {
      ...catalogBug,
      targetSoftwareId: affectedSystem,
      status: (liveNode?.status as any) || catalogBug.status
    };
  });

  // Also include any live injected vulnerabilities not in preset catalog
  vulnerabilityNodes.forEach(vn => {
    if (!allBugs.some(b => b.id === vn.id)) {
      const affectedEdge = edges.find(e => e.from === vn.id && e.label === 'AFFECTS');
      allBugs.push({
        id: vn.id,
        name: vn.name || vn.id,
        targetSoftwareId: affectedEdge?.to || 'Infrastructure Target',
        severity: (vn.severity as any) || 'CRITICAL',
        cvss: vn.cvss || 9.0,
        description: vn.description || vn.details || 'Zero-day vulnerability payload stream',
        cause: vn.cause || 'Unvalidated memory buffer or input parameter',
        reproduction: vn.reproduction || 'Automated exploit payload',
        installationProcedure: vn.installationProcedure || 'TCP exploit sequence delivery',
        symptoms: vn.symptoms || 'High CPU, process crash, root shell elevation',
        troubleshootingProcess: vn.troubleshootingProcess || 'Inspect system logs and active sockets',
        fixSolution: vn.fixSolution || 'Deploy vendor patch and restrict firewall ingress',
        verificationProcedure: vn.verificationProcedure || 'Run exploit regression test',
        status: (vn.status as any) || 'UNMITIGATED',
        dataset: vn.dataset || 'Live Payload Stream'
      });
    }
  });

  const filteredSystems = systemNodes.filter(s =>
    s.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    s.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (s.purpose && s.purpose.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  const filteredBugs = allBugs.filter(b =>
    b.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    b.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
    b.targetSoftwareId.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div 
        className={`w-full max-w-5xl h-[88vh] rounded-2xl border shadow-2xl flex flex-col overflow-hidden transition-all duration-300 ${
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
            <div className="p-2 rounded-lg bg-blue-600/20 text-blue-400 border border-blue-500/30">
              <BookOpen className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold tracking-wide flex items-center gap-2">
                Knowledge Hub: Systems Catalog, Architecture & CTI Intelligence
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  Knowledge Hub
                </span>
              </h2>
              <p className={`text-xs ${isDark ? 'text-neutral-400' : 'text-slate-500'}`}>
                Authoritative catalog of network infrastructure systems, CTI threat intelligence, and automated remediation specifications
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

        {/* Navigation & Search Bar */}
        <div 
          className={`px-6 py-3 border-b flex flex-col md:flex-row items-center justify-between gap-4 ${
            isDark ? 'bg-neutral-950/70 border-neutral-800' : 'bg-slate-50 border-slate-200'
          }`}
        >
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setActiveTab('systems')}
              className={`px-4 py-2 rounded-lg font-bold text-xs uppercase tracking-wider transition-all flex items-center gap-2 ${
                activeTab === 'systems'
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
                  : isDark ? 'text-neutral-400 hover:bg-neutral-800' : 'text-slate-600 hover:bg-slate-200'
              }`}
            >
              <Server className="w-4 h-4" /> Computer Systems ({systemNodes.length})
            </button>
            <button
              onClick={() => setActiveTab('bugs')}
              className={`px-4 py-2 rounded-lg font-bold text-xs uppercase tracking-wider transition-all flex items-center gap-2 ${
                activeTab === 'bugs'
                  ? 'bg-red-600 text-white shadow-md shadow-red-600/30'
                  : isDark ? 'text-neutral-400 hover:bg-neutral-800' : 'text-slate-600 hover:bg-slate-200'
              }`}
            >
              <Bug className="w-4 h-4" /> Security Flaws & Bugs ({allBugs.length})
            </button>
          </div>

          <div className="flex items-center gap-2.5 w-full md:w-auto justify-end">
            <div className="relative w-full md:w-64">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-neutral-500" />
              <input
                type="text"
                placeholder={`Search ${activeTab}...`}
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className={`w-full pl-9 pr-3 py-1.5 rounded-lg border text-xs focus:outline-none transition-colors ${
                  isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-200 focus:border-blue-500' : 'bg-white border-slate-300 text-slate-800 focus:border-blue-500'
                }`}
              />
            </div>

            {onDownloadReport && (
              <button
                onClick={onDownloadReport}
                className={`px-3 py-1.5 rounded-lg border text-xs font-serif font-semibold flex items-center gap-1.5 transition-all shrink-0 shadow-xs ${
                  isDark 
                    ? 'bg-gradient-to-r from-emerald-950/60 to-teal-950/60 border-emerald-700/60 text-emerald-300 hover:text-white hover:border-emerald-400 hover:bg-emerald-900/50' 
                    : 'bg-emerald-50 border-emerald-300 text-emerald-900 hover:bg-emerald-100 hover:border-emerald-500 font-bold'
                }`}
                title="Download JSON Summary Report of all systems, vulnerabilities, and graph topology"
              >
                <Download className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Export JSON Report</span>
              </button>
            )}
          </div>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4 text-xs">
          
          {/* TAB 1: SYSTEMS CATALOG */}
          {activeTab === 'systems' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filteredSystems.map(system => {
                const connectedBugs = edges
                  .filter(e => e.to === system.id && (e.label === 'AFFECTS' || e.label === 'EXPLOITS'))
                  .map(e => nodes.find(n => n.id === e.from))
                  .filter(Boolean);

                const unmitigatedBugs = connectedBugs.filter(b => b?.status === 'UNMITIGATED');
                const isSelected = selectedSystemId === system.id;

                return (
                  <div
                    key={system.id}
                    onClick={() => setSelectedSystemId(isSelected ? null : system.id)}
                    className={`p-4 rounded-xl border transition-all cursor-pointer ${
                      isSelected
                        ? isDark ? 'bg-blue-950/30 border-blue-500 shadow-lg' : 'bg-blue-50/80 border-blue-500 shadow-lg'
                        : isDark ? 'bg-neutral-900/50 border-neutral-800 hover:border-neutral-700' : 'bg-slate-50 border-slate-200 hover:border-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Server className="w-4 h-4 text-blue-400" />
                        <h3 className="font-bold text-sm">{system.name}</h3>
                      </div>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold uppercase ${
                        system.status === 'HEALTHY'
                          ? (isDark ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-emerald-100 text-emerald-800 border border-emerald-300')
                          : system.status === 'COMPROMISED'
                          ? (isDark ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-red-100 text-red-800 border border-red-300')
                          : (isDark ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' : 'bg-amber-100 text-amber-900 border border-amber-300')
                      }`}>
                        {system.status || 'ONLINE'}
                      </span>
                    </div>

                    <p className={`mb-3 ${isDark ? 'text-neutral-400' : 'text-slate-700'}`}>
                      {system.purpose || system.description || 'Production Component'}
                    </p>

                    <div className="grid grid-cols-2 gap-2 text-[11px] mb-3">
                      <div><span className={isDark ? "text-neutral-400 font-bold" : "text-slate-600 font-bold"}>Application:</span> <span className={isDark ? "text-neutral-200 font-semibold" : "text-slate-900 font-semibold"}>{system.application || 'Production Service'}</span></div>
                      <div><span className={isDark ? "text-neutral-400 font-bold" : "text-slate-600 font-bold"}>Technology:</span> <span className={isDark ? "text-neutral-200 font-semibold" : "text-slate-900 font-semibold"}>{system.technology || 'Linux / Service'}</span></div>
                      <div><span className={isDark ? "text-neutral-400 font-bold" : "text-slate-600 font-bold"}>Hostname / OS:</span> <span className={isDark ? "text-neutral-200" : "text-slate-900 font-medium"}>{system.hostname || system.name} ({system.os || 'Ubuntu 24.04'})</span></div>
                      <div><span className={isDark ? "text-neutral-400 font-bold" : "text-slate-600 font-bold"}>Port & IP:</span> <code className={`font-mono font-medium ${isDark ? 'text-neutral-200' : 'text-slate-900'}`}>{system.ip || '192.168.10.100'}:{system.port || 80}</code></div>
                    </div>

                    <div className={`pt-3 border-t text-[11px] ${isDark ? 'border-neutral-800' : 'border-slate-200'}`}>
                      <div className="flex items-center justify-between mb-1.5">
                        <span className={`font-bold uppercase tracking-wider text-[10px] ${isDark ? 'text-neutral-400' : 'text-slate-600'}`}>
                          Associated Bugs ({connectedBugs.length})
                        </span>
                        {unmitigatedBugs.length > 0 ? (
                          <span className={`font-bold text-[10px] flex items-center gap-1 ${isDark ? 'text-red-400' : 'text-red-700'}`}>
                            <AlertTriangle className="w-3 h-3" /> {unmitigatedBugs.length} At Risk
                          </span>
                        ) : (
                          <span className={`font-bold text-[10px] flex items-center gap-1 ${isDark ? 'text-emerald-400' : 'text-emerald-700'}`}>
                            <CheckCircle2 className="w-3 h-3" /> Clean / Healed
                          </span>
                        )}
                      </div>

                      <div className="flex flex-wrap gap-1.5">
                        {connectedBugs.map(b => (
                          <span
                            key={b!.id}
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                              b!.status === 'UNMITIGATED'
                                ? (isDark ? 'bg-red-950/60 text-red-400 border border-red-800/40' : 'bg-red-50 text-red-900 border border-red-200')
                                : (isDark ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/40' : 'bg-emerald-50 text-emerald-900 border border-emerald-200')
                            }`}
                          >
                            {b!.id}
                          </span>
                        ))}
                        {connectedBugs.length === 0 && (
                          <span className="text-neutral-500 italic text-[10px]">No security vulnerabilities attached.</span>
                        )}
                      </div>
                    </div>

                    {/* Expanded details */}
                    {isSelected && (
                      <div className={`mt-4 pt-3 border-t space-y-2 text-[11px] ${isDark ? 'border-neutral-800' : 'border-slate-200'}`}>
                        <div>
                          <span className="text-neutral-500 font-bold">Service Daemon:</span> <code className="font-mono ml-1">{system.service || 'daemon.service'}</code>
                        </div>
                        <div>
                          <span className="text-neutral-500 font-bold">Config File:</span> <code className="font-mono ml-1">{system.configFile || 'app.conf'} ({system.configPath || '/etc/'})</code>
                        </div>
                        <div>
                          <span className="text-neutral-500 font-bold">Tools:</span> <span className="ml-1">{system.availableTools || 'systemctl, journalctl, curl'}</span>
                        </div>
                        <div>
                          <span className="text-neutral-500 font-bold">Dependencies:</span> <span className="ml-1">{system.dependencies || 'glibc, openssl'}</span>
                        </div>

                        {/* Real System Implementation Code & Associated Tools */}
                        <div onClick={(e) => e.stopPropagation()}>
                          <SystemTechnicalViewer systemId={system.id} isDark={isDark} />
                        </div>

                        {onSelectSystemForInjection && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectSystemForInjection(system.id);
                              onClose();
                            }}
                            className="mt-3 w-full py-1.5 bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/40 font-bold rounded-lg uppercase tracking-wider text-[10px] transition-colors"
                          >
                            Target this System in Red Team Portal &rarr;
                          </button>
                        )}
                      </div>
                    )}

                  </div>
                );
              })}
            </div>
          )}

          {/* TAB 2: BUG & CVE LIBRARY */}
          {activeTab === 'bugs' && (
            <div className="space-y-4">
              {filteredBugs.map(bug => {
                const isExpanded = selectedBugId === bug.id;

                return (
                  <div
                    key={bug.id}
                    className={`rounded-xl border transition-all ${
                      isExpanded
                        ? isDark ? 'bg-red-950/20 border-red-500/80 shadow-xl' : 'bg-red-50/50 border-red-400 shadow-xl'
                        : isDark ? 'bg-neutral-900/40 border-neutral-800 hover:border-neutral-700' : 'bg-slate-50 border-slate-200 hover:border-slate-300'
                    }`}
                  >
                    <div 
                      onClick={() => setSelectedBugId(isExpanded ? null : bug.id)}
                      className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 cursor-pointer"
                    >
                      <div className="flex items-start gap-3">
                        <div className={`p-2 rounded-lg shrink-0 mt-0.5 ${
                          bug.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                          bug.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                          bug.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' :
                          'bg-blue-500/20 text-blue-400'
                        }`}>
                          <Bug className="w-5 h-5" />
                        </div>
                        <div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-bold text-sm">{bug.name}</span>
                            <span className={`font-mono text-xs px-2 py-0.5 rounded border ${
                              isDark ? 'bg-neutral-800 text-neutral-300 border-neutral-700' : 'bg-slate-200 text-slate-700 border-slate-300'
                            }`}>
                              {bug.id}
                            </span>
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase border ${
                              bug.severity === 'CRITICAL' 
                                ? (isDark ? 'bg-red-950 text-red-400 border-red-800' : 'bg-red-50 text-red-700 border-red-200') :
                              bug.severity === 'HIGH' 
                                ? (isDark ? 'bg-orange-950 text-orange-400 border-orange-800' : 'bg-orange-50 text-orange-700 border-orange-200') :
                                (isDark ? 'bg-yellow-950 text-yellow-400 border-yellow-800' : 'bg-yellow-50 text-yellow-800 border-yellow-200')
                            }`}>
                              {bug.severity} &bull; CVSS {bug.cvss}
                            </span>
                          </div>
                          <div className={`text-xs mt-1 ${isDark ? 'text-neutral-400' : 'text-slate-500'}`}>
                            Target System: <span className={`font-semibold ${isDark ? 'text-neutral-200' : 'text-slate-800'}`}>{bug.targetSoftwareId}</span> &bull; Provenance: <span className="italic">{bug.dataset}</span>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2.5 shrink-0 flex-wrap">
                        {/* Instant View Code & Fix Button */}
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedBugId(isExpanded ? null : bug.id);
                          }}
                          className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-semibold flex items-center gap-1.5 transition-all shadow-xs ${
                            isExpanded
                              ? 'bg-amber-500 text-black font-bold'
                              : isDark 
                                ? 'bg-amber-500/20 text-amber-300 hover:bg-amber-500/30 border border-amber-500/40' 
                                : 'bg-amber-100 text-amber-800 hover:bg-amber-200 border border-amber-300'
                          }`}
                        >
                          <Code className="w-3.5 h-3.5" />
                          <span>{isExpanded ? 'Hide Code' : 'View Code & Fix'}</span>
                        </button>

                        <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider flex items-center gap-1 border ${
                          bug.status === 'UNMITIGATED'
                            ? (isDark ? 'bg-red-950/80 text-red-400 border-red-800' : 'bg-red-50 text-red-700 border-red-200')
                            : (isDark ? 'bg-emerald-950/80 text-emerald-400 border-emerald-800' : 'bg-emerald-50 text-emerald-700 border-emerald-200')
                        }`}>
                          {bug.status === 'UNMITIGATED' ? <AlertTriangle className="w-3 h-3" /> : <ShieldCheck className="w-3 h-3" />}
                          {bug.status}
                        </span>
                        <span className="text-neutral-500 text-xs font-mono">
                          {isExpanded ? '▲ Hide Details' : '▼ Full Specification'}
                        </span>
                      </div>
                    </div>

                    {/* Expanded Technical Specification */}
                    {isExpanded && (
                      <div className={`p-5 border-t space-y-4 text-xs ${isDark ? 'bg-black/40 border-neutral-800' : 'bg-white border-slate-200'}`}>
                        {/* Real Buggy Code, Exploit Script, Error Trace & Corrected Fix at the TOP */}
                        <div onClick={(e) => e.stopPropagation()} className="pb-2">
                          <BugTechnicalViewer 
                            bugId={bug.id} 
                            isDark={isDark} 
                            nodeProperties={bug}
                            customCode={customCodes[bug.id]}
                            onUpdateCode={(updated) => onUpdateCode && onUpdateCode(bug.id, updated)}
                            onLiveBugFix={onLiveBugFix}
                          />
                        </div>

                        <div>
                          <span className={`font-bold uppercase tracking-wider text-[10px] block mb-1 ${
                            isDark ? 'text-neutral-400' : 'text-slate-600 font-bold'
                          }`}>
                            Description & What This Flaw Does
                          </span>
                          <p className={`leading-relaxed ${isDark ? 'text-neutral-200' : 'text-slate-900 font-normal'}`}>
                            {bug.description}
                          </p>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className={`p-3 rounded-lg border ${isDark ? 'bg-neutral-900/60 border-neutral-800' : 'bg-slate-50 border-slate-200'}`}>
                            <span className={`font-bold uppercase tracking-wider text-[10px] block mb-1 ${
                              isDark ? 'text-red-400' : 'text-red-800 font-bold'
                            }`}>
                              Why This Bug Exists (Root Cause)
                            </span>
                            <p className={isDark ? 'text-neutral-200' : 'text-slate-900 font-normal'}>
                              {bug.cause}
                            </p>
                          </div>

                          <div className={`p-3 rounded-lg border ${isDark ? 'bg-neutral-900/60 border-neutral-800' : 'bg-slate-50 border-slate-200'}`}>
                            <span className={`font-bold uppercase tracking-wider text-[10px] block mb-1 ${
                              isDark ? 'text-amber-400' : 'text-amber-800 font-bold'
                            }`}>
                              Signs of Attack (Symptoms)
                            </span>
                            <p className={isDark ? 'text-neutral-200' : 'text-slate-900 font-normal'}>
                              {bug.symptoms}
                            </p>
                          </div>
                        </div>

                        <div>
                          <span className={`font-bold uppercase tracking-wider text-[10px] block mb-1 ${
                            isDark ? 'text-neutral-400' : 'text-slate-600 font-bold'
                          }`}>
                            How Attackers Trigger It (Test Command)
                          </span>
                          <code className={`block p-2.5 rounded font-mono text-[11px] border overflow-x-auto ${
                            isDark ? 'bg-neutral-950 border-neutral-800 text-blue-300' : 'bg-slate-100 border-slate-300 text-slate-950 font-medium'
                          }`}>
                            {bug.reproduction}
                          </code>
                        </div>

                        <div>
                          <span className={`font-bold uppercase tracking-wider text-[10px] block mb-1 ${
                            isDark ? 'text-neutral-400' : 'text-slate-600 font-bold'
                          }`}>
                            How This Flaw is Introduced (Attack Step)
                          </span>
                          <p className={`leading-relaxed ${isDark ? 'text-neutral-200' : 'text-slate-900 font-normal'}`}>
                            {bug.installationProcedure}
                          </p>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className={`p-3 rounded-lg border ${isDark ? 'bg-neutral-900/60 border-neutral-800' : 'bg-slate-50 border-slate-200'}`}>
                            <span className={`font-bold uppercase tracking-wider text-[10px] block mb-1 ${
                              isDark ? 'text-blue-400' : 'text-blue-800 font-bold'
                            }`}>
                              How to Spot & Diagnose the Flaw
                            </span>
                            <p className={isDark ? 'text-neutral-200' : 'text-slate-900 font-normal'}>
                              {bug.troubleshootingProcess}
                            </p>
                          </div>

                          <div className={`p-3 rounded-lg border ${isDark ? 'bg-neutral-900/60 border-neutral-800' : 'bg-slate-50 border-slate-200'}`}>
                            <span className={`font-bold uppercase tracking-wider text-[10px] block mb-1 ${
                              isDark ? 'text-emerald-400' : 'text-emerald-800 font-bold'
                            }`}>
                              How We Fix It (Solution & Patch)
                            </span>
                            <p className={isDark ? 'text-neutral-200' : 'text-slate-900 font-normal'}>
                              {bug.fixSolution || 'Apply defensive parameter bounds validation and install updated security release.'}
                            </p>
                          </div>
                        </div>

                        <div>
                          <span className={`font-bold uppercase tracking-wider text-[10px] block mb-1 ${
                            isDark ? 'text-purple-400' : 'text-purple-800 font-bold'
                          }`}>
                            How We Test & Verify the Fix Works
                          </span>
                          <p className={`leading-relaxed ${isDark ? 'text-neutral-200' : 'text-slate-900 font-normal'}`}>
                            {bug.verificationProcedure}
                          </p>
                        </div>
                      </div>
                    )}

                  </div>
                );
              })}
            </div>
          )}

        </div>

        {/* Footer */}
        <div 
          className={`px-6 py-3 border-t flex items-center justify-between ${
            isDark ? 'bg-black/60 border-neutral-800' : 'bg-slate-100 border-slate-200'
          }`}
        >
          <span className="text-[11px] text-neutral-500 font-mono">
            Showing {activeTab === 'systems' ? filteredSystems.length : filteredBugs.length} recorded items
          </span>
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
