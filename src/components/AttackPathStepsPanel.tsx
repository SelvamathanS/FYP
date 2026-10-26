import React from 'react';
import { 
  GitFork, Route, Shield, AlertTriangle, ArrowRight, CheckCircle2, 
  Flame, Crosshair, Server, Bug, Sparkles, X, ChevronRight, 
  ExternalLink, Wrench, ShieldAlert, Cpu
} from 'lucide-react';
import { GraphNode } from '../types/threatGraph';
import { ShortestPathResult, PathStep } from '../utils/shortestPath';

interface AttackPathStepsPanelProps {
  isDark: boolean;
  pathResult: ShortestPathResult | null;
  nodes: GraphNode[];
  selectedThreatActor: string;
  onSelectThreatActor: (id: string) => void;
  selectedSoftware: string;
  onSelectSoftware: (id: string) => void;
  onCalculatePath: (actorId?: string, swId?: string) => void;
  onClearPath: () => void;
  onSelectNode: (node: GraphNode) => void;
  onLiveBugFix?: (vulnId: string) => void;
}

export const AttackPathStepsPanel: React.FC<AttackPathStepsPanelProps> = ({
  isDark,
  pathResult,
  nodes,
  selectedThreatActor,
  onSelectThreatActor,
  selectedSoftware,
  onSelectSoftware,
  onCalculatePath,
  onClearPath,
  onSelectNode,
  onLiveBugFix
}) => {
  const threatActors = nodes.filter(n => n.label === 'ThreatActor');
  const softwareSystems = nodes.filter(n => n.label === 'Software');

  const quickPresets = [
    { label: 'APT29 ➔ Apache', actor: 'APT29', sw: 'Apache Web Server' },
    { label: 'Lazarus ➔ DB', actor: 'Lazarus', sw: 'Customer DB' },
    { label: 'Sandworm ➔ DC', actor: 'Sandworm', sw: 'Windows DC' },
    { label: 'FIN7 ➔ Payment', actor: 'FIN7', sw: 'Payment Gateway' }
  ];

  return (
    <div className="flex-1 overflow-y-auto flex flex-col p-4 space-y-4 text-xs">
      
      {/* Top Controls: Attacker & Target Selectors */}
      <div className={`p-3.5 rounded-xl border space-y-3 ${
        isDark ? 'bg-slate-900/60 border-slate-800' : 'bg-slate-50 border-slate-200'
      }`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Route className="w-4 h-4 text-amber-500" />
            <span className="font-serif font-bold text-xs text-slate-800 dark:text-slate-100">
              Shortest Path Analyzer
            </span>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-cyan-400 border border-blue-500/20 font-semibold">
            BFS Algorithm
          </span>
        </div>

        <p className="text-[11px] text-slate-500 dark:text-slate-400">
          Find the minimum-hop infiltration chain from an adversary group to a targeted computer system.
        </p>

        {/* Inputs Grid */}
        <div className="space-y-2.5">
          {/* Threat Actor Dropdown */}
          <div>
            <label className="text-[10px] uppercase font-bold text-slate-400 dark:text-slate-500 flex items-center gap-1 mb-1">
              <Crosshair className="w-3 h-3 text-red-400" />
              1. Origin Threat Actor
            </label>
            <select
              value={selectedThreatActor}
              onChange={(e) => {
                onSelectThreatActor(e.target.value);
                onCalculatePath(e.target.value, selectedSoftware);
              }}
              className={`w-full px-2.5 py-1.5 rounded-lg border text-xs outline-none transition-colors ${
                isDark 
                  ? 'bg-slate-950 border-slate-800 text-slate-200 focus:border-cyan-500' 
                  : 'bg-white border-slate-200 text-slate-800 focus:border-blue-500'
              }`}
            >
              {threatActors.map(actor => (
                <option key={actor.id} value={actor.id}>
                  {actor.name} ({actor.id})
                </option>
              ))}
            </select>
          </div>

          {/* Software System Dropdown */}
          <div>
            <label className="text-[10px] uppercase font-bold text-slate-400 dark:text-slate-500 flex items-center gap-1 mb-1">
              <Server className="w-3 h-3 text-blue-400" />
              2. Target Computer System
            </label>
            <select
              value={selectedSoftware}
              onChange={(e) => {
                onSelectSoftware(e.target.value);
                onCalculatePath(selectedThreatActor, e.target.value);
              }}
              className={`w-full px-2.5 py-1.5 rounded-lg border text-xs outline-none transition-colors ${
                isDark 
                  ? 'bg-slate-950 border-slate-800 text-slate-200 focus:border-cyan-500' 
                  : 'bg-white border-slate-200 text-slate-800 focus:border-blue-500'
              }`}
            >
              {softwareSystems.map(sw => (
                <option key={sw.id} value={sw.id}>
                  {sw.name} [{sw.status || 'ACTIVE'}]
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2 pt-1">
          <button
            onClick={() => onCalculatePath(selectedThreatActor, selectedSoftware)}
            className="flex-1 py-1.5 px-3 rounded-lg text-xs font-serif font-semibold bg-gradient-to-r from-amber-500 via-orange-500 to-red-500 text-white shadow-sm hover:opacity-95 active:scale-[0.98] transition-all flex items-center justify-center gap-1.5"
          >
            <Route className="w-3.5 h-3.5" />
            <span>Calculate Shortest Path</span>
          </button>
          
          {pathResult?.found && (
            <button
              onClick={onClearPath}
              className={`py-1.5 px-2.5 rounded-lg border text-xs font-serif transition-colors flex items-center gap-1 ${
                isDark ? 'bg-slate-800 border-slate-700 text-slate-300 hover:text-white' : 'bg-slate-100 border-slate-200 text-slate-600 hover:bg-slate-200'
              }`}
              title="Clear Highlight from Graph"
            >
              <X className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Clear</span>
            </button>
          )}
        </div>

        {/* Quick Scenario Shortcuts */}
        <div className="pt-2 border-t border-slate-200 dark:border-slate-800/80">
          <span className="text-[10px] text-slate-400 dark:text-slate-500 block mb-1.5">
            Quick Scenario Presets:
          </span>
          <div className="flex flex-wrap gap-1.5">
            {quickPresets.map(preset => (
              <button
                key={preset.label}
                onClick={() => {
                  onSelectThreatActor(preset.actor);
                  onSelectSoftware(preset.sw);
                  onCalculatePath(preset.actor, preset.sw);
                }}
                className={`text-[10px] px-2 py-0.5 rounded-md border font-mono transition-colors ${
                  selectedThreatActor === preset.actor && selectedSoftware === preset.sw
                    ? 'bg-amber-500/20 border-amber-500/40 text-amber-400 font-bold'
                    : isDark 
                      ? 'bg-slate-950/80 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700' 
                      : 'bg-white border-slate-200 text-slate-600 hover:bg-slate-100'
                }`}
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Path Results Display */}
      {pathResult && pathResult.found ? (
        <div className="space-y-4">
          
          {/* Path Metrics Ribbon */}
          <div className={`p-3 rounded-xl border relative overflow-hidden ${
            isDark 
              ? 'bg-gradient-to-br from-amber-950/30 via-slate-900/50 to-red-950/20 border-amber-500/30' 
              : 'bg-amber-50/70 border-amber-200'
          }`}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-mono uppercase tracking-wider font-bold text-amber-500 flex items-center gap-1">
                <Flame className="w-3.5 h-3.5" />
                Active Attack Path Identified
              </span>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold uppercase ${
                pathResult.riskAssessment.level === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                pathResult.riskAssessment.level === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                'bg-blue-500/20 text-blue-400 border border-blue-500/30'
              }`}>
                {pathResult.riskAssessment.level} RISK
              </span>
            </div>

            <div className="grid grid-cols-3 gap-2 text-center my-2">
              <div className={`p-2 rounded-lg border ${
                isDark ? 'bg-slate-950/60 border-slate-800/80' : 'bg-white border-slate-300 shadow-2xs'
              }`}>
                <div className={`text-[10px] ${isDark ? 'text-slate-400' : 'text-slate-600 font-semibold'}`}>Total Distance</div>
                <div className={`font-mono font-bold text-sm ${isDark ? 'text-amber-400' : 'text-amber-800'}`}>
                  {pathResult.totalHops} {pathResult.totalHops === 1 ? 'Hop' : 'Hops'}
                </div>
              </div>

              <div className={`p-2 rounded-lg border ${
                isDark ? 'bg-slate-950/60 border-slate-800/80' : 'bg-white border-slate-300 shadow-2xs'
              }`}>
                <div className={`text-[10px] ${isDark ? 'text-slate-400' : 'text-slate-600 font-semibold'}`}>Peak Threat CVSS</div>
                <div className={`font-mono font-bold text-sm ${
                  pathResult.riskAssessment.maxCvss >= 9 
                    ? (isDark ? 'text-red-400' : 'text-red-700') 
                    : (isDark ? 'text-amber-400' : 'text-amber-700')
                }`}>
                  {pathResult.riskAssessment.maxCvss || 'N/A'}
                </div>
              </div>

              <div className={`p-2 rounded-lg border ${
                isDark ? 'bg-slate-950/60 border-slate-800/80' : 'bg-white border-slate-300 shadow-2xs'
              }`}>
                <div className={`text-[10px] ${isDark ? 'text-slate-400' : 'text-slate-600 font-semibold'}`}>Target Server</div>
                <div className={`font-mono font-bold text-[11px] truncate ${
                  pathResult.riskAssessment.targetCompromised 
                    ? (isDark ? 'text-red-400' : 'text-red-700') 
                    : (isDark ? 'text-emerald-400' : 'text-emerald-800')
                }`}>
                  {pathResult.endNode?.name}
                </div>
              </div>
            </div>

            <p className={`text-[11px] leading-relaxed mt-2 pt-2 border-t border-amber-500/20 ${
              isDark ? 'text-slate-300' : 'text-slate-800 font-medium'
            }`}>
              {pathResult.summary}
            </p>

            {/* Quick Mitigate Button if active vulnerability is on path */}
            {pathResult.riskAssessment.criticalVulnerability && onLiveBugFix && (
              <div className="mt-3 pt-2 border-t border-amber-500/20">
                <button
                  onClick={() => {
                    if (pathResult.riskAssessment.criticalVulnerability) {
                      onLiveBugFix(pathResult.riskAssessment.criticalVulnerability.id);
                    }
                  }}
                  className="w-full py-1.5 px-3 rounded-lg text-xs font-serif font-semibold bg-emerald-600 hover:bg-emerald-500 active:scale-[0.98] text-white shadow-sm transition-all flex items-center justify-center gap-1.5"
                >
                  <Shield className="w-3.5 h-3.5" />
                  <span>Break Chain: Patch {pathResult.riskAssessment.criticalVulnerability.name}</span>
                </button>
              </div>
            )}
          </div>

          {/* Detailed Step-by-Step Path Cards */}
          <div className="space-y-3">
            <div className="flex items-center justify-between text-[11px] font-serif font-bold text-slate-700 dark:text-slate-300">
              <span>Step-by-Step Attack Vector</span>
              <span className="text-[10px] font-mono text-slate-400 font-normal">
                {pathResult.steps.length} sequential nodes
              </span>
            </div>

            <div className="space-y-2 relative">
              {pathResult.steps.map((step, idx) => {
                const isFirst = idx === 0;
                const isLast = idx === pathResult.steps.length - 1;
                const isVuln = step.node.label === 'Vulnerability';
                const isSoftware = step.node.label === 'Software';
                const isActor = step.node.label === 'ThreatActor';

                return (
                  <div key={step.node.id} className="relative">
                    
                    {/* Node Card */}
                    <div 
                      onClick={() => onSelectNode(step.node)}
                      className={`p-3 rounded-xl border transition-all cursor-pointer hover:scale-[1.01] ${
                        isDark 
                          ? 'bg-slate-900/80 border-slate-800 hover:border-amber-500/60 hover:bg-slate-900' 
                          : 'bg-white border-slate-200 hover:border-amber-400 hover:shadow-md'
                      } ${
                        isFirst ? 'border-l-4 border-l-red-500' :
                        isLast ? 'border-l-4 border-l-blue-500' :
                        isVuln ? 'border-l-4 border-l-pink-500' :
                        'border-l-4 border-l-amber-500'
                      }`}
                    >
                      {/* Step Header */}
                      <div className="flex items-center justify-between mb-1.5">
                        <div className="flex items-center gap-2">
                          <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-mono font-bold ${
                            isFirst ? 'bg-red-500 text-white' :
                            isLast ? 'bg-blue-600 text-white' :
                            'bg-amber-500 text-slate-950 font-extrabold'
                          }`}>
                            {step.stepNumber}
                          </span>
                          <span className="font-serif font-bold text-xs text-slate-800 dark:text-slate-100">
                            {step.node.name}
                          </span>
                        </div>

                        <span className={`text-[9px] font-mono uppercase px-1.5 py-0.5 rounded border ${
                          isActor ? (isDark ? 'bg-red-500/10 text-red-400 border-red-500/20' : 'bg-red-50 text-red-800 border-red-300 font-bold') :
                          isSoftware ? (isDark ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' : 'bg-blue-50 text-blue-800 border-blue-300 font-bold') :
                          isVuln ? (isDark ? 'bg-pink-500/10 text-pink-400 border-pink-500/20' : 'bg-pink-50 text-pink-800 border-pink-300 font-bold') :
                          (isDark ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' : 'bg-amber-50 text-amber-800 border-amber-300 font-bold')
                        }`}>
                          {step.node.label === 'Software' ? 'Target Server' :
                           step.node.label === 'ThreatActor' ? 'Attacker' :
                           step.node.label === 'Vulnerability' ? 'Security Flaw' :
                           step.node.label === 'Malware' ? 'Malicious Tool' : step.node.label}
                        </span>
                      </div>

                      {/* Step Detail Explanation */}
                      <p className={`text-[11px] leading-snug ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>
                        {step.actionSummary}
                      </p>

                      {/* Metadata tags */}
                      <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
                        {step.node.cvss && (
                          <span className={`px-1.5 py-0.5 rounded border ${
                            isDark ? 'bg-red-950/40 text-red-400 border-red-800/40' : 'bg-red-50 text-red-800 border-red-300 font-bold'
                          }`}>
                            CVSS: {step.node.cvss}
                          </span>
                        )}
                        {step.node.status && (
                          <span className={`px-1.5 py-0.5 rounded border ${
                            step.node.status === 'COMPROMISED' || step.node.status === 'UNMITIGATED'
                              ? (isDark ? 'bg-red-500/20 text-red-400 border-red-500/30' : 'bg-red-100 text-red-800 border-red-300 font-bold')
                              : (isDark ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' : 'bg-emerald-100 text-emerald-800 border-emerald-300 font-bold')
                          }`}>
                            {step.node.status}
                          </span>
                        )}
                        {step.node.ip && (
                          <span className={isDark ? 'text-slate-400' : 'text-slate-700 font-medium'}>
                            IP: {step.node.ip}
                          </span>
                        )}
                        {step.node.port && (
                          <span className={isDark ? 'text-slate-400' : 'text-slate-700 font-medium'}>
                            Port: {step.node.port}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Edge Connector Between Steps */}
                    {step.edgeToNext && (
                      <div className="py-1.5 flex items-center justify-center relative">
                        <div className="w-0.5 h-6 bg-gradient-to-b from-amber-500 to-orange-500" />
                        <span className={`absolute px-2 py-0.5 rounded-full text-[9px] font-mono font-bold tracking-wider uppercase border shadow-sm flex items-center gap-1 ${
                          isDark ? 'bg-slate-900 text-amber-400 border-amber-500/40' : 'bg-amber-100 text-amber-900 border-amber-400'
                        }`}>
                          <ArrowRight className="w-2.5 h-2.5" />
                          {step.hopLabel || step.edgeToNext.label}
                        </span>
                      </div>
                    )}

                  </div>
                );
              })}
            </div>
          </div>

        </div>
      ) : pathResult && !pathResult.found ? (
        <div className={`p-4 rounded-xl border text-center space-y-2 ${
          isDark ? 'bg-slate-900/40 border-slate-800' : 'bg-slate-50 border-slate-200'
        }`}>
          <AlertTriangle className="w-6 h-6 text-amber-500 mx-auto" />
          <h4 className="font-serif font-bold text-xs text-slate-800 dark:text-slate-200">
            No Direct Attack Path Found
          </h4>
          <p className="text-[11px] text-slate-500 leading-relaxed">
            {pathResult.summary}
          </p>
          <div className="pt-2">
            <button
              onClick={() => {
                onSelectThreatActor('APT29');
                onSelectSoftware('Apache Web Server');
                onCalculatePath('APT29', 'Apache Web Server');
              }}
              className="px-3 py-1.5 rounded-lg text-xs font-serif font-medium bg-blue-600 text-white hover:bg-blue-500 transition-colors"
            >
              Try Connected Path: APT29 ➔ Apache
            </button>
          </div>
        </div>
      ) : (
        <div className={`p-5 rounded-xl border text-center space-y-2 ${
          isDark ? 'bg-slate-900/30 border-slate-800' : 'bg-slate-50 border-slate-200'
        }`}>
          <Route className="w-8 h-8 text-slate-400 mx-auto opacity-60" />
          <h4 className="font-serif font-semibold text-xs text-slate-700 dark:text-slate-300">
            Select Attacker & Target
          </h4>
          <p className="text-[11px] text-slate-500 max-w-[240px] mx-auto">
            Choose a Threat Actor and Computer System above, or click Calculate Shortest Path to view the highlighted vector on the graph.
          </p>
        </div>
      )}

    </div>
  );
};
