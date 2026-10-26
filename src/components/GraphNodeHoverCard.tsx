import React from 'react';
import { GraphNode, GraphEdge } from '../types/threatGraph';
import { 
  Server, 
  Bug, 
  ShieldCheck, 
  Crosshair, 
  Skull, 
  Radio, 
  Network, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldAlert,
  ArrowRight,
  Sparkles,
  Code
} from 'lucide-react';

interface GraphNodeHoverCardProps {
  node: GraphNode;
  allNodes: GraphNode[];
  allEdges: GraphEdge[];
  transform: { x: number; y: number; k: number };
  containerWidth: number;
  containerHeight: number;
  isDark: boolean;
}

export const GraphNodeHoverCard: React.FC<GraphNodeHoverCardProps> = ({
  node,
  allNodes,
  allEdges,
  transform,
  containerWidth,
  containerHeight,
  isDark
}) => {
  // Calculate node center in container coordinates
  const nodeScreenX = node.x * transform.k + transform.x;
  const nodeScreenY = node.y * transform.k + transform.y;

  // Connected entities analysis
  const incomingEdges = allEdges.filter(e => e.to === node.id);
  const outgoingEdges = allEdges.filter(e => e.from === node.id);
  const totalConnections = incomingEdges.length + outgoingEdges.length;

  const connectedVulns = incomingEdges
    .map(e => allNodes.find(n => n.id === e.from))
    .filter(n => n?.label === 'Vulnerability');

  const connectedMitigations = incomingEdges
    .map(e => allNodes.find(n => n.id === e.from))
    .filter(n => n?.label === 'Mitigation');

  // Flyout Card dimensions
  const cardWidth = 288;
  const estimatedCardHeight = 175;

  // Decide whether to show above or below the node
  // If node is in the lower 40% of the canvas, position above it
  const showAbove = (nodeScreenY + estimatedCardHeight + 50) > containerHeight;

  // Calculate clamped left coordinate
  // Ensure at least 16px padding from left and right edges
  const targetLeft = nodeScreenX - cardWidth / 2;
  const clampedLeft = Math.max(16, Math.min(containerWidth - cardWidth - 16, targetLeft));

  // Calculate target top coordinate
  const targetTop = showAbove 
    ? Math.max(16, nodeScreenY - estimatedCardHeight - 38)
    : Math.min(containerHeight - estimatedCardHeight - 16, nodeScreenY + 36);

  // Status computation
  const isHealthy = node.status === 'HEALTHY' || node.status === 'SELF_HEALED';
  const isCompromised = node.status === 'COMPROMISED' || node.status === 'UNMITIGATED';

  // Domain icon and category label with easily understandable terms
  let categoryKicker = 'SECURITY ITEM';
  let CategoryIcon = Radio;

  if (node.label === 'Software') {
    categoryKicker = 'COMPUTER SYSTEM';
    CategoryIcon = Server;
  } else if (node.label === 'Vulnerability') {
    categoryKicker = 'SECURITY FLAW (BUG / CVE)';
    CategoryIcon = Bug;
  } else if (node.label === 'Mitigation') {
    categoryKicker = 'SECURITY DEFENSE & FIX';
    CategoryIcon = ShieldCheck;
  } else if (node.label === 'ThreatActor') {
    categoryKicker = 'CYBER ATTACKER (HACKER GROUP)';
    CategoryIcon = Skull;
  } else if (node.label === 'Malware') {
    categoryKicker = 'MALICIOUS SOFTWARE (VIRUS / TOOL)';
    CategoryIcon = Radio;
  } else if (node.label === 'Technique') {
    categoryKicker = 'ATTACK METHOD (HOW THEY BREACH)';
    CategoryIcon = Crosshair;
  }

  return (
    <div
      className={`absolute pointer-events-none z-50 transition-all duration-150 ease-out select-none ${
        isDark
          ? 'bg-slate-950/95 text-slate-100 border border-slate-700/60 shadow-[0_12px_32px_rgba(0,0,0,0.6)]'
          : 'bg-white/95 text-slate-800 border border-slate-300/80 shadow-[0_12px_32px_rgba(15,23,42,0.15)]'
      } backdrop-blur-xl rounded-xl p-3.5`}
      style={{
        left: clampedLeft,
        top: targetTop,
        width: cardWidth
      }}
    >
      {/* Header Row: Category Kicker & Unboxed Live Status */}
      <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-200 dark:border-slate-800">
        <div className="flex items-center gap-1.5 text-[10px] font-semibold tracking-wider uppercase text-slate-500 dark:text-slate-400">
          <CategoryIcon className="w-3.5 h-3.5 text-blue-500 dark:text-blue-400" />
          <span>{categoryKicker}</span>
        </div>

        {/* Clean Unboxed Status Indicator (Zero-Pill Compliance) */}
        <div className="flex items-center gap-1.5 text-[11px] font-mono font-medium">
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              isCompromised
                ? 'bg-red-500 animate-pulse'
                : isHealthy
                ? 'bg-emerald-500'
                : 'bg-amber-500'
            }`}
          />
          <span
            className={
              isCompromised
                ? 'text-red-500 dark:text-red-400 font-semibold'
                : isHealthy
                ? 'text-emerald-600 dark:text-emerald-400 font-semibold'
                : 'text-amber-600 dark:text-amber-400 font-semibold'
            }
          >
            {node.status === 'COMPROMISED'
              ? 'Infected / Under Attack'
              : node.status === 'UNMITIGATED'
              ? 'Exposed (Unfixed Flaw)'
              : node.status === 'SELF_HEALED'
              ? 'Automatically Repaired'
              : node.status === 'HEALTHY'
              ? 'Safe & Healthy'
              : node.status || 'Active'}
          </span>
        </div>
      </div>

      {/* Main Title & Identifier */}
      <div className="mb-2">
        <div className="text-xs font-bold tracking-tight text-slate-950 dark:text-white flex items-center justify-between">
          <span className="truncate">{node.name}</span>
          {node.port && (
            <span className="text-[10px] font-mono text-slate-600 dark:text-slate-400 font-normal">
              :{node.port}
            </span>
          )}
        </div>
        {node.details && (
          <p className="text-[11px] text-slate-700 dark:text-slate-300 mt-0.5 line-clamp-2 leading-relaxed">
            {node.details}
          </p>
        )}
      </div>

      {/* Technical Specifications (Zero-Pill Clean Typography Grid) */}
      <div className="pt-2 border-t border-slate-200 dark:border-slate-800 text-[10px] space-y-1 font-mono">
        {node.label === 'Software' && (
          <>
            {node.application && (
              <div className="flex justify-between items-center text-slate-600 dark:text-slate-400">
                <span>Application</span>
                <span className="text-slate-950 dark:text-slate-200 font-semibold truncate max-w-[150px]">
                  {node.application}
                </span>
              </div>
            )}
            {node.technology && (
              <div className="flex justify-between items-center text-slate-600 dark:text-slate-400">
                <span>Technology</span>
                <span className="text-slate-950 dark:text-slate-200 font-semibold">
                  {node.technology}
                </span>
              </div>
            )}
            <div className="flex justify-between items-center text-slate-600 dark:text-slate-400">
              <span>Hostname / IP</span>
              <span className="text-slate-950 dark:text-slate-200 font-semibold">
                {node.hostname || node.name} ({node.ip || '192.168.10.100'}:{node.port || '80'})
              </span>
            </div>
            <div className="flex justify-between items-center text-slate-600 dark:text-slate-400">
              <span>OS Environment</span>
              <span className="text-slate-950 dark:text-slate-200 font-semibold">
                {node.os || 'Ubuntu 24.04 LTS'}
              </span>
            </div>
            {isCompromised && node.threat && (
              <div className="flex justify-between items-center text-red-500 font-bold">
                <span>Threat</span>
                <span className="truncate max-w-[150px]">{node.threat}</span>
              </div>
            )}
            <div className="flex justify-between items-center text-slate-600 dark:text-slate-400">
              <span>Security Surface</span>
              <span className="text-slate-950 dark:text-slate-200 font-semibold">
                {connectedVulns.length > 0 ? (
                  <span className={isDark ? 'text-red-400 font-semibold' : 'text-red-700 font-bold'}>{connectedVulns.length} vulnerabilities</span>
                ) : (
                  <span className={isDark ? 'text-emerald-400 font-semibold' : 'text-emerald-700 font-bold'}>0 vulnerabilities active</span>
                )}
              </span>
            </div>
          </>
        )}

        {node.label === 'Vulnerability' && (
          <>
            <div className="flex justify-between items-center text-slate-600 dark:text-slate-400">
              <span>Danger Rating</span>
              <span className={isDark ? 'text-red-400 font-bold' : 'text-red-700 font-bold'}>
                {node.severity || 'CRITICAL'} (Score {node.cvss || '9.8'}/10)
              </span>
            </div>
            <div className="flex justify-between items-center text-slate-600 dark:text-slate-400">
              <span>Fix Status</span>
              <span className={
                node.status === 'SELF_HEALED'
                  ? (isDark ? 'text-emerald-400 font-semibold' : 'text-emerald-800 font-bold')
                  : (isDark ? 'text-amber-400 font-semibold' : 'text-amber-800 font-bold')
              }>
                {node.status === 'SELF_HEALED' ? 'Automatically Repaired & Shielded' : 'Needs Repair (Exposed)'}
              </span>
            </div>
            <div className={`flex justify-between items-center pt-0.5 ${isDark ? 'text-amber-400' : 'text-amber-900 font-semibold'}`}>
              <span className="flex items-center gap-1 font-semibold">
                <Code className="w-2.5 h-2.5" />
                <span>Source Code & Fix</span>
              </span>
              <span className={`text-[9px] font-mono px-1 py-0.2 rounded border ${
                isDark ? 'bg-amber-500/10 border-amber-500/20 text-amber-300' : 'bg-amber-50 border-amber-300 text-amber-900 font-medium'
              }`}>
                {node.codeFileName || (node.codeLanguage ? `${node.codeLanguage} file` : 'Code attached')}
              </span>
            </div>
            {node.ai_generated_description && (
              <div className={`flex justify-between items-center pt-0.5 ${isDark ? 'text-cyan-300' : 'text-cyan-900 font-semibold'}`}>
                <span className="flex items-center gap-1 font-medium">
                  <Sparkles className="w-2.5 h-2.5 text-cyan-500 dark:text-cyan-400" />
                  <span>AI Security Analysis</span>
                </span>
                <span className={`text-[9px] font-mono ${isDark ? 'text-cyan-300' : 'text-cyan-800'}`}>Gemini Grounded</span>
              </div>
            )}
          </>
        )}

        {node.label === 'Mitigation' && (
          <>
            <div className="flex justify-between items-center text-slate-600 dark:text-slate-400">
              <span>Defense Type</span>
              <span className="text-emerald-700 dark:text-emerald-400 font-semibold">
                Automated Runtime Shield
              </span>
            </div>
            <div className="flex justify-between items-center text-slate-600 dark:text-slate-400">
              <span>Protection Target</span>
              <span className="text-slate-950 dark:text-slate-200 font-semibold">
                {totalConnections} Connected Nodes
              </span>
            </div>
          </>
        )}

        {node.label === 'ThreatActor' && (
          <>
            <div className="flex justify-between items-center text-slate-600 dark:text-slate-400">
              <span>Threat Category</span>
              <span className="text-red-700 dark:text-red-400 font-bold">
                Advanced Persistent Threat
              </span>
            </div>
            <div className="flex justify-between items-center text-slate-600 dark:text-slate-400">
              <span>Campaign Scope</span>
              <span className="text-slate-950 dark:text-slate-200 font-semibold">
                {totalConnections} Targeted Vectors
              </span>
            </div>
          </>
        )}

        {node.label !== 'Software' && node.label !== 'Vulnerability' && node.label !== 'Mitigation' && node.label !== 'ThreatActor' && (
          <div className="flex justify-between items-center text-slate-600 dark:text-slate-400">
            <span>Topology Graph Connections</span>
            <span className="text-slate-950 dark:text-slate-200 font-semibold">
              {totalConnections} Edges
            </span>
          </div>
        )}
      </div>

      {/* Footer Action Hint */}
      <div className="mt-2.5 pt-2 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-[9px] text-slate-600 dark:text-slate-400 font-sans">
        <span className="flex items-center gap-1 font-medium">
          <span className={`inline-block w-1.5 h-1.5 rounded-full ${node.label === 'Vulnerability' ? 'bg-amber-500 animate-pulse' : 'bg-blue-500'}`} />
          {node.label === 'Vulnerability' ? 'Click to inspect & edit bug code' : 'Click to inspect details'}
        </span>
        <span className="flex items-center gap-0.5 text-blue-700 dark:text-blue-400 font-semibold">
          Drag to reposition <ArrowRight className="w-2.5 h-2.5" />
        </span>
      </div>
    </div>
  );
};
