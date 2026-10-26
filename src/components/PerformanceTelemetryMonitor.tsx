import React, { useState, useEffect, useRef } from 'react';
import { 
  Activity, Cpu, Layers, Map as MapIcon, ChevronDown, ChevronUp, ChevronsDown, ChevronsUp,
  Zap, CheckCircle2, AlertTriangle, Flame, Server, Bug, Shield, Crosshair,
  Radio, HardDrive, Wifi, Maximize2, Minimize2, PanelRight,
  Sparkles, Terminal, RotateCcw, BarChart3
} from 'lucide-react';
import { ThemeMode, GraphNode } from '../types/threatGraph';

export interface PerformanceTelemetryProps {
  fps: number;
  frameTimeMs: number;
  fpsHistory: number[];
  nodeCount: number;
  nodeBreakdown: {
    software: number;
    vulnerability: number;
    mitigation: number;
    actorsAndTech: number;
  };
  edgeCount: number;
  edgeProcessingTimeMs: number;
  theme: ThemeMode;
  showHotZones: boolean;
  onToggleHotZones: () => void;
  showHeatmap: boolean;
  onToggleHeatmap: () => void;
  isNeo4jActive: boolean;
  nodes?: GraphNode[];
  // Portable & Sinkable capabilities
  isSunk?: boolean;
  onToggleSink?: () => void;
  dockMode?: 'docked' | 'floating';
  onToggleDockMode?: () => void;
  onClose?: () => void;
  className?: string;
}

interface TelemetryLogEntry {
  id: string;
  time: string;
  type: 'info' | 'alert' | 'success' | 'network';
  source: string;
  message: string;
}

export const PerformanceTelemetryMonitor: React.FC<PerformanceTelemetryProps> = ({
  fps,
  frameTimeMs,
  fpsHistory,
  nodeCount,
  nodeBreakdown,
  edgeCount,
  edgeProcessingTimeMs,
  theme,
  showHotZones,
  onToggleHotZones,
  showHeatmap,
  onToggleHeatmap,
  isNeo4jActive,
  nodes = [],
  isSunk = false,
  onToggleSink,
  dockMode = 'floating',
  onToggleDockMode,
  onClose,
  className = ''
}) => {
  const [isExpanded, setIsExpanded] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<'metrics' | 'feed' | 'layers' | 'diagnostics'>('metrics');
  const [simulatedStress, setSimulatedStress] = useState<boolean>(false);
  const isDark = theme === 'dark';

  // Count compromised/under attack systems from nodes
  const compromisedCount = nodes.filter(
    n => (n.label === 'Software' && n.status === 'COMPROMISED') || (n.label === 'Vulnerability' && n.status === 'UNMITIGATED')
  ).length;

  const healthyServersCount = nodes.filter(
    n => n.label === 'Software' && (n.status === 'HEALTHY' || n.status === 'SELF_HEALED')
  ).length;

  const totalServers = nodeBreakdown.software || 1;
  const securityHealthScore = Math.max(10, Math.round(((totalServers - nodes.filter(n => n.label === 'Software' && n.status === 'COMPROMISED').length) / totalServers) * 100));

  // Dynamic live performance metrics that pulse like the active SOC sensor stream
  const [cpuUsage, setCpuUsage] = useState<number>(24);
  const [ramUsageGb, setRamUsageGb] = useState<number>(4.2);
  const [packetRate, setPacketRate] = useState<number>(1420);
  const [networkMbPerSec, setNetworkMbPerSec] = useState<number>(18.5);
  const [lastUpdateAgo, setLastUpdateAgo] = useState<string>('just now');
  const [liveLogs, setLiveLogs] = useState<TelemetryLogEntry[]>([
    {
      id: 'init-1',
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      type: 'info',
      source: 'Sensor Ingress',
      message: 'SOC telemetry stream online. Live sensor ingress connected to enterprise nodes.'
    },
    {
      id: 'init-2',
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      type: 'success',
      source: 'Sensor Daemon',
      message: 'Zero-trust heartbeat signals validated across all registered infrastructure systems.'
    }
  ]);

  const logIndexRef = useRef<number>(0);

  // Dynamic Telemetry Pulse Loop (runs every 1.8 seconds)
  useEffect(() => {
    const interval = setInterval(() => {
      // 1. Calculate dynamic CPU load based on compromised nodes or stress simulation
      let baseCpu = 22;
      if (simulatedStress) {
        baseCpu = 88;
      } else if (compromisedCount > 0) {
        baseCpu = 56 + Math.min(34, compromisedCount * 8.5);
      }
      const jitter = (Math.random() * 7) - 3.5;
      const newCpu = Math.min(99, Math.max(12, Math.round((baseCpu + jitter) * 10) / 10));
      setCpuUsage(newCpu);

      // 2. Calculate dynamic RAM usage (GB out of 16 GB)
      const baseRam = 3.8 + (nodeCount * 0.07);
      const ramJitter = (Math.random() * 0.2) - 0.1;
      const newRam = Math.min(15.8, Math.max(2.5, Math.round((baseRam + ramJitter) * 100) / 100));
      setRamUsageGb(newRam);

      // 3. Dynamic network packet and throughput rate
      const basePackets = (simulatedStress || compromisedCount > 0) ? 3600 : 1350;
      const pJitter = Math.floor((Math.random() * 300) - 150);
      const newPackets = Math.max(800, basePackets + pJitter);
      setPacketRate(newPackets);

      const newMb = Math.round((newPackets * 0.0135 + Math.random() * 2) * 10) / 10;
      setNetworkMbPerSec(newMb);

      setLastUpdateAgo('just now');

      // 4. Generate dynamic telemetry log messages based on actual graph state
      const nowStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const serverNodes = nodes.filter(n => n.label === 'Software');

      if (serverNodes.length > 0) {
        const randomServer = serverNodes[Math.floor(Math.random() * serverNodes.length)];
        const isTargetCompromised = randomServer.status === 'COMPROMISED';

        let newLog: TelemetryLogEntry;
        logIndexRef.current += 1;

        if (isTargetCompromised) {
          const alertTemplates = [
            `🚨 Alert: Abnormal packet spike detected on ${randomServer.name} (Port ${randomServer.port || 80}).`,
            `⚠️ Alert: High CPU utilization on ${randomServer.name} matching exploit payload signature.`,
            `🚨 Alert: Deep packet inspection on ${randomServer.name} flagged unauthorized lateral movement.`,
            `⚠️ Alert: Suspicious outbound egress request intercepted from ${randomServer.name}.`
          ];
          newLog = {
            id: `log-${logIndexRef.current}`,
            time: nowStr,
            type: 'alert',
            source: randomServer.name,
            message: alertTemplates[Math.floor(Math.random() * alertTemplates.length)]
          };
        } else {
          const healthyTemplates = [
            `Sensor Check: ${randomServer.name} operating within nominal latency thresholds (0 dropped pkts).`,
            `Heartbeat: Port ${randomServer.port || 80} responding in 1.4ms (TLS 1.3 verified & healthy).`,
            `Defense Monitor: Zero unauthorized ingress attempts flagged on ${randomServer.name}.`,
            `System Status: CPU and memory parameters stable on ${randomServer.name}.`
          ];
          newLog = {
            id: `log-${logIndexRef.current}`,
            time: nowStr,
            type: 'info',
            source: randomServer.name,
            message: healthyTemplates[Math.floor(Math.random() * healthyTemplates.length)]
          };
        }

        setLiveLogs(prev => [newLog, ...prev.slice(0, 24)]);
      }
    }, 1800);

    return () => clearInterval(interval);
  }, [simulatedStress, compromisedCount, nodeCount, nodes]);

  // Effective display metrics
  const effectiveFps = simulatedStress ? 22 : fps;
  const effectiveFrameTime = simulatedStress ? 45.5 : frameTimeMs;
  const isStressed = simulatedStress || effectiveFps < 30 || cpuUsage > 80;

  // Status Colors
  const cpuColor = cpuUsage > 80 ? 'text-red-500 font-extrabold animate-pulse' : cpuUsage > 50 ? 'text-amber-400' : 'text-emerald-400';
  const fpsColor = effectiveFps < 30 ? 'text-red-500 font-extrabold animate-pulse' : effectiveFps < 50 ? 'text-amber-400' : 'text-emerald-400';

  // Mini sparkline for FPS
  const sparkWidth = 64;
  const sparkHeight = 16;
  const maxFpsScale = 75;
  const points = fpsHistory.map((val, idx) => {
    const x = (idx / Math.max(1, fpsHistory.length - 1)) * sparkWidth;
    const clampedVal = Math.min(maxFpsScale, Math.max(0, val));
    const y = sparkHeight - (clampedVal / maxFpsScale) * (sparkHeight - 2) - 1;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const sparklinePath = points.length > 0 ? `M ${points.join(' L ')}` : '';

  // =========================================================================
  // SUNK STATE: Portable, Compact, Non-Obstructive Bottom-Right Status Bar
  // Takes virtually ZERO graph space so the network graph remains 100% visible!
  // =========================================================================
  if (isSunk) {
    return (
      <div 
        className={`absolute bottom-3 right-3 z-30 flex items-center gap-2 p-1.5 px-3 rounded-xl border backdrop-blur-md shadow-2xl transition-all duration-300 select-none animate-in fade-in slide-in-from-bottom-2 ${
          isStressed
            ? 'bg-red-950/90 border-red-500/70 text-red-200 shadow-red-950/60 ring-1 ring-red-500/40'
            : isDark 
            ? 'bg-[#070e1c]/90 border-cyan-500/30 text-slate-200 shadow-[0_8px_30px_rgba(0,0,0,0.6)]' 
            : 'bg-white/95 border-blue-300 text-slate-800 shadow-lg'
        }`}
      >
        {/* Pulsing Radar Pulse */}
        <div className="relative flex items-center justify-center shrink-0">
          <span className={`w-2.5 h-2.5 rounded-full absolute ${
            isStressed ? 'bg-red-500 animate-ping opacity-90' : 'bg-emerald-500 animate-ping opacity-75'
          }`} />
          <span className={`w-2.5 h-2.5 rounded-full relative ${
            isStressed ? 'bg-red-500' : 'bg-emerald-500'
          }`} />
        </div>

        {/* Title */}
        <div className="flex items-center gap-1.5 border-r border-slate-700/50 pr-2.5">
          <Activity className={`w-3.5 h-3.5 ${isStressed ? 'text-red-400 animate-pulse' : 'text-cyan-400'}`} />
          <span className="font-serif font-bold text-xs tracking-tight whitespace-nowrap">
            Live Telemetry
          </span>
          <span className={`text-[9px] font-mono px-1 py-0.2 rounded border font-semibold ${
            isStressed 
              ? 'bg-red-500/20 border-red-500/40 text-red-300' 
              : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
          }`}>
            {isStressed ? 'ALERT' : 'LIVE'}
          </span>
        </div>

        {/* Vital Metrics Pill Ticker */}
        <div className="hidden sm:flex items-center gap-2.5 text-[11px] font-mono">
          <div className="flex items-center gap-1">
            <span className="text-slate-400 text-[10px]">FPS:</span>
            <span className={`font-bold ${fpsColor}`}>{effectiveFps}</span>
          </div>

          <div className="flex items-center gap-1">
            <span className="text-slate-400 text-[10px]">CPU:</span>
            <span className={`font-bold ${cpuColor}`}>{cpuUsage}%</span>
          </div>

          <div className="hidden md:flex items-center gap-1">
            <span className="text-slate-400 text-[10px]">NET:</span>
            <span className="font-bold text-cyan-400">{networkMbPerSec} MB/s</span>
          </div>

          <div className="hidden lg:flex items-center gap-1">
            <span className="text-slate-400 text-[10px]">HEALTH:</span>
            <span className={`font-bold ${
              securityHealthScore >= 80 ? 'text-emerald-400' : securityHealthScore >= 50 ? 'text-amber-400' : 'text-red-400'
            }`}>{securityHealthScore}%</span>
          </div>
        </div>

        {/* Restore / Expand Action Button */}
        {onToggleSink && (
          <button
            onClick={onToggleSink}
            className={`ml-1 px-2.5 py-1 rounded-lg border text-xs font-serif font-semibold flex items-center gap-1.5 transition-all ${
              isStressed
                ? 'bg-red-600 hover:bg-red-500 text-white border-red-400 shadow-sm'
                : isDark 
                ? 'bg-gradient-to-r from-cyan-600/30 to-blue-600/30 hover:from-cyan-600/50 hover:to-blue-600/50 border-cyan-500/50 text-cyan-200 hover:text-white shadow-sm' 
                : 'bg-blue-50 hover:bg-blue-100 border-blue-300 text-blue-900 font-bold'
            }`}
            title="Restore Telemetry Monitor (Open full live telemetry on the right)"
          >
            <Maximize2 className="w-3.5 h-3.5 text-cyan-500 dark:text-cyan-400" />
            <span>Open Monitor</span>
          </button>
        )}
      </div>
    );
  }

  // =========================================================================
  // EXPANDED STATE: Portable Docked Right Rail OR Floating HUD on Right
  // =========================================================================
  const containerClasses = dockMode === 'docked'
    ? `w-full h-full flex flex-col overflow-hidden select-none transition-colors ${
        isStressed
          ? 'bg-[#120609]/95 text-red-100'
          : isDark 
          ? 'bg-[#070d18] bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900/60 via-[#070d18] to-[#03060c] text-neutral-200' 
          : 'bg-white text-slate-800'
      } ${className}`
    : `absolute top-3 right-3 z-30 w-88 max-w-[calc(100vw-24px)] max-h-[calc(100vh-100px)] flex flex-col rounded-2xl border backdrop-blur-xl shadow-2xl transition-all duration-300 select-none overflow-hidden ${
        isStressed
          ? 'border-red-500/80 ring-2 ring-red-500/30 shadow-red-950/70 bg-[#120609]/95 text-red-100'
          : isDark 
          ? 'bg-[#070e1c]/95 border-slate-800 text-neutral-200 shadow-[0_12px_40px_rgba(0,0,0,0.7)]' 
          : 'bg-white/95 border-slate-300 text-slate-800 shadow-xl'
      } ${className}`;

  return (
    <div className={containerClasses}>
      {/* Dynamic Telemetry Header */}
      <div className={`px-3.5 py-2.5 flex items-center justify-between border-b shrink-0 transition-colors ${
        isStressed
          ? 'border-red-900/60 bg-gradient-to-r from-red-950/90 via-rose-950/80 to-red-950/90'
          : isDark 
          ? 'border-slate-800/80 bg-gradient-to-r from-slate-900/90 via-[#091326]/90 to-slate-950/90' 
          : 'border-slate-200 bg-gradient-to-r from-slate-50 via-white to-slate-100'
      } ${dockMode === 'floating' ? 'rounded-t-2xl' : ''}`}>
        
        <div className="flex items-center gap-2">
          {/* Animated Radar Pulse */}
          <div className="relative flex items-center justify-center">
            <span className={`w-2.5 h-2.5 rounded-full absolute ${
              isStressed ? 'bg-red-500 animate-ping opacity-90' : 'bg-emerald-500 animate-ping opacity-75'
            }`} />
            <span className={`w-2.5 h-2.5 rounded-full relative ${
              isStressed ? 'bg-red-500' : 'bg-emerald-500'
            }`} />
          </div>

          <div>
            <div className="flex items-center gap-1.5">
              <span className={`font-serif font-bold text-xs tracking-tight flex items-center gap-1.5 ${
                isStressed ? 'text-red-300' : (isDark ? 'text-slate-100' : 'text-slate-800')
              }`}>
                <Activity className={`w-3.5 h-3.5 ${isStressed ? 'text-red-400 animate-pulse' : 'text-cyan-400'}`} />
                Live System Telemetry
              </span>
              <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded border font-semibold ${
                isStressed 
                  ? 'bg-red-500/20 border-red-500/40 text-red-300 animate-pulse'
                  : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              }`}>
                {isStressed ? 'THREAT ACTIVE' : 'INGRESS LIVE'}
              </span>
            </div>
            <div className="text-[10px] text-slate-400 flex items-center gap-1">
              <span>SOC Sensor Stream:</span>
              <span className="font-mono text-cyan-400 font-medium">Port 443 TLS 1.3</span>
            </div>
          </div>
        </div>

        {/* Header Portable & Sink Controls */}
        <div className="flex items-center gap-1">
          {/* Dock / Float Toggle */}
          {onToggleDockMode && (
            <button
              onClick={onToggleDockMode}
              className={`p-1.5 rounded-lg border text-xs transition-colors ${
                isDark 
                  ? 'bg-slate-900/80 border-slate-800 text-slate-400 hover:text-white hover:bg-slate-800' 
                  : 'bg-white border-slate-200 text-slate-600 hover:bg-slate-100'
              }`}
              title={dockMode === 'docked' ? "Switch to Floating HUD" : "Dock to Right Rail (ensures zero graph overlap)"}
            >
              {dockMode === 'docked' ? <Minimize2 className="w-3.5 h-3.5" /> : <PanelRight className="w-3.5 h-3.5 text-cyan-400" />}
            </button>
          )}

          {/* MINIMIZE BUTTON: Smoothly collapses monitor into compact bottom dock */}
          {onToggleSink && (
            <button
              onClick={onToggleSink}
              className={`px-2 py-1 rounded-lg border text-xs font-serif font-medium flex items-center gap-1 transition-all ${
                isStressed
                  ? 'bg-red-950/60 border-red-800 text-red-200 hover:bg-red-900/60'
                  : isDark 
                  ? 'bg-slate-900/80 border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800' 
                  : 'bg-white border-slate-300 text-slate-800 hover:bg-slate-100 font-semibold'
              }`}
              title="Minimize Telemetry Monitor into compact bottom bar (leaves graph 100% free)"
            >
              <Minimize2 className="w-3.5 h-3.5 text-cyan-500 dark:text-cyan-400" />
              <span className="text-[11px] font-serif font-semibold">Minimize to Dock</span>
            </button>
          )}

          {/* Expand/Collapse Details */}
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className={`p-1.5 rounded-lg border text-xs transition-colors ${
              isStressed
                ? 'hover:bg-red-900/50 border-red-800 text-red-300'
                : isDark 
                ? 'hover:bg-slate-800 border-slate-800 text-slate-400 hover:text-white' 
                : 'hover:bg-slate-200 border-slate-300 text-slate-600 hover:text-slate-900'
            }`}
            title={isExpanded ? 'Collapse telemetry details' : 'Expand telemetry details'}
          >
            {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Under Attack Alert Banner */}
      {compromisedCount > 0 && (
        <div className="mx-3 mt-2 px-2.5 py-1.5 rounded-xl border border-red-500/60 bg-red-950/80 text-red-200 shadow-md flex items-center gap-2 animate-pulse shrink-0">
          <div className="p-1 rounded-lg bg-red-500/30 text-red-300 shrink-0">
            <AlertTriangle className="w-4 h-4 text-red-400" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="font-bold text-[10px] uppercase font-mono tracking-wider text-red-300 flex items-center gap-1.5">
              <span>Threat Payload Active</span>
              <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-ping" />
            </div>
            <div className="text-[9px] font-serif text-red-300/90 leading-tight">
              {compromisedCount} {compromisedCount === 1 ? 'target system is compromised' : 'systems are under active exploit'}. SOC telemetry sensors detect elevated compute workload.
            </div>
          </div>
        </div>
      )}

      {/* Main Dynamic 4-Metric Grid */}
      <div className="p-3 overflow-y-auto flex-1 space-y-3">
        <div className="grid grid-cols-2 gap-2">
          
          {/* Metric 1: CPU Workload (Dynamic) */}
          <div className={`p-2 rounded-xl border flex flex-col justify-between transition-colors ${
            cpuUsage > 80
              ? 'bg-red-950/40 border-red-500/60 ring-1 ring-red-500/30'
              : isDark 
              ? 'bg-slate-900/60 border-slate-800' 
              : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="flex items-center justify-between">
              <span className={`text-[10px] font-serif uppercase tracking-tight flex items-center gap-1 font-semibold ${
                isDark ? 'text-slate-400' : 'text-slate-600'
              }`}>
                <Cpu className={`w-3 h-3 ${cpuUsage > 80 ? 'text-red-400' : 'text-blue-500'}`} /> Processor
              </span>
              <span className={`text-[9px] font-mono px-1 py-0.2 rounded font-bold border ${
                cpuUsage > 80 
                  ? 'bg-red-500/20 border-red-500/40 text-red-400' 
                  : isDark ? 'bg-blue-500/10 border-blue-500/30 text-blue-400' : 'bg-blue-50 border-blue-300 text-blue-800'
              }`}>
                Live
              </span>
            </div>

            <div className="my-1 flex items-baseline gap-1">
              <span className={`text-xl leading-none tracking-tight font-mono font-bold ${cpuColor}`}>
                {cpuUsage}%
              </span>
              <span className={`text-[9px] font-serif ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>utilization</span>
            </div>

            {/* Dynamic Progress Bar */}
            <div className="w-full bg-slate-800/80 rounded-full h-1.5 overflow-hidden">
              <div 
                className={`h-full transition-all duration-500 rounded-full ${
                  cpuUsage > 80 ? 'bg-red-500' : cpuUsage > 50 ? 'bg-amber-400' : 'bg-emerald-400'
                }`}
                style={{ width: `${Math.min(100, Math.max(8, cpuUsage))}%` }}
              />
            </div>
          </div>

          {/* Metric 2: Memory / RAM (Dynamic) */}
          <div className={`p-2 rounded-xl border flex flex-col justify-between transition-colors ${
            isDark ? 'bg-slate-900/60 border-slate-800' : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="flex items-center justify-between">
              <span className={`text-[10px] font-serif uppercase tracking-tight flex items-center gap-1 font-semibold ${
                isDark ? 'text-slate-400' : 'text-slate-600'
              }`}>
                <HardDrive className="w-3 h-3 text-purple-500" /> RAM Memory
              </span>
              <span className={`text-[9px] font-mono px-1 py-0.2 rounded font-bold border ${
                isDark ? 'bg-purple-500/10 border-purple-500/30 text-purple-400' : 'bg-purple-50 border-purple-300 text-purple-800'
              }`}>
                16 GB
              </span>
            </div>

            <div className="my-1 flex items-baseline gap-1">
              <span className={`text-xl font-bold font-mono leading-none tracking-tight ${
                isDark ? 'text-purple-400' : 'text-purple-800 font-extrabold'
              }`}>
                {ramUsageGb}
              </span>
              <span className={`text-[9px] font-serif ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>GB pool</span>
            </div>

            {/* Dynamic Progress Bar */}
            <div className="w-full bg-slate-800/80 rounded-full h-1.5 overflow-hidden">
              <div 
                className="h-full bg-purple-500 transition-all duration-500 rounded-full"
                style={{ width: `${Math.min(100, Math.max(15, (ramUsageGb / 16) * 100))}%` }}
              />
            </div>
          </div>

          {/* Metric 3: Network Traffic Speed (Dynamic) */}
          <div className={`p-2 rounded-xl border flex flex-col justify-between transition-colors ${
            isDark ? 'bg-slate-900/60 border-slate-800' : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="flex items-center justify-between">
              <span className={`text-[10px] font-serif uppercase tracking-tight flex items-center gap-1 font-semibold ${
                isDark ? 'text-slate-400' : 'text-slate-600'
              }`}>
                <Wifi className="w-3 h-3 text-cyan-500" /> Ingress Flow
              </span>
              <span className={`text-[9px] font-mono px-1 py-0.2 rounded font-bold border ${
                isDark ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400' : 'bg-cyan-50 border-cyan-300 text-cyan-800'
              }`}>
                {packetRate} pkt/s
              </span>
            </div>

            <div className="my-1 flex items-baseline gap-1">
              <span className={`text-xl font-bold font-mono leading-none tracking-tight ${
                isDark ? 'text-cyan-400' : 'text-cyan-800 font-extrabold'
              }`}>
                {networkMbPerSec}
              </span>
              <span className={`text-[9px] font-serif ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>MB / sec</span>
            </div>

            <div className={`text-[9px] font-serif flex items-center justify-between ${
              isDark ? 'text-slate-400' : 'text-slate-600 font-medium'
            }`}>
              <span>{edgeCount} network links</span>
              <span className={isDark ? 'text-emerald-400 font-mono text-[8.5px]' : 'text-emerald-700 font-mono text-[8.5px] font-bold'}>0% drop</span>
            </div>
          </div>

          {/* Metric 4: Display Smoothness (FPS) */}
          <div className={`p-2 rounded-xl border flex flex-col justify-between transition-colors ${
            effectiveFps < 30
              ? 'bg-red-950/40 border-red-500/60 ring-1 ring-red-500/30'
              : isDark 
              ? 'bg-slate-900/60 border-slate-800' 
              : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="flex items-center justify-between">
              <span className={`text-[10px] font-serif uppercase tracking-tight flex items-center gap-1 font-semibold ${
                isDark ? 'text-slate-400' : 'text-slate-600'
              }`}>
                <Zap className={`w-3 h-3 ${effectiveFps < 30 ? 'text-red-400' : 'text-amber-500'}`} /> Render Engine
              </span>
              <span className={`text-[9px] font-mono px-1 py-0.2 rounded font-bold border ${
                effectiveFps >= 50 
                  ? (isDark ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-emerald-50 border-emerald-300 text-emerald-800') 
                  : (isDark ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' : 'bg-amber-50 border-amber-300 text-amber-800')
              }`}>
                {effectiveFps} FPS
              </span>
            </div>

            <div className="my-1 flex items-baseline gap-1">
              <span className={`text-xl font-bold font-mono leading-none tracking-tight ${fpsColor}`}>
                {effectiveFps}
              </span>
              <span className={`text-[9px] font-serif ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>FPS ({effectiveFrameTime}ms)</span>
            </div>

            {/* Sparkline */}
            <div className="flex items-center justify-between mt-0.5">
              <span className="text-[9px] font-serif text-slate-400">60 FPS Target</span>
              <svg width={sparkWidth} height={sparkHeight} className="overflow-visible opacity-85">
                {sparklinePath && (
                  <path 
                    d={sparklinePath} 
                    fill="none" 
                    stroke={effectiveFps < 30 ? '#ef4444' : '#10b981'} 
                    strokeWidth="1.5" 
                    strokeLinecap="round" 
                  />
                )}
              </svg>
            </div>
          </div>

        </div>

        {/* Detailed Tabs & Controls when Expanded */}
        {isExpanded && (
          <div className={`pt-2 border-t space-y-2.5 animate-in fade-in duration-150 ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
            
            {/* View Selector Tabs */}
            <div className={`flex rounded-lg p-0.5 border text-[11px] font-serif font-medium ${
              isDark ? 'bg-slate-900/60 border-slate-800' : 'bg-slate-100 border-slate-300'
            }`}>
              <button
                onClick={() => setActiveTab('metrics')}
                className={`flex-1 py-1 rounded-md transition-all flex items-center justify-center gap-1 ${
                  activeTab === 'metrics'
                    ? 'bg-blue-600 text-white shadow-sm font-semibold'
                    : isDark ? 'text-slate-400 hover:text-slate-200' : 'text-slate-700 hover:text-slate-950'
                }`}
              >
                <Cpu className="w-3 h-3" />
                <span>Components</span>
              </button>
              <button
                onClick={() => setActiveTab('feed')}
                className={`flex-1 py-1 rounded-md transition-all flex items-center justify-center gap-1 relative ${
                  activeTab === 'feed'
                    ? 'bg-blue-600 text-white shadow-sm font-semibold'
                    : isDark ? 'text-slate-400 hover:text-slate-200' : 'text-slate-700 hover:text-slate-950'
                }`}
              >
                <Terminal className="w-3 h-3" />
                <span>Sensor Feed</span>
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping ml-0.5" />
              </button>
              <button
                onClick={() => setActiveTab('layers')}
                className={`flex-1 py-1 rounded-md transition-all flex items-center justify-center gap-1 ${
                  activeTab === 'layers'
                    ? 'bg-blue-600 text-white shadow-sm font-semibold'
                    : isDark ? 'text-slate-400 hover:text-slate-200' : 'text-slate-700 hover:text-slate-950'
                }`}
              >
                <Layers className="w-3 h-3" />
                <span>Layers</span>
              </button>
              <button
                onClick={() => setActiveTab('diagnostics')}
                className={`flex-1 py-1 rounded-md transition-all flex items-center justify-center gap-1 ${
                  activeTab === 'diagnostics'
                    ? 'bg-blue-600 text-white shadow-sm font-semibold'
                    : isDark ? 'text-slate-400 hover:text-slate-200' : 'text-slate-700 hover:text-slate-950'
                }`}
              >
                <BarChart3 className="w-3 h-3" />
                <span>Diagnostics</span>
              </button>
            </div>

            {/* TAB 1: Network Components Breakdown */}
            {activeTab === 'metrics' && (
              <div className="space-y-1.5">
                <div className={`text-[10px] uppercase font-serif font-semibold tracking-wider flex items-center justify-between ${
                  isDark ? 'text-slate-400' : 'text-slate-600'
                }`}>
                  <span>Network Components in Graph</span>
                  <span className={`font-mono font-bold ${isDark ? 'text-cyan-400' : 'text-blue-700'}`}>{nodeCount} items total</span>
                </div>

                <div className="grid grid-cols-2 gap-1.5 text-[10px] font-serif">
                  <div className={`px-2 py-1.5 rounded-lg border flex items-center justify-between ${
                    isDark ? 'bg-slate-900/40 border-slate-800/80 text-slate-300' : 'bg-white border-slate-200 text-slate-800'
                  }`}>
                    <span className="flex items-center gap-1.5">
                      <Server className="w-3 h-3 text-blue-600 dark:text-blue-400" /> Computer Systems
                    </span>
                    <span className="font-mono font-bold">{nodeBreakdown.software}</span>
                  </div>

                  <div className={`px-2 py-1.5 rounded-lg border flex items-center justify-between ${
                    isDark ? 'bg-slate-900/40 border-slate-800/80 text-slate-300' : 'bg-white border-slate-200 text-slate-800'
                  }`}>
                    <span className="flex items-center gap-1.5">
                      <Bug className="w-3 h-3 text-red-600 dark:text-red-400" /> Security Flaws (Bugs)
                    </span>
                    <span className="font-mono font-bold">{nodeBreakdown.vulnerability}</span>
                  </div>

                  <div className={`px-2 py-1.5 rounded-lg border flex items-center justify-between ${
                    isDark ? 'bg-slate-900/40 border-slate-800/80 text-slate-300' : 'bg-white border-slate-200 text-slate-800'
                  }`}>
                    <span className="flex items-center gap-1.5">
                      <Shield className="w-3 h-3 text-emerald-600 dark:text-emerald-400" /> Defenses & Fixes
                    </span>
                    <span className="font-mono font-bold">{nodeBreakdown.mitigation}</span>
                  </div>

                  <div className={`px-2 py-1.5 rounded-lg border flex items-center justify-between ${
                    isDark ? 'bg-slate-900/40 border-slate-800/80 text-slate-300' : 'bg-white border-slate-200 text-slate-800'
                  }`}>
                    <span className="flex items-center gap-1.5">
                      <Crosshair className="w-3 h-3 text-purple-600 dark:text-purple-400" /> Adversaries & Tools
                    </span>
                    <span className="font-mono font-bold">{nodeBreakdown.actorsAndTech}</span>
                  </div>
                </div>

                {/* Plain-Language Status Bar */}
                <div className={`px-2.5 py-1.5 rounded-xl border flex items-center justify-between text-[10px] font-serif ${
                  isStressed
                    ? 'bg-red-950/50 border-red-900/60 text-red-300'
                    : isDark 
                    ? 'bg-black/40 border-slate-800 text-slate-400' 
                    : 'bg-slate-100 border-slate-200 text-slate-700 font-medium'
                }`}>
                  <div className="flex items-center gap-1.5">
                    {isStressed ? (
                      <AlertTriangle className="w-3 h-3 text-red-400 animate-pulse" />
                    ) : (
                      <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                    )}
                    <span>{isStressed ? 'Heavy Threat Ingress: Adversary Payload Active' : 'NIST CSF Status: Nominal Telemetry Baseline'}</span>
                  </div>
                  <span className={`font-mono font-bold ${isStressed ? (isDark ? 'text-red-400' : 'text-red-700') : (isDark ? 'text-emerald-400' : 'text-emerald-700')}`}>
                    {isStressed ? 'ALERT' : 'SECURE'}
                  </span>
                </div>
              </div>
            )}

            {/* TAB 2: Dynamic Live Telemetry Stream Feed */}
            {activeTab === 'feed' && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[10px] text-slate-400">
                  <span className="font-serif font-semibold uppercase tracking-wider flex items-center gap-1">
                    <Radio className="w-3 h-3 text-emerald-400 animate-pulse" /> Live SOC Ingress Log
                  </span>
                  <span className="font-mono text-[9px] text-slate-500">Auto-streaming</span>
                </div>

                <div className={`rounded-xl border p-2 max-h-40 overflow-y-auto space-y-1.5 text-[10.5px] font-mono ${
                  isDark ? 'bg-black/70 border-slate-800' : 'bg-slate-100 border-slate-200'
                }`}>
                  {liveLogs.map((log) => (
                    <div 
                      key={log.id} 
                      className={`p-1.5 rounded-lg border leading-tight transition-all ${
                        log.type === 'alert'
                          ? 'bg-red-950/40 border-red-800/60 text-red-200'
                          : log.type === 'success'
                          ? 'bg-emerald-950/30 border-emerald-800/50 text-emerald-300'
                          : isDark
                          ? 'bg-slate-900/60 border-slate-800/80 text-slate-300'
                          : 'bg-white border-slate-200 text-slate-800'
                      }`}
                    >
                      <div className="flex items-center justify-between text-[9px] text-slate-400 mb-0.5 font-sans">
                        <span className="font-bold flex items-center gap-1">
                          {log.type === 'alert' ? '🚨 INGRESS ALERT' : '✓ SENSOR PULSE'} • {log.source}
                        </span>
                        <span className="text-[8.5px] font-mono">{log.time}</span>
                      </div>
                      <div className="text-[10px] leading-snug">{log.message}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* TAB 3: Visual Map Layer Controls */}
            {activeTab === 'layers' && (
              <div className="space-y-2">
                <div className="text-[10px] font-serif text-slate-400">
                  Toggle visual layers to highlight vulnerability corridors on the network topology:
                </div>

                <div className="flex items-center gap-2">
                  <button 
                    onClick={onToggleHotZones}
                    className={`flex-1 px-2.5 py-2 rounded-xl border text-[11px] font-serif font-medium transition-all flex items-center justify-center gap-1.5 shadow-sm ${
                      showHotZones 
                        ? 'bg-gradient-to-r from-red-600 to-rose-700 text-white border-red-500 shadow-red-600/30' 
                        : isDark ? 'bg-slate-900/90 border-slate-700 text-slate-300 hover:text-white hover:bg-slate-800' : 'bg-slate-100 border-slate-300 text-slate-700 hover:bg-slate-200'
                    }`}
                    title="Highlight servers that are exposed or under attack"
                  >
                    <Layers className="w-3.5 h-3.5" /> High-Risk Areas: {showHotZones ? 'ON' : 'OFF'}
                  </button>

                  <button 
                    onClick={onToggleHeatmap}
                    className={`flex-1 px-2.5 py-2 rounded-xl border text-[11px] font-serif font-medium transition-all flex items-center justify-center gap-1.5 shadow-sm ${
                      showHeatmap 
                        ? 'bg-gradient-to-r from-amber-600 to-orange-700 text-white border-amber-500 shadow-amber-600/30' 
                        : isDark ? 'bg-slate-900/90 border-slate-700 text-slate-300 hover:text-white hover:bg-slate-800' : 'bg-slate-100 border-slate-300 text-slate-700 hover:bg-slate-200'
                    }`}
                    title="Color-code servers by danger level"
                  >
                    <MapIcon className="w-3.5 h-3.5" /> Danger Heatmap: {showHeatmap ? 'ON' : 'OFF'}
                  </button>
                </div>
              </div>
            )}

            {/* TAB 4: SOC Diagnostics & Stress Testing */}
            {activeTab === 'diagnostics' && (
              <div className="space-y-2">
                <div className="text-[10px] font-serif text-slate-400">
                  Execute incident response benchmarks against active graph infrastructure:
                </div>

                <div className="grid grid-cols-2 gap-1.5 text-[10px] font-mono">
                  <div className={`p-2 rounded-lg border ${isDark ? 'bg-slate-900/50 border-slate-800 text-slate-300' : 'bg-slate-100 border-slate-200 text-slate-700'}`}>
                    <div className="text-slate-500 text-[9px] uppercase font-sans font-semibold">Mean Time to Fix (MTTR)</div>
                    <div className="text-emerald-400 font-bold text-xs mt-0.5">3.2 sec auto</div>
                  </div>
                  <div className={`p-2 rounded-lg border ${isDark ? 'bg-slate-900/50 border-slate-800 text-slate-300' : 'bg-slate-100 border-slate-200 text-slate-700'}`}>
                    <div className="text-slate-500 text-[9px] uppercase font-sans font-semibold">Ingress Latency</div>
                    <div className="text-cyan-400 font-bold text-xs mt-0.5">{effectiveFrameTime} ms jitter</div>
                  </div>
                </div>

                {/* Simulated Stress Test Button */}
                <button
                  onClick={() => setSimulatedStress(!simulatedStress)}
                  className={`w-full py-2 px-2.5 rounded-xl border text-[11px] font-serif font-medium transition-all flex items-center justify-center gap-1.5 ${
                    simulatedStress
                      ? 'bg-gradient-to-r from-red-600 via-rose-600 to-red-700 text-white border-red-500 shadow-md shadow-red-600/50'
                      : isDark
                      ? 'bg-slate-900/80 hover:bg-red-950/40 border-slate-700 text-slate-300 hover:text-red-300 hover:border-red-800'
                      : 'bg-slate-100 hover:bg-red-50 border-slate-300 text-slate-700 hover:text-red-700 hover:border-red-300'
                  }`}
                  title="Simulate high computation adversary workload"
                >
                  <Flame className={`w-3.5 h-3.5 ${simulatedStress ? 'animate-bounce text-yellow-300' : 'text-slate-400'}`} />
                  {simulatedStress ? 'Adversary Flood Load: ACTIVE' : 'Simulate Heavy Threat Flood Load'}
                </button>
              </div>
            )}

          </div>
        )}
      </div>
    </div>
  );
};
