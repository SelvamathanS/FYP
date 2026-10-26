import React, { useState } from 'react';
import { 
  Flame, Shield, MessageSquare, Activity, Map as MapIcon, Send, 
  Terminal, CheckCircle2, ArrowRightLeft, Maximize2, PanelLeftClose, 
  PanelRightClose, Sparkles, Loader2, RotateCcw, Bug, ChevronRight, Route,
  Code, FileCode, Edit3, ChevronDown, Check, Copy, Wrench, ArrowRight
} from 'lucide-react';
import { BarChart, Bar, XAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { GraphNode } from '../types/threatGraph';
import { PRESET_BUGS_CATALOG } from '../data/systemsAndBugsCatalog';
import { ShortestPathResult } from '../utils/shortestPath';
import { AttackPathStepsPanel } from './AttackPathStepsPanel';
import { BugTechnicalDetail } from '../data/technicalDetailsCatalog';

interface ChatMessage {
  id: string;
  role: 'user' | 'bot';
  text: string;
}

interface RoleConsolePanelProps {
  authRole: 'hacker' | 'analyst';
  isDark: boolean;
  panelDockSide?: 'left' | 'right';
  onToggleDockSide?: () => void;
  onClose: () => void;
  onEnterFullGraph: () => void;
  analystTab: 'chat' | 'logs' | 'knowledge_map' | 'attack_path';
  setAnalystTab: (tab: 'chat' | 'logs' | 'knowledge_map' | 'attack_path') => void;
  nodes: GraphNode[];
  softwareSystems: GraphNode[];
  selectedPresetBug: string;
  onSelectPresetBug: (id: string) => void;
  vulnName: string;
  setVulnName: (v: string) => void;
  targetSoftware: string;
  setTargetSoftware: (v: string) => void;
  vulnSeverity: string;
  setVulnSeverity: (v: string) => void;
  vulnDesc: string;
  setVulnDesc: (v: string) => void;
  isInjecting: boolean;
  isGeneratingAiDesc: boolean;
  onGenerateAiDesc: () => void;
  onLiveBugInstall: (e: React.FormEvent) => void;
  chatMessages: ChatMessage[];
  chatInput: string;
  setChatInput: (v: string) => void;
  isChatting: boolean;
  healedLog: string[];
  chatContainerRef: React.RefObject<HTMLDivElement | null>;
  onSendMessage: (e: React.FormEvent) => void;
  onLiveBugFix: (vulnId: string) => void;
  onSelectNode: (node: GraphNode) => void;
  pathResult?: ShortestPathResult | null;
  selectedThreatActorForPath?: string;
  onSelectThreatActorForPath?: (id: string) => void;
  selectedSoftwareForPath?: string;
  onSelectSoftwareForPath?: (id: string) => void;
  onCalculatePath?: (actorId?: string, swId?: string) => void;
  onClearPath?: () => void;
  bugCodeData?: Partial<BugTechnicalDetail>;
  onUpdateBugCodeData?: (data: Partial<BugTechnicalDetail>) => void;
  onOpenGraphRagStudio?: (systemId?: string) => void;
}

// Formats bot responses supporting markdown headers, bold, bullets, and clickable commands
const renderFormattedMessageText = (
  text: string, 
  isDark: boolean, 
  onSelectCommand?: (cmd: string) => void
) => {
  const lines = text.split('\n');
  const elements: React.ReactNode[] = [];

  const formatInline = (str: string, keyPrefix: string) => {
    const parts: React.ReactNode[] = [];
    let remaining = str;
    let idx = 0;
    const regex = /(\*\*.*?\*\*|`.*?`)/g;
    let match: RegExpExecArray | null;
    let lastIndex = 0;

    while ((match = regex.exec(str)) !== null) {
      if (match.index > lastIndex) {
        parts.push(str.substring(lastIndex, match.index));
      }
      const token = match[0];
      if (token.startsWith('**') && token.endsWith('**')) {
        parts.push(
          <strong key={`${keyPrefix}-b-${idx++}`} className={`font-bold ${isDark ? 'text-slate-100' : 'text-slate-950'}`}>
            {token.slice(2, -2)}
          </strong>
        );
      } else if (token.startsWith('`') && token.endsWith('`')) {
        const codeText = token.slice(1, -1);
        parts.push(
          <button
            key={`${keyPrefix}-c-${idx++}`}
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              if (onSelectCommand) onSelectCommand(codeText);
            }}
            title={onSelectCommand ? `Click to run "${codeText}"` : undefined}
            className={`inline-block font-mono text-[11px] px-1.5 py-0.2 mx-0.5 rounded border transition-all ${
              isDark 
                ? 'bg-blue-950/70 border-blue-800/80 text-cyan-300 hover:bg-blue-900 hover:border-cyan-400' 
                : 'bg-blue-50 border-blue-300 text-blue-900 font-semibold hover:bg-blue-100 hover:border-blue-500'
            }`}
          >
            {codeText}
          </button>
        );
      }
      lastIndex = match.index + token.length;
    }

    if (lastIndex < str.length) {
      parts.push(str.substring(lastIndex));
    }

    return parts.length > 0 ? parts : str;
  };

  lines.forEach((line, lineIdx) => {
    const trimmed = line.trim();
    if (!trimmed) {
      elements.push(<div key={`empty-${lineIdx}`} className="h-1.5" />);
      return;
    }

    if (trimmed.startsWith('### ')) {
      elements.push(
        <h4 key={`h3-${lineIdx}`} className={`font-serif font-bold text-[13px] tracking-tight mt-1.5 mb-1 flex items-center gap-1.5 ${
          isDark ? 'text-cyan-300' : 'text-blue-900'
        }`}>
          {formatInline(trimmed.replace(/^###\s+/, ''), `h-${lineIdx}`)}
        </h4>
      );
      return;
    }
    if (trimmed.startsWith('## ')) {
      elements.push(
        <h3 key={`h2-${lineIdx}`} className={`font-serif font-bold text-sm tracking-tight mt-2 mb-1 ${
          isDark ? 'text-white' : 'text-slate-900'
        }`}>
          {formatInline(trimmed.replace(/^##\s+/, ''), `h2-${lineIdx}`)}
        </h3>
      );
      return;
    }

    if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
      elements.push(
        <div key={`li-${lineIdx}`} className="flex items-start gap-1.5 my-0.5 pl-1 leading-snug">
          <span className={`text-[10px] mt-0.5 shrink-0 ${isDark ? 'text-cyan-400' : 'text-blue-600'}`}>•</span>
          <div className="flex-1 min-w-0">
            {formatInline(trimmed.replace(/^[-*]\s+/, ''), `li-${lineIdx}`)}
          </div>
        </div>
      );
      return;
    }

    const numMatch = trimmed.match(/^(\d+)\.\s+(.*)$/);
    if (numMatch) {
      elements.push(
        <div key={`num-${lineIdx}`} className="flex items-start gap-1.5 my-0.5 pl-1 leading-snug">
          <span className={`font-mono text-[10px] font-bold shrink-0 ${isDark ? 'text-cyan-400' : 'text-blue-600'}`}>
            {numMatch[1]}.
          </span>
          <div className="flex-1 min-w-0">
            {formatInline(numMatch[2], `num-${lineIdx}`)}
          </div>
        </div>
      );
      return;
    }

    elements.push(
      <p key={`p-${lineIdx}`} className="my-0.5 leading-relaxed">
        {formatInline(trimmed, `p-${lineIdx}`)}
      </p>
    );
  });

  return elements;
};

export const RoleConsolePanel: React.FC<RoleConsolePanelProps> = ({
  authRole,
  isDark,
  panelDockSide,
  onToggleDockSide,
  onClose,
  onEnterFullGraph,
  analystTab,
  setAnalystTab,
  nodes,
  softwareSystems,
  selectedPresetBug,
  onSelectPresetBug,
  vulnName,
  setVulnName,
  targetSoftware,
  setTargetSoftware,
  vulnSeverity,
  setVulnSeverity,
  vulnDesc,
  setVulnDesc,
  isInjecting,
  isGeneratingAiDesc,
  onGenerateAiDesc,
  onLiveBugInstall,
  bugCodeData,
  onUpdateBugCodeData,
  chatMessages,
  chatInput,
  setChatInput,
  isChatting,
  healedLog,
  chatContainerRef,
  onSendMessage,
  onLiveBugFix,
  onSelectNode,
  pathResult,
  selectedThreatActorForPath = 'APT29',
  onSelectThreatActorForPath,
  selectedSoftwareForPath = 'Apache Web Server',
  onSelectSoftwareForPath,
  onCalculatePath,
  onClearPath,
  onOpenGraphRagStudio
}) => {
  const [isCodeSectionOpen, setIsCodeSectionOpen] = useState(true);
  const [isGeneratingAiCode, setIsGeneratingAiCode] = useState(false);

  const handleAiGenerateCodeForForm = async () => {
    setIsGeneratingAiCode(true);
    try {
      const res = await fetch('/api/bug/generate-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          bug_id: vulnName,
          bug_name: vulnName,
          target_software: targetSoftware,
          language: bugCodeData?.codeLanguage || 'python'
        })
      });
      const data = await res.json();
      if (data.status === 'success' && data.code && onUpdateBugCodeData) {
        onUpdateBugCodeData({
          ...bugCodeData,
          codeLanguage: data.code.codeLanguage || bugCodeData?.codeLanguage || 'python',
          codeFileName: data.code.codeFileName || bugCodeData?.codeFileName || 'exploit.py',
          buggyCode: data.code.buggyCode,
          correctedCode: '',
          errorMessage: data.code.errorMessage,
          exploitScript: data.code.exploitScript,
          rootCause: data.code.rootCause,
          fixExplanation: ''
        });
      }
    } catch (err) {
      console.warn('AI code synthesis error:', err);
    } finally {
      setIsGeneratingAiCode(false);
    }
  };

  const handleLoadTemplateForForm = (type: 'sqli' | 'rce' | 'buffer' | 'traversal') => {
    if (!onUpdateBugCodeData) return;
    if (type === 'sqli') {
      onUpdateBugCodeData({
        ...bugCodeData,
        codeLanguage: 'sql',
        codeFileName: 'auth_handler.sql',
        buggyCode: `-- Vulnerable Raw SQL Query\nSELECT * FROM users WHERE user = '\${userInput}' AND role = 'ADMIN';`,
        exploitScript: `curl -X POST "http://${targetSoftware}/login" -d "user=admin' OR '1'='1' --"`,
        correctedCode: '',
        errorMessage: `SQLSyntaxErrorException: Unclosed quotation mark after character string 'admin' OR '1'='1' --'`
      });
    } else if (type === 'rce') {
      onUpdateBugCodeData({
        ...bugCodeData,
        codeLanguage: 'python',
        codeFileName: 'diagnostics_agent.py',
        buggyCode: `# Vulnerable Command Injection\nimport os\ndef run_diag(host):\n    os.system(f"traceroute {host}") # FLAW: Shell metacharacters`,
        exploitScript: `curl "http://${targetSoftware}/diag?host=127.0.0.1;id;whoami"`,
        correctedCode: '',
        errorMessage: `traceroute: 127.0.0.1\nuid=0(root) gid=0(root) groups=0(root)\nRemote reverse shell spawned!`
      });
    } else if (type === 'buffer') {
      onUpdateBugCodeData({
        ...bugCodeData,
        codeLanguage: 'c',
        codeFileName: 'packet_ingress.c',
        buggyCode: `// Vulnerable Buffer Copy\nvoid handle_stream(char *net_stream, int len) {\n    char stack_buf[256];\n    strcpy(stack_buf, net_stream); // FLAW: Unchecked copy\n}`,
        exploitScript: `python3 -c "import socket; s=socket.socket(); s.connect(('10.0.1.5', 8080)); s.send(b'A'*512)"`,
        correctedCode: '',
        errorMessage: `*** stack smashing detected ***: terminated\nInstruction pointer overwritten at 0x4141414141414141`
      });
    } else {
      onUpdateBugCodeData({
        ...bugCodeData,
        codeLanguage: 'go',
        codeFileName: 'file_dispatcher.go',
        buggyCode: `// Vulnerable Path Traversal\nfunc serve(w http.ResponseWriter, r *http.Request) {\n    doc := r.URL.Query().Get("doc")\n    data, _ := os.ReadFile("/var/www/data/" + doc)\n    w.Write(data)\n}`,
        exploitScript: `curl "http://${targetSoftware}/file?doc=../../../../etc/passwd"`,
        correctedCode: '',
        errorMessage: `root:x:0:0:root:/root:/bin/bash\nUnauthorized file read disclosure confirmed!`
      });
    }
  };

  return (
    <div className={`w-96 min-w-[384px] max-w-[384px] shrink-0 border-r border-l flex flex-col h-full overflow-hidden relative transition-all duration-300 shadow-xl ${
      isDark 
        ? 'bg-[#080d19] bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900/60 via-[#080d19] to-[#040810] border-slate-800/80' 
        : 'bg-white border-slate-200 shadow-sm'
    }`}>

      {/* RED TEAM: ADVERSARY EMULATION & EXPLOIT INJECTION */}
      {authRole === 'hacker' && (
        <div className="flex-1 flex flex-col overflow-y-auto overflow-x-hidden min-w-0">
          {/* Header */}
          <div className={`px-4 py-3 border-b flex items-center justify-between shrink-0 ${
            isDark 
              ? 'bg-gradient-to-r from-red-950/40 via-slate-900/60 to-red-950/40 border-red-900/40 text-red-300' 
              : 'bg-red-50/80 border-red-200 text-red-900'
          }`}>
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-lg bg-red-600/20 border border-red-500/40 flex items-center justify-center text-red-400 shrink-0">
                <Flame className="w-4 h-4 text-red-500" />
              </div>
              <div>
                <h2 className="font-serif font-bold text-xs tracking-tight text-red-400 dark:text-red-300">
                  Attack Simulation (Red Team)
                </h2>
                <p className="text-[10px] text-red-500/80 dark:text-red-400/70 font-normal">
                  Simulate cyber attacks to test server defenses
                </p>
              </div>
            </div>

            {/* Dynamic Controls: Left Docked & Full Graph */}
            <div className="flex items-center gap-1">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono border bg-red-500/10 border-red-500/30 text-red-400 font-semibold hidden sm:inline">
                Left Dock
              </span>
              <button
                type="button"
                onClick={onEnterFullGraph}
                className={`p-1.5 rounded-lg border text-xs transition-colors ${
                  isDark ? 'bg-slate-900/80 border-slate-800 text-slate-400 hover:text-white hover:bg-slate-800' : 'bg-white border-slate-200 text-slate-600 hover:bg-slate-100'
                }`}
                title="Full graph view (collapse sidebars)"
              >
                <Maximize2 className="w-3.5 h-3.5" />
              </button>
              <button
                type="button"
                onClick={onClose}
                className={`px-2 py-1 rounded-lg border text-xs font-serif font-medium flex items-center gap-1 transition-colors ${
                  isDark ? 'bg-slate-900/80 border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800' : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-100'
                }`}
                title="Collapse console to left side (leaves full space for graph)"
              >
                <PanelLeftClose className="w-3.5 h-3.5 text-red-400" />
                <span className="text-[11px] hidden sm:inline">Send to Side</span>
              </button>
            </div>
          </div>

          {/* Quick Attack Vector Tracer Banner */}
          <div className={`px-4 py-2 border-b flex items-center justify-between text-xs shrink-0 ${
            isDark ? 'bg-red-950/20 border-red-900/30' : 'bg-red-50/50 border-red-100'
          }`}>
            <span className="text-[11px] text-slate-400 font-serif flex items-center gap-1.5">
              <Route className="w-3.5 h-3.5 text-amber-500" />
              <span>Target Vector: <b className="text-slate-200">{targetSoftware}</b></span>
            </span>
            <button
              type="button"
              onClick={() => {
                if (onCalculatePath) {
                  onCalculatePath(selectedThreatActorForPath || 'APT29', targetSoftware);
                }
                setAnalystTab('attack_path');
              }}
              className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 hover:bg-amber-500/30 border border-amber-500/40 transition-colors"
            >
              Trace Shortest Path ➔
            </button>
          </div>

          {/* GraphRAG AI Vulnerability Studio Action Banner */}
          {onOpenGraphRagStudio && (
            <div className={`p-3 border-b flex items-center justify-between gap-2 shrink-0 ${
              isDark 
                ? 'bg-gradient-to-r from-cyan-950/40 via-blue-950/30 to-slate-900/60 border-cyan-800/40' 
                : 'bg-cyan-50/80 border-cyan-200'
            }`}>
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400 shrink-0" />
                <div className="text-left">
                  <span className="font-sans font-bold text-xs text-cyan-300 block">GraphRAG AI Studio</span>
                  <span className="text-[10px] text-slate-400">Autonomous 15-step reasoning & fix</span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => onOpenGraphRagStudio(targetSoftware)}
                className="px-2.5 py-1 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-sans font-bold text-[11px] shadow-sm flex items-center gap-1 transition-all shrink-0"
              >
                <span>Launch</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          )}

          <form onSubmit={onLiveBugInstall} className="p-4 space-y-4 flex-1">
            {/* CVE Catalog Selector */}
            <div>
              <label className={`block text-[10px] font-serif font-semibold uppercase tracking-wider mb-1 ${
                isDark ? 'text-slate-400' : 'text-slate-600'
              }`}>
                Choose Security Flaw (Bug / CVE)
              </label>
              <select
                value={selectedPresetBug}
                onChange={e => onSelectPresetBug(e.target.value)}
                className={`w-full p-2 rounded-lg border text-xs font-medium transition-colors ${
                  isDark ? 'bg-slate-900 border-slate-800 text-red-300 focus:border-red-500' : 'bg-white border-slate-300 text-slate-800 focus:border-red-500'
                }`}
              >
                {PRESET_BUGS_CATALOG.map(b => (
                  <option key={b.id} value={b.id}>
                    {b.id} · {b.name} ({b.severity})
                  </option>
                ))}
              </select>
            </div>

            {/* Vulnerability ID */}
            <div>
              <label className={`block text-[10px] font-serif font-semibold uppercase tracking-wider mb-1 ${
                isDark ? 'text-slate-400' : 'text-slate-600'
              }`}>
                Security Flaw Name / Identifier
              </label>
              <input 
                type="text" 
                value={vulnName}
                onChange={e => setVulnName(e.target.value)}
                placeholder="e.g. CVE-2024-XXXX"
                className={`w-full p-2 rounded-lg border text-xs font-mono font-medium transition-colors ${
                  isDark ? 'bg-slate-900 border-slate-800 text-red-300 focus:border-red-500' : 'bg-white border-slate-300 text-slate-800 focus:border-red-500'
                }`}
                required
              />
            </div>

            {/* Target System */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className={`text-[10px] font-serif font-semibold uppercase tracking-wider ${
                  isDark ? 'text-slate-400' : 'text-slate-600'
                }`}>
                  Target Computer System ({softwareSystems.length} Computers Available)
                </label>
                <span className={`text-[10px] font-mono font-semibold ${isDark ? 'text-cyan-400' : 'text-blue-600'}`}>
                  Live Network
                </span>
              </div>
              <select 
                value={targetSoftware}
                onChange={e => setTargetSoftware(e.target.value)}
                className={`w-full p-2 rounded-lg border text-xs font-medium transition-colors ${
                  isDark ? 'bg-slate-900 border-slate-800 text-slate-200' : 'bg-white border-slate-300 text-slate-800'
                }`}
              >
                {softwareSystems.map(n => (
                  <option key={n.id} value={n.id}>
                    {n.name} · {n.application || 'App'} ({n.technology || 'Service'}) · {n.status === 'COMPROMISED' ? 'COMPROMISED' : 'HEALTHY'}
                  </option>
                ))}
              </select>
            </div>

            {/* Severity Level */}
            <div>
              <label className={`block text-[10px] font-serif font-semibold uppercase tracking-wider mb-1 ${
                isDark ? 'text-slate-400' : 'text-slate-600'
              }`}>
                Danger Level (Severity)
              </label>
              <div className="grid grid-cols-3 gap-2">
                {['CRITICAL', 'HIGH', 'MEDIUM'].map(sev => (
                  <button
                    type="button"
                    key={sev}
                    onClick={() => setVulnSeverity(sev)}
                    className={`py-1.5 rounded-lg border font-serif text-xs font-semibold transition-all ${
                      vulnSeverity === sev
                        ? 'bg-gradient-to-r from-red-600 to-rose-600 text-white border-red-500 shadow-md'
                        : isDark ? 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white' : 'bg-slate-100 border-slate-300 text-slate-600 hover:bg-slate-200'
                    }`}
                  >
                    {sev === 'CRITICAL' ? 'Critical' : sev === 'HIGH' ? 'High Risk' : 'Medium'}
                  </button>
                ))}
              </div>
            </div>

            {/* Description & AI Generator */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className={`text-[10px] font-serif font-semibold uppercase tracking-wider ${
                  isDark ? 'text-slate-400' : 'text-slate-600'
                }`}>
                  Flaw Explanation (How Attack Works)
                </label>
                <button
                  type="button"
                  onClick={onGenerateAiDesc}
                  disabled={isGeneratingAiDesc || !vulnName}
                  className={`text-[10px] font-serif px-2 py-0.5 rounded-md border flex items-center gap-1 transition-all ${
                    isGeneratingAiDesc
                      ? 'bg-purple-950/40 border-purple-800/60 text-purple-300'
                      : isDark
                      ? 'bg-gradient-to-r from-indigo-950/80 to-purple-950/80 border-indigo-700/60 text-indigo-300 hover:text-white hover:border-indigo-500 shadow-sm'
                      : 'bg-indigo-50 border-indigo-200 text-indigo-700 hover:bg-indigo-100'
                  }`}
                  title="Generate a plain-English explanation of this security flaw with Gemini AI"
                >
                  {isGeneratingAiDesc ? (
                    <>
                      <Loader2 className="w-3 h-3 animate-spin text-purple-400" />
                      <span>Writing...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-3 h-3 text-indigo-400" />
                      <span>AI Explain Flaw</span>
                    </>
                  )}
                </button>
              </div>
              <textarea 
                value={vulnDesc}
                onChange={e => setVulnDesc(e.target.value)}
                placeholder="Explain the security weakness and how an attacker could exploit this server..."
                rows={3}
                className={`w-full p-2.5 rounded-lg border text-xs leading-relaxed transition-colors ${
                  isDark ? 'bg-slate-900 border-slate-800 text-slate-200 focus:border-red-500' : 'bg-slate-50 border-slate-300 text-slate-800'
                }`}
                required
              />
            </div>

            {/* EXPANDABLE SECTION: VULNERABILITY CODE & EXPLOIT SCRIPT */}
            <div className={`rounded-xl border overflow-hidden transition-all ${
              isDark ? 'bg-black/40 border-slate-800/80' : 'bg-slate-50/80 border-slate-200'
            }`}>
              <button
                type="button"
                onClick={() => setIsCodeSectionOpen(!isCodeSectionOpen)}
                className={`w-full px-3 py-2 flex items-center justify-between text-left transition-colors ${
                  isDark ? 'hover:bg-slate-900/60' : 'hover:bg-slate-100'
                }`}
              >
                <div className="flex items-center gap-2">
                  <div className="p-1 rounded bg-amber-500/20 text-amber-400">
                    <Code className="w-3.5 h-3.5" />
                  </div>
                  <div>
                    <span className="font-serif font-bold text-xs text-amber-400 block">
                      Vulnerability Code & Exploit Payload
                    </span>
                    <span className="text-[10px] text-slate-400 block">
                      {isCodeSectionOpen ? 'Hide code details' : 'Attach / customize buggy code & security patch'}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                    {bugCodeData?.codeLanguage || 'python'}
                  </span>
                  <ChevronDown className={`w-3.5 h-3.5 text-slate-400 transition-transform ${isCodeSectionOpen ? 'rotate-180' : ''}`} />
                </div>
              </button>

              {isCodeSectionOpen && (
                <div className="p-3 border-t border-slate-800/80 space-y-3 animate-in fade-in duration-150">
                  {/* Quick AI & Template Actions */}
                  <div className="flex items-center justify-between flex-wrap gap-1.5">
                    <button
                      type="button"
                      onClick={handleAiGenerateCodeForForm}
                      disabled={isGeneratingAiCode}
                      className="px-2 py-0.5 rounded-md text-[10px] font-medium bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white flex items-center gap-1 transition-all disabled:opacity-50 shadow-xs"
                    >
                      {isGeneratingAiCode ? <Loader2 className="w-2.5 h-2.5 animate-spin" /> : <Sparkles className="w-2.5 h-2.5" />}
                      <span>{isGeneratingAiCode ? 'Synthesizing...' : 'AI Generate Code'}</span>
                    </button>

                    <div className="flex items-center gap-1 flex-wrap text-[9px] font-mono">
                      <span className="text-slate-500">Presets:</span>
                      <button
                        type="button"
                        onClick={() => handleLoadTemplateForForm('sqli')}
                        className="px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700"
                      >
                        SQLi
                      </button>
                      <button
                        type="button"
                        onClick={() => handleLoadTemplateForForm('rce')}
                        className="px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-red-300 border border-slate-700"
                      >
                        RCE
                      </button>
                      <button
                        type="button"
                        onClick={() => handleLoadTemplateForForm('buffer')}
                        className="px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-amber-300 border border-slate-700"
                      >
                        Overflow
                      </button>
                      <button
                        type="button"
                        onClick={() => handleLoadTemplateForForm('traversal')}
                        className="px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-emerald-300 border border-slate-700"
                      >
                        Traversal
                      </button>
                    </div>
                  </div>

                  {/* Language and File Name */}
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="block text-[9px] font-mono uppercase text-slate-400 font-bold mb-0.5">
                        Language
                      </label>
                      <select
                        value={bugCodeData?.codeLanguage || 'python'}
                        onChange={e => onUpdateBugCodeData && onUpdateBugCodeData({ ...bugCodeData, codeLanguage: e.target.value })}
                        className={`w-full p-1.5 rounded-lg border text-[11px] font-mono ${
                          isDark ? 'bg-slate-900 border-slate-800 text-slate-200' : 'bg-white border-slate-300 text-slate-800'
                        }`}
                      >
                        <option value="python">Python</option>
                        <option value="c">C / C++</option>
                        <option value="java">Java</option>
                        <option value="typescript">TypeScript</option>
                        <option value="go">Go</option>
                        <option value="rust">Rust</option>
                        <option value="sql">SQL</option>
                        <option value="bash">Bash</option>
                        <option value="apache">Apache/Nginx</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-[9px] font-mono uppercase text-slate-400 font-bold mb-0.5">
                        Source File Name
                      </label>
                      <input
                        type="text"
                        value={bugCodeData?.codeFileName || 'vulnerability.py'}
                        onChange={e => onUpdateBugCodeData && onUpdateBugCodeData({ ...bugCodeData, codeFileName: e.target.value })}
                        placeholder="e.g. auth_service.py"
                        className={`w-full p-1.5 rounded-lg border text-[11px] font-mono ${
                          isDark ? 'bg-slate-900 border-slate-800 text-slate-200' : 'bg-white border-slate-300 text-slate-800'
                        }`}
                      />
                    </div>
                  </div>

                  {/* Buggy Code Editor */}
                  <div>
                    <label className={`block text-[9px] font-mono uppercase font-bold mb-0.5 ${
                      isDark ? 'text-red-400' : 'text-red-800'
                    }`}>
                      Vulnerable / Buggy Code
                    </label>
                    <textarea
                      value={bugCodeData?.buggyCode || ''}
                      onChange={e => onUpdateBugCodeData && onUpdateBugCodeData({ ...bugCodeData, buggyCode: e.target.value })}
                      rows={4}
                      placeholder="// Paste vulnerable implementation here..."
                      className={`w-full p-2 rounded-lg font-mono text-[10.5px] leading-relaxed border transition-colors ${
                        isDark 
                          ? 'bg-[#0c0505] border-red-900/60 text-red-200 focus:outline-none focus:border-red-500' 
                          : 'bg-white border-red-300 text-red-950 font-medium focus:outline-none focus:border-red-600 focus:ring-1 focus:ring-red-400'
                      }`}
                    />
                  </div>

                  {/* Exploit Script */}
                  <div>
                    <label className={`block text-[9px] font-mono uppercase font-bold mb-0.5 ${
                      isDark ? 'text-purple-400' : 'text-purple-800'
                    }`}>
                      Exploit Script / Attack Payload
                    </label>
                    <textarea
                      value={bugCodeData?.exploitScript || ''}
                      onChange={e => onUpdateBugCodeData && onUpdateBugCodeData({ ...bugCodeData, exploitScript: e.target.value })}
                      rows={2}
                      placeholder="curl -X POST http://target/exploit"
                      className={`w-full p-2 rounded-lg font-mono text-[10.5px] leading-relaxed border transition-colors ${
                        isDark 
                          ? 'bg-[#0a0510] border-purple-900/60 text-purple-200 focus:outline-none focus:border-purple-500' 
                          : 'bg-white border-purple-300 text-purple-950 font-medium focus:outline-none focus:border-purple-600 focus:ring-1 focus:ring-purple-400'
                      }`}
                    />
                  </div>

                  {/* Defensive Fix Withheld Notice */}
                  <div className={`p-2.5 rounded-lg border text-[10.5px] flex items-start gap-2 ${
                    isDark 
                      ? 'bg-emerald-950/20 border-emerald-900/40 text-emerald-300' 
                      : 'bg-emerald-50 border-emerald-200 text-emerald-900'
                  }`}>
                    <Shield className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold block">Defensive Fix Withheld from Attack Surface</span>
                      <span className="text-slate-400 block text-[10px] leading-relaxed mt-0.5">
                        Attackers only simulate vulnerable code & exploit payloads. The Graph AI will autonomously reason over the knowledge graph, analyze root causes, and synthesize the secure fix code at the end upon remediation.
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <button
              type="submit"
              disabled={isInjecting}
              className="w-full py-2.5 rounded-xl font-serif text-xs font-semibold bg-gradient-to-r from-red-600 via-rose-600 to-red-700 hover:from-red-500 hover:to-rose-600 text-white shadow-lg shadow-red-900/30 flex items-center justify-center gap-2 transition-all active:scale-[0.99] disabled:opacity-50"
            >
              <Flame className="w-4 h-4" />
              <span>{isInjecting ? 'Simulating Attack on Server...' : 'Simulate Attack on Selected Server'}</span>
            </button>
          </form>
        </div>
      )}

      {/* BLUE TEAM: SOC THREAT DEFENSE & GRAPH COPILOT */}
      {authRole === 'analyst' && (
        <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
          {/* Header with Send to Side, Dock Side, and Full Graph controls */}
          <div className={`px-4 py-3 border-b flex items-center justify-between shrink-0 ${
            isDark 
              ? 'bg-gradient-to-r from-slate-900/90 via-[#0b1426]/90 to-slate-900/90 border-slate-800 text-slate-200' 
              : 'bg-slate-50 border-slate-200 text-slate-800'
          }`}>
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400 shrink-0">
                <Shield className="w-4 h-4" />
              </div>
              <div>
                <h2 className="font-serif font-bold text-xs tracking-tight text-slate-900 dark:text-white">
                  Security Defense & AI Copilot
                </h2>
                <p className={`text-[10px] font-normal ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                  Fix security flaws, investigate threats & monitor network
                </p>
              </div>
            </div>

            {/* Dynamic Controls: Left Docked & Full Graph */}
            <div className="flex items-center gap-1">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono border bg-blue-500/10 border-blue-500/30 text-blue-400 font-semibold hidden sm:inline">
                Left Dock
              </span>
              <button
                type="button"
                onClick={onEnterFullGraph}
                className={`p-1.5 rounded-lg border text-xs transition-colors ${
                  isDark ? 'bg-slate-900/80 border-slate-800 text-slate-400 hover:text-white hover:bg-slate-800' : 'bg-white border-slate-200 text-slate-600 hover:bg-slate-100'
                }`}
                title="Full graph view (collapse all sidebars)"
              >
                <Maximize2 className="w-3.5 h-3.5" />
              </button>
              <button
                type="button"
                onClick={onClose}
                className={`px-2 py-1 rounded-lg border text-xs font-serif font-medium flex items-center gap-1 transition-colors ${
                  isDark ? 'bg-slate-900/80 border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800' : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-100'
                }`}
                title="Collapse console to left side (leaves full space for graph)"
              >
                <PanelLeftClose className="w-3.5 h-3.5 text-cyan-400" />
                <span className="text-[11px] hidden sm:inline">Send to Side</span>
              </button>
            </div>
          </div>

          {/* Sub-Tab Navigation */}
          <div className={`p-2 border-b flex justify-between items-center shrink-0 ${
            isDark ? 'bg-slate-950/60 border-slate-800/80' : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="flex space-x-1 p-0.5 rounded-lg bg-slate-200/60 dark:bg-slate-900/80 border border-slate-300/40 dark:border-slate-800 w-full">
              <button 
                onClick={() => setAnalystTab('chat')} 
                className={`flex-1 py-1 px-1 rounded-md font-serif font-medium text-[11px] flex items-center justify-center gap-1 transition-all ${
                  analystTab === 'chat' 
                    ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-sm' 
                    : isDark ? 'text-slate-400 hover:text-white' : 'text-slate-600 hover:text-slate-900'
                }`}
                title="AI Threat Intelligence Assistant"
              >
                <MessageSquare className="w-3 h-3" />
                <span className="truncate">AI Bot</span>
              </button>
              <button 
                onClick={() => setAnalystTab('logs')} 
                className={`flex-1 py-1 px-1 rounded-md font-serif font-medium text-[11px] flex items-center justify-center gap-1 transition-all ${
                  analystTab === 'logs' 
                    ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-sm' 
                    : isDark ? 'text-slate-400 hover:text-white' : 'text-slate-600 hover:text-slate-900'
                }`}
                title="Active Vulnerabilities & Flaws"
              >
                <Activity className="w-3 h-3" />
                <span className="truncate">Flaws ({nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED').length})</span>
              </button>
              <button 
                onClick={() => {
                  setAnalystTab('attack_path');
                  if (!pathResult?.found && onCalculatePath) {
                    onCalculatePath();
                  }
                }} 
                className={`flex-1 py-1 px-1 rounded-md font-serif font-medium text-[11px] flex items-center justify-center gap-1 transition-all ${
                  analystTab === 'attack_path' 
                    ? 'bg-gradient-to-r from-amber-600 via-orange-600 to-red-600 text-white shadow-sm' 
                    : isDark ? 'text-slate-400 hover:text-white' : 'text-slate-600 hover:text-slate-900'
                }`}
                title="Highlight Shortest Attack Vector on Graph"
              >
                <Route className="w-3 h-3 text-amber-300" />
                <span className="truncate">Path {pathResult?.found ? `(${pathResult.totalHops}h)` : ''}</span>
              </button>
              <button 
                onClick={() => setAnalystTab('knowledge_map')} 
                className={`flex-1 py-1 px-1 rounded-md font-serif font-medium text-[11px] flex items-center justify-center gap-1 transition-all ${
                  analystTab === 'knowledge_map' 
                    ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-sm' 
                    : isDark ? 'text-slate-400 hover:text-white' : 'text-slate-600 hover:text-slate-900'
                }`}
                title="System Components & Entities"
              >
                <MapIcon className="w-3 h-3" />
                <span className="truncate">Items</span>
              </button>
            </div>
          </div>

          {/* Vulnerability Severity Distribution Bar */}
          {analystTab === 'chat' && (
            <div className={`h-28 border-b p-2.5 flex flex-col ${
              isDark ? 'bg-black/30 border-slate-800/80' : 'bg-slate-50/50 border-slate-200'
            }`}>
              <div className={`flex items-center justify-between mb-1 text-[10px] font-serif font-semibold uppercase tracking-wider ${
                isDark ? 'text-slate-400' : 'text-slate-600'
              }`}>
                <span>Active Security Flaws by Danger Level</span>
                <span className={`font-mono font-bold ${isDark ? 'text-cyan-400' : 'text-blue-600'}`}>
                  Exposed: {nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED').length}
                </span>
              </div>
              <div className="flex-1">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={[
                    { name: 'CRIT', count: nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED' && n.severity === 'CRITICAL').length, color: '#ef4444' },
                    { name: 'HIGH', count: nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED' && n.severity === 'HIGH').length, color: '#f97316' },
                    { name: 'MED', count: nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED' && n.severity === 'MEDIUM').length, color: '#eab308' },
                    { name: 'LOW', count: nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED' && n.severity === 'LOW').length, color: '#3b82f6' }
                  ]}>
                    <XAxis dataKey="name" stroke="#64748b" fontSize={9} tickLine={false} axisLine={false} />
                    <Tooltip 
                      cursor={{fill: isDark ? '#172554' : '#e2e8f0'}} 
                      contentStyle={{ 
                        backgroundColor: isDark ? '#090e1a' : '#ffffff', 
                        border: `1px solid ${isDark ? '#1e3a8a' : '#cbd5e1'}`, 
                        fontSize: '11px', 
                        fontFamily: "'Plus Jakarta Sans', sans-serif",
                        color: isDark ? '#93c5fd' : '#1e293b' 
                      }} 
                    />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                      {[
                        { color: '#ef4444' },
                        { color: '#f97316' },
                        { color: '#eab308' },
                        { color: '#3b82f6' }
                      ].map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* TAB 1: AI Chatbot Analyst */}
          {analystTab === 'chat' && (
            <>
              <div ref={chatContainerRef} className="flex-1 overflow-y-auto overflow-x-hidden p-4 space-y-3.5 text-xs min-w-0">
                {chatMessages.map(msg => (
                  <div key={msg.id} className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'} min-w-0`}>
                    <div className={`max-w-[92%] p-3.5 rounded-xl leading-relaxed break-words min-w-0 shadow-xs ${
                      msg.role === 'user' 
                        ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white rounded-tr-xs shadow-sm font-sans text-xs' 
                        : isDark 
                          ? 'bg-slate-900/95 border border-slate-800 text-slate-100 rounded-tl-xs font-serif text-[12.5px]' 
                          : 'bg-white border border-slate-200 text-slate-900 rounded-tl-xs font-serif text-[12.5px] shadow-sm'
                    }`}>
                      {msg.role === 'user' ? (
                        <div className="whitespace-pre-wrap">{msg.text}</div>
                      ) : (
                        <div className="space-y-1">
                          {renderFormattedMessageText(msg.text, isDark, (cmd) => {
                            setChatInput(cmd);
                            setTimeout(() => {
                              const btn = document.getElementById('chat-send-btn');
                              if (btn) btn.click();
                            }, 50);
                          })}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
                {isChatting && (
                  <div className={`border rounded-xl rounded-tl-xs p-3 max-w-[85%] flex space-x-1.5 ${
                    isDark ? 'bg-slate-900/90 border-slate-800' : 'bg-slate-100 border-slate-200'
                  }`}>
                    <div className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce"></div>
                    <div className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce delay-75"></div>
                    <div className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce delay-150"></div>
                  </div>
                )}
                {/* Reasoning Trace Logs */}
                {healedLog.length > 0 && (
                  <div className={`border rounded-xl p-3.5 text-xs space-y-1.5 ${
                    isDark ? 'border-emerald-800/40 bg-emerald-950/20 text-emerald-200' : 'border-emerald-300 bg-emerald-50 text-emerald-900'
                  }`}>
                    <div className="font-serif font-bold mb-1.5 flex items-center tracking-normal text-xs text-emerald-400">
                      <Terminal className="w-3.5 h-3.5 mr-1 text-emerald-400" /> Investigation & Reasoning Trace
                    </div>
                    {healedLog.map((log, i) => (
                      <div key={i} className="leading-snug font-serif text-[11px] opacity-90">{log}</div>
                    ))}
                  </div>
                )}
              </div>

              {/* Fast Copilot Prompts & Input Box */}
              <div className={`p-3 border-t shrink-0 ${isDark ? 'bg-[#090e1a] border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                <div className="flex items-center gap-1.5 overflow-x-auto pb-2 mb-1 scrollbar-none">
                  <button
                    type="button"
                    onClick={() => {
                      setChatInput('hi');
                      setTimeout(() => {
                        const btn = document.getElementById('chat-send-btn');
                        if (btn) btn.click();
                      }, 50);
                    }}
                    className={`text-[10px] font-serif px-2.5 py-1 rounded-lg border font-semibold whitespace-nowrap transition-colors flex items-center gap-1 shrink-0 ${
                      isDark 
                        ? 'bg-slate-900 border-cyan-800/60 text-cyan-300 hover:border-cyan-400 hover:bg-slate-800' 
                        : 'bg-white border-blue-300 text-blue-800 hover:border-blue-500 hover:bg-slate-50'
                    }`}
                  >
                    <span>👋</span>
                    <span>Hi Copilot</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setChatInput('status');
                      setTimeout(() => {
                        const btn = document.getElementById('chat-send-btn');
                        if (btn) btn.click();
                      }, 50);
                    }}
                    className={`text-[10px] font-serif px-2.5 py-1 rounded-lg border font-medium whitespace-nowrap transition-colors flex items-center gap-1 shrink-0 ${
                      isDark 
                        ? 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700 hover:bg-slate-800' 
                        : 'bg-white border-slate-200 text-slate-700 hover:border-slate-300 hover:bg-slate-50'
                    }`}
                  >
                    <span>📊</span>
                    <span>System Health</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setChatInput('fix all bugs');
                      setTimeout(() => {
                        const btn = document.getElementById('chat-send-btn');
                        if (btn) btn.click();
                      }, 50);
                    }}
                    className={`text-[10px] font-serif px-2.5 py-1 rounded-lg border font-medium whitespace-nowrap transition-colors flex items-center gap-1 shrink-0 ${
                      isDark 
                        ? 'bg-slate-900 border-slate-800 text-cyan-400 hover:border-cyan-500/50 hover:bg-slate-800' 
                        : 'bg-white border-slate-200 text-blue-600 hover:border-blue-300 hover:bg-slate-50'
                    }`}
                  >
                    <Shield className="w-3 h-3 text-cyan-400" />
                    Remediate All Active Threats
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setChatInput('fix Log4Shell');
                      setTimeout(() => {
                        const btn = document.getElementById('chat-send-btn');
                        if (btn) btn.click();
                      }, 50);
                    }}
                    className={`text-[10px] font-serif px-2.5 py-1 rounded-lg border font-medium whitespace-nowrap transition-colors flex items-center gap-1 shrink-0 ${
                      isDark 
                        ? 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700 hover:bg-slate-800' 
                        : 'bg-white border-slate-200 text-slate-700 hover:border-slate-300 hover:bg-slate-50'
                    }`}
                  >
                    Remediate Log4Shell
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setChatInput('what should I fix first?');
                      setTimeout(() => {
                        const btn = document.getElementById('chat-send-btn');
                        if (btn) btn.click();
                      }, 50);
                    }}
                    className={`text-[10px] font-serif px-2.5 py-1 rounded-lg border font-medium whitespace-nowrap transition-colors flex items-center gap-1 shrink-0 ${
                      isDark 
                        ? 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700 hover:bg-slate-800' 
                        : 'bg-white border-slate-200 text-slate-700 hover:border-slate-300 hover:bg-slate-50'
                    }`}
                  >
                    Blast Radius & Priority
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setChatInput('steps to fix active vulnerabilities');
                      setTimeout(() => {
                        const btn = document.getElementById('chat-send-btn');
                        if (btn) btn.click();
                      }, 50);
                    }}
                    className={`text-[10px] font-serif px-2.5 py-1 rounded-lg border font-medium whitespace-nowrap transition-colors flex items-center gap-1 shrink-0 ${
                      isDark 
                        ? 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700 hover:bg-slate-800' 
                        : 'bg-white border-slate-200 text-slate-700 hover:border-slate-300 hover:bg-slate-50'
                    }`}
                  >
                    Incident Response Runbook
                  </button>
                </div>

                <form onSubmit={onSendMessage} className="relative">
                  <input
                    type="text"
                    value={chatInput}
                    onChange={e => setChatInput(e.target.value)}
                    placeholder='Ask: "fix vulnerabilities", "assess lateral risk", "remediation steps"...'
                    className={`w-full rounded-xl pl-3.5 pr-10 py-2.5 text-xs font-serif focus:outline-none focus:ring-1 focus:ring-blue-500 border transition-all ${
                      isDark ? 'bg-slate-900 border-slate-800 text-slate-100 placeholder-slate-500' : 'bg-white border-slate-300 text-slate-900 placeholder-slate-400'
                    }`}
                    disabled={isChatting}
                  />
                  <button 
                    id="chat-send-btn"
                    type="submit"
                    disabled={isChatting || !chatInput.trim()}
                    className="absolute right-2 top-2 p-1 text-cyan-400 hover:text-cyan-300 transition-colors disabled:opacity-30"
                  >
                    <Send className="w-4 h-4" />
                  </button>
                </form>
              </div>
            </>
          )}

          {/* TAB 2: Live Threat Telemetry Logs */}
          {analystTab === 'logs' && (
            <div className="flex-1 flex flex-col min-h-0">
              <div className="flex-1 overflow-y-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className={`text-[10px] font-serif uppercase tracking-wider border-b ${
                      isDark ? 'bg-slate-950/70 text-slate-400 border-slate-800' : 'bg-slate-100 text-slate-500 border-slate-200'
                    }`}>
                      <th className="p-3 font-bold">Security Flaw (Bug)</th>
                      <th className="p-3 font-bold">Danger Level</th>
                      <th className="p-3 font-bold text-right">Fix & Protection Status</th>
                    </tr>
                  </thead>
                  <tbody className="text-xs">
                    {nodes
                      .filter(n => n.label === 'Vulnerability')
                      .map((node) => (
                        <tr key={`log-${node.id}`} className={`border-b transition-colors ${
                          isDark ? 'border-slate-800/60 hover:bg-slate-900/40' : 'border-slate-200 hover:bg-slate-50'
                        }`}>
                          <td className="p-3">
                            <div className={`font-serif font-bold ${isDark ? 'text-slate-200' : 'text-slate-900'}`}>{node.id}</div>
                            <div className={`text-[11px] truncate max-w-[150px] font-serif ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>{node.name}</div>
                          </td>
                          <td className="p-3">
                            <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-serif font-semibold border ${
                              node.severity === 'CRITICAL' 
                                ? (isDark ? 'bg-red-950/80 text-red-400 border-red-800' : 'bg-red-50 text-red-700 border-red-200') :
                              node.severity === 'HIGH' 
                                ? (isDark ? 'bg-amber-950/80 text-amber-400 border-amber-800' : 'bg-amber-50 text-amber-800 border-amber-200') :
                                (isDark ? 'bg-blue-950/80 text-blue-400 border-blue-800' : 'bg-blue-50 text-blue-700 border-blue-200')
                            }`}>
                              {node.severity || 'HIGH'}
                            </span>
                          </td>
                          <td className="p-3 text-right">
                            {node.status === 'UNMITIGATED' ? (
                              <button
                                onClick={() => onLiveBugFix(node.id)}
                                className="px-2.5 py-1 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white rounded-lg text-[10px] font-serif font-semibold transition-all shadow-sm"
                              >
                                Auto-Repair & Protect &rarr;
                              </button>
                            ) : (
                              <span className="text-emerald-400 font-serif font-semibold text-[11px] inline-flex items-center">
                                <CheckCircle2 className="w-3.5 h-3.5 mr-1 text-emerald-400" /> Repaired & Safe
                              </span>
                            )}
                          </td>
                        </tr>
                      ))}
                    {nodes.filter(n => n.label === 'Vulnerability').length === 0 && (
                      <tr>
                        <td colSpan={3} className="p-8 text-center text-slate-500 text-xs italic font-serif">
                          All systems are safe! Zero security flaws currently active. You can simulate an attack from Attack Simulation (Red Team).
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 3: Knowledge Map Catalog */}
          {analystTab === 'knowledge_map' && (
            <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
              {[
                { key: 'Software', title: 'Computer Systems (Servers & Databases)', desc: 'Network targets running apps and databases' },
                { key: 'Vulnerability', title: 'Security Flaws (Bugs & CVEs)', desc: 'Weaknesses in code that attackers target' },
                { key: 'Mitigation', title: 'Defenses & Fixes (Patches & Firewalls)', desc: 'Protections that seal security holes' },
                { key: 'ThreatActor', title: 'Cyber Attackers (Hacker Groups)', desc: 'Known adversarial groups attempting unauthorized access' },
                { key: 'Malware', title: 'Malicious Software (Viruses & Tools)', desc: 'Harmful software used to gain control' },
                { key: 'Technique', title: 'Attack Methods (Breach Techniques)', desc: 'Methods used to bypass defense per MITRE ATT&CK' }
              ].map(({ key: category, title: catTitle, desc: catDesc }) => {
                const catNodes = nodes.filter(n => n.label === category);
                if (catNodes.length === 0) return null;
                return (
                  <div key={category} className="space-y-1.5">
                    <div className={`border-b pb-1 ${isDark ? 'border-slate-800/60' : 'border-slate-200'}`}>
                      <div className={`flex items-center justify-between font-serif font-bold text-[11px] ${
                        isDark ? 'text-slate-300' : 'text-slate-800'
                      }`}>
                        <span>{catTitle}</span>
                        <span className="text-[10px] font-mono text-cyan-400 font-semibold">{catNodes.length} items</span>
                      </div>
                      <div className="text-[10px] text-slate-500">{catDesc}</div>
                    </div>
                    <div className="space-y-1">
                      {catNodes.map(node => (
                        <div 
                          key={node.id} 
                          onClick={() => onSelectNode(node)}
                          className={`p-2.5 rounded-xl border flex items-center justify-between cursor-pointer transition-all ${
                            isDark ? 'bg-slate-900/50 border-slate-800/80 hover:border-slate-700 hover:bg-slate-900' : 'bg-slate-50 border-slate-200 hover:border-slate-300'
                          }`}
                        >
                          <div>
                            <div className={`font-serif font-semibold ${isDark ? 'text-slate-200' : 'text-slate-900'}`}>{node.name}</div>
                            <div className={`text-[10px] truncate max-w-[210px] ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>{node.details}</div>
                          </div>
                          <span className={`text-[9px] font-mono px-2 py-0.5 rounded border ${
                            isDark ? 'bg-blue-500/10 text-cyan-400 border-blue-500/20' : 'bg-blue-50 text-blue-700 border-blue-200'
                          }`}>
                            {node.label === 'Software' ? 'Server' : node.label === 'Vulnerability' ? 'Flaw' : node.label === 'Mitigation' ? 'Defense' : node.label}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* TAB 4: Shortest Attack Vector & Path Steps */}
          {analystTab === 'attack_path' && (
            <AttackPathStepsPanel
              isDark={isDark}
              pathResult={pathResult || null}
              nodes={nodes}
              selectedThreatActor={selectedThreatActorForPath}
              onSelectThreatActor={onSelectThreatActorForPath || (() => {})}
              selectedSoftware={selectedSoftwareForPath}
              onSelectSoftware={onSelectSoftwareForPath || (() => {})}
              onCalculatePath={onCalculatePath || (() => {})}
              onClearPath={onClearPath || (() => {})}
              onSelectNode={onSelectNode}
              onLiveBugFix={onLiveBugFix}
            />
          )}

        </div>
      )}

    </div>
  );
};
