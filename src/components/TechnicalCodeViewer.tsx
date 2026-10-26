import React, { useState, useEffect } from 'react';
import { 
  Code, Terminal, Check, Copy, AlertTriangle, ShieldCheck, 
  Wrench, FileCode, CheckCircle2, ChevronDown, ChevronRight, Layers, ExternalLink,
  Edit3, Play, Plus, Sparkles, RefreshCw, X, Save, FileText, CheckCircle, Shield
} from 'lucide-react';
import { 
  SystemTechnicalDetail, 
  BugTechnicalDetail, 
  TECHNICAL_SYSTEMS_CATALOG, 
  TECHNICAL_BUGS_CATALOG,
  resolveBugTechnicalDetail,
  resolveSystemTechnicalDetail
} from '../data/technicalDetailsCatalog';

interface SystemCodeViewerProps {
  systemId: string;
  isDark: boolean;
}

interface SystemCodeFile {
  id: string;
  name: string;
  language: string;
  content: string;
  explanation: string;
  isCustom?: boolean;
}

export const SystemTechnicalViewer: React.FC<SystemCodeViewerProps> = ({ systemId, isDark }) => {
  const [copiedSection, setCopiedSection] = useState<string | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<'code' | 'editor' | 'tools'>('code');
  const [selectedToolIndex, setSelectedToolIndex] = useState<number>(0);

  const systemData = resolveSystemTechnicalDetail(systemId);

  // Custom File Management State
  const storageKey = `secops_system_code_${systemId}`;
  const [files, setFiles] = useState<SystemCodeFile[]>(() => {
    const saved = localStorage.getItem(storageKey);
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      } catch (e) {
        // fallback
      }
    }
    return [
      {
        id: 'primary-service',
        name: systemData?.codeFileName || 'server.ts',
        language: systemData?.codeLanguage || 'typescript',
        content: systemData?.exampleCode || '// Initialize system daemon\nconsole.log("Service active");\n',
        explanation: systemData?.codeExplanation || 'Primary microservice implementation.',
        isCustom: false
      }
    ];
  });

  const [activeFileId, setActiveFileId] = useState<string>(files[0]?.id || 'primary-service');
  const [isDeploying, setIsDeploying] = useState(false);
  const [deploySuccess, setDeploySuccess] = useState(false);
  const [auditResult, setAuditResult] = useState<{ status: 'PASS' | 'WARN' | 'CRIT'; findings: string[] } | null>(null);

  // Active edited file state
  const currentFile = files.find(f => f.id === activeFileId) || files[0];
  const [editFileName, setEditFileName] = useState(currentFile?.name || '');
  const [editLanguage, setEditLanguage] = useState(currentFile?.language || 'typescript');
  const [editContent, setEditContent] = useState(currentFile?.content || '');
  const [editExplanation, setEditExplanation] = useState(currentFile?.explanation || '');

  // Keep editor in sync when switching files
  useEffect(() => {
    if (currentFile) {
      setEditFileName(currentFile.name);
      setEditLanguage(currentFile.language);
      setEditContent(currentFile.content);
      setEditExplanation(currentFile.explanation);
      setAuditResult(null);
    }
  }, [activeFileId]);

  if (!systemData) return null;

  const handleCopy = (text: string, sectionKey: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(sectionKey);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const handleAddNewFile = () => {
    const newId = `script-${Date.now()}`;
    const newFile: SystemCodeFile = {
      id: newId,
      name: `/opt/scripts/custom_agent_${files.length + 1}.py`,
      language: 'python',
      content: `#!/usr/bin/env python3\n"""\nSecOps Custom Agent Script for ${systemId}\nAuto-generated security hardening & telemetry hook.\n"""\nimport sys\nimport time\n\ndef main():\n    print("[SEC-MON] Daemon hook initialized on ${systemId}")\n    # Insert custom monitoring or business logic here\n\nif __name__ == '__main__':\n    main()\n`,
      explanation: 'Custom operational Python script injected by SecOps operator.',
      isCustom: true
    };
    const updated = [...files, newFile];
    setFiles(updated);
    setActiveFileId(newId);
    setActiveSubTab('editor');
    localStorage.setItem(storageKey, JSON.stringify(updated));
  };

  const handleApplyTemplate = (templateType: string) => {
    if (templateType === 'fastapi') {
      setEditFileName('/app/api/microservice.py');
      setEditLanguage('python');
      setEditExplanation('Python FastAPI service with strict Pydantic parameter schemas and CORS defense.');
      setEditContent(`from fastapi import FastAPI, HTTPException, Depends\nfrom pydantic import BaseModel, Field\nimport uvicorn\n\napp = FastAPI(title="${systemId} Microservice", version="1.4.2")\n\nclass AuditPayload(BaseModel):\n    operator_id: str = Field(..., max_length=64)\n    action: str = Field(..., max_length=128)\n\n@app.get("/healthz")\ndef healthcheck():\n    return {"status": "HEALTHY", "node": "${systemId}", "tier": "PROD"}\n\n@app.post("/api/v1/dispatch")\ndef dispatch_event(payload: AuditPayload):\n    return {"acknowledged": True, "event_id": "EVT-88219", "operator": payload.operator_id}\n\nif __name__ == '__main__':\n    uvicorn.run(app, host="0.0.0.0", port=8080)\n`);
    } else if (templateType === 'go') {
      setEditFileName('/usr/local/bin/collector.go');
      setEditLanguage('go');
      setEditExplanation('High-throughput concurrent Go metrics listener with TLS handshake.');
      setEditContent(`package main\n\nimport (\n\t"fmt"\n\t"log"\n\t"net/http"\n\t"time"\n)\n\nfunc healthHandler(w http.ResponseWriter, r *http.Request) {\n\tw.Header().Set("Content-Type", "application/json")\n\tw.WriteHeader(http.StatusOK)\n\tfmt.Fprintf(w, \`{"node":"${systemId}","status":"ONLINE","timestamp":%d}\`, time.Now().Unix())\n}\n\nfunc main() {\n\thttp.HandleFunc("/health", healthHandler)\n\tlog.Println("[GO-SYS] Listening on :9090 for node ${systemId}")\n\tlog.Fatal(http.ListenAndServe(":9090", nil))\n}\n`);
    } else if (templateType === 'bash') {
      setEditFileName('/etc/security/audit_ports.sh');
      setEditLanguage('bash');
      setEditExplanation('Automated iptables hardening and socket listener inspector for Ubuntu/Debian.');
      setEditContent(`#!/usr/bin/env bash\nset -euo pipefail\n\n# SecOps Linux Port & Daemon Hardening Script for ${systemId}\necho "=================================================="\necho "[SYSTEM AUDIT] Checking sockets on ${systemId}..."\necho "=================================================="\n\n# Check open listening TCP ports\nss -tulpn | grep LISTEN || true\n\n# Enforce firewall default drop\niptables -P FORWARD DROP\necho "[AUDIT COMPLETE] Sockets audited; kernel network parameters locked."\n`);
    } else if (templateType === 'express') {
      setEditFileName('/var/www/service/server.ts');
      setEditLanguage('typescript');
      setEditExplanation('Node.js Express TypeScript server with helmet security headers and token authorization.');
      setEditContent(`import express, { Request, Response } from 'express';\nimport helmet from 'helmet';\n\nconst app = express();\nconst PORT = process.env.PORT || 3000;\n\napp.use(helmet());\napp.use(express.json({ limit: '500kb' }));\n\napp.get('/api/health', (req: Request, res: Response) => {\n  res.json({\n    system: '${systemId}',\n    status: 'ACTIVE',\n    timestamp: new Date().toISOString()\n  });\n});\n\napp.listen(PORT, () => {\n  console.log(\`[DAEMON] Running securely on port \${PORT}\`);\n});\n`);
    }
  };

  const handleRunSecurityAudit = () => {
    const findings: string[] = [];
    const code = editContent;

    if (code.includes('eval(') || code.includes('exec(')) {
      findings.push('DANGER: Potential arbitrary code execution detected (eval / exec invocation).');
    }
    if (/password\s*=\s*['"][^'"]+['"]/i.test(code) || /api_key\s*=\s*['"][^'"]+['"]/i.test(code)) {
      findings.push('WARNING: Hardcoded credentials or API key string pattern detected.');
    }
    if (/SELECT\s+.*?\s+FROM\s+.*?\s*\+/i.test(code) || /WHERE\s+.*?=\s*['"].*?\+/i.test(code)) {
      findings.push('CRITICAL: Possible SQL String Concatenation injection vector.');
    }
    if (code.includes('0.0.0.0') && !code.includes('helmet') && !code.includes('iptables')) {
      findings.push('NOTE: Listening on universal address 0.0.0.0 without explicit perimeter firewall.');
    }

    if (findings.length === 0) {
      setAuditResult({
        status: 'PASS',
        findings: ['Zero critical vulnerabilities detected.', 'Code conforms to SecOps syntax integrity checks.']
      });
    } else {
      const isCrit = findings.some(f => f.startsWith('CRITICAL') || f.startsWith('DANGER'));
      setAuditResult({
        status: isCrit ? 'CRIT' : 'WARN',
        findings
      });
    }
  };

  const handleSaveAndDeploy = () => {
    setIsDeploying(true);
    const updated = files.map(f => {
      if (f.id === activeFileId) {
        return {
          ...f,
          name: editFileName,
          language: editLanguage,
          content: editContent,
          explanation: editExplanation || 'Custom operator script',
          isCustom: true
        };
      }
      return f;
    });

    setFiles(updated);
    localStorage.setItem(storageKey, JSON.stringify(updated));

    setTimeout(() => {
      setIsDeploying(false);
      setDeploySuccess(true);
      setTimeout(() => setDeploySuccess(false), 2500);
    }, 700);
  };

  const handleResetFiles = () => {
    localStorage.removeItem(storageKey);
    const defaultList = [
      {
        id: 'primary-service',
        name: systemData.codeFileName,
        language: systemData.codeLanguage,
        content: systemData.exampleCode,
        explanation: systemData.codeExplanation,
        isCustom: false
      }
    ];
    setFiles(defaultList);
    setActiveFileId('primary-service');
    setAuditResult(null);
  };

  const currentTool = systemData.tools[selectedToolIndex] || systemData.tools[0];

  return (
    <div className={`rounded-xl border overflow-hidden mt-3 transition-colors ${
      isDark ? 'bg-black/50 border-blue-900/40 text-slate-200' : 'bg-slate-50 border-slate-300 text-slate-800'
    }`}>
      {/* Header bar with Sub-tabs */}
      <div className={`px-3 py-2 border-b flex items-center justify-between flex-wrap gap-2 ${
        isDark ? 'bg-slate-950/80 border-blue-900/30' : 'bg-slate-100 border-slate-200'
      }`}>
        <div className="flex items-center gap-1.5">
          <Code className="w-3.5 h-3.5 text-cyan-400" />
          <span className="font-sans font-bold text-xs tracking-tight">Codebase & Technical Architecture</span>
        </div>

        <div className="flex items-center gap-1 p-0.5 rounded-lg border border-slate-700/40 bg-slate-900/60 text-[11px]">
          <button
            onClick={() => setActiveSubTab('code')}
            className={`px-2.5 py-1 rounded-md font-sans font-medium transition-all ${
              activeSubTab === 'code'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Source Code
          </button>
          <button
            onClick={() => setActiveSubTab('editor')}
            className={`px-2.5 py-1 rounded-md font-sans font-medium transition-all flex items-center gap-1 ${
              activeSubTab === 'editor'
                ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-cyan-300'
            }`}
          >
            <Edit3 className="w-3 h-3 text-cyan-400" />
            <span>Add / Edit Code</span>
            {files.some(f => f.isCustom) && (
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            )}
          </button>
          <button
            onClick={() => setActiveSubTab('tools')}
            className={`px-2.5 py-1 rounded-md font-sans font-medium transition-all flex items-center gap-1 ${
              activeSubTab === 'tools'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <span>Tools</span>
            <span className="text-[10px] font-mono px-1 rounded-full bg-blue-500/20 text-cyan-300">
              {systemData.tools.length}
            </span>
          </button>
        </div>
      </div>

      {/* SUB-TAB 1: SYSTEM SOURCE CODE (READ / VIEW MODE) */}
      {activeSubTab === 'code' && (
        <div className="p-3.5 space-y-3">
          {/* File selector bar if multiple files exist */}
          <div className="flex items-center justify-between flex-wrap gap-2 border-b border-slate-800/80 pb-2">
            <div className="flex items-center gap-1.5 overflow-x-auto max-w-full">
              {files.map(f => (
                <button
                  key={f.id}
                  onClick={() => setActiveFileId(f.id)}
                  className={`px-2 py-1 rounded-md text-[11px] font-mono flex items-center gap-1.5 transition-all ${
                    activeFileId === f.id
                      ? 'bg-blue-600/30 border border-blue-500/50 text-cyan-300 shadow-xs'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                  }`}
                >
                  <FileCode className="w-3 h-3 text-blue-400" />
                  <span className="truncate max-w-[140px]">{f.name.split('/').pop()}</span>
                  {f.isCustom && <span className="text-[9px] px-1 rounded bg-cyan-950 text-cyan-400">Custom</span>}
                </button>
              ))}
              <button
                onClick={handleAddNewFile}
                className="px-2 py-1 rounded-md text-[11px] font-sans font-medium text-cyan-400 hover:bg-cyan-950/40 border border-dashed border-cyan-800/60 flex items-center gap-1 transition-colors"
                title="Add a new script or configuration file to this computer"
              >
                <Plus className="w-3 h-3" />
                <span>New Script</span>
              </button>
            </div>

            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setActiveSubTab('editor')}
                className="px-2.5 py-1 rounded-md text-[11px] font-sans font-semibold bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/40 text-cyan-300 flex items-center gap-1 transition-all"
              >
                <Edit3 className="w-3 h-3" />
                <span>Edit This Code</span>
              </button>
              <button
                onClick={() => handleCopy(currentFile.content, 'system-code')}
                className="px-2 py-1 rounded text-[10px] font-mono border border-slate-700 hover:bg-slate-800 text-slate-300 flex items-center gap-1 transition-colors"
              >
                {copiedSection === 'system-code' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedSection === 'system-code' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>

          <div className="flex items-center justify-between text-[11px]">
            <div className="flex items-center gap-2">
              <FileCode className="w-3.5 h-3.5 text-blue-400" />
              <span className="font-mono text-cyan-400 font-semibold">{currentFile.name}</span>
              <span className="text-[10px] font-mono uppercase px-1.5 py-0.2 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20">
                {currentFile.language}
              </span>
            </div>
          </div>

          <p className="text-[11px] text-slate-400 leading-relaxed italic font-sans">
            {currentFile.explanation}
          </p>

          <pre className={`p-3 rounded-lg font-mono text-[11px] overflow-x-auto leading-relaxed border max-h-[360px] ${
            isDark ? 'bg-[#060a12] border-slate-800 text-cyan-200' : 'bg-white border-slate-300 text-slate-900 font-medium'
          }`}>
            <code>{currentFile.content}</code>
          </pre>
        </div>
      )}

      {/* SUB-TAB 2: INTERACTIVE ADD / EDIT CODE EDITOR */}
      {activeSubTab === 'editor' && (
        <div className="p-3.5 space-y-3 animate-in fade-in duration-150">
          {/* File selector bar */}
          <div className="flex items-center justify-between flex-wrap gap-2 border-b border-slate-800/80 pb-2.5">
            <div className="flex items-center gap-1.5 overflow-x-auto">
              {files.map(f => (
                <button
                  key={f.id}
                  onClick={() => setActiveFileId(f.id)}
                  className={`px-2.5 py-1 rounded-md text-[11px] font-mono flex items-center gap-1.5 transition-all ${
                    activeFileId === f.id
                      ? 'bg-cyan-600 text-white shadow-xs font-semibold'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  <FileCode className="w-3 h-3" />
                  <span>{f.name.split('/').pop()}</span>
                </button>
              ))}
              <button
                onClick={handleAddNewFile}
                className="px-2 py-1 rounded-md text-[11px] font-sans font-medium text-cyan-400 hover:bg-cyan-950/40 border border-dashed border-cyan-700/60 flex items-center gap-1 transition-colors"
              >
                <Plus className="w-3 h-3" />
                <span>Add Script</span>
              </button>
            </div>

            {/* Template loader dropdown */}
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] font-sans text-slate-400">Load Template:</span>
              <select
                onChange={(e) => {
                  if (e.target.value) {
                    handleApplyTemplate(e.target.value);
                    e.target.value = '';
                  }
                }}
                className={`text-[10.5px] font-sans px-2 py-1 rounded-md border outline-none ${
                  isDark ? 'bg-slate-900 border-slate-800 text-slate-200' : 'bg-white border-slate-300 text-slate-800'
                }`}
              >
                <option value="">Choose standard...</option>
                <option value="express">Node.js Express Server</option>
                <option value="fastapi">Python FastAPI Microservice</option>
                <option value="go">Go Concurrency Worker</option>
                <option value="bash">SecOps Hardening Script</option>
              </select>
            </div>
          </div>

          {/* Filename & Language Bar */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <div className="sm:col-span-2">
              <label className="block text-[10px] font-sans uppercase font-bold text-slate-400 mb-1">
                File Path & Name on Node
              </label>
              <input
                type="text"
                value={editFileName}
                onChange={e => setEditFileName(e.target.value)}
                className={`w-full px-2.5 py-1.5 rounded-lg border font-mono text-xs outline-none ${
                  isDark ? 'bg-[#060a12] border-slate-800 text-cyan-300 focus:border-cyan-500' : 'bg-white border-slate-300 text-slate-900'
                }`}
                placeholder="/etc/nginx/sites-available/app.conf"
              />
            </div>
            <div>
              <label className="block text-[10px] font-sans uppercase font-bold text-slate-400 mb-1">
                Language / Syntax
              </label>
              <select
                value={editLanguage}
                onChange={e => setEditLanguage(e.target.value)}
                className={`w-full px-2.5 py-1.5 rounded-lg border font-mono text-xs outline-none ${
                  isDark ? 'bg-[#060a12] border-slate-800 text-slate-200 focus:border-cyan-500' : 'bg-white border-slate-300 text-slate-800'
                }`}
              >
                <option value="typescript">TypeScript</option>
                <option value="javascript">JavaScript</option>
                <option value="python">Python</option>
                <option value="go">Go (Golang)</option>
                <option value="bash">Bash / Shell</option>
                <option value="nginx">Nginx Config</option>
                <option value="rust">Rust</option>
                <option value="sql">SQL / DDL</option>
                <option value="yaml">YAML / Docker</option>
              </select>
            </div>
          </div>

          {/* Code Editor Area */}
          <div>
            <div className="flex items-center justify-between text-[10.5px] font-sans text-slate-400 mb-1">
              <span>Source Code Implementation:</span>
              <span className="font-mono text-[10px]">{editContent.split('\n').length} lines</span>
            </div>
            <textarea
              value={editContent}
              onChange={e => setEditContent(e.target.value)}
              rows={12}
              spellCheck={false}
              className={`w-full p-3 rounded-lg border font-mono text-xs leading-relaxed outline-none resize-y ${
                isDark 
                  ? 'bg-[#050811] border-slate-800 text-emerald-300 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/40' 
                  : 'bg-white border-slate-300 text-slate-900 font-medium'
              }`}
            />
          </div>

          {/* Audit Result Display */}
          {auditResult && (
            <div className={`p-2.5 rounded-lg border text-xs font-sans ${
              auditResult.status === 'PASS'
                ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
                : auditResult.status === 'WARN'
                ? 'bg-amber-950/40 border-amber-800/60 text-amber-300'
                : 'bg-rose-950/40 border-rose-800/60 text-rose-300'
            }`}>
              <div className="font-bold flex items-center gap-1.5 mb-1">
                {auditResult.status === 'PASS' ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                )}
                <span>SecOps Code Scan: {auditResult.status === 'PASS' ? 'CLEAN (0 Vulnerabilities)' : 'Security Warnings'}</span>
              </div>
              <ul className="list-disc list-inside space-y-0.5 text-[11px] opacity-90">
                {auditResult.findings.map((f, i) => (
                  <li key={i}>{f}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex items-center justify-between flex-wrap gap-2 pt-1 border-t border-slate-800/70">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleRunSecurityAudit}
                className="px-3 py-1.5 rounded-lg border text-xs font-sans font-semibold border-amber-600/40 bg-amber-950/30 hover:bg-amber-900/40 text-amber-300 flex items-center gap-1.5 transition-colors"
                title="Perform static security analysis and check for injection vectors"
              >
                <Shield className="w-3.5 h-3.5 text-amber-400" />
                <span>Run Security Audit</span>
              </button>
              <button
                type="button"
                onClick={handleResetFiles}
                className="px-2.5 py-1.5 rounded-lg text-xs font-sans text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 transition-colors"
                title="Restore default factory code"
              >
                <span>Reset to Factory</span>
              </button>
            </div>

            <button
              type="button"
              onClick={handleSaveAndDeploy}
              disabled={isDeploying}
              className={`px-4 py-1.5 rounded-lg font-sans font-semibold text-xs flex items-center gap-1.5 transition-all shadow-md ${
                deploySuccess
                  ? 'bg-emerald-600 text-white'
                  : 'bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white'
              }`}
            >
              {isDeploying ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Compiling & Deploying to Node...</span>
                </>
              ) : deploySuccess ? (
                <>
                  <Check className="w-3.5 h-3.5" />
                  <span>Deployed Successfully!</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" />
                  <span>Save & Deploy to Computer</span>
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {/* SUB-TAB 2: ASSOCIATED TOOLS */}
      {activeSubTab === 'tools' && (
        <div className="p-3.5 space-y-3">
          {/* Tool selector pills */}
          <div className="flex flex-wrap gap-1.5 border-b border-slate-800/80 pb-2.5">
            {systemData.tools.map((tool, idx) => (
              <button
                key={tool.name}
                onClick={() => setSelectedToolIndex(idx)}
                className={`px-2.5 py-1 rounded-lg text-xs font-mono font-medium border transition-all flex items-center gap-1.5 ${
                  selectedToolIndex === idx
                    ? 'bg-blue-600/20 border-blue-500 text-cyan-300 shadow-sm'
                    : isDark 
                      ? 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200' 
                      : 'bg-white border-slate-300 text-slate-600 hover:bg-slate-100'
                }`}
              >
                <Wrench className="w-3 h-3 text-blue-400" />
                <span>{tool.name}</span>
                <span className="text-[9px] opacity-70">({tool.version})</span>
              </button>
            ))}
          </div>

          {/* Active Tool Specifications */}
          {currentTool && (
            <div className="space-y-3 animate-in fade-in duration-200">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="font-bold text-xs text-slate-200 flex items-center gap-2">
                    {currentTool.name}
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-blue-500/10 text-cyan-400 border border-blue-500/20">
                      {currentTool.version}
                    </span>
                  </h4>
                  {currentTool.description && (
                    <p className="text-[11px] text-slate-400 mt-0.5">{currentTool.description}</p>
                  )}
                </div>
              </div>

              {/* Installation Command */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[10px] font-mono uppercase text-slate-400 font-bold">
                  <span>Installation Command</span>
                  <button
                    onClick={() => handleCopy(currentTool.installationCommand, `tool-install-${currentTool.name}`)}
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 normal-case"
                  >
                    {copiedSection === `tool-install-${currentTool.name}` ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
                    <span>{copiedSection === `tool-install-${currentTool.name}` ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <div className={`p-2 rounded-lg font-mono text-[11px] border overflow-x-auto flex items-center justify-between ${
                  isDark ? 'bg-[#070d18] border-slate-800 text-emerald-300' : 'bg-white border-slate-300 text-emerald-700'
                }`}>
                  <code>{currentTool.installationCommand}</code>
                </div>
              </div>

              {/* Basic Configuration Example */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[10px] font-mono uppercase text-slate-400 font-bold">
                  <span>Basic Configuration Example</span>
                  <button
                    onClick={() => handleCopy(currentTool.configExample, `tool-cfg-${currentTool.name}`)}
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 normal-case"
                  >
                    {copiedSection === `tool-cfg-${currentTool.name}` ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
                    <span>{copiedSection === `tool-cfg-${currentTool.name}` ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className={`p-2.5 rounded-lg font-mono text-[11px] overflow-x-auto leading-relaxed border ${
                  isDark ? 'bg-[#060a12] border-slate-800 text-slate-300' : 'bg-white border-slate-300 text-slate-800'
                }`}>
                  <code>{currentTool.configExample}</code>
                </pre>
              </div>

              {/* Example Usage / Code */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[10px] font-mono uppercase text-slate-400 font-bold">
                  <span>Example Usage / Code</span>
                  <button
                    onClick={() => handleCopy(currentTool.exampleUsage, `tool-usage-${currentTool.name}`)}
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 normal-case"
                  >
                    {copiedSection === `tool-usage-${currentTool.name}` ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
                    <span>{copiedSection === `tool-usage-${currentTool.name}` ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className={`p-2.5 rounded-lg font-mono text-[11px] overflow-x-auto leading-relaxed border ${
                  isDark ? 'bg-[#060a12] border-slate-800 text-amber-200' : 'bg-white border-slate-300 text-amber-950 font-medium'
                }`}>
                  <code>{currentTool.exampleUsage}</code>
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

interface BugCodeViewerProps {
  bugId: string;
  isDark: boolean;
  customCode?: Partial<BugTechnicalDetail>;
  onUpdateCode?: (updated: BugTechnicalDetail) => void;
  nodeProperties?: any;
  onLiveBugFix?: (bugId: string, systemId?: string) => void;
}

export const BugTechnicalViewer: React.FC<BugCodeViewerProps> = ({ 
  bugId, 
  isDark, 
  customCode, 
  onUpdateCode, 
  nodeProperties,
  onLiveBugFix
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<'both' | 'buggy' | 'fixed' | 'exploit' | 'simulate'>('both');
  const [isEditing, setIsEditing] = useState<boolean>(false);
  const [isGeneratingAi, setIsGeneratingAi] = useState<boolean>(false);
  const [isSynthesizingAiFix, setIsSynthesizingAiFix] = useState<boolean>(false);

  // Simulation state
  const [simulationRunning, setSimulationRunning] = useState<boolean>(false);
  const [simulationType, setSimulationType] = useState<'exploit' | 'fix' | null>(null);
  const [simulationLogs, setSimulationLogs] = useState<string[]>([]);
  const [simulationSuccess, setSimulationSuccess] = useState<boolean | null>(null);

  // Resolve data dynamically (Catalog, Custom User Codes, or Realistic Synthesis)
  const resolvedData = resolveBugTechnicalDetail(bugId, customCode, nodeProperties);
  const hasCorrectedCode = Boolean(resolvedData.correctedCode && resolvedData.correctedCode.trim() !== '');

  // Local editing form state
  const [editForm, setEditForm] = useState<BugTechnicalDetail>({
    ...resolvedData
  });

  // Sync edit form if bugId changes
  React.useEffect(() => {
    setEditForm(resolveBugTechnicalDetail(bugId, customCode, nodeProperties));
  }, [bugId, customCode, nodeProperties]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleSaveCode = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (onUpdateCode) {
      onUpdateCode(editForm);
    }
    setIsEditing(false);
  };

  // Synthesize fix code on demand with Graph AI
  const handleSynthesizeAiFix = async () => {
    setIsSynthesizingAiFix(true);
    try {
      const res = await fetch('/api/bug/synthesize-fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vuln_id: bugId,
          vuln_name: resolvedData.bugName,
          system_id: resolvedData.targetSoftwareId,
          codeLanguage: resolvedData.codeLanguage,
          buggyCode: resolvedData.buggyCode,
          severity: nodeProperties?.severity || 'CRITICAL',
          cause: nodeProperties?.cause || resolvedData.rootCause
        })
      });
      const data = await res.json();
      if (data.status === 'success' && data.correctedCode) {
        const updated: BugTechnicalDetail = {
          ...resolvedData,
          correctedCode: data.correctedCode,
          fixExplanation: data.fixExplanation || 'Security patch synthesized by Graph AI.',
          rootCause: data.rootCause || resolvedData.rootCause
        };
        setEditForm(updated);
        if (onUpdateCode) {
          onUpdateCode(updated);
        }
        if (onLiveBugFix) {
          onLiveBugFix(bugId, resolvedData.targetSoftwareId);
        }
      }
    } catch (err) {
      console.warn('Error synthesizing AI fix:', err);
    } finally {
      setIsSynthesizingAiFix(false);
    }
  };

  const handleApplyTemplate = (type: 'sqli' | 'rce' | 'buffer' | 'traversal' | 'deser') => {
    if (type === 'sqli') {
      setEditForm(prev => ({
        ...prev,
        codeLanguage: 'sql',
        codeFileName: 'auth_query.sql',
        buggyCode: `-- Vulnerable Dynamic SQL Query\nSELECT * FROM accounts WHERE username = '` + '${userInput}' + `' AND status = 'ACTIVE';`,
        exploitScript: `curl -X POST "http://target/login" -d "username=admin' OR '1'='1' --"`,
        errorMessage: `DatabaseQueryError: Syntax error or unexpected record array returned\nExtracted 2,400 user records via SQLi union injection`,
        correctedCode: `-- Hardened Parameterized Query\nPREPARE auth_stmt FROM 'SELECT * FROM accounts WHERE username = ? AND status = ?';\nEXECUTE auth_stmt USING @sanitized_user, 'ACTIVE';`,
        rootCause: 'String interpolation in SQL query allowed parameter escaping.',
        fixExplanation: 'Migrated to parameterized prepared statements.'
      }));
    } else if (type === 'rce') {
      setEditForm(prev => ({
        ...prev,
        codeLanguage: 'python',
        codeFileName: 'system_hook.py',
        buggyCode: `# Vulnerable Command Execution\nimport os\ndef ping_host(host):\n    # FLAW: Shell metacharacters are executed directly\n    os.system(f"ping -c 2 {host}")`,
        exploitScript: `curl -X POST "http://target/diagnostics" -d "host=127.0.0.1; whoami; id"`,
        errorMessage: `root\nuid=0(root) gid=0(root) groups=0(root)\nRemote shell spawned on TCP port 4444!`,
        correctedCode: `# Hardened Command Execution\nimport subprocess, ipaddress\ndef ping_host(host):\n    valid_ip = str(ipaddress.ip_address(host.strip()))\n    subprocess.run(["ping", "-c", "2", valid_ip], check=True, timeout=5)`,
        rootCause: 'Unsanitized input passed directly to os.system shell invocation.',
        fixExplanation: 'Validated IP address format and executed binary via immutable argument array.'
      }));
    } else if (type === 'buffer') {
      setEditForm(prev => ({
        ...prev,
        codeLanguage: 'c',
        codeFileName: 'packet_ingress.c',
        buggyCode: `// Vulnerable Heap/Stack Copy\nvoid parse_stream(const char *buf, size_t len) {\n    char stack_buf[256];\n    strcpy(stack_buf, buf); // FLAW: Unchecked copy\n}`,
        exploitScript: `python3 -c "import socket; s=socket.socket(); s.connect(('10.0.1.5', 9000)); s.send(b'A'*384 + b'\\x90'*32 + b'payload')"\n`,
        errorMessage: `*** stack smashing detected ***: terminated\nInstruction Pointer (RIP) overwritten with 0x4141414141414141`,
        correctedCode: `// Hardened Bounded Copy\nbool parse_stream(const char *buf, size_t len) {\n    char stack_buf[256];\n    if (len >= sizeof(stack_buf)) return false;\n    memcpy(stack_buf, buf, len);\n    stack_buf[len] = '\\0';\n    return true;\n}`,
        rootCause: 'Unbounded memory copy without destination buffer verification.',
        fixExplanation: 'Enforced strict boundary checks and bounds-safe memcpy.'
      }));
    } else if (type === 'traversal') {
      setEditForm(prev => ({
        ...prev,
        codeLanguage: 'go',
        codeFileName: 'file_server.go',
        buggyCode: `// Vulnerable Directory Traversal\nfunc serveDoc(w http.ResponseWriter, r *http.Request) {\n    filename := r.URL.Query().Get("doc")\n    data, _ := os.ReadFile("/var/www/uploads/" + filename)\n    w.Write(data)\n}`,
        exploitScript: `curl "http://target/download?doc=../../../../etc/shadow"`,
        errorMessage: `HTTP/1.1 200 OK\nroot:$6$salt$encrypted_hash:19100:0:99999:7:::\nSensitive shadow passwords retrieved!`,
        correctedCode: `// Hardened Path Cleansing\nfunc serveDoc(w http.ResponseWriter, r *http.Request) {\n    filename := filepath.Clean(r.URL.Query().Get("doc"))\n    fullPath := filepath.Join("/var/www/uploads", filepath.Base(filename))\n    data, err := os.ReadFile(fullPath)\n    if err != nil { http.NotFound(w, r); return }\n    w.Write(data)\n}`,
        rootCause: 'Unchecked path concatenation allowed dot-dot directory escape.',
        fixExplanation: 'Applied filepath.Clean and filepath.Base to restrict access strictly to upload root.'
      }));
    } else {
      setEditForm(prev => ({
        ...prev,
        codeLanguage: 'java',
        codeFileName: 'SessionDeserializer.java',
        buggyCode: `// Vulnerable Deserialization\nObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));\nUserSession session = (UserSession) ois.readObject(); // FLAW: Unrestricted class loading`,
        exploitScript: `ysoserial CommonsCollections6 "touch /tmp/pwned" | base64 | curl -X POST -d @- http://target/session`,
        errorMessage: `java.lang.Runtime.exec() executed by GadgetChain\nReverse shell connected to attacker server!`,
        correctedCode: `// Hardened Safe Object Filter\nValidatingObjectInputStream ois = new ValidatingObjectInputStream(new ByteArrayInputStream(payload));\nois.accept(UserSession.class);\nUserSession session = (UserSession) ois.readObject();`,
        rootCause: 'Java ObjectInputStream deserialized arbitrary gadget classes without allowlisting.',
        fixExplanation: 'Enforced ValidatingObjectInputStream with strict class allowlist.'
      }));
    }
  };

  const handleAiGenerateCode = async () => {
    setIsGeneratingAi(true);
    try {
      const res = await fetch('/api/bug/generate-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          bug_id: bugId,
          bug_name: editForm.bugName,
          target_software: editForm.targetSoftwareId,
          language: editForm.codeLanguage,
          current_code: editForm.buggyCode
        })
      });
      const data = await res.json();
      if (data.status === 'success' && data.code) {
        setEditForm(prev => ({
          ...prev,
          codeLanguage: data.code.codeLanguage || prev.codeLanguage,
          codeFileName: data.code.codeFileName || prev.codeFileName,
          buggyCode: data.code.buggyCode || prev.buggyCode,
          correctedCode: data.code.correctedCode || prev.correctedCode,
          errorMessage: data.code.errorMessage || prev.errorMessage,
          exploitScript: data.code.exploitScript || prev.exploitScript,
          rootCause: data.code.rootCause || prev.rootCause,
          fixExplanation: data.code.fixExplanation || prev.fixExplanation
        }));
      }
    } catch (err) {
      console.warn('AI code generation notice, applying synthesized domain code:', err);
      handleApplyTemplate('rce');
    } finally {
      setIsGeneratingAi(false);
    }
  };

  // Run live terminal simulation
  const runSimulation = (mode: 'exploit' | 'fix') => {
    setActiveView('simulate');
    setSimulationRunning(true);
    setSimulationType(mode);
    setSimulationLogs([]);
    setSimulationSuccess(null);

    const logs: string[] = [];
    if (mode === 'exploit') {
      logs.push(`[SIMULATOR] Initializing sandbox environment for ${resolvedData.bugId}...`);
      logs.push(`[SOCKET] Establishing raw TCP stream to target '${resolvedData.targetSoftwareId}'...`);
      logs.push(`[PAYLOAD] Preparing exploit script: ${resolvedData.codeFileName}`);
      logs.push(`[DISPATCH] Transmitting exploit payload to target daemon...`);
      logs.push(`[OUTPUT] Target triggered: ${resolvedData.errorMessage.split('\n')[0]}`);
      logs.push(`[ALERT] Compromise established! Shell/Privilege escalation verified.`);
    } else {
      if (!hasCorrectedCode) {
        logs.push(`[SIMULATOR] Staging remediation verification for ${resolvedData.bugId}...`);
        logs.push(`[NOTICE] No patch code is currently staged.`);
        logs.push(`[ACTION] Click 'Synthesize Fix Code with Graph AI' or edit code to stage a patch.`);
      } else {
        logs.push(`[SIMULATOR] Staging remediation verification for ${resolvedData.bugId}...`);
        logs.push(`[COMPILER] Compiling patched code: ${resolvedData.codeFileName}...`);
        logs.push(`[DEPLOY] Injecting security boundary fix into runtime memory...`);
        logs.push(`[TEST] Executing regression exploit payload...`);
        logs.push(`[VERIFICATION] Target daemon intercepted attack: Access Denied / Safe boundary maintained.`);
        logs.push(`[STATUS] System health restored. CVE verified as SELF_HEALED.`);
      }
    }

    let i = 0;
    const interval = setInterval(() => {
      if (i < logs.length) {
        setSimulationLogs(prev => [...prev, logs[i]]);
        i++;
      } else {
        clearInterval(interval);
        setSimulationRunning(false);
        setSimulationSuccess(mode === 'fix' && hasCorrectedCode);
      }
    }, 400);
  };

  return (
    <div className={`rounded-xl border overflow-hidden mt-3 transition-colors ${
      isDark ? 'bg-black/50 border-red-900/40 text-slate-200' : 'bg-slate-50 border-slate-300 text-slate-800'
    }`}>
      {/* Header with Segmented View Control & Add/Edit Codes Button */}
      <div className={`px-3 py-2 border-b flex items-center justify-between flex-wrap gap-2 ${
        isDark ? 'bg-slate-950/80 border-red-900/30' : 'bg-slate-100 border-slate-200'
      }`}>
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-red-400" />
          <span className="font-sans font-bold text-xs">Vulnerability Code & Fix Analysis</span>
          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-neutral-800 text-neutral-300 border border-neutral-700">
            {resolvedData.codeFileName}
          </span>
          <span className="text-[9px] font-mono uppercase px-1.5 py-0.2 rounded bg-red-500/10 text-red-400 border border-red-500/20">
            {resolvedData.codeLanguage}
          </span>
        </div>

        {/* Action Buttons: Add/Edit Codes & Segmented View */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <button
            onClick={() => setIsEditing(!isEditing)}
            className={`px-2 py-0.5 rounded-md text-[10.5px] font-medium border flex items-center gap-1 transition-all ${
              isEditing 
                ? 'bg-amber-600 text-white border-amber-500 shadow-xs' 
                : isDark ? 'bg-neutral-900/80 border-neutral-700 text-amber-300 hover:bg-neutral-800' : 'bg-white border-slate-300 text-amber-700 hover:bg-amber-50'
            }`}
            title="Add or edit code snippets, exploit script, and security patches for this bug"
          >
            {isEditing ? <X className="w-3 h-3" /> : <Edit3 className="w-3 h-3" />}
            <span>{isEditing ? 'Close Editor' : 'Add / Edit Codes to Bug'}</span>
          </button>

          {/* Segmented View Toggles */}
          <div className="flex items-center gap-0.5 p-0.5 rounded-lg border border-slate-700/40 bg-slate-900/60 text-[10.5px]">
            <button
              onClick={() => setActiveView('both')}
              className={`px-2 py-0.5 rounded-md font-medium transition-all ${
                activeView === 'both' ? 'bg-blue-600 text-white shadow-xs' : 'text-slate-400 hover:text-white'
              }`}
            >
              Side-by-Side
            </button>
            <button
              onClick={() => setActiveView('buggy')}
              className={`px-2 py-0.5 rounded-md font-medium transition-all text-red-400 ${
                activeView === 'buggy' ? 'bg-red-600 text-white shadow-xs' : 'hover:text-red-300'
              }`}
            >
              Buggy Code
            </button>
            <button
              onClick={() => setActiveView('fixed')}
              className={`px-2 py-0.5 rounded-md font-medium transition-all ${
                activeView === 'fixed' ? 'bg-emerald-600 text-white shadow-xs' : 'text-emerald-400 hover:text-emerald-300'
              }`}
            >
              Fixed Code
            </button>
            <button
              onClick={() => setActiveView('exploit')}
              className={`px-2 py-0.5 rounded-md font-medium transition-all text-purple-400 ${
                activeView === 'exploit' ? 'bg-purple-600 text-white shadow-xs' : 'hover:text-purple-300'
              }`}
            >
              Exploit Script
            </button>
            <button
              onClick={() => runSimulation('exploit')}
              className={`px-2 py-0.5 rounded-md font-medium transition-all text-cyan-400 flex items-center gap-1 ${
                activeView === 'simulate' ? 'bg-cyan-600 text-white shadow-xs' : 'hover:text-cyan-300'
              }`}
              title="Run interactive simulation in virtual cyber terminal"
            >
              <Play className="w-2.5 h-2.5" />
              <span>Simulate</span>
            </button>
          </div>
        </div>
      </div>

      {/* CODE EDITOR DRAWER: Allows user to add or modify codes for ANY bug! */}
      {isEditing && (
        <form onSubmit={handleSaveCode} className="p-3.5 border-b border-amber-900/40 bg-amber-950/10 space-y-3 animate-in fade-in duration-200">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <span className="font-sans font-bold text-xs text-amber-400 flex items-center gap-1.5">
                <Code className="w-3.5 h-3.5" />
                Customize Bug Code & Exploit Payload ({resolvedData.bugId})
              </span>
            </div>

            {/* Quick Actions: AI Generate & Template Presets */}
            <div className="flex items-center gap-1.5 flex-wrap">
              <button
                type="button"
                onClick={handleAiGenerateCode}
                disabled={isGeneratingAi}
                className="px-2.5 py-1 rounded-md text-[10px] font-medium bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white shadow-xs flex items-center gap-1 transition-all disabled:opacity-50"
              >
                {isGeneratingAi ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Sparkles className="w-3 h-3" />}
                <span>{isGeneratingAi ? 'Writing Code...' : 'AI Generate Codes'}</span>
              </button>

              <span className="text-[10px] text-slate-500">|</span>

              <span className="text-[10px] font-mono text-slate-400">Templates:</span>
              <button
                type="button"
                onClick={() => handleApplyTemplate('sqli')}
                className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700"
              >
                SQLi
              </button>
              <button
                type="button"
                onClick={() => handleApplyTemplate('rce')}
                className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 hover:bg-slate-700 text-red-300 border border-slate-700"
              >
                RCE
              </button>
              <button
                type="button"
                onClick={() => handleApplyTemplate('buffer')}
                className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 hover:bg-slate-700 text-amber-300 border border-slate-700"
              >
                Overflow
              </button>
              <button
                type="button"
                onClick={() => handleApplyTemplate('traversal')}
                className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 hover:bg-slate-700 text-emerald-300 border border-slate-700"
              >
                Traversal
              </button>
              <button
                type="button"
                onClick={() => handleApplyTemplate('deser')}
                className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 hover:bg-slate-700 text-purple-300 border border-slate-700"
              >
                Deserialization
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="block text-[10px] font-mono uppercase text-slate-400 font-bold mb-1">
                Programming Language
              </label>
              <select
                value={editForm.codeLanguage}
                onChange={e => setEditForm({ ...editForm, codeLanguage: e.target.value })}
                className={`w-full p-1.5 rounded-lg border text-xs font-mono ${
                  isDark ? 'bg-slate-900 border-slate-800 text-slate-200' : 'bg-white border-slate-300 text-slate-800'
                }`}
              >
                <option value="python">Python</option>
                <option value="c">C / C++</option>
                <option value="java">Java</option>
                <option value="typescript">TypeScript / Node.js</option>
                <option value="go">Go (Golang)</option>
                <option value="rust">Rust</option>
                <option value="sql">SQL / Database</option>
                <option value="bash">Bash / Shell</option>
                <option value="php">PHP</option>
                <option value="apache">Apache / Nginx Config</option>
              </select>
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase text-slate-400 font-bold mb-1">
                Source File Name
              </label>
              <input
                type="text"
                value={editForm.codeFileName}
                onChange={e => setEditForm({ ...editForm, codeFileName: e.target.value })}
                placeholder="e.g. auth_controller.py"
                className={`w-full p-1.5 rounded-lg border text-xs font-mono ${
                  isDark ? 'bg-slate-900 border-slate-800 text-slate-200' : 'bg-white border-slate-300 text-slate-800'
                }`}
              />
            </div>
          </div>

          {/* Buggy Code & Corrected Code Editors */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            <div>
              <label className="block text-[10px] font-mono uppercase text-red-400 font-bold mb-1 flex items-center justify-between">
                <span>Vulnerable / Buggy Code</span>
                <span className="text-[9px] text-slate-500 font-normal">Add flawed logic here</span>
              </label>
              <textarea
                value={editForm.buggyCode}
                onChange={e => setEditForm({ ...editForm, buggyCode: e.target.value })}
                rows={6}
                className={`w-full p-2.5 rounded-lg font-mono text-[11px] leading-relaxed border transition-colors ${
                  isDark 
                    ? 'bg-[#0c0505] border-red-900/60 text-red-200 focus:outline-none focus:border-red-500' 
                    : 'bg-white border-red-300 text-red-950 font-medium focus:outline-none focus:border-red-600 focus:ring-1 focus:ring-red-400'
                }`}
                placeholder="// Enter vulnerable implementation here..."
              />
            </div>

            <div>
              <label className={`block text-[10px] font-mono uppercase font-bold mb-1 flex items-center justify-between ${
                isDark ? 'text-emerald-400' : 'text-emerald-800'
              }`}>
                <span>Corrected / Patched Code</span>
                <span className="text-[9px] text-slate-500 font-normal">Add security fix here</span>
              </label>
              <textarea
                value={editForm.correctedCode}
                onChange={e => setEditForm({ ...editForm, correctedCode: e.target.value })}
                rows={6}
                className={`w-full p-2.5 rounded-lg font-mono text-[11px] leading-relaxed border transition-colors ${
                  isDark 
                    ? 'bg-[#030c05] border-emerald-900/60 text-emerald-200 focus:outline-none focus:border-emerald-500' 
                    : 'bg-white border-emerald-300 text-emerald-950 font-medium focus:outline-none focus:border-emerald-600 focus:ring-1 focus:ring-emerald-400'
                }`}
                placeholder="// Enter corrected code or security patch..."
              />
            </div>
          </div>

          {/* Exploit Reproduction & Error Output */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            <div>
              <label className={`block text-[10px] font-mono uppercase font-bold mb-1 ${
                isDark ? 'text-purple-400' : 'text-purple-800'
              }`}>
                Exploit Script / Attack Command
              </label>
              <textarea
                value={editForm.exploitScript || ''}
                onChange={e => setEditForm({ ...editForm, exploitScript: e.target.value })}
                rows={3}
                className={`w-full p-2.5 rounded-lg font-mono text-[11px] leading-relaxed border transition-colors ${
                  isDark 
                    ? 'bg-[#0a0510] border-purple-900/60 text-purple-200 focus:outline-none focus:border-purple-500' 
                    : 'bg-white border-purple-300 text-purple-950 font-medium focus:outline-none focus:border-purple-600 focus:ring-1 focus:ring-purple-400'
                }`}
                placeholder="curl -X POST http://target/exploit"
              />
            </div>

            <div>
              <label className={`block text-[10px] font-mono uppercase font-bold mb-1 ${
                isDark ? 'text-amber-400' : 'text-amber-800'
              }`}>
                Observed Error Trace / Stack Trace
              </label>
              <textarea
                value={editForm.errorMessage}
                onChange={e => setEditForm({ ...editForm, errorMessage: e.target.value })}
                rows={3}
                className={`w-full p-2.5 rounded-lg font-mono text-[11px] leading-relaxed border transition-colors ${
                  isDark 
                    ? 'bg-[#100a05] border-amber-900/60 text-amber-200 focus:outline-none focus:border-amber-500' 
                    : 'bg-white border-amber-300 text-amber-950 font-medium focus:outline-none focus:border-amber-600 focus:ring-1 focus:ring-amber-400'
                }`}
                placeholder="Stack trace or core dump output..."
              />
            </div>
          </div>

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-amber-900/30">
            <button
              type="button"
              onClick={() => setIsEditing(false)}
              className="px-3 py-1.5 rounded-lg text-xs font-sans border border-slate-700 text-slate-400 hover:text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-1.5 rounded-lg text-xs font-sans font-semibold bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white shadow-md flex items-center gap-1.5"
            >
              <Save className="w-3.5 h-3.5" />
              <span>Save & Attach Codes to Bug</span>
            </button>
          </div>
        </form>
      )}

      {/* SIMULATOR TERMINAL VIEW */}
      {activeView === 'simulate' && (
        <div className="p-3.5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span className="font-bold text-xs text-cyan-300">
                Interactive Cyber Sandbox Terminal: {resolvedData.bugId}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => runSimulation('exploit')}
                disabled={simulationRunning}
                className="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold bg-red-600 hover:bg-red-500 text-white flex items-center gap-1 disabled:opacity-50"
              >
                <Play className="w-2.5 h-2.5" />
                <span>Simulate Exploit Attack</span>
              </button>
              <button
                onClick={() => runSimulation('fix')}
                disabled={simulationRunning}
                className="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold bg-emerald-600 hover:bg-emerald-500 text-white flex items-center gap-1 disabled:opacity-50"
              >
                <Shield className="w-2.5 h-2.5" />
                <span>Simulate Security Fix</span>
              </button>
            </div>
          </div>

          <pre className="p-3 rounded-lg font-mono text-[11px] overflow-x-auto leading-relaxed border bg-black border-cyan-900/60 text-cyan-300 min-h-[160px] max-h-[260px]">
            {simulationLogs.map((line, idx) => (
              <div key={idx} className="flex items-start gap-2">
                <span className="text-slate-600 select-none">{(idx + 1).toString().padStart(2, '0')}</span>
                <span className={
                  line.includes('[ALERT]') || line.includes('Compromise') ? 'text-red-400 font-bold' :
                  line.includes('[STATUS]') || line.includes('restored') ? 'text-emerald-400 font-bold' :
                  line.includes('[OUTPUT]') ? 'text-amber-300' :
                  'text-cyan-300'
                }>{line}</span>
              </div>
            ))}
            {simulationRunning && (
              <div className="flex items-center gap-2 text-slate-500 animate-pulse mt-2">
                <span>Executing payload in isolated container...</span>
              </div>
            )}
          </pre>
        </div>
      )}

      {/* EXPLOIT SCRIPT VIEW */}
      {activeView === 'exploit' && (
        <div className="p-3.5 space-y-3">
          <div className="flex items-center justify-between text-[11px]">
            <div className={`flex items-center gap-2 font-bold ${isDark ? 'text-purple-400' : 'text-purple-900'}`}>
              <Terminal className="w-3.5 h-3.5 text-purple-500" />
              <span>Exploit Reproduction Script & Verification Command</span>
            </div>
            <button
              onClick={() => handleCopy(resolvedData.exploitScript || resolvedData.errorMessage, 'exploit-script')}
              className={`px-2 py-0.5 rounded text-[10px] font-mono border flex items-center gap-1 transition-colors ${
                isDark ? 'border-purple-900/50 hover:bg-purple-900/30 text-purple-300' : 'border-purple-300 hover:bg-purple-100 text-purple-900'
              }`}
            >
              {copiedKey === 'exploit-script' ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
              <span>{copiedKey === 'exploit-script' ? 'Copied' : 'Copy Script'}</span>
            </button>
          </div>
          <pre className={`p-3 rounded-lg font-mono text-[11px] overflow-x-auto leading-relaxed border ${
            isDark ? 'bg-[#08040d] border-purple-900/50 text-purple-200' : 'bg-purple-50/80 border-purple-300 text-purple-950 font-medium'
          }`}>
            <code>{resolvedData.exploitScript || `# Exploit Command:\ncurl -X POST "http://${resolvedData.targetSoftwareId}/api/exploit"`}</code>
          </pre>
        </div>
      )}

      {/* NORMAL CODE COMPARISON / BUGGY / FIXED VIEWS */}
      {(activeView === 'both' || activeView === 'buggy' || activeView === 'fixed') && (
        <div className="p-3.5 space-y-4">
          
          {/* Code Comparison Grid */}
          <div className={`grid gap-3.5 ${activeView === 'both' ? 'grid-cols-1 lg:grid-cols-2' : 'grid-cols-1'}`}>
            
            {/* 1. BUGGY CODE PANEL */}
            {(activeView === 'both' || activeView === 'buggy') && (
              <div className={`rounded-xl border overflow-hidden ${
                isDark ? 'bg-[#0a0505] border-red-900/60' : 'bg-red-50/70 border-red-300 shadow-xs'
              }`}>
                <div className={`px-3 py-2 border-b flex items-center justify-between ${
                  isDark ? 'bg-red-950/40 border-red-900/40' : 'bg-red-100/90 border-red-200'
                }`}>
                  <div className={`flex items-center gap-1.5 font-bold text-[11px] ${
                    isDark ? 'text-red-400' : 'text-red-900'
                  }`}>
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Buggy Code / Vulnerable Implementation</span>
                  </div>
                  <button
                    onClick={() => handleCopy(resolvedData.buggyCode, 'buggy-code')}
                    className={`px-2 py-0.5 rounded text-[10px] font-mono border flex items-center gap-1 transition-colors ${
                      isDark ? 'border-red-900/50 hover:bg-red-900/30 text-red-300' : 'border-red-300 hover:bg-red-200/80 text-red-900'
                    }`}
                  >
                    {copiedKey === 'buggy-code' ? <Check className="w-2.5 h-2.5 text-emerald-500" /> : <Copy className="w-2.5 h-2.5" />}
                    <span>{copiedKey === 'buggy-code' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>

                <pre className={`p-3 font-mono text-[11px] overflow-x-auto leading-relaxed bg-transparent ${
                  isDark ? 'text-red-200' : 'text-red-950 font-medium'
                }`}>
                  <code>{resolvedData.buggyCode}</code>
                </pre>
              </div>
            )}

            {/* 2. CORRECTED CODE PANEL */}
            {(activeView === 'both' || activeView === 'fixed') && (
              <div className={`rounded-xl border overflow-hidden ${
                isDark ? 'bg-[#030a05] border-emerald-900/60' : 'bg-emerald-50/70 border-emerald-300 shadow-xs'
              }`}>
                <div className={`px-3 py-2 border-b flex items-center justify-between ${
                  isDark ? 'bg-emerald-950/40 border-emerald-900/40' : 'bg-emerald-100/90 border-emerald-200'
                }`}>
                  <div className={`flex items-center gap-1.5 font-bold text-[11px] ${
                    isDark ? 'text-emerald-400' : 'text-emerald-900'
                  }`}>
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Corrected Code / Security Fix</span>
                  </div>
                  {hasCorrectedCode && (
                    <div className="flex items-center gap-1.5">
                      <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
                        <Sparkles className="w-2.5 h-2.5 text-emerald-400" /> Graph AI Generated
                      </span>
                      <button
                        onClick={() => handleCopy(resolvedData.correctedCode, 'fixed-code')}
                        className={`px-2 py-0.5 rounded text-[10px] font-mono border flex items-center gap-1 transition-colors ${
                          isDark ? 'border-emerald-900/50 hover:bg-emerald-900/30 text-emerald-300' : 'border-emerald-300 hover:bg-emerald-200/80 text-emerald-900'
                        }`}
                      >
                        {copiedKey === 'fixed-code' ? <Check className="w-2.5 h-2.5 text-emerald-500" /> : <Copy className="w-2.5 h-2.5" />}
                        <span>{copiedKey === 'fixed-code' ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  )}
                </div>

                {!hasCorrectedCode ? (
                  <div className="p-4 flex flex-col items-center justify-center text-center space-y-2.5 min-h-[160px]">
                    <div className="w-9 h-9 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                      <Shield className="w-4 h-4 text-emerald-400" />
                    </div>
                    <div>
                      <h4 className="font-bold text-xs text-emerald-400 mb-0.5">
                        No Patch Code Staged
                      </h4>
                      <p className={`text-[10.5px] max-w-sm leading-relaxed ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                        Patch code has not yet been attached to target <b>{resolvedData.targetSoftwareId}</b>. You can synthesize a fix with Graph AI or edit the code directly.
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={handleSynthesizeAiFix}
                        disabled={isSynthesizingAiFix}
                        className="px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold text-xs shadow-md shadow-emerald-900/30 flex items-center gap-1.5 transition-all disabled:opacity-50"
                      >
                        {isSynthesizingAiFix ? (
                          <>
                            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                            <span>Graph AI Reasoning & Synthesizing Fix...</span>
                          </>
                        ) : (
                          <>
                            <Sparkles className="w-3.5 h-3.5 text-amber-200" />
                            <span>Synthesize Fix Code with Graph AI</span>
                          </>
                        )}
                      </button>
                      <button
                        type="button"
                        onClick={() => setIsEditing(true)}
                        className={`px-3 py-1.5 rounded-lg border font-semibold text-xs flex items-center gap-1 transition-all ${
                          isDark ? 'border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700' : 'border-slate-300 bg-white text-slate-800 hover:bg-slate-50'
                        }`}
                      >
                        <Edit3 className="w-3 h-3 text-amber-400" />
                        <span>Add Patch Manually</span>
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    <pre className={`p-3 font-mono text-[11px] overflow-x-auto leading-relaxed bg-transparent ${
                      isDark ? 'text-emerald-200' : 'text-emerald-950 font-medium'
                    }`}>
                      <code>{resolvedData.correctedCode}</code>
                    </pre>
                    {resolvedData.fixExplanation && (
                      <div className={`px-3 py-2 border-t text-[10.5px] flex items-start gap-1.5 ${
                        isDark ? 'border-emerald-900/40 bg-emerald-950/20 text-emerald-300/90' : 'border-emerald-200 bg-emerald-50 text-emerald-900'
                      }`}>
                        <Sparkles className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                        <span><b>AI Remediation:</b> {resolvedData.fixExplanation}</span>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

          </div>

          {/* Expected Error Trace Terminal */}
          <div className="space-y-1">
            <div className={`flex items-center justify-between text-[10px] font-mono uppercase font-bold ${
              isDark ? 'text-slate-400' : 'text-slate-600'
            }`}>
              <span className={`flex items-center gap-1 ${isDark ? 'text-red-400' : 'text-red-700'}`}>
                <Terminal className="w-3 h-3" />
                Observed Error Output / Exploit Stack Trace
              </span>
              <button
                onClick={() => handleCopy(resolvedData.errorMessage, 'error-trace')}
                className={`${isDark ? 'text-cyan-400 hover:text-cyan-300' : 'text-blue-700 hover:text-blue-900'} flex items-center gap-1 normal-case text-[10px] font-medium`}
              >
                {copiedKey === 'error-trace' ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
                <span>{copiedKey === 'error-trace' ? 'Copied' : 'Copy Trace'}</span>
              </button>
            </div>
            <pre className={`p-3 rounded-lg font-mono text-[10.5px] overflow-x-auto leading-relaxed border ${
              isDark ? 'bg-black border-red-900/50 text-red-300' : 'bg-slate-950 border-slate-800 text-red-300 font-medium'
            }`}>
              <code>{resolvedData.errorMessage}</code>
            </pre>
          </div>

          {/* Technical Root Cause & Fix Explanation Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
            <div className={`p-3 rounded-xl border ${
              isDark ? 'bg-red-950/20 border-red-900/40 text-slate-200' : 'bg-red-50 border-red-200 text-slate-900'
            }`}>
              <span className={`font-bold text-[10px] uppercase tracking-wider block mb-1 ${
                isDark ? 'text-red-400' : 'text-red-800 font-bold'
              }`}>
                Technical Root Cause
              </span>
              <p className="text-[11px] leading-relaxed">
                {resolvedData.rootCause}
              </p>
            </div>

            <div className={`p-3 rounded-xl border ${
              isDark ? 'bg-emerald-950/20 border-emerald-900/40 text-slate-200' : 'bg-emerald-50 border-emerald-200 text-slate-900'
            }`}>
              <span className={`font-bold text-[10px] uppercase tracking-wider block mb-1 ${
                isDark ? 'text-emerald-400' : 'text-emerald-800 font-bold'
              }`}>
                Fix & Remediation Explanation
              </span>
              <p className="text-[11px] leading-relaxed">
                {resolvedData.fixExplanation}
              </p>
            </div>
          </div>

        </div>
      )}
    </div>
  );
};
