import React, { useState, useEffect } from 'react';
import { X, Settings, Check, Terminal, Shield, RefreshCw, Layers, Code, FileCode, Play, Plus, Edit3 } from 'lucide-react';
import { ThemeMode, SystemConfigData } from '../types/threatGraph';

interface SystemConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  system: SystemConfigData | null;
  onSaveConfig: (updatedSystem: SystemConfigData) => Promise<void>;
  theme: ThemeMode;
}

export const SystemConfigModal: React.FC<SystemConfigModalProps> = ({
  isOpen,
  onClose,
  system,
  onSaveConfig,
  theme
}) => {
  const isDark = theme === 'dark';
  const [formData, setFormData] = useState<SystemConfigData | null>(null);
  const [activeTab, setActiveTab] = useState<'specs' | 'code'>('specs');
  const [isApplying, setIsApplying] = useState(false);
  const [applyStep, setApplyStep] = useState<'idle' | 'validating' | 'applying' | 'completed'>('idle');

  // Code state for this system
  const storageKey = formData ? `secops_system_code_${formData.name || formData.id}` : '';
  const [codeFileName, setCodeFileName] = useState('');
  const [codeLanguage, setCodeLanguage] = useState('typescript');
  const [codeContent, setCodeContent] = useState('');

  useEffect(() => {
    if (system) {
      setFormData({ ...system });
      setApplyStep('idle');
      setActiveTab('specs');

      const saved = localStorage.getItem(`secops_system_code_${system.name || system.id}`);
      if (saved) {
        try {
          const parsed = JSON.parse(saved);
          if (Array.isArray(parsed) && parsed.length > 0) {
            setCodeFileName(parsed[0].name);
            setCodeLanguage(parsed[0].language);
            setCodeContent(parsed[0].content);
            return;
          }
        } catch (e) {
          // fallback
        }
      }

      // Default template
      setCodeFileName(`/var/www/${system.name.toLowerCase().replace(/[^a-z0-9]/g, '_')}/server.ts`);
      setCodeLanguage('typescript');
      setCodeContent(`import express, { Request, Response } from 'express';\n\nconst app = express();\nconst PORT = ${system.port || 8080};\n\n// System Daemon for ${system.name}\napp.use(express.json());\n\napp.get('/health', (req: Request, res: Response) => {\n  res.json({ node: '${system.name}', status: 'HEALTHY', timestamp: new Date().toISOString() });\n});\n\napp.listen(PORT, '0.0.0.0', () => {\n  console.log(\`[DAEMON] ${system.name} listening on port \${PORT}\`);\n});\n`);
    }
  }, [system]);

  if (!isOpen || !formData) return null;

  const handleChange = (field: keyof SystemConfigData, value: any) => {
    setFormData(prev => prev ? ({ ...prev, [field]: value }) : null);
  };

  const handleApply = async () => {
    if (!formData) return;
    setIsApplying(true);
    setApplyStep('validating');

    // Save custom code file to localStorage
    if (storageKey) {
      const codeRecord = [{
        id: 'primary-service',
        name: codeFileName,
        language: codeLanguage,
        content: codeContent,
        explanation: `Custom microservice daemon deployed on ${formData.name}`,
        isCustom: true
      }];
      localStorage.setItem(storageKey, JSON.stringify(codeRecord));
    }

    setTimeout(async () => {
      setApplyStep('applying');
      await onSaveConfig(formData);

      setTimeout(() => {
        setApplyStep('completed');
        setIsApplying(false);
        setTimeout(() => {
          onClose();
        }, 1200);
      }, 700);
    }, 600);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div 
        className={`w-full max-w-3xl rounded-2xl border shadow-2xl flex flex-col overflow-hidden transition-all duration-300 ${
          isDark 
            ? 'bg-[#0b111b] border-blue-900/60 text-neutral-200' 
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
              <Settings className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold tracking-wide flex items-center gap-2">
                System Configuration Details
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold uppercase ${
                  formData.status === 'HEALTHY'
                    ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    : formData.status === 'COMPROMISED'
                    ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                    : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                }`}>
                  {formData.status}
                </span>
              </h2>
              <p className={`text-xs ${isDark ? 'text-neutral-400' : 'text-slate-500'}`}>
                {formData.name} &bull; {formData.id}
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

        {/* Tab Switcher */}
        <div className={`px-6 py-2 border-b flex items-center gap-2 ${
          isDark ? 'bg-slate-950/60 border-neutral-800' : 'bg-slate-50 border-slate-200'
        }`}>
          <button
            type="button"
            onClick={() => setActiveTab('specs')}
            className={`px-3 py-1.5 rounded-lg text-xs font-sans font-medium flex items-center gap-1.5 transition-all ${
              activeTab === 'specs'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Settings className="w-3.5 h-3.5" />
            <span>Parameters & Hardware Specs</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('code')}
            className={`px-3 py-1.5 rounded-lg text-xs font-sans font-medium flex items-center gap-1.5 transition-all ${
              activeTab === 'code'
                ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-cyan-300'
            }`}
          >
            <Code className="w-3.5 h-3.5" />
            <span>Source Code & Startup Scripts</span>
          </button>
        </div>

        {/* Process Animation Banner when applying */}
        {applyStep !== 'idle' && (
          <div className={`px-6 py-2.5 border-b flex items-center justify-between text-xs font-mono ${
            applyStep === 'completed'
              ? 'bg-emerald-950/40 border-emerald-800/50 text-emerald-300'
              : 'bg-blue-950/40 border-blue-800/50 text-blue-300'
          }`}>
            <div className="flex items-center gap-2">
              {applyStep === 'completed' ? (
                <Check className="w-4 h-4 text-emerald-400" />
              ) : (
                <RefreshCw className="w-4 h-4 text-blue-400 animate-spin" />
              )}
              <span className="font-bold uppercase tracking-wider">
                {applyStep === 'validating' && 'Stage 1/2: Validating configuration schema & ports...'}
                {applyStep === 'applying' && 'Stage 2/2: Applying live configuration & restarting service daemon...'}
                {applyStep === 'completed' && 'Configuration Applied Successfully!'}
              </span>
            </div>
            <div className="text-[10px] opacity-80">
              {applyStep === 'completed' ? 'Status: 100%' : 'In Progress...'}
            </div>
          </div>
        )}

        {/* Form Body */}
        <div className="p-6 overflow-y-auto space-y-4 text-xs max-h-[70vh]">
          
          {activeTab === 'specs' ? (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] font-bold uppercase tracking-wider text-neutral-500 mb-1">
                System Identifier / Name
              </label>
              <input
                type="text"
                value={formData.name}
                onChange={e => handleChange('name', e.target.value)}
                className={`w-full p-2.5 rounded-lg border font-medium ${
                  isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-100' : 'bg-slate-50 border-slate-300 text-slate-900'
                }`}
              />
            </div>

            <div>
              <label className="block text-[11px] font-bold uppercase tracking-wider text-neutral-500 mb-1">
                Operational Purpose
              </label>
              <input
                type="text"
                value={formData.purpose}
                onChange={e => handleChange('purpose', e.target.value)}
                className={`w-full p-2.5 rounded-lg border font-medium ${
                  isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-100' : 'bg-slate-50 border-slate-300 text-slate-900'
                }`}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-[11px] font-bold uppercase tracking-wider text-neutral-500 mb-1">
                Software Version
              </label>
              <input
                type="text"
                value={formData.version}
                onChange={e => handleChange('version', e.target.value)}
                className={`w-full p-2.5 rounded-lg border font-mono ${
                  isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-100' : 'bg-slate-50 border-slate-300 text-slate-900'
                }`}
              />
            </div>

            <div>
              <label className="block text-[11px] font-bold uppercase tracking-wider text-neutral-500 mb-1">
                TCP/UDP Listening Port
              </label>
              <input
                type="number"
                value={formData.port}
                onChange={e => handleChange('port', Number(e.target.value))}
                className={`w-full p-2.5 rounded-lg border font-mono ${
                  isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-100' : 'bg-slate-50 border-slate-300 text-slate-900'
                }`}
              />
            </div>

            <div>
              <label className="block text-[11px] font-bold uppercase tracking-wider text-neutral-500 mb-1">
                Assigned IP Address
              </label>
              <input
                type="text"
                value={formData.ip}
                onChange={e => handleChange('ip', e.target.value)}
                className={`w-full p-2.5 rounded-lg border font-mono ${
                  isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-100' : 'bg-slate-50 border-slate-300 text-slate-900'
                }`}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] font-bold uppercase tracking-wider text-neutral-500 mb-1">
                Operating System & Kernel
              </label>
              <input
                type="text"
                value={formData.os}
                onChange={e => handleChange('os', e.target.value)}
                className={`w-full p-2.5 rounded-lg border font-medium ${
                  isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-100' : 'bg-slate-50 border-slate-300 text-slate-900'
                }`}
              />
            </div>

            <div>
              <label className="block text-[11px] font-bold uppercase tracking-wider text-neutral-500 mb-1">
                systemd / Daemon Service
              </label>
              <input
                type="text"
                value={formData.service}
                onChange={e => handleChange('service', e.target.value)}
                className={`w-full p-2.5 rounded-lg border font-mono ${
                  isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-100' : 'bg-slate-50 border-slate-300 text-slate-900'
                }`}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] font-bold uppercase tracking-wider text-neutral-500 mb-1">
                Primary Config File
              </label>
              <input
                type="text"
                value={formData.configFile}
                onChange={e => handleChange('configFile', e.target.value)}
                className={`w-full p-2.5 rounded-lg border font-mono ${
                  isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-100' : 'bg-slate-50 border-slate-300 text-slate-900'
                }`}
              />
            </div>

            <div>
              <label className="block text-[11px] font-bold uppercase tracking-wider text-neutral-500 mb-1">
                Configuration File Path
              </label>
              <input
                type="text"
                value={formData.configPath}
                onChange={e => handleChange('configPath', e.target.value)}
                className={`w-full p-2.5 rounded-lg border font-mono ${
                  isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-100' : 'bg-slate-50 border-slate-300 text-slate-900'
                }`}
              />
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-bold uppercase tracking-wider text-neutral-500 mb-1">
              Available Operational & Diagnostic Tools
            </label>
            <input
              type="text"
              value={formData.availableTools}
              onChange={e => handleChange('availableTools', e.target.value)}
              placeholder="e.g. systemctl, tcpdump, netstat, curl"
              className={`w-full p-2.5 rounded-lg border font-mono ${
                isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-100' : 'bg-slate-50 border-slate-300 text-slate-900'
              }`}
            />
          </div>

          <div>
            <label className="block text-[11px] font-bold uppercase tracking-wider text-neutral-500 mb-1">
              Linked System Dependencies & Shared Libraries
            </label>
            <input
              type="text"
              value={formData.dependencies}
              onChange={e => handleChange('dependencies', e.target.value)}
              placeholder="e.g. openssl 3.0, glibc 2.35, libapr1"
              className={`w-full p-2.5 rounded-lg border font-mono ${
                isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-100' : 'bg-slate-50 border-slate-300 text-slate-900'
              }`}
            />
          </div>

          {/* Quick Environment Variables Preview */}
          <div className={`p-3 rounded-xl border ${isDark ? 'bg-neutral-950 border-neutral-800' : 'bg-slate-50 border-slate-300'}`}>
            <div className={`text-[10px] font-bold uppercase mb-2 flex items-center gap-1.5 ${
              isDark ? 'text-neutral-400' : 'text-slate-600'
            }`}>
              <Terminal className="w-3.5 h-3.5 text-blue-500" /> Active Service Environment Variables
            </div>
            <div className="grid grid-cols-2 gap-2 font-mono text-[10px]">
              <div className={`p-1.5 rounded border ${
                isDark ? 'bg-black/60 border-neutral-800 text-blue-300' : 'bg-white border-blue-200 text-blue-900 font-semibold'
              }`}>
                NODE_ENV=production
              </div>
              <div className={`p-1.5 rounded border ${
                isDark ? 'bg-black/60 border-neutral-800 text-emerald-300' : 'bg-white border-emerald-200 text-emerald-900 font-semibold'
              }`}>
                PORT={formData.port}
              </div>
              <div className={`p-1.5 rounded border ${
                isDark ? 'bg-black/60 border-neutral-800 text-purple-300' : 'bg-white border-purple-200 text-purple-900 font-semibold'
              }`}>
                LISTEN_IP={formData.ip}
              </div>
              <div className={`p-1.5 rounded border ${
                isDark ? 'bg-black/60 border-neutral-800 text-amber-300' : 'bg-white border-amber-200 text-amber-900 font-semibold'
              }`}>
                CONFIG_PATH={formData.configPath}
              </div>
            </div>
          </div>
          </>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center justify-between flex-wrap gap-2 pb-2 border-b border-slate-800/80">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-cyan-400" />
                <span className="font-bold text-slate-200">System Daemon & Startup Scripts ({formData.name})</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-[10.5px] text-slate-400">Load Template:</span>
                <select
                  onChange={(e) => {
                    const val = e.target.value;
                    if (val === 'express') {
                      setCodeFileName(`/var/www/${formData.name.toLowerCase().replace(/[^a-z0-9]/g, '_')}/server.ts`);
                      setCodeLanguage('typescript');
                      setCodeContent(`import express, { Request, Response } from 'express';\nimport helmet from 'helmet';\n\nconst app = express();\nconst PORT = ${formData.port || 8080};\n\napp.use(helmet());\napp.use(express.json());\n\n// Primary service daemon for ${formData.name}\napp.get('/health', (req: Request, res: Response) => {\n  res.json({ node: '${formData.name}', status: 'HEALTHY', timestamp: new Date().toISOString() });\n});\n\napp.listen(PORT, '0.0.0.0', () => {\n  console.log(\`[DAEMON] ${formData.name} listening on port \${PORT}\`);\n});\n`);
                    } else if (val === 'fastapi') {
                      setCodeFileName(`/opt/services/${formData.name.toLowerCase().replace(/[^a-z0-9]/g, '_')}/main.py`);
                      setCodeLanguage('python');
                      setCodeContent(`from fastapi import FastAPI\nimport uvicorn\n\napp = FastAPI(title="${formData.name} Daemon")\n\n@app.get("/status")\ndef get_status():\n    return {"system": "${formData.name}", "state": "OPERATIONAL", "port": ${formData.port || 8080}}\n\nif __name__ == '__main__':\n    uvicorn.run(app, host="0.0.0.0", port=${formData.port || 8080})\n`);
                    } else if (val === 'bash') {
                      setCodeFileName(`/etc/init.d/${formData.name.toLowerCase().replace(/[^a-z0-9]/g, '_')}_startup.sh`);
                      setCodeLanguage('bash');
                      setCodeContent(`#!/usr/bin/env bash\nset -euo pipefail\necho "[BOOT] Starting ${formData.name} on port ${formData.port}..."\nsystemctl restart ${formData.serviceDaemon || 'daemon'}\n`);
                    }
                    e.target.value = '';
                  }}
                  className={`text-[11px] px-2 py-1 rounded-md border outline-none ${
                    isDark ? 'bg-slate-900 border-slate-800 text-slate-200' : 'bg-white border-slate-300 text-slate-800'
                  }`}
                >
                  <option value="">Select standard template...</option>
                  <option value="express">Node.js Express Server</option>
                  <option value="fastapi">Python FastAPI Microservice</option>
                  <option value="bash">Linux Startup Script</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="sm:col-span-2">
                <label className="block text-[11px] font-bold uppercase tracking-wider text-neutral-500 mb-1">
                  File Path on Computer Node
                </label>
                <input
                  type="text"
                  value={codeFileName}
                  onChange={e => setCodeFileName(e.target.value)}
                  placeholder="/var/www/app/server.ts"
                  className={`w-full p-2.5 rounded-lg border font-mono text-xs ${
                    isDark ? 'bg-neutral-900 border-neutral-700 text-cyan-300' : 'bg-slate-50 border-slate-300 text-slate-900'
                  }`}
                />
              </div>
              <div>
                <label className="block text-[11px] font-bold uppercase tracking-wider text-neutral-500 mb-1">
                  Language / Syntax
                </label>
                <select
                  value={codeLanguage}
                  onChange={e => setCodeLanguage(e.target.value)}
                  className={`w-full p-2.5 rounded-lg border font-mono text-xs ${
                    isDark ? 'bg-neutral-900 border-neutral-700 text-neutral-100' : 'bg-slate-50 border-slate-300 text-slate-900'
                  }`}
                >
                  <option value="typescript">TypeScript</option>
                  <option value="javascript">JavaScript</option>
                  <option value="python">Python</option>
                  <option value="go">Go (Golang)</option>
                  <option value="bash">Bash / Shell</option>
                  <option value="nginx">Nginx Config</option>
                  <option value="yaml">YAML</option>
                </select>
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-[11px] font-bold uppercase tracking-wider text-neutral-500">
                  Source Code Content:
                </label>
                <span className="font-mono text-[10px] text-slate-400">
                  {codeContent.split('\n').length} lines
                </span>
              </div>
              <textarea
                value={codeContent}
                onChange={e => setCodeContent(e.target.value)}
                rows={14}
                spellCheck={false}
                className={`w-full p-3 rounded-lg border font-mono text-xs leading-relaxed outline-none resize-y ${
                  isDark 
                    ? 'bg-[#050811] border-slate-800 text-emerald-300 focus:border-cyan-500' 
                    : 'bg-white border-slate-300 text-slate-900 font-medium'
                }`}
                placeholder="// Paste or write your service code here..."
              />
            </div>

            <div className={`p-3 rounded-lg border text-xs font-sans flex items-start gap-2 ${
              isDark ? 'bg-cyan-950/20 border-cyan-800/40 text-cyan-300' : 'bg-blue-50 border-blue-200 text-blue-900'
            }`}>
              <Terminal className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold">Hot Code Deployment:</span> Clicking &ldquo;Apply Configuration&rdquo; below will compile, attach, and deploy this code directly into the computer node&rsquo;s runtime environment and store it permanently.
              </div>
            </div>
          </div>
        )}

        </div>

        {/* Footer */}
        <div 
          className={`px-6 py-4 border-t flex items-center justify-between ${
            isDark ? 'bg-black/60 border-neutral-800' : 'bg-slate-100 border-slate-200'
          }`}
        >
          <div className="text-[11px] text-neutral-500 flex items-center gap-1.5">
            <Shield className="w-4 h-4 text-blue-500" />
            <span>Changes persist to Graph State & Runtime Service Specs</span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              disabled={isApplying}
              className={`px-4 py-2 rounded-lg font-bold text-xs tracking-wider transition-colors ${
                isDark ? 'hover:bg-neutral-800 text-neutral-400' : 'hover:bg-slate-200 text-slate-600'
              }`}
            >
              Cancel
            </button>
            <button
              onClick={handleApply}
              disabled={isApplying}
              className="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-lg text-xs tracking-wider uppercase transition-all shadow-md flex items-center gap-2 disabled:opacity-50"
            >
              {isApplying ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Applying Configuration...
                </>
              ) : (
                <>
                  <Check className="w-4 h-4" />
                  Apply Configuration
                </>
              )}
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
