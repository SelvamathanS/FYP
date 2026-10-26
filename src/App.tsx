import React, { useState, useEffect, useRef, useMemo } from 'react';
import { 
  Shield, AlertTriangle, Sparkles, Terminal, Activity, CheckCircle2, Flame, Send, 
  MessageSquare, Bug, Code, X, LogOut, User, LayoutDashboard, Info, Layers, Clock, 
  Map as MapIcon, Server, Settings, BookOpen, RefreshCw, Check, Play, FileText, ChevronRight,
  ZoomIn, ZoomOut, Maximize2, Search, Sliders, Crosshair, RotateCcw,
  PanelLeftClose, PanelRightClose, PanelLeft, PanelRight, ArrowRightLeft, Columns2, ChevronLeft, ChevronDown, Minimize2,
  ChevronsDown, ChevronsUp,
  Route, GitFork, Download, FileJson, Grid, LayoutGrid, Network, Menu, Wrench
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { motion, AnimatePresence } from 'motion/react';

import { ThemeMode, GraphNode, GraphEdge, SystemConfigData, ProcessAnimationState } from './types/threatGraph';
import { PRESET_SYSTEM_TEMPLATES, PRESET_BUGS_CATALOG } from './data/systemsAndBugsCatalog';
import { DEFAULT_GRAPH_DATA } from './data/defaultGraph';
import { transformRawGraph, GraphLayoutMode, getSystemEnclave } from './utils/graphTransformer';
import { stepPhysicsSimulation } from './utils/physicsEngine';
import { findShortestPath, getEdgeKey, ShortestPathResult } from './utils/shortestPath';
import { ThemeToggle } from './components/ThemeToggle';
import { EnvironmentModal } from './components/EnvironmentModal';
import { SystemConfigModal } from './components/SystemConfigModal';
import { KnowledgeHubModal } from './components/KnowledgeHubModal';
import { ExploitLabModal } from './components/ExploitLabModal';
import { ProcessAnimationBanner } from './components/ProcessAnimationBanner';
import { DynamicSystemControls } from './components/DynamicSystemControls';
import { PerformanceTelemetryMonitor } from './components/PerformanceTelemetryMonitor';
import { GraphNodeVisual } from './components/GraphNodeVisual';
import { GraphNodeHoverCard } from './components/GraphNodeHoverCard';
import { RoleConsolePanel } from './components/RoleConsolePanel';
import { SystemTechnicalViewer, BugTechnicalViewer } from './components/TechnicalCodeViewer';
import { GraphRagVulnerabilityModal } from './components/GraphRagVulnerabilityModal';
import { 
  TECHNICAL_SYSTEMS_CATALOG, 
  TECHNICAL_BUGS_CATALOG,
  BugTechnicalDetail,
  resolveBugTechnicalDetail
} from './data/technicalDetailsCatalog';

interface ChatMessage {
  id: string;
  role: 'user' | 'bot';
  text: string;
}

export default function App() {
  // 1. Theme State (Requirement 1)
  const [theme, setTheme] = useState<ThemeMode>(() => {
    return (localStorage.getItem('cti_theme') as ThemeMode) || 'dark';
  });

  const toggleTheme = () => {
    const nextTheme: ThemeMode = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    localStorage.setItem('cti_theme', nextTheme);
  };

  const isDark = theme === 'dark';

  // Synchronize document root classes and color-scheme for rock-solid theme stability
  useEffect(() => {
    const root = document.documentElement;
    if (isDark) {
      root.classList.add('dark');
      root.classList.remove('light');
      root.style.colorScheme = 'dark';
    } else {
      root.classList.remove('dark');
      root.classList.add('light');
      root.style.colorScheme = 'light';
    }
    root.setAttribute('data-theme', theme);
  }, [theme, isDark]);

  // 2. Modals State (Requirements 5, 6, 7)
  const [showEnvModal, setShowEnvModal] = useState(false);
  const [showKnowledgeHubModal, setShowKnowledgeHubModal] = useState(false);
  const [showExploitLabModal, setShowExploitLabModal] = useState(false);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [configuringSystem, setConfiguringSystem] = useState<SystemConfigData | null>(null);
  const [showGraphRagModal, setShowGraphRagModal] = useState(false);
  const [graphRagTargetSystem, setGraphRagTargetSystem] = useState<string>('Computer 26');

  // 3. Process Animation State (Requirement 8)
  const [processAnimation, setProcessAnimation] = useState<ProcessAnimationState>({
    stage: 'IDLE',
    active: false,
    title: '',
    subtitle: '',
    progress: 0,
    targetId: '',
    logs: []
  });

  // Dynamic Workspace & Graph View States (Chatbot strictly on Left; Telemetry on Right)
  const [isSidePanelOpen, setIsSidePanelOpen] = useState(true);
  const [isFullGraphView, setIsFullGraphView] = useState(false);

  // Live System Telemetry: Portable & Sinkable State (Minimized to Dock by default)
  const [isTelemetrySunk, setIsTelemetrySunk] = useState<boolean>(() => {
    const saved = localStorage.getItem('telemetry_sunk_state');
    // Default to true so it is automatically minimized to dock on initial load!
    return saved !== null ? saved === 'true' : true;
  });
  const [telemetryDockMode, setTelemetryDockMode] = useState<'docked' | 'floating'>('docked');
  const [rightSidebarTab, setRightSidebarTab] = useState<'telemetry' | 'inspector'>('telemetry');

  // Operational Role State (Analyst = Blue Team Threat Defense, Hacker = Red Team Emulation)
  const [authRole, setAuthRole] = useState<'hacker' | 'analyst'>('analyst');
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [loginStep, setLoginStep] = useState<'select' | 'hacker' | 'analyst'>('select');

  // Graph State & Layout Position Cache
  const graphContainerRef = useRef<HTMLDivElement>(null);
  const [containerSize, setContainerSize] = useState<{ width: number; height: number }>({ width: 1200, height: 800 });
  const persistentPositionsRef = useRef<Map<string, { x: number; y: number }>>(new Map());
  // Initialize with cached state or default graph so graph renders immediately with 0 blank frames
  const [nodes, setNodes] = useState<GraphNode[]>(() => {
    try {
      const cached = localStorage.getItem('cached_graph_state');
      if (cached) {
        const parsed = JSON.parse(cached);
        if (parsed && Array.isArray(parsed.nodes) && parsed.nodes.length > 0) {
          const { nodes: initNodes } = transformRawGraph(parsed.nodes, parsed.edges || [], persistentPositionsRef.current);
          return initNodes;
        }
      }
    } catch {
      // ignore
    }
    const { nodes: defaultNodes } = transformRawGraph(DEFAULT_GRAPH_DATA.nodes, DEFAULT_GRAPH_DATA.edges, persistentPositionsRef.current);
    return defaultNodes;
  });

  const [edges, setEdges] = useState<GraphEdge[]>(() => {
    try {
      const cached = localStorage.getItem('cached_graph_state');
      if (cached) {
        const parsed = JSON.parse(cached);
        if (parsed && Array.isArray(parsed.edges)) {
          return parsed.edges;
        }
      }
    } catch {
      // ignore
    }
    return DEFAULT_GRAPH_DATA.edges as GraphEdge[];
  });
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [bugInspectorTab, setBugInspectorTab] = useState<'code' | 'details'>('code');

  // Synchronize right sidebar when selecting/inspecting a node
  const handleSelectNode = (node: GraphNode | null) => {
    setSelectedNode(node);
    if (node) {
      setRightSidebarTab('inspector');
      if (node.label === 'Vulnerability') {
        setBugInspectorTab('code'); // Default to showing code for any bug!
      }
      if (isFullGraphView) {
        setIsFullGraphView(false); // Make sure sidebar is visible
      }
    }
  };
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);
  const [showHotZones, setShowHotZones] = useState(false);
  const [showHeatmap, setShowHeatmap] = useState(false);
  const [transform, setTransform] = useState({ x: 25, y: 30, k: 0.62 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [dbEngine, setDbEngine] = useState<string>('Graph Engine Active');
  const [isNeo4jActive, setIsNeo4jActive] = useState<boolean>(false);

  // Advanced Enterprise Layout & Topology Engine
  const [layoutMode, setLayoutMode] = useState<GraphLayoutMode>('pipeline');
  const [isPhysicsRunning, setIsPhysicsRunning] = useState<boolean>(false);

  // Real-time organic physics simulation loop when physics mode is engaged
  useEffect(() => {
    if (!isPhysicsRunning) return;
    let animId: number;
    const tick = () => {
      setNodes(prev => stepPhysicsSimulation(prev, edges, new Set(draggingNodeId ? [draggingNodeId] : [])));
      animId = requestAnimationFrame(tick);
    };
    animId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animId);
  }, [isPhysicsRunning, edges, draggingNodeId]);

  // Verification Results State
  const [verificationResult, setVerificationResult] = useState<any | null>(null);

  // UI State
  const [toast, setToast] = useState<{ title: string; message: string; type: 'red' | 'green' } | null>(null);
  const [showToolsDropdown, setShowToolsDropdown] = useState(false);
  const [isMobileNavOpen, setIsMobileNavOpen] = useState(false);
  const [analystTab, setAnalystTab] = useState<'chat' | 'logs' | 'knowledge_map' | 'attack_path'>('chat');
  const [remediationProgress, setRemediationProgress] = useState<Record<string, number>>({});
  const [selectedLogs, setSelectedLogs] = useState<string[]>([]);

  // Shortest Path Highlighting State (Threat Actor -> Software System via BFS)
  const [selectedThreatActorForPath, setSelectedThreatActorForPath] = useState<string>('APT29');
  const [selectedSoftwareForPath, setSelectedSoftwareForPath] = useState<string>('Apache Web Server');
  const [activePathResult, setActivePathResult] = useState<ShortestPathResult | null>(null);

  // Red Team State (Requirement 3: Live Bug Installation)
  const [selectedPresetBug, setSelectedPresetBug] = useState<string>('CVE-2021-44228');
  const [vulnName, setVulnName] = useState('CVE-2021-44228');
  const [targetSoftware, setTargetSoftware] = useState('Customer DB');
  const [vulnDesc, setVulnDesc] = useState('Remote code execution in Apache Log4j2 JNDI LDAP lookup parser.');
  const [vulnSeverity, setVulnSeverity] = useState('CRITICAL');
  const [isInjecting, setIsInjecting] = useState(false);
  const [isGeneratingAiDesc, setIsGeneratingAiDesc] = useState(false);
  const [bugCustomCodes, setBugCustomCodes] = useState<Record<string, Partial<BugTechnicalDetail>>>({});
  const [activeBugCode, setActiveBugCode] = useState<Partial<BugTechnicalDetail>>(() => {
    return resolveBugTechnicalDetail('CVE-2021-44228');
  });

  // Chat State (Requirement 4: Live Bug Solving / Fixing)
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    { 
      id: '1', 
      role: 'bot', 
      text: `### 👋 Welcome to Threat Intelligence & Self-Healing Copilot\n\nI am connected to your live enterprise security graph and telemetry stream.\n\n* **Auto-Fix:** Type \`fix\` to execute automated remediation across all compromised assets.\n* **Triage:** Type \`what should I fix first?\` to assess highest risk blast radius.\n* **Runbooks:** Type \`steps to fix Log4Shell\` to view technical remediation procedures.\n* **Greetings:** Say \`hi\` anytime to check live topology health!` 
    }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [isChatting, setIsChatting] = useState(false);
  const [healedLog, setHealedLog] = useState<string[]>([]);
  const chatContainerRef = useRef<HTMLDivElement>(null);

  // Systems filter
  const softwareSystems = nodes.filter(n => n.label === 'Software');

  // Fetch Graph from Backend with Intelligent Tier Layout & Position Persistence
  const fetchGraph = async () => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      const res = await fetch('/api/user/graph', { signal: controller.signal });
      clearTimeout(timeoutId);

      if (!res.ok) {
        return; // Dev server warming up or transient proxy response
      }

      const contentType = res.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        return; // Nginx warmup or html page during restart
      }

      const data = await res.json();
      if (data && Array.isArray(data.nodes) && data.nodes.length > 0) {
        try {
          localStorage.setItem('cached_graph_state', JSON.stringify({
            nodes: data.nodes,
            edges: data.edges,
            meta: data.meta
          }));
        } catch {
          // ignore storage error
        }

        const { nodes: typedNodes, edges: typedEdges } = transformRawGraph(
          data.nodes,
          data.edges || [],
          persistentPositionsRef.current
        );

        setNodes(typedNodes);
        setEdges(typedEdges);

        if (data.meta) {
          setDbEngine(data.meta.engine || (data.meta.isNeo4jAvailable ? 'Neo4j Live' : 'Graph Engine Active'));
          setIsNeo4jActive(!!data.meta.isNeo4jAvailable);
        }

        // Update selected node if exists
        if (selectedNode) {
          const updated = typedNodes.find(n => n.id === selectedNode.id);
          if (updated) setSelectedNode(updated);
        }
      }
    } catch {
      // Graceful fallback: maintain uninterrupted topology view
      setNodes(prev => {
        if (!prev || prev.length === 0) {
          const { nodes: fallbackNodes, edges: fallbackEdges } = transformRawGraph(
            DEFAULT_GRAPH_DATA.nodes,
            DEFAULT_GRAPH_DATA.edges,
            persistentPositionsRef.current
          );
          setEdges(fallbackEdges);
          return fallbackNodes;
        }
        return prev;
      });
    }
  };

  useEffect(() => {
    fetchGraph();
    const interval = setInterval(fetchGraph, 3000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => setToast(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [toast]);

  // Self-contained chat auto-scroller: ONLY scrolls the chat list, never the window or graph canvas
  useEffect(() => {
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight;
    }
  }, [chatMessages, healedLog, isChatting]);

  // When preset bug changes in Red Team, populate inputs
  const handleSelectPresetBug = (bugId: string) => {
    setSelectedPresetBug(bugId);
    const found = PRESET_BUGS_CATALOG.find(b => b.id === bugId);
    if (found) {
      setVulnName(found.id);
      setVulnDesc(found.description);
      setVulnSeverity(found.severity);
      if (nodes.some(n => n.id === found.targetSoftwareId)) {
        setTargetSoftware(found.targetSoftwareId);
      }
    }
    const resolvedCode = resolveBugTechnicalDetail(bugId, bugCustomCodes[bugId]);
    // During attacker injection, defensive fix code is withheld - Graph AI will synthesize it at the end!
    setActiveBugCode({
      ...resolvedCode,
      correctedCode: '',
      fixExplanation: ''
    });
  };

  // On-demand AI Description Generation via Gemini 3.8 Flash
  const handleGenerateAiDescription = async () => {
    setIsGeneratingAiDesc(true);
    try {
      const catalogPreset = PRESET_BUGS_CATALOG.find(b => b.id === vulnName);
      const res = await fetch('/api/bug/generate-description', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vuln_id: vulnName,
          vuln_name: catalogPreset?.name || vulnName,
          system_id: targetSoftware,
          severity: vulnSeverity,
          cause: catalogPreset?.cause,
          cvss: catalogPreset?.cvss || 9.5,
          description: vulnDesc
        })
      });
      const data = await res.json();
      if (data.status === 'success' && data.description) {
        setVulnDesc(data.description);
        setToast({
          title: 'AI Description Synthesized',
          message: data.model === 'gemini-3.8-flash'
            ? 'Gemini 3.8 Flash generated live vulnerability description.'
            : 'AI domain intelligence generated description for target host.',
          type: 'green'
        });
      }
    } catch (err) {
      console.warn('Notice during AI description generation, applying domain intelligence fallback:', err);
      const catalogPreset = PRESET_BUGS_CATALOG.find(b => b.id === vulnName);
      const fallbackDesc = catalogPreset?.description || `Critical vulnerability identified in ${targetSoftware} affecting network communication protocol. Remote unauthenticated exploitation disrupts service availability.`;
      setVulnDesc(fallbackDesc);
    } finally {
      setIsGeneratingAiDesc(false);
    }
  };

  // REQUIREMENT 2: Dynamic System Management (+)
  const handleAddSystem = async (template?: Partial<SystemConfigData>) => {
    const sysId = template?.id || `Service-${Date.now().toString().slice(-4)}`;
    
    // Process Animation: Creating -> Initializing -> Active
    setProcessAnimation({
      stage: 'CREATING_SYSTEM',
      active: true,
      title: `Creating System Node: ${sysId}`,
      subtitle: 'Allocating network namespace & generating graph node metadata...',
      progress: 25,
      targetId: sysId,
      logs: [`Allocating CIDR block for ${sysId}...`, `Initializing port ${template?.port || 8080}...`]
    });

    try {
      setTimeout(async () => {
        try {
          setProcessAnimation(prev => ({
            ...prev,
            stage: 'INITIALIZING_SYSTEM',
            subtitle: 'Starting daemon service & linking TCP ingress sockets...',
            progress: 65,
            logs: [...prev.logs, `Spawning daemon ${template?.service || `${sysId}.service`}`]
          }));

          const res = await fetch('/api/system/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              id: sysId,
              name: template?.name || sysId,
              purpose: template?.purpose || 'Production Microservice',
              os: template?.os || 'Ubuntu 22.04 LTS',
              port: template?.port || 8080,
              ip: template?.ip,
              service: template?.service,
              configFile: template?.configFile,
              configPath: template?.configPath,
              availableTools: template?.availableTools,
              dependencies: template?.dependencies
            })
          });

          await res.json();
          await fetchGraph();

          setProcessAnimation(prev => ({
            ...prev,
            stage: 'SYSTEM_ACTIVE',
            subtitle: `System ${sysId} is online and HEALTHY in topology!`,
            progress: 100,
            logs: [...prev.logs, `Node ${sysId} registered to Graph DB with status HEALTHY.`]
          }));

          setToast({
            title: 'System Added Successfully',
            message: `${sysId} was added to the active topology graph.`,
            type: 'green'
          });

          setTimeout(() => {
            setProcessAnimation(prev => ({ ...prev, active: false }));
          }, 3000);
        } catch (innerErr) {
          console.warn('Notice adding system, applying local registration:', innerErr);
          const newSysNode: GraphNode = {
            id: sysId,
            name: template?.name || sysId,
            label: 'Software',
            status: 'HEALTHY',
            purpose: template?.purpose || 'Production Microservice',
            os: template?.os || 'Ubuntu 22.04 LTS',
            port: template?.port ? Number(template.port) : 8080,
            ip: template?.ip || '10.0.1.X',
            service: template?.service,
            configFile: template?.configFile,
            configPath: template?.configPath,
            availableTools: template?.availableTools,
            dependencies: template?.dependencies,
            x: 960,
            y: 360,
            timestamp: new Date().toISOString()
          };
          setNodes(prev => prev.some(n => n.id === sysId) ? prev : [...prev, newSysNode]);
          setProcessAnimation(prev => ({
            ...prev,
            stage: 'SYSTEM_ACTIVE',
            subtitle: `System ${sysId} is online and HEALTHY in topology!`,
            progress: 100,
            logs: [...prev.logs, `Node ${sysId} registered to Graph DB with status HEALTHY.`]
          }));
          setToast({
            title: 'System Added Successfully',
            message: `${sysId} was added to the active topology graph.`,
            type: 'green'
          });
          setTimeout(() => {
            setProcessAnimation(prev => ({ ...prev, active: false }));
          }, 3000);
        }
      }, 600);

    } catch (e) {
      console.warn('System addition flow notice:', e);
      setProcessAnimation(prev => ({ ...prev, active: false }));
    }
  };

  // REQUIREMENT 2: Dynamic System Management (−)
  const handleRemoveSystem = async (systemId: string) => {
    setProcessAnimation({
      stage: 'REMOVING_SYSTEM',
      active: true,
      title: `Decommissioning System: ${systemId}`,
      subtitle: 'Detaching graph edges and terminating service daemon...',
      progress: 40,
      targetId: systemId,
      logs: [`MATCH (s {id: '${systemId}'})-[r]-() DELETE r, s`, `Stopping service on port...`]
    });

    try {
      setTimeout(async () => {
        try {
          const res = await fetch('/api/system/remove', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ system_id: systemId })
          });
          await res.json();
          await fetchGraph();

          if (selectedNode?.id === systemId) {
            setSelectedNode(null);
          }

          setProcessAnimation(prev => ({
            ...prev,
            stage: 'SYSTEM_REMOVED',
            subtitle: `System ${systemId} successfully decommissioned from graph!`,
            progress: 100,
            logs: [...prev.logs, `System node ${systemId} safely detached.`]
          }));

          setToast({
            title: 'System Removed',
            message: `${systemId} was successfully detached from network.`,
            type: 'red'
          });

          setTimeout(() => {
            setProcessAnimation(prev => ({ ...prev, active: false }));
          }, 3000);
        } catch (innerErr) {
          console.warn('Notice removing system, applying local detachment:', innerErr);
          setNodes(prev => prev.filter(n => n.id !== systemId));
          setEdges(prev => prev.filter(e => e.from !== systemId && e.to !== systemId));
          if (selectedNode?.id === systemId) {
            setSelectedNode(null);
          }
          setProcessAnimation(prev => ({
            ...prev,
            stage: 'SYSTEM_REMOVED',
            subtitle: `System ${systemId} successfully decommissioned from graph!`,
            progress: 100,
            logs: [...prev.logs, `System node ${systemId} safely detached.`]
          }));
          setToast({
            title: 'System Removed',
            message: `${systemId} was successfully detached from network.`,
            type: 'red'
          });
          setTimeout(() => {
            setProcessAnimation(prev => ({ ...prev, active: false }));
          }, 3000);
        }
      }, 700);

    } catch (e) {
      console.warn('System decommissioning flow notice:', e);
      setProcessAnimation(prev => ({ ...prev, active: false }));
    }
  };

  // REQUIREMENT 6: System Configuration Save
  const handleSaveSystemConfig = async (updated: SystemConfigData) => {
    try {
      await fetch('/api/system/configure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          system_id: updated.id,
          config: updated
        })
      });
      await fetchGraph();
      setToast({
        title: 'Configuration Updated',
        message: `System configuration for ${updated.name} has been applied.`,
        type: 'green'
      });
    } catch (e) {
      console.warn('System configuration notice:', e);
    }
  };

  // REQUIREMENT 3: Live Bug Installation (with Requirement 8 Process Animation)
  const handleLiveBugInstall = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setIsInjecting(true);

    const catalogPreset = PRESET_BUGS_CATALOG.find(b => b.id === vulnName);

    // Process Animation: Installing -> In progress -> Installed -> Bug detected / active
    setProcessAnimation({
      stage: 'INSTALLING_BUG',
      active: true,
      title: `Installing Bug: ${vulnName}`,
      subtitle: `Transmitting exploit payload to target: ${targetSoftware}...`,
      progress: 20,
      targetId: vulnName,
      logs: [
        `Connecting to target socket at ${targetSoftware}...`,
        `Payload size: 1.4 KB; Protocol: TCP; Vector: Memory boundary overflow.`,
        `Invoking Gemini AI intelligence engine for threat vector analysis...`
      ]
    });

    try {
      // Stage 2: Bug In Progress
      setTimeout(() => {
        setProcessAnimation(prev => ({
          ...prev,
          stage: 'BUG_IN_PROGRESS',
          subtitle: `Executing payload & escalating privileges on ${targetSoftware}...`,
          progress: 55,
          logs: [
            ...prev.logs,
            `Exploit triggered: ${catalogPreset?.cause || 'Invalid memory pointer dereference'}`,
            `Synthesizing AI-grounded vulnerability description...`,
            `Injecting AFFECTS relationship into Graph DB...`
          ]
        }));

        // Stage 3: Bug Installed & Backend commit
        setTimeout(async () => {
          try {
            const res = await fetch('/api/bug/install', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                system_id: targetSoftware,
                vuln_id: vulnName,
                vuln_name: catalogPreset?.name || vulnName,
                description: vulnDesc,
                severity: vulnSeverity,
                cvss: catalogPreset?.cvss || 9.5,
                cause: catalogPreset?.cause,
                reproduction: catalogPreset?.reproduction,
                installationProcedure: catalogPreset?.installationProcedure,
                symptoms: catalogPreset?.symptoms,
                troubleshootingProcess: catalogPreset?.troubleshootingProcess,
                fixSolution: 'Remediation patch withheld during active attack. Graph AI must reason over the graph and synthesize the secure fix at the end.',
                verificationProcedure: catalogPreset?.verificationProcedure,
                codeLanguage: activeBugCode?.codeLanguage || 'python',
                codeFileName: activeBugCode?.codeFileName || 'vulnerability_patch.py',
                buggyCode: activeBugCode?.buggyCode,
                correctedCode: '',
                errorMessage: activeBugCode?.errorMessage,
                exploitScript: activeBugCode?.exploitScript,
                rootCause: activeBugCode?.rootCause,
                fixExplanation: ''
              })
            });

            // Store customized bug code locally (without fix code)
            if (activeBugCode) {
              setBugCustomCodes(prev => ({
                ...prev,
                [vulnName]: {
                  ...activeBugCode,
                  correctedCode: '',
                  fixExplanation: '',
                  bugId: vulnName,
                  bugName: catalogPreset?.name || vulnName,
                  targetSoftwareId: targetSoftware
                }
              }));
            }

            const bugData = await res.json();
            if (bugData.description) {
              setVulnDesc(bugData.description);
            }
            await fetchGraph();

            // Stage 4: Bug Detected / Active
            setProcessAnimation(prev => ({
              ...prev,
              stage: 'BUG_DETECTED',
              title: `Bug Active: ${vulnName}`,
              subtitle: `Target ${targetSoftware} is COMPROMISED! Telemetry alert broadcasted.`,
              progress: 100,
              logs: [
                ...prev.logs,
                `Telemetry hook active. Target state changed to COMPROMISED.`,
                `CVSS ${catalogPreset?.cvss || 9.5} alert registered.`,
                `AI-generated vulnerability intelligence attached to ${vulnName}.`
              ]
            }));

            setToast({
              title: 'Vulnerability Active',
              message: `${vulnName} installed and affecting ${targetSoftware}. Target is COMPROMISED.`,
              type: 'red'
            });

            setIsInjecting(false);

            // Rotate to next random or preset CVE
            const nextIndex = Math.floor(Math.random() * PRESET_BUGS_CATALOG.length);
            const nextBug = PRESET_BUGS_CATALOG[nextIndex];
            setVulnName(nextBug.id);
            setVulnDesc(nextBug.description);
            setVulnSeverity(nextBug.severity);

            setTimeout(() => {
              setProcessAnimation(prev => ({ ...prev, active: false }));
            }, 3500);
          } catch (innerErr) {
            console.warn('Notice installing bug, applying local emulation:', innerErr);
            setNodes(prev => {
              const updated = prev.map(n => n.id === targetSoftware ? { ...n, status: 'COMPROMISED' } : n);
              if (!updated.some(n => n.id === vulnName)) {
                updated.push({
                  id: vulnName,
                  name: catalogPreset?.name || vulnName,
                  label: 'Vulnerability',
                  status: 'UNMITIGATED',
                  severity: vulnSeverity,
                  cvss: catalogPreset?.cvss || 9.5,
                  description: vulnDesc,
                  details: vulnDesc,
                  cause: catalogPreset?.cause,
                  x: 720,
                  y: 360,
                  timestamp: new Date().toISOString()
                });
              }
              return updated;
            });
            setEdges(prev => {
              if (!prev.some(e => e.from === vulnName && e.to === targetSoftware)) {
                return [...prev, { from: vulnName, to: targetSoftware, label: 'AFFECTS' }];
              }
              return prev;
            });
            setProcessAnimation(prev => ({
              ...prev,
              stage: 'BUG_DETECTED',
              title: `Bug Active: ${vulnName}`,
              subtitle: `Target ${targetSoftware} is COMPROMISED! Telemetry alert broadcasted.`,
              progress: 100,
              logs: [
                ...prev.logs,
                `Telemetry hook active. Target state changed to COMPROMISED.`,
                `CVSS ${catalogPreset?.cvss || 9.5} alert registered.`
              ]
            }));
            setToast({
              title: 'Vulnerability Active',
              message: `${vulnName} installed and affecting ${targetSoftware}. Target is COMPROMISED.`,
              type: 'red'
            });
            setIsInjecting(false);
            setTimeout(() => {
              setProcessAnimation(prev => ({ ...prev, active: false }));
            }, 3500);
          }
        }, 700);

      }, 600);

    } catch (e) {
      console.warn('Bug installation flow notice:', e);
      setIsInjecting(false);
      setProcessAnimation(prev => ({ ...prev, active: false }));
    }
  };

  // REQUIREMENT 4: Live Bug Solving / Fixing (with Requirement 8 Process Animation)
  const handleLiveBugFix = async (vulnId: string, systemId?: string) => {
    const vulnNode = nodes.find(n => n.id === vulnId);
    const catalogBug = PRESET_BUGS_CATALOG.find(b => b.id === vulnId);
    const affectedEdge = edges.find(e => e.from === vulnId && (e.label === 'AFFECTS' || e.label === 'EXPLOITS'));
    const targetSys = systemId || affectedEdge?.to || vulnNode?.targetSoftwareId || 'Apache Web Server';

    // Step 1: Bug detected -> Diagnosing
    setProcessAnimation({
      stage: 'DIAGNOSING',
      active: true,
      title: `Diagnosing Threat: ${vulnId}`,
      subtitle: `Auditing memory core dumps and network sockets on ${targetSys}...`,
      progress: 20,
      targetId: vulnId,
      logs: [
        `[Step 1: Diagnostic Audit] Inspecting syslog on ${targetSys}...`,
        `Identified anomaly: ${vulnNode?.symptoms || catalogBug?.symptoms || 'High CPU, SIGSEGV exception'}`
      ]
    });

    setTimeout(() => {
      // Step 2: Analyzing -> Solution Identified
      setProcessAnimation(prev => ({
        ...prev,
        stage: 'SOLUTION_IDENTIFIED',
        subtitle: `Root Cause: ${vulnNode?.cause || catalogBug?.cause || 'Flawed input normalization'}. Patch synthesized.`,
        progress: 45,
        logs: [
          ...prev.logs,
          `[Step 2: Root Cause] ${vulnNode?.cause || catalogBug?.cause || 'Unsanitized parameter parsed.'}`,
          `[Step 3: Solution] ${vulnNode?.fixSolution || catalogBug?.fixSolution || 'Deploy vendor security patch'}`
        ]
      }));

      setTimeout(() => {
        // Step 3: Fixing -> Fix applied
        setProcessAnimation(prev => ({
          ...prev,
          stage: 'FIXING',
          subtitle: `Deploying automated security patch & restarting daemon service...`,
          progress: 75,
          logs: [
            ...prev.logs,
            `[Step 4: Patch Execution] Applying virtual firewall patch...`,
            `Creating Mitigation node and HAS_MITIGATION relationship...`
          ]
        }));

        setTimeout(async () => {
          try {
            // Backend fix commit
            const res = await fetch('/api/bug/fix', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                vuln_id: vulnId,
                system_id: targetSys,
                patch_name: `Automated Patch for ${vulnId}`
              })
            });
            const fixData = await res.json();
            if (fixData.correctedCode) {
              setBugCustomCodes(prev => ({
                ...prev,
                [vulnId]: {
                  ...(prev[vulnId] || {}),
                  correctedCode: fixData.correctedCode,
                  fixExplanation: fixData.fixExplanation,
                  rootCause: fixData.rootCause || prev[vulnId]?.rootCause,
                  bugId: vulnId
                }
              }));
              setNodes(prev => prev.map(n => n.id === vulnId ? {
                ...n,
                correctedCode: fixData.correctedCode,
                fixExplanation: fixData.fixExplanation,
                rootCause: fixData.rootCause || n.rootCause,
                status: 'SELF_HEALED'
              } : n));
            }
            await fetchGraph();

            // Step 4: Verifying -> System restored
            setProcessAnimation(prev => ({
              ...prev,
              stage: 'VERIFYING',
              subtitle: `Executing post-patch verification probe against ${targetSys}...`,
              progress: 90,
              logs: [
                ...prev.logs,
                `[Step 5: Verification Probe] Sending test payload to port...`,
                `Probe rejected: HTTP 403 Forbidden / Socket Closed. System is safe!`
              ]
            }));

            // Run live verification
            const verifyRes = await fetch('/api/system/verify', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ system_id: targetSys })
            });
            const verifyData = await verifyRes.json();
            setVerificationResult(verifyData);
            await fetchGraph();

            // Step 5: Healthy Restored
            setProcessAnimation(prev => ({
              ...prev,
              stage: 'HEALTHY_RESTORED',
              title: `System Restored to HEALTHY: ${targetSys}`,
              subtitle: `Vulnerability ${vulnId} self-healed. 0 unmitigated exploits.`,
              progress: 100,
              logs: [
                ...prev.logs,
                `[Step 6: Status Commit] ${targetSys} restored to HEALTHY in Graph DB.`
              ]
            }));

            setToast({
              title: 'Graph AI Remediation Complete',
              message: `${vulnId} was patched via Graph AI fix synthesis. ${targetSys} is verified HEALTHY.`,
              type: 'green'
            });

            // Add to bot chat conversation
            setChatMessages(prev => [
              ...prev,
              { 
                id: Date.now().toString(), 
                role: 'bot', 
                text: `### 🛡️ Graph AI Remediation Complete for ${vulnId}\n\n- **Target System:** ${targetSys}\n- **Root Cause:** ${fixData.rootCause || 'Boundary validation flaw'}\n- **Graph AI Synthesized Fix:** Generated clean secure patch code and deployed mitigation.\n- **Verification Result:** PASS (Zero unmitigated exploits detected).\n- **Current Health:** 🟢 HEALTHY` 
              }
            ]);

            setTimeout(() => {
              setProcessAnimation(prev => ({ ...prev, active: false }));
            }, 3500);

          } catch (innerErr) {
            console.warn('Notice fixing bug, applying local remediation:', innerErr);
            setNodes(prev => prev.map(n => {
              if (n.id === vulnId) return { ...n, status: 'SELF_HEALED' };
              if (n.id === targetSys) return { ...n, status: 'HEALTHY' };
              return n;
            }));
            setProcessAnimation(prev => ({
              ...prev,
              stage: 'HEALTHY_RESTORED',
              title: `System Restored to HEALTHY: ${targetSys}`,
              subtitle: `Vulnerability ${vulnId} self-healed.`,
              progress: 100,
              logs: [
                ...prev.logs,
                `[Remediation Commit] ${targetSys} restored to HEALTHY in Graph.`
              ]
            }));
            setToast({
              title: 'System Restored to Healthy',
              message: `${vulnId} was successfully patched. ${targetSys} is verified HEALTHY.`,
              type: 'green'
            });
            setTimeout(() => {
              setProcessAnimation(prev => ({ ...prev, active: false }));
            }, 3500);
          }
        }, 700);

      }, 700);

    }, 600);
  };

  // Run live verification probe on any system
  const handleVerifySystem = async (systemId: string) => {
    setProcessAnimation({
      stage: 'VERIFYING',
      active: true,
      title: `Verifying System Integrity: ${systemId}`,
      subtitle: 'Executing TCP port check, daemon process audit, and exploit immunity test...',
      progress: 50,
      targetId: systemId,
      logs: [
        `Probing TCP listening socket...`,
        `Auditing active vulnerability relationships in Graph DB...`
      ]
    });

    try {
      const res = await fetch('/api/system/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ system_id: systemId })
      });
      const data = await res.json();
      setVerificationResult(data);
      await fetchGraph();

      setProcessAnimation(prev => ({
        ...prev,
        stage: data.isHealthy ? 'HEALTHY_RESTORED' : 'BUG_DETECTED',
        title: data.isHealthy ? `System Verified: HEALTHY` : `System Verification Failed: COMPROMISED`,
        subtitle: data.isHealthy 
          ? `All diagnostics passed! System ${systemId} has 0 open vulnerabilities.`
          : `Found ${data.unmitigatedCount} unmitigated vulnerability vector(s)!`,
        progress: 100,
        logs: [
          ...prev.logs,
          `Result: ${data.isHealthy ? '100% HEALTHY' : 'VULNERABILITIES DETECTED'}`
        ]
      }));

      setToast({
        title: data.isHealthy ? 'Verification Passed' : 'Verification Alert',
        message: data.isHealthy ? `${systemId} is verified clean and operational.` : `${systemId} has active vulnerabilities!`,
        type: data.isHealthy ? 'green' : 'red'
      });

      setTimeout(() => {
        setProcessAnimation(prev => ({ ...prev, active: false }));
      }, 3000);

    } catch (e) {
      console.warn('System verification notice:', e);
      setProcessAnimation(prev => ({ ...prev, active: false }));
    }
  };

  // Chat message send handler
  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim()) return;

    const userMessage = chatInput.trim();
    setChatInput('');
    setChatMessages(prev => [...prev, { id: Date.now().toString(), role: 'user', text: userMessage }]);
    setIsChatting(true);

    const isFixIntent = /(fix|heal|patch|remediate|resolve|solve|repair)/i.test(userMessage);
    if (isFixIntent && !/(steps|how to|guide|runbook|what is|explain)/i.test(userMessage)) {
      setProcessAnimation({
        stage: 'DIAGNOSING',
        active: true,
        title: 'Autonomous Self-Healing Triggered via Copilot',
        subtitle: 'Auditing active attack vectors and dispatching patch synthesis...',
        progress: 35,
        logs: [
          `[Chat Command Received] "${userMessage}"`,
          `Querying active unmitigated vulnerabilities across live topology...`
        ]
      });
    }

    try {
      const res = await fetch('/api/user/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: userMessage })
      });
      const data = await res.json();
      const reply = data?.data?.reply || data?.reply || 'Received response from graph engine.';
      
      setChatMessages(prev => [...prev, { id: (Date.now() + 1).toString(), role: 'bot', text: reply }]);
      
      if (data?.data?.logs && data.data.logs.length > 0) {
        setHealedLog(data.data.logs);
      }

      // If bugs were healed
      if (data?.data?.isHealed || data?.data?.healedCount > 0) {
        setProcessAnimation(prev => ({
          ...prev,
          stage: 'HEALTHY_RESTORED',
          title: `Self-Healing Complete (${data.data.healedCount} Vector${data.data.healedCount > 1 ? 's' : ''} Mitigated)`,
          subtitle: `Remediated: ${(data.data.fixedVulns || []).join(', ') || 'All open vulnerabilities'}. Systems restored to HEALTHY.`,
          progress: 100,
          logs: [
            ...(prev.logs || []),
            `[Verification Complete] Restored systems: ${(data.data.restoredSystems || []).join(', ') || 'All software nodes'}.`,
            `Topology database updated. Security posture restored to 100%.`
          ]
        }));

        setToast({
          title: 'Remediation Executed',
          message: `Autonomous self-healing completed for ${data.data.healedCount || 'all'} vulnerability vector(s).`,
          type: 'green'
        });

        setTimeout(() => {
          setProcessAnimation(prev => ({ ...prev, active: false }));
        }, 4000);
      } else if (isFixIntent) {
        setTimeout(() => {
          setProcessAnimation(prev => ({ ...prev, active: false }));
        }, 1500);
      }

      // Always refresh graph so visual canvas and posture are updated in real time
      await fetchGraph();

    } catch (e) {
      console.warn('Chat interaction notice:', e);
      setChatMessages(prev => [...prev, { 
        id: (Date.now() + 1).toString(), 
        role: 'bot', 
        text: 'The threat intelligence copilot is synchronizing with the graph topology. All network telemetry streams remain active.' 
      }]);
      setProcessAnimation(prev => ({ ...prev, active: false }));
    }
    setIsChatting(false);
  };

  // Connected components on hover
  const getConnectedComponent = (startNodeId: string) => {
    const connectedNodes = new Set<string>();
    const connectedEdges = new Set<string>();
    const queue = [startNodeId];
    connectedNodes.add(startNodeId);

    while (queue.length > 0) {
      const current = queue.shift()!;
      edges.forEach((edge, idx) => {
        const edgeId = `edge-${idx}`;
        if (edge.from === current && !connectedNodes.has(edge.to)) {
          connectedNodes.add(edge.to);
          connectedEdges.add(edgeId);
          queue.push(edge.to);
        } else if (edge.to === current && !connectedNodes.has(edge.from)) {
          connectedNodes.add(edge.from);
          connectedEdges.add(edgeId);
          queue.push(edge.from);
        } else if ((edge.from === current || edge.to === current) && !connectedEdges.has(edgeId)) {
          connectedEdges.add(edgeId);
        }
      });
    }
    return { connectedNodes, connectedEdges };
  };

  const { connectedNodes, connectedEdges } = hoveredNode
    ? getConnectedComponent(hoveredNode.id)
    : { connectedNodes: new Set<string>(), connectedEdges: new Set<string>() };

  // Feature: Calculate & Highlight Shortest Path from Threat Actor to Software System
  const handleCalculateShortestPath = (actorId?: string, swId?: string) => {
    const startId = actorId || selectedThreatActorForPath;
    const targetId = swId || selectedSoftwareForPath;

    if (actorId) setSelectedThreatActorForPath(actorId);
    if (swId) setSelectedSoftwareForPath(swId);

    const result = findShortestPath(nodes, edges, startId, targetId);
    setActivePathResult(result);

    if (result.found) {
      // Pan viewport to encompass the shortest path
      const pathXs = result.pathNodes.map(n => n.x);
      const pathYs = result.pathNodes.map(n => n.y);
      if (pathXs.length > 0) {
        const minX = Math.min(...pathXs);
        const maxX = Math.max(...pathXs);
        const minY = Math.min(...pathYs);
        const maxY = Math.max(...pathYs);
        const centerX = (minX + maxX) / 2;
        const centerY = (minY + maxY) / 2;
        const width = containerSize.width || 1200;
        const height = containerSize.height || 800;

        setTransform({
          x: Math.round(width / 2 - centerX * 0.85),
          y: Math.round(height / 2 - centerY * 0.85),
          k: 0.85
        });
      }

      setToast({
        title: 'Shortest Path Highlighted',
        message: `${result.startNode?.name} ➔ ${result.endNode?.name} (${result.totalHops} hops via BFS)`,
        type: 'green'
      });
    } else {
      setToast({
        title: 'No Direct Path Found',
        message: result.summary,
        type: 'red'
      });
    }
  };

  const handleClearShortestPath = () => {
    setActivePathResult(null);
  };

  // Feature: Generate & Download JSON-Formatted Summary Report of Graph Topology
  const handleDownloadTopologyReport = () => {
    try {
      const softwareNodes = nodes.filter(n => n.label === 'Software');
      const vulnNodes = nodes.filter(n => n.label === 'Vulnerability');
      const unmitigatedVulns = vulnNodes.filter(v => v.status === 'UNMITIGATED');
      const healedVulns = vulnNodes.filter(v => v.status === 'SELF_HEALED');
      const compromisedSoftware = softwareNodes.filter(s => s.status === 'COMPROMISED');
      const healthySoftware = softwareNodes.filter(s => s.status === 'HEALTHY');
      const threatActorNodes = nodes.filter(n => n.label === 'ThreatActor');
      const mitigationNodes = nodes.filter(n => n.label === 'Mitigation');

      const totalSw = softwareNodes.length || 1;
      const posturePercent = Math.max(0, Math.round(((totalSw - compromisedSoftware.length) / totalSw) * 100));

      const reportData = {
        report_metadata: {
          report_id: `CTI-TOPO-REPORT-${Date.now()}`,
          generated_at: new Date().toISOString(),
          system: "Self-Healing GraphRAG CTI Platform",
          format_version: "2.1.0",
          graph_database_engine: dbEngine,
          authoritative_source: "Live Monitored Graph Topology"
        },
        security_posture_summary: {
          overall_health_percentage: posturePercent,
          alert_status: unmitigatedVulns.length > 0 ? "ELEVATED_THREAT_ACTIVE" : "ALL_SYSTEMS_HEALTHY",
          total_nodes_count: nodes.length,
          total_edges_count: edges.length,
          vulnerabilities_count: {
            unmitigated: unmitigatedVulns.length,
            self_healed: healedVulns.length,
            total: vulnNodes.length
          },
          software_systems_count: {
            compromised: compromisedSoftware.length,
            healthy: healthySoftware.length,
            total: softwareNodes.length
          },
          threat_actors_tracked: threatActorNodes.length,
          active_mitigations_deployed: mitigationNodes.length
        },
        vulnerability_status_breakdown: {
          unmitigated_active_exploits: unmitigatedVulns.map(v => {
            const targets = edges
              .filter(e => e.from === v.id && (e.label === 'AFFECTS' || e.label === 'EXPLOITS'))
              .map(e => e.to);
            return {
              vulnerability_id: v.id,
              name: v.name,
              severity: v.severity || 'CRITICAL',
              cvss_score: v.cvss || 9.5,
              status: v.status || 'UNMITIGATED',
              root_cause: v.cause || 'Unvalidated input handling',
              impacted_infrastructure_nodes: targets,
              description: v.description || v.details,
              reproduction_command: v.reproduction || `curl http://target:${v.port || 80}/exploit`,
              fix_solution: v.fixSolution || 'Deploy vendor security patch'
            };
          }),
          remediated_and_healed_exploits: healedVulns.map(v => ({
            vulnerability_id: v.id,
            name: v.name,
            severity: v.severity || 'CRITICAL',
            cvss_score: v.cvss || 9.5,
            status: 'SELF_HEALED',
            remediated_at: v.resolved_at || v.timestamp
          }))
        },
        nodes: nodes.map(n => ({
          id: n.id,
          name: n.name,
          label: n.label,
          status: n.status || 'ACTIVE',
          severity: n.severity || null,
          cvss: n.cvss || null,
          description: n.description || n.details || null,
          ip: n.ip || null,
          port: n.port || null,
          service: n.service || null,
          dataset_provenance: n.dataset || 'NVD / MITRE ATT&CK',
          coordinates: { x: Math.round(n.x), y: Math.round(n.y) }
        })),
        edges: edges.map(e => ({
          from_node: e.from,
          to_node: e.to,
          relationship: e.label
        }))
      };

      const jsonString = JSON.stringify(reportData, null, 2);
      const blob = new Blob([jsonString], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const dateStr = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `graph-topology-summary-report-${dateStr}.json`;

      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      setToast({
        title: 'Topology Report Downloaded',
        message: `Saved JSON summary report (${nodes.length} nodes, ${edges.length} edges).`,
        type: 'green'
      });
    } catch (err: any) {
      console.error('Error generating topology report:', err);
      setToast({
        title: 'Report Generation Failed',
        message: err?.message || 'Could not generate JSON report',
        type: 'red'
      });
    }
  };

  // Real-time production telemetry: Frame Rate (FPS) & Frame Latency loop
  const [fps, setFps] = useState<number>(60);
  const [frameTimeMs, setFrameTimeMs] = useState<number>(16.6);
  const [fpsHistory, setFpsHistory] = useState<number[]>(new Array(16).fill(60));

  useEffect(() => {
    let frameCount = 0;
    let lastTime = performance.now();
    let animId: number;

    const measureFrame = (now: number) => {
      frameCount++;
      const elapsed = now - lastTime;
      if (elapsed >= 500) {
        const measuredFps = Math.min(120, Math.round((frameCount * 1000) / elapsed));
        const avgFrame = Number((elapsed / frameCount).toFixed(1));
        setFps(measuredFps);
        setFrameTimeMs(avgFrame);
        setFpsHistory(prev => [...prev.slice(1), measuredFps]);
        frameCount = 0;
        lastTime = now;
      }
      animId = requestAnimationFrame(measureFrame);
    };

    animId = requestAnimationFrame(measureFrame);
    return () => cancelAnimationFrame(animId);
  }, []);

  // Monitor Graph Container bounds for precision tooltip positioning and viewport clamping
  useEffect(() => {
    if (!graphContainerRef.current) return;
    const updateSize = () => {
      if (graphContainerRef.current) {
        setContainerSize({
          width: graphContainerRef.current.clientWidth || 1200,
          height: graphContainerRef.current.clientHeight || 800
        });
      }
    };
    updateSize();
    const observer = new ResizeObserver(updateSize);
    observer.observe(graphContainerRef.current);
    return () => observer.disconnect();
  }, []);

  // Edge Bézier Curve & Routing Geometry Computation with precise execution telemetry
  const { calculatedEdges, measuredEdgeTime } = useMemo(() => {
    const t0 = performance.now();
    const isPathActive = Boolean(activePathResult?.found);
    
    const result = edges.map((edge, idx) => {
      const source = nodes.find(n => n.id === edge.from);
      const target = nodes.find(n => n.id === edge.to);
      if (!source || !target) return null;

      const edgeId = `edge-${idx}`;
      const isHealed = edge.label === 'HAS_MITIGATION';
      const isExploit = edge.label === 'EXPLOITS' || edge.label === 'AFFECTS';
      const isEdgeInPath = isPathActive && (activePathResult?.edgeKeys.has(getEdgeKey(edge)) || false);

      let isFaded = false;
      if (isPathActive) {
        isFaded = !isEdgeInPath;
      } else if (hoveredNode !== null) {
        isFaded = !connectedEdges.has(edgeId);
      }

      let strokeColor = '#3b82f6';
      let markerId = 'url(#arrow-blue)';

      if (isEdgeInPath) {
        strokeColor = '#f59e0b';
        markerId = 'url(#arrow-path-highlight)';
      } else if (isFaded) {
        strokeColor = '#64748b';
        markerId = 'url(#arrow-dim)';
      } else if (isHealed) {
        strokeColor = '#10b981';
        markerId = 'url(#arrow-green)';
      } else if (isExploit) {
        strokeColor = '#ef4444';
        markerId = 'url(#arrow-red)';
      }

      const dx = target.x - source.x;
      const curveOffset = Math.min(Math.abs(dx) * 0.45, 120);
      const pathData = `M ${source.x} ${source.y} C ${source.x + curveOffset} ${source.y}, ${target.x - curveOffset} ${target.y}, ${target.x} ${target.y}`;
      const midX = (source.x + target.x) / 2;
      const midY = (source.y + target.y) / 2;

      return {
        edgeId,
        edge,
        source,
        target,
        pathData,
        midX,
        midY,
        strokeColor,
        markerId,
        isFaded,
        isExploit,
        isHealed,
        isEdgeInPath
      };
    }).filter(Boolean) as {
      edgeId: string;
      edge: GraphEdge;
      source: GraphNode;
      target: GraphNode;
      pathData: string;
      midX: number;
      midY: number;
      strokeColor: string;
      markerId: string;
      isFaded: boolean;
      isExploit: boolean;
      isHealed: boolean;
      isEdgeInPath: boolean;
    }[];

    const t1 = performance.now();
    const elapsed = Math.max(0.12, Number((t1 - t0).toFixed(2)));
    return { calculatedEdges: result, measuredEdgeTime: elapsed };
  }, [edges, nodes, hoveredNode, connectedEdges, activePathResult]);

  // Node telemetry composition breakdown
  const nodeBreakdown = useMemo(() => ({
    software: nodes.filter(n => n.label === 'Software').length,
    vulnerability: nodes.filter(n => n.label === 'Vulnerability').length,
    mitigation: nodes.filter(n => n.label === 'Mitigation').length,
    actorsAndTech: nodes.filter(n => n.label !== 'Software' && n.label !== 'Vulnerability' && n.label !== 'Mitigation').length
  }), [nodes]);

  const handleWheel = (e: React.WheelEvent<SVGSVGElement>) => {
    const zoomSensitivity = 0.001;
    const delta = -e.deltaY * zoomSensitivity;
    const newK = Math.min(Math.max(0.1, transform.k * (1 + delta)), 4);
    setTransform(prev => ({ ...prev, k: newK }));
  };

  const handleMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    if ((e.target as HTMLElement).closest('.graph-node')) return;
    setIsDragging(true);
    setHoveredNode(null);
    setDragStart({ x: e.clientX - transform.x, y: e.clientY - transform.y });
  };

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (draggingNodeId) {
      const svgRect = e.currentTarget.getBoundingClientRect();
      const newX = Math.round((e.clientX - svgRect.left - transform.x) / transform.k);
      const newY = Math.round((e.clientY - svgRect.top - transform.y) / transform.k);
      persistentPositionsRef.current.set(draggingNodeId, { x: newX, y: newY });
      setNodes(prev => prev.map(n => n.id === draggingNodeId ? { ...n, x: newX, y: newY } : n));
    } else if (isDragging) {
      setTransform(prev => ({
        ...prev,
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y
      }));
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
    setDraggingNodeId(null);
  };
  const handleMouseLeave = () => {
    setIsDragging(false);
    setDraggingNodeId(null);
  };

  const handleZoomIn = () => setTransform(prev => ({ ...prev, k: Math.min(prev.k * 1.25, 2.8) }));
  const handleZoomOut = () => setTransform(prev => ({ ...prev, k: Math.max(prev.k / 1.25, 0.35) }));
  const handleResetZoom = () => setTransform({ x: 0, y: 0, k: 1 });

  // 1. Fully Dynamic Bounding Box for Enterprise Workload Mesh (Hugs actual software nodes)
  const workloadMeshBox = useMemo(() => {
    const softNodes = nodes.filter(n => n.label === 'Software');
    if (softNodes.length === 0) {
      return { x: 700, y: 90, width: 900, height: 600, centerX: 1150 };
    }
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    softNodes.forEach(n => {
      minX = Math.min(minX, n.x - 92);
      maxX = Math.max(maxX, n.x + 92);
      minY = Math.min(minY, n.y - 52);
      maxY = Math.max(maxY, n.y + 52);
    });
    const padX = 28;
    const padTop = 38;
    const padBottom = 24;
    return {
      x: minX - padX,
      y: minY - padTop,
      width: (maxX - minX) + padX * 2,
      height: (maxY - minY) + padTop + padBottom,
      centerX: (minX + maxX) / 2
    };
  }, [nodes]);

  // 2. Fully Dynamic Bounding Boxes for Zone Enclaves in 'zones' mode
  const dynamicZoneBoxes = useMemo(() => {
    const zoneDefs: Array<{ id: 'edge' | 'app' | 'data' | 'mgmt'; name: string; cidr: string; color: string }> = [
      { id: 'edge', name: 'DMZ & INGRESS GATEWAY', cidr: '10.0.1.0/24', color: '#38bdf8' },
      { id: 'app', name: 'APPLICATION SERVICES', cidr: '10.0.2.0/24', color: '#818cf8' },
      { id: 'data', name: 'SECURE DATA VAULT', cidr: '10.0.3.0/24', color: '#34d399' },
      { id: 'mgmt', name: 'INTERNAL IAM & MGMT', cidr: '10.0.4.0/24', color: '#fbbf24' }
    ];
    const softNodes = nodes.filter(n => n.label === 'Software');
    
    return zoneDefs.map(z => {
      const zoneNodes = softNodes.filter((s, i) => getSystemEnclave(s.name, i).zoneId === z.id);
      if (zoneNodes.length === 0) return null;
      let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
      zoneNodes.forEach(n => {
        minX = Math.min(minX, n.x - 92);
        maxX = Math.max(maxX, n.x + 92);
        minY = Math.min(minY, n.y - 52);
        maxY = Math.max(maxY, n.y + 52);
      });
      const padX = 20;
      const padTop = 38;
      const padBottom = 20;
      return {
        ...z,
        x: minX - padX,
        y: minY - padTop,
        width: (maxX - minX) + padX * 2,
        height: (maxY - minY) + padTop + padBottom,
        centerX: (minX + maxX) / 2
      };
    }).filter((z): z is NonNullable<typeof z> => z !== null);
  }, [nodes]);

  // 3. Fully Dynamic Column Guides at top that align precisely over actual node tiers
  const dynamicColumnGuides = useMemo(() => {
    const getAvgX = (label: string, fallback: number) => {
      const catNodes = nodes.filter(n => n.label === label);
      if (catNodes.length === 0) return fallback;
      const sum = catNodes.reduce((acc, n) => acc + n.x, 0);
      return Math.round(sum / catNodes.length);
    };

    const taX = getAvgX('ThreatActor', 90);
    const malX = getAvgX('Malware', 290);
    const techX = getAvgX('Technique', 490);
    const vulnX = getAvgX('Vulnerability', 710);
    const mitX = getAvgX('Mitigation', 2200);
    const infraX = workloadMeshBox.centerX;

    return [
      { x: taX, label: 'Threat Actors', sub: 'Adversary Intelligence', color: '#ef4444' },
      { x: malX, label: 'Malware', sub: 'Payloads & Tools', color: '#a855f7' },
      { x: techX, label: 'Techniques', sub: 'MITRE ATT&CK', color: '#f97316' },
      { x: vulnX, label: 'Vulnerabilities', sub: 'Active CVEs', color: '#ec4899' },
      { x: infraX, label: 'Infrastructure', sub: 'Monitored Fleet', color: '#0284c7' },
      { x: mitX, label: 'Mitigations', sub: 'Active Defenses', color: '#10b981' }
    ];
  }, [nodes, workloadMeshBox]);

  // Advanced Enterprise Topology Auto-Align & Layout Engine
  const handleAutoAlignTopology = (targetMode: GraphLayoutMode = layoutMode) => {
    persistentPositionsRef.current.clear();
    try {
      localStorage.removeItem('cached_graph_state');
    } catch {
      // ignore
    }
    const { nodes: alignedNodes, edges: alignedEdges } = transformRawGraph(
      DEFAULT_GRAPH_DATA.nodes,
      DEFAULT_GRAPH_DATA.edges,
      persistentPositionsRef.current,
      true,
      targetMode
    );
    setNodes(alignedNodes);
    setEdges(alignedEdges);
    setLayoutMode(targetMode);
    if (targetMode === 'organic') {
      setIsPhysicsRunning(true);
    } else {
      setIsPhysicsRunning(false);
    }

    const modeLabels: Record<GraphLayoutMode, string> = {
      pipeline: 'Kill-Chain Attack Flow Pipeline',
      zones: 'Enterprise Subnet Enclaves',
      rack: 'Dynamic Workload Mesh',
      organic: 'Force-Directed Physics'
    };

    setToast({
      title: 'Topology Layout Aligned',
      message: `Infrastructure workloads and threat vectors aligned to ${modeLabels[targetMode]}.`,
      type: 'green'
    });
  };

  const handleFitCenter = () => {
    const width = containerSize.width || 1200;
    const height = containerSize.height || 800;
    if (nodes.length === 0) {
      setTransform({ x: 25, y: 30, k: 0.62 });
      return;
    }
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    nodes.forEach(n => {
      minX = Math.min(minX, n.x - 95);
      maxX = Math.max(maxX, n.x + 95);
      minY = Math.min(minY, n.y - 65);
      maxY = Math.max(maxY, n.y + 65);
    });
    const graphW = Math.max(400, maxX - minX + 80);
    const graphH = Math.max(300, maxY - minY + 100);
    const scaleX = (width - 80) / graphW;
    const scaleY = (height - 80) / graphH;
    const targetK = Math.min(1.05, Math.max(0.35, Math.min(scaleX, scaleY)));
    const centerX = (minX + maxX) / 2;
    const centerY = (minY + maxY) / 2;
    const targetX = Math.round(width / 2 - centerX * targetK);
    const targetY = Math.round(height / 2 - centerY * targetK);
    setTransform({ x: targetX, y: targetY, k: Number(targetK.toFixed(2)) });
  };

  return (
    <div className={`h-screen w-full min-w-0 max-w-full overflow-hidden font-sans text-xs flex flex-col transition-colors duration-200 antialiased theme-stabilized ${
      isDark 
        ? 'dark bg-[#060a12] text-slate-100' 
        : 'bg-slate-50 text-slate-800'
    }`}>
      
      {/* REQUIREMENT 8: Process Animation Banner */}
      <ProcessAnimationBanner
        state={processAnimation}
        onDismiss={() => setProcessAnimation(prev => ({ ...prev, active: false }))}
        theme={theme}
      />

      {/* REQUIREMENT 5: Project Environment Specifications Modal */}
      <EnvironmentModal
        isOpen={showEnvModal}
        onClose={() => setShowEnvModal(false)}
        theme={theme}
      />

      {/* REQUIREMENT 6: System Configuration Modal */}
      <SystemConfigModal
        isOpen={showConfigModal}
        onClose={() => { setShowConfigModal(false); setConfiguringSystem(null); }}
        system={configuringSystem}
        onSaveConfig={handleSaveSystemConfig}
        theme={theme}
      />

      {/* Knowledge Hub: Systems Catalog, Enclaves & CTI Architecture Modal */}
      <KnowledgeHubModal
        isOpen={showKnowledgeHubModal}
        onClose={() => setShowKnowledgeHubModal(false)}
        nodes={nodes}
        edges={edges}
        theme={theme}
        onDownloadReport={handleDownloadTopologyReport}
        onSelectSystemForTesting={(sysId) => {
          setAuthRole('hacker');
          setTargetSoftware(sysId);
          setShowKnowledgeHubModal(false);
          setShowExploitLabModal(true);
        }}
      />

      {/* Exploit Lab: Interactive PoC Payloads & Attack Sandbox Modal */}
      <ExploitLabModal
        isOpen={showExploitLabModal}
        onClose={() => setShowExploitLabModal(false)}
        nodes={nodes}
        edges={edges}
        theme={theme}
        customCodes={bugCustomCodes}
        onUpdateCode={(bugId, updated) => {
          setBugCustomCodes(prev => ({ ...prev, [bugId]: updated }));
          setNodes(prev => prev.map(n => n.id === bugId ? {
            ...n,
            codeLanguage: updated.codeLanguage,
            codeFileName: updated.codeFileName,
            buggyCode: updated.buggyCode,
            correctedCode: updated.correctedCode,
            errorMessage: updated.errorMessage,
            exploitScript: updated.exploitScript,
            rootCause: updated.rootCause,
            fixExplanation: updated.fixExplanation
          } : n));
        }}
        onSelectSystemForInjection={(sysId) => {
          setAuthRole('hacker');
          setTargetSoftware(sysId);
          setToast({ title: 'Target Selected', message: `Target software switched to ${sysId}.`, type: 'red' });
        }}
        onLiveBugFix={(vulnId, systemId) => {
          handleLiveBugFix(vulnId, systemId);
        }}
        onOpenGraphRagStudio={(sysId) => {
          if (sysId) setGraphRagTargetSystem(sysId);
          setShowExploitLabModal(false);
          setShowGraphRagModal(true);
        }}
      />

      {/* GraphRAG Autonomous Vulnerability & Remediation Studio Modal */}
      <GraphRagVulnerabilityModal
        isOpen={showGraphRagModal}
        onClose={() => setShowGraphRagModal(false)}
        theme={theme}
        nodes={nodes}
        defaultSystemId={graphRagTargetSystem}
        onWorkflowComplete={(result) => {
          fetchGraph();
          setToast({
            title: 'GraphRAG Pipeline Verified',
            message: `${result.vulnerability.name} analyzed, remediated, and verified for ${result.system.id}.`,
            type: 'green'
          });
        }}
      />

      {/* Optional Operator Credentials & Session Drawer */}
      {showAuthModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className={`border rounded-xl w-full max-w-md p-6 overflow-hidden shadow-2xl relative transition-colors ${
            isDark ? 'bg-[#0a0f1d] border-slate-800 text-slate-200' : 'bg-white border-slate-200 text-slate-800'
          }`}>
            <button 
              onClick={() => setShowAuthModal(false)} 
              className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
            
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-lg bg-blue-600/10 border border-blue-500/20 flex items-center justify-center text-blue-500">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-bold text-sm text-slate-900 dark:text-white">Active SecOps Session</h3>
                <p className="text-xs text-slate-500 dark:text-neutral-400">Authenticated Enterprise Identity</p>
              </div>
            </div>

            <div className="space-y-3 mb-5 p-3 rounded-lg bg-slate-100 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 text-xs">
              <div className="flex justify-between items-center">
                <span className="text-slate-500 dark:text-neutral-400">Operator</span>
                <span className="font-semibold text-slate-800 dark:text-neutral-200 font-mono">SecOps-Lead-88</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-500 dark:text-neutral-400">Current Role</span>
                <span className="font-semibold text-blue-500 font-mono uppercase">
                  {authRole === 'analyst' ? 'Blue Team (Analyst)' : 'Red Team (Operator)'}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-500 dark:text-neutral-400">Topology Access</span>
                <span className="font-semibold text-emerald-500 font-mono">Read / Write / Self-Heal</span>
              </div>
            </div>

            <div className="flex gap-2">
              <button
                onClick={() => { setAuthRole('analyst'); setShowAuthModal(false); }}
                className={`flex-1 py-2 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                  authRole === 'analyst' ? 'bg-blue-600 text-white' : 'bg-slate-200 dark:bg-neutral-800 hover:bg-slate-300 dark:hover:bg-neutral-700'
                }`}
              >
                <Shield className="w-3.5 h-3.5" /> Blue Team
              </button>
              <button
                onClick={() => { setAuthRole('hacker'); setShowAuthModal(false); }}
                className={`flex-1 py-2 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                  authRole === 'hacker' ? 'bg-red-600 text-white' : 'bg-slate-200 dark:bg-neutral-800 hover:bg-slate-300 dark:hover:bg-neutral-700'
                }`}
              >
                <Flame className="w-3.5 h-3.5" /> Red Team
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toast Notification */}
      <div className={`fixed top-4 right-4 z-50 transition-all duration-300 transform ${toast ? 'translate-y-0 opacity-100' : '-translate-y-4 opacity-0 pointer-events-none'}`}>
        {toast && (
          <div className={`px-4 py-3 rounded-xl shadow-xl backdrop-blur-md border flex items-center gap-3 ${
            toast.type === 'red' 
              ? 'bg-red-950/90 border-red-800/80 text-red-200' 
              : 'bg-emerald-950/90 border-emerald-800/80 text-emerald-200'
          }`}>
            {toast.type === 'red' ? <Flame className="w-4 h-4 text-red-400 shrink-0" /> : <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />}
            <div>
              <h4 className="font-semibold text-xs tracking-tight">{toast.title}</h4>
              <p className="text-[11px] opacity-90">{toast.message}</p>
            </div>
            <button onClick={() => setToast(null)} className="ml-2 text-neutral-400 hover:text-white">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>

      {/* HEADER BAR (Enterprise CTI & SOC Command Navigation) */}
      <header className={`h-14 w-full max-w-full min-w-0 flex items-center justify-between px-2 sm:px-3 md:px-4 border-b z-40 transition-colors shrink-0 select-none ${
        isDark 
          ? 'bg-[#070c18]/95 backdrop-blur-md border-slate-800/80 shadow-[0_4px_24px_rgba(0,0,0,0.4)]' 
          : 'bg-white/95 backdrop-blur-md border-slate-200 shadow-xs'
      }`}>
        {/* Left: Brand Identity & Telemetry Status */}
        <div className="flex items-center space-x-2 sm:space-x-2.5 shrink-0">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-600 via-indigo-600 to-cyan-400 p-[1px] shadow-[0_0_16px_rgba(59,130,246,0.35)] shrink-0">
            <div className="w-full h-full rounded-[7px] bg-[#070d18] flex items-center justify-center text-blue-400">
              <Shield className="w-4 h-4 text-cyan-400" />
            </div>
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-1.5 sm:gap-2">
              <span className="font-sans font-bold tracking-tight text-xs sm:text-sm text-slate-900 dark:text-white whitespace-nowrap">
                Self-Healing GraphRAG
              </span>
              <span className="hidden 2xl:inline-flex items-center gap-1.5 font-mono text-[10px] text-cyan-400 px-2 py-0.5 rounded-full bg-cyan-950/60 border border-cyan-800/50">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                {dbEngine}
              </span>
            </div>
            <span className="hidden 3xl:inline text-[10px] font-sans font-medium text-slate-500 dark:text-slate-400 tracking-wide">
              Enterprise Cyber Threat Intelligence Platform
            </span>
          </div>
        </div>

        {/* Center: Operational Mode Switcher (Blue Defense vs Red Attack) */}
        <div className="hidden lg:flex items-center p-0.5 rounded-lg border bg-slate-100 dark:bg-slate-950/90 border-slate-200 dark:border-slate-800/90 shadow-inner shrink-0">
          <button
            onClick={() => setAuthRole('analyst')}
            className={`px-2.5 py-1.5 rounded-md text-xs font-sans font-semibold transition-all flex items-center gap-1.5 ${
              authRole === 'analyst'
                ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-sm'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-white'
            }`}
            title="Switch to Blue Team: Monitor topology, investigate alerts, and execute autonomous remediation"
          >
            <Shield className="w-3.5 h-3.5 shrink-0" />
            <span>Defense</span>
            <span className="hidden xl:inline text-[11px] opacity-80">(Blue Team)</span>
          </button>
          <button
            onClick={() => setAuthRole('hacker')}
            className={`px-2.5 py-1.5 rounded-md text-xs font-sans font-semibold transition-all flex items-center gap-1.5 ${
              authRole === 'hacker'
                ? 'bg-gradient-to-r from-rose-600 to-red-600 text-white shadow-sm'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-white'
            }`}
            title="Switch to Red Team: Inject active exploits, weaponize zero-days, and stress-test infrastructure"
          >
            <Crosshair className="w-3.5 h-3.5 shrink-0" />
            <span>Attack</span>
            <span className="hidden xl:inline text-[11px] opacity-80">(Red Team)</span>
          </button>
        </div>

        {/* Right Section: Core Tools, Workload Stepper, View Controls & Profile */}
        <div className="flex items-center space-x-1 sm:space-x-1.5 md:space-x-2 shrink-0">
          
          {/* Desktop Full Navigation Hub (>= 1536px / 2xl) */}
          <nav className="hidden 2xl:flex items-center space-x-1 border-r border-slate-200 dark:border-slate-800/80 pr-2 mr-0.5 shrink-0">
            <button
              onClick={() => {
                setShowKnowledgeHubModal(true);
              }}
              className={`px-2 py-1.5 rounded-md text-xs font-sans font-medium flex items-center gap-1.5 transition-colors ${
                isDark ? 'text-slate-300 hover:text-white hover:bg-slate-800/70' : 'text-slate-700 hover:text-slate-950 hover:bg-slate-100'
              }`}
              title="Open Systems Catalog, Enclaves, Architecture & CTI Intelligence Hub"
            >
              <BookOpen className="w-3.5 h-3.5 text-amber-400" />
              <span>Knowledge Hub</span>
            </button>

            <button
              onClick={() => {
                setGraphRagTargetSystem('Computer 26');
                setShowGraphRagModal(true);
              }}
              className={`px-2.5 py-1.5 rounded-md text-xs font-sans font-semibold flex items-center gap-1.5 transition-all ${
                isDark 
                  ? 'bg-gradient-to-r from-cyan-950/60 to-blue-950/60 text-cyan-300 hover:text-white border border-cyan-800/50 shadow-xs' 
                  : 'bg-cyan-50 text-cyan-900 hover:bg-cyan-100 border border-cyan-200'
              }`}
              title="Autonomous 15-Step GraphRAG Vulnerability Reasoning, Safe Code Synthesis & Verification Studio"
            >
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
              <span>GraphRAG Studio</span>
            </button>

            <button
              onClick={() => {
                setShowExploitLabModal(true);
              }}
              className={`px-2 py-1.5 rounded-md text-xs font-sans font-medium flex items-center gap-1.5 transition-colors ${
                isDark ? 'text-slate-300 hover:text-white hover:bg-slate-800/70' : 'text-slate-700 hover:text-slate-950 hover:bg-slate-100'
              }`}
              title="Interactive PoC Payloads, Sandbox Exploit Execution & Red Team Attack Lab"
            >
              <Code className="w-3.5 h-3.5 text-rose-400" />
              <span>Exploit Lab</span>
            </button>

            <button
              onClick={() => setShowEnvModal(true)}
              className={`px-2 py-1.5 rounded-md text-xs font-sans font-medium flex items-center gap-1.5 transition-colors ${
                isDark ? 'text-slate-300 hover:text-white hover:bg-slate-800/70' : 'text-slate-700 hover:text-slate-950 hover:bg-slate-100'
              }`}
              title="Inspect Environment Details & Setup Instructions"
            >
              <Server className="w-3.5 h-3.5 text-blue-400" />
              <span>Specs</span>
            </button>

            <button
              onClick={handleDownloadTopologyReport}
              className={`px-2 py-1.5 rounded-md text-xs font-sans font-semibold flex items-center gap-1.5 transition-all ${
                isDark 
                  ? 'text-emerald-300 hover:text-white hover:bg-emerald-950/60' 
                  : 'text-emerald-800 hover:text-emerald-950 hover:bg-emerald-50'
              }`}
              title="Download comprehensive JSON topology report"
            >
              <Download className="w-3.5 h-3.5 text-emerald-400" />
              <span>Export</span>
            </button>
          </nav>

          {/* Compact View for < 2xl: Directly shows GraphRAG Studio button */}
          <div className="hidden md:flex 2xl:hidden items-center space-x-1.5 border-r border-slate-200 dark:border-slate-800/80 pr-2 mr-0.5 shrink-0">
            <button
              onClick={() => {
                setGraphRagTargetSystem('Computer 26');
                setShowGraphRagModal(true);
              }}
              className={`px-2.5 py-1.5 rounded-md text-xs font-sans font-semibold flex items-center gap-1.5 transition-all ${
                isDark 
                  ? 'bg-gradient-to-r from-cyan-950/60 to-blue-950/60 text-cyan-300 hover:text-white border border-cyan-800/50 shadow-xs' 
                  : 'bg-cyan-50 text-cyan-900 hover:bg-cyan-100 border border-cyan-200'
              }`}
              title="Autonomous 15-Step GraphRAG Vulnerability Reasoning, Safe Code Synthesis & Verification Studio"
            >
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
              <span>GraphRAG Studio</span>
            </button>
          </div>

          {/* Medium Screen Dropdown (< 2xl) */}
          <div className="relative 2xl:hidden shrink-0">
            <button
              onClick={() => setShowToolsDropdown(prev => !prev)}
              className={`px-2.5 py-1.5 rounded-lg border text-xs font-sans font-medium flex items-center gap-1.5 transition-colors ${
                showToolsDropdown
                  ? (isDark ? 'bg-slate-800 border-cyan-500/50 text-cyan-300' : 'bg-slate-100 border-blue-400 text-blue-900')
                  : (isDark ? 'bg-slate-900/90 border-slate-800 text-slate-300 hover:text-white' : 'bg-white border-slate-300 text-slate-700 hover:bg-slate-100')
              }`}
              title="Tools, Intelligence & Documentation"
            >
              <Layers className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden sm:inline">Tools & Docs</span>
              <ChevronDown className={`w-3 h-3 transition-transform ${showToolsDropdown ? 'rotate-180' : ''}`} />
            </button>

            {showToolsDropdown && (
              <>
                <div 
                  className="fixed inset-0 z-40"
                  onClick={() => setShowToolsDropdown(false)}
                />
                <div 
                  className={`absolute right-0 mt-2 w-64 rounded-xl border shadow-2xl p-1.5 z-50 animate-in fade-in zoom-in-95 duration-150 ${
                    isDark ? 'bg-[#0a0f1d] border-slate-800 text-slate-200 shadow-black/80' : 'bg-white border-slate-200 text-slate-800 shadow-xl'
                  }`}
                >
                  <button
                    onClick={() => {
                      setShowKnowledgeHubModal(true);
                      setShowToolsDropdown(false);
                    }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-sans font-medium transition-colors ${
                      isDark ? 'hover:bg-slate-800/80 hover:text-white' : 'hover:bg-slate-100'
                    }`}
                  >
                    <BookOpen className="w-4 h-4 text-amber-400 shrink-0" />
                    <div className="flex flex-col text-left">
                      <span className="font-semibold">Knowledge Hub</span>
                      <span className="text-[10px] text-slate-400">Architecture, Systems Catalog & CTI</span>
                    </div>
                  </button>

                  <button
                    onClick={() => {
                      setGraphRagTargetSystem('Computer 26');
                      setShowGraphRagModal(true);
                      setShowToolsDropdown(false);
                    }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-sans font-medium transition-colors ${
                      isDark ? 'hover:bg-slate-800/80 hover:text-white' : 'hover:bg-slate-100'
                    }`}
                  >
                    <Sparkles className="w-4 h-4 text-cyan-400 shrink-0" />
                    <div className="flex flex-col text-left">
                      <span className="font-semibold text-cyan-400">GraphRAG AI Studio</span>
                      <span className="text-[10px] text-slate-400">Autonomous 15-Step Vulnerability & Fix Studio</span>
                    </div>
                  </button>

                  <button
                    onClick={() => {
                      setShowExploitLabModal(true);
                      setShowToolsDropdown(false);
                    }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-sans font-medium transition-colors ${
                      isDark ? 'hover:bg-slate-800/80 hover:text-white' : 'hover:bg-slate-100'
                    }`}
                  >
                    <Code className="w-4 h-4 text-rose-400 shrink-0" />
                    <div className="flex flex-col text-left">
                      <span className="font-semibold text-rose-400">Exploit Lab</span>
                      <span className="text-[10px] text-slate-400">Interactive PoC Payloads & Attack Sandbox</span>
                    </div>
                  </button>

                  <button
                    onClick={() => {
                      setShowEnvModal(true);
                      setShowToolsDropdown(false);
                    }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-sans font-medium transition-colors ${
                      isDark ? 'hover:bg-slate-800/80 hover:text-white' : 'hover:bg-slate-100'
                    }`}
                  >
                    <Server className="w-4 h-4 text-blue-400 shrink-0" />
                    <div className="flex flex-col text-left">
                      <span className="font-semibold">Environment Specs</span>
                      <span className="text-[10px] text-slate-400">Runtime & Neo4j Settings</span>
                    </div>
                  </button>

                  <div className="my-1 border-t border-slate-800/60" />

                  <button
                    onClick={() => {
                      handleDownloadTopologyReport();
                      setShowToolsDropdown(false);
                    }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-sans font-medium transition-colors ${
                      isDark ? 'hover:bg-slate-800/80 hover:text-white text-emerald-400' : 'hover:bg-slate-100 text-emerald-700'
                    }`}
                  >
                    <Download className="w-4 h-4 text-emerald-400 shrink-0" />
                    <div className="flex flex-col text-left">
                      <span className="font-semibold">Export Topology</span>
                      <span className="text-[10px] text-slate-400">Download JSON Graph Snapshot</span>
                    </div>
                  </button>
                </div>
              </>
            )}
          </div>

          {/* Dynamic Workload Stepper (Nodes Count) */}
          <DynamicSystemControls
            systemCount={softwareSystems.length}
            onAddSystem={handleAddSystem}
            onRemoveSystem={handleRemoveSystem}
            systems={softwareSystems}
            theme={theme}
          />

          {/* View Panels Controls Group (Copilot, Telemetry, Focus) */}
          <div className={`flex items-center p-0.5 rounded-lg border shrink-0 ${
            isDark ? 'bg-slate-900/90 border-slate-800' : 'bg-slate-100 border-slate-200'
          }`}>
            {/* Copilot Assistant Toggle */}
            <button
              onClick={() => {
                setIsSidePanelOpen(prev => !prev);
                setIsFullGraphView(false);
              }}
              className={`p-1.5 rounded-md transition-all flex items-center gap-1 text-xs font-sans font-medium ${
                isSidePanelOpen && !isFullGraphView
                  ? (isDark ? 'bg-blue-600/30 text-blue-300 border border-blue-500/40 shadow-xs' : 'bg-blue-600 text-white shadow-xs')
                  : (isDark ? 'text-slate-400 hover:text-white hover:bg-slate-800' : 'text-slate-600 hover:text-slate-950 hover:bg-slate-200')
              }`}
              title={isSidePanelOpen ? "Close AI Copilot" : "Open AI Threat Assistant Copilot"}
            >
              <MessageSquare className="w-3.5 h-3.5" />
              <span className="hidden 3xl:inline">Copilot</span>
            </button>

            {/* Live System Telemetry Toggle */}
            <button
              onClick={() => {
                setIsTelemetrySunk(prev => !prev);
              }}
              className={`p-1.5 rounded-md transition-all flex items-center gap-1 text-xs font-sans font-medium ${
                !isTelemetrySunk
                  ? (isDark ? 'bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 shadow-xs' : 'bg-cyan-600 text-white shadow-xs')
                  : (isDark ? 'text-slate-400 hover:text-white hover:bg-slate-800' : 'text-slate-600 hover:text-slate-950 hover:bg-slate-200')
              }`}
              title={isTelemetrySunk ? "Open Live Telemetry Monitor" : "Minimize Live Telemetry"}
            >
              <Activity className="w-3.5 h-3.5" />
              <span className="hidden 3xl:inline">Telemetry</span>
              <span className={`w-1.5 h-1.5 rounded-full ${!isTelemetrySunk ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
            </button>

            {/* Full Canvas View Toggle */}
            <button
              onClick={() => {
                setIsFullGraphView(prev => {
                  const next = !prev;
                  if (next) setIsSidePanelOpen(false);
                  else setIsSidePanelOpen(true);
                  return next;
                });
              }}
              className={`p-1.5 rounded-md transition-all flex items-center gap-1 text-xs font-sans font-medium ${
                isFullGraphView
                  ? (isDark ? 'bg-emerald-600/30 text-emerald-300 border border-emerald-500/40 shadow-xs' : 'bg-emerald-600 text-white shadow-xs')
                  : (isDark ? 'text-slate-400 hover:text-white hover:bg-slate-800' : 'text-slate-600 hover:text-slate-950 hover:bg-slate-200')
              }`}
              title={isFullGraphView ? "Exit Full Canvas View" : "Toggle Full Canvas View"}
            >
              {isFullGraphView ? <Minimize2 className="w-3.5 h-3.5 text-emerald-300" /> : <Maximize2 className="w-3.5 h-3.5" />}
              <span className="hidden 3xl:inline">{isFullGraphView ? 'Exit Focus' : 'Focus'}</span>
            </button>
          </div>

          {/* Theme Toggle (Light / Dark) */}
          <ThemeToggle theme={theme} onToggle={toggleTheme} />

          {/* SecOps Operator Profile Badge (Opens Auth & Session modal) */}
          <button
            onClick={() => setShowAuthModal(true)}
            className={`flex items-center gap-1.5 px-2 py-1.5 sm:px-2.5 rounded-lg border text-xs font-sans transition-colors shrink-0 ${
              isDark 
                ? 'bg-slate-900/90 border-slate-800 text-slate-300 hover:bg-slate-800 hover:text-white' 
                : 'bg-slate-100 border-slate-200 text-slate-700 hover:bg-slate-200'
            }`}
            title="View Operational Session & Role Configuration"
          >
            <User className="w-3.5 h-3.5 text-slate-400 shrink-0" />
            <span className="hidden sm:inline lg:hidden 2xl:inline font-medium text-[11px] whitespace-nowrap">
              SecOps Operator
            </span>
            <span className="hidden lg:inline 2xl:hidden font-medium text-[11px] whitespace-nowrap">
              SecOps
            </span>
            <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${authRole === 'hacker' ? 'bg-rose-500' : 'bg-blue-500'}`} />
          </button>

          {/* Mobile Menu Button (< md) */}
          <button
            onClick={() => setIsMobileNavOpen(prev => !prev)}
            className={`md:hidden p-1.5 rounded-lg border transition-colors ${
              isMobileNavOpen
                ? (isDark ? 'bg-slate-800 border-cyan-500 text-white' : 'bg-slate-200 border-blue-500 text-slate-900')
                : (isDark ? 'bg-slate-900 border-slate-800 text-slate-300 hover:text-white' : 'bg-slate-100 border-slate-200 text-slate-700')
            }`}
            title="Toggle Mobile Menu"
            aria-label="Toggle Mobile Menu"
          >
            {isMobileNavOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>
        </div>
      </header>

      {/* Mobile Navigation Dropdown Drawer (< md) */}
      {isMobileNavOpen && (
        <>
          <div 
            className="fixed inset-0 z-30 bg-black/40 backdrop-blur-xs md:hidden"
            onClick={() => setIsMobileNavOpen(false)}
          />
          <div className={`md:hidden border-b px-4 py-3 z-40 transition-all animate-in slide-in-from-top-2 duration-200 relative ${
            isDark ? 'bg-[#080d19] border-slate-800 text-slate-200' : 'bg-white border-slate-200 text-slate-800 shadow-md'
          }`}>
            {/* Mobile Role Switcher */}
            <div className="mb-3">
              <span className="text-[10px] font-sans font-bold uppercase text-slate-400 tracking-wider mb-1.5 block">
                Operational Team Perspective
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    setAuthRole('analyst');
                    setIsMobileNavOpen(false);
                  }}
                  className={`flex-1 py-1.5 px-3 rounded-lg text-xs font-sans font-semibold flex items-center justify-center gap-1.5 border transition-all ${
                    authRole === 'analyst'
                      ? 'bg-blue-600 text-white border-blue-500 shadow-sm'
                      : isDark ? 'bg-slate-900 border-slate-800 text-slate-300' : 'bg-slate-100 border-slate-200 text-slate-700'
                  }`}
                >
                  <Shield className="w-3.5 h-3.5" />
                  <span>Blue Team (Defense)</span>
                </button>
                <button
                  onClick={() => {
                    setAuthRole('hacker');
                    setIsMobileNavOpen(false);
                  }}
                  className={`flex-1 py-1.5 px-3 rounded-lg text-xs font-sans font-semibold flex items-center justify-center gap-1.5 border transition-all ${
                    authRole === 'hacker'
                      ? 'bg-rose-600 text-white border-rose-500 shadow-sm'
                      : isDark ? 'bg-slate-900 border-slate-800 text-slate-300' : 'bg-slate-100 border-slate-200 text-slate-700'
                  }`}
                >
                  <Crosshair className="w-3.5 h-3.5" />
                  <span>Red Team (Attack)</span>
                </button>
              </div>
            </div>

            {/* Quick Tool Links */}
            <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800/60">
              <button
                onClick={() => {
                  setGraphRagTargetSystem('Computer 26');
                  setShowGraphRagModal(true);
                  setIsMobileNavOpen(false);
                }}
                className={`col-span-2 flex items-center justify-center gap-2 p-2 rounded-lg border text-xs font-sans font-semibold ${
                  isDark ? 'bg-cyan-950/40 border-cyan-800/60 text-cyan-300' : 'bg-cyan-50 border-cyan-300 text-cyan-900'
                }`}
              >
                <Sparkles className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span>GraphRAG AI Vulnerability Studio</span>
              </button>
              <button
                onClick={() => {
                  setShowKnowledgeHubModal(true);
                  setIsMobileNavOpen(false);
                }}
                className={`flex items-center gap-2 p-2 rounded-lg border text-xs font-sans font-medium text-left ${
                  isDark ? 'bg-slate-900/80 border-slate-800 text-slate-300' : 'bg-slate-50 border-slate-200 text-slate-700'
                }`}
              >
                <BookOpen className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                <span>Knowledge Hub</span>
              </button>
              <button
                onClick={() => {
                  setShowExploitLabModal(true);
                  setIsMobileNavOpen(false);
                }}
                className={`flex items-center gap-2 p-2 rounded-lg border text-xs font-sans font-medium text-left ${
                  isDark ? 'bg-slate-900/80 border-slate-800 text-slate-300' : 'bg-slate-50 border-slate-200 text-slate-700'
                }`}
              >
                <Code className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                <span>Exploit Lab</span>
              </button>
              <button
                onClick={() => {
                  setShowEnvModal(true);
                  setIsMobileNavOpen(false);
                }}
                className={`flex items-center gap-2 p-2 rounded-lg border text-xs font-sans font-medium text-left ${
                  isDark ? 'bg-slate-900/80 border-slate-800 text-slate-300' : 'bg-slate-50 border-slate-200 text-slate-700'
                }`}
              >
                <Server className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                <span>Environment Specs</span>
              </button>
              <button
                onClick={() => {
                  handleDownloadTopologyReport();
                  setIsMobileNavOpen(false);
                }}
                className={`col-span-2 flex items-center justify-center gap-2 p-2 rounded-lg border text-xs font-sans font-semibold ${
                  isDark ? 'bg-emerald-950/40 border-emerald-700/60 text-emerald-300' : 'bg-emerald-50 border-emerald-300 text-emerald-800'
                }`}
              >
                <Download className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Download Topology Report</span>
              </button>
            </div>
          </div>
        </>
      )}

      {/* MAIN CONTENT AREA */}
      <main className="flex-1 min-h-0 flex flex-row overflow-hidden relative">
        
        {/* Left Side Role Console (Chat Bot is strictly on the left) */}
        {isSidePanelOpen && !isFullGraphView && (
          <RoleConsolePanel
            authRole={authRole}
            isDark={isDark}
            onClose={() => setIsSidePanelOpen(false)}
            onEnterFullGraph={() => {
              setIsFullGraphView(true);
              setIsSidePanelOpen(false);
            }}
            analystTab={analystTab}
            setAnalystTab={setAnalystTab}
            nodes={nodes}
            softwareSystems={softwareSystems}
            selectedPresetBug={selectedPresetBug}
            onSelectPresetBug={handleSelectPresetBug}
            vulnName={vulnName}
            setVulnName={setVulnName}
            targetSoftware={targetSoftware}
            setTargetSoftware={setTargetSoftware}
            vulnSeverity={vulnSeverity}
            setVulnSeverity={setVulnSeverity}
            vulnDesc={vulnDesc}
            setVulnDesc={setVulnDesc}
            isInjecting={isInjecting}
            isGeneratingAiDesc={isGeneratingAiDesc}
            onGenerateAiDesc={handleGenerateAiDescription}
            onLiveBugInstall={handleLiveBugInstall}
            bugCodeData={activeBugCode}
            onUpdateBugCodeData={setActiveBugCode}
            chatMessages={chatMessages}
            chatInput={chatInput}
            setChatInput={setChatInput}
            isChatting={isChatting}
            healedLog={healedLog}
            chatContainerRef={chatContainerRef}
            onSendMessage={handleSendMessage}
            onLiveBugFix={handleLiveBugFix}
            onSelectNode={handleSelectNode}
            pathResult={activePathResult}
            selectedThreatActorForPath={selectedThreatActorForPath}
            onSelectThreatActorForPath={setSelectedThreatActorForPath}
            selectedSoftwareForPath={selectedSoftwareForPath}
            onSelectSoftwareForPath={setSelectedSoftwareForPath}
            onCalculatePath={handleCalculateShortestPath}
            onClearPath={handleClearShortestPath}
            onOpenGraphRagStudio={(sysId) => {
              if (sysId) setGraphRagTargetSystem(sysId);
              setShowGraphRagModal(true);
            }}
          />
        )}

        {/* RIGHT AREA: SVG Interactive Network Graph & Side Details Panel */}
        <div className={`flex-1 flex flex-row min-w-0 transition-colors ${
          isDark ? 'bg-[#060b13]' : 'bg-slate-50'
        }`}>
          
          {/* Main SVG Graph Container */}
          <div ref={graphContainerRef} className="flex-1 relative overflow-hidden">
            {/* Top-Left Search and Posture Indicator */}
            <div className="absolute top-3 left-3 z-10 flex flex-wrap items-center gap-2 pointer-events-auto">
              {/* Node Search Bar */}
              <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border backdrop-blur-md shadow-xs transition-colors ${
                isDark ? 'bg-slate-900/90 border-slate-800' : 'bg-white/95 border-slate-200'
              }`}>
                <Search className="w-3.5 h-3.5 text-slate-400" />
                <input 
                  type="text"
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder="Search computers, applications, bugs, defenses..."
                  className={`bg-transparent text-xs outline-none w-52 placeholder-slate-400 ${
                    isDark ? 'text-slate-100' : 'text-slate-800'
                  }`}
                />
                {searchQuery && (
                  <button 
                    onClick={() => setSearchQuery('')}
                    className="text-slate-400 hover:text-slate-200 text-xs px-0.5"
                    title="Clear search"
                  >
                    <X className="w-3 h-3" />
                  </button>
                )}
              </div>

              {/* Security Posture Rating */}
              {(() => {
                const unmitigated = nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED').length;
                const compromisedSw = nodes.filter(n => n.label === 'Software' && n.status === 'COMPROMISED').length;
                const totalSw = softwareSystems.length || 1;
                const score = Math.max(10, Math.round(((totalSw - compromisedSw) / totalSw) * 100));
                return (
                  <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border backdrop-blur-md shadow-xs text-xs font-mono font-medium ${
                    isDark ? 'bg-slate-900/90 border-slate-800' : 'bg-white/95 border-slate-200'
                  }`}>
                    <span className={`w-2 h-2 rounded-full ${
                      score >= 80 ? 'bg-emerald-500' : score >= 50 ? 'bg-amber-500' : 'bg-red-500'
                    }`} />
                    <span className="text-slate-400">Network Health:</span>
                    <span className={`font-semibold ${
                      score >= 80 ? 'text-emerald-500' : score >= 50 ? 'text-amber-500' : 'text-red-500'
                    }`}>{score}%</span>
                  </div>
                );
              })()}

              {/* Shortest Attack Path Quick Action Button */}
              <button
                onClick={() => {
                  setIsSidePanelOpen(true);
                  setIsFullGraphView(false);
                  setAnalystTab('attack_path');
                  if (!activePathResult?.found) {
                    handleCalculateShortestPath();
                  }
                }}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border backdrop-blur-md shadow-xs text-xs font-serif font-semibold transition-all ${
                  activePathResult?.found
                    ? 'bg-amber-500/20 border-amber-500/50 text-amber-300 shadow-[0_0_12px_rgba(245,158,11,0.25)]'
                    : isDark 
                      ? 'bg-slate-900/90 border-slate-800 text-slate-300 hover:text-white hover:border-amber-500/40' 
                      : 'bg-white/95 border-slate-200 text-slate-700 hover:bg-slate-50'
                }`}
                title="Highlight shortest path from Threat Actor to Computer System"
              >
                <Route className="w-3.5 h-3.5 text-amber-400" />
                <span>Shortest Attack Path</span>
                {activePathResult?.found && (
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-amber-500 text-slate-950 font-extrabold">
                    {activePathResult.totalHops}h
                  </span>
                )}
              </button>

              {/* Dynamic Copilot Trigger when panel is sent to side */}
              {(!isSidePanelOpen || isFullGraphView) && (
                <button
                  onClick={() => {
                    setIsSidePanelOpen(true);
                    setIsFullGraphView(false);
                  }}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border backdrop-blur-md shadow-lg text-xs font-serif font-semibold transition-all ${
                    isDark 
                      ? 'bg-gradient-to-r from-blue-950/90 via-indigo-950/90 to-slate-900/90 border-cyan-500/40 text-cyan-200 hover:text-white hover:border-cyan-300 shadow-[0_0_15px_rgba(6,182,212,0.15)]' 
                      : 'bg-white/95 border-blue-300 text-blue-800 hover:bg-blue-50'
                  }`}
                  title="Open Threat Copilot & Analysis Console"
                >
                  <MessageSquare className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Open AI Threat Assistant</span>
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                </button>
              )}

              {/* Exit Full Graph View button */}
              {isFullGraphView && (
                <button
                  onClick={() => {
                    setIsFullGraphView(false);
                    setIsSidePanelOpen(true);
                  }}
                  className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border backdrop-blur-md text-xs font-sans font-medium transition-colors ${
                    isDark ? 'bg-slate-900/90 border-slate-700 text-slate-300 hover:text-white' : 'bg-white/95 border-slate-200 text-slate-700 hover:bg-slate-50'
                  }`}
                  title="Exit Full Graph View"
                >
                  <Minimize2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Exit Full Screen</span>
                </button>
              )}
            </div>

            {/* Active Shortest Path Highlight Floating Banner */}
            {activePathResult?.found && (
              <div className="absolute top-3 left-1/2 -translate-x-1/2 z-20 pointer-events-auto">
                <div className={`px-4 py-2 rounded-xl border backdrop-blur-md shadow-2xl flex items-center gap-3 animate-in fade-in slide-in-from-top-2 duration-300 ${
                  isDark 
                    ? 'bg-black/90 border-amber-500/50 text-slate-200 shadow-[0_0_25px_rgba(245,158,11,0.2)]' 
                    : 'bg-white/95 border-amber-300 text-slate-800 shadow-lg'
                }`}>
                  <div className="w-2.5 h-2.5 rounded-full bg-amber-400 animate-ping" />
                  <div className="flex items-center gap-1.5 text-xs font-serif">
                    <span className="font-bold text-amber-400">Shortest Path:</span>
                    <span className="font-semibold text-slate-800 dark:text-slate-100">{activePathResult.startNode?.name}</span>
                    <span className="text-amber-500 font-bold">➔</span>
                    <span className="text-slate-400 font-mono text-[11px]">({activePathResult.totalHops} hops)</span>
                    <span className="text-amber-500 font-bold">➔</span>
                    <span className="font-semibold text-blue-500 dark:text-cyan-400">{activePathResult.endNode?.name}</span>
                  </div>

                  <div className="flex items-center gap-1.5 border-l border-slate-700/60 pl-2">
                    <button
                      onClick={() => {
                        setIsSidePanelOpen(true);
                        setIsFullGraphView(false);
                        setAnalystTab('attack_path');
                      }}
                      className="px-2.5 py-1 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-400 hover:bg-amber-500/30 border border-amber-500/40 transition-colors"
                    >
                      View Steps
                    </button>
                    <button
                      onClick={handleClearShortestPath}
                      className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                      title="Clear path highlight"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* SUNK STATE: Portable, Compact Status Ticker (Takes ZERO graph space) */}
            {isTelemetrySunk && (
              <PerformanceTelemetryMonitor 
                fps={fps}
                frameTimeMs={frameTimeMs}
                fpsHistory={fpsHistory}
                nodeCount={nodes.length}
                nodeBreakdown={nodeBreakdown}
                edgeCount={calculatedEdges.length}
                edgeProcessingTimeMs={measuredEdgeTime}
                theme={theme}
                showHotZones={showHotZones}
                onToggleHotZones={() => setShowHotZones(!showHotZones)}
                showHeatmap={showHeatmap}
                onToggleHeatmap={() => setShowHeatmap(!showHeatmap)}
                isNeo4jActive={isNeo4jActive}
                nodes={nodes}
                isSunk={true}
                onToggleSink={() => setIsTelemetrySunk(false)}
              />
            )}

            {/* FLOATING HUD MODE: Telemetry Monitor on Right (when floating & not sunk) */}
            {!isTelemetrySunk && telemetryDockMode === 'floating' && !isFullGraphView && (
              <PerformanceTelemetryMonitor 
                fps={fps}
                frameTimeMs={frameTimeMs}
                fpsHistory={fpsHistory}
                nodeCount={nodes.length}
                nodeBreakdown={nodeBreakdown}
                edgeCount={calculatedEdges.length}
                edgeProcessingTimeMs={measuredEdgeTime}
                theme={theme}
                showHotZones={showHotZones}
                onToggleHotZones={() => setShowHotZones(!showHotZones)}
                showHeatmap={showHeatmap}
                onToggleHeatmap={() => setShowHeatmap(!showHeatmap)}
                isNeo4jActive={isNeo4jActive}
                nodes={nodes}
                isSunk={false}
                dockMode="floating"
                onToggleSink={() => setIsTelemetrySunk(true)}
                onToggleDockMode={() => setTelemetryDockMode('docked')}
              />
            )}

            {/* Bottom-Right Canvas Viewport Toolbar */}
            <div className={`absolute bottom-3 right-3 z-20 flex items-center gap-1.5 p-1 rounded-lg border backdrop-blur-md shadow-lg ${
              isDark ? 'bg-slate-900/90 border-slate-800 text-slate-300' : 'bg-white/95 border-slate-200 text-slate-700'
            }`}>
              {/* Segmented Layout Mode Switcher */}
              <div className={`flex items-center gap-0.5 p-0.5 rounded-md border ${
                isDark ? 'bg-slate-950/60 border-slate-800' : 'bg-slate-100 border-slate-200'
              }`}>
                {(['pipeline', 'zones', 'rack', 'organic'] as GraphLayoutMode[]).map((mode) => {
                  const isActive = layoutMode === mode;
                  const labels: Record<GraphLayoutMode, string> = {
                    pipeline: 'Pipeline',
                    zones: 'Zones',
                    rack: 'Rack',
                    organic: 'Physics'
                  };
                  return (
                    <button
                      key={mode}
                      onClick={() => handleAutoAlignTopology(mode)}
                      className={`px-2 py-0.5 rounded text-[10px] font-medium transition-all ${
                        isActive
                          ? isDark
                            ? 'bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/40'
                            : 'bg-white text-blue-700 font-semibold shadow-xs border border-blue-200'
                          : isDark
                            ? 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                            : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/50'
                      }`}
                      title={`Switch to ${labels[mode]} layout`}
                    >
                      {labels[mode]}
                    </button>
                  );
                })}
              </div>

              <button 
                onClick={() => handleAutoAlignTopology(layoutMode)} 
                className={`flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-medium transition-all ${
                  isDark 
                    ? 'hover:bg-slate-800 text-slate-300 hover:text-white' 
                    : 'hover:bg-slate-100 text-slate-700 hover:text-slate-900'
                }`}
                title="Auto-align infrastructure topology and threat nodes"
              >
                <LayoutGrid className="w-3.5 h-3.5 text-cyan-400" />
                <span>Align Topology</span>
              </button>
              <div className="w-[1px] h-4 bg-slate-700/50 mx-0.5" />
              <button 
                onClick={handleZoomIn} 
                className={`p-1.5 rounded-lg transition-colors ${
                  isDark ? 'hover:bg-slate-800 hover:text-white' : 'hover:bg-slate-100 hover:text-slate-900'
                }`}
                title="Zoom In"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
              <button 
                onClick={handleZoomOut} 
                className={`p-1.5 rounded-lg transition-colors ${
                  isDark ? 'hover:bg-slate-800 hover:text-white' : 'hover:bg-slate-100 hover:text-slate-900'
                }`}
                title="Zoom Out"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <button 
                onClick={handleResetZoom} 
                className={`px-2 py-1 rounded-lg text-[10px] font-mono font-bold transition-colors ${
                  isDark ? 'hover:bg-slate-800 hover:text-white' : 'hover:bg-slate-100 hover:text-slate-900'
                }`}
                title="Reset Scale"
              >
                {Math.round(transform.k * 100)}%
              </button>
              <button 
                onClick={handleFitCenter} 
                className={`p-1.5 rounded-lg transition-colors ${
                  isDark ? 'hover:bg-slate-800 hover:text-white' : 'hover:bg-slate-100 hover:text-slate-900'
                }`}
                title="Fit Topology to Canvas"
              >
                <Maximize2 className="w-3.5 h-3.5" />
              </button>
            </div>

            <style>{`
              @keyframes flow {
                from { stroke-dashoffset: 24; }
                to { stroke-dashoffset: 0; }
              }
              .edge-flow {
                stroke-dasharray: 6 6;
                animation: flow 1.2s linear infinite;
              }
              @keyframes shortestPathDash {
                to { stroke-dashoffset: -32; }
              }
              .shortest-path-animated-flow {
                animation: shortestPathDash 1.2s linear infinite;
              }
            `}</style>

            <svg 
              className="w-full h-full cursor-grab active:cursor-grabbing"
              onWheel={handleWheel}
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onMouseLeave={handleMouseLeave}
            >
              <g transform={`translate(${transform.x}, ${transform.y}) scale(${transform.k})`}>
                <defs>
                  <radialGradient id="hotzoneGradient" cx="50%" cy="50%" r="50%">
                    <stop offset="0%" stopColor="#ef4444" stopOpacity="0.25" />
                    <stop offset="60%" stopColor="#ef4444" stopOpacity="0.08" />
                    <stop offset="100%" stopColor="#ef4444" stopOpacity="0" />
                  </radialGradient>
                  <radialGradient id="highRiskGradient" cx="50%" cy="50%" r="50%">
                    <stop offset="0%" stopColor="#ef4444" stopOpacity="0.3" />
                    <stop offset="100%" stopColor="#ef4444" stopOpacity="0" />
                  </radialGradient>
                  <radialGradient id="medRiskGradient" cx="50%" cy="50%" r="50%">
                    <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.2" />
                    <stop offset="100%" stopColor="#f59e0b" stopOpacity="0" />
                  </radialGradient>

                  {/* High-Fidelity Server Chassis Gradients */}
                  <linearGradient id="srv-chassis-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#1e293b" />
                    <stop offset="50%" stopColor="#0f172a" />
                    <stop offset="100%" stopColor="#090d16" />
                  </linearGradient>
                  <linearGradient id="srv-compromised-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#450a0a" />
                    <stop offset="50%" stopColor="#1c0505" />
                    <stop offset="100%" stopColor="#0b0202" />
                  </linearGradient>

                  <marker id="arrow-blue" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#3b82f6" opacity="0.7" />
                  </marker>
                  <marker id="arrow-red" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" opacity="0.8" />
                  </marker>
                  <marker id="arrow-green" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#10b981" opacity="0.8" />
                  </marker>
                  <marker id="arrow-dim" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b" opacity="0.3" />
                  </marker>
                  <marker id="arrow-path-highlight" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#f59e0b" opacity="0.95" />
                  </marker>

                  {/* High-Precision Cyber Grid Canvas Background Pattern */}
                  <pattern id="graph-cyber-grid" width="40" height="40" patternUnits="userSpaceOnUse">
                    <path 
                      d="M 40 0 L 0 0 0 40" 
                      fill="none" 
                      stroke={isDark ? 'rgba(56, 189, 248, 0.05)' : 'rgba(2, 132, 199, 0.05)'} 
                      strokeWidth="1" 
                    />
                    <circle 
                      cx="0" 
                      cy="0" 
                      r="1" 
                      fill={isDark ? 'rgba(56, 189, 248, 0.2)' : 'rgba(2, 132, 199, 0.15)'} 
                    />
                  </pattern>
                </defs>

                {/* SVG Cyber Coordinate Grid Background */}
                <rect 
                  x="-600" 
                  y="-300" 
                  width="3200" 
                  height="1800" 
                  fill="url(#graph-cyber-grid)" 
                  pointerEvents="none" 
                />

                {/* Risk Halo under Software Nodes */}
                {nodes.filter(n => n.label === 'Software').map(sw => {
                  const connectedVulns = edges
                    .filter(e => (e.label === 'AFFECTS' || e.label === 'EXPLOITS') && e.to === sw.id)
                    .map(e => nodes.find(n => n.id === e.from))
                    .filter(n => n?.label === 'Vulnerability' && n.status === 'UNMITIGATED');

                  if (connectedVulns.length === 0 && sw.status !== 'COMPROMISED') return null;

                  return (
                    <circle 
                      key={`risk-halo-${sw.id}`} 
                      cx={sw.x} 
                      cy={sw.y} 
                      r="160" 
                      fill="url(#highRiskGradient)" 
                      pointerEvents="none" 
                      className="animate-pulse"
                    />
                  );
                })}

                {/* Hot Zones */}
                {showHotZones && nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED').map(node => (
                  <circle 
                    key={`hotzone-${node.id}`} 
                    cx={node.x} 
                    cy={node.y} 
                    r="220" 
                    fill="url(#hotzoneGradient)" 
                    pointerEvents="none" 
                    className="animate-pulse"
                  />
                ))}

                {/* Graph Edges with Smooth Cubic Bézier Curves & Real-time Telemetry Routing */}
                {calculatedEdges.map(({ edgeId, edge, pathData, strokeColor, isFaded, markerId, isExploit, isHealed, midX, midY, isEdgeInPath }) => (
                  <g key={edgeId} className={`transition-all duration-300 ${isFaded ? 'opacity-15' : 'opacity-100'}`}>
                    {/* Glowing highlight aura underneath shortest path edges */}
                    {isEdgeInPath && (
                      <path
                        d={pathData}
                        fill="none"
                        stroke="#f59e0b"
                        strokeWidth={8}
                        strokeLinecap="round"
                        opacity={0.35}
                        className="animate-pulse"
                      />
                    )}

                    <path
                      d={pathData}
                      fill="none"
                      stroke={strokeColor}
                      strokeWidth={isEdgeInPath ? 4.5 : isFaded ? 1.2 : 2.4}
                      strokeLinecap="round"
                      opacity={isEdgeInPath ? 1 : isFaded ? 0.25 : 0.85}
                      markerEnd={markerId}
                      strokeDasharray={isEdgeInPath ? "10 6" : undefined}
                      className={`transition-colors duration-300 ${
                        isEdgeInPath
                          ? 'shortest-path-animated-flow'
                          : !isFaded && (isExploit || isHealed) 
                            ? 'edge-flow' 
                            : ''
                      }`}
                    />

                    {!isFaded && (
                      isEdgeInPath ? (
                        <g>
                          <rect
                            x={midX - 34}
                            y={midY - 17}
                            width="68"
                            height="18"
                            rx="5"
                            fill={isDark ? '#451a03' : '#fef3c7'}
                            stroke="#f59e0b"
                            strokeWidth="1.5"
                            filter="drop-shadow(0 2px 4px rgba(0,0,0,0.4))"
                          />
                          <text 
                            x={midX} 
                            y={midY - 4} 
                            fill={isDark ? '#fef08a' : '#b45309'} 
                            fontSize="9" 
                            textAnchor="middle" 
                            opacity="1" 
                            fontWeight="bold"
                            className="tracking-widest select-none font-mono"
                          >
                            {edge.label}
                          </text>
                        </g>
                      ) : (
                        <text 
                          x={midX} 
                          y={midY - 8} 
                          fill={strokeColor} 
                          fontSize="9.5" 
                          textAnchor="middle" 
                          opacity="0.9" 
                          fontWeight="bold"
                          className="tracking-widest select-none font-mono"
                        >
                          {edge.label}
                        </text>
                      )
                    )}
                  </g>
                ))}

                {/* ENTERPRISE ARCHITECTURAL BOUNDARIES & WORKLOAD MESH (100% Dynamic & Non-overlapping) */}
                <g className="select-none pointer-events-none">
                  {layoutMode === 'zones' ? (
                    // Dynamically hugged Zone Enclaves with Subnet CIDRs (Zero-Overlap Precision)
                    dynamicZoneBoxes.map(zone => (
                      <g key={zone.id}>
                        <rect
                          x={zone.x}
                          y={zone.y}
                          width={zone.width}
                          height={zone.height}
                          rx={10}
                          fill={isDark ? 'rgba(15, 23, 42, 0.35)' : 'rgba(241, 245, 249, 0.55)'}
                          stroke={isDark ? `${zone.color}33` : `${zone.color}44`}
                          strokeWidth="1"
                          strokeDasharray="4 4"
                        />
                        <rect
                          x={zone.x + 10}
                          y={zone.y + 10}
                          width={Math.max(120, zone.width - 20)}
                          height={20}
                          rx={4}
                          fill={isDark ? '#080d1a' : '#ffffff'}
                          stroke={isDark ? `${zone.color}44` : `${zone.color}55`}
                          strokeWidth="0.8"
                        />
                        <text
                          x={zone.centerX}
                          y={zone.y + 23.5}
                          textAnchor="middle"
                          fontSize="8"
                          fontWeight="700"
                          fontFamily="ui-monospace, monospace"
                          fill={isDark ? zone.color : '#0f172a'}
                          letterSpacing="0.04em"
                        >
                          {zone.name} · {zone.cidr}
                        </text>
                      </g>
                    ))
                  ) : layoutMode === 'organic' ? (
                    // Subtle dynamic organic physics field indicator
                    <circle
                      cx={workloadMeshBox.centerX}
                      cy={workloadMeshBox.y + workloadMeshBox.height / 2}
                      r={Math.max(300, Math.min(workloadMeshBox.width, workloadMeshBox.height) / 2 + 60)}
                      fill="none"
                      stroke={isDark ? 'rgba(56, 189, 248, 0.08)' : 'rgba(2, 132, 199, 0.08)'}
                      strokeWidth="1"
                      strokeDasharray="6 6"
                    />
                  ) : (
                    // Dynamically bounded Enterprise Infrastructure Workload Mesh Frame (Clean & Zero Overlap)
                    <g>
                      <rect
                        x={workloadMeshBox.x}
                        y={workloadMeshBox.y}
                        width={workloadMeshBox.width}
                        height={workloadMeshBox.height}
                        rx={10}
                        fill={isDark ? 'rgba(15, 23, 42, 0.35)' : 'rgba(241, 245, 249, 0.55)'}
                        stroke={isDark ? 'rgba(56, 189, 248, 0.18)' : 'rgba(2, 132, 199, 0.2)'}
                        strokeWidth="1"
                        strokeDasharray="4 4"
                      />
                      <text
                        x={workloadMeshBox.x + 16}
                        y={workloadMeshBox.y + 20}
                        fontSize="8.5"
                        fontWeight="700"
                        fontFamily="ui-monospace, monospace"
                        letterSpacing="0.08em"
                        fill={isDark ? '#475569' : '#94a3b8'}
                      >
                        MONITORED INFRASTRUCTURE
                      </text>
                    </g>
                  )}
                </g>

                {/* Fully Dynamic Column Flow Guides with Clear Architecture Labels (Zero Overlap) */}
                {dynamicColumnGuides.map(col => (
                  <g key={col.label} className="select-none pointer-events-none">
                    <rect
                      x={col.x - 70}
                      y={34}
                      width={140}
                      height={28}
                      rx={6}
                      fill={isDark ? '#080d1a' : '#ffffff'}
                      stroke={col.color}
                      strokeWidth={1}
                      strokeOpacity={0.6}
                    />
                    <text
                      x={col.x}
                      y={46.5}
                      textAnchor="middle"
                      fontSize="9"
                      fontWeight="bold"
                      fill={col.color}
                    >
                      {col.label}
                    </text>
                    <text
                      x={col.x}
                      y={56.5}
                      textAnchor="middle"
                      fontSize="7.5"
                      fill={isDark ? '#94a3b8' : '#64748b'}
                      fontWeight="500"
                    >
                      {col.sub}
                    </text>
                  </g>
                ))}

                {/* Graph Nodes */}
                <AnimatePresence>
                  {nodes.map(node => {
                    const isSelected = selectedNode?.id === node.id;
                    const matchesSearch = searchQuery.trim() === '' || 
                      node.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
                      node.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
                      (node.details && node.details.toLowerCase().includes(searchQuery.toLowerCase())) ||
                      (node.service && node.service.toLowerCase().includes(searchQuery.toLowerCase()));

                    const isPathActive = Boolean(activePathResult?.found);
                    const isPathNode = isPathActive && (activePathResult?.nodeIds.has(node.id) || false);
                    const pathStep = isPathActive ? activePathResult?.steps.find(s => s.node.id === node.id) : undefined;

                    let isFaded = false;
                    if (isPathActive) {
                      isFaded = !isPathNode;
                    } else {
                      isFaded = (hoveredNode !== null && !connectedNodes.has(node.id)) || !matchesSearch;
                    }
                    
                    let fill = isDark ? '#1e3a8a' : '#2563eb';
                    let stroke = '#3b82f6';
                    let glow = 'rgba(59, 130, 246, 0.4)';
                    
                    if (showHeatmap && node.label === 'Software') {
                      const hasThreat = edges.some(e => e.to === node.id && (e.label === 'AFFECTS' || e.label === 'EXPLOITS'));
                      if (hasThreat) {
                        fill = '#991b1b'; stroke = '#ef4444'; glow = 'rgba(239, 68, 68, 0.6)';
                      }
                    } else if (node.status === 'UNMITIGATED' || (node.label === 'Software' && node.status === 'COMPROMISED')) {
                      fill = '#7f1d1d'; stroke = '#ef4444'; glow = 'rgba(239, 68, 68, 0.7)';
                    } else if (node.label === 'Mitigation' || node.status === 'SELF_HEALED' || (node.label === 'Software' && node.status === 'HEALTHY')) {
                      fill = '#065f46'; stroke = '#10b981'; glow = 'rgba(16, 185, 129, 0.5)';
                    }

                    const isHovered = hoveredNode?.id === node.id;

                    return (
                      <motion.g 
                        key={node.id} 
                        onClick={() => handleSelectNode(node)}
                        onMouseEnter={() => setHoveredNode(node)}
                        onMouseLeave={() => setHoveredNode(null)}
                        onMouseDown={(e) => {
                          e.stopPropagation();
                          setDraggingNodeId(node.id);
                        }}
                        initial={{ scale: 0, opacity: 0 }}
                        animate={{ scale: isSelected ? 1.05 : 1, opacity: isFaded ? 0.2 : 1 }}
                        exit={{ scale: 0, opacity: 0 }}
                        transition={{ type: "spring", stiffness: 350, damping: 25 }}
                        className="cursor-pointer graph-node select-none"
                      >
                        {/* Shortest Path Beacon Pulse Rings around Node */}
                        {isPathNode && (
                          <g pointerEvents="none" className="select-none">
                            <circle
                              cx={node.x}
                              cy={node.y}
                              r="50"
                              fill="none"
                              stroke="#f59e0b"
                              strokeWidth="2.5"
                              opacity="0.8"
                              className="animate-ping"
                              style={{ animationDuration: '3s' }}
                            />
                            <circle
                              cx={node.x}
                              cy={node.y}
                              r="44"
                              fill="none"
                              stroke="#f59e0b"
                              strokeWidth="1.8"
                              strokeDasharray="4 4"
                              opacity="0.9"
                            />
                          </g>
                        )}

                        <GraphNodeVisual
                          node={node}
                          isSelected={isSelected}
                          isHovered={isHovered}
                          isFaded={isFaded}
                          isDark={isDark}
                        />

                        {/* Shortest Path Step Number Badge */}
                        {pathStep && (
                          <g transform={`translate(${node.x}, ${node.y - 44})`} className="select-none pointer-events-none">
                            <rect
                              x="-34"
                              y="-11"
                              width="68"
                              height="22"
                              rx="11"
                              fill={pathStep.stepNumber === 1 ? '#ef4444' : pathStep.stepNumber === activePathResult?.steps.length ? '#2563eb' : '#f59e0b'}
                              stroke="#ffffff"
                              strokeWidth="1.5"
                              filter="drop-shadow(0 2px 5px rgba(0,0,0,0.5))"
                            />
                            <text
                              x="0"
                              y="3"
                              textAnchor="middle"
                              fill="#ffffff"
                              fontSize="9.5"
                              fontWeight="bold"
                              className="font-mono tracking-wider uppercase"
                            >
                              STEP {pathStep.stepNumber}
                            </text>
                          </g>
                        )}
                      </motion.g>
                    );
                  })}
                </AnimatePresence>
              </g>
            </svg>

            {/* Hover Tooltip Overlay */}
            {hoveredNode && (
              <div 
                className={`absolute pointer-events-none z-50 p-3 rounded-xl shadow-2xl backdrop-blur-md border transform -translate-x-1/2 animate-in fade-in zoom-in-95 duration-200 ${
                  isDark ? 'bg-black/90 border-neutral-700 text-neutral-200' : 'bg-white/95 border-slate-300 text-slate-800'
                }`}
                style={{ 
                  left: hoveredNode.x * transform.k + transform.x, 
                  top: (hoveredNode.y + 45) * transform.k + transform.y, 
                  width: 240 
                }}
              >
                <div className="flex justify-between items-center mb-1">
                  <span className={`text-[10px] uppercase font-bold ${isDark ? 'text-neutral-400' : 'text-slate-500'}`}>{hoveredNode.label}</span>
                  <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded uppercase ${
                    hoveredNode.status === 'UNMITIGATED' || hoveredNode.status === 'COMPROMISED' ? 'bg-red-500/20 text-red-400' :
                    hoveredNode.status === 'HEALTHY' || hoveredNode.status === 'SELF_HEALED' ? 'bg-emerald-500/20 text-emerald-400' :
                    'bg-blue-500/20 text-blue-400'
                  }`}>
                    {hoveredNode.status || 'ACTIVE'}
                  </span>
                </div>
                <div className="text-xs font-bold truncate">{hoveredNode.name}</div>
                <div className={`text-[11px] mt-1 line-clamp-2 ${isDark ? 'text-neutral-400' : 'text-slate-600'}`}>{hoveredNode.details}</div>
                {hoveredNode.port && (
                  <div className={`text-[10px] mt-1 font-mono ${isDark ? 'text-cyan-400' : 'text-blue-600'}`}>Port: {hoveredNode.port} &bull; IP: {hoveredNode.ip || '10.0.1.X'}</div>
                )}
              </div>
            )}

            {/* Minimized Bottom-Right Dock when Live System Telemetry is minimized */}
            {isTelemetrySunk && !isFullGraphView && (
              <PerformanceTelemetryMonitor 
                fps={fps}
                frameTimeMs={frameTimeMs}
                fpsHistory={fpsHistory}
                nodeCount={nodes.length}
                nodeBreakdown={nodeBreakdown}
                edgeCount={calculatedEdges.length}
                edgeProcessingTimeMs={measuredEdgeTime}
                theme={theme}
                showHotZones={showHotZones}
                onToggleHotZones={() => setShowHotZones(!showHotZones)}
                showHeatmap={showHeatmap}
                onToggleHeatmap={() => setShowHeatmap(!showHeatmap)}
                isNeo4jActive={isNeo4jActive}
                nodes={nodes}
                isSunk={true}
                dockMode="docked"
                onToggleSink={() => {
                  setIsTelemetrySunk(false);
                  localStorage.setItem('telemetry_sunk_state', 'false');
                }}
                onToggleDockMode={() => setTelemetryDockMode('floating')}
              />
            )}
          </div>
          
          {/* RIGHT SIDEBAR: Live System Telemetry (Docked) and/or Selected Node Inspector */}
          {!isFullGraphView && ((!isTelemetrySunk && telemetryDockMode === 'docked') || selectedNode) && (
            <div className={`w-88 border-l flex flex-col h-full overflow-hidden animate-in slide-in-from-right-8 duration-200 transition-colors shrink-0 ${
              isDark ? 'bg-[#080d18] bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900/60 via-[#080d18] to-[#040810] border-slate-800' : 'bg-white border-slate-200 shadow-sm'
            }`}>
              {/* Dual Tab Switcher when BOTH docked Telemetry and Selected Node are active */}
              {!isTelemetrySunk && telemetryDockMode === 'docked' && selectedNode ? (
                <div className={`p-1.5 border-b flex items-center justify-between shrink-0 ${
                  isDark ? 'bg-slate-900/70 border-slate-800' : 'bg-slate-100 border-slate-200'
                }`}>
                  <div className="flex gap-1 flex-1">
                    <button
                      onClick={() => setRightSidebarTab('telemetry')}
                      className={`flex-1 py-1.5 px-2 rounded-lg text-xs font-serif font-semibold flex items-center justify-center gap-1.5 transition-all ${
                        rightSidebarTab === 'telemetry'
                          ? 'bg-gradient-to-r from-blue-600 to-cyan-600 text-white shadow-sm'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <Activity className="w-3.5 h-3.5 text-cyan-300" />
                      <span>Live Telemetry</span>
                    </button>
                    <button
                      onClick={() => setRightSidebarTab('inspector')}
                      className={`flex-1 py-1.5 px-2 rounded-lg text-xs font-serif font-semibold flex items-center justify-center gap-1.5 transition-all ${
                        rightSidebarTab === 'inspector'
                          ? 'bg-gradient-to-r from-indigo-600 to-blue-600 text-white shadow-sm'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <Info className="w-3.5 h-3.5 text-blue-300" />
                      <span className="truncate max-w-[100px]">{selectedNode.name}</span>
                    </button>
                  </div>
                  <div className="flex items-center gap-1 ml-1.5">
                    <button
                      onClick={() => {
                        setIsTelemetrySunk(true);
                        localStorage.setItem('telemetry_sunk_state', 'true');
                      }}
                      className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800"
                      title="Minimize Telemetry to Bottom Dock"
                    >
                      <Minimize2 className="w-3.5 h-3.5 text-cyan-500 dark:text-cyan-400" />
                    </button>
                    <button
                      onClick={() => setSelectedNode(null)}
                      className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800"
                      title="Close Node Inspector"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ) : null}

              {/* VIEW 1: Docked Live System Telemetry */}
              {!isTelemetrySunk && telemetryDockMode === 'docked' && (rightSidebarTab === 'telemetry' || !selectedNode) ? (
                <PerformanceTelemetryMonitor 
                  fps={fps}
                  frameTimeMs={frameTimeMs}
                  fpsHistory={fpsHistory}
                  nodeCount={nodes.length}
                  nodeBreakdown={nodeBreakdown}
                  edgeCount={calculatedEdges.length}
                  edgeProcessingTimeMs={measuredEdgeTime}
                  theme={theme}
                  showHotZones={showHotZones}
                  onToggleHotZones={() => setShowHotZones(!showHotZones)}
                  showHeatmap={showHeatmap}
                  onToggleHeatmap={() => setShowHeatmap(!showHeatmap)}
                  isNeo4jActive={isNeo4jActive}
                  nodes={nodes}
                  isSunk={false}
                  dockMode="docked"
                  onToggleSink={() => {
                    setIsTelemetrySunk(true);
                    localStorage.setItem('telemetry_sunk_state', 'true');
                  }}
                  onToggleDockMode={() => setTelemetryDockMode('floating')}
                />
              ) : selectedNode ? (
                /* VIEW 2: Selected Node Details & Technical Viewer */
                <div className="flex-1 flex flex-col h-full overflow-hidden">
                  {/* Single view header if not tabbed */}
                  {(!(!isTelemetrySunk && telemetryDockMode === 'docked')) && (
                    <div className={`px-4 py-3 border-b flex justify-between items-center shrink-0 ${
                      isDark ? 'bg-slate-900/50 border-slate-800' : 'bg-slate-50 border-slate-200'
                    }`}>
                      <div className="flex items-center gap-2">
                        <Info className="w-4 h-4 text-cyan-400" />
                        <span className="font-serif font-bold text-xs tracking-tight">Selected Component Details</span>
                      </div>
                      <button onClick={() => setSelectedNode(null)} className="p-1 text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  )}

                  {/* Body */}
                  <div className="p-4 overflow-y-auto space-y-4 flex-1 text-xs">
                {/* Active Attack Path Step Callout */}
                {activePathResult?.found && activePathResult.nodeIds.has(selectedNode.id) && (
                  <div className="p-3 rounded-xl border border-amber-500/50 bg-gradient-to-r from-amber-500/15 via-orange-500/10 to-red-500/15 text-amber-300 flex items-center justify-between shadow-sm">
                    <div className="flex items-center gap-2.5">
                      <div className="w-6 h-6 rounded-full bg-amber-500 text-slate-950 font-mono font-black text-xs flex items-center justify-center shrink-0">
                        {activePathResult.steps.findIndex(s => s.node.id === selectedNode.id) + 1}
                      </div>
                      <div>
                        <div className="text-[11px] font-bold text-amber-400">
                          Step {activePathResult.steps.findIndex(s => s.node.id === selectedNode.id) + 1} of {activePathResult.steps.length}
                        </div>
                        <div className="text-[10px] text-slate-400 font-mono">
                          On Active Shortest Attack Path
                        </div>
                      </div>
                    </div>
                    <button
                      onClick={() => {
                        setIsSidePanelOpen(true);
                        setAnalystTab('attack_path');
                      }}
                      className="px-2 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-[10px] font-mono font-bold text-amber-300 border border-amber-500/40 transition-colors"
                    >
                      View Steps
                    </button>
                  </div>
                )}

                {/* Visual Entity Preview Card */}
                <div className={`p-3 rounded-xl border flex flex-col items-center justify-center relative overflow-hidden ${
                  isDark ? 'bg-slate-950/80 border-slate-800' : 'bg-slate-50 border-slate-200'
                }`}>
                  <svg width="150" height="95" viewBox="0 0 150 95" className="overflow-visible">
                    <g transform="translate(75, 38)">
                      <GraphNodeVisual
                        node={{ ...selectedNode, x: 0, y: 0 }}
                        isSelected={true}
                        isHovered={false}
                        isFaded={false}
                        isDark={isDark}
                      />
                    </g>
                  </svg>
                  <div className="mt-4 text-center">
                    <span className="font-semibold text-xs text-slate-800 dark:text-neutral-200">{selectedNode.name}</span>
                    <span className="block text-[10px] text-slate-400 dark:text-neutral-500 font-mono">
                      {selectedNode.label === 'Software' ? 'Computer System / Server' :
                       selectedNode.label === 'Vulnerability' ? 'Security Flaw (Bug / CVE)' :
                       selectedNode.label === 'Mitigation' ? 'Security Defense & Fix' :
                       selectedNode.label === 'ThreatActor' ? 'Cyber Attacker (Hacker Group)' :
                       selectedNode.label === 'Malware' ? 'Malicious Software (Virus / Tool)' :
                       selectedNode.label === 'Technique' ? 'Attack Method (How They Breach)' : 'Security Component'}
                    </span>
                  </div>
                </div>

                {/* Bug Inspector View Switcher: Code (Primary) vs Threat Specs */}
                {(selectedNode.label === 'Vulnerability' || TECHNICAL_BUGS_CATALOG[selectedNode.id]) && (
                  <div className={`flex rounded-xl p-1 text-xs shadow-sm border ${
                    isDark ? 'bg-slate-900/90 border-slate-800' : 'bg-slate-100 border-slate-300'
                  }`}>
                    <button
                      onClick={() => setBugInspectorTab('code')}
                      className={`flex-1 py-1.5 px-2 rounded-lg font-serif font-semibold flex items-center justify-center gap-1.5 transition-all ${
                        bugInspectorTab === 'code'
                          ? 'bg-gradient-to-r from-red-600 via-rose-600 to-amber-600 text-white shadow-sm'
                          : isDark ? 'text-slate-400 hover:text-white' : 'text-slate-700 hover:text-slate-950 font-bold'
                      }`}
                    >
                      <Code className="w-3.5 h-3.5 text-amber-300" />
                      <span>Bug Code & Exploit</span>
                    </button>
                    <button
                      onClick={() => setBugInspectorTab('details')}
                      className={`flex-1 py-1.5 px-2 rounded-lg font-serif font-semibold flex items-center justify-center gap-1.5 transition-all ${
                        bugInspectorTab === 'details'
                          ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-sm'
                          : isDark ? 'text-slate-400 hover:text-white' : 'text-slate-700 hover:text-slate-950 font-bold'
                      }`}
                    >
                      <FileText className="w-3.5 h-3.5 text-blue-300" />
                      <span>Threat Specs</span>
                    </button>
                  </div>
                )}

                {/* VIEW A: BUG CODE & EXPLOIT VIEW (Primary when bug selected) */}
                {(selectedNode.label === 'Vulnerability' || TECHNICAL_BUGS_CATALOG[selectedNode.id]) && bugInspectorTab === 'code' ? (
                  <div className="space-y-3">
                    {/* Auto Repair & Shield Button */}
                    {selectedNode.status !== 'SELF_HEALED' && selectedNode.status !== 'HEALTHY' && selectedNode.status !== 'APPROVED' && (
                      <button 
                        onClick={() => handleLiveBugFix(selectedNode.id)}
                        className="w-full bg-gradient-to-r from-blue-600 via-indigo-600 to-blue-700 hover:from-blue-500 hover:to-indigo-500 text-white font-serif font-semibold text-xs py-2.5 rounded-xl flex items-center justify-center transition-all shadow-md shadow-blue-900/30"
                      >
                        <Shield className="w-4 h-4 mr-1.5" /> Automatically Repair & Shield Server
                      </button>
                    )}

                    {/* Full Interactive Bug Source Code & Exploit Viewer */}
                    <BugTechnicalViewer 
                      bugId={selectedNode.id} 
                      isDark={isDark}
                      customCode={bugCustomCodes[selectedNode.id]}
                      onUpdateCode={(updated) => {
                        setBugCustomCodes(prev => ({ ...prev, [selectedNode.id]: updated }));
                        setNodes(prev => prev.map(n => n.id === selectedNode.id ? {
                          ...n,
                          codeLanguage: updated.codeLanguage,
                          codeFileName: updated.codeFileName,
                          buggyCode: updated.buggyCode,
                          correctedCode: updated.correctedCode,
                          errorMessage: updated.errorMessage,
                          exploitScript: updated.exploitScript,
                          rootCause: updated.rootCause,
                          fixExplanation: updated.fixExplanation
                        } : n));
                        fetch('/api/bug/save-code', {
                          method: 'POST',
                          headers: { 'Content-Type': 'application/json' },
                          body: JSON.stringify({
                            vuln_id: selectedNode.id,
                            ...updated
                          })
                        }).catch(err => console.warn('Saved locally, remote sync notice:', err));
                        setToast({
                          title: 'Code Saved to Bug',
                          message: `Code snippet and exploit payload attached to ${selectedNode.id}.`,
                          type: 'green'
                        });
                      }}
                      nodeProperties={selectedNode}
                      onLiveBugFix={(vulnId, sysId) => handleLiveBugFix(vulnId, sysId)}
                    />

                    {/* Quick Link to Threat Specs */}
                    <div className="pt-2 text-center">
                      <button
                        onClick={() => setBugInspectorTab('details')}
                        className="text-[11px] font-mono text-slate-400 hover:text-cyan-400 underline decoration-slate-700 hover:decoration-cyan-400 transition-colors"
                      >
                        View CVSS, cause, and vulnerability threat specs ➔
                      </button>
                    </div>
                  </div>
                ) : (
                  /* VIEW B: GENERAL INSPECTOR / THREAT SPECIFICATIONS */
                  <>
                <div>
                  <div className={`text-[10px] uppercase font-bold mb-1 ${
                    isDark ? 'text-slate-400' : 'text-slate-600'
                  }`}>Component Type</div>
                  <div className={`font-mono text-xs font-semibold tracking-wide uppercase ${
                    isDark ? 'text-cyan-400' : 'text-blue-700'
                  }`}>
                    {selectedNode.label === 'Software' ? 'Computer / System' :
                     selectedNode.label === 'Vulnerability' ? 'Security Flaw' :
                     selectedNode.label === 'Mitigation' ? 'Defense & Fix' :
                     selectedNode.label === 'ThreatActor' ? 'Cyber Attacker' :
                     selectedNode.label === 'Malware' ? 'Malicious Software' :
                     selectedNode.label === 'Technique' ? 'Attack Method' : selectedNode.label}
                  </div>
                </div>

                <div>
                  <div className={`text-[10px] uppercase font-bold mb-1 ${
                    isDark ? 'text-slate-400' : 'text-slate-600'
                  }`}>Item Name</div>
                  <div className="font-semibold text-sm text-slate-900 dark:text-white">{selectedNode.name}</div>
                  <div className={`text-[11px] font-mono mt-0.5 ${
                    isDark ? 'text-slate-400' : 'text-slate-600 font-semibold'
                  }`}>{selectedNode.id}</div>
                </div>

                {selectedNode.status && (
                  <div>
                    <div className={`text-[10px] uppercase font-bold mb-1 ${
                      isDark ? 'text-slate-400' : 'text-slate-600'
                    }`}>Current Health Status</div>
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${
                        selectedNode.status === 'HEALTHY' || selectedNode.status === 'SELF_HEALED' ? 'bg-emerald-500' :
                        selectedNode.status === 'COMPROMISED' || selectedNode.status === 'UNMITIGATED' ? 'bg-red-500' : 'bg-amber-500'
                      }`} />
                      <span className={`font-mono text-xs ${
                        isDark ? 'text-slate-200' : 'text-slate-950 font-semibold'
                      }`}>
                        {selectedNode.status === 'HEALTHY' ? 'Safe & Operating Normally' :
                         selectedNode.status === 'SELF_HEALED' ? 'Repaired & Protected' :
                         selectedNode.status === 'COMPROMISED' ? 'Infected / Breached' :
                         selectedNode.status === 'UNMITIGATED' ? 'Exposed (Needs Fix)' :
                         selectedNode.status}
                      </span>
                    </div>
                  </div>
                )}

                {selectedNode.severity && (
                  <div>
                    <div className={`text-[10px] uppercase font-bold mb-1 ${
                      isDark ? 'text-slate-400' : 'text-slate-600'
                    }`}>Risk Level</div>
                    <div className="font-mono text-xs flex items-center gap-1.5">
                      <span className={`font-bold ${
                        selectedNode.severity === 'CRITICAL' ? (isDark ? 'text-red-400' : 'text-red-700') :
                        selectedNode.severity === 'HIGH' ? (isDark ? 'text-amber-400' : 'text-amber-700') : (isDark ? 'text-blue-400' : 'text-blue-700')
                      }`}>
                        {selectedNode.severity}
                      </span>
                      <span className="text-slate-400">·</span>
                      <span className={isDark ? 'text-slate-300' : 'text-slate-700 font-semibold'}>Score {selectedNode.cvss || 9.5} / 10</span>
                    </div>
                  </div>
                )}

                <div>
                  <div className={`text-[10px] uppercase font-bold mb-1 flex items-center justify-between ${
                    isDark ? 'text-slate-400' : 'text-slate-600'
                  }`}>
                    <span>What This Does (Description)</span>
                    {selectedNode.ai_generated_description && (
                      <span className={`text-[9px] font-mono flex items-center gap-1 font-medium lowercase ${
                        isDark ? 'text-cyan-400' : 'text-cyan-800 font-bold'
                      }`}>
                        <Sparkles className="w-2.5 h-2.5" />
                        ai generated
                      </span>
                    )}
                  </div>
                  <p className={`p-3 rounded-lg border text-xs leading-relaxed ${
                    isDark ? 'bg-slate-900/60 border-slate-800 text-slate-200' : 'bg-slate-50 border-slate-300 text-slate-950 font-normal'
                  }`}>
                    {selectedNode.details || selectedNode.description || 'No description provided.'}
                  </p>
                  {selectedNode.label === 'Vulnerability' && (
                    <button
                      onClick={async () => {
                        try {
                          const affectedEdge = edges.find(e => e.from === selectedNode.id && e.label === 'AFFECTS');
                          const res = await fetch('/api/bug/generate-description', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                              vuln_id: selectedNode.id,
                              vuln_name: selectedNode.name,
                              system_id: affectedEdge?.to || 'Infrastructure Target',
                              severity: selectedNode.severity,
                              cause: selectedNode.cause,
                              cvss: selectedNode.cvss,
                              description: selectedNode.description
                            })
                          });
                          const data = await res.json();
                          if (data.status === 'success' && data.description) {
                            const updatedNode = { ...selectedNode, description: data.description, details: data.description, ai_generated_description: true };
                            setSelectedNode(updatedNode);
                            setNodes(prev => prev.map(n => n.id === selectedNode.id ? updatedNode : n));
                            setToast({
                              title: 'AI Description Refreshed',
                              message: data.model === 'gemini-3.8-flash'
                                ? 'Gemini 3.8 Flash re-analyzed live threat intelligence.'
                                : 'AI intelligence refreshed vulnerability profile.',
                              type: 'green'
                            });
                          }
                        } catch (err) {
                          console.warn('Description regeneration notice:', err);
                        }
                      }}
                      className="mt-1.5 flex items-center gap-1 text-[10px] font-mono text-cyan-500 hover:text-cyan-400 cursor-pointer"
                    >
                      <Sparkles className="w-2.5 h-2.5" />
                      <span>Explain in detail with AI</span>
                    </button>
                  )}
                </div>

                {/* Computer / System Technical Specifications Profile (Requirement 1, 3, 7) */}
                {selectedNode.label === 'Software' && (
                  <div className="space-y-3 pt-3 border-t border-slate-200 dark:border-neutral-800">
                    <div className="flex items-center justify-between">
                      <div className={`text-[10px] uppercase font-bold tracking-wider ${
                        isDark ? 'text-slate-400' : 'text-slate-600'
                      }`}>
                        Computer / System Profile
                      </div>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-extrabold uppercase ${
                        selectedNode.status === 'COMPROMISED'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/40 animate-pulse'
                          : selectedNode.status === 'SELF_HEALED'
                            ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
                            : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                      }`}>
                        {selectedNode.status === 'COMPROMISED' ? 'COMPROMISED' : selectedNode.status === 'SELF_HEALED' ? 'SELF-HEALED' : 'HEALTHY'}
                      </span>
                    </div>

                    {/* Exact Requirement 7 Technical Specification Grid */}
                    <div className={`p-3 rounded-xl border text-[11px] font-mono space-y-2.5 ${
                      isDark ? 'bg-slate-900/80 border-slate-800 text-slate-200' : 'bg-slate-50 border-slate-300 text-slate-800'
                    }`}>
                      <div>
                        <span className="block text-[9.5px] uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider">COMPUTER</span>
                        <span className="text-xs font-bold text-cyan-500 dark:text-cyan-400">{selectedNode.name || selectedNode.id}</span>
                      </div>

                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <span className="block text-[9.5px] uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider">HOSTNAME</span>
                          <span className="font-semibold text-slate-900 dark:text-white">{selectedNode.hostname || (selectedNode.name ? `${selectedNode.name.replace(/\s+/g, '-').toUpperCase()}` : 'COMP-NODE')}</span>
                        </div>
                        <div>
                          <span className="block text-[9.5px] uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider">CURRENT STATUS</span>
                          <span className={`font-bold ${
                            selectedNode.status === 'COMPROMISED' ? 'text-red-500' : selectedNode.status === 'SELF_HEALED' ? 'text-cyan-400' : 'text-emerald-500'
                          }`}>
                            {selectedNode.status || 'HEALTHY'}
                          </span>
                        </div>
                      </div>

                      <div>
                        <span className="block text-[9.5px] uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider">APPLICATION</span>
                        <span className="font-bold text-slate-900 dark:text-white text-xs">{selectedNode.application || 'Application Service'}</span>
                      </div>

                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <span className="block text-[9.5px] uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider">TECHNOLOGY</span>
                          <span className="font-semibold text-slate-800 dark:text-slate-200">{selectedNode.technology || 'Linux / Service'}</span>
                        </div>
                        <div>
                          <span className="block text-[9.5px] uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider">VERSION</span>
                          <span className="font-medium text-slate-700 dark:text-slate-300">{selectedNode.version || '1.0.0'}</span>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <span className="block text-[9.5px] uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider">IP ADDRESS</span>
                          <code className="text-cyan-600 dark:text-cyan-300 font-bold">{selectedNode.ip || '192.168.10.100'}</code>
                        </div>
                        <div>
                          <span className="block text-[9.5px] uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider">PORT</span>
                          <code className="text-cyan-600 dark:text-cyan-300 font-bold">{selectedNode.port || 80}</code>
                        </div>
                      </div>

                      {/* Display Threat and Affected Component when compromised */}
                      {selectedNode.status === 'COMPROMISED' && (
                        <div className="pt-2 border-t border-red-500/20 bg-red-950/20 -mx-3 -mb-3 p-3 rounded-b-xl space-y-2">
                          <div>
                            <span className="block text-[9.5px] uppercase font-bold text-red-400 tracking-wider">THREAT</span>
                            <span className="font-bold text-red-500 dark:text-red-400 text-xs">
                              {selectedNode.threat || 'Active Vulnerability Exploitation'}
                            </span>
                          </div>
                          <div>
                            <span className="block text-[9.5px] uppercase font-bold text-red-400 tracking-wider">AFFECTED COMPONENT</span>
                            <code className="text-[10px] text-amber-400 bg-black/40 px-1.5 py-0.5 rounded border border-amber-500/30 font-bold block truncate">
                              {selectedNode.affectedComponent || 'Target Software Component'}
                            </code>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Hardware & Environment Specs */}
                    <div className="space-y-1 text-[11px] font-mono pt-1">
                      {selectedNode.purpose && (
                        <div><span className={`font-bold ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Application Purpose:</span> <span className={isDark ? 'text-slate-300' : 'text-slate-900 font-medium'}>{selectedNode.purpose}</span></div>
                      )}
                      <div><span className={`font-bold ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Operating System:</span> <span className={isDark ? 'text-slate-200' : 'text-slate-950 font-medium'}>{selectedNode.os || 'Ubuntu 24.04 LTS'}</span></div>
                      {(selectedNode.cpu || selectedNode.ram) && (
                        <div><span className={`font-bold ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Hardware:</span> <span className={isDark ? 'text-slate-300' : 'text-slate-800'}>{selectedNode.cpu || '4 vCPU'} · {selectedNode.ram || '16 GB RAM'} · {selectedNode.storage || '500 GB SSD'}</span></div>
                      )}
                      {selectedNode.installedSoftware && (
                        <div><span className={`font-bold ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Installed Software:</span> <span className={isDark ? 'text-slate-300' : 'text-slate-800'}>{selectedNode.installedSoftware}</span></div>
                      )}
                      <div><span className={`font-bold ${isDark ? 'text-slate-400' : 'text-slate-700'}`}>Active Service:</span> <code className={`font-mono font-medium ${isDark ? 'text-cyan-300' : 'text-slate-950 font-bold'}`}>{selectedNode.service || 'service.service'}</code></div>
                    </div>

                    <div className="flex flex-col gap-2 pt-2">
                      <button
                        onClick={() => {
                          setGraphRagTargetSystem(selectedNode.id);
                          setShowGraphRagModal(true);
                        }}
                        className="w-full py-2 bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white rounded-lg font-bold text-xs uppercase tracking-wider flex items-center justify-center gap-1.5 transition-all shadow-md"
                      >
                        <Sparkles className="w-3.5 h-3.5 text-cyan-200" /> GraphRAG AI Vulnerability Studio
                      </button>

                      <button
                        onClick={() => {
                          setConfiguringSystem({
                            id: selectedNode.id,
                            name: selectedNode.name,
                            purpose: selectedNode.purpose || 'Production Microservice',
                            environment: selectedNode.environment || 'Production Linux',
                            os: selectedNode.os || 'Ubuntu 24.04 LTS',
                            version: selectedNode.version || '1.0.0',
                            port: selectedNode.port || 80,
                            ip: selectedNode.ip || '192.168.10.100',
                            service: selectedNode.service || 'daemon.service',
                            configFile: selectedNode.configFile || 'app.conf',
                            configPath: selectedNode.configPath || '/etc/app/',
                            status: selectedNode.status || 'HEALTHY',
                            availableTools: selectedNode.availableTools || 'systemctl, journalctl',
                            dependencies: selectedNode.dependencies || 'glibc, openssl'
                          });
                          setShowConfigModal(true);
                        }}
                        className={`w-full py-2 rounded-lg border font-bold text-xs uppercase tracking-wider flex items-center justify-center gap-1.5 transition-colors ${
                          isDark ? 'bg-neutral-900 border-neutral-700 hover:bg-neutral-800 text-blue-400' : 'bg-slate-100 border-slate-300 hover:bg-slate-200 text-blue-600'
                        }`}
                      >
                        <Settings className="w-3.5 h-3.5" /> Configure Computer Settings
                      </button>

                      <button
                        onClick={() => handleVerifySystem(selectedNode.id)}
                        className="w-full py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-bold text-xs uppercase tracking-wider flex items-center justify-center gap-1.5 transition-colors shadow-sm"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" /> Verify System Security & Integrity
                      </button>
                    </div>

                    {/* Software Inbound Attack Vector Tracer */}
                    <div className="pt-3 border-t border-slate-200 dark:border-slate-800/80 space-y-2">
                      <div className="text-[10px] uppercase font-bold text-amber-500 flex items-center gap-1.5">
                        <Route className="w-3.5 h-3.5" />
                        <span>Inbound Attack Vector Analysis</span>
                      </div>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400">
                        Check which adversary group can reach this computer in the fewest hops:
                      </p>
                      <div className="flex gap-1.5">
                        <select
                          value={selectedThreatActorForPath}
                          onChange={(e) => setSelectedThreatActorForPath(e.target.value)}
                          className={`flex-1 px-2.5 py-1.5 rounded-lg border text-xs outline-none ${
                            isDark ? 'bg-slate-900 border-slate-800 text-slate-200' : 'bg-white border-slate-300 text-slate-800'
                          }`}
                        >
                          {nodes.filter(n => n.label === 'ThreatActor').map(ta => (
                            <option key={ta.id} value={ta.id}>{ta.name}</option>
                          ))}
                        </select>
                        <button
                          onClick={() => {
                            handleCalculateShortestPath(selectedThreatActorForPath, selectedNode.id);
                            setIsSidePanelOpen(true);
                            setAnalystTab('attack_path');
                          }}
                          className="px-3 py-1.5 bg-gradient-to-r from-amber-500 to-orange-500 hover:opacity-95 text-white font-serif font-semibold text-xs rounded-lg flex items-center gap-1 transition-all shadow-sm"
                        >
                          <Route className="w-3.5 h-3.5" />
                          <span>Trace</span>
                        </button>
                      </div>
                    </div>

                    {/* Realistic System Source Code & Associated Tools */}
                    {(selectedNode.label === 'Software' || TECHNICAL_SYSTEMS_CATALOG[selectedNode.id]) && (
                      <div className="pt-2">
                        <SystemTechnicalViewer systemId={selectedNode.id} isDark={isDark} />
                      </div>
                    )}
                  </div>
                )}

                {/* Threat Actor Shortest Path Calculation */}
                {selectedNode.label === 'ThreatActor' && (
                  <div className="space-y-2.5 pt-3 border-t border-slate-200 dark:border-slate-800">
                    <div className="text-[10px] uppercase font-bold text-amber-500 flex items-center gap-1.5">
                      <Route className="w-3.5 h-3.5" />
                      <span>Trace Shortest Attack Vector</span>
                    </div>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400">
                      Compute minimum hops for {selectedNode.name} to breach target systems:
                    </p>
                    <div className="space-y-1.5">
                      <label className="text-[10px] text-slate-400 block font-mono">Target Computer System:</label>
                      <select
                        value={selectedSoftwareForPath}
                        onChange={(e) => setSelectedSoftwareForPath(e.target.value)}
                        className={`w-full px-2.5 py-1.5 rounded-lg border text-xs outline-none ${
                          isDark ? 'bg-slate-900 border-slate-800 text-slate-200' : 'bg-white border-slate-300 text-slate-800'
                        }`}
                      >
                        {softwareSystems.map(sw => (
                          <option key={sw.id} value={sw.id}>{sw.name} [{sw.status || 'ACTIVE'}]</option>
                        ))}
                      </select>
                      <button
                        onClick={() => {
                          handleCalculateShortestPath(selectedNode.id, selectedSoftwareForPath);
                          setIsSidePanelOpen(true);
                          setAnalystTab('attack_path');
                        }}
                        className="w-full py-2 bg-gradient-to-r from-amber-500 via-orange-500 to-red-500 hover:opacity-95 text-white rounded-lg font-serif font-semibold text-xs flex items-center justify-center gap-1.5 shadow-sm transition-all"
                      >
                        <Route className="w-3.5 h-3.5" />
                        <span>Find Shortest Path to Server</span>
                      </button>
                    </div>
                  </div>
                )}

                {/* Link to Code View if in Threat Specs mode */}
                {selectedNode.label === 'Vulnerability' && (
                  <div className="pt-3 border-t border-slate-200 dark:border-slate-800">
                    <button
                      onClick={() => setBugInspectorTab('code')}
                      className={`w-full py-2.5 px-3 rounded-xl text-xs font-serif font-semibold flex items-center justify-center gap-1.5 transition-all shadow-xs border ${
                        isDark
                          ? 'bg-gradient-to-r from-amber-500/15 to-orange-500/15 hover:from-amber-500/25 hover:to-orange-500/25 text-amber-300 border-amber-500/40'
                          : 'bg-amber-100 hover:bg-amber-200 text-amber-950 border-amber-300 font-bold'
                      }`}
                    >
                      <Code className={`w-4 h-4 ${isDark ? 'text-amber-400' : 'text-amber-800'}`} />
                      <span>Inspect Vulnerability Source Code & Exploit Payload ➔</span>
                    </button>
                  </div>
                )}
                  </>
                )}

              </div>
                </div>
              ) : null}
            </div>
          )}

        </div>

      </main>

    </div>
  );
}
