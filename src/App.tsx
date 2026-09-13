import React, { useState, useEffect, useRef } from 'react';
import { Shield, AlertTriangle, Sparkles, Terminal, Activity, CheckCircle2, Flame, Send, MessageSquare, Bug, Code, X, LogOut, User, LayoutDashboard, Info, Layers, Clock, Map } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { motion, AnimatePresence } from 'motion/react';

interface GraphNode {
  id: string;
  label: 'ThreatActor' | 'Malware' | 'Vulnerability' | 'Software' | 'Mitigation';
  name: string;
  x: number;
  y: number;
  status?: string;
  details: string;
  injected?: boolean;
  healed?: boolean;
  severity?: string;
  timestamp?: string;
}

interface GraphEdge {
  from: string;
  to: string;
  label: string;
}

interface ChatMessage {
  id: string;
  role: 'user' | 'bot';
  text: string;
}

export default function App() {
  // Auth State
  const [authRole, setAuthRole] = useState<'none' | 'hacker' | 'analyst'>('none');
  const [showAuthModal, setShowAuthModal] = useState(true);
  const [loginStep, setLoginStep] = useState<'select' | 'hacker' | 'analyst'>('select');
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');

  // Graph State
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);
  const [showHotZones, setShowHotZones] = useState(false);
  const [showHeatmap, setShowHeatmap] = useState(false);
  const [transform, setTransform] = useState({ x: 0, y: 0, k: 1 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  // UI State
  const [toast, setToast] = useState<{ title: string; message: string; type: 'red' | 'green' } | null>(null);
  const [analystTab, setAnalystTab] = useState<'chat' | 'logs' | 'knowledge_map'>('chat');
  const [remediationProgress, setRemediationProgress] = useState<Record<string, number>>({});
  const [selectedLogs, setSelectedLogs] = useState<string[]>([]);

  // Red Team State
  const [vulnName, setVulnName] = useState('CVE-2024-38812');
  const [targetSoftware, setTargetSoftware] = useState('Apache Web Server');
  const [vulnDesc, setVulnDesc] = useState('Remote code execution flaw in directory request parsing via forged URI parameters.');
  const [isInjecting, setIsInjecting] = useState(false);

  // Chat State
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    { id: '1', role: 'bot', text: 'GraphRAG system online. How can I help you analyze the graph or mitigate threats today?' }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [isChatting, setIsChatting] = useState(false);
  const [healedLog, setHealedLog] = useState<string[]>([]);
  const chatEndRef = useRef<HTMLDivElement>(null);

  const fetchGraph = async () => {
    try {
      const res = await fetch('/api/user/graph');
      const data = await res.json();
      if (data && data.nodes) {
        let offsets: Record<string, number> = { ThreatActor: 0, Technique: 0, Malware: 0, Vulnerability: 0, Software: 0, Mitigation: 0 };
        const typedNodes = data.nodes.map((n: any) => {
           let cx = 100;
           let cy = 100;
           const lbl = n.properties.label;
           
           if (lbl === 'ThreatActor') { cx = 100; cy = 100 + (offsets[lbl] * 110); offsets[lbl]++; }
           else if (lbl === 'Technique') { cx = 300; cy = 100 + (offsets[lbl] * 110); offsets[lbl]++; }
           else if (lbl === 'Malware') { cx = 500; cy = 100 + (offsets[lbl] * 110); offsets[lbl]++; }
           else if (lbl === 'Vulnerability') { cx = 700; cy = 100 + (offsets[lbl] * 110); offsets[lbl]++; }
           else if (lbl === 'Software') { cx = 900; cy = 100 + (offsets[lbl] * 110); offsets[lbl]++; }
           else if (lbl === 'Mitigation') { cx = 1100; cy = 100 + (offsets[lbl] * 110); offsets[lbl]++; }
           else { cx = 400 + Math.random() * 100; cy = 400 + Math.random() * 100; }
           
           return {
             id: n.id,
             label: n.properties.label,
             name: n.properties.name || n.id,
             x: cx,
             y: cy,
             status: n.properties.status,
             details: n.properties.description || n.title,
             injected: n.properties.injected_by ? true : false,
             healed: n.properties.status === 'SELF_HEALED',
             severity: n.properties.severity,
             timestamp: n.properties.timestamp || new Date().toISOString()
           };
        });
        setNodes(typedNodes);
        setEdges(data.edges);
      }
    } catch (e) {
      console.error(e);
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

  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [chatMessages, healedLog]);

  const handleInject = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsInjecting(true);
    try {
      await fetch('/api/hacker/inject', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vuln_name: vulnName,
          target_software: targetSoftware,
          description: vulnDesc
        })
      });
      setToast({
        title: 'Vulnerability Injected',
        message: `${vulnName} successfully injected targeting ${targetSoftware}.`,
        type: 'red'
      });
      fetchGraph();
      setVulnName(`CVE-2024-${Math.floor(10000 + Math.random() * 90000)}`);
    } catch (e) {
      console.error(e);
    }
    setIsInjecting(false);
  };

  const simulateRemediation = (nodeId: string) => {
    setRemediationProgress(prev => ({ ...prev, [nodeId]: 0 }));
    let progress = 0;
    const interval = setInterval(() => {
      progress += Math.floor(Math.random() * 15) + 5;
      if (progress >= 100) {
        progress = 100;
        clearInterval(interval);
        
        // Auto-trigger the fix command after progress completes
        const msg = `fix ${nodeId}`;
        setChatMessages(prev => [...prev, { id: Date.now().toString(), role: 'user', text: msg }]);
        setIsChatting(true);
        fetch('/api/user/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: msg })
        }).then(res => res.json()).then(data => {
          setChatMessages(prev => [...prev, { id: (Date.now() + 1).toString(), role: 'bot', text: data.data.reply }]);
          if (data.data && data.data.logs && data.data.logs.length > 0) {
             setHealedLog(data.data.logs);
             setToast({
              title: 'Graph Repaired',
              message: `Mitigation dynamically written to Graph DB.`,
              type: 'green'
            });
            fetchGraph();
          }
          setIsChatting(false);
          // clear progress
          setTimeout(() => {
            setRemediationProgress(prev => {
              const updated = { ...prev };
              delete updated[nodeId];
              return updated;
            });
          }, 1000);
        }).catch(e => {
          console.error(e);
          setIsChatting(false);
        });

      } else {
        setRemediationProgress(prev => ({ ...prev, [nodeId]: progress }));
      }
    }, 400);
  };

  const simulateBatchRemediation = async () => {
    if (selectedLogs.length === 0) return;
    
    // Set initial progress for all selected
    const initialProgress = selectedLogs.reduce((acc, id) => ({ ...acc, [id]: 0 }), {});
    setRemediationProgress(prev => ({ ...prev, ...initialProgress }));

    let progress = 0;
    const interval = setInterval(() => {
      progress += Math.floor(Math.random() * 15) + 5;
      if (progress >= 100) {
        progress = 100;
        clearInterval(interval);
        
        // Trigger batch fix chat
        const msg = `fix ${selectedLogs.join(', ')}`;
        setChatMessages(prev => [...prev, { id: Date.now().toString(), role: 'user', text: msg }]);
        setAnalystTab('chat');
        setIsChatting(true);
        fetch('/api/user/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: msg })
        }).then(res => res.json()).then(data => {
          setChatMessages(prev => [...prev, { id: (Date.now() + 1).toString(), role: 'bot', text: data.data.reply }]);
          if (data.data && data.data.logs && data.data.logs.length > 0) {
             setHealedLog(data.data.logs);
             setToast({
              title: 'Batch Repair Complete',
              message: `Multiple mitigations written to Graph DB.`,
              type: 'green'
            });
            fetchGraph();
          }
          setIsChatting(false);
          // clear progress
          setTimeout(() => {
            setRemediationProgress(prev => {
              const updated = { ...prev };
              selectedLogs.forEach(id => delete updated[id]);
              return updated;
            });
            setSelectedLogs([]);
          }, 1000);
        }).catch(e => {
          console.error(e);
          setIsChatting(false);
        });
      } else {
        const updateProgress = selectedLogs.reduce((acc, id) => ({ ...acc, [id]: progress }), {});
        setRemediationProgress(prev => ({ ...prev, ...updateProgress }));
      }
    }, 400);
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim()) return;

    const userMessage = chatInput.trim();
    setChatInput('');
    setChatMessages(prev => [...prev, { id: Date.now().toString(), role: 'user', text: userMessage }]);
    setIsChatting(true);

    try {
      const res = await fetch('/api/user/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: userMessage })
      });
      const data = await res.json();
      
      setChatMessages(prev => [...prev, { id: (Date.now() + 1).toString(), role: 'bot', text: data.data.reply }]);
      
      if (data.data && data.data.logs && data.data.logs.length > 0) {
         setHealedLog(data.data.logs);
         setToast({
          title: 'Graph Repaired',
          message: `Mitigation dynamically written to Graph DB.`,
          type: 'green'
        });
        fetchGraph();
      }
    } catch (e) {
      console.error(e);
    }
    setIsChatting(false);
  };

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

  const handleWheel = (e: React.WheelEvent<SVGSVGElement>) => {
    const zoomSensitivity = 0.001;
    const delta = -e.deltaY * zoomSensitivity;
    const newK = Math.min(Math.max(0.1, transform.k * (1 + delta)), 4);
    setTransform(prev => ({ ...prev, k: newK }));
  };

  const handleMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX - transform.x, y: e.clientY - transform.y });
  };

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!isDragging) return;
    setTransform(prev => ({
      ...prev,
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y
    }));
  };

  const handleMouseUp = () => setIsDragging(false);
  const handleMouseLeave = () => setIsDragging(false);

  return (
    <div className="min-h-screen font-mono text-sm flex flex-col bg-[#050a10] text-neutral-300">
      
      {/* Split-View Auth Modal */}
      {showAuthModal && (
        <div className="fixed inset-0 z-50 bg-black/90 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0a0a0a] border border-blue-900/50 rounded-xl w-full max-w-4xl flex flex-col md:flex-row overflow-hidden shadow-2xl relative min-h-[400px]">
            <button 
              onClick={() => { setShowAuthModal(false); setLoginStep('select'); }} 
              className="absolute top-4 right-4 z-10 p-2 bg-black/50 rounded-full text-neutral-500 hover:text-white transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
            
            {loginStep === 'select' && (
              <>
                {/* Hacker Side */}
                <div 
                  className="flex-1 p-10 border-b md:border-b-0 md:border-r border-neutral-800 hover:bg-red-950/20 transition-colors group cursor-pointer flex flex-col items-center text-center justify-center" 
                  onClick={() => setLoginStep('hacker')}
                >
                  <div className="w-20 h-20 rounded-full bg-red-950/50 border border-red-900 flex items-center justify-center mb-6 group-hover:scale-110 transition-transform shadow-[0_0_30px_rgba(239,68,68,0.2)]">
                    <Flame className="w-10 h-10 text-red-500" />
                  </div>
                  <h2 className="text-2xl font-bold text-red-400 mb-3 tracking-widest uppercase">Red Team</h2>
                  <h3 className="text-white font-semibold mb-4">Hacker Role</h3>
                  <p className="text-neutral-400 text-sm leading-relaxed max-w-xs">
                    Inject zero-day vulnerabilities, deploy payloads, and test the resilience of the network graph.
                  </p>
                  <div className="mt-8 px-6 py-2 border border-red-900/50 text-red-400 rounded-full text-xs font-bold tracking-wider group-hover:bg-red-900/30 transition-colors">
                    INITIALIZE SESSION
                  </div>
                </div>

                {/* Analyst Side */}
                <div 
                  className="flex-1 p-10 hover:bg-blue-950/20 transition-colors group cursor-pointer flex flex-col items-center text-center justify-center" 
                  onClick={() => setLoginStep('analyst')}
                >
                  <div className="w-20 h-20 rounded-full bg-blue-950/50 border border-blue-900 flex items-center justify-center mb-6 group-hover:scale-110 transition-transform shadow-[0_0_30px_rgba(59,130,246,0.2)]">
                    <Shield className="w-10 h-10 text-blue-500" />
                  </div>
                  <h2 className="text-2xl font-bold text-blue-400 mb-3 tracking-widest uppercase">Blue Team</h2>
                  <h3 className="text-white font-semibold mb-4">Analyst Role</h3>
                  <p className="text-neutral-400 text-sm leading-relaxed max-w-xs">
                    Query threats, view live topology changes, and execute automated mitigations using GraphRAG.
                  </p>
                  <div className="mt-8 px-6 py-2 border border-blue-900/50 text-blue-400 rounded-full text-xs font-bold tracking-wider group-hover:bg-blue-900/30 transition-colors">
                    AUTHENTICATE
                  </div>
                </div>
              </>
            )}

            {loginStep === 'hacker' && (
              <div className="flex-1 p-10 flex flex-col items-center justify-center bg-red-950/10 border-r border-red-900/30 w-full relative">
                <button onClick={() => setLoginStep('select')} className="absolute top-6 left-6 text-neutral-500 hover:text-white text-xs font-bold tracking-widest uppercase">&larr; Back</button>
                <Flame className="w-12 h-12 text-red-500 mb-6" />
                <h2 className="text-2xl font-bold text-red-400 mb-8 tracking-widest uppercase">Red Team Access</h2>
                <form 
                  className="w-full max-w-sm space-y-4"
                  onSubmit={(e) => { e.preventDefault(); setAuthRole('hacker'); setShowAuthModal(false); setLoginStep('select'); }}
                >
                  <input type="text" placeholder="Alias / Handle" required className="w-full bg-black border border-red-900/50 rounded p-3 text-red-400 focus:outline-none focus:border-red-500 text-sm" />
                  <input type="password" placeholder="Access Key" required className="w-full bg-black border border-red-900/50 rounded p-3 text-red-400 focus:outline-none focus:border-red-500 text-sm" />
                  <button type="submit" className="w-full bg-red-950 hover:bg-red-900 text-red-400 font-bold border border-red-800 rounded py-3 mt-4 transition-all tracking-widest uppercase">
                    Connect
                  </button>
                </form>
              </div>
            )}

            {loginStep === 'analyst' && (
              <div className="flex-1 p-10 flex flex-col items-center justify-center bg-blue-950/10 w-full relative">
                <button onClick={() => setLoginStep('select')} className="absolute top-6 left-6 text-neutral-500 hover:text-white text-xs font-bold tracking-widest uppercase">&larr; Back</button>
                <Shield className="w-12 h-12 text-blue-500 mb-6" />
                <h2 className="text-2xl font-bold text-blue-400 mb-8 tracking-widest uppercase">SOC Authentication</h2>
                <form 
                  className="w-full max-w-sm space-y-4"
                  onSubmit={(e) => { e.preventDefault(); setAuthRole('analyst'); setShowAuthModal(false); setLoginStep('select'); }}
                >
                  <input type="text" placeholder="Badge ID" required className="w-full bg-black border border-blue-900/50 rounded p-3 text-blue-400 focus:outline-none focus:border-blue-500 text-sm" />
                  <input type="password" placeholder="Password" required className="w-full bg-black border border-blue-900/50 rounded p-3 text-blue-400 focus:outline-none focus:border-blue-500 text-sm" />
                  <button type="submit" className="w-full bg-blue-950 hover:bg-blue-900 text-blue-400 font-bold border border-blue-800 rounded py-3 mt-4 transition-all tracking-widest uppercase">
                    Login
                  </button>
                </form>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Dynamic Top Toast Notification */}
      <div className={`fixed top-0 left-0 w-full z-50 transition-all duration-500 transform ${toast ? 'translate-y-0 opacity-100' : '-translate-y-full opacity-0'}`}>
        {toast && (
          <div className={`w-full py-4 px-6 flex items-center justify-center shadow-2xl backdrop-blur-md ${
            toast.type === 'red' 
              ? 'bg-red-950/90 border-b border-red-500/50 text-red-200' 
              : 'bg-green-950/90 border-b border-green-500/50 text-green-200'
          }`}>
            {toast.type === 'red' ? <Flame className="w-6 h-6 mr-3 text-red-500 animate-pulse" /> : <CheckCircle2 className="w-6 h-6 mr-3 text-green-500 animate-pulse" />}
            <div>
              <h3 className="font-bold text-base tracking-wide">{toast.title}</h3>
              <p className="opacity-90 mt-1">{toast.message}</p>
            </div>
          </div>
        )}
      </div>

      {/* Header */}
      <header className="h-16 flex items-center justify-between px-6 border-b border-blue-900/30 bg-black/50 z-40">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded bg-blue-950 border border-blue-900 flex items-center justify-center">
            <Shield className="w-4 h-4 text-blue-500" />
          </div>
          <span className="font-bold text-white tracking-wide">Cybersecurity Threat Intelligence (CTI) GraphRAG</span>
        </div>
        
        <div className="flex items-center space-x-6">
          <div className="flex items-center space-x-2 text-neutral-400 border-r border-blue-900/30 pr-6">
            <Activity className="w-4 h-4" />
            <span>Nodes: {nodes.length} | Edges: {edges.length}</span>
          </div>
          {/* Auth Controls */}
          <div className="flex items-center space-x-3">
            {authRole === 'none' ? (
              <>
                <button onClick={() => setShowAuthModal(true)} className="px-4 py-1.5 text-blue-400 hover:bg-blue-950/50 rounded transition-colors border border-transparent hover:border-blue-900/50 flex items-center">
                  <User className="w-4 h-4 mr-2" /> Login
                </button>
              </>
            ) : (
              <>
                <div className="px-4 py-1.5 text-xs uppercase tracking-wider font-bold rounded border bg-neutral-900 flex items-center shadow-inner">
                  {authRole === 'hacker' ? (
                    <span className="text-red-400 flex items-center"><Flame className="w-4 h-4 mr-2" /> Hacker Session</span>
                  ) : (
                    <span className="text-blue-400 flex items-center"><Shield className="w-4 h-4 mr-2" /> Analyst Session</span>
                  )}
                </div>
                <button onClick={() => setAuthRole('none')} className="px-3 py-1.5 text-neutral-400 hover:text-white hover:bg-neutral-800 rounded transition-colors" title="Logout">
                  <LogOut className="w-4 h-4" />
                </button>
              </>
            )}
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 flex overflow-hidden">
        
        {/* LEFT PANEL: Role-Based Dashboard */}
        <div className="w-96 border-r border-blue-900/30 bg-neutral-950/50 flex flex-col h-full overflow-hidden relative">
          
          {authRole === 'none' && (
            <div className="absolute inset-0 flex flex-col items-center justify-center p-8 text-center bg-neutral-950/80 backdrop-blur-sm z-10">
              <User className="w-12 h-12 mb-4 text-neutral-600" />
              <h3 className="text-lg font-bold text-neutral-300 mb-2">Authentication Required</h3>
              <p className="text-neutral-500 text-xs mb-6 leading-relaxed">
                Please authenticate as a Hacker (Red Team) or Analyst (Blue Team) to access operational controls.
              </p>
              <button 
                onClick={() => setShowAuthModal(true)} 
                className="px-6 py-2 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded transition-colors flex items-center text-xs tracking-widest uppercase"
              >
                Open Login Portal
              </button>
            </div>
          )}

          {/* Threat Injection Form (Hacker Only) */}
          {(authRole === 'hacker' || authRole === 'none') && (
            <div className={`${authRole === 'hacker' ? 'flex-1 flex flex-col' : 'flex-shrink-0'}`}>
               <div className="p-3 border-b border-red-900/30 bg-red-950/10 flex items-center">
                 <Flame className="w-4 h-4 text-red-500 mr-2" />
                 <span className="font-bold text-red-400 text-xs tracking-wider uppercase">Hacker Portal (Red Team)</span>
               </div>
               <form onSubmit={handleInject} className="p-4 space-y-4 flex-1">
                  <div>
                    <input 
                      type="text" 
                      value={vulnName}
                      onChange={e => setVulnName(e.target.value)}
                      placeholder="Vulnerability ID"
                      className="w-full bg-black border border-red-900/30 rounded p-2 text-red-400 focus:outline-none focus:border-red-500 text-xs"
                      required
                    />
                  </div>
                  <div>
                    <select 
                      value={targetSoftware}
                      onChange={e => setTargetSoftware(e.target.value)}
                      className="w-full bg-black border border-red-900/30 rounded p-2 text-red-400 focus:outline-none focus:border-red-500 text-xs appearance-none"
                    >
                      {nodes.filter(n => n.label === 'Software').map(n => (
                        <option key={n.id} value={n.id}>{n.name}</option>
                      ))}
                      <option value="New Core Service">New Core Service</option>
                    </select>
                  </div>
                  <button 
                    type="submit"
                    disabled={isInjecting}
                    className="w-full bg-red-950/50 hover:bg-red-900 text-red-400 font-bold border border-red-800/50 rounded py-2 transition-all flex items-center justify-center text-xs"
                  >
                    {isInjecting ? 'Deploying...' : 'Inject Threat'}
                  </button>
               </form>
            </div>
          )}

          {/* AI Chatbot (Analyst Only) */}
          {(authRole === 'analyst' || authRole === 'none') && (
            <div className={`flex-1 flex flex-col min-h-0 ${authRole === 'none' ? 'border-t border-blue-900/30' : ''}`}>
              <div className="p-3 border-b border-blue-900/30 bg-blue-950/10 flex justify-between items-center">
                <div className="flex space-x-6">
                  <button 
                    onClick={() => setAnalystTab('chat')} 
                    className={`font-bold text-xs tracking-wider uppercase flex items-center transition-colors ${analystTab === 'chat' ? 'text-blue-400' : 'text-blue-900 hover:text-blue-700'}`}
                  >
                    <MessageSquare className="w-4 h-4 mr-2" /> AI Analyst
                  </button>
                  <button 
                    onClick={() => setAnalystTab('logs')} 
                    className={`font-bold text-xs tracking-wider uppercase flex items-center transition-colors ${analystTab === 'logs' ? 'text-blue-400' : 'text-blue-900 hover:text-blue-700'}`}
                  >
                    <Activity className="w-4 h-4 mr-2" /> Threat Logs
                  </button>
                  <button 
                    onClick={() => setAnalystTab('knowledge_map')} 
                    className={`font-bold text-xs tracking-wider uppercase flex items-center transition-colors ${analystTab === 'knowledge_map' ? 'text-blue-400' : 'text-blue-900 hover:text-blue-700'}`}
                  >
                    <Map className="w-4 h-4 mr-2" /> Knowledge Map
                  </button>
                </div>
              </div>
              
              {authRole === 'analyst' && analystTab === 'chat' && (
                <div className="h-48 border-b border-blue-900/30 bg-black p-4 flex flex-col">
                  <span className="text-xs text-neutral-400 font-bold tracking-wider mb-2 uppercase">Active Vulnerabilities by Severity</span>
                  <div className="flex-1">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={[
                        { name: 'CRITICAL', count: nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED' && n.severity === 'CRITICAL').length, color: '#ef4444' },
                        { name: 'HIGH', count: nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED' && n.severity === 'HIGH').length, color: '#f97316' },
                        { name: 'MEDIUM', count: nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED' && n.severity === 'MEDIUM').length, color: '#eab308' },
                        { name: 'LOW', count: nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED' && n.severity === 'LOW').length, color: '#3b82f6' }
                      ]}>
                        <XAxis dataKey="name" stroke="#525252" fontSize={10} tickLine={false} axisLine={false} />
                        <Tooltip 
                          cursor={{fill: '#172554'}} 
                          contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #1e3a8a', fontSize: '12px', color: '#93c5fd' }} 
                        />
                        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                          {
                            [
                              { name: 'CRITICAL', count: nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED' && n.severity === 'CRITICAL').length, color: '#ef4444' },
                              { name: 'HIGH', count: nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED' && n.severity === 'HIGH').length, color: '#f97316' },
                              { name: 'MEDIUM', count: nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED' && n.severity === 'MEDIUM').length, color: '#eab308' },
                              { name: 'LOW', count: nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED' && n.severity === 'LOW').length, color: '#3b82f6' }
                            ].map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={entry.color} />
                            ))
                          }
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}
            
            {analystTab === 'chat' ? (
              <>
                <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
                  {chatMessages.map(msg => (
                    <div key={msg.id} className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
                      <div className={`max-w-[90%] p-3 rounded-lg leading-relaxed whitespace-pre-wrap ${
                        msg.role === 'user' 
                          ? 'bg-blue-900/40 text-blue-100 border border-blue-800/50 rounded-tr-none' 
                          : 'bg-black text-neutral-300 border border-neutral-800 rounded-tl-none'
                      }`}>
                        {msg.text}
                      </div>
                    </div>
                  ))}
                  {isChatting && (
                    <div className="bg-black text-neutral-300 border border-neutral-800 rounded-lg rounded-tl-none p-3 max-w-[90%] flex space-x-1">
                      <div className="w-1.5 h-1.5 bg-blue-500 rounded-full animate-bounce"></div>
                      <div className="w-1.5 h-1.5 bg-blue-500 rounded-full animate-bounce delay-75"></div>
                      <div className="w-1.5 h-1.5 bg-blue-500 rounded-full animate-bounce delay-150"></div>
                    </div>
                  )}
                  {/* Agent Logs */}
                  {healedLog.length > 0 && (
                    <div className="mt-4 border border-green-900/30 bg-green-950/10 rounded p-3 text-[10px] space-y-1">
                      <div className="text-green-500 font-bold mb-2 flex items-center uppercase tracking-widest">
                        <Terminal className="w-3 h-3 mr-1" /> Execution Trace
                      </div>
                      {healedLog.map((log, i) => (
                        <div key={i} className="text-green-400/80">{log}</div>
                      ))}
                    </div>
                  )}
                  <div ref={chatEndRef} />
                </div>

                <div className="p-3 bg-black border-t border-blue-900/30">
                  <form onSubmit={handleSendMessage} className="relative">
                    <input
                      type="text"
                      value={chatInput}
                      onChange={e => setChatInput(e.target.value)}
                      placeholder="Ask about vulnerabilities..."
                      className="w-full bg-neutral-900 border border-neutral-800 rounded pl-3 pr-10 py-2 text-blue-100 placeholder-neutral-600 focus:outline-none focus:border-blue-500 text-xs"
                      disabled={isChatting}
                    />
                    <button 
                      type="submit"
                      disabled={isChatting || !chatInput.trim()}
                      className="absolute right-1 top-1 p-1.5 text-blue-500 hover:text-blue-400 transition-colors disabled:opacity-50"
                    >
                      <Send className="w-4 h-4" />
                    </button>
                  </form>
                </div>
              </>
            ) : analystTab === 'logs' ? (
              <div className="flex-1 flex flex-col min-h-0 bg-[#0a0a0a]">
                <div className="flex-1 overflow-y-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-neutral-900/50 text-[10px] uppercase tracking-widest text-neutral-500 border-b border-neutral-800">
                        <th className="p-3 font-medium w-8">
                          <input 
                            type="checkbox" 
                            className="rounded bg-neutral-800 border-neutral-700" 
                            onChange={(e) => {
                              if (e.target.checked) {
                                setSelectedLogs(nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED').map(n => n.id));
                              } else {
                                setSelectedLogs([]);
                              }
                            }}
                            checked={selectedLogs.length > 0 && selectedLogs.length === nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED').length}
                          />
                        </th>
                        <th className="p-3 font-medium">Timestamp</th>
                        <th className="p-3 font-medium">Vulnerability</th>
                        <th className="p-3 font-medium">Severity</th>
                        <th className="p-3 font-medium text-right">Status</th>
                      </tr>
                    </thead>
                    <tbody className="text-xs text-neutral-300">
                      {nodes
                        .filter(n => n.label === 'Vulnerability')
                        .sort((a, b) => new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime())
                        .map((node) => (
                        <tr key={`log-${node.id}`} className="border-b border-neutral-800/50 hover:bg-neutral-900/30 transition-colors">
                          <td className="p-3">
                            {node.status === 'UNMITIGATED' && (
                              <input 
                                type="checkbox" 
                                className="rounded bg-neutral-800 border-neutral-700"
                                checked={selectedLogs.includes(node.id)}
                                onChange={(e) => {
                                  if (e.target.checked) {
                                    setSelectedLogs(prev => [...prev, node.id]);
                                  } else {
                                    setSelectedLogs(prev => prev.filter(id => id !== node.id));
                                  }
                                }}
                              />
                            )}
                          </td>
                          <td className="p-3 whitespace-nowrap text-neutral-500 font-mono text-[10px]">
                            {node.timestamp ? new Date(node.timestamp).toLocaleString() : 'N/A'}
                          </td>
                          <td className="p-3 font-semibold">{node.id}</td>
                          <td className="p-3">
                            <span className={`inline-flex px-1.5 py-0.5 rounded text-[10px] font-bold tracking-wider ${
                               node.severity === 'CRITICAL' ? 'bg-red-950/50 text-red-500' :
                               node.severity === 'HIGH' ? 'bg-orange-950/50 text-orange-500' :
                               node.severity === 'MEDIUM' ? 'bg-yellow-950/50 text-yellow-500' :
                               'bg-blue-950/50 text-blue-500'
                             }`}>
                              {node.severity || 'UNKNOWN'}
                            </span>
                          </td>
                          <td className="p-3 text-right">
                            <span className={`inline-flex items-center text-[10px] font-bold uppercase tracking-wider ${node.status === 'UNMITIGATED' ? 'text-red-500' : 'text-green-500'}`}>
                              {node.status === 'UNMITIGATED' ? <AlertTriangle className="w-3 h-3 mr-1" /> : <CheckCircle2 className="w-3 h-3 mr-1" />}
                              {node.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                      {nodes.filter(n => n.label === 'Vulnerability').length === 0 && (
                        <tr>
                          <td colSpan={5} className="p-8 text-center text-neutral-600 text-xs italic">
                            No vulnerabilities detected in the network.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
                {selectedLogs.length > 0 && (
                  <div className="p-3 bg-black border-t border-neutral-800 animate-in slide-in-from-bottom-2">
                    <button 
                      onClick={simulateBatchRemediation}
                      className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold tracking-widest uppercase text-xs py-2 rounded flex items-center justify-center transition-colors shadow-[0_0_15px_rgba(37,99,235,0.3)]"
                    >
                      <Shield className="w-4 h-4 mr-2" /> Batch Mitigate ({selectedLogs.length})
                    </button>
                  </div>
                )}
              </div>
            ) : analystTab === 'knowledge_map' ? (
              <div className="flex-1 overflow-y-auto bg-[#0a0a0a] p-4 text-xs">
                <div className="space-y-6">
                  {['ThreatActor', 'Malware', 'Technique', 'Vulnerability', 'Software'].map(category => {
                    const catNodes = nodes.filter(n => n.label === category);
                    if (catNodes.length === 0) return null;
                    return (
                      <div key={category} className="space-y-2">
                        <div className="flex items-center space-x-2 text-neutral-400 font-bold tracking-widest uppercase border-b border-neutral-800 pb-1">
                          {category === 'ThreatActor' && <User className="w-4 h-4 text-purple-500" />}
                          {category === 'Malware' && <Bug className="w-4 h-4 text-red-500" />}
                          {category === 'Technique' && <Code className="w-4 h-4 text-orange-500" />}
                          {category === 'Vulnerability' && <AlertTriangle className="w-4 h-4 text-yellow-500" />}
                          {category === 'Software' && <Terminal className="w-4 h-4 text-blue-500" />}
                          <span>{category} ({catNodes.length})</span>
                        </div>
                        <ul className="pl-6 space-y-3 border-l border-neutral-800 ml-2">
                          {catNodes.map(node => (
                            <li key={node.id} className="relative">
                              <div className="absolute -left-[25px] top-1.5 w-4 h-[1px] bg-neutral-800"></div>
                              <div className="flex flex-col">
                                <div className="flex items-center justify-between group cursor-pointer" onClick={() => setSelectedNode(node)}>
                                  <span className="font-semibold text-neutral-200 group-hover:text-blue-400 transition-colors">{node.name}</span>
                                  {node.dataset && (
                                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-neutral-500 font-mono tracking-wider ml-2">
                                      {node.dataset}
                                    </span>
                                  )}
                                </div>
                                <span className="text-neutral-500 text-[10px] mt-0.5 line-clamp-1">{node.details}</span>
                              </div>
                            </li>
                          ))}
                        </ul>
                      </div>
                    );
                  })}
                </div>
              </div>
            ) : null}
          </div>
          )}
        </div>

        {/* RIGHT PANEL: SVG Graph + Side Panel */}
        <div className="flex-1 flex flex-row min-w-0 bg-[#0a0a0a]">
          
          {/* Top Half: Graph Viewer */}
          <div className="flex-1 relative border-b border-neutral-800">
             <div className="absolute inset-0 opacity-[0.03] pointer-events-none" style={{ backgroundImage: 'linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)', backgroundSize: '40px 40px' }}></div>
             
             <div className="absolute top-4 left-4 z-10">
               <h2 className="text-sm font-bold text-neutral-400 uppercase tracking-widest flex items-center">
                 <Activity className="w-4 h-4 mr-2" /> Interactive Network Graph
               </h2>
             </div>

             <div className="absolute top-4 right-4 z-10 bg-black/60 backdrop-blur border border-neutral-800 rounded p-3 text-xs text-neutral-400 space-y-2">
               <div className="flex items-center"><div className="w-3 h-3 rounded-full bg-blue-500 mr-2"></div> Software / Infrastructure</div>
               <div className="flex items-center"><div className="w-3 h-3 rounded-full bg-red-500 mr-2"></div> Vulnerability</div>
               <div className="flex items-center"><div className="w-3 h-3 rounded-full bg-green-500 mr-2"></div> Mitigation</div>
               <button 
                 onClick={() => setShowHotZones(!showHotZones)}
                 className={`mt-4 w-full px-2 py-1.5 flex items-center justify-center rounded border transition-colors font-bold tracking-widest ${showHotZones ? 'bg-red-950 border-red-900 text-red-500 shadow-[0_0_10px_rgba(239,68,68,0.3)]' : 'bg-neutral-950 border-neutral-800 text-neutral-500 hover:text-neutral-300'}`}
               >
                 <Layers className="w-4 h-4 mr-2" /> HOT ZONES {showHotZones ? 'ON' : 'OFF'}
               </button>
               <button 
                 onClick={() => setShowHeatmap(!showHeatmap)}
                 className={`mt-2 w-full px-2 py-1.5 flex items-center justify-center rounded border transition-colors font-bold tracking-widest ${showHeatmap ? 'bg-orange-950 border-orange-900 text-orange-500 shadow-[0_0_10px_rgba(249,115,22,0.3)]' : 'bg-neutral-950 border-neutral-800 text-neutral-500 hover:text-neutral-300'}`}
               >
                 <Map className="w-4 h-4 mr-2" /> RISK HEATMAP {showHeatmap ? 'ON' : 'OFF'}
               </button>
             </div>

             <style>{`
               @keyframes flow {
                 from { stroke-dashoffset: 24; }
                 to { stroke-dashoffset: 0; }
               }
               @keyframes float {
                 0%, 100% { transform: translateY(0px); }
                 50% { transform: translateY(-6px); }
               }
               .edge-flow {
                 stroke-dasharray: 6 6;
                 animation: flow 1s linear infinite;
               }
               .node-float {
                 animation: float 4s ease-in-out infinite;
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
                  <stop offset="0%" stopColor="#ef4444" stopOpacity="0.15" />
                  <stop offset="50%" stopColor="#ef4444" stopOpacity="0.05" />
                  <stop offset="100%" stopColor="#ef4444" stopOpacity="0" />
                </radialGradient>
                <radialGradient id="highRiskGradient" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#ef4444" stopOpacity="0.2" />
                  <stop offset="100%" stopColor="#ef4444" stopOpacity="0" />
                </radialGradient>
                <radialGradient id="medRiskGradient" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.15" />
                  <stop offset="100%" stopColor="#f59e0b" stopOpacity="0" />
                </radialGradient>
                <radialGradient id="lowRiskGradient" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#eab308" stopOpacity="0.1" />
                  <stop offset="100%" stopColor="#eab308" stopOpacity="0" />
                </radialGradient>
                <marker id="arrow-blue" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#3b82f6" opacity="0.6" />
                </marker>
                <marker id="arrow-red" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" opacity="0.6" />
                </marker>
                <marker id="arrow-green" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#22c55e" opacity="0.6" />
                </marker>
                <marker id="arrow-dim" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#525252" opacity="0.3" />
                </marker>
              </defs>

              {nodes.filter(n => n.label === 'Software').map(sw => {
                const connectedVulns = edges
                  .filter(e => (e.label === 'AFFECTS' || e.label === 'EXPLOITS') && e.to === sw.id)
                  .map(e => nodes.find(n => n.id === e.from))
                  .filter(n => n?.label === 'Vulnerability' && n.status === 'UNMITIGATED');

                let riskScore = 0;
                connectedVulns.forEach(v => {
                  if (v?.severity === 'CRITICAL') riskScore += 4;
                  else if (v?.severity === 'HIGH') riskScore += 3;
                  else if (v?.severity === 'MEDIUM') riskScore += 2;
                  else if (v?.severity === 'LOW') riskScore += 1;
                });

                if (riskScore === 0) return null;

                const gradient = riskScore >= 6 ? 'url(#highRiskGradient)' : riskScore >= 3 ? 'url(#medRiskGradient)' : 'url(#lowRiskGradient)';
                const radius = Math.min(150 + riskScore * 15, 300);

                return (
                  <circle 
                    key={`risk-${sw.id}`} 
                    cx={sw.x} 
                    cy={sw.y} 
                    r={radius} 
                    fill={gradient} 
                    pointerEvents="none" 
                    className="animate-pulse"
                  />
                );
              })}

              {showHotZones && nodes.filter(n => n.label === 'Vulnerability' && n.status === 'UNMITIGATED').map(node => (
                <circle 
                  key={`hotzone-${node.id}`} 
                  cx={node.x} 
                  cy={node.y} 
                  r="200" 
                  fill="url(#hotzoneGradient)" 
                  pointerEvents="none" 
                  className="animate-pulse"
                />
              ))}

              {edges.map((edge, idx) => {
                const source = nodes.find(n => n.id === edge.from);
                const target = nodes.find(n => n.id === edge.to);
                if (!source || !target) return null;
                
                const edgeId = `edge-${idx}`;
                const isHealed = edge.label === 'HAS_MITIGATION';
                const isExploit = edge.label === 'EXPLOITS' || edge.label === 'AFFECTS';
                
                const isFaded = hoveredNode !== null && !connectedEdges.has(edgeId);
                
                let strokeColor = '#3b82f6';
                let markerId = 'url(#arrow-blue)';
                
                if (isFaded) {
                  strokeColor = '#525252';
                  markerId = 'url(#arrow-dim)';
                } else if (isHealed) {
                  strokeColor = '#22c55e';
                  markerId = 'url(#arrow-green)';
                } else if (isExploit) {
                  strokeColor = '#ef4444';
                  markerId = 'url(#arrow-red)';
                }

                const midX = (source.x + target.x) / 2;
                const midY = (source.y + target.y) / 2;

                return (
                  <g key={edgeId} className={`transition-all duration-300 ${isFaded ? 'opacity-20' : 'opacity-100'}`}>
                    <line
                      x1={source.x}
                      y1={source.y}
                      x2={target.x}
                      y2={target.y}
                      stroke={strokeColor}
                      strokeWidth={isFaded ? 1 : 2}
                      opacity={isFaded ? 0.3 : 0.6}
                      markerEnd={markerId}
                      className={`transition-colors duration-300 ${!isFaded && (isExploit || isHealed) ? 'edge-flow' : ''}`}
                    />
                    {!isFaded && (
                      <text x={midX} y={midY - 8} fill={strokeColor} fontSize="10" textAnchor="middle" opacity="0.8" className="tracking-widest">
                        {edge.label}
                      </text>
                    )}
                  </g>
                );
              })}

              <AnimatePresence>
              {nodes.map(node => {
                const isSelected = selectedNode?.id === node.id;
                const isFaded = hoveredNode !== null && !connectedNodes.has(node.id);
                
                let fill = '#1e3a8a';
                let stroke = '#3b82f6';
                let glow = 'rgba(59, 130, 246, 0.4)';
                
                if (showHeatmap && node.label === 'Software') {
                  const connectedVulns = edges
                    .filter(e => (e.label === 'AFFECTS' || e.label === 'EXPLOITS') && e.to === node.id)
                    .map(e => nodes.find(n => n.id === e.from))
                    .filter(n => n?.label === 'Vulnerability' && n.status === 'UNMITIGATED');
                  let riskScore = 0;
                  connectedVulns.forEach(v => {
                    if (v?.severity === 'CRITICAL') riskScore += 4;
                    else if (v?.severity === 'HIGH') riskScore += 3;
                    else if (v?.severity === 'MEDIUM') riskScore += 2;
                    else if (v?.severity === 'LOW') riskScore += 1;
                  });
                  if (riskScore >= 6) { fill = '#7f1d1d'; stroke = '#ef4444'; glow = 'rgba(239, 68, 68, 0.6)'; }
                  else if (riskScore >= 3) { fill = '#78350f'; stroke = '#f59e0b'; glow = 'rgba(245, 158, 11, 0.6)'; }
                  else if (riskScore > 0) { fill = '#422006'; stroke = '#eab308'; glow = 'rgba(234, 179, 8, 0.6)'; }
                } else if (node.status === 'UNMITIGATED') {
                  fill = '#450a0a';
                  stroke = '#ef4444';
                  glow = 'rgba(239, 68, 68, 0.6)';
                } else if (node.label === 'Mitigation' || node.status === 'SELF_HEALED') {
                  fill = '#052e16';
                  stroke = '#22c55e';
                  glow = 'rgba(34, 197, 94, 0.4)';
                }

                return (
                  <motion.g 
                    key={node.id} 
                    onClick={() => setSelectedNode(node)}
                    onMouseEnter={() => setHoveredNode(node)}
                    onMouseLeave={() => setHoveredNode(null)}
                    initial={{ scale: 0, opacity: 0 }}
                    animate={{ scale: 1, opacity: isFaded ? 0.2 : 1 }}
                    exit={{ scale: 0, opacity: 0, filter: 'blur(10px)' }}
                    transition={{ type: "spring", stiffness: 300, damping: 20 }}
                    className={`cursor-pointer transition-all duration-300 node-float`}
                  >
                    {isSelected && !isFaded && (
                      <circle cx={node.x} cy={node.y} r="32" fill="none" stroke={stroke} strokeWidth="1" strokeDasharray="4 4" className="animate-[spin_4s_linear_infinite]" opacity="0.5" />
                    )}
                    {!isFaded && (
                      <circle cx={node.x} cy={node.y} r="20" fill={glow} opacity="0.5" filter="blur(8px)" />
                    )}
                    <circle cx={node.x} cy={node.y} r="24" fill={fill} stroke={stroke} strokeWidth={isSelected ? "3" : "2"} className="transition-colors duration-300" />
                    
                    {node.label === 'Vulnerability' && <text x={node.x} y={node.y + 5} fill="#fff" fontSize="14" textAnchor="middle" style={{pointerEvents:'none'}}>Bug</text>}
                    {node.label === 'Mitigation' && <text x={node.x} y={node.y + 5} fill="#fff" fontSize="14" textAnchor="middle" style={{pointerEvents:'none'}}>🛡</text>}
                    {node.label === 'Software' && <text x={node.x} y={node.y + 5} fill="#fff" fontSize="14" textAnchor="middle" style={{pointerEvents:'none'}}>Srv</text>}
                    {node.label === 'Malware' && <text x={node.x} y={node.y + 5} fill="#fff" fontSize="14" textAnchor="middle" style={{pointerEvents:'none'}}>☠</text>}
                    {node.label === 'ThreatActor' && <text x={node.x} y={node.y + 5} fill="#fff" fontSize="14" textAnchor="middle" style={{pointerEvents:'none'}}>Apt</text>}
                    
                    <text x={node.x} y={node.y + 40} fill={isFaded ? '#525252' : '#e5e5e5'} fontSize="12" textAnchor="middle" className="font-semibold transition-colors duration-300">{node.name}</text>
                    {node.status === 'UNMITIGATED' && !isFaded && (
                       <circle cx={node.x} cy={node.y} r="34" fill="none" stroke="#ef4444" strokeWidth="1" className="animate-ping opacity-20" />
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
                  className="absolute pointer-events-none z-50 bg-black/95 border border-neutral-700 p-3 rounded shadow-2xl backdrop-blur transform -translate-x-1/2 animate-in fade-in zoom-in-95 duration-200"
                  style={{ 
                    left: hoveredNode.x * transform.k + transform.x, 
                    top: (hoveredNode.y + 40) * transform.k + transform.y, 
                    width: 220 
                  }}
                >
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-[10px] uppercase tracking-widest text-neutral-500 font-bold">{hoveredNode.label}</span>
                    <span className={`text-[10px] font-bold tracking-wider px-1.5 py-0.5 rounded ${
                       hoveredNode.severity === 'CRITICAL' ? 'bg-red-950/50 text-red-500' :
                       hoveredNode.severity === 'HIGH' ? 'bg-orange-950/50 text-orange-500' :
                       hoveredNode.severity === 'MEDIUM' ? 'bg-yellow-950/50 text-yellow-500' :
                       hoveredNode.severity ? 'bg-blue-950/50 text-blue-500' : 'bg-neutral-800 text-neutral-400'
                     }`}>{hoveredNode.severity || (hoveredNode.status === 'UNMITIGATED' ? 'AT RISK' : 'SECURE')}</span>
                  </div>
                  <div className="text-sm font-bold text-white truncate">{hoveredNode.name}</div>
                  <div className="text-xs text-neutral-400 mt-1 line-clamp-2">{hoveredNode.details}</div>
                  {hoveredNode.timestamp && (
                    <div className="text-[10px] text-neutral-500 mt-2 font-mono flex items-center pt-2 border-t border-neutral-800">
                      <Clock className="w-3 h-3 mr-1" /> {new Date(hoveredNode.timestamp).toLocaleTimeString()}
                    </div>
                  )}
                </div>
              )}
          </div>
           
           {/* Side Panel for Selected Node */}
           {selectedNode && (
             <div className="w-80 border-l border-neutral-800 bg-[#050a10] flex flex-col h-full overflow-hidden animate-in slide-in-from-right-8 duration-300">
               <div className="p-4 border-b border-neutral-800 flex justify-between items-center bg-black/50">
                 <h3 className="text-sm font-bold text-neutral-300 flex items-center tracking-widest uppercase">
                   <Info className="w-4 h-4 mr-2" /> Node Details
                 </h3>
                 <button onClick={() => setSelectedNode(null)} className="text-neutral-500 hover:text-white p-1">
                   <X className="w-4 h-4" />
                 </button>
               </div>
               
               <div className="p-5 overflow-y-auto space-y-6 flex-1">
                 <div>
                   <div className="text-[10px] uppercase tracking-widest text-neutral-500 mb-1">Entity Type</div>
                   <div className="inline-flex items-center px-2 py-1 rounded bg-blue-950/30 border border-blue-900/50 text-blue-400 text-xs font-bold uppercase tracking-wider">
                     {selectedNode.label}
                   </div>
                 </div>

                 <div>
                   <div className="text-[10px] uppercase tracking-widest text-neutral-500 mb-1">Identifier</div>
                   <div className="text-sm font-mono text-white">{selectedNode.id}</div>
                 </div>

                 {selectedNode.severity && (
                   <div>
                     <div className="text-[10px] uppercase tracking-widest text-neutral-500 mb-1">Severity / CVSS</div>
                     <div className={`inline-flex px-2 py-1 rounded border text-xs font-bold ${
                       selectedNode.severity === 'CRITICAL' ? 'bg-red-950/50 border-red-900 text-red-500' :
                       selectedNode.severity === 'HIGH' ? 'bg-orange-950/50 border-orange-900 text-orange-500' :
                       selectedNode.severity === 'MEDIUM' ? 'bg-yellow-950/50 border-yellow-900 text-yellow-500' :
                       'bg-blue-950/50 border-blue-900 text-blue-500'
                     }`}>
                       {selectedNode.severity}
                     </div>
                   </div>
                 )}

                 {selectedNode.status && (
                   <div>
                     <div className="text-[10px] uppercase tracking-widest text-neutral-500 mb-1">Risk Status</div>
                     <div className={`inline-flex px-2 py-1 rounded border text-xs font-bold ${selectedNode.status === 'UNMITIGATED' ? 'bg-red-950/30 border-red-900/50 text-red-500' : 'bg-green-950/30 border-green-900/50 text-green-500'}`}>
                       {selectedNode.status}
                     </div>
                   </div>
                 )}

                 <div>
                   <div className="text-[10px] uppercase tracking-widest text-neutral-500 mb-1">Description</div>
                   <p className="text-xs text-neutral-400 leading-relaxed border-l-2 border-neutral-800 pl-3 py-1">
                     {selectedNode.details}
                   </p>
                 </div>
                 
                 {selectedNode.label === 'Vulnerability' && selectedNode.status === 'UNMITIGATED' && (
                   <div className="pt-4 border-t border-neutral-800">
                     {remediationProgress[selectedNode.id] !== undefined ? (
                       <div className="space-y-2">
                         <div className="flex justify-between text-[10px] text-blue-400 font-bold tracking-widest uppercase">
                           <span>Self-Healing Protocol</span>
                           <span>{remediationProgress[selectedNode.id]}%</span>
                         </div>
                         <div className="h-2 w-full bg-neutral-900 rounded-full overflow-hidden">
                           <div 
                             className="h-full bg-blue-500 shadow-[0_0_10px_rgba(59,130,246,0.8)] transition-all duration-300"
                             style={{ width: `${remediationProgress[selectedNode.id]}%` }}
                           ></div>
                         </div>
                       </div>
                     ) : (
                       <button 
                         onClick={() => {
                            setAuthRole('analyst');
                            simulateRemediation(selectedNode.id);
                         }}
                         className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold tracking-widest uppercase text-xs py-3 rounded flex items-center justify-center transition-colors shadow-lg shadow-blue-900/20"
                       >
                         <Shield className="w-4 h-4 mr-2" /> Execute Auto-Fix
                       </button>
                     )}
                   </div>
                 )}

               </div>
             </div>
           )}

        </div>

      </main>
    </div>
  );
}
