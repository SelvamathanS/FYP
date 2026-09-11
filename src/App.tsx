import React, { useState, useEffect, useRef } from 'react';
import { Shield, AlertTriangle, Sparkles, Terminal, Activity, CheckCircle2, Flame, Send, MessageSquare, Bug, Code, X, LogOut, User } from 'lucide-react';

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

  // Graph State
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  // UI State
  const [toast, setToast] = useState<{ title: string; message: string; type: 'red' | 'green' } | null>(null);

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
        let offsets: Record<string, number> = { ThreatActor: 0, Malware: 0, Vulnerability: 0, Software: 0, Mitigation: 0 };
        const typedNodes = data.nodes.map((n: any) => {
           let cx = 100;
           let cy = 100;
           const lbl = n.properties.label;
           
           if (lbl === 'ThreatActor') { cx = 100; cy = 100 + (offsets[lbl] * 110); offsets[lbl]++; }
           else if (lbl === 'Malware') { cx = 280; cy = 100 + (offsets[lbl] * 110); offsets[lbl]++; }
           else if (lbl === 'Vulnerability') { cx = 460; cy = 100 + (offsets[lbl] * 110); offsets[lbl]++; }
           else if (lbl === 'Software') { cx = 640; cy = 100 + (offsets[lbl] * 110); offsets[lbl]++; }
           else if (lbl === 'Mitigation') { cx = 820; cy = 100 + (offsets[lbl] * 110); offsets[lbl]++; }
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
             healed: n.properties.status === 'SELF_HEALED'
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

  const { connectedNodes, connectedEdges } = hoveredNodeId 
    ? getConnectedComponent(hoveredNodeId) 
    : { connectedNodes: new Set<string>(), connectedEdges: new Set<string>() };

  return (
    <div className="min-h-screen font-mono text-sm flex flex-col bg-[#050a10] text-neutral-300">
      
      {/* Split-View Auth Modal */}
      {showAuthModal && (
        <div className="fixed inset-0 z-50 bg-black/90 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0a0a0a] border border-blue-900/50 rounded-xl w-full max-w-4xl flex flex-col md:flex-row overflow-hidden shadow-2xl relative">
            <button 
              onClick={() => setShowAuthModal(false)} 
              className="absolute top-4 right-4 z-10 p-2 bg-black/50 rounded-full text-neutral-500 hover:text-white transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
            
            {/* Hacker Side */}
            <div 
              className="flex-1 p-10 border-b md:border-b-0 md:border-r border-neutral-800 hover:bg-red-950/20 transition-colors group cursor-pointer flex flex-col items-center text-center" 
              onClick={() => { setAuthRole('hacker'); setShowAuthModal(false); }}
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
              className="flex-1 p-10 hover:bg-blue-950/20 transition-colors group cursor-pointer flex flex-col items-center text-center" 
              onClick={() => { setAuthRole('analyst'); setShowAuthModal(false); }}
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
                <span className="font-bold text-blue-400 text-xs tracking-wider uppercase flex items-center">
                  <MessageSquare className="w-4 h-4 mr-2" /> Analyst Portal (Blue Team)
                </span>
              </div>
            
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
          </div>
          )}
        </div>

        {/* RIGHT PANEL: SVG Graph + Code Viewer */}
        <div className="flex-1 flex flex-col min-w-0 bg-[#0a0a0a]">
          
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

             <svg className="w-full h-full">
              <defs>
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

              {edges.map((edge, idx) => {
                const source = nodes.find(n => n.id === edge.from);
                const target = nodes.find(n => n.id === edge.to);
                if (!source || !target) return null;
                
                const edgeId = `edge-${idx}`;
                const isHealed = edge.label === 'HAS_MITIGATION';
                const isExploit = edge.label === 'EXPLOITS' || edge.label === 'AFFECTS';
                
                const isFaded = hoveredNodeId !== null && !connectedEdges.has(edgeId);
                
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

              {nodes.map(node => {
                const isSelected = selectedNode?.id === node.id;
                const isFaded = hoveredNodeId !== null && !connectedNodes.has(node.id);
                
                let fill = '#1e3a8a';
                let stroke = '#3b82f6';
                let glow = 'rgba(59, 130, 246, 0.4)';
                
                if (node.status === 'UNMITIGATED') {
                  fill = '#450a0a';
                  stroke = '#ef4444';
                  glow = 'rgba(239, 68, 68, 0.6)';
                } else if (node.label === 'Mitigation' || node.status === 'SELF_HEALED') {
                  fill = '#052e16';
                  stroke = '#22c55e';
                  glow = 'rgba(34, 197, 94, 0.4)';
                }

                return (
                  <g 
                    key={node.id} 
                    onClick={() => setSelectedNode(node)}
                    onMouseEnter={() => setHoveredNodeId(node.id)}
                    onMouseLeave={() => setHoveredNodeId(null)}
                    className={`cursor-pointer transition-all duration-300 node-float ${isFaded ? 'opacity-20' : 'opacity-100'}`}
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
                  </g>
                );
              })}
             </svg>
          </div>

        </div>

      </main>
    </div>
  );
}
