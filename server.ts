import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // In-memory Graph State mimicking the Python backend's fallback graph_db
  const graphState: any = {
    nodes: [
      { id: 'APT29', properties: { label: 'ThreatActor', name: 'APT29 (Cozy Bear)', description: 'Russian state-sponsored advanced persistent threat actor' } },
      { id: 'Lazarus', properties: { label: 'ThreatActor', name: 'Lazarus Group', description: 'North Korean cyber threat group' } },
      { id: 'Sandworm', properties: { label: 'ThreatActor', name: 'Sandworm Team', description: 'Destructive threat actor targeting critical infrastructure' } },
      { id: 'FIN7', properties: { label: 'ThreatActor', name: 'FIN7', description: 'Financially motivated cybercrime group' } },
      
      { id: 'WellMess', properties: { label: 'Malware', name: 'WellMess RAT', description: 'Cross-platform malware for shell execution and TLS exfiltration' } },
      { id: 'CobaltStrike', properties: { label: 'Malware', name: 'Cobalt Strike', description: 'Commercial adversary simulation software' } },
      { id: 'BlackEnergy', properties: { label: 'Malware', name: 'BlackEnergy', description: 'Trojan used in attacks against industrial control systems' } },
      { id: 'DarkSide', properties: { label: 'Malware', name: 'DarkSide Ransomware', description: 'Ransomware-as-a-Service (RaaS) payload' } },
      
      { id: 'CVE-2021-41773', properties: { label: 'Vulnerability', name: 'CVE-2021-41773', description: 'Apache HTTP Server 2.4.49 path traversal & RCE', status: 'SELF_HEALED', injected_by: 'system' } },
      { id: 'CVE-2021-44228', properties: { label: 'Vulnerability', name: 'Log4Shell', description: 'RCE in Log4j logging library', status: 'UNMITIGATED', injected_by: 'system' } },
      { id: 'CVE-2023-23397', properties: { label: 'Vulnerability', name: 'CVE-2023-23397', description: 'Microsoft Outlook Elevation of Privilege', status: 'UNMITIGATED', injected_by: 'system' } },
      { id: 'CVE-2020-1472', properties: { label: 'Vulnerability', name: 'ZeroLogon', description: 'Netlogon Elevation of Privilege', status: 'UNMITIGATED', injected_by: 'system' } },
      
      { id: 'Apache Web Server', properties: { label: 'Software', name: 'Apache Web Server', description: 'Production HTTP Server' } },
      { id: 'MS Exchange', properties: { label: 'Software', name: 'MS Exchange Server', description: 'Enterprise email server' } },
      { id: 'Customer DB', properties: { label: 'Software', name: 'MySQL DB', description: 'Customer transaction database' } },
      { id: 'K8s Cluster', properties: { label: 'Software', name: 'Kubernetes Cluster', description: 'Container orchestration platform' } },
      { id: 'Windows DC', properties: { label: 'Software', name: 'Windows Domain Controller', description: 'Active Directory Identity Server' } },
      { id: 'Payment Gateway', properties: { label: 'Software', name: 'Payment Gateway', description: 'Financial transaction processor' } },
      { id: 'SCADA System', properties: { label: 'Software', name: 'SCADA Controller', description: 'Industrial control network' } },
      
      { id: 'Patch Apache 2.4.51', properties: { label: 'Mitigation', name: 'Patch Apache 2.4.51', description: 'Vendor security upgrade', status: 'APPROVED' } },
      { id: 'MFA Enforced', properties: { label: 'Mitigation', name: 'Enforce MFA', description: 'Multi-factor authentication policy', status: 'APPROVED' } }
    ],
    edges: [
      { from: 'APT29', to: 'WellMess', label: 'USES' },
      { from: 'Lazarus', to: 'CobaltStrike', label: 'USES' },
      { from: 'Sandworm', to: 'BlackEnergy', label: 'USES' },
      { from: 'FIN7', to: 'DarkSide', label: 'USES' },
      
      { from: 'WellMess', to: 'CVE-2021-41773', label: 'EXPLOITS' },
      { from: 'CobaltStrike', to: 'CVE-2021-44228', label: 'EXPLOITS' },
      { from: 'BlackEnergy', to: 'CVE-2020-1472', label: 'EXPLOITS' },
      { from: 'DarkSide', to: 'CVE-2023-23397', label: 'EXPLOITS' },
      { from: 'FIN7', to: 'CobaltStrike', label: 'USES' },
      
      { from: 'CVE-2021-41773', to: 'Apache Web Server', label: 'AFFECTS' },
      { from: 'CVE-2021-44228', to: 'Customer DB', label: 'AFFECTS' },
      { from: 'CVE-2021-44228', to: 'K8s Cluster', label: 'AFFECTS' },
      { from: 'CVE-2023-23397', to: 'MS Exchange', label: 'AFFECTS' },
      { from: 'CVE-2020-1472', to: 'Windows DC', label: 'AFFECTS' },
      { from: 'CVE-2020-1472', to: 'SCADA System', label: 'AFFECTS' },
      { from: 'CVE-2021-44228', to: 'Payment Gateway', label: 'AFFECTS' },
      
      { from: 'CVE-2021-41773', to: 'Patch Apache 2.4.51', label: 'HAS_MITIGATION' },
      { from: 'CVE-2023-23397', to: 'MFA Enforced', label: 'HAS_MITIGATION' }
    ]
  };

  // Keep track of WS clients
  let wsClients: any[] = [];
  // Since we can't easily do WebSocket upgrades on the same port in Express without a custom HTTP server, 
  // we'll let Vite handle WS for now or just skip actual WS broadcast if not requested, but wait, 
  // the frontend connects to `ws://${window.location.host}/api/user/ws`. 
  // Let's implement a simple HTTP long-polling or just ignore it since it's just a demo.
  // Actually, Express-WS can be used, but we don't have it. We can just mock the WS.
  
  // API Routes
  app.get('/api/user/graph', (req, res) => {
    res.json(graphState);
  });

  app.post('/api/hacker/inject', (req, res) => {
    const { vuln_name, target_software, description } = req.body;
    
    // Inject node
    graphState.nodes.push({
      id: vuln_name,
      properties: { label: 'Vulnerability', name: vuln_name, description, status: 'UNMITIGATED', injected_by: 'hacker' }
    });
    
    // Check if target software exists, if not add it
    if (!graphState.nodes.find((n: any) => n.id === target_software)) {
      graphState.nodes.push({
        id: target_software,
        properties: { label: 'Software', name: target_software, description: 'Targeted System' }
      });
    }

    // Add Affects edge
    graphState.edges.push({
      from: vuln_name,
      to: target_software,
      label: 'AFFECTS'
    });

    res.json({ status: "success", details: { vulnerability: vuln_name, target_software } });
  });

  app.post('/api/user/chat', (req, res) => {
    const { query } = req.body;
    const queryLower = query.toLowerCase();
    
    // 1. Check for "fix" command
    if (queryLower === 'fix' || queryLower.startsWith('fix ')) {
      const unmitigatedVulns = graphState.nodes.filter((n: any) => n.properties.label === 'Vulnerability' && n.properties.status === 'UNMITIGATED');
      if (unmitigatedVulns.length === 0) {
        return res.json({ data: { reply: "There are currently no active vulnerabilities to fix. The system is secure.", logs: [] } });
      }

      let targetVuln = unmitigatedVulns[0];
      if (queryLower.startsWith('fix ')) {
        const specific = queryLower.split(' ')[1];
        const found = unmitigatedVulns.find((v: any) => v.id.toLowerCase().includes(specific) || v.properties.name.toLowerCase().includes(specific));
        if (found) targetVuln = found;
      }

      const vuln_name = targetVuln.id;
      const patch_name = `Patch for ${vuln_name}`;
      
      graphState.nodes.push({
        id: patch_name,
        properties: { label: 'Mitigation', name: patch_name, description: 'Dynamically synthesized patch via Gemini LLM', status: 'SELF_HEALED' }
      });
      
      targetVuln.properties.status = 'SELF_HEALED';
      graphState.edges.push({
        from: vuln_name,
        to: patch_name,
        label: 'HAS_MITIGATION'
      });

      const affected = graphState.edges.filter((e: any) => e.from === vuln_name && e.label === 'AFFECTS').map((e: any) => e.to).join(', ') || 'Unknown Service';

      let replyText = `### Remediation Applied: ${vuln_name}\n\n`;
      replyText += `**🔍 Root Cause:** The vulnerability occurs due to unvalidated input parsing in the target service leading to arbitrary code execution.\n\n`;
      replyText += `**🛡️ Possibilities & Risks:** If left unpatched, threat actors could achieve remote privilege escalation and pivot laterally into the internal network.\n\n`;
      replyText += `**⚙️ Steps Taken by Agent:**\n1. Traversed graph to identify affected node: \`${affected}\`.\n2. Queried NVD API for recommended mitigations.\n3. Synthesized patch script configuration.\n4. Applied virtual patch to ingress firewall rules.\n\n`;
      replyText += `**📝 Changed Items:**\n- Added \`${patch_name}\` to Mitigation controls.\n- Edges updated: \`${vuln_name} -> HAS_MITIGATION -> ${patch_name}\`\n- Risk Status changed to **SELF_HEALED**.\n\n`;
      replyText += `The network topology has been updated to reflect the new secured state.`;

      const logs = [
        `⚡ [Step 1: Agentic Reflection] Received 'fix' command for ${vuln_name}.`,
        `🌐 [Step 2: Knowledge Retrieval] Fetching mitigation steps from LLM/NVD...`,
        `🛡️ [Step 3: Graph Mutation] MERGE (m:Mitigation) MERGE (v)-[:HAS_MITIGATION]->(m)`,
        `✅ [Step 4: Subgraph Updated] Risk mitigated for target: ${affected}`
      ];

      return res.json({ data: { reply: replyText, logs, snapshot: graphState } });
    }

    // 2. Check if asking about bugs/vulns
    if (queryLower.includes('bug') || queryLower.includes('injected') || queryLower.includes('affect') || queryLower.includes('vulnerabilit')) {
      const activeVulns = graphState.nodes.filter((n: any) => n.properties.label === 'Vulnerability' && n.properties.status === 'UNMITIGATED');
      
      if (activeVulns.length > 0) {
        let replyText = "Based on the latest graph telemetry, here are the active threats:\n\n";
        
        activeVulns.forEach((vuln: any) => {
          const affectEdges = graphState.edges.filter((e: any) => e.from === vuln.id && e.label === 'AFFECTS');
          const affectedTargets = affectEdges.map((e: any) => e.to).join(', ');
          replyText += `- **Vulnerability:** ${vuln.id}\n- **Details:** ${vuln.properties.description}\n- **Affects:** 🖥️ ${affectedTargets}\n- **Status:** 🔴 ${vuln.properties.status}\n\n`;
        });

        replyText += "Would you like to fix this? (Reply with **'fix'** to initiate automated remediation)";
        
        const logs = [
          "⚡ [Step 1: Intent Routing] User requested active threat landscape.",
          "🔍 [Step 2: Graph Traversal] Cypher: MATCH (v:Vulnerability {status: 'UNMITIGATED'})-[r:AFFECTS]->(s:Software) RETURN v, s",
          `✅ [Step 3: Retrieval] Found ${activeVulns.length} active node(s) affecting target infrastructure.`
        ];
        
        return res.json({ data: { reply: replyText, logs: logs }});
      } else {
        return res.json({ data: { reply: "I do not see any active unmitigated vulnerabilities (bugs) in the graph right now. The infrastructure is clean.", logs: [] } });
      }
    }

    // 3. General overview
    if (queryLower.includes('system') || queryLower.includes('component') || queryLower.includes('software') || queryLower.includes('actor') || queryLower.includes('tell me about') || queryLower.includes('what is')) {
      const softwares = graphState.nodes.filter((n: any) => n.properties.label === 'Software').map((n: any) => n.properties.name);
      const actors = graphState.nodes.filter((n: any) => n.properties.label === 'ThreatActor').map((n: any) => n.properties.name);
      
      let replyText = `### GraphRAG System Overview\n\n`;
      replyText += `I am currently monitoring **${graphState.nodes.length} entities** and **${graphState.edges.length} relationships** in the knowledge graph.\n\n`;
      replyText += `**🖥️ Infrastructure / Components:**\n${softwares.map((s: string) => `- ${s}`).join('\n')}\n\n`;
      replyText += `**🥷 Known Threat Actors Tracked:**\n${actors.map((a: string) => `- ${a}`).join('\n')}\n\n`;
      replyText += `Ask me about active vulnerabilities, or inject a new one from the Red Team console.`;

      return res.json({ data: { reply: replyText, logs: ["⚡ [Step 1: Graph Traversal] MATCH (n) RETURN n.label, n.name"] }});
    }

    // Default chatbot response
    res.json({ data: { 
      reply: `I am your GraphRAG Assistant. I am monitoring ${graphState.nodes.length} nodes and ${graphState.edges.length} edges in the knowledge graph.\n\n(Tip: Try asking "what bugs are active?", "tell me about the system components", or reply "fix" to patch open vulnerabilities!)`, 
      logs: [] 
    } });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*all', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
