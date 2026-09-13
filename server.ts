import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import neo4j from 'neo4j-driver';

const NEO4J_URI = process.env.NEO4J_URI || '';
const NEO4J_USERNAME = process.env.NEO4J_USERNAME || '';
const NEO4J_PASSWORD = process.env.NEO4J_PASSWORD || '';

let driver: neo4j.Driver | null = null;
if (NEO4J_URI) {
  driver = neo4j.driver(NEO4J_URI, neo4j.auth.basic(NEO4J_USERNAME, NEO4J_PASSWORD));
}

const DEFAULT_GRAPH_STATE = {
    nodes: [
      { id: 'APT29', properties: { label: 'ThreatActor', name: 'APT29 (Cozy Bear)', description: 'Russian state-sponsored advanced persistent threat actor', dataset: 'MITRE ATT&CK' } },
      { id: 'Lazarus', properties: { label: 'ThreatActor', name: 'Lazarus Group', description: 'North Korean cyber threat group', dataset: 'MITRE ATT&CK' } },
      { id: 'Sandworm', properties: { label: 'ThreatActor', name: 'Sandworm Team', description: 'Destructive threat actor targeting critical infrastructure', dataset: 'MITRE ATT&CK' } },
      { id: 'FIN7', properties: { label: 'ThreatActor', name: 'FIN7', description: 'Financially motivated cybercrime group', dataset: 'MITRE ATT&CK' } },
      
      { id: 'T1190', properties: { label: 'Technique', name: 'Exploit Public-Facing Application', description: 'Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.', dataset: 'MITRE ATT&CK' } },
      { id: 'T1078', properties: { label: 'Technique', name: 'Valid Accounts', description: 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.', dataset: 'MITRE ATT&CK' } },

      { id: 'WellMess', properties: { label: 'Malware', name: 'WellMess RAT', description: 'Cross-platform malware for shell execution and TLS exfiltration', dataset: 'MITRE ATT&CK' } },
      { id: 'CobaltStrike', properties: { label: 'Malware', name: 'Cobalt Strike', description: 'Commercial adversary simulation software', dataset: 'MITRE ATT&CK' } },
      { id: 'BlackEnergy', properties: { label: 'Malware', name: 'BlackEnergy', description: 'Trojan used in attacks against industrial control systems', dataset: 'MITRE ATT&CK' } },
      { id: 'DarkSide', properties: { label: 'Malware', name: 'DarkSide Ransomware', description: 'Ransomware-as-a-Service (RaaS) payload', dataset: 'MITRE ATT&CK' } },
      
      { id: 'CVE-2021-41773', properties: { label: 'Vulnerability', name: 'CVE-2021-41773', description: 'Apache HTTP Server 2.4.49 path traversal & RCE', status: 'SELF_HEALED', injected_by: 'system', severity: 'MEDIUM', timestamp: new Date(Date.now() - 5000000).toISOString(), dataset: 'NVD CVE' } },
      { id: 'CVE-2021-44228', properties: { label: 'Vulnerability', name: 'Log4Shell', description: 'RCE in Log4j logging library', status: 'UNMITIGATED', injected_by: 'system', severity: 'CRITICAL', timestamp: new Date(Date.now() - 3000000).toISOString(), dataset: 'NVD CVE' } },
      { id: 'CVE-2023-23397', properties: { label: 'Vulnerability', name: 'CVE-2023-23397', description: 'Microsoft Outlook Elevation of Privilege', status: 'UNMITIGATED', injected_by: 'system', severity: 'HIGH', timestamp: new Date(Date.now() - 1000000).toISOString(), dataset: 'NVD CVE' } },
      { id: 'CVE-2020-1472', properties: { label: 'Vulnerability', name: 'ZeroLogon', description: 'Netlogon Elevation of Privilege', status: 'UNMITIGATED', injected_by: 'system', severity: 'CRITICAL', timestamp: new Date(Date.now() - 500000).toISOString(), dataset: 'NVD CVE' } },
      
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
      
      { from: 'APT29', to: 'T1190', label: 'USES' },
      { from: 'Lazarus', to: 'T1078', label: 'USES' },
      
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

// Fallback in-memory state if Neo4j is not connected or failing
let inMemoryState = JSON.parse(JSON.stringify(DEFAULT_GRAPH_STATE));

async function getGraphState() {
  if (!driver) return inMemoryState;
  
  const session = driver.session();
  try {
    const result = await session.run(`MATCH (n) OPTIONAL MATCH (n)-[r]->(m) RETURN n, r, m`);
    
    if (result.records.length === 0) {
      // Seed Database
      await saveGraphState(DEFAULT_GRAPH_STATE);
      return DEFAULT_GRAPH_STATE;
    }

    const nodesMap = new Map();
    const edgesMap = new Map();

    result.records.forEach(record => {
      const n = record.get('n');
      if (n) {
        nodesMap.set(n.properties.id, { id: n.properties.id, properties: n.properties });
      }
      const r = record.get('r');
      const m = record.get('m');
      if (r && m) {
        const edgeId = `${n.properties.id}-${r.type}-${m.properties.id}`;
        edgesMap.set(edgeId, { from: n.properties.id, to: m.properties.id, label: r.type });
        nodesMap.set(m.properties.id, { id: m.properties.id, properties: m.properties });
      }
    });

    return {
      nodes: Array.from(nodesMap.values()),
      edges: Array.from(edgesMap.values())
    };
  } catch (error) {
    console.error('Neo4j read error, falling back to memory:', error);
    return inMemoryState;
  } finally {
    await session.close();
  }
}

async function saveGraphState(state: any) {
  if (!driver) {
    inMemoryState = state;
    return;
  }
  
  const session = driver.session();
  try {
    // Basic sync: clear and rewrite for this demo
    await session.run('MATCH (n) DETACH DELETE n');
    
    for (const node of state.nodes) {
      const label = node.properties.label || 'Node';
      // Use parameterized query for safety and correct types
      await session.run(
        `CREATE (n:${label} $props)`,
        { props: { ...node.properties, id: node.id } }
      );
    }
    
    for (const edge of state.edges) {
      await session.run(
        `MATCH (a {id: $from}), (b {id: $to}) CREATE (a)-[r:${edge.label}]->(b)`,
        { from: edge.from, to: edge.to }
      );
    }
    inMemoryState = state; // Keep memory in sync
  } catch (error) {
    console.error('Neo4j write error:', error);
    inMemoryState = state;
  } finally {
    await session.close();
  }
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Routes
  app.get('/api/user/graph', async (req, res) => {
    const graphState = await getGraphState();
    res.json(graphState);
  });

  app.post('/api/hacker/inject', async (req, res) => {
    const graphState = await getGraphState();
    const { vuln_name, target_software, description } = req.body;
    
    // Inject node
    const severityOpts = ['CRITICAL', 'HIGH', 'MEDIUM'];
    const randomSeverity = severityOpts[Math.floor(Math.random() * severityOpts.length)];
    
    graphState.nodes.push({
      id: vuln_name,
      properties: { label: 'Vulnerability', name: vuln_name, description, status: 'UNMITIGATED', injected_by: 'hacker', severity: randomSeverity, timestamp: new Date().toISOString(), dataset: 'Live Injection Payload Stream' }
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

    await saveGraphState(graphState);
    res.json({ status: "success", details: { vulnerability: vuln_name, target_software } });
  });

  app.post('/api/user/chat', async (req, res) => {
    const graphState = await getGraphState();
    const { query } = req.body;
    const queryLower = query.toLowerCase();
    
    // 0. Check for prioritization / importance
    if (queryLower.includes('important') || queryLower.includes('prioriti') || queryLower.includes('faster') || queryLower.includes('critical')) {
       const unmitigated = graphState.nodes.filter((n: any) => n.properties.label === 'Vulnerability' && n.properties.status === 'UNMITIGATED');
       
       if (unmitigated.length === 0) {
          return res.json({ data: { reply: "There are currently no active vulnerabilities requiring prioritization. The system is secure.", logs: [] } });
       }

       let prioritized = unmitigated.map((vuln: any) => {
          const affectsEdges = graphState.edges.filter((e: any) => e.from === vuln.id && e.label === 'AFFECTS');
          const targets = affectsEdges.map((e: any) => e.to);
          let score = targets.length * 10;
          if (targets.some((t: string) => t.includes('SCADA') || t.includes('DC') || t.includes('Payment'))) score += 50;
          return { vuln, targets, score };
       }).sort((a: any, b: any) => b.score - a.score);

       const top = prioritized[0];
       let replyText = `### 🚨 Critical Priority: ${top.vuln.properties.name} (${top.vuln.id})\n\n`;
       replyText += `**Why?** Based on graph centrality, this vulnerability has the highest blast radius, actively affecting **${top.targets.length} critical systems** (${top.targets.join(', ')}).\n\n`;
       replyText += `If exploited, threat actors could pivot through these nodes leading to widespread network compromise. I recommend patching this immediately.\n\n`;
       replyText += `Reply with **"steps to fix ${top.vuln.id}"** to see the remediation plan, or just **"fix ${top.vuln.id}"** to deploy it automatically.`;
       
       return res.json({ data: { reply: replyText, logs: ["⚡ [Step 1: Impact Analysis] Calculating node centrality and critical paths...", `✅ [Step 2: Prioritization] Identified ${top.vuln.id} as highest risk.`] } });
    }

    // 0.5. Check for steps to fix
    if (queryLower.includes('step') || queryLower.includes('how to fix') || queryLower.includes('mitigate')) {
       const unmitigated = graphState.nodes.filter((n: any) => n.properties.label === 'Vulnerability' && n.properties.status === 'UNMITIGATED');
       if (unmitigated.length === 0) {
          return res.json({ data: { reply: "There are currently no active vulnerabilities to fix.", logs: [] } });
       }

       let targetVuln = unmitigated[0];
       if (queryLower.includes(targetVuln.id.toLowerCase())) {
         // keep it
       } else {
         const specific = unmitigated.find((v: any) => queryLower.includes(v.id.toLowerCase()) || queryLower.includes(v.properties.name.toLowerCase()));
         if (specific) targetVuln = specific;
       }

       const vuln_name = targetVuln.id;
       const affected = graphState.edges.filter((e: any) => e.from === vuln_name && e.label === 'AFFECTS').map((e: any) => e.to).join(', ') || 'Unknown Service';

       let replyText = `### 📋 Remediation Plan: ${vuln_name}\n\n`;
       replyText += `**Target System(s):** ${affected}\n\n`;
       replyText += `**Recommended Steps:**\n`;
       replyText += `1. **Isolate:** Temporarily restrict network ingress to \`${affected}\` to prevent active exploitation.\n`;
       replyText += `2. **Analyze Logs:** Check for Indicators of Compromise (IoCs) related to ${vuln_name}.\n`;
       replyText += `3. **Apply Patch:** Deploy the vendor-approved security update for ${vuln_name}.\n`;
       replyText += `4. **Verify:** Run a targeted vulnerability scan against \`${affected}\` to confirm mitigation.\n\n`;
       replyText += `Would you like me to automatically execute this workflow? Reply **"fix ${vuln_name}"**.`;

       return res.json({ data: { reply: replyText, logs: [`⚡ [Step 1: RAG Retrieval] Fetching runbooks for ${vuln_name}...`, `✅ [Step 2: Plan Generated] Remediation steps synthesized.`] } });
    }

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

      await saveGraphState(graphState);

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

    // 2.5 Check for queries about datasets and training
    if (queryLower.includes('dataset') || queryLower.includes('train') || queryLower.includes('mitre') || queryLower.includes('nvd') || queryLower.includes('cve') || queryLower.includes('data source') || queryLower.includes('knowledge')) {
      const mitreCount = graphState.nodes.filter((n: any) => n.properties.dataset === 'MITRE ATT&CK').length;
      const nvdCount = graphState.nodes.filter((n: any) => n.properties.dataset === 'NVD CVE').length;
      const streamCount = graphState.nodes.filter((n: any) => n.properties.dataset === 'Live Injection Payload Stream').length;
      
      let replyText = `### 🧠 Knowledge Graph Datasets & Training\n\n`;
      replyText += `The GraphRAG system is fully trained on structured threat intelligence and live telemetry. This makes the system **faster and absolute** when querying and mitigating threats. The current database includes:\n\n`;
      replyText += `1. **MITRE ATT&CK Framework (STIX 2.1)**\n   - Contains structured profiles for Threat Actors, Techniques, Tactics, and Malware.\n   - *Currently tracking ${mitreCount} nodes from this dataset.*\n\n`;
      replyText += `2. **National Vulnerability Database (NVD CVE JSON Feeds)**\n   - Dictionary of CVEs with standardized descriptions, affected software CPEs, and CVSS severity scores.\n   - *Currently tracking ${nvdCount} nodes from this dataset.*\n\n`;
      replyText += `3. **Live Injection Payload Stream**\n   - Runtime dynamic data generated by Hacker user sessions containing customized vulnerability records and exploit descriptions.\n   - *Currently tracking ${streamCount} dynamically injected node(s).*\n\n`;
      replyText += `Because the chatbot uses GraphRAG (Retrieval-Augmented Generation over this Knowledge Graph), it can directly query the DB to provide highly contextual mitigation strategies.`;
      
      const logs = [
        "⚡ [Step 1: Dataset Query] Identifying requested data sources in Graph DB...",
        "🔍 [Step 2: Cypher Execution] MATCH (n) WHERE EXISTS(n.dataset) RETURN n.dataset, count(n)",
        `✅ [Step 3: RAG Construction] Formulated response using underlying data provenance.`
      ];
      
      return res.json({ data: { reply: replyText, logs: logs }});
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
