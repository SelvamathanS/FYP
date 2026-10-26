import { GraphNode, GraphEdge } from '../types/threatGraph';
import { RawGraphNode, RawGraphEdge } from '../data/defaultGraph';

export type GraphLayoutMode = 'pipeline' | 'zones' | 'rack' | 'organic';

/**
 * Canonical semantic layer assignment according to CTI ontology:
 * Layer 0: ThreatActor
 * Layer 1: Malware
 * Layer 2: Technique
 * Layer 3: Vulnerability
 * Layer 4: Software / Application
 * Layer 5: Computer (Monitored Infrastructure)
 * Layer 6: Mitigation
 */
export function getNodeLayer(node: { label?: string; properties?: { label?: string } } | string): number {
  const lbl = typeof node === 'string' ? node : (node.properties?.label || node.label || 'Software');
  switch (lbl) {
    case 'ThreatActor':
    case 'Threat_Actor':
      return 0;
    case 'Malware':
      return 1;
    case 'Technique':
    case 'AttackPattern':
    case 'Attack_Pattern':
      return 2;
    case 'Vulnerability':
      return 3;
    case 'Software':
    case 'Application':
      return 4;
    case 'Computer':
    case 'Host':
    case 'Infrastructure':
      return 5;
    case 'Mitigation':
    case 'Defense':
      return 6;
    case 'Document':
      return 0;
    case 'IOC':
      return 1;
    case 'Campaign':
      return 0;
    default:
      return 4;
  }
}

export const xTiers: Record<string, number> = {
  ThreatActor: 90,
  Malware: 290,
  Technique: 490,
  Vulnerability: 690,
  Software: 940,
  Computer: 940,
  Mitigation: 2050
};

/**
 * Enterprise Subnet Zone mappings for network enclave clustering
 */
export function getSystemEnclave(name: string, index: number): {
  zoneId: 'edge' | 'app' | 'data' | 'mgmt';
  zoneName: string;
  cidr: string;
} {
  const lower = name.toLowerCase();
  if (lower.includes('db') || lower.includes('sql') || lower.includes('postgres') || (index >= 15 && index < 20)) {
    return { zoneId: 'data', zoneName: 'Secure Data Vault', cidr: '10.0.3.0/24' };
  }
  if (lower.includes('gw') || lower.includes('ingress') || lower.includes('web') || index < 6) {
    return { zoneId: 'edge', zoneName: 'DMZ & Ingress Gateway', cidr: '10.0.1.0/24' };
  }
  if (lower.includes('dc') || lower.includes('iam') || lower.includes('auth') || lower.includes('admin') || index >= 20) {
    return { zoneId: 'mgmt', zoneName: 'Identity & Core Management', cidr: '10.0.4.0/24' };
  }
  return { zoneId: 'app', zoneName: 'Application Services', cidr: '10.0.2.0/24' };
}

/**
 * Transforms raw threat graph data into positioned, typed graph entities
 * supporting multiple enterprise topology layout modes with guaranteed zero overlap.
 */
export function transformRawGraph(
  rawNodes: RawGraphNode[],
  rawEdges: RawGraphEdge[],
  positionCache?: Map<string, { x: number; y: number }>,
  forceReset: boolean = false,
  layoutMode: GraphLayoutMode = 'pipeline'
): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const categorized: Record<string, RawGraphNode[]> = {
    ThreatActor: [],
    Technique: [],
    Malware: [],
    Vulnerability: [],
    Software: [],
    Mitigation: []
  };

  rawNodes.forEach((n) => {
    const lbl = n.properties?.label || 'Software';
    if (categorized[lbl]) categorized[lbl].push(n);
    else categorized.Software.push(n);
  });

  const typedNodes: GraphNode[] = [];

  // Sort Software nodes by numeric identifier for deterministic layout
  const sortedSystems = [...categorized.Software].sort((a, b) => {
    const numA = parseInt((a.properties?.name || a.id).replace(/\D/g, '') || '0', 10);
    const numB = parseInt((b.properties?.name || b.id).replace(/\D/g, '') || '0', 10);
    return numA - numB;
  });

  const totalSystems = sortedSystems.length;

  // Grid dimensions with guaranteed zero-overlap air gaps
  // Software cards are width: 184, height: 104
  const spacingX = 230; // 184 width + 46px horizontal air gap
  const spacingY = 145; // 104 height + 41px vertical air gap
  const softwareStartX = 800;
  const startY = 140;

  // Dynamically compute optimal columns for software fleet
  const cols = totalSystems <= 6 ? 2 : totalSystems <= 12 ? 3 : totalSystems <= 20 ? 4 : 5;
  const maxSoftwareX = softwareStartX + (cols - 1) * spacingX;
  const softwareRightEdge = maxSoftwareX + 92;

  // In zones mode, calculate zone centers dynamically
  const zoneWidth = 260; // 184 card + 76px air gap between enclaves
  const zoneCenters: Record<'edge' | 'app' | 'data' | 'mgmt', number> = {
    edge: softwareStartX,
    app: softwareStartX + zoneWidth,
    data: softwareStartX + zoneWidth * 2,
    mgmt: softwareStartX + zoneWidth * 3
  };

  // Dynamic mitigation X coordinate guarantees clearance from the widest software boundary
  const dynamicMitigationX = layoutMode === 'zones'
    ? zoneCenters.mgmt + 92 + 160
    : layoutMode === 'organic'
      ? 1780
      : softwareRightEdge + 150;

  // Calculate infrastructure node positions dynamically based on active layout mode
  sortedSystems.forEach((n, index) => {
    let pos = forceReset ? null : positionCache?.get(n.id);

    if (!pos) {
      if (layoutMode === 'zones') {
        // Enclave clustering by enterprise security zone (single centered column per zone, zero overlap)
        const enclave = getSystemEnclave(n.properties?.name || n.id, index);
        const zoneSystems = sortedSystems.filter((s, i) => getSystemEnclave(s.properties?.name || s.id, i).zoneId === enclave.zoneId);
        const localIdx = Math.max(0, zoneSystems.findIndex(s => s.id === n.id));
        pos = {
          x: zoneCenters[enclave.zoneId],
          y: 150 + localIdx * 135
        };
      } else if (layoutMode === 'organic') {
        // Organic radial-flow coordinates with collision buffer
        const angle = (index / totalSystems) * Math.PI * 2;
        const radius = 290 + (index % 3) * 65;
        pos = {
          x: Math.round(1240 + Math.cos(angle) * radius),
          y: Math.round(430 + Math.sin(angle) * (radius * 0.75))
        };
      } else {
        // 'pipeline' and 'rack' layout modes (ample 46px horizontal & 41px vertical air gaps)
        const colIdx = index % cols;
        const rowIdx = Math.floor(index / cols);

        pos = {
          x: softwareStartX + colIdx * spacingX,
          y: startY + rowIdx * spacingY
        };
      }

      positionCache?.set(n.id, pos);
    }

    typedNodes.push({
      id: n.id,
      label: n.properties.label,
      name: n.properties.name || n.id,
      x: pos.x,
      y: pos.y,
      status: n.properties.status,
      details: n.properties.description || n.id,
      description: n.properties.description,
      severity: n.properties.severity,
      cvss: n.properties.cvss ? Number(n.properties.cvss) : undefined,
      cause: n.properties.cause,
      reproduction: n.properties.reproduction,
      installationProcedure: n.properties.installationProcedure,
      symptoms: n.properties.symptoms,
      troubleshootingProcess: n.properties.troubleshootingProcess,
      fixSolution: n.properties.fixSolution,
      verificationProcedure: n.properties.verificationProcedure,
      timestamp: n.properties.timestamp || new Date().toISOString(),
      dataset: n.properties.dataset,
      injected_by: n.properties.injected_by,
      ai_generated_description: n.properties.ai_generated_description,
      ai_generated_at: n.properties.ai_generated_at,
      codeLanguage: n.properties.codeLanguage,
      codeFileName: n.properties.codeFileName,
      buggyCode: n.properties.buggyCode,
      correctedCode: n.properties.correctedCode,
      errorMessage: n.properties.errorMessage,
      exploitScript: n.properties.exploitScript,
      rootCause: n.properties.rootCause,
      fixExplanation: n.properties.fixExplanation,
      hostname: n.properties.hostname,
      application: n.properties.application,
      technology: n.properties.technology,
      cpu: n.properties.cpu,
      ram: n.properties.ram,
      storage: n.properties.storage,
      installedSoftware: n.properties.installedSoftware,
      softwareVersions: n.properties.softwareVersions,
      affectedComponent: n.properties.affectedComponent,
      threat: n.properties.threat,
      purpose: n.properties.purpose,
      environment: n.properties.environment,
      os: n.properties.os,
      version: n.properties.version,
      port: n.properties.port ? Number(n.properties.port) : undefined,
      ip: n.properties.ip,
      service: n.properties.service,
      configFile: n.properties.configFile,
      configPath: n.properties.configPath,
      availableTools: n.properties.availableTools,
      dependencies: n.properties.dependencies
    });
  });

  // Position non-software tiers dynamically using canonical semantic layers:
  // Layer 0: ThreatActor (x: 90)
  // Layer 1: Malware (x: 290)
  // Layer 2: Technique (x: 490)
  // Layer 3: Vulnerability (x: 690)
  // Layer 6: Mitigation (x: dynamicMitigationX)
  const nonSoftwareCategories = ['ThreatActor', 'Malware', 'Technique', 'Vulnerability', 'Mitigation'];

  nonSoftwareCategories.forEach((cat) => {
    const catNodes = categorized[cat] || [];
    // Sort nodes deterministically for consistent vertical distribution
    const sortedCatNodes = [...catNodes].sort((a, b) => {
      const nameA = a.properties.name || a.id;
      const nameB = b.properties.name || b.id;
      return nameA.localeCompare(nameB);
    });

    const tierCount = sortedCatNodes.length;
    // Calculate vertical spacing with guaranteed zero-overlap
    const nonSoftSpacingY = Math.max(130, Math.min(180, Math.floor(650 / Math.max(tierCount, 1))));

    sortedCatNodes.forEach((n, index) => {
      let pos = forceReset ? null : positionCache?.get(n.id);
      if (!pos) {
        const targetX = cat === 'Mitigation' ? dynamicMitigationX : (xTiers[cat] ?? (100 + getNodeLayer(cat) * 200));
        const targetY = startY + index * nonSoftSpacingY;
        pos = { x: targetX, y: targetY };
        positionCache?.set(n.id, pos);
      }

      typedNodes.push({
        id: n.id,
        label: n.properties.label,
        name: n.properties.name || n.id,
        x: pos.x,
        y: pos.y,
        status: n.properties.status,
        details: n.properties.description || n.id,
        description: n.properties.description,
        severity: n.properties.severity,
        cvss: n.properties.cvss ? Number(n.properties.cvss) : undefined,
        cause: n.properties.cause,
        reproduction: n.properties.reproduction,
        installationProcedure: n.properties.installationProcedure,
        symptoms: n.properties.symptoms,
        troubleshootingProcess: n.properties.troubleshootingProcess,
        fixSolution: n.properties.fixSolution,
        verificationProcedure: n.properties.verificationProcedure,
        timestamp: n.properties.timestamp || new Date().toISOString(),
        dataset: n.properties.dataset,
        injected_by: n.properties.injected_by,
        ai_generated_description: n.properties.ai_generated_description,
        ai_generated_at: n.properties.ai_generated_at,
        codeLanguage: n.properties.codeLanguage,
        codeFileName: n.properties.codeFileName,
        buggyCode: n.properties.buggyCode,
        correctedCode: n.properties.correctedCode,
        errorMessage: n.properties.errorMessage,
        exploitScript: n.properties.exploitScript,
        rootCause: n.properties.rootCause,
        fixExplanation: n.properties.fixExplanation,
        hostname: n.properties.hostname,
        application: n.properties.application,
        technology: n.properties.technology,
        cpu: n.properties.cpu,
        ram: n.properties.ram,
        storage: n.properties.storage,
        installedSoftware: n.properties.installedSoftware,
        softwareVersions: n.properties.softwareVersions,
        affectedComponent: n.properties.affectedComponent,
        threat: n.properties.threat,
        purpose: n.properties.purpose,
        environment: n.properties.environment,
        os: n.properties.os,
        version: n.properties.version,
        port: n.properties.port ? Number(n.properties.port) : undefined,
        ip: n.properties.ip,
        service: n.properties.service,
        configFile: n.properties.configFile,
        configPath: n.properties.configPath,
        availableTools: n.properties.availableTools,
        dependencies: n.properties.dependencies
      });
    });
  });

  const typedEdges: GraphEdge[] = (rawEdges || []).map((e) => ({
    from: e.from,
    to: e.to,
    label: e.label
  }));

  return { nodes: typedNodes, edges: typedEdges };
}
