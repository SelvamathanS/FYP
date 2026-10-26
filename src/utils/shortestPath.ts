import { GraphNode, GraphEdge } from '../types/threatGraph';

export interface PathStep {
  stepNumber: number;
  node: GraphNode;
  edgeToNext?: GraphEdge;
  hopLabel?: string;
  actionSummary: string;
}

export interface ShortestPathResult {
  found: boolean;
  startNode: GraphNode | null;
  endNode: GraphNode | null;
  pathNodes: GraphNode[];
  pathEdges: GraphEdge[];
  steps: PathStep[];
  totalHops: number;
  nodeIds: Set<string>;
  edgeKeys: Set<string>;
  algorithm: 'Breadth-First Search (BFS)' | 'Undirected BFS Fallback';
  summary: string;
  riskAssessment: {
    level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    maxCvss: number;
    hasActiveFlaw: boolean;
    targetCompromised: boolean;
    criticalVulnerability?: GraphNode;
    mitigationNode?: GraphNode;
  };
}

/**
 * Creates a unique key for identifying edges
 */
export function getEdgeKey(edge: GraphEdge): string {
  return `${edge.from}->${edge.to}:${edge.label || ''}`;
}

/**
 * Breadth-First Search (BFS) to find the shortest path between startNodeId and targetNodeId.
 * BFS is mathematically optimal for finding minimum-hop shortest paths in graph networks.
 */
export function findShortestPath(
  nodes: GraphNode[],
  edges: GraphEdge[],
  startNodeId: string,
  targetNodeId: string
): ShortestPathResult {
  const nodeMap = new Map<string, GraphNode>();
  nodes.forEach(n => nodeMap.set(n.id, n));

  const startNode = nodeMap.get(startNodeId) || null;
  const endNode = nodeMap.get(targetNodeId) || null;

  if (!startNode || !endNode || startNodeId === targetNodeId) {
    return {
      found: false,
      startNode,
      endNode,
      pathNodes: startNode ? [startNode] : [],
      pathEdges: [],
      steps: startNode ? [{
        stepNumber: 1,
        node: startNode,
        actionSummary: 'Origin entity.'
      }] : [],
      totalHops: 0,
      nodeIds: new Set(startNode ? [startNode.id] : []),
      edgeKeys: new Set(),
      algorithm: 'Breadth-First Search (BFS)',
      summary: 'Start and target must be distinct, valid nodes in the network graph.',
      riskAssessment: {
        level: 'LOW',
        maxCvss: 0,
        hasActiveFlaw: false,
        targetCompromised: false
      }
    };
  }

  // 1. First attempt: Directed BFS (Adversary flow: ThreatActor -> Technique/Malware -> Vulnerability -> Software)
  const directedQueue: Array<{
    currentId: string;
    pathNodeIds: string[];
    pathEdges: GraphEdge[];
  }> = [{
    currentId: startNodeId,
    pathNodeIds: [startNodeId],
    pathEdges: []
  }];

  const directedVisited = new Set<string>([startNodeId]);
  let foundDirectedPath: { pathNodeIds: string[]; pathEdges: GraphEdge[] } | null = null;

  while (directedQueue.length > 0) {
    const item = directedQueue.shift()!;
    if (item.currentId === targetNodeId) {
      foundDirectedPath = item;
      break;
    }

    const outgoingEdges = edges.filter(e => e.from === item.currentId);
    for (const edge of outgoingEdges) {
      if (!directedVisited.has(edge.to)) {
        directedVisited.add(edge.to);
        directedQueue.push({
          currentId: edge.to,
          pathNodeIds: [...item.pathNodeIds, edge.to],
          pathEdges: [...item.pathEdges, edge]
        });
      }
    }
  }

  if (foundDirectedPath) {
    return assemblePathResult(
      nodes,
      foundDirectedPath.pathNodeIds,
      foundDirectedPath.pathEdges,
      startNode,
      endNode,
      'Breadth-First Search (BFS)'
    );
  }

  // 2. Fallback attempt: Undirected BFS (traversing edges in either direction if custom links exist)
  const undirectedQueue: Array<{
    currentId: string;
    pathNodeIds: string[];
    pathEdges: GraphEdge[];
  }> = [{
    currentId: startNodeId,
    pathNodeIds: [startNodeId],
    pathEdges: []
  }];

  const undirectedVisited = new Set<string>([startNodeId]);
  let foundUndirectedPath: { pathNodeIds: string[]; pathEdges: GraphEdge[] } | null = null;

  while (undirectedQueue.length > 0) {
    const item = undirectedQueue.shift()!;
    if (item.currentId === targetNodeId) {
      foundUndirectedPath = item;
      break;
    }

    // Check outgoing and incoming edges
    for (const edge of edges) {
      let nextId: string | null = null;
      if (edge.from === item.currentId && !undirectedVisited.has(edge.to)) {
        nextId = edge.to;
      } else if (edge.to === item.currentId && !undirectedVisited.has(edge.from)) {
        nextId = edge.from;
      }

      if (nextId) {
        undirectedVisited.add(nextId);
        undirectedQueue.push({
          currentId: nextId,
          pathNodeIds: [...item.pathNodeIds, nextId],
          pathEdges: [...item.pathEdges, edge]
        });
      }
    }
  }

  if (foundUndirectedPath) {
    return assemblePathResult(
      nodes,
      foundUndirectedPath.pathNodeIds,
      foundUndirectedPath.pathEdges,
      startNode,
      endNode,
      'Undirected BFS Fallback'
    );
  }

  // No path found
  return {
    found: false,
    startNode,
    endNode,
    pathNodes: [],
    pathEdges: [],
    steps: [],
    totalHops: 0,
    nodeIds: new Set(),
    edgeKeys: new Set(),
    algorithm: 'Breadth-First Search (BFS)',
    summary: `No connecting attack path exists between ${startNode.name} and ${endNode.name} in current graph topology.`,
    riskAssessment: {
      level: 'LOW',
      maxCvss: 0,
      hasActiveFlaw: false,
      targetCompromised: endNode.status === 'COMPROMISED'
    }
  };
}

function assemblePathResult(
  allNodes: GraphNode[],
  pathNodeIds: string[],
  pathEdges: GraphEdge[],
  startNode: GraphNode,
  endNode: GraphNode,
  algorithm: 'Breadth-First Search (BFS)' | 'Undirected BFS Fallback'
): ShortestPathResult {
  const nodeMap = new Map<string, GraphNode>();
  allNodes.forEach(n => nodeMap.set(n.id, n));

  const pathNodes = pathNodeIds.map(id => nodeMap.get(id)!).filter(Boolean);
  const nodeIds = new Set(pathNodeIds);
  const edgeKeys = new Set(pathEdges.map(getEdgeKey));

  // Build sequential steps
  const steps: PathStep[] = [];
  let maxCvss = 0;
  let criticalVulnerability: GraphNode | undefined;
  let hasActiveFlaw = false;

  for (let i = 0; i < pathNodes.length; i++) {
    const node = pathNodes[i];
    const edgeToNext = pathEdges[i];

    if (node.label === 'Vulnerability') {
      const cvss = node.cvss || (node.severity === 'CRITICAL' ? 10.0 : node.severity === 'HIGH' ? 8.5 : 6.0);
      if (cvss > maxCvss) {
        maxCvss = cvss;
        criticalVulnerability = node;
      }
      if (node.status === 'UNMITIGATED') {
        hasActiveFlaw = true;
      }
    }

    let actionSummary = '';
    const nextNode = pathNodes[i + 1];

    if (node.label === 'ThreatActor') {
      actionSummary = nextNode
        ? `Adversary group ${node.name} launches attack campaign deploying ${nextNode.name} via ${edgeToNext?.label || 'USES'}.`
        : `Threat actor ${node.name} serves as origin vector.`;
    } else if (node.label === 'Malware') {
      actionSummary = nextNode
        ? `Malicious payload ${node.name} executes on network and exploits flaw ${nextNode.name}.`
        : `Malware payload ${node.name} active in chain.`;
    } else if (node.label === 'Technique') {
      actionSummary = nextNode
        ? `Attack method ${node.name} (${node.id}) leveraged to reach ${nextNode.name}.`
        : `Tactical technique ${node.name} utilized.`;
    } else if (node.label === 'Vulnerability') {
      actionSummary = nextNode
        ? `Security flaw ${node.name} (CVSS ${node.cvss || 9.5}) directly compromises host ${nextNode.name}.`
        : `Vulnerability ${node.name} exploited.`;
    } else if (node.label === 'Software') {
      actionSummary = `Target host ${node.name} is breached; service ${node.service || 'daemon'} compromised on port ${node.port || 80}.`;
    } else {
      actionSummary = `Entity ${node.name} engaged in path step.`;
    }

    steps.push({
      stepNumber: i + 1,
      node,
      edgeToNext,
      hopLabel: edgeToNext?.label,
      actionSummary
    });
  }

  // Find if any mitigation exists for vulnerabilities in this path
  let mitigationNode: GraphNode | undefined;
  if (criticalVulnerability) {
    const mitEdge = allNodes.find(n => n.label === 'Mitigation');
    mitigationNode = mitEdge;
  }

  // Calculate Risk Level
  let level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM';
  if (maxCvss >= 9.0 || endNode.status === 'COMPROMISED') {
    level = 'CRITICAL';
  } else if (maxCvss >= 7.0 || hasActiveFlaw) {
    level = 'HIGH';
  } else if (maxCvss >= 4.0) {
    level = 'MEDIUM';
  } else {
    level = 'LOW';
  }

  const hopsCount = pathEdges.length;
  const summary = `Found shortest attack path of ${hopsCount} hop${hopsCount === 1 ? '' : 's'} (${pathNodes.map(n => n.name).join(' ➔ ')}). Exploit vector carries ${level} risk with highest CVSS score of ${maxCvss || 'N/A'}.`;

  return {
    found: true,
    startNode,
    endNode,
    pathNodes,
    pathEdges,
    steps,
    totalHops: hopsCount,
    nodeIds,
    edgeKeys,
    algorithm,
    summary,
    riskAssessment: {
      level,
      maxCvss,
      hasActiveFlaw,
      targetCompromised: endNode.status === 'COMPROMISED',
      criticalVulnerability,
      mitigationNode
    }
  };
}

/**
 * Finds the shortest path from a Threat Actor to ANY Software system in the graph.
 */
export function findShortestPathToAnySoftware(
  nodes: GraphNode[],
  edges: GraphEdge[],
  threatActorId: string
): ShortestPathResult | null {
  const softwareNodes = nodes.filter(n => n.label === 'Software');
  let bestResult: ShortestPathResult | null = null;

  for (const sw of softwareNodes) {
    const res = findShortestPath(nodes, edges, threatActorId, sw.id);
    if (res.found) {
      if (!bestResult || res.totalHops < bestResult.totalHops) {
        bestResult = res;
      }
    }
  }

  return bestResult;
}

/**
 * Finds the shortest attack path targeting a specific Software system from ANY Threat Actor.
 */
export function findShortestPathFromAnyThreatActor(
  nodes: GraphNode[],
  edges: GraphEdge[],
  softwareId: string
): ShortestPathResult | null {
  const threatActors = nodes.filter(n => n.label === 'ThreatActor');
  let bestResult: ShortestPathResult | null = null;

  for (const actor of threatActors) {
    const res = findShortestPath(nodes, edges, actor.id, softwareId);
    if (res.found) {
      if (!bestResult || res.totalHops < bestResult.totalHops) {
        bestResult = res;
      }
    }
  }

  return bestResult;
}
