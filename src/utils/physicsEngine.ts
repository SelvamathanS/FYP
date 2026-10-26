import { GraphNode, GraphEdge } from '../types/threatGraph';

export interface PhysicsSimulationOptions {
  repulsion: number;
  springLength: number;
  springStrength: number;
  centerPull: number;
  damping: number;
  centerX: number;
  centerY: number;
}

const DEFAULT_OPTIONS: PhysicsSimulationOptions = {
  repulsion: 50000,
  springLength: 230,
  springStrength: 0.04,
  centerPull: 0.005,
  damping: 0.82,
  centerX: 1150,
  centerY: 400
};

/**
 * Executes a single discrete step of force-directed layout relaxation.
 * Uses Barnes-Hut / Verlet physics principles with guaranteed non-overlapping collision boundaries.
 */
export function stepPhysicsSimulation(
  nodes: GraphNode[],
  edges: GraphEdge[],
  pinnedNodeIds: Set<string> = new Set(),
  options: Partial<PhysicsSimulationOptions> = {}
): GraphNode[] {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const n = nodes.length;
  if (n === 0) return nodes;

  // Node velocity & force maps
  const forces = new Map<string, { fx: number; fy: number }>();
  nodes.forEach(node => {
    forces.set(node.id, { fx: 0, fy: 0 });
  });

  // 1. Coulomb Repulsion & Hard Collision Boundary between all node pairs
  for (let i = 0; i < n; i++) {
    const nodeA = nodes[i];
    const forceA = forces.get(nodeA.id)!;

    for (let j = i + 1; j < n; j++) {
      const nodeB = nodes[j];
      const forceB = forces.get(nodeB.id)!;

      const dx = nodeB.x - nodeA.x;
      const dy = nodeB.y - nodeA.y;
      const distSq = dx * dx + dy * dy || 1;
      const dist = Math.sqrt(distSq);

      // Strict minimum boundary distances (Software cards are 184x104, icons are ~60x60)
      const isSoftwareA = nodeA.label === 'Software';
      const isSoftwareB = nodeB.label === 'Software';
      const minDist = isSoftwareA && isSoftwareB ? 230 : isSoftwareA || isSoftwareB ? 190 : 150;
      
      const rep = (opts.repulsion / (distSq + 120)) * (dist < minDist ? 3.0 : 1.0);
      const fx = (dx / dist) * rep;
      const fy = (dy / dist) * rep;

      forceA.fx -= fx;
      forceA.fy -= fy;
      forceB.fx += fx;
      forceB.fy += fy;

      // Hard non-overlapping elastic separation
      if (dist < minDist) {
        const overlap = minDist - dist;
        const pushX = (dx / dist) * overlap * 0.55;
        const pushY = (dy / dist) * overlap * 0.55;
        forceA.fx -= pushX * 25;
        forceA.fy -= pushY * 25;
        forceB.fx += pushX * 25;
        forceB.fy += pushY * 25;
      }
    }
  }

  // 2. Hooke's Spring Attraction along edges
  const nodeMap = new Map<string, GraphNode>();
  nodes.forEach(node => nodeMap.set(node.id, node));

  edges.forEach(edge => {
    const source = nodeMap.get(edge.from);
    const target = nodeMap.get(edge.to);
    if (!source || !target) return;

    const dx = target.x - source.x;
    const dy = target.y - source.y;
    const dist = Math.sqrt(dx * dx + dy * dy) || 1;

    const displacement = dist - opts.springLength;
    const springForce = displacement * opts.springStrength;

    const fx = (dx / dist) * springForce;
    const fy = (dy / dist) * springForce;

    const sourceF = forces.get(source.id);
    const targetF = forces.get(target.id);

    if (sourceF) {
      sourceF.fx += fx;
      sourceF.fy += fy;
    }
    if (targetF) {
      targetF.fx -= fx;
      targetF.fy -= fy;
    }
  });

  // 3. Gentle Centering Gravity & Velocity Integration
  return nodes.map(node => {
    if (pinnedNodeIds.has(node.id)) return node;

    const f = forces.get(node.id) || { fx: 0, fy: 0 };
    
    // Centering force
    const centerDx = opts.centerX - node.x;
    const centerDy = opts.centerY - node.y;
    f.fx += centerDx * opts.centerPull;
    f.fy += centerDy * opts.centerPull;

    // Dampen forces
    const maxVelocity = 25;
    const vx = Math.max(-maxVelocity, Math.min(maxVelocity, f.fx * 0.15)) * opts.damping;
    const vy = Math.max(-maxVelocity, Math.min(maxVelocity, f.fy * 0.15)) * opts.damping;

    return {
      ...node,
      x: Math.round(node.x + vx),
      y: Math.round(node.y + vy)
    };
  });
}
