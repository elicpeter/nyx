import type { GraphNode, GraphEdge } from './types';

/** Node types that should never be collapsed into a compound block. */
const CONTROL_TYPES = new Set([
  'Entry',
  'Exit',
  'If',
  'Loop',
  'Return',
  'Break',
  'Continue',
]);

interface CompactResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** Map from compound node ID to the original node IDs it contains. */
  expandedIds: Map<number, number[]>;
}

/**
 * Collapse straight-line sequences of non-control-flow nodes into compound blocks.
 * A sequence is a chain of nodes where each has exactly one Seq in-edge and one Seq out-edge.
 */
export function compactGraph(
  nodes: GraphNode[],
  edges: GraphEdge[],
): CompactResult {
  if (nodes.length <= 3) {
    return { nodes, edges, expandedIds: new Map() };
  }

  // Build adjacency for Seq edges only
  const seqOut = new Map<number, number>(); // node -> single Seq successor
  const seqIn = new Map<number, number>(); // node -> single Seq predecessor
  const seqOutCount = new Map<number, number>();
  const seqInCount = new Map<number, number>();

  for (const n of nodes) {
    seqOutCount.set(n.id, 0);
    seqInCount.set(n.id, 0);
  }

  for (const e of edges) {
    if (e.type !== 'Seq') continue;
    seqOutCount.set(e.source, (seqOutCount.get(e.source) ?? 0) + 1);
    seqInCount.set(e.target, (seqInCount.get(e.target) ?? 0) + 1);
    seqOut.set(e.source, e.target);
    seqIn.set(e.target, e.source);
  }

  // Also count non-Seq edges for in/out degree
  const totalOutCount = new Map<number, number>();
  const totalInCount = new Map<number, number>();
  for (const n of nodes) {
    totalOutCount.set(n.id, 0);
    totalInCount.set(n.id, 0);
  }
  for (const e of edges) {
    totalOutCount.set(e.source, (totalOutCount.get(e.source) ?? 0) + 1);
    totalInCount.set(e.target, (totalInCount.get(e.target) ?? 0) + 1);
  }

  // A node is "chainable" if:
  // - Not a control-flow node type
  // - Exactly 1 total in-edge and 1 total out-edge (both Seq)
  const chainable = new Set<number>();
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  for (const n of nodes) {
    if (CONTROL_TYPES.has(n.type)) continue;
    if (
      totalInCount.get(n.id) === 1 &&
      totalOutCount.get(n.id) === 1 &&
      seqInCount.get(n.id) === 1 &&
      seqOutCount.get(n.id) === 1
    ) {
      chainable.add(n.id);
    }
  }

  // Walk chains: find runs of consecutive chainable nodes
  const consumed = new Set<number>();
  const chains: number[][] = [];

  for (const n of nodes) {
    if (consumed.has(n.id) || chainable.has(n.id)) continue;
    // Check if this non-chainable node leads into a chain
    if (seqOutCount.get(n.id) !== 1) continue;
    const next = seqOut.get(n.id);
    if (next === undefined || !chainable.has(next)) continue;

    const chain: number[] = [];
    let cur = next;
    while (cur !== undefined && chainable.has(cur) && !consumed.has(cur)) {
      chain.push(cur);
      consumed.add(cur);
      cur = seqOut.get(cur)!;
    }
    if (chain.length >= 2) {
      chains.push(chain);
    }
  }

  if (chains.length === 0) {
    return { nodes, edges, expandedIds: new Map() };
  }

  // Build compound nodes
  const removedIds = new Set<number>();
  const expandedIds = new Map<number, number[]>();
  const compoundNodes: GraphNode[] = [];
  let nextId = Math.max(...nodes.map((n) => n.id)) + 1;

  for (const chain of chains) {
    for (const id of chain) removedIds.add(id);

    const firstNode = nodeMap.get(chain[0])!;
    const lastNode = nodeMap.get(chain[chain.length - 1])!;
    const minLine = Math.min(
      ...chain.map((id) => nodeMap.get(id)!.line ?? 0).filter((l) => l > 0),
    );
    const maxLine = Math.max(
      ...chain.map((id) => nodeMap.get(id)!.line ?? 0).filter((l) => l > 0),
    );
    const lineRange =
      minLine > 0 && maxLine > 0 ? `L${minLine}\u2013L${maxLine}` : '';

    const compoundId = nextId++;
    compoundNodes.push({
      id: compoundId,
      label: `${chain.length} statements`,
      type: 'Compound',
      detail: lineRange || undefined,
      line: minLine > 0 ? minLine : undefined,
    });
    expandedIds.set(compoundId, chain);
  }

  // Rebuild node list
  const newNodes = nodes
    .filter((n) => !removedIds.has(n.id))
    .concat(compoundNodes);

  // Rebuild edges: remap edges that reference removed nodes to compound nodes
  const removedToCompound = new Map<number, number>();
  for (const cn of compoundNodes) {
    const origIds = expandedIds.get(cn.id)!;
    for (const id of origIds) {
      removedToCompound.set(id, cn.id);
    }
  }

  const edgeSet = new Set<string>();
  const newEdges: GraphEdge[] = [];

  for (const e of edges) {
    const src = removedToCompound.get(e.source) ?? e.source;
    const tgt = removedToCompound.get(e.target) ?? e.target;

    // Skip edges internal to a compound
    if (src === tgt && removedIds.has(e.source) && removedIds.has(e.target))
      continue;
    // Skip if both ends were removed to the same compound (internal edge)
    if (
      removedToCompound.has(e.source) &&
      removedToCompound.has(e.target) &&
      removedToCompound.get(e.source) === removedToCompound.get(e.target)
    )
      continue;

    const key = `${src}-${tgt}-${e.type}`;
    if (edgeSet.has(key)) continue;
    edgeSet.add(key);

    newEdges.push({ source: src, target: tgt, label: e.label, type: e.type });
  }

  return { nodes: newNodes, edges: newEdges, expandedIds };
}
