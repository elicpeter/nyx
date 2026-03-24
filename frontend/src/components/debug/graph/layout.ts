import dagre from '@dagrejs/dagre';
import type { GraphNode, GraphEdge, LayoutResult, LayoutNode, LayoutEdge } from './types';

const CHAR_W = 7.2;
const PAD_X = 32;
const LINE_H = 16;
const PAD_Y = 16;
const MIN_W = 90;
const BADGE_H = 16;

function computeNodeDimensions(node: GraphNode): { w: number; h: number } {
  const lines = [node.label];
  if (node.detail) lines.push(node.detail);
  if (node.sublabel) lines.push(node.sublabel);

  const maxLen = Math.max(...lines.map((l) => l.length));
  const w = Math.max(MIN_W, maxLen * CHAR_W + PAD_X);
  const h = lines.length * LINE_H + PAD_Y + (node.badges?.length ? BADGE_H : 0);

  return { w, h };
}

export function computeLayout(
  nodes: GraphNode[],
  edges: GraphEdge[],
  mode: 'cfg' | 'callgraph' = 'cfg',
): LayoutResult {
  if (nodes.length === 0) return { nodes: [], edges: [], width: 0, height: 0 };

  const g = new dagre.graphlib.Graph();

  const isCfg = mode === 'cfg';
  g.setGraph({
    rankdir: 'TB',
    nodesep: isCfg ? 40 : 60,
    ranksep: isCfg ? 100 : 120,
    edgesep: isCfg ? 20 : 30,
    marginx: 40,
    marginy: 40,
    ranker: 'network-simplex',
  });
  g.setDefaultEdgeLabel(() => ({}));

  const idSet = new Set(nodes.map((n) => n.id));
  const dimMap = new Map<number, { w: number; h: number }>();

  for (const node of nodes) {
    const dims = computeNodeDimensions(node);
    dimMap.set(node.id, dims);
    g.setNode(String(node.id), { width: dims.w, height: dims.h });
  }

  for (const edge of edges) {
    if (!idSet.has(edge.source) || !idSet.has(edge.target)) continue;
    // Back edges get higher minlen to push them farther apart vertically
    const isBack = edge.type === 'Back';
    g.setEdge(String(edge.source), String(edge.target), {
      minlen: isBack ? 1 : 1,
      weight: isBack ? 0.3 : 1,
    });
  }

  dagre.layout(g);

  const layoutNodes: LayoutNode[] = [];
  for (const node of nodes) {
    const pos = g.node(String(node.id));
    const dims = dimMap.get(node.id)!;
    if (!pos) continue;
    layoutNodes.push({
      id: node.id,
      x: pos.x,
      y: pos.y,
      w: dims.w,
      h: dims.h,
      label: node.label,
      type: node.type,
      detail: node.detail,
      sublabel: node.sublabel,
      badges: node.badges,
      line: node.line,
    });
  }

  const layoutEdges: LayoutEdge[] = [];
  for (const edge of edges) {
    if (!idSet.has(edge.source) || !idSet.has(edge.target)) continue;
    const dagreEdge = g.edge(String(edge.source), String(edge.target));
    if (!dagreEdge) continue;
    layoutEdges.push({
      source: edge.source,
      target: edge.target,
      label: edge.label,
      type: edge.type,
      points: dagreEdge.points ?? [],
    });
  }

  const graphLabel = g.graph();
  const width = graphLabel?.width ?? 0;
  const height = graphLabel?.height ?? 0;

  return { nodes: layoutNodes, edges: layoutEdges, width, height };
}
