import { useMemo, useState, useRef, useCallback } from 'react';

interface GraphNode {
  id: number;
  label: string;
  type: string;
  detail?: string;
}

interface GraphEdge {
  source: number;
  target: number;
  label?: string;
  type: string;
}

interface Props {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onNodeClick?: (id: number) => void;
  selectedNode?: number | null;
}

interface LayoutNode {
  id: number;
  x: number;
  y: number;
  w: number;
  h: number;
  label: string;
  type: string;
}

interface LayoutEdge {
  source: number;
  target: number;
  label?: string;
  type: string;
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}

const NODE_H = 36;
const LAYER_GAP = 80;
const NODE_GAP = 24;
const CHAR_WIDTH = 7.5;
const NODE_PAD = 24;

function nodeColor(type: string): string {
  switch (type) {
    case 'Entry': return 'var(--success)';
    case 'Exit': return 'var(--text-tertiary)';
    case 'Call': return '#e67e22';
    case 'If': return 'var(--accent)';
    case 'Loop': return '#9b59b6';
    case 'Return': return '#e74c3c';
    default: return 'var(--bg-tertiary)';
  }
}

function edgeColor(type: string): string {
  switch (type) {
    case 'True': return 'var(--success)';
    case 'False': return '#e74c3c';
    case 'Back': return '#9b59b6';
    case 'Exception': return '#e67e22';
    default: return 'var(--text-tertiary)';
  }
}

function edgeDash(type: string): string {
  if (type === 'Back' || type === 'Exception') return '4 3';
  return '';
}

/** Simple layered graph layout using BFS ranking + barycenter ordering. */
function layoutGraph(
  nodes: GraphNode[],
  edges: GraphEdge[],
  entryId?: number,
): { nodes: LayoutNode[]; edges: LayoutEdge[]; width: number; height: number } {
  if (nodes.length === 0) return { nodes: [], edges: [], width: 0, height: 0 };

  const idSet = new Set(nodes.map((n) => n.id));
  const adj = new Map<number, number[]>();
  for (const n of nodes) adj.set(n.id, []);
  for (const e of edges) {
    if (e.type !== 'Back' && idSet.has(e.source) && idSet.has(e.target)) {
      adj.get(e.source)?.push(e.target);
    }
  }

  // BFS rank assignment
  const rank = new Map<number, number>();
  const start = entryId ?? nodes[0].id;
  const queue = [start];
  rank.set(start, 0);
  while (queue.length > 0) {
    const n = queue.shift()!;
    const r = rank.get(n)!;
    for (const s of adj.get(n) ?? []) {
      if (!rank.has(s)) {
        rank.set(s, r + 1);
        queue.push(s);
      }
    }
  }
  // Assign unranked nodes (disconnected) to max_rank + 1
  const maxRank = Math.max(0, ...rank.values());
  for (const n of nodes) {
    if (!rank.has(n.id)) rank.set(n.id, maxRank + 1);
  }

  // Group by layer
  const layers = new Map<number, GraphNode[]>();
  for (const n of nodes) {
    const r = rank.get(n.id)!;
    if (!layers.has(r)) layers.set(r, []);
    layers.get(r)!.push(n);
  }

  // Barycenter ordering (2 passes)
  const pos = new Map<number, number>();
  const sortedRanks = [...layers.keys()].sort((a, b) => a - b);
  for (const r of sortedRanks) {
    layers.get(r)!.forEach((n, i) => pos.set(n.id, i));
  }

  for (let pass = 0; pass < 2; pass++) {
    for (const r of sortedRanks) {
      if (r === 0) continue;
      const layer = layers.get(r)!;
      const pred = new Map<number, number[]>();
      for (const e of edges) {
        if (rank.get(e.source) === r - 1 && rank.get(e.target) === r) {
          if (!pred.has(e.target)) pred.set(e.target, []);
          pred.get(e.target)!.push(e.source);
        }
      }
      layer.sort((a, b) => {
        const ap = pred.get(a.id)?.map((p) => pos.get(p) ?? 0) ?? [];
        const bp = pred.get(b.id)?.map((p) => pos.get(p) ?? 0) ?? [];
        const am = ap.length > 0 ? ap.reduce((s, v) => s + v, 0) / ap.length : pos.get(a.id)!;
        const bm = bp.length > 0 ? bp.reduce((s, v) => s + v, 0) / bp.length : pos.get(b.id)!;
        return am - bm;
      });
      layer.forEach((n, i) => pos.set(n.id, i));
    }
  }

  // Compute coordinates
  const layoutNodes: LayoutNode[] = [];
  const nodeMap = new Map<number, LayoutNode>();
  let totalWidth = 0;

  for (const r of sortedRanks) {
    const layer = layers.get(r)!;
    let layerWidth = 0;
    const layerNodes: LayoutNode[] = [];

    for (const n of layer) {
      const w = Math.max(60, n.label.length * CHAR_WIDTH + NODE_PAD);
      layerNodes.push({
        id: n.id,
        x: 0,
        y: r * (NODE_H + LAYER_GAP) + 20,
        w,
        h: NODE_H,
        label: n.label,
        type: n.type,
      });
      layerWidth += w + NODE_GAP;
    }
    layerWidth -= NODE_GAP;
    totalWidth = Math.max(totalWidth, layerWidth);

    // Center within layer
    let x = -layerWidth / 2;
    for (const ln of layerNodes) {
      ln.x = x + ln.w / 2;
      x += ln.w + NODE_GAP;
      nodeMap.set(ln.id, ln);
      layoutNodes.push(ln);
    }
  }

  // Compute edges
  const layoutEdges: LayoutEdge[] = edges
    .filter((e) => nodeMap.has(e.source) && nodeMap.has(e.target))
    .map((e) => {
      const s = nodeMap.get(e.source)!;
      const t = nodeMap.get(e.target)!;
      return {
        ...e,
        x1: s.x,
        y1: s.y + s.h / 2,
        x2: t.x,
        y2: t.y - t.h / 2,
      };
    });

  const maxY = Math.max(0, ...layoutNodes.map((n) => n.y + n.h));
  return {
    nodes: layoutNodes,
    edges: layoutEdges,
    width: totalWidth + 100,
    height: maxY + 40,
  };
}

export function GraphRenderer({ nodes, edges, onNodeClick, selectedNode }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const dragStart = useRef({ x: 0, y: 0, panX: 0, panY: 0 });

  const layout = useMemo(() => {
    const entryNode = nodes.find((n) => n.type === 'Entry');
    return layoutGraph(nodes, edges, entryNode?.id);
  }, [nodes, edges]);

  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      if (e.button !== 0) return;
      setDragging(true);
      dragStart.current = { x: e.clientX, y: e.clientY, panX: pan.x, panY: pan.y };
    },
    [pan],
  );

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      if (!dragging) return;
      setPan({
        x: dragStart.current.panX + (e.clientX - dragStart.current.x),
        y: dragStart.current.panY + (e.clientY - dragStart.current.y),
      });
    },
    [dragging],
  );

  const handleMouseUp = useCallback(() => setDragging(false), []);

  if (nodes.length === 0) {
    return <div className="empty-state">No graph data</div>;
  }

  const cx = layout.width / 2 + pan.x;
  const cy = pan.y;

  return (
    <svg
      ref={svgRef}
      className="graph-renderer"
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
      style={{ cursor: dragging ? 'grabbing' : 'grab' }}
    >
      <defs>
        <marker id="arrow" viewBox="0 0 10 7" refX="10" refY="3.5" markerWidth="8" markerHeight="6" orient="auto">
          <polygon points="0 0, 10 3.5, 0 7" fill="var(--text-tertiary)" />
        </marker>
      </defs>
      <g transform={`translate(${cx}, ${cy})`}>
        {/* Edges */}
        {layout.edges.map((e, i) => {
          const dx = e.x2 - e.x1;
          const dy = e.y2 - e.y1;
          const mx = (e.x1 + e.x2) / 2;
          const my = (e.y1 + e.y2) / 2;
          const path =
            e.type === 'Back'
              ? `M ${e.x1} ${e.y1} C ${e.x1 + 60} ${e.y1}, ${e.x2 + 60} ${e.y2}, ${e.x2} ${e.y2}`
              : `M ${e.x1} ${e.y1} C ${e.x1} ${e.y1 + dy * 0.4}, ${e.x2} ${e.y2 - dy * 0.4}, ${e.x2} ${e.y2}`;

          return (
            <g key={i}>
              <path
                d={path}
                fill="none"
                stroke={edgeColor(e.type)}
                strokeWidth={1.5}
                strokeDasharray={edgeDash(e.type)}
                markerEnd="url(#arrow)"
              />
              {e.label && (
                <text
                  x={mx}
                  y={my - 4}
                  textAnchor="middle"
                  className="graph-edge-label"
                >
                  {e.label}
                </text>
              )}
            </g>
          );
        })}

        {/* Nodes */}
        {layout.nodes.map((n) => (
          <g
            key={n.id}
            className={`graph-node${selectedNode === n.id ? ' graph-node-selected' : ''}`}
            onClick={() => onNodeClick?.(n.id)}
            style={{ cursor: onNodeClick ? 'pointer' : 'default' }}
          >
            <rect
              x={n.x - n.w / 2}
              y={n.y - n.h / 2}
              width={n.w}
              height={n.h}
              rx={4}
              fill={nodeColor(n.type)}
              stroke={selectedNode === n.id ? 'var(--accent)' : 'var(--border)'}
              strokeWidth={selectedNode === n.id ? 2 : 1}
              opacity={0.9}
            />
            <text
              x={n.x}
              y={n.y + 4}
              textAnchor="middle"
              className="graph-node-label"
            >
              {n.label}
            </text>
          </g>
        ))}
      </g>
    </svg>
  );
}
