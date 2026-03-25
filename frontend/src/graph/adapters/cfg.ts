import type { CfgEdgeView, CfgGraphView, CfgNodeView } from '@/api/types';
import type { GraphModel } from '../types';

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function normalizeText(value: string): string {
  return value.replace(/\s+/g, ' ').trim();
}

const CFG_EDGE_PRIORITY: Record<string, number> = {
  True: 4,
  False: 4,
  Exception: 3,
  Back: 2,
  Seq: 1,
};

function getCfgEdgePriority(kind: string): number {
  return CFG_EDGE_PRIORITY[kind] ?? 2;
}

export function formatCfgNodeLabel(node: CfgNodeView): string {
  const summary =
    node.kind === 'Call'
      ? node.callee ?? node.defines
      : node.defines ?? node.callee;

  if (summary) return `${node.kind}: ${truncate(normalizeText(summary), 56)}`;
  return node.kind;
}

export function normalizeCfgEdges(edges: CfgEdgeView[]): CfgEdgeView[] {
  const deduped = new Map<string, CfgEdgeView>();

  for (const edge of edges) {
    const key = `${edge.source}:${edge.target}`;
    const current = deduped.get(key);

    if (
      !current ||
      getCfgEdgePriority(edge.kind) > getCfgEdgePriority(current.kind)
    ) {
      deduped.set(key, edge);
    }
  }

  return [...deduped.values()];
}

export function adaptCfgGraph(data: CfgGraphView): GraphModel {
  const edges = normalizeCfgEdges(data.edges);

  return {
    kind: 'cfg',
    nodes: data.nodes.map((node) => ({
      key: String(node.id),
      rawId: node.id,
      label: formatCfgNodeLabel(node),
      kind: node.kind,
      detail: `Line ${node.line}`,
      sublabel: node.condition_text
        ? truncate(node.condition_text, 40)
        : undefined,
      badges: node.labels.length > 0 ? node.labels.slice(0, 4) : undefined,
      line: node.line,
      metadata: {
        ...node,
        isEntry: node.id === data.entry,
        isExit: node.kind === 'Exit' || node.kind === 'Return',
      },
    })),
    edges: edges.map((edge, index) => ({
      key: `cfg:${edge.source}:${edge.target}:${edge.kind}:${index}`,
      source: String(edge.source),
      target: String(edge.target),
      kind: edge.kind,
      label: edge.kind !== 'Seq' ? edge.kind : undefined,
      metadata: {
        ...edge,
      },
    })),
  };
}
