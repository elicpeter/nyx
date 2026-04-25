import type { CallGraphNodeView, CallGraphView } from '@/api/types';
import type { GraphModel } from '../types';

const MAX_LABEL = 44;
const MAX_DETAIL = 48;

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function summarizeNode(node: CallGraphNodeView): string {
  if (node.namespace) return truncate(node.namespace, MAX_DETAIL);

  const segments = node.file.split(/[\\/]/);
  return truncate(segments[segments.length - 1] ?? node.file, MAX_DETAIL);
}

export function adaptCallGraph(data: CallGraphView): GraphModel {
  const recursiveNodes = new Set<number>();
  for (const scc of data.sccs) {
    for (const id of scc) recursiveNodes.add(id);
  }

  return {
    kind: 'callgraph',
    nodes: data.nodes.map((node) => ({
      key: String(node.id),
      rawId: node.id,
      label: truncate(node.name, MAX_LABEL),
      kind: 'Call',
      detail: summarizeNode(node),
      metadata: {
        ...node,
        isRecursive: recursiveNodes.has(node.id),
        searchText: [
          node.name,
          node.namespace,
          node.file,
          node.lang,
          node.arity == null ? '' : String(node.arity),
        ]
          .filter(Boolean)
          .join(' ')
          .toLowerCase(),
      },
    })),
    edges: data.edges.map((edge, index) => ({
      key: `call:${edge.source}:${edge.target}:${index}`,
      source: String(edge.source),
      target: String(edge.target),
      kind: 'Call',
      metadata: {
        ...edge,
      },
    })),
  };
}
