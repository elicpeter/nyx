import type { GraphModel, GraphNodeModel } from '../types';

export function collectSearchMatches(
  graph: GraphModel,
  query: string,
  limit = 200,
): GraphNodeModel[] {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return [];

  const matches: GraphNodeModel[] = [];
  for (const node of graph.nodes) {
    const haystack = String(
      node.metadata?.searchText ?? node.label,
    ).toLowerCase();
    if (!haystack.includes(normalized)) continue;
    matches.push(node);
    if (matches.length >= limit) break;
  }

  return matches;
}

export function extractNeighborhoodSubgraph(
  graph: GraphModel,
  centerKey: string | null,
  radius: number,
): GraphModel {
  if (!centerKey || radius < 1) return graph;

  const nodeKeys = new Set(graph.nodes.map((node) => node.key));
  if (!nodeKeys.has(centerKey)) return graph;

  const adjacency = new Map<string, Set<string>>();
  for (const node of graph.nodes) adjacency.set(node.key, new Set());
  for (const edge of graph.edges) {
    adjacency.get(edge.source)?.add(edge.target);
    adjacency.get(edge.target)?.add(edge.source);
  }

  const visible = new Set<string>([centerKey]);
  let frontier = new Set<string>([centerKey]);

  for (let depth = 0; depth < radius; depth += 1) {
    const next = new Set<string>();
    for (const key of frontier) {
      const neighbors = adjacency.get(key);
      if (!neighbors) continue;
      for (const neighbor of neighbors) {
        if (visible.has(neighbor)) continue;
        visible.add(neighbor);
        next.add(neighbor);
      }
    }
    if (next.size === 0) break;
    frontier = next;
  }

  return {
    kind: graph.kind,
    nodes: graph.nodes.filter((node) => visible.has(node.key)),
    edges: graph.edges.filter(
      (edge) => visible.has(edge.source) && visible.has(edge.target),
    ),
  };
}
