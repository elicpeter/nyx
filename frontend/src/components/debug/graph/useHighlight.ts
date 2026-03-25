import { useState, useMemo, useCallback } from 'react';
import type { LayoutEdge } from './types';

interface UseHighlightResult {
  hoveredNode: number | null;
  isNodeDimmed: (id: number) => boolean;
  isNodeHighlighted: (id: number) => boolean;
  isEdgeDimmed: (source: number, target: number) => boolean;
  isEdgeHighlighted: (source: number, target: number) => boolean;
  onNodeEnter: (id: number) => void;
  onNodeLeave: () => void;
}

export function useHighlight(edges: LayoutEdge[]): UseHighlightResult {
  const [hoveredNode, setHoveredNode] = useState<number | null>(null);

  // Pre-compute adjacency: node -> set of connected nodes
  const adjacency = useMemo(() => {
    const map = new Map<number, Set<number>>();
    for (const e of edges) {
      if (!map.has(e.source)) map.set(e.source, new Set());
      if (!map.has(e.target)) map.set(e.target, new Set());
      map.get(e.source)!.add(e.target);
      map.get(e.target)!.add(e.source);
    }
    return map;
  }, [edges]);

  const connectedNodes = useMemo(() => {
    if (hoveredNode === null) return null;
    const set = new Set<number>([hoveredNode]);
    const neighbors = adjacency.get(hoveredNode);
    if (neighbors) {
      for (const n of neighbors) set.add(n);
    }
    return set;
  }, [hoveredNode, adjacency]);

  const isNodeDimmed = useCallback(
    (id: number) => {
      if (connectedNodes === null) return false;
      return !connectedNodes.has(id);
    },
    [connectedNodes],
  );

  const isNodeHighlighted = useCallback(
    (id: number) => {
      if (connectedNodes === null) return false;
      return connectedNodes.has(id) && id !== hoveredNode;
    },
    [connectedNodes, hoveredNode],
  );

  const isEdgeDimmed = useCallback(
    (source: number, target: number) => {
      if (hoveredNode === null) return false;
      return source !== hoveredNode && target !== hoveredNode;
    },
    [hoveredNode],
  );

  const isEdgeHighlighted = useCallback(
    (source: number, target: number) => {
      if (hoveredNode === null) return false;
      return source === hoveredNode || target === hoveredNode;
    },
    [hoveredNode],
  );

  const onNodeEnter = useCallback((id: number) => setHoveredNode(id), []);
  const onNodeLeave = useCallback(() => setHoveredNode(null), []);

  return {
    hoveredNode,
    isNodeDimmed,
    isNodeHighlighted,
    isEdgeDimmed,
    isEdgeHighlighted,
    onNodeEnter,
    onNodeLeave,
  };
}
