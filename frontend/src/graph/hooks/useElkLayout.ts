import { useEffect, useMemo, useRef, useState } from 'react';
import { layoutGraphWithElk } from '../layout/elk';
import type { ElkLayoutPreset, GraphModel, LayoutGraphModel } from '../types';

interface LayoutState {
  graph: LayoutGraphModel | null;
  isLoading: boolean;
  error: Error | null;
}

function createLayoutKey(
  graph: GraphModel,
  overrides?: Partial<ElkLayoutPreset>,
): string {
  const nodeKey = graph.nodes
    .map(
      (node) => `${node.key}:${node.label}:${node.kind}:${node.detail ?? ''}`,
    )
    .join('|');
  const edgeKey = graph.edges
    .map((edge) => `${edge.key}:${edge.source}:${edge.target}:${edge.kind}`)
    .join('|');
  return JSON.stringify({
    kind: graph.kind,
    nodeKey,
    edgeKey,
    overrides,
  });
}

const layoutCache = new Map<string, LayoutGraphModel>();

// The hook stays async even on the main thread so moving ELK into a worker later
// does not require rewriting the React call sites.
export function useElkLayout(
  graph: GraphModel,
  overrides?: Partial<ElkLayoutPreset>,
): LayoutState {
  const layoutKey = useMemo(
    () => createLayoutKey(graph, overrides),
    [graph, overrides],
  );
  const [state, setState] = useState<LayoutState>(() => {
    const cached = layoutCache.get(layoutKey) ?? null;
    return {
      graph: cached,
      isLoading: cached == null,
      error: null,
    };
  });
  const requestRef = useRef(0);

  useEffect(() => {
    const cached = layoutCache.get(layoutKey);
    if (cached) {
      setState({
        graph: cached,
        isLoading: false,
        error: null,
      });
      return;
    }

    const requestId = requestRef.current + 1;
    requestRef.current = requestId;
    let cancelled = false;

    setState((current) => ({
      graph: current.graph,
      isLoading: true,
      error: null,
    }));

    void layoutGraphWithElk(graph, overrides)
      .then((layout) => {
        if (cancelled || requestRef.current !== requestId) return;
        layoutCache.set(layoutKey, layout);
        setState({
          graph: layout,
          isLoading: false,
          error: null,
        });
      })
      .catch((error: unknown) => {
        if (cancelled || requestRef.current !== requestId) return;
        setState({
          graph: null,
          isLoading: false,
          error: error instanceof Error ? error : new Error('Layout failed'),
        });
      });

    return () => {
      cancelled = true;
    };
  }, [graph, layoutKey, overrides]);

  return state;
}
