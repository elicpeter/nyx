import { useMemo, useEffect, useCallback, useState } from 'react';
import type { GraphRendererProps } from './types';
import { computeLayout } from './layout';
import { compactGraph } from './compactGraph';
import { CfgNode } from './CfgNode';
import { EdgePath, EdgeMarkers, getMarkerId } from './EdgePath';
import { useZoomPan } from './useZoomPan';
import { useHighlight } from './useHighlight';
import { GraphToolbar } from './GraphToolbar';

export function GraphRenderer({
  nodes,
  edges,
  onNodeClick,
  selectedNode,
  mode = 'cfg',
  compact: compactProp,
  className,
}: GraphRendererProps) {
  const [compact, setCompact] = useState(compactProp ?? false);
  const isCfg = mode === 'cfg';

  // Update compact state when prop changes
  useEffect(() => {
    if (compactProp !== undefined) setCompact(compactProp);
  }, [compactProp]);

  // Compact graph transformation
  const graphData = useMemo(() => {
    if (!compact)
      return { nodes, edges, expandedIds: new Map<number, number[]>() };
    return compactGraph(nodes, edges);
  }, [nodes, edges, compact]);

  // Layout computation
  const layout = useMemo(() => {
    return computeLayout(graphData.nodes, graphData.edges, mode);
  }, [graphData.nodes, graphData.edges, mode]);

  // Interaction hooks
  const zoomPan = useZoomPan();
  const highlight = useHighlight(layout.edges);

  // Auto fit-to-view on data change
  useEffect(() => {
    // Small delay to allow container to mount/resize
    const timer = setTimeout(() => {
      zoomPan.fitToView(layout.width, layout.height);
    }, 50);
    return () => clearTimeout(timer);
  }, [layout.width, layout.height]);

  const handleFitToView = useCallback(() => {
    zoomPan.fitToView(layout.width, layout.height);
  }, [zoomPan.fitToView, layout.width, layout.height]);

  const handleResetView = useCallback(() => {
    zoomPan.resetView(layout.width, layout.height);
  }, [zoomPan.resetView, layout.width, layout.height]);

  const handleNodeClick = useCallback(
    (id: number) => {
      onNodeClick?.(id);
      // Center on clicked node
      const node = layout.nodes.find((n) => n.id === id);
      if (node) {
        zoomPan.centerOnNode(node.x, node.y);
      }
    },
    [onNodeClick, layout.nodes, zoomPan.centerOnNode],
  );

  if (nodes.length === 0) {
    return <div className="empty-state">No graph data</div>;
  }

  return (
    <div
      className={`graph-renderer-container ${className ?? ''}`}
      ref={zoomPan.containerRef}
    >
      <GraphToolbar
        onZoomIn={zoomPan.zoomIn}
        onZoomOut={zoomPan.zoomOut}
        onFitToView={handleFitToView}
        onResetView={handleResetView}
        compact={compact}
        onToggleCompact={() => setCompact((c) => !c)}
        showCompactToggle={isCfg}
        scale={zoomPan.state.scale}
      />
      <svg
        className="graph-renderer"
        onWheel={zoomPan.handlers.onWheel}
        onMouseDown={zoomPan.handlers.onMouseDown}
        onMouseMove={zoomPan.handlers.onMouseMove}
        onMouseUp={zoomPan.handlers.onMouseUp}
        onMouseLeave={zoomPan.handlers.onMouseLeave}
        style={{ cursor: zoomPan.dragging ? 'grabbing' : 'grab' }}
      >
        <defs>
          <EdgeMarkers />
        </defs>
        <g
          transform={`translate(${zoomPan.state.x}, ${zoomPan.state.y}) scale(${zoomPan.state.scale})`}
        >
          {/* Edges (rendered first, below nodes) */}
          {layout.edges.map((e, i) => (
            <EdgePath
              key={`${e.source}-${e.target}-${i}`}
              edge={e}
              dimmed={highlight.isEdgeDimmed(e.source, e.target)}
              highlighted={highlight.isEdgeHighlighted(e.source, e.target)}
              markerId={getMarkerId(e.type)}
            />
          ))}

          {/* Nodes */}
          {layout.nodes.map((n) => (
            <CfgNode
              key={n.id}
              node={n}
              selected={selectedNode === n.id}
              dimmed={highlight.isNodeDimmed(n.id)}
              highlighted={highlight.isNodeHighlighted(n.id)}
              onMouseEnter={() => highlight.onNodeEnter(n.id)}
              onMouseLeave={highlight.onNodeLeave}
              onClick={() => handleNodeClick(n.id)}
            />
          ))}
        </g>
      </svg>
    </div>
  );
}
