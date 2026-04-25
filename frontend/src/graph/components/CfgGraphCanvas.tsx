import { useEffect, useMemo, useState } from 'react';
import type { CfgGraphView, CfgNodeView } from '@/api/types';
import { AnalysisWorkspace } from '@/components/explorer/AnalysisWorkspace';
import {
  adaptCfgGraph,
  formatCfgNodeLabel,
  normalizeCfgEdges,
} from '../adapters/cfg';
import { useElkLayout } from '../hooks/useElkLayout';
import { SigmaGraph } from '../rendering/sigma/SigmaGraph';

interface CfgGraphCanvasProps {
  data: CfgGraphView;
}

function formatNodeList(
  ids: number[],
  nodeMap: Map<number, CfgNodeView>,
): string {
  if (ids.length === 0) return 'None';

  return ids
    .map((id) => {
      const node = nodeMap.get(id);
      return node ? `${id} (${node.kind})` : `${id}`;
    })
    .join(', ');
}

function NodeDetail({
  node,
  label,
  predecessorIds,
  successorIds,
  nodeMap,
}: {
  node: CfgNodeView;
  label: string;
  predecessorIds: number[];
  successorIds: number[];
  nodeMap: Map<number, CfgNodeView>;
}) {
  return (
    <div className="analysis-node-detail">
      <div className="debug-detail-row">
        <span className="debug-detail-label">Kind</span>
        <span className="debug-detail-value">{node.kind}</span>
      </div>
      <div className="debug-detail-row">
        <span className="debug-detail-label">Label</span>
        <span className="debug-detail-value mono">{label}</span>
      </div>
      <div className="debug-detail-row">
        <span className="debug-detail-label">Source</span>
        <span className="debug-detail-value">
          L{node.line} • span {node.span[0]}-{node.span[1]}
        </span>
      </div>
      {node.defines && (
        <div className="debug-detail-row">
          <span className="debug-detail-label">Defines</span>
          <span className="debug-detail-value mono">{node.defines}</span>
        </div>
      )}
      {node.uses.length > 0 && (
        <div className="debug-detail-row">
          <span className="debug-detail-label">Uses</span>
          <span className="debug-detail-value mono">
            {node.uses.join(', ')}
          </span>
        </div>
      )}
      {node.callee && (
        <div className="debug-detail-row">
          <span className="debug-detail-label">Callee</span>
          <span className="debug-detail-value mono">{node.callee}</span>
        </div>
      )}
      {node.labels.length > 0 && (
        <div className="debug-detail-row">
          <span className="debug-detail-label">Labels</span>
          <div>
            {node.labels.map((labelValue, index) => (
              <span key={index} className="cap-badge">
                {labelValue}
              </span>
            ))}
          </div>
        </div>
      )}
      {node.condition_text && (
        <div className="debug-detail-row">
          <span className="debug-detail-label">Condition</span>
          <span className="debug-detail-value mono">{node.condition_text}</span>
        </div>
      )}
      {node.enclosing_func && (
        <div className="debug-detail-row">
          <span className="debug-detail-label">Function</span>
          <span className="debug-detail-value mono">{node.enclosing_func}</span>
        </div>
      )}
      <div className="debug-detail-row">
        <span className="debug-detail-label">Predecessors</span>
        <span className="debug-detail-value mono">
          {formatNodeList(predecessorIds, nodeMap)}
        </span>
      </div>
      <div className="debug-detail-row">
        <span className="debug-detail-label">Successors</span>
        <span className="debug-detail-value mono">
          {formatNodeList(successorIds, nodeMap)}
        </span>
      </div>
    </div>
  );
}

export function CfgGraphCanvas({ data }: CfgGraphCanvasProps) {
  const [selectedNodeKey, setSelectedNodeKey] = useState<string | null>(null);

  const normalizedEdges = useMemo(
    () => normalizeCfgEdges(data.edges),
    [data.edges],
  );
  const fullGraph = useMemo(() => adaptCfgGraph(data), [data]);
  const nodeMap = useMemo(
    () => new Map(data.nodes.map((node) => [node.id, node])),
    [data.nodes],
  );
  const { graph, isLoading, error } = useElkLayout(fullGraph);

  useEffect(() => {
    if (!selectedNodeKey) return;
    if (fullGraph.nodes.some((node) => node.key === selectedNodeKey)) return;
    setSelectedNodeKey(null);
  }, [fullGraph.nodes, selectedNodeKey]);

  if (error) {
    return <div className="error-state">Failed to compute the CFG layout.</div>;
  }

  if (!graph) {
    return <div className="loading">Preparing CFG…</div>;
  }

  const selectedVisibleNode =
    selectedNodeKey == null
      ? undefined
      : fullGraph.nodes.find((node) => node.key === selectedNodeKey);

  const selectedRawNode =
    selectedVisibleNode && selectedVisibleNode.rawId >= 0
      ? nodeMap.get(selectedVisibleNode.rawId)
      : undefined;

  const predecessorIds =
    selectedRawNode == null
      ? []
      : normalizedEdges
          .filter((edge) => edge.target === selectedRawNode.id)
          .map((edge) => edge.source);
  const successorIds =
    selectedRawNode == null
      ? []
      : normalizedEdges
          .filter((edge) => edge.source === selectedRawNode.id)
          .map((edge) => edge.target);

  const inspector =
    selectedRawNode != null ? (
      <NodeDetail
        node={selectedRawNode}
        label={formatCfgNodeLabel(selectedRawNode)}
        predecessorIds={predecessorIds}
        successorIds={successorIds}
        nodeMap={nodeMap}
      />
    ) : undefined;

  const inspectorTitle = selectedRawNode
    ? `Node ${selectedRawNode.id}`
    : undefined;

  return (
    <AnalysisWorkspace
      inspector={inspector}
      inspectorTitle={inspectorTitle}
      canvas={
        <div className="analysis-graph-frame">
          <SigmaGraph
            graph={graph}
            viewKind="cfg"
            selectedNodeKey={selectedNodeKey}
            onNodeClick={(key) =>
              setSelectedNodeKey((current) => (current === key ? null : key))
            }
            loading={isLoading}
          />
        </div>
      }
    />
  );
}
