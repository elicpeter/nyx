import { useEffect, useMemo, useState } from 'react';
import { useDebugCfg } from '../../api/queries/debug';
import { GraphRenderer } from '../../components/debug/GraphRenderer';
import { AnalysisWorkspace } from '../../components/explorer/AnalysisWorkspace';
import { ApiError } from '../../api/client';
import { EmptyState } from '../../components/ui/EmptyState';
import { ErrorState } from '../../components/ui/ErrorState';
import { LoadingState } from '../../components/ui/LoadingState';
import type { CfgNodeView } from '../../api/types';

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 1) + '\u2026' : s;
}

interface CfgAnalysisPanelProps {
  file: string;
  functionName: string;
}

export function CfgAnalysisPanel({
  file,
  functionName,
}: CfgAnalysisPanelProps) {
  const { data, isLoading, error } = useDebugCfg(file, functionName);
  const [selectedNode, setSelectedNode] = useState<number | null>(null);

  useEffect(() => {
    setSelectedNode(null);
  }, [file, functionName]);

  const nodeMap = useMemo(
    () => new Map(data?.nodes.map((node) => [node.id, node]) ?? []),
    [data],
  );

  if (isLoading) {
    return <LoadingState message="Loading CFG..." />;
  }
  if (error) {
    if (error instanceof ApiError && error.status === 404) {
      return (
        <EmptyState message="CFG data is not available for the selected function." />
      );
    }
    return <ErrorState message="Failed to load CFG." />;
  }
  if (!data || data.nodes.length === 0) {
    return (
      <EmptyState message="No CFG nodes are available for this function." />
    );
  }

  const graphNodes = data.nodes.map((n) => ({
    id: n.id,
    label: formatNodeLabel(n),
    type: n.kind,
    detail: `Line ${n.line}`,
    sublabel: n.condition_text ? truncate(n.condition_text, 35) : undefined,
    badges: n.labels.length > 0 ? n.labels : undefined,
    line: n.line,
  }));

  const graphEdges = data.edges.map((e) => ({
    source: e.source,
    target: e.target,
    label: e.kind !== 'Seq' ? e.kind : undefined,
    type: e.kind,
  }));

  const selectedInfo = data.nodes.find((n) => n.id === selectedNode);
  const predecessorIds =
    selectedInfo == null
      ? []
      : data.edges
          .filter((edge) => edge.target === selectedInfo.id)
          .map((edge) => edge.source);
  const successorIds =
    selectedInfo == null
      ? []
      : data.edges
          .filter((edge) => edge.source === selectedInfo.id)
          .map((edge) => edge.target);

  const handleNodeClick = (nodeId: number) => {
    setSelectedNode((current) => (current === nodeId ? null : nodeId));
  };

  return (
    <AnalysisWorkspace
      inspector={
        selectedInfo ? (
          <NodeDetail
            node={selectedInfo}
            label={formatNodeLabel(selectedInfo)}
            predecessorIds={predecessorIds}
            successorIds={successorIds}
            nodeMap={nodeMap}
          />
        ) : undefined
      }
      inspectorTitle={selectedInfo ? `Node ${selectedInfo.id}` : undefined}
      canvas={
        <div className="analysis-graph-frame">
          <GraphRenderer
            nodes={graphNodes}
            edges={graphEdges}
            onNodeClick={handleNodeClick}
            selectedNode={selectedNode}
            mode="cfg"
          />
        </div>
      }
    />
  );
}

function formatNodeLabel(node: CfgNodeView): string {
  if (node.callee) {
    return `${node.kind}: ${node.callee}`;
  }
  if (node.defines) {
    return `${node.kind}: ${node.defines}`;
  }
  return node.kind;
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
            {node.labels.map((l, i) => (
              <span key={i} className="cap-badge">
                {l}
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

function formatNodeList(
  ids: number[],
  nodeMap: Map<number, CfgNodeView>,
): string {
  if (ids.length === 0) {
    return 'None';
  }

  return ids
    .map((id) => {
      const node = nodeMap.get(id);
      return node ? `${id} (${node.kind})` : `${id}`;
    })
    .join(', ');
}
