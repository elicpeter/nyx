import { useState } from 'react';
import { useDebugCallGraph } from '../../api/queries/debug';
import { GraphRenderer } from '../../components/debug/GraphRenderer';

export function CallGraphPage() {
  const [selectedNode, setSelectedNode] = useState<number | null>(null);
  const { data, isLoading, error } = useDebugCallGraph('project');

  if (isLoading) return <div className="loading">Loading call graph...</div>;
  if (error)
    return (
      <div className="error-state">
        Failed to load call graph. Have you run a scan?
      </div>
    );
  if (!data) return null;

  const graphNodes = data.nodes.map((n) => ({
    id: n.id,
    label: n.name,
    type: 'Call',
  }));

  const graphEdges = data.edges.map((e) => ({
    source: e.source,
    target: e.target,
    label: undefined,
    type: 'Seq',
  }));

  const selectedInfo = data.nodes.find((n) => n.id === selectedNode);

  return (
    <div className="debug-split">
      <div className="debug-split-main">
        <div className="debug-toolbar">
          <span className="debug-toolbar-label">Project scope</span>
          <span className="text-secondary">
            {data.nodes.length} functions, {data.edges.length} edges
            {data.sccs.length > 0 && `, ${data.sccs.length} recursive SCCs`}
            {data.unresolved_count > 0 &&
              `, ${data.unresolved_count} unresolved`}
          </span>
        </div>
        <GraphRenderer
          nodes={graphNodes}
          edges={graphEdges}
          onNodeClick={setSelectedNode}
          selectedNode={selectedNode}
        />
      </div>
      {selectedInfo && (
        <div className="debug-split-sidebar">
          <h3>{selectedInfo.name}</h3>
          <div className="debug-node-detail">
            <div className="debug-detail-row">
              <span className="debug-detail-label">Language</span>
              <span className="debug-detail-value">{selectedInfo.lang}</span>
            </div>
            <div className="debug-detail-row">
              <span className="debug-detail-label">Namespace</span>
              <span className="debug-detail-value mono">
                {selectedInfo.namespace}
              </span>
            </div>
            {selectedInfo.arity != null && (
              <div className="debug-detail-row">
                <span className="debug-detail-label">Arity</span>
                <span className="debug-detail-value">{selectedInfo.arity}</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
