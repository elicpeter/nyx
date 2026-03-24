import { useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { useDebugCfg } from '../../api/queries/debug';
import { GraphRenderer } from '../../components/debug/GraphRenderer';
import type { CfgNodeView } from '../../api/types';

export function CfgViewerPage() {
  const { file, fn_name } = useOutletContext<{ file: string | null; fn_name: string | null }>();
  const { data, isLoading, error } = useDebugCfg(file, fn_name);
  const [selectedNode, setSelectedNode] = useState<number | null>(null);

  if (!file || !fn_name) {
    return <div className="empty-state">Select a file and function to view the CFG.</div>;
  }
  if (isLoading) return <div className="loading">Loading CFG...</div>;
  if (error) return <div className="error-state">Failed to load CFG.</div>;
  if (!data) return null;

  const graphNodes = data.nodes.map((n) => ({
    id: n.id,
    label: `${n.kind}${n.callee ? ': ' + n.callee : n.defines ? ': ' + n.defines : ''} (L${n.line})`,
    type: n.kind,
  }));

  const graphEdges = data.edges.map((e) => ({
    source: e.source,
    target: e.target,
    label: e.kind !== 'Seq' ? e.kind : undefined,
    type: e.kind,
  }));

  const selectedInfo = data.nodes.find((n) => n.id === selectedNode);

  return (
    <div className="debug-split">
      <div className="debug-split-main">
        <GraphRenderer
          nodes={graphNodes}
          edges={graphEdges}
          onNodeClick={setSelectedNode}
          selectedNode={selectedNode}
        />
      </div>
      {selectedInfo && (
        <div className="debug-split-sidebar">
          <h3>Node {selectedInfo.id}</h3>
          <NodeDetail node={selectedInfo} />
        </div>
      )}
    </div>
  );
}

function NodeDetail({ node }: { node: CfgNodeView }) {
  return (
    <div className="debug-node-detail">
      <div className="debug-detail-row">
        <span className="debug-detail-label">Kind</span>
        <span className="debug-detail-value">{node.kind}</span>
      </div>
      <div className="debug-detail-row">
        <span className="debug-detail-label">Line</span>
        <span className="debug-detail-value">{node.line}</span>
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
          <span className="debug-detail-value mono">{node.uses.join(', ')}</span>
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
              <span key={i} className="cap-badge">{l}</span>
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
    </div>
  );
}
