import { useMemo, useState } from 'react';
import type { CallGraphView } from '@/api/types';
import { adaptCallGraph } from '../adapters/callgraph';
import { useElkLayout } from '../hooks/useElkLayout';
import {
  collectSearchMatches,
  extractNeighborhoodSubgraph,
} from '../reduction/neighborhood';
import { SigmaGraph } from '../rendering/sigma/SigmaGraph';

interface CallGraphCanvasProps {
  data: CallGraphView;
  selectedNodeId: number | null;
  onSelectNode: (id: number) => void;
}

export function CallGraphCanvas({
  data,
  selectedNodeId,
  onSelectNode,
}: CallGraphCanvasProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [neighborhoodOnly, setNeighborhoodOnly] = useState(false);
  const [radius, setRadius] = useState(1);

  const fullGraph = useMemo(() => adaptCallGraph(data), [data]);
  const selectedNodeKey =
    selectedNodeId == null ? null : String(selectedNodeId);

  const matches = useMemo(
    () => collectSearchMatches(fullGraph, searchQuery, 60),
    [fullGraph, searchQuery],
  );
  const matchKeys = useMemo(
    () => new Set(matches.map((node) => node.key)),
    [matches],
  );

  const visibleGraph = useMemo(() => {
    if (!neighborhoodOnly || !selectedNodeKey) return fullGraph;
    return extractNeighborhoodSubgraph(fullGraph, selectedNodeKey, radius);
  }, [fullGraph, neighborhoodOnly, radius, selectedNodeKey]);

  const { graph, isLoading, error } = useElkLayout(visibleGraph);

  if (error) {
    return (
      <div className="error-state">
        Failed to compute the call graph layout.
      </div>
    );
  }

  if (!graph) {
    return <div className="loading">Preparing call graph…</div>;
  }

  const extras = (
    <>
      <label className="graph-toolbar-field">
        <span>Search</span>
        <input
          className="graph-toolbar-input"
          type="search"
          value={searchQuery}
          onChange={(event) => setSearchQuery(event.target.value)}
          placeholder="Function name"
        />
      </label>
      <label className="graph-toolbar-field">
        <span>Match</span>
        <select
          className="graph-toolbar-select"
          value={selectedNodeKey ?? ''}
          onChange={(event) => {
            const next = event.target.value;
            if (!next) return;
            onSelectNode(Number(next));
          }}
        >
          <option value="">Select…</option>
          {matches.map((match) => (
            <option key={match.key} value={match.key}>
              {match.label}
            </option>
          ))}
        </select>
      </label>
      <label className="graph-toolbar-check">
        <input
          type="checkbox"
          checked={neighborhoodOnly}
          onChange={(event) => setNeighborhoodOnly(event.target.checked)}
        />
        <span>Neighbors only</span>
      </label>
      <label className="graph-toolbar-field graph-toolbar-field-compact">
        <span>Radius</span>
        <input
          className="graph-toolbar-range"
          type="range"
          min="1"
          max="4"
          step="1"
          value={radius}
          disabled={!neighborhoodOnly}
          onChange={(event) => setRadius(Number(event.target.value))}
        />
        <strong>{radius}</strong>
      </label>
    </>
  );

  return (
    <SigmaGraph
      graph={graph}
      viewKind="callgraph"
      selectedNodeKey={selectedNodeKey}
      onNodeClick={(key) => onSelectNode(Number(key))}
      searchMatchKeys={matchKeys}
      toolbarExtras={extras}
      loading={isLoading}
    />
  );
}
