import { useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { useDebugSummaries } from '../../api/queries/debug';
import type { FuncSummaryView } from '../../api/types';

export function SummaryExplorerPage() {
  const { file, fn_name } = useOutletContext<{ file: string | null; fn_name: string | null }>();
  const { data, isLoading, error } = useDebugSummaries(file, fn_name);
  const [expanded, setExpanded] = useState<string | null>(null);

  if (isLoading) return <div className="loading">Loading summaries...</div>;
  if (error) return <div className="error-state">Failed to load summaries. Have you run a scan?</div>;
  if (!data || data.length === 0) {
    return <div className="empty-state">No summaries found. Run a scan first.</div>;
  }

  return (
    <div className="summary-explorer">
      <div className="summary-header">
        <span className="text-secondary">{data.length} functions</span>
      </div>
      <table className="summary-table">
        <thead>
          <tr>
            <th>Function</th>
            <th>Lang</th>
            <th>Params</th>
            <th>Sources</th>
            <th>Sanitizers</th>
            <th>Sinks</th>
            <th>Propagates</th>
          </tr>
        </thead>
        <tbody>
          {data.map((s) => (
            <SummaryRow
              key={`${s.namespace}::${s.name}`}
              summary={s}
              isExpanded={expanded === `${s.namespace}::${s.name}`}
              onToggle={() =>
                setExpanded(
                  expanded === `${s.namespace}::${s.name}`
                    ? null
                    : `${s.namespace}::${s.name}`,
                )
              }
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SummaryRow({
  summary,
  isExpanded,
  onToggle,
}: {
  summary: FuncSummaryView;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  return (
    <>
      <tr onClick={onToggle} style={{ cursor: 'pointer' }}>
        <td className="mono">{summary.name}</td>
        <td>{summary.lang}</td>
        <td>{summary.param_count}</td>
        <td>
          {summary.source_caps.map((c, i) => (
            <span key={i} className="cap-badge cap-badge-source">{c}</span>
          ))}
        </td>
        <td>
          {summary.sanitizer_caps.map((c, i) => (
            <span key={i} className="cap-badge cap-badge-sanitizer">{c}</span>
          ))}
        </td>
        <td>
          {summary.sink_caps.map((c, i) => (
            <span key={i} className="cap-badge cap-badge-sink">{c}</span>
          ))}
        </td>
        <td>{summary.propagates_taint ? 'Yes' : 'No'}</td>
      </tr>
      {isExpanded && (
        <tr>
          <td colSpan={7}>
            <div className="summary-detail">
              <div className="debug-detail-row">
                <span className="debug-detail-label">File</span>
                <span className="debug-detail-value mono">{summary.file_path}</span>
              </div>
              {summary.propagating_params.length > 0 && (
                <div className="debug-detail-row">
                  <span className="debug-detail-label">Propagating params</span>
                  <span className="debug-detail-value">{summary.propagating_params.join(', ')}</span>
                </div>
              )}
              {summary.tainted_sink_params.length > 0 && (
                <div className="debug-detail-row">
                  <span className="debug-detail-label">Sink params</span>
                  <span className="debug-detail-value">{summary.tainted_sink_params.join(', ')}</span>
                </div>
              )}
              {summary.callees.length > 0 && (
                <div className="debug-detail-row">
                  <span className="debug-detail-label">Callees</span>
                  <span className="debug-detail-value mono">{summary.callees.join(', ')}</span>
                </div>
              )}
              {summary.ssa_summary && (
                <div className="summary-ssa-detail">
                  <h4>SSA Summary</h4>
                  {summary.ssa_summary.source_caps.length > 0 && (
                    <div className="debug-detail-row">
                      <span className="debug-detail-label">Source caps</span>
                      <span>
                        {summary.ssa_summary.source_caps.map((c, i) => (
                          <span key={i} className="cap-badge cap-badge-source">{c}</span>
                        ))}
                      </span>
                    </div>
                  )}
                  {summary.ssa_summary.param_to_return.length > 0 && (
                    <div className="debug-detail-row">
                      <span className="debug-detail-label">Param-to-return</span>
                      <span>
                        {summary.ssa_summary.param_to_return.map((p, i) => (
                          <span key={i} className="mono">
                            p{p.param_index} → {p.transform}{i < summary.ssa_summary!.param_to_return.length - 1 ? ', ' : ''}
                          </span>
                        ))}
                      </span>
                    </div>
                  )}
                  {summary.ssa_summary.param_to_sink.length > 0 && (
                    <div className="debug-detail-row">
                      <span className="debug-detail-label">Param-to-sink</span>
                      <span>
                        {summary.ssa_summary.param_to_sink.map((p, i) => (
                          <span key={i}>
                            p{p.param_index} → {p.sink_caps.map((c, j) => (
                              <span key={j} className="cap-badge cap-badge-sink">{c}</span>
                            ))}
                          </span>
                        ))}
                      </span>
                    </div>
                  )}
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
