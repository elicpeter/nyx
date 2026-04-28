import { useMemo, useState } from 'react';
import { useDebugSummaries } from '../../api/queries/debug';
import { ApiError } from '../../api/client';
import { EmptyState } from '../../components/ui/EmptyState';
import { ErrorState } from '../../components/ui/ErrorState';
import { LoadingState } from '../../components/ui/LoadingState';
import type { FuncSummaryView } from '../../api/types';

interface SummaryAnalysisPanelProps {
  file?: string | null;
  functionName?: string | null;
  scope?: 'file' | 'global';
}

export function SummaryAnalysisPanel({
  file,
  functionName,
  scope = 'file',
}: SummaryAnalysisPanelProps) {
  const { data, isLoading, error } = useDebugSummaries(
    scope === 'global' ? null : (file ?? null),
    scope === 'global' ? null : (functionName ?? null),
  );
  const [expanded, setExpanded] = useState<string | null>(null);
  const [showClosures, setShowClosures] = useState(false);

  const closureCount = useMemo(
    () => data?.filter((s) => s.func_kind === 'closure').length ?? 0,
    [data],
  );

  const visible = useMemo(() => {
    if (!data) return data;
    return showClosures
      ? data
      : data.filter((s) => s.func_kind !== 'closure');
  }, [data, showClosures]);

  if (isLoading) {
    return <LoadingState message="Loading summaries..." />;
  }
  if (error) {
    if (error instanceof ApiError && error.status === 404) {
      return (
        <EmptyState message="Summaries are not available for the selected scope." />
      );
    }
    return (
      <ErrorState message="Failed to load summaries. Have you run a scan?" />
    );
  }
  if (!data || data.length === 0) {
    return (
      <EmptyState
        message={
          scope === 'global'
            ? 'No global summaries found. Run a scan first.'
            : 'No summaries found for this file.'
        }
      />
    );
  }

  const visibleCount = visible?.length ?? 0;
  const totalCount = data.length;

  return (
    <div className="summary-explorer">
      <div className="summary-header">
        <span className="text-secondary">
          {visibleCount}
          {visibleCount !== totalCount && ` of ${totalCount}`}{' '}
          {scope === 'global'
            ? 'functions across the project'
            : 'functions in this file'}
        </span>
        {closureCount > 0 && (
          <label className="summary-toggle">
            <input
              type="checkbox"
              checked={showClosures}
              onChange={(e) => setShowClosures(e.target.checked)}
            />
            <span>
              Show {closureCount} anonymous closure
              {closureCount === 1 ? '' : 's'}
            </span>
          </label>
        )}
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
          {visible?.map((s) => {
            const rowKey = `${s.namespace}::${s.container}::${s.name}`;
            return (
              <SummaryRow
                key={rowKey}
                summary={s}
                isExpanded={expanded === rowKey}
                onToggle={() =>
                  setExpanded(expanded === rowKey ? null : rowKey)
                }
              />
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function SummaryExplorerPage() {
  return <SummaryAnalysisPanel scope="global" />;
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
  const isClosure = summary.func_kind === 'closure';
  return (
    <>
      <tr onClick={onToggle} style={{ cursor: 'pointer' }}>
        <td className="mono">
          {summary.name}
          {isClosure && (
            <span
              className="text-secondary"
              style={{ marginLeft: 8, fontSize: '0.85em' }}
            >
              {summary.container
                ? `[closure in ${summary.container}]`
                : '[closure]'}
            </span>
          )}
        </td>
        <td>{summary.lang}</td>
        <td>{summary.param_count}</td>
        <td>
          {summary.source_caps.map((c, i) => (
            <span key={i} className="cap-badge cap-badge-source">
              {c}
            </span>
          ))}
        </td>
        <td>
          {summary.sanitizer_caps.map((c, i) => (
            <span key={i} className="cap-badge cap-badge-sanitizer">
              {c}
            </span>
          ))}
        </td>
        <td>
          {summary.sink_caps.map((c, i) => (
            <span key={i} className="cap-badge cap-badge-sink">
              {c}
            </span>
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
                <span className="debug-detail-value mono">
                  {summary.file_path}
                </span>
              </div>
              {summary.propagating_params.length > 0 && (
                <div className="debug-detail-row">
                  <span className="debug-detail-label">Propagating params</span>
                  <span className="debug-detail-value">
                    {summary.propagating_params.join(', ')}
                  </span>
                </div>
              )}
              {summary.tainted_sink_params.length > 0 && (
                <div className="debug-detail-row">
                  <span className="debug-detail-label">Sink params</span>
                  <span className="debug-detail-value">
                    {summary.tainted_sink_params.join(', ')}
                  </span>
                </div>
              )}
              {summary.callees.length > 0 && (
                <div className="debug-detail-row">
                  <span className="debug-detail-label">Callees</span>
                  <span className="debug-detail-value mono">
                    {summary.callees.join(', ')}
                  </span>
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
                          <span key={i} className="cap-badge cap-badge-source">
                            {c}
                          </span>
                        ))}
                      </span>
                    </div>
                  )}
                  {summary.ssa_summary.param_to_return.length > 0 && (
                    <div className="debug-detail-row">
                      <span className="debug-detail-label">
                        Param-to-return
                      </span>
                      <span>
                        {summary.ssa_summary.param_to_return.map((p, i) => (
                          <span key={i} className="mono">
                            p{p.param_index} → {p.transform}
                            {i < summary.ssa_summary!.param_to_return.length - 1
                              ? ', '
                              : ''}
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
                            p{p.param_index} →{' '}
                            {p.sink_caps.map((c, j) => (
                              <span
                                key={j}
                                className="cap-badge cap-badge-sink"
                              >
                                {c}
                              </span>
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
