import { useDebugSymex } from '../../api/queries/debug';
import { ApiError } from '../../api/client';
import { EmptyState } from '../../components/ui/EmptyState';
import { ErrorState } from '../../components/ui/ErrorState';
import { LoadingState } from '../../components/ui/LoadingState';

interface SymexAnalysisPanelProps {
  file: string;
  functionName: string;
}

export function SymexAnalysisPanel({
  file,
  functionName,
}: SymexAnalysisPanelProps) {
  const { data, isLoading, error } = useDebugSymex(file, functionName);

  if (isLoading) {
    return <LoadingState message="Loading symbolic execution..." />;
  }
  if (error) {
    if (error instanceof ApiError && error.status === 404) {
      return (
        <EmptyState message="Symbolic execution data is not available for the selected function." />
      );
    }
    return <ErrorState message="Failed to load symbolic execution." />;
  }
  if (!data) {
    return (
      <EmptyState message="No symbolic execution data is available for this function." />
    );
  }

  return (
    <div className="symex-viewer">
      {data.tainted_roots.length > 0 && (
        <div className="symex-section">
          <h3>Tainted Roots</h3>
          <div className="symex-roots">
            {data.tainted_roots.map((r) => (
              <span key={r} className="cap-badge cap-badge-source">
                v{r}
              </span>
            ))}
          </div>
        </div>
      )}

      {data.path_constraints.length > 0 && (
        <div className="symex-section">
          <h3>Path Constraints</h3>
          {data.path_constraints.map((pc, i) => (
            <div key={i} className="symex-constraint">
              <span className="text-secondary">B{pc.block}</span>
              <span
                className={`symex-polarity ${pc.polarity ? 'symex-true' : 'symex-false'}`}
              >
                {pc.polarity ? 'TRUE' : 'FALSE'}
              </span>
              <span className="mono">{pc.condition}</span>
            </div>
          ))}
        </div>
      )}

      <div className="symex-section">
        <h3>Symbolic Values ({data.values.length})</h3>
        <table className="symex-table">
          <thead>
            <tr>
              <th>Value</th>
              <th>Name</th>
              <th>Expression</th>
            </tr>
          </thead>
          <tbody>
            {data.values.map((v) => (
              <tr key={v.ssa_value}>
                <td className="mono">v{v.ssa_value}</td>
                <td className="mono">{v.var_name ?? '-'}</td>
                <td className="mono">{v.expression}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
