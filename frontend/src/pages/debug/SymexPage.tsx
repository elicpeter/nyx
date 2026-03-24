import { useOutletContext } from 'react-router-dom';
import { useDebugSymex } from '../../api/queries/debug';

export function SymexPage() {
  const { file, fn_name } = useOutletContext<{ file: string | null; fn_name: string | null }>();
  const { data, isLoading, error } = useDebugSymex(file, fn_name);

  if (!file || !fn_name) {
    return <div className="empty-state">Select a file and function to view symbolic execution state.</div>;
  }
  if (isLoading) return <div className="loading">Loading symbolic execution...</div>;
  if (error) return <div className="error-state">Failed to load symbolic execution.</div>;
  if (!data) return null;

  return (
    <div className="symex-viewer">
      {data.tainted_roots.length > 0 && (
        <div className="symex-section">
          <h3>Tainted Roots</h3>
          <div className="symex-roots">
            {data.tainted_roots.map((r) => (
              <span key={r} className="cap-badge cap-badge-source">v{r}</span>
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
              <span className={`symex-polarity ${pc.polarity ? 'symex-true' : 'symex-false'}`}>
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
