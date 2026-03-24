import { useOutletContext } from 'react-router-dom';
import { useDebugTaint } from '../../api/queries/debug';
import type { TaintBlockStateView, TaintEventView, TaintValueView } from '../../api/types';

export function TaintViewerPage() {
  const { file, fn_name } = useOutletContext<{ file: string | null; fn_name: string | null }>();
  const { data, isLoading, error } = useDebugTaint(file, fn_name);

  if (!file || !fn_name) {
    return <div className="empty-state">Select a file and function to view taint analysis.</div>;
  }
  if (isLoading) return <div className="loading">Loading taint analysis...</div>;
  if (error) return <div className="error-state">Failed to load taint analysis.</div>;
  if (!data) return null;

  return (
    <div className="taint-viewer">
      {data.events.length > 0 && (
        <div className="taint-events-section">
          <h3>Sink Events ({data.events.length})</h3>
          {data.events.map((e, i) => (
            <TaintEvent key={i} event={e} />
          ))}
        </div>
      )}
      <div className="taint-blocks-section">
        <h3>Per-Block Taint State</h3>
        {data.block_states.map((bs) => (
          <TaintBlockState key={bs.block_id} state={bs} />
        ))}
      </div>
    </div>
  );
}

function TaintEvent({ event }: { event: TaintEventView }) {
  return (
    <div className={`taint-event${event.all_validated ? ' taint-event-validated' : ''}`}>
      <div className="taint-event-header">
        <span>Sink node #{event.sink_node}</span>
        {event.all_validated && <span className="badge-success">validated</span>}
        {event.uses_summary && <span className="badge-info">via summary</span>}
      </div>
      <div className="taint-event-caps">
        Sink caps: {event.sink_caps.map((c, i) => (
          <span key={i} className="cap-badge cap-badge-sink">{c}</span>
        ))}
      </div>
      <div className="taint-event-values">
        {event.tainted_values.map((v, i) => (
          <TaintValue key={i} value={v} />
        ))}
      </div>
    </div>
  );
}

function TaintBlockState({ state }: { state: TaintBlockStateView }) {
  if (state.values.length === 0) return null;

  return (
    <div className="taint-block-state">
      <div className="taint-block-state-header">
        <span className="ssa-block-id">B{state.block_id}</span>
        <span className="text-secondary">{state.values.length} tainted values</span>
      </div>
      <div className="taint-block-state-values">
        {state.values.map((v, i) => (
          <TaintValue key={i} value={v} />
        ))}
      </div>
    </div>
  );
}

function TaintValue({ value }: { value: TaintValueView }) {
  return (
    <div className="taint-value">
      <span className="taint-value-id">v{value.ssa_value}</span>
      {value.var_name && <span className="taint-value-name">{value.var_name}</span>}
      <span className="taint-value-caps">
        {value.caps.map((c, i) => (
          <span key={i} className="cap-badge cap-badge-source">{c}</span>
        ))}
      </span>
      {value.uses_summary && <span className="badge-info">summary</span>}
    </div>
  );
}
