import { useDebugTaint } from '../../api/queries/debug';
import { ApiError } from '../../api/client';
import { EmptyState } from '../../components/ui/EmptyState';
import { ErrorState } from '../../components/ui/ErrorState';
import { LoadingState } from '../../components/ui/LoadingState';
import type {
  TaintBlockStateView,
  TaintEventView,
  TaintValueView,
} from '../../api/types';

interface TaintAnalysisPanelProps {
  file: string;
  functionName: string;
}

export function TaintAnalysisPanel({
  file,
  functionName,
}: TaintAnalysisPanelProps) {
  const { data, isLoading, error } = useDebugTaint(file, functionName);

  if (isLoading) {
    return <LoadingState message="Loading taint analysis..." />;
  }
  if (error) {
    if (error instanceof ApiError && error.status === 404) {
      return (
        <EmptyState message="Taint analysis is not available for the selected function." />
      );
    }
    return <ErrorState message="Failed to load taint analysis." />;
  }
  if (!data) {
    return (
      <EmptyState message="No taint analysis data is available for this function." />
    );
  }

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
    <div
      className={`taint-event${event.all_validated ? ' taint-event-validated' : ''}`}
    >
      <div className="taint-event-header">
        <span>Sink node #{event.sink_node}</span>
        {event.all_validated && (
          <span className="badge-success">validated</span>
        )}
        {event.uses_summary && <span className="badge-info">via summary</span>}
      </div>
      <div className="taint-event-caps">
        Sink caps:{' '}
        {event.sink_caps.map((c, i) => (
          <span key={i} className="cap-badge cap-badge-sink">
            {c}
          </span>
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
        <span className="text-secondary">
          {state.values.length} tainted values
        </span>
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
      {value.var_name && (
        <span className="taint-value-name">{value.var_name}</span>
      )}
      <span className="taint-value-caps">
        {value.caps.map((c, i) => (
          <span key={i} className="cap-badge cap-badge-source">
            {c}
          </span>
        ))}
      </span>
      {value.uses_summary && <span className="badge-info">summary</span>}
    </div>
  );
}
