import { useDebugAbstractInterp } from '../../api/queries/debug';
import { ApiError } from '../../api/client';
import { EmptyState } from '../../components/ui/EmptyState';
import { ErrorState } from '../../components/ui/ErrorState';
import { LoadingState } from '../../components/ui/LoadingState';
import type {
  AbstractBlockView,
  AbstractValueView,
  TypeFactView,
  ConstValueViewEntry,
} from '../../api/types';

interface AbstractInterpAnalysisPanelProps {
  file: string;
  functionName: string;
}

export function AbstractInterpAnalysisPanel({
  file,
  functionName,
}: AbstractInterpAnalysisPanelProps) {
  const { data, isLoading, error } = useDebugAbstractInterp(file, functionName);

  if (isLoading) {
    return <LoadingState message="Loading abstract interpretation..." />;
  }
  if (error) {
    if (error instanceof ApiError && error.status === 404) {
      return (
        <EmptyState message="Abstract interpretation data is not available for the selected function." />
      );
    }
    return <ErrorState message="Failed to load abstract interpretation." />;
  }
  if (
    !data ||
    (data.blocks.length === 0 &&
      data.type_facts.length === 0 &&
      data.const_values.length === 0)
  ) {
    return (
      <EmptyState message="No abstract domain facts are tracked for this function." />
    );
  }

  return (
    <div className="abstract-interp-viewer">
      {data.blocks.length > 0 && (
        <>
          <h3>Abstract Domain Facts</h3>
          {data.blocks.map((block) => (
            <AbstractBlock key={block.block_id} block={block} />
          ))}
        </>
      )}

      {data.type_facts.length > 0 && (
        <div className="abstract-block">
          <div className="abstract-block-header">
            <h3 style={{ margin: 0 }}>Type Facts</h3>
            <span className="text-secondary">
              {data.type_facts.length} typed values
            </span>
          </div>
          <table className="abstract-table">
            <thead>
              <tr>
                <th>Value</th>
                <th>Name</th>
                <th>Type</th>
                <th>Nullable</th>
              </tr>
            </thead>
            <tbody>
              {data.type_facts.map((tf) => (
                <tr key={tf.ssa_value}>
                  <td className="mono">v{tf.ssa_value}</td>
                  <td className="mono">{tf.var_name ?? '-'}</td>
                  <td className="mono">{tf.type_kind}</td>
                  <td>{tf.nullable ? 'Yes' : 'No'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data.const_values.length > 0 && (
        <div className="abstract-block">
          <div className="abstract-block-header">
            <h3 style={{ margin: 0 }}>Constant Values</h3>
            <span className="text-secondary">
              {data.const_values.length} constants
            </span>
          </div>
          <table className="abstract-table">
            <thead>
              <tr>
                <th>Value</th>
                <th>Name</th>
                <th>Constant</th>
              </tr>
            </thead>
            <tbody>
              {data.const_values.map((cv) => (
                <tr key={cv.ssa_value}>
                  <td className="mono">v{cv.ssa_value}</td>
                  <td className="mono">{cv.var_name ?? '-'}</td>
                  <td className="mono">{cv.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function AbstractBlock({ block }: { block: AbstractBlockView }) {
  return (
    <div className="abstract-block">
      <div className="abstract-block-header">
        <span className="ssa-block-id">B{block.block_id}</span>
        <span className="text-secondary">
          {block.values.length} tracked values
        </span>
      </div>
      <table className="abstract-table">
        <thead>
          <tr>
            <th>Value</th>
            <th>Name</th>
            <th>Interval</th>
            <th>String Prefix</th>
            <th>String Suffix</th>
            <th>Bit Masks</th>
          </tr>
        </thead>
        <tbody>
          {block.values.map((v) => (
            <AbstractValueRow key={v.ssa_value} value={v} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AbstractValueRow({ value }: { value: AbstractValueView }) {
  const lo = value.interval_lo != null ? `${value.interval_lo}` : '-inf';
  const hi = value.interval_hi != null ? `${value.interval_hi}` : '+inf';
  const interval = `[${lo}, ${hi}]`;
  const hasBits = value.known_zero !== 0 || value.known_one !== 0;

  return (
    <tr>
      <td className="mono">v{value.ssa_value}</td>
      <td className="mono">{value.var_name ?? '-'}</td>
      <td className="mono">{interval}</td>
      <td className="mono">{value.string_prefix ?? '-'}</td>
      <td className="mono">{value.string_suffix ?? '-'}</td>
      <td className="mono">
        {hasBits
          ? `zero=0x${value.known_zero.toString(16)} one=0x${value.known_one.toString(16)}`
          : '-'}
      </td>
    </tr>
  );
}
