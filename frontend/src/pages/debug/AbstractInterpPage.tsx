import { useOutletContext } from 'react-router-dom';
import { useDebugAbstractInterp } from '../../api/queries/debug';
import type { AbstractBlockView, AbstractValueView } from '../../api/types';

export function AbstractInterpPage() {
  const { file, fn_name } = useOutletContext<{ file: string | null; fn_name: string | null }>();
  const { data, isLoading, error } = useDebugAbstractInterp(file, fn_name);

  if (!file || !fn_name) {
    return <div className="empty-state">Select a file and function to view abstract interpretation state.</div>;
  }
  if (isLoading) return <div className="loading">Loading abstract interpretation...</div>;
  if (error) return <div className="error-state">Failed to load abstract interpretation.</div>;
  if (!data || data.blocks.length === 0) {
    return <div className="empty-state">No abstract domain facts tracked for this function.</div>;
  }

  return (
    <div className="abstract-interp-viewer">
      {data.blocks.map((block) => (
        <AbstractBlock key={block.block_id} block={block} />
      ))}
    </div>
  );
}

function AbstractBlock({ block }: { block: AbstractBlockView }) {
  return (
    <div className="abstract-block">
      <div className="abstract-block-header">
        <span className="ssa-block-id">B{block.block_id}</span>
        <span className="text-secondary">{block.values.length} tracked values</span>
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
