import { useOutletContext } from 'react-router-dom';
import { useDebugSsa } from '../../api/queries/debug';
import type { SsaBlockView, SsaInstView } from '../../api/types';

export function SsaViewerPage() {
  const { file, fn_name } = useOutletContext<{
    file: string | null;
    fn_name: string | null;
  }>();
  const { data, isLoading, error } = useDebugSsa(file, fn_name);

  if (!file || !fn_name) {
    return (
      <div className="empty-state">
        Select a file and function to view SSA IR.
      </div>
    );
  }
  if (isLoading) return <div className="loading">Loading SSA...</div>;
  if (error) return <div className="error-state">Failed to load SSA.</div>;
  if (!data) return null;

  // Render entry block first, then the rest in order
  const entryBlock = data.blocks.find((b) => b.id === data.entry);
  const otherBlocks = data.blocks.filter((b) => b.id !== data.entry);
  const ordered = entryBlock ? [entryBlock, ...otherBlocks] : data.blocks;

  return (
    <div className="ssa-viewer">
      <div className="ssa-header">
        <span className="text-secondary">
          {data.num_values} SSA values, {data.blocks.length} blocks
        </span>
      </div>
      {ordered.map((block) => (
        <SsaBlock
          key={block.id}
          block={block}
          isEntry={block.id === data.entry}
        />
      ))}
    </div>
  );
}

function SsaBlock({
  block,
  isEntry,
}: {
  block: SsaBlockView;
  isEntry: boolean;
}) {
  return (
    <div className={`ssa-block${isEntry ? ' ssa-block-entry' : ''}`}>
      <div className="ssa-block-header">
        <span className="ssa-block-id">B{block.id}</span>
        {isEntry && <span className="badge-info">entry</span>}
        {block.preds.length > 0 && (
          <span className="text-secondary ssa-block-preds">
            preds: {block.preds.map((p) => `B${p}`).join(', ')}
          </span>
        )}
        {block.succs.length > 0 && (
          <span className="text-secondary ssa-block-succs">
            succs: {block.succs.map((s) => `B${s}`).join(', ')}
          </span>
        )}
      </div>
      {block.phis.length > 0 && (
        <div className="ssa-phi-section">
          {block.phis.map((inst) => (
            <SsaInstLine key={inst.value} inst={inst} isPhi />
          ))}
        </div>
      )}
      <div className="ssa-body-section">
        {block.body.map((inst) => (
          <SsaInstLine key={inst.value} inst={inst} />
        ))}
      </div>
      <div className="ssa-terminator">{block.terminator}</div>
    </div>
  );
}

function SsaInstLine({ inst, isPhi }: { inst: SsaInstView; isPhi?: boolean }) {
  const operands =
    inst.operands.length > 0 ? `(${inst.operands.join(', ')})` : '';
  return (
    <div className={`ssa-inst${isPhi ? ' ssa-inst-phi' : ''}`}>
      <span className="ssa-value">v{inst.value}</span>
      <span className="ssa-eq"> = </span>
      <span className="ssa-op">{inst.op}</span>
      <span className="ssa-operands">{operands}</span>
      {inst.var_name && (
        <span className="ssa-var-name"> # {inst.var_name}</span>
      )}
      <span className="ssa-line-ref"> L{inst.line}</span>
    </div>
  );
}
