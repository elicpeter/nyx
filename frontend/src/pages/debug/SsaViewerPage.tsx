import { useDebugSsa } from '../../api/queries/debug';
import { ApiError } from '../../api/client';
import { EmptyState } from '../../components/ui/EmptyState';
import { ErrorState } from '../../components/ui/ErrorState';
import { LoadingState } from '../../components/ui/LoadingState';
import type { SsaBlockView, SsaInstView } from '../../api/types';

interface SsaAnalysisPanelProps {
  file: string;
  functionName: string;
}

export function SsaAnalysisPanel({
  file,
  functionName,
}: SsaAnalysisPanelProps) {
  const { data, isLoading, error } = useDebugSsa(file, functionName);

  if (isLoading) {
    return <LoadingState message="Loading SSA..." />;
  }
  if (error) {
    if (error instanceof ApiError && error.status === 404) {
      return (
        <EmptyState message="SSA data is not available for the selected function." />
      );
    }
    return <ErrorState message="Failed to load SSA." />;
  }
  if (!data) {
    return <EmptyState message="No SSA data is available for this function." />;
  }

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
