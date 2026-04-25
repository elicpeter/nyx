import type { ReactNode } from 'react';

interface AnalysisWorkspaceProps {
  canvas: ReactNode;
  inspector?: ReactNode;
  inspectorTitle?: string;
  inspectorSide?: 'left' | 'right';
}

export function AnalysisWorkspace({
  canvas,
  inspector,
  inspectorTitle,
  inspectorSide = 'right',
}: AnalysisWorkspaceProps) {
  const hasInspector = Boolean(inspector);
  const inspectorPanel = hasInspector ? (
    <aside className="analysis-inspector">
      {inspectorTitle && <h3>{inspectorTitle}</h3>}
      {inspector}
    </aside>
  ) : null;

  return (
    <div
      className={`analysis-workspace${hasInspector ? ' analysis-workspace-with-inspector' : ''}${
        hasInspector ? ` analysis-workspace-inspector-${inspectorSide}` : ''
      }`}
    >
      {inspectorSide === 'left' && inspectorPanel}
      <div className="analysis-canvas">{canvas}</div>
      {inspectorSide === 'right' && inspectorPanel}
    </div>
  );
}
