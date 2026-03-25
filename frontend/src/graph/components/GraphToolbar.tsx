import type { ReactNode } from 'react';

interface GraphToolbarProps {
  zoomPercentage: number;
  onZoomIn: () => void;
  onZoomOut: () => void;
  onFitGraph: () => void;
  onFocusSelection?: () => void;
  focusDisabled?: boolean;
  extras?: ReactNode;
  status?: ReactNode;
}

export function GraphToolbar({
  zoomPercentage,
  onZoomIn,
  onZoomOut,
  onFitGraph,
  onFocusSelection,
  focusDisabled,
  extras,
  status,
}: GraphToolbarProps) {
  return (
    <div className="graph-toolbar">
      <div className="graph-toolbar-group">
        <button
          className="graph-toolbar-btn"
          onClick={onZoomOut}
          title="Zoom out"
          type="button"
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 14 14"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
          >
            <line x1="3" y1="7" x2="11" y2="7" />
          </svg>
        </button>
        <span className="graph-toolbar-zoom">{zoomPercentage}%</span>
        <button
          className="graph-toolbar-btn"
          onClick={onZoomIn}
          title="Zoom in"
          type="button"
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 14 14"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
          >
            <line x1="3" y1="7" x2="11" y2="7" />
            <line x1="7" y1="3" x2="7" y2="11" />
          </svg>
        </button>
        <div className="graph-toolbar-sep" />
        <button
          className="graph-toolbar-btn"
          onClick={onFitGraph}
          title="Fit graph"
          type="button"
        >
          Fit
        </button>
        {onFocusSelection && (
          <button
            className="graph-toolbar-btn"
            onClick={onFocusSelection}
            disabled={focusDisabled}
            title="Focus selection"
            type="button"
          >
            Focus
          </button>
        )}
      </div>
      {extras ? <div className="graph-toolbar-extras">{extras}</div> : null}
      {status ? <div className="graph-toolbar-status">{status}</div> : null}
    </div>
  );
}
