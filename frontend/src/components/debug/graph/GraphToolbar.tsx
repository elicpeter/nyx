interface Props {
  onZoomIn: () => void;
  onZoomOut: () => void;
  onFitToView: () => void;
  onResetView: () => void;
  compact: boolean;
  onToggleCompact: () => void;
  showCompactToggle: boolean;
  scale: number;
}

export function GraphToolbar({
  onZoomIn,
  onZoomOut,
  onFitToView,
  onResetView,
  compact,
  onToggleCompact,
  showCompactToggle,
  scale,
}: Props) {
  return (
    <div className="graph-toolbar">
      <button className="graph-toolbar-btn" onClick={onZoomOut} title="Zoom out">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
          <line x1="3" y1="7" x2="11" y2="7" />
        </svg>
      </button>
      <span className="graph-toolbar-zoom">{Math.round(scale * 100)}%</span>
      <button className="graph-toolbar-btn" onClick={onZoomIn} title="Zoom in">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
          <line x1="3" y1="7" x2="11" y2="7" />
          <line x1="7" y1="3" x2="7" y2="11" />
        </svg>
      </button>
      <div className="graph-toolbar-sep" />
      <button className="graph-toolbar-btn" onClick={onFitToView} title="Fit to view">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
          <rect x="2" y="2" width="10" height="10" rx="1" />
          <line x1="5" y1="5" x2="9" y2="9" />
          <polyline points="6,9 9,9 9,6" />
        </svg>
      </button>
      <button className="graph-toolbar-btn" onClick={onResetView} title="Reset view">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M3 7a4 4 0 1 1 1.2 2.8" />
          <polyline points="1,7 3,7 3,5" />
        </svg>
      </button>
      {showCompactToggle && (
        <>
          <div className="graph-toolbar-sep" />
          <button
            className={`graph-toolbar-btn${compact ? ' graph-toolbar-btn-active' : ''}`}
            onClick={onToggleCompact}
            title={compact ? 'Show all blocks' : 'Compact view'}
          >
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
              <rect x="3" y="2" width="8" height="3" rx="1" />
              <rect x="3" y="9" width="8" height="3" rx="1" />
              <line x1="7" y1="5" x2="7" y2="9" strokeDasharray="2 1" />
            </svg>
            <span style={{ marginLeft: 4, fontSize: 11 }}>{compact ? 'Full' : 'Compact'}</span>
          </button>
        </>
      )}
    </div>
  );
}
