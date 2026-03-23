import { useState, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useScans } from '../api/queries/scans';
import { useSSE } from '../contexts/SSEContext';
import { LoadingState } from '../components/ui/LoadingState';
import { ErrorState } from '../components/ui/ErrorState';
import type { ScanView } from '../api/types';

function relTime(iso?: string): string {
  if (!iso) return '-';
  const d = new Date(iso);
  const diff = Date.now() - d.getTime();
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return d.toLocaleDateString();
}

function truncPath(p?: string, max = 50): string {
  if (!p) return '';
  if (p.length <= max) return p;
  return '...' + p.slice(p.length - max + 3);
}

function ScanProgress({ data }: { data: NonNullable<ReturnType<typeof useSSE>['scanProgress']> }) {
  const stages = ['discovering', 'parsing', 'analyzing', 'complete'] as const;
  const stageLabels: Record<string, string> = {
    discovering: 'Discovering',
    parsing: 'Parsing',
    analyzing: 'Analyzing',
    complete: 'Complete',
  };
  const currentIdx = stages.indexOf(data.stage as typeof stages[number]);

  const total = data.files_discovered || 1;
  const processed =
    data.stage === 'parsing'
      ? data.files_parsed
      : data.stage === 'analyzing'
        ? data.files_analyzed
        : data.stage === 'complete'
          ? total
          : 0;
  const pct = Math.min(100, (processed / total) * 100);
  const elapsed = data.elapsed_ms ? (data.elapsed_ms / 1000).toFixed(1) + 's' : '-';

  return (
    <div className="scan-progress">
      <div className="scan-progress-header">
        <h3>Scan in Progress</h3>
        <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          {elapsed} elapsed
        </span>
      </div>
      <div className="stage-pipeline">
        {stages.map((s, i) => {
          const cls = i < currentIdx ? 'done' : i === currentIdx ? 'active' : '';
          return (
            <div key={s} className={`stage-step ${cls}`}>
              <div className="stage-dot"></div>
              <span className="stage-label">{stageLabels[s]}</span>
            </div>
          );
        })}
      </div>
      <div className="progress-bar">
        <div className="progress-bar-fill" style={{ width: `${pct}%` }}></div>
      </div>
      <div className="progress-stats">
        <span>
          {processed} / {data.files_discovered || 0} files
        </span>
        <span>{pct.toFixed(0)}%</span>
      </div>
      {data.current_file && (
        <div className="progress-current-file">{truncPath(data.current_file, 80)}</div>
      )}
    </div>
  );
}

export function ScansPage() {
  const navigate = useNavigate();
  const { data: scans, isLoading, error } = useScans();
  const { scanProgress, isScanRunning } = useSSE();
  const [selectedScans, setSelectedScans] = useState<Set<string>>(new Set());

  const completedScans = useMemo(
    () => (scans || []).filter((s) => s.status === 'completed'),
    [scans],
  );

  const runningScans = useMemo(
    () => (scans || []).filter((s) => s.status === 'running'),
    [scans],
  );

  const handleCheckbox = useCallback(
    (e: React.MouseEvent, scanId: string) => {
      e.stopPropagation();
      setSelectedScans((prev) => {
        const next = new Set(prev);
        if (next.has(scanId)) {
          next.delete(scanId);
        } else {
          if (next.size >= 2) return prev;
          next.add(scanId);
        }
        return next;
      });
    },
    [],
  );

  const handleCompare = useCallback(() => {
    if (selectedScans.size !== 2) return;
    const ids = [...selectedScans];
    // Sort by started_at so left=older, right=newer
    const scanMap = new Map((scans || []).map((s) => [s.id, s]));
    ids.sort((a, b) =>
      (scanMap.get(a)?.started_at || '').localeCompare(scanMap.get(b)?.started_at || ''),
    );
    navigate(`/scans/compare/${ids[0]}/${ids[1]}`);
  }, [selectedScans, scans, navigate]);

  if (isLoading) return <LoadingState message="Loading scans..." />;
  if (error) return <ErrorState message={error.message} />;

  const showCheckboxes = completedScans.length >= 2;

  return (
    <>
      <div className="page-header">
        <h2>Scans</h2>
      </div>

      {(runningScans.length > 0 || isScanRunning) && scanProgress && (
        <ScanProgress data={scanProgress} />
      )}

      {selectedScans.size > 0 && (
        <div className="compare-select-bar" style={{ display: 'flex' }}>
          <span>
            {selectedScans.size === 2
              ? '2 scans selected'
              : `Select ${2 - selectedScans.size} more completed scan${selectedScans.size === 0 ? 's' : ''}`}
          </span>
          <button
            className="btn btn-sm"
            disabled={selectedScans.size !== 2}
            onClick={handleCompare}
          >
            Compare Selected
          </button>
        </div>
      )}

      {!scans || scans.length === 0 ? (
        <div className="empty-state">
          <h3>No scans yet</h3>
          <p>Use the &quot;Start Scan&quot; button in the header to start your first scan.</p>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                {showCheckboxes && <th style={{ width: 32 }}></th>}
                <th>Status</th>
                <th>Root</th>
                <th>Duration</th>
                <th>Findings</th>
                <th>Languages</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s: ScanView) => (
                <tr
                  key={s.id}
                  className="clickable"
                  onClick={() => navigate(`/scans/${s.id}`)}
                >
                  {showCheckboxes && (
                    <td>
                      {s.status === 'completed' && (
                        <input
                          type="checkbox"
                          className="scan-compare-cb"
                          checked={selectedScans.has(s.id)}
                          onClick={(e) => handleCheckbox(e, s.id)}
                          onChange={() => {}}
                        />
                      )}
                    </td>
                  )}
                  <td>
                    <span className={`status-badge ${s.status}`}>
                      <span className={`status-dot ${s.status}`}></span>
                      {s.status}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}>
                    {truncPath(s.scan_root)}
                  </td>
                  <td>
                    {s.duration_secs != null ? s.duration_secs.toFixed(2) + 's' : '-'}
                  </td>
                  <td>{s.finding_count ?? '-'}</td>
                  <td>
                    {(s.languages || []).length > 0
                      ? (s.languages || []).map((l) => (
                          <span key={l} className="lang-badge">
                            {l}
                          </span>
                        ))
                      : '-'}
                  </td>
                  <td>{relTime(s.started_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
