import { useState, useMemo, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useFindings } from '../api/queries/findings';
import {
  useTriageAudit,
  useSuppressions,
  useSyncStatus,
} from '../api/queries/triage';
import {
  useBulkTriage,
  useDeleteSuppression,
  useTriageExport,
  useTriageImport,
} from '../api/mutations/triage';
import { LoadingState } from '../components/ui/LoadingState';
import { ErrorState } from '../components/ui/ErrorState';
import type { FindingView, AuditEntry, SuppressionRule } from '../api/types';

function truncPath(p?: string, max = 35): string {
  if (!p) return '';
  if (p.length <= max) return p;
  return '...' + p.slice(p.length - max + 3);
}

const ALL_STATES = [
  'open',
  'investigating',
  'false_positive',
  'accepted_risk',
  'suppressed',
  'fixed',
] as const;

function stateLabel(s: string): string {
  return s.replace(/_/g, ' ');
}

// ── Triage Actions ───────────────────────────────────────────────────────────

interface TriageAction {
  state: string;
  label: string;
}

function triageActionsFor(f: FindingView): TriageAction[] {
  const ts = f.triage_state || 'open';
  if (ts === 'open') {
    return [
      { state: 'investigating', label: 'Investigate' },
      { state: 'false_positive', label: 'FP' },
      { state: 'suppressed', label: 'Suppress' },
      { state: 'accepted_risk', label: 'Accept' },
    ];
  }
  if (ts === 'investigating') {
    return [
      { state: 'false_positive', label: 'FP' },
      { state: 'suppressed', label: 'Suppress' },
      { state: 'accepted_risk', label: 'Accept' },
      { state: 'fixed', label: 'Fixed' },
      { state: 'open', label: 'Reopen' },
    ];
  }
  return [
    { state: 'open', label: 'Reopen' },
    { state: 'investigating', label: 'Investigate' },
  ];
}

// ── Summary Cards ────────────────────────────────────────────────────────────

function SummaryCards({
  totalCount,
  needsAttention,
  stateCounts,
  activeFilter,
  onFilter,
}: {
  totalCount: number;
  needsAttention: number;
  stateCounts: Record<string, number>;
  activeFilter: string;
  onFilter: (filter: string) => void;
}) {
  return (
    <div className="triage-summary-row">
      <div
        className={`triage-summary-card triage-card-clickable ${activeFilter === 'all' ? 'triage-card-active' : ''}`}
        onClick={() => onFilter('all')}
      >
        <div className="triage-card-count">{totalCount}</div>
        <div className="triage-card-label">Total</div>
      </div>
      <div
        className={`triage-summary-card triage-card-clickable triage-card-attention ${activeFilter === 'needs_attention' ? 'triage-card-active' : ''}`}
        onClick={() => onFilter('needs_attention')}
      >
        <div className="triage-card-count">{needsAttention}</div>
        <div className="triage-card-label">Needs Attention</div>
      </div>
      {ALL_STATES.map((s) => (
        <div
          key={s}
          className={`triage-summary-card triage-card-clickable ${activeFilter === s ? 'triage-card-active' : ''}`}
          onClick={() => onFilter(s)}
        >
          <div className="triage-card-count">{stateCounts[s] || 0}</div>
          <div className="triage-card-label">
            <span className={`badge badge-triage-${s}`}>{stateLabel(s)}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Findings Tab ─────────────────────────────────────────────────────────────

function FindingsTable({
  findings,
  activeFilter,
  onTriage,
}: {
  findings: FindingView[];
  activeFilter: string;
  onTriage: (fingerprint: string, state: string) => void;
}) {
  if (findings.length === 0) {
    return (
      <div className="empty-state">
        <h3>No findings{activeFilter !== 'all' ? ' in this state' : ''}</h3>
        <p>
          {activeFilter === 'all'
            ? 'Run a scan to see results.'
            : 'Click a different state card above to see other findings.'}
        </p>
      </div>
    );
  }

  const shown = findings.slice(0, 200);

  return (
    <>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>State</th>
              <th>Severity</th>
              <th>Confidence</th>
              <th>Rule</th>
              <th>File</th>
              <th>Line</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((f) => (
              <tr key={f.fingerprint}>
                <td>
                  <span
                    className={`badge badge-triage-${f.triage_state || 'open'}`}
                  >
                    {stateLabel(f.triage_state || 'open')}
                  </span>
                </td>
                <td>
                  <span
                    className={`badge badge-${(f.severity || '').toLowerCase()}`}
                  >
                    {f.severity || '-'}
                  </span>
                </td>
                <td>
                  {f.confidence ? (
                    <span
                      className={`badge badge-conf-${f.confidence.toLowerCase()}`}
                    >
                      {f.confidence}
                    </span>
                  ) : (
                    '-'
                  )}
                </td>
                <td>{f.rule_id}</td>
                <td className="cell-path" title={f.path}>
                  {truncPath(f.path)}
                </td>
                <td>{f.line}</td>
                <td className="triage-quick-actions">
                  {triageActionsFor(f).map((action) => (
                    <button
                      key={action.state}
                      className={`btn btn-sm btn-triage-quick btn-triage-${action.state}`}
                      onClick={() => onTriage(f.fingerprint, action.state)}
                    >
                      {action.label}
                    </button>
                  ))}
                  <Link to={`/findings/${f.index}`} className="btn btn-sm">
                    View
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {findings.length > 200 && (
        <p className="triage-truncation-note">
          Showing first 200 of {findings.length} findings. Use the state cards
          above to narrow down.
        </p>
      )}
    </>
  );
}

// ── Suppression Rules Tab ────────────────────────────────────────────────────

function SuppressionRulesTab({
  rules,
  onDelete,
}: {
  rules: SuppressionRule[];
  onDelete: (id: number) => void;
}) {
  if (rules.length === 0) {
    return (
      <div className="empty-state">
        <h3>No suppression rules</h3>
        <p>
          Suppress findings by pattern from the Findings page bulk actions, or
          from individual finding detail pages.
        </p>
      </div>
    );
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Type</th>
            <th>Pattern</th>
            <th>State</th>
            <th>Note</th>
            <th>Created</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.id}>
              <td>
                <span className="badge">{r.suppress_by}</span>
              </td>
              <td>
                <code>{r.match_value}</code>
              </td>
              <td>
                <span className={`badge badge-triage-${r.state}`}>
                  {stateLabel(r.state)}
                </span>
              </td>
              <td>{r.note || '-'}</td>
              <td style={{ fontSize: 'var(--text-xs)', whiteSpace: 'nowrap' }}>
                {r.created_at ? r.created_at.substring(0, 10) : '-'}
              </td>
              <td>
                <button
                  className="btn btn-sm btn-danger"
                  onClick={() => onDelete(r.id)}
                >
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Audit Log Tab ────────────────────────────────────────────────────────────

function AuditLogTab({ entries }: { entries: AuditEntry[] }) {
  if (entries.length === 0) {
    return (
      <div className="empty-state">
        <h3>No audit entries yet</h3>
        <p>
          Every triage action will be logged here with a timestamp and state
          transition.
        </p>
      </div>
    );
  }

  return (
    <div className="table-wrap">
      <table className="triage-audit-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Fingerprint</th>
            <th>Action</th>
            <th>Transition</th>
            <th>Note</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.id}>
              <td style={{ fontSize: 'var(--text-xs)', whiteSpace: 'nowrap' }}>
                {e.timestamp
                  ? e.timestamp.substring(0, 19).replace('T', ' ')
                  : '-'}
              </td>
              <td style={{ fontSize: 'var(--text-xs)' }}>
                <code title={e.fingerprint}>
                  {e.fingerprint.substring(0, 12)}
                </code>
              </td>
              <td>
                <span className="badge">{e.action}</span>
              </td>
              <td>
                <span className={`badge badge-triage-${e.previous_state}`}>
                  {stateLabel(e.previous_state)}
                </span>
                <span className="triage-arrow">&rarr;</span>
                <span className={`badge badge-triage-${e.new_state}`}>
                  {stateLabel(e.new_state)}
                </span>
              </td>
              <td style={{ fontSize: 'var(--text-xs)' }}>{e.note || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Triage Page ──────────────────────────────────────────────────────────────

type TriageTab = 'findings' | 'rules' | 'audit';

export function TriagePage() {
  const [triageFilter, setTriageFilter] = useState('all');
  const [activeTab, setActiveTab] = useState<TriageTab>('findings');

  // Load all findings (matching vanilla JS approach)
  const {
    data: findingsPage,
    isLoading: findingsLoading,
    error: findingsError,
  } = useFindings({
    per_page: 5000,
  });
  const { data: auditData } = useTriageAudit({ per_page: 100 });
  const { data: suppressionData } = useSuppressions();
  const { data: syncStatus } = useSyncStatus();

  const bulkTriage = useBulkTriage();
  const deleteSuppression = useDeleteSuppression();
  const triageExport = useTriageExport();
  const triageImport = useTriageImport();

  const findings = useMemo(() => findingsPage?.findings ?? [], [findingsPage]);
  const auditEntries = useMemo(() => auditData?.entries ?? [], [auditData]);
  const suppressionRules = useMemo(
    () => suppressionData?.rules ?? [],
    [suppressionData],
  );

  // Compute summary stats
  const { stateCounts, totalCount, needsAttention, openBySev, topRules } =
    useMemo(() => {
      const counts: Record<string, number> = {};
      ALL_STATES.forEach((s) => (counts[s] = 0));

      findings.forEach((f) => {
        const ts = f.triage_state || 'open';
        counts[ts] = (counts[ts] || 0) + 1;
      });

      const total = findings.length;
      const attention = (counts['open'] || 0) + (counts['investigating'] || 0);

      // Severity breakdown for open findings
      const bySev: Record<string, number> = {};
      ['High', 'Medium', 'Low'].forEach((sev) => {
        bySev[sev] = findings.filter(
          (f) => (f.triage_state || 'open') === 'open' && f.severity === sev,
        ).length;
      });

      // Top rules among open findings
      const ruleCounts: Record<string, number> = {};
      findings
        .filter((f) => (f.triage_state || 'open') === 'open')
        .forEach((f) => {
          ruleCounts[f.rule_id] = (ruleCounts[f.rule_id] || 0) + 1;
        });
      const top = Object.entries(ruleCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

      return {
        stateCounts: counts,
        totalCount: total,
        needsAttention: attention,
        openBySev: bySev,
        topRules: top,
      };
    }, [findings]);

  // Filter findings
  const filtered = useMemo(() => {
    if (triageFilter === 'all') return findings;
    if (triageFilter === 'needs_attention') {
      return findings.filter((f) => {
        const ts = f.triage_state || 'open';
        return ts === 'open' || ts === 'investigating';
      });
    }
    return findings.filter((f) => (f.triage_state || 'open') === triageFilter);
  }, [findings, triageFilter]);

  const handleTriage = useCallback(
    (fingerprint: string, state: string) => {
      bulkTriage.mutate({ fingerprints: [fingerprint], state, note: '' });
    },
    [bulkTriage],
  );

  const handleDeleteRule = useCallback(
    (id: number) => {
      deleteSuppression.mutate(id);
    },
    [deleteSuppression],
  );

  const handleExport = useCallback(() => {
    triageExport.mutate(undefined, {
      onSuccess: (result) => {
        const r = result as { exported?: number; suppression_rules?: number };
        alert(
          `Exported ${r.exported ?? 0} decisions and ${r.suppression_rules ?? 0} suppression rules to .nyx/triage.json\n\nCommit this file to share triage decisions with your team.`,
        );
      },
      onError: (err) => {
        alert('Export failed: ' + err.message);
      },
    });
  }, [triageExport]);

  const handleImport = useCallback(() => {
    triageImport.mutate(undefined, {
      onSuccess: (result) => {
        const r = result as { imported?: number; total_in_file?: number };
        alert(
          `Imported ${r.imported ?? 0} of ${r.total_in_file ?? 0} decisions from .nyx/triage.json`,
        );
      },
      onError: (err) => {
        alert('Import failed: ' + err.message);
      },
    });
  }, [triageImport]);

  if (findingsLoading) return <LoadingState message="Loading triage data..." />;
  if (findingsError) {
    return (
      <ErrorState
        title="Error loading triage data"
        message={findingsError.message}
      />
    );
  }

  const tabs: { id: TriageTab; label: string; count: number }[] = [
    { id: 'findings', label: 'Findings', count: filtered.length },
    { id: 'rules', label: 'Suppression Rules', count: suppressionRules.length },
    { id: 'audit', label: 'Audit Log', count: auditEntries.length },
  ];

  return (
    <div className="triage-page">
      {/* Summary cards */}
      <SummaryCards
        totalCount={totalCount}
        needsAttention={needsAttention}
        stateCounts={stateCounts}
        activeFilter={triageFilter}
        onFilter={setTriageFilter}
      />

      {/* Open findings breakdown */}
      {(stateCounts['open'] || 0) > 0 && (
        <div className="triage-open-summary">
          <div className="triage-open-severity">
            <span className="triage-open-label">Open by severity:</span>
            {['High', 'Medium', 'Low'].map((sev) => (
              <span key={sev} className="triage-sev-pill">
                <span className={`badge badge-${sev.toLowerCase()}`}>
                  {sev}
                </span>{' '}
                {openBySev[sev]}
              </span>
            ))}
          </div>
          {topRules.length > 0 && (
            <div className="triage-top-rules">
              <span className="triage-open-label">Top open rules:</span>
              {topRules.map(([rule, count]) => (
                <span key={rule} className="triage-rule-pill">
                  <code>{rule}</code>{' '}
                  <span className="triage-rule-count">{count}</span>
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tabs and sync controls */}
      <div className="triage-tabs-row">
        <div className="triage-tabs">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              className={`triage-tab ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label} ({tab.count})
            </button>
          ))}
        </div>
        <div className="triage-sync-controls">
          {syncStatus ? (
            syncStatus.sync_enabled ? (
              syncStatus.file_exists ? (
                <span className="triage-sync-status">
                  <span className="triage-sync-dot synced"></span>{' '}
                  .nyx/triage.json ({syncStatus.decisions} decisions)
                </span>
              ) : (
                <span className="triage-sync-status">
                  <span className="triage-sync-dot unsynced"></span> No sync
                  file
                </span>
              )
            ) : (
              <span className="triage-sync-status">
                <span className="triage-sync-dot unsynced"></span> Sync disabled
              </span>
            )
          ) : null}
          <button
            className="btn btn-sm"
            title="Save triage decisions to .nyx/triage.json for team sharing via git"
            onClick={handleExport}
          >
            Export
          </button>
          {syncStatus?.file_exists && (
            <button
              className="btn btn-sm"
              title="Load triage decisions from .nyx/triage.json"
              onClick={handleImport}
            >
              Import
            </button>
          )}
        </div>
      </div>

      {/* Tab content */}
      <div
        className="triage-tab-content"
        style={{ display: activeTab === 'findings' ? 'block' : 'none' }}
      >
        <FindingsTable
          findings={filtered}
          activeFilter={triageFilter}
          onTriage={handleTriage}
        />
      </div>

      <div
        className="triage-tab-content"
        style={{ display: activeTab === 'rules' ? 'block' : 'none' }}
      >
        <SuppressionRulesTab
          rules={suppressionRules}
          onDelete={handleDeleteRule}
        />
      </div>

      <div
        className="triage-tab-content"
        style={{ display: activeTab === 'audit' ? 'block' : 'none' }}
      >
        <AuditLogTab entries={auditEntries} />
      </div>
    </div>
  );
}
