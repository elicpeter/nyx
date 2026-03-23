import { useNavigate } from 'react-router-dom';
import { useOverview, useOverviewTrends } from '../api/queries/overview';
import { StatCard } from '../components/ui/StatCard';
import { LoadingState } from '../components/ui/LoadingState';
import { ErrorState } from '../components/ui/ErrorState';
import { HorizontalBarChart } from '../components/charts/HorizontalBarChart';
import { LineChart } from '../components/charts/LineChart';
import { OverviewIcon } from '../components/icons/Icons';
import { truncPath } from '../utils/truncPath';
import type { OverviewCount, ScanSummary, Insight } from '../api/types';

export function OverviewPage() {
  const navigate = useNavigate();
  const { data: overview, isLoading, error } = useOverview();
  const { data: trends } = useOverviewTrends();

  if (isLoading) {
    return <LoadingState message="Loading overview..." />;
  }

  if (error) {
    return <ErrorState title="Error loading overview" message={(error as Error).message} />;
  }

  if (!overview) {
    return <LoadingState message="Loading overview..." />;
  }

  // Empty state
  if (overview.state === 'empty') {
    return (
      <div className="overview-empty">
        <OverviewIcon size={48} />
        <h2>Welcome to Nyx</h2>
        <p>Start your first scan to see security findings and analytics.</p>
        <button
          className="btn btn-primary"
          onClick={() => {
            // TODO: wire to openNewScanModal when modals are ported
          }}
        >
          Start Scan
        </button>
      </div>
    );
  }

  // Data preparation
  const netDelta = overview.new_since_last - overview.fixed_since_last;

  const sevItems = (['HIGH', 'MEDIUM', 'LOW'] as const).map(s => ({
    label: s.charAt(0) + s.slice(1).toLowerCase(),
    value: overview.by_severity[s] || 0,
    color: s === 'HIGH' ? '#e74c3c' : s === 'MEDIUM' ? '#e67e22' : '#3498db',
  }));

  const catItems = Object.entries(overview.by_category || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([k, v]) => ({ label: k, value: v, color: '#5856d6' }));

  const langItems = Object.entries(overview.by_language || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([k, v]) => ({ label: k, value: v, color: '#5856d6' }));

  const trendData = (trends || []).map(t => ({ label: t.timestamp, value: t.total }));

  return (
    <>
      <div className="page-header">
        <h2>Overview</h2>
      </div>

      {/* Fresh banner */}
      {overview.state === 'fresh' && (
        <div className="overview-fresh-banner">
          <strong>Scan completed</strong>
          <span>
            {overview.total_findings} finding{overview.total_findings === 1 ? '' : 's'} detected
            {overview.latest_scan_duration_secs != null
              ? ` in ${overview.latest_scan_duration_secs.toFixed(1)}s`
              : ''}
            .
          </span>
          <a
            href="/findings"
            className="nav-link-internal"
            onClick={e => {
              e.preventDefault();
              navigate('/findings');
            }}
          >
            View all findings &rarr;
          </a>
        </div>
      )}

      {/* Stat cards */}
      <div className="overview-stat-grid">
        <StatCard
          label="Total Findings"
          value={overview.total_findings}
          delta={netDelta || null}
        />
        <StatCard
          label="New"
          value={overview.new_since_last}
          color={overview.new_since_last > 0 ? 'var(--sev-high)' : undefined}
        />
        <StatCard
          label="Fixed"
          value={overview.fixed_since_last}
          color={overview.fixed_since_last > 0 ? 'var(--success)' : undefined}
        />
        <StatCard
          label="High Confidence"
          value={`${(overview.high_confidence_rate * 100).toFixed(0)}%`}
        />
        <StatCard
          label="Triage Coverage"
          value={`${(overview.triage_coverage * 100).toFixed(0)}%`}
        />
        <StatCard
          label="Scan Duration"
          value={
            overview.latest_scan_duration_secs != null
              ? `${overview.latest_scan_duration_secs.toFixed(1)}s`
              : '-'
          }
        />
      </div>

      {/* Charts */}
      <div className="overview-chart-grid">
        <div className="card">
          <div className="card-header">Findings Over Time</div>
          <LineChart points={trendData} />
        </div>
        <div className="card">
          <div className="card-header">By Severity</div>
          <HorizontalBarChart items={sevItems} />
        </div>
        <div className="card">
          <div className="card-header">By Category</div>
          <HorizontalBarChart items={catItems} />
        </div>
        <div className="card">
          <div className="card-header">By Language</div>
          <HorizontalBarChart items={langItems} />
        </div>
      </div>

      {/* Tables */}
      <div className="overview-table-grid">
        <div className="card">
          <div className="card-header">Top Affected Files</div>
          <CompactTable
            items={overview.top_files}
            nameLabel="File"
            countLabel="Findings"
            truncate
            onRowClick={item =>
              navigate(`/findings?search=${encodeURIComponent(item.name)}`)
            }
          />
        </div>
        <div className="card">
          <div className="card-header">Top Directories</div>
          <CompactTable
            items={overview.top_directories}
            nameLabel="Directory"
            countLabel="Findings"
            truncate
          />
        </div>
        <div className="card">
          <div className="card-header">Top Rules Triggered</div>
          <CompactTable
            items={overview.top_rules}
            nameLabel="Rule"
            countLabel="Findings"
          />
        </div>
        <div className="card">
          <div className="card-header">Recent Scans</div>
          <RecentScansTable
            scans={overview.recent_scans}
            onRowClick={scan => navigate(`/scans/${scan.id}`)}
          />
        </div>
      </div>

      {/* Insights */}
      {overview.insights.length > 0 && (
        <div className="overview-insights">
          <div className="card">
            <div className="card-header">Insights</div>
            <div className="insight-list">
              {overview.insights.map((insight, i) => (
                <InsightCard key={i} insight={insight} />
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// ── Sub-components ──────────────────────────────────────────────────────────

interface CompactTableProps {
  items: OverviewCount[];
  nameLabel: string;
  countLabel: string;
  truncate?: boolean;
  onRowClick?: (item: OverviewCount) => void;
}

function CompactTable({ items, nameLabel, countLabel, truncate, onRowClick }: CompactTableProps) {
  if (!items || items.length === 0) {
    return (
      <div className="empty-state" style={{ padding: 16 }}>
        <p>No data</p>
      </div>
    );
  }

  return (
    <table>
      <thead>
        <tr>
          <th>{nameLabel}</th>
          <th>{countLabel}</th>
        </tr>
      </thead>
      <tbody>
        {items.map(item => {
          const displayName = truncate ? truncPath(item.name, 45) : item.name;
          return (
            <tr
              key={item.name}
              className={onRowClick ? 'clickable' : undefined}
              onClick={onRowClick ? () => onRowClick(item) : undefined}
              title={item.name}
            >
              <td>{displayName}</td>
              <td>{item.count}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

interface RecentScansTableProps {
  scans: ScanSummary[];
  onRowClick: (scan: ScanSummary) => void;
}

function RecentScansTable({ scans, onRowClick }: RecentScansTableProps) {
  if (!scans || scans.length === 0) {
    return (
      <div className="empty-state" style={{ padding: 16 }}>
        <p>No scans yet</p>
      </div>
    );
  }

  return (
    <table>
      <thead>
        <tr>
          <th>Status</th>
          <th>Duration</th>
          <th>Findings</th>
          <th>Time</th>
        </tr>
      </thead>
      <tbody>
        {scans.slice(0, 5).map(scan => (
          <tr
            key={scan.id}
            className="clickable"
            onClick={() => onRowClick(scan)}
          >
            <td>
              <span className={`status-dot ${scan.status}`} /> {scan.status}
            </td>
            <td>
              {scan.duration_secs != null
                ? `${scan.duration_secs.toFixed(1)}s`
                : '-'}
            </td>
            <td>{scan.finding_count ?? '-'}</td>
            <td>
              {scan.started_at
                ? new Date(scan.started_at).toLocaleString()
                : '-'}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

interface InsightCardProps {
  insight: Insight;
}

function InsightCard({ insight }: InsightCardProps) {
  const navigate = useNavigate();

  return (
    <div className={`insight-card insight-${insight.severity}`}>
      <span>{insight.message}</span>
      {insight.action_url && (
        <a
          href={insight.action_url}
          className="nav-link-internal"
          onClick={e => {
            e.preventDefault();
            navigate(insight.action_url!);
          }}
        >
          View &rarr;
        </a>
      )}
    </div>
  );
}
