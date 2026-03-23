import { useLocation } from 'react-router-dom';
import { ICONS } from '../components/icons/Icons';

const STUB_DESCRIPTIONS: Record<string, string> = {
  '/explorer':
    'Browse the scanned codebase, view file trees, and inspect individual files with inline annotations.',
  '/debug':
    'Inspect internal analysis state — control flow graphs, SSA IR, call graphs, and taint propagation.',
  '/debug/cfg':
    'Visualize control flow graphs for individual functions with block-level detail.',
  '/debug/ssa':
    'Inspect SSA intermediate representation including phi nodes, value numbering, and taint state.',
  '/debug/call-graph':
    'Explore the inter-procedural call graph with SCC highlighting and topo-order visualization.',
  '/debug/taint':
    'Step through taint propagation with per-instruction state snapshots and path tracking.',
  '/settings':
    'Application settings and preferences.',
};

const ROUTE_LABELS: Record<string, string> = {
  '/explorer': 'Explorer',
  '/debug': 'Debug',
  '/debug/cfg': 'CFG Viewer',
  '/debug/ssa': 'SSA Viewer',
  '/debug/call-graph': 'Call Graph',
  '/debug/taint': 'Taint Debugger',
  '/settings': 'Settings',
};

function sectionFromPath(pathname: string): string {
  if (pathname === '/') return 'overview';
  const first = pathname.split('/')[1];
  return first || 'overview';
}

export function StubPage() {
  const { pathname } = useLocation();
  const label = ROUTE_LABELS[pathname] ?? sectionFromPath(pathname);
  const description =
    STUB_DESCRIPTIONS[pathname] ?? 'This page is under construction.';
  const section = sectionFromPath(pathname);
  const IconComponent = ICONS[section];

  return (
    <div className="stub-page">
      {IconComponent && (
        <div className="stub-icon">
          <IconComponent size={48} />
        </div>
      )}
      <h2 className="stub-title">{label}</h2>
      <p className="stub-description">{description}</p>
      <span className="stub-badge">Coming Soon</span>
    </div>
  );
}
