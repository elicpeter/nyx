import { Link, useLocation } from 'react-router-dom';

const SECTION_TITLES: Record<string, string> = {
  overview: 'Overview',
  findings: 'Findings',
  scans: 'Scans',
  rules: 'Rules',
  triage: 'Triage',
  config: 'Config',
  explorer: 'Explorer',
  debug: 'Debug',
  settings: 'Settings',
};

const ROUTE_TITLES: Record<string, string> = {
  '/debug/cfg': 'CFG Viewer',
  '/debug/ssa': 'SSA Viewer',
  '/debug/call-graph': 'Call Graph',
  '/debug/taint': 'Taint Debugger',
};

function pathToSection(pathname: string): string {
  if (pathname === '/') return 'overview';
  const first = pathname.split('/')[1];
  return first || 'overview';
}

function buildBreadcrumbs(pathname: string) {
  const section = pathToSection(pathname);
  const sectionTitle = SECTION_TITLES[section] ?? section;
  const crumbs: Array<{ label: string; path?: string }> = [];

  // Always show section as root breadcrumb
  const sectionPath = section === 'overview' ? '/' : `/${section}`;
  crumbs.push({ label: sectionTitle, path: sectionPath });

  // If we have a sub-route, show it
  if (ROUTE_TITLES[pathname]) {
    crumbs.push({ label: ROUTE_TITLES[pathname] });
  } else {
    const parts = pathname.split('/').filter(Boolean);
    if (parts.length > 1) {
      // e.g. /findings/123 or /scans/compare/1/2
      const sub = parts.slice(1).join('/');
      crumbs.push({ label: sub });
    }
  }

  return crumbs;
}

interface HeaderBarProps {
  onStartScan?: () => void;
}

export function HeaderBar({ onStartScan }: HeaderBarProps) {
  const { pathname } = useLocation();
  const crumbs = buildBreadcrumbs(pathname);

  return (
    <header className="header-bar">
      <div className="header-left">
        <nav className="breadcrumbs">
          {crumbs.map((crumb, i) => {
            const isLast = i === crumbs.length - 1;
            return (
              <span key={i}>
                {i > 0 && <span className="breadcrumb-sep">/</span>}
                {isLast || !crumb.path ? (
                  <span className="breadcrumb-current">{crumb.label}</span>
                ) : (
                  <Link to={crumb.path} className="breadcrumb-link">
                    {crumb.label}
                  </Link>
                )}
              </span>
            );
          })}
        </nav>
      </div>
      <div className="header-right">
        {onStartScan && (
          <button className="btn btn-primary btn-sm" onClick={onStartScan}>
            Start Scan
          </button>
        )}
      </div>
    </header>
  );
}
