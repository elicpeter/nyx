import { NavLink } from 'react-router-dom';
import {
  OverviewIcon,
  FindingsIcon,
  ScansIcon,
  RulesIcon,
  TriageIcon,
  ConfigIcon,
  ExplorerIcon,
  DebugIcon,
  FolderIcon,
  TagIcon,
} from '../icons/Icons';
import type { FC } from 'react';
import type { IconProps } from '../icons/Icons';
import { useHealth } from '../../api/queries/health';
import { useSSE } from '../../contexts/SSEContext';

interface NavItem {
  id: string;
  label: string;
  path: string;
  Icon: FC<IconProps>;
  group: 'primary' | 'secondary' | 'footer';
}

const NAV_SECTIONS: NavItem[] = [
  {
    id: 'overview',
    label: 'Overview',
    path: '/',
    Icon: OverviewIcon,
    group: 'primary',
  },
  {
    id: 'findings',
    label: 'Findings',
    path: '/findings',
    Icon: FindingsIcon,
    group: 'primary',
  },
  {
    id: 'scans',
    label: 'Scans',
    path: '/scans',
    Icon: ScansIcon,
    group: 'primary',
  },
  {
    id: 'rules',
    label: 'Rules',
    path: '/rules',
    Icon: RulesIcon,
    group: 'primary',
  },
  {
    id: 'triage',
    label: 'Triage',
    path: '/triage',
    Icon: TriageIcon,
    group: 'primary',
  },
  {
    id: 'explorer',
    label: 'Explorer',
    path: '/explorer',
    Icon: ExplorerIcon,
    group: 'secondary',
  },
  {
    id: 'debug',
    label: 'Debug',
    path: '/debug',
    Icon: DebugIcon,
    group: 'secondary',
  },
  {
    id: 'config',
    label: 'Config',
    path: '/config',
    Icon: ConfigIcon,
    group: 'footer',
  },
];

function navLinkClass({ isActive }: { isActive: boolean }) {
  return `nav-link${isActive ? ' active' : ''}`;
}

export function Sidebar() {
  const { data: health } = useHealth();
  const { isScanRunning } = useSSE();

  const primary = NAV_SECTIONS.filter((n) => n.group === 'primary');
  const secondary = NAV_SECTIONS.filter((n) => n.group === 'secondary');
  const footer = NAV_SECTIONS.filter((n) => n.group === 'footer');

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <span className="logo">nyx</span>
        {health?.version && <span className="version">v{health.version}</span>}
      </div>

      <ul className="nav-list">
        {primary.map((item) => (
          <li key={item.id}>
            <NavLink
              to={item.path}
              end={item.path === '/'}
              className={navLinkClass}
            >
              <span className="nav-icon">
                <item.Icon />
              </span>
              <span>{item.label}</span>
            </NavLink>
          </li>
        ))}

        <li className="nav-separator" />

        {secondary.map((item) => (
          <li key={item.id}>
            <NavLink to={item.path} className={navLinkClass}>
              <span className="nav-icon">
                <item.Icon />
              </span>
              <span>{item.label}</span>
            </NavLink>
          </li>
        ))}
      </ul>

      <div className="sidebar-footer">
        <ul className="nav-list" style={{ flex: 'none' }}>
          {footer.map((item) => (
            <li key={item.id}>
              <NavLink to={item.path} className={navLinkClass}>
                <span className="nav-icon">
                  <item.Icon />
                </span>
                <span>{item.label}</span>
              </NavLink>
            </li>
          ))}
        </ul>
      </div>

      <div className="sidebar-meta">
        {health?.scan_root && (
          <div className="sidebar-meta-item" title={health.scan_root}>
            <FolderIcon />
            <span>{health.scan_root}</span>
          </div>
        )}
        {health?.version && (
          <div className="sidebar-meta-item">
            <TagIcon />
            <span>v{health.version}</span>
          </div>
        )}
        <div className={`scan-indicator${isScanRunning ? ' visible' : ''}`}>
          <span className="status-dot running" />
          Scanning...
        </div>
      </div>
    </aside>
  );
}
