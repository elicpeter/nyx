import { NavLink, Outlet } from 'react-router-dom';

const TABS = [
  { path: '/debug/call-graph', label: 'Call Graph' },
  { path: '/debug/summaries', label: 'Summaries' },
  { path: '/debug/auth', label: 'Auth Analysis' },
];

export function DebugLayout() {
  return (
    <div className="debug-layout debug-layout-global">
      <div className="debug-main">
        <nav className="debug-tabs">
          {TABS.map((tab) => (
            <NavLink
              key={tab.path}
              to={tab.path}
              className={({ isActive }) =>
                `debug-tab${isActive ? ' debug-tab-active' : ''}`
              }
            >
              {tab.label}
            </NavLink>
          ))}
        </nav>
        <div className="debug-content">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
