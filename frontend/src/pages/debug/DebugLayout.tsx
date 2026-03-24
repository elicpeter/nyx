import { NavLink, Outlet, useSearchParams } from 'react-router-dom';
import { FunctionSelector } from './FunctionSelector';

const TABS = [
  { path: '/debug/cfg', label: 'CFG' },
  { path: '/debug/ssa', label: 'SSA' },
  { path: '/debug/call-graph', label: 'Call Graph' },
  { path: '/debug/taint', label: 'Taint' },
  { path: '/debug/summaries', label: 'Summaries' },
  { path: '/debug/abstract-interp', label: 'Abstract Interp' },
  { path: '/debug/symex', label: 'Symex' },
];

export function DebugLayout() {
  const [params, setParams] = useSearchParams();
  const file = params.get('file') ?? '';
  const fn_name = params.get('function') ?? null;

  const updateParam = (key: string, value: string | null) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (value) {
        next.set(key, value);
      } else {
        next.delete(key);
      }
      return next;
    });
  };

  return (
    <div className="debug-layout">
      <nav className="debug-tabs">
        {TABS.map((tab) => (
          <NavLink
            key={tab.path}
            to={`${tab.path}?${params}`}
            className={({ isActive }) =>
              `debug-tab${isActive ? ' debug-tab-active' : ''}`
            }
          >
            {tab.label}
          </NavLink>
        ))}
      </nav>
      <FunctionSelector
        file={file}
        selectedFunction={fn_name}
        onFileChange={(f) => updateParam('file', f)}
        onFunctionChange={(f) => updateParam('function', f)}
      />
      <div className="debug-content">
        <Outlet context={{ file: file || null, fn_name }} />
      </div>
    </div>
  );
}
