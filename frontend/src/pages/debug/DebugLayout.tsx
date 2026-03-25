import { useState, useCallback } from 'react';
import { NavLink, Outlet, useSearchParams } from 'react-router-dom';
import { FunctionSelector } from './FunctionSelector';
import { FileTree } from '../../components/data-display/FileTree';
import { LoadingState } from '../../components/ui/LoadingState';
import { useFileTree } from '../../hooks/useFileTree';

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
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const file = params.get('file') ?? '';
  const fn_name = params.get('function') ?? null;

  const handleFileSelect = useCallback(
    (path: string) => {
      setParams((prev) => {
        const next = new URLSearchParams(prev);
        next.set('file', path);
        next.delete('function');
        return next;
      });
    },
    [setParams],
  );

  const {
    rootEntries,
    isLoading: treeLoading,
    expandedPaths,
    loadedChildren,
    selectedPath,
    handleToggleExpand,
    handleSelectFile,
  } = useFileTree(file || null, handleFileSelect);

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
      <aside className={`debug-sidebar${sidebarOpen ? '' : ' collapsed'}`}>
        <div className="debug-sidebar-header">
          <span>Files</span>
          <button
            className="debug-sidebar-toggle"
            onClick={() => setSidebarOpen(false)}
            title="Collapse sidebar"
          >
            &lsaquo;
          </button>
        </div>
        <div className="debug-sidebar-body">
          {treeLoading && <LoadingState message="Loading files..." />}
          {rootEntries && (
            <FileTree
              entries={rootEntries}
              expandedPaths={expandedPaths}
              selectedPath={selectedPath}
              onToggleExpand={handleToggleExpand}
              onSelectFile={handleSelectFile}
              loadedChildren={loadedChildren}
            />
          )}
        </div>
      </aside>
      {!sidebarOpen && (
        <button
          className="debug-sidebar-expand"
          onClick={() => setSidebarOpen(true)}
          title="Show file tree"
        >
          &rsaquo;
        </button>
      )}
      <div className="debug-main">
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
          onFunctionChange={(f) => updateParam('function', f)}
        />
        <div className="debug-content">
          <Outlet context={{ file: file || null, fn_name }} />
        </div>
      </div>
    </div>
  );
}
