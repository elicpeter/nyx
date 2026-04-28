import { useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useDebugAuth } from '../../api/queries/debug';
import { ApiError } from '../../api/client';
import { EmptyState } from '../../components/ui/EmptyState';
import { ErrorState } from '../../components/ui/ErrorState';
import { LoadingState } from '../../components/ui/LoadingState';
import { FileTree } from '../../components/data-display/FileTree';
import { useFileTree } from '../../hooks/useFileTree';
import type {
  AuthAnalysisView,
  AuthCheckView,
  AuthOperationView,
  AuthRouteView,
  AuthUnitView,
  AuthValueRefView,
} from '../../api/types';

export function AuthAnalysisPage() {
  const [params, setParams] = useSearchParams();
  const file = params.get('file') || null;

  const handleSelectFile = useCallback(
    (path: string) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          next.set('file', path);
          return next;
        },
        { replace: false },
      );
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
    handleSelectFile: onTreeSelect,
  } = useFileTree(file, handleSelectFile);

  return (
    <div className="debug-split">
      <div
        className="debug-split-sidebar"
        style={{ width: 320, overflow: 'auto' }}
      >
        <div className="debug-toolbar" style={{ marginBottom: 8 }}>
          <span className="debug-toolbar-label">Pick a file</span>
        </div>
        {treeLoading && <LoadingState message="Loading files..." />}
        {rootEntries && (
          <FileTree
            entries={rootEntries}
            expandedPaths={expandedPaths}
            selectedPath={selectedPath}
            onToggleExpand={handleToggleExpand}
            onSelectFile={onTreeSelect}
            loadedChildren={loadedChildren}
          />
        )}
      </div>
      <div className="debug-split-main">
        <AuthAnalysisContent file={file} />
      </div>
    </div>
  );
}

function AuthAnalysisContent({ file }: { file: string | null }) {
  const { data, isLoading, error } = useDebugAuth(file);

  if (!file) {
    return (
      <EmptyState message="Select a file from the left to inspect its authorization model." />
    );
  }
  if (isLoading) {
    return <LoadingState message="Running authorization extraction..." />;
  }
  if (error) {
    if (error instanceof ApiError && error.status === 400) {
      return (
        <EmptyState message="Auth analysis only runs on supported source files. Try a .ts / .py / .rb / .rs / .go / .java / .php / .rs file." />
      );
    }
    return <ErrorState message="Failed to run authorization extraction." />;
  }
  if (!data) {
    return null;
  }

  if (!data.enabled) {
    return (
      <EmptyState message="Authorization analysis is disabled for this file's language. Toggle scanner.auth_analysis.enable in your nyx.toml to opt in." />
    );
  }

  if (data.routes.length === 0 && data.units.length === 0) {
    return (
      <EmptyState message="No routes or analysis units were extracted from this file. Auth analysis fires on framework route handlers and helper functions whose body matches an authorization-check pattern." />
    );
  }

  return (
    <div className="abstract-interp-viewer">
      <AuthSummaryHeader data={data} />
      {data.routes.length > 0 && <AuthRoutesBlock routes={data.routes} />}
      {data.units.length > 0 && <AuthUnitsBlock units={data.units} />}
    </div>
  );
}

function AuthSummaryHeader({ data }: { data: AuthAnalysisView }) {
  const totalChecks = data.units.reduce(
    (acc, u) => acc + u.auth_checks.length,
    0,
  );
  const totalOps = data.units.reduce((acc, u) => acc + u.operations.length, 0);
  return (
    <div className="abstract-block">
      <div className="abstract-block-header">
        <h3 style={{ margin: 0 }}>Authorization Model</h3>
        <span className="text-secondary">
          {data.routes.length} route{data.routes.length === 1 ? '' : 's'} ·{' '}
          {data.units.length} unit{data.units.length === 1 ? '' : 's'} ·{' '}
          {totalChecks} auth check{totalChecks === 1 ? '' : 's'} ·{' '}
          {totalOps} sensitive op{totalOps === 1 ? '' : 's'}
        </span>
      </div>
    </div>
  );
}

function AuthRoutesBlock({ routes }: { routes: AuthRouteView[] }) {
  return (
    <div className="abstract-block">
      <div className="abstract-block-header">
        <h3 style={{ margin: 0 }}>Routes</h3>
        <span className="text-secondary">
          {routes.length} registration{routes.length === 1 ? '' : 's'}
        </span>
      </div>
      <table className="abstract-table">
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Framework</th>
            <th>Middleware</th>
            <th>Handler Params</th>
            <th>Line</th>
            <th>Unit</th>
          </tr>
        </thead>
        <tbody>
          {routes.map((r, i) => (
            <tr key={`${r.method}-${r.path}-${i}`}>
              <td>
                <span className="cap-badge cap-badge-source">{r.method}</span>
              </td>
              <td className="mono">{r.path}</td>
              <td>{r.framework}</td>
              <td className="mono">
                {r.middleware.length > 0 ? r.middleware.join(', ') : '-'}
              </td>
              <td className="mono">
                {r.handler_params.length > 0
                  ? r.handler_params.join(', ')
                  : '-'}
              </td>
              <td className="mono">L{r.line}</td>
              <td className="mono">#{r.unit_idx}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AuthUnitsBlock({ units }: { units: AuthUnitView[] }) {
  return (
    <>
      {units.map((u, i) => (
        <AuthUnitCard key={`${u.name ?? '<anon>'}-${i}`} unit={u} index={i} />
      ))}
    </>
  );
}

function AuthUnitCard({ unit, index }: { unit: AuthUnitView; index: number }) {
  return (
    <div className="abstract-block">
      <div className="abstract-block-header">
        <h3 style={{ margin: 0 }}>
          #{index} {unit.name ?? '<anonymous>'}
          <span className="text-secondary" style={{ marginLeft: 8 }}>
            {unit.kind} · L{unit.line}
          </span>
        </h3>
        <span className="text-secondary">
          {unit.auth_checks.length} check
          {unit.auth_checks.length === 1 ? '' : 's'} ·{' '}
          {unit.operations.length} op
          {unit.operations.length === 1 ? '' : 's'}
        </span>
      </div>
      {unit.params.length > 0 && (
        <DetailRow label="Params" value={unit.params.join(', ')} />
      )}
      {unit.self_actor_vars.length > 0 && (
        <DetailRow
          label="Self-actor vars"
          value={unit.self_actor_vars.join(', ')}
        />
      )}
      {unit.typed_bounded_vars.length > 0 && (
        <DetailRow
          label="Typed-bounded params"
          value={unit.typed_bounded_vars.join(', ')}
        />
      )}
      {unit.authorized_sql_vars.length > 0 && (
        <DetailRow
          label="Authorized SQL vars"
          value={unit.authorized_sql_vars.join(', ')}
        />
      )}
      {unit.const_bound_vars.length > 0 && (
        <DetailRow
          label="Const-bound vars"
          value={unit.const_bound_vars.join(', ')}
        />
      )}

      {unit.auth_checks.length > 0 && (
        <AuthCheckTable checks={unit.auth_checks} />
      )}
      {unit.operations.length > 0 && (
        <OperationTable operations={unit.operations} />
      )}
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="debug-detail-row" style={{ padding: '4px 12px' }}>
      <span className="debug-detail-label">{label}</span>
      <span className="debug-detail-value mono">{value}</span>
    </div>
  );
}

function AuthCheckTable({ checks }: { checks: AuthCheckView[] }) {
  return (
    <div style={{ paddingTop: 8 }}>
      <h4 style={{ margin: '0 12px 4px' }}>Auth Checks</h4>
      <table className="abstract-table">
        <thead>
          <tr>
            <th>Kind</th>
            <th>Callee</th>
            <th>Subjects</th>
            <th>Line</th>
          </tr>
        </thead>
        <tbody>
          {checks.map((c, i) => (
            <tr key={`${c.callee}-${c.line}-${i}`}>
              <td>
                <span className="cap-badge cap-badge-source">{c.kind}</span>
              </td>
              <td className="mono">{c.callee}</td>
              <td>
                {c.subjects.length === 0 ? (
                  '-'
                ) : (
                  <SubjectChips subjects={c.subjects} />
                )}
              </td>
              <td className="mono">L{c.line}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function OperationTable({ operations }: { operations: AuthOperationView[] }) {
  return (
    <div style={{ paddingTop: 8 }}>
      <h4 style={{ margin: '0 12px 4px' }}>Sensitive Operations</h4>
      <table className="abstract-table">
        <thead>
          <tr>
            <th>Kind</th>
            <th>Sink Class</th>
            <th>Callee</th>
            <th>Subjects</th>
            <th>Line</th>
          </tr>
        </thead>
        <tbody>
          {operations.map((op, i) => (
            <tr key={`${op.callee}-${op.line}-${i}`}>
              <td>
                <span className="cap-badge cap-badge-sanitizer">{op.kind}</span>
              </td>
              <td>
                {op.sink_class ? (
                  <span className="cap-badge cap-badge-sink">
                    {op.sink_class}
                  </span>
                ) : (
                  '-'
                )}
              </td>
              <td className="mono" title={op.text}>
                {op.callee}
              </td>
              <td>
                {op.subjects.length === 0 ? (
                  '-'
                ) : (
                  <SubjectChips subjects={op.subjects} />
                )}
              </td>
              <td className="mono">L{op.line}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SubjectChips({ subjects }: { subjects: AuthValueRefView[] }) {
  return (
    <>
      {subjects.map((s, i) => (
        <span
          key={`${s.name}-${i}`}
          className="cap-badge"
          style={{ marginRight: 4 }}
          title={`${s.source_kind}${s.base ? ` (base: ${s.base})` : ''}`}
        >
          {s.name}
        </span>
      ))}
    </>
  );
}
