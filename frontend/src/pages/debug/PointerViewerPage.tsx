import { useMemo } from 'react';
import { useDebugPointer } from '../../api/queries/debug';
import { ApiError } from '../../api/client';
import { EmptyState } from '../../components/ui/EmptyState';
import { ErrorState } from '../../components/ui/ErrorState';
import { LoadingState } from '../../components/ui/LoadingState';
import type {
  PointerLocationView,
  PointerValueView,
  PointerFieldEntryView,
} from '../../api/types';

interface PointerAnalysisPanelProps {
  file: string;
  functionName: string;
}

export function PointerAnalysisPanel({
  file,
  functionName,
}: PointerAnalysisPanelProps) {
  const { data, isLoading, error } = useDebugPointer(file, functionName);

  if (isLoading) {
    return <LoadingState message="Loading points-to facts..." />;
  }
  if (error) {
    if (error instanceof ApiError && error.status === 404) {
      return (
        <EmptyState message="Pointer analysis is not available for the selected function." />
      );
    }
    return <ErrorState message="Failed to load pointer analysis." />;
  }
  if (
    !data ||
    (data.values.length === 0 &&
      data.field_reads.length === 0 &&
      data.field_writes.length === 0)
  ) {
    return (
      <EmptyState message="No points-to facts were derived for this function. Pointer analysis flags up parameters, allocation sites, and field projections; functions that only manipulate scalars will appear empty." />
    );
  }

  return (
    <div className="abstract-interp-viewer">
      <div className="abstract-block">
        <div className="abstract-block-header">
          <h3 style={{ margin: 0 }}>Per-Value Points-To</h3>
          <span className="text-secondary">
            {data.values.length} value
            {data.values.length === 1 ? '' : 's'} ·{' '}
            {data.location_count} location
            {data.location_count === 1 ? '' : 's'}
          </span>
        </div>
        {data.values.length === 0 ? (
          <p className="abstract-empty">All SSA values point to nothing tracked.</p>
        ) : (
          <PointerValueTable
            values={data.values}
            locations={data.locations}
          />
        )}
      </div>

      {data.field_reads.length > 0 && (
        <FieldEntriesBlock
          title="Field Reads"
          entries={data.field_reads}
          emptyHint="(no parameter field reads recorded)"
        />
      )}

      {data.field_writes.length > 0 && (
        <FieldEntriesBlock
          title="Field Writes"
          entries={data.field_writes}
          emptyHint="(no parameter field writes recorded)"
        />
      )}
    </div>
  );
}

function PointerValueTable({
  values,
  locations,
}: {
  values: PointerValueView[];
  locations: PointerLocationView[];
}) {
  const locById = useMemo(() => {
    const map = new Map<number, PointerLocationView>();
    for (const loc of locations) map.set(loc.id, loc);
    return map;
  }, [locations]);

  return (
    <table className="abstract-table">
      <thead>
        <tr>
          <th>Value</th>
          <th>Name</th>
          <th>Points-To</th>
        </tr>
      </thead>
      <tbody>
        {values.map((v) => (
          <tr key={v.ssa_value}>
            <td className="mono">v{v.ssa_value}</td>
            <td className="mono">{v.var_name ?? '-'}</td>
            <td>
              {v.is_top ? (
                <span className="cap-badge cap-badge-sink" title="Over-approximation">
                  ⊤ (top)
                </span>
              ) : (
                v.points_to.map((id) => (
                  <LocationChip key={id} loc={locById.get(id)} />
                ))
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function LocationChip({ loc }: { loc?: PointerLocationView }) {
  if (!loc) {
    return (
      <span className="cap-badge" title="Unknown location id">
        ?
      </span>
    );
  }
  const className =
    loc.kind === 'Top'
      ? 'cap-badge cap-badge-sink'
      : loc.kind === 'Field'
        ? 'cap-badge cap-badge-sanitizer'
        : 'cap-badge cap-badge-source';
  return (
    <span
      className={className}
      title={`${loc.kind} (loc#${loc.id})`}
      style={{ marginRight: 4 }}
    >
      {loc.display}
    </span>
  );
}

function FieldEntriesBlock({
  title,
  entries,
  emptyHint,
}: {
  title: string;
  entries: PointerFieldEntryView[];
  emptyHint: string;
}) {
  return (
    <div className="abstract-block">
      <div className="abstract-block-header">
        <h3 style={{ margin: 0 }}>{title}</h3>
        <span className="text-secondary">
          {entries.length} entr{entries.length === 1 ? 'y' : 'ies'}
        </span>
      </div>
      {entries.length === 0 ? (
        <p className="abstract-empty">{emptyHint}</p>
      ) : (
        <table className="abstract-table">
          <thead>
            <tr>
              <th>Target</th>
              <th>Field</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e, i) => (
              <tr key={`${e.param_index ?? 'self'}-${e.field}-${i}`}>
                <td className="mono">
                  {e.param_index === null ? 'self' : `param[${e.param_index}]`}
                </td>
                <td className="mono">{e.field}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
