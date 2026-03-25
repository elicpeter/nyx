import { useState, useCallback, useMemo, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useFindingsURLState } from '../hooks/useFindingsURLState';
import { useDebounce } from '../hooks/useDebounce';
import { useFindings, useFindingFilters } from '../api/queries/findings';
import { useBulkTriage, useAddSuppression } from '../api/mutations/triage';
import { Pagination } from '../components/ui/Pagination';
import { truncPath } from '../utils/truncPath';
import type { FindingView, FilterValues } from '../api/types';

// ── Helpers ─────────────────────────────────────────────────────────────────

function formatTriageState(state: string): string {
  return (state || 'open').replace(/_/g, ' ');
}

// ── Filter Bar ──────────────────────────────────────────────────────────────

interface FilterSelectProps {
  id: string;
  label: string;
  values: string[] | undefined;
  current: string;
  onChange: (value: string) => void;
}

function FilterSelect({
  id,
  label,
  values,
  current,
  onChange,
}: FilterSelectProps) {
  if (!values || values.length === 0) return null;
  return (
    <select id={id} value={current} onChange={(e) => onChange(e.target.value)}>
      <option value="">All {label}</option>
      {values.map((v) => (
        <option key={v} value={v}>
          {v}
        </option>
      ))}
    </select>
  );
}

// ── Bulk Action Bar ─────────────────────────────────────────────────────────

interface BulkBarProps {
  selectedCount: number;
  onBulkTriage: (state: string) => void;
  onSuppressByPattern: () => void;
}

function BulkActionBar({
  selectedCount,
  onBulkTriage,
  onSuppressByPattern,
}: BulkBarProps) {
  return (
    <div className={`bulk-action-bar${selectedCount > 0 ? ' visible' : ''}`}>
      <span className="bulk-count">{selectedCount} selected</span>
      <button
        className="btn btn-sm btn-bulk-triage"
        onClick={() => onBulkTriage('suppressed')}
      >
        Suppress
      </button>
      <button
        className="btn btn-sm btn-bulk-triage"
        onClick={() => onBulkTriage('false_positive')}
      >
        Mark FP
      </button>
      <button
        className="btn btn-sm btn-bulk-triage"
        onClick={() => onBulkTriage('accepted_risk')}
      >
        Accept Risk
      </button>
      <button
        className="btn btn-sm btn-bulk-triage"
        onClick={() => onBulkTriage('investigating')}
      >
        Investigating
      </button>
      <button className="btn btn-sm" onClick={onSuppressByPattern}>
        Suppress by Pattern
      </button>
    </div>
  );
}

// ── Suppress Modal ──────────────────────────────────────────────────────────

interface SuppressModalProps {
  rules: string[];
  files: string[];
  onSuppress: (by: string, value: string, note: string) => void;
  onClose: () => void;
}

function SuppressModal({
  rules,
  files,
  onSuppress,
  onClose,
}: SuppressModalProps) {
  const [note, setNote] = useState('');

  return (
    <div
      className="suppress-modal-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="suppress-modal">
        <h3>Suppress by Pattern</h3>
        <div className="suppress-options">
          {rules.map((r) => (
            <button
              key={`rule-${r}`}
              className="btn btn-sm suppress-opt"
              onClick={() => onSuppress('rule', r, note)}
            >
              By rule: {r}
            </button>
          ))}
          {files.map((f) => (
            <button
              key={`file-${f}`}
              className="btn btn-sm suppress-opt"
              onClick={() => onSuppress('file', f, note)}
            >
              By file: {truncPath(f, 40)}
            </button>
          ))}
        </div>
        <textarea
          placeholder="Note (optional)..."
          rows={2}
          style={{ width: '100%', marginTop: 'var(--space-3)' }}
          value={note}
          onChange={(e) => setNote(e.target.value)}
        />
        <div
          style={{
            display: 'flex',
            gap: 'var(--space-2)',
            marginTop: 'var(--space-3)',
          }}
        >
          <button className="btn btn-sm" onClick={onClose}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Sortable Header ─────────────────────────────────────────────────────────

interface SortableThProps {
  column: string;
  label: string;
  currentSort: string;
  currentDir: string;
  onSort: (col: string, dir: string) => void;
}

function SortableTh({
  column,
  label,
  currentSort,
  currentDir,
  onSort,
}: SortableThProps) {
  const isActive = currentSort === column;
  const arrow = isActive ? (currentDir === 'desc' ? '\u2193' : '\u2191') : '';

  const handleClick = () => {
    const newDir =
      currentSort === column && currentDir === 'asc' ? 'desc' : 'asc';
    onSort(column, newDir);
  };

  return (
    <th
      className={`sortable${isActive ? ' active' : ''}`}
      onClick={handleClick}
    >
      {label}
      {arrow && <span className="sort-arrow">{arrow}</span>}
    </th>
  );
}

// ── Main Component ──────────────────────────────────────────────────────────

export function FindingsPage() {
  const navigate = useNavigate();
  const { state, updateState, resetFilters, hasActiveFilters } =
    useFindingsURLState();

  // Local search input state (debounced before pushing to URL)
  const [searchInput, setSearchInput] = useState(state.search);
  const debouncedSearch = useDebounce(searchInput, 300);

  // Sync debounced search to URL state
  useEffect(() => {
    if (debouncedSearch !== state.search) {
      updateState({ search: debouncedSearch });
    }
  }, [debouncedSearch]); // eslint-disable-line react-hooks/exhaustive-deps

  // Sync URL search back to local input when navigating
  useEffect(() => {
    setSearchInput(state.search);
  }, [state.search]);

  // Build query params for the API
  const queryParams = useMemo(
    () => ({
      page: Number(state.page) || 1,
      per_page: Number(state.per_page) || 50,
      sort_by: state.sort_by || undefined,
      sort_dir: state.sort_dir !== 'asc' ? state.sort_dir : undefined,
      severity: state.severity || undefined,
      category: state.category || undefined,
      confidence: state.confidence || undefined,
      language: state.language || undefined,
      rule_id: state.rule_id || undefined,
      status: state.status || undefined,
      search: state.search || undefined,
    }),
    [state],
  );

  const { data, isLoading, isError, error } = useFindings(queryParams);
  const { data: filters } = useFindingFilters();

  // Selection state
  const [selected, setSelected] = useState<Set<number>>(new Set());

  // Clear selection when data changes
  useEffect(() => {
    setSelected(new Set());
  }, [data]);

  const bulkTriage = useBulkTriage();
  const addSuppression = useAddSuppression();

  // Suppress modal
  const [suppressModalOpen, setSuppressModalOpen] = useState(false);

  // ── Selection handlers ──

  const toggleRow = useCallback((index: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }, []);

  const toggleSelectAll = useCallback(
    (checked: boolean) => {
      if (!data) return;
      if (checked) {
        setSelected(new Set(data.findings.map((f) => f.index)));
      } else {
        setSelected(new Set());
      }
    },
    [data],
  );

  const allSelected =
    data != null &&
    data.findings.length > 0 &&
    data.findings.every((f) => selected.has(f.index));

  // ── Bulk action handlers ──

  const getSelectedFingerprints = useCallback((): string[] => {
    if (!data) return [];
    return data.findings
      .filter((f) => selected.has(f.index))
      .map((f) => f.fingerprint);
  }, [data, selected]);

  const handleBulkTriage = useCallback(
    (triageState: string) => {
      const fingerprints = getSelectedFingerprints();
      if (fingerprints.length === 0) return;
      bulkTriage.mutate(
        { fingerprints, state: triageState, note: '' },
        { onSuccess: () => setSelected(new Set()) },
      );
    },
    [getSelectedFingerprints, bulkTriage],
  );

  const handleSuppressByPattern = useCallback(() => {
    if (selected.size === 0 || !data) return;
    setSuppressModalOpen(true);
  }, [selected.size, data]);

  const suppressPatternRules = useMemo(() => {
    if (!data) return [];
    const selectedFindings = data.findings.filter((f) => selected.has(f.index));
    return [...new Set(selectedFindings.map((f) => f.rule_id))];
  }, [data, selected]);

  const suppressPatternFiles = useMemo(() => {
    if (!data) return [];
    const selectedFindings = data.findings.filter((f) => selected.has(f.index));
    return [...new Set(selectedFindings.map((f) => f.path))];
  }, [data, selected]);

  const handleSuppress = useCallback(
    (by: string, value: string, note: string) => {
      addSuppression.mutate(
        { by, value, note },
        {
          onSuccess: () => {
            setSuppressModalOpen(false);
            setSelected(new Set());
          },
        },
      );
    },
    [addSuppression],
  );

  // ── Sort handler ──

  const handleSort = useCallback(
    (col: string, dir: string) => {
      updateState({ sort_by: col, sort_dir: dir });
    },
    [updateState],
  );

  // ── Filter handler ──

  const handleFilterChange = useCallback(
    (key: string, value: string) => {
      updateState({ [key]: value });
    },
    [updateState],
  );

  // ── Row click ──

  const handleRowClick = useCallback(
    (e: React.MouseEvent, finding: FindingView) => {
      if ((e.target as HTMLElement).tagName === 'INPUT') return;
      navigate(`/findings/${finding.index}`);
    },
    [navigate],
  );

  // ── Render ──

  if (isLoading) {
    return <div className="loading">Loading findings...</div>;
  }

  if (isError) {
    const msg = error instanceof Error ? error.message : 'Unknown error';
    if (msg.includes('404')) {
      return (
        <div className="empty-state">
          <h3>No scan results yet</h3>
          <p>Run a scan first to see findings.</p>
        </div>
      );
    }
    return (
      <div className="error-state">
        <h3>Error</h3>
        <p>{msg}</p>
      </div>
    );
  }

  if (!data) return null;

  const page = data.page;
  const totalPages = Math.ceil(data.total / data.per_page) || 1;

  return (
    <>
      <div className="page-header">
        <h2>Findings</h2>
        <span className="filter-count">
          {data.total} finding{data.total !== 1 ? 's' : ''}
          {hasActiveFilters ? ' (filtered)' : ''}
        </span>
      </div>

      {/* Filter bar */}
      <div className="filter-bar">
        <input
          type="text"
          placeholder="Search findings... (/)"
          className="search-input"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
        />
        <FilterSelect
          id="filter-severity"
          label="Severities"
          values={filters?.severities}
          current={state.severity}
          onChange={(v) => handleFilterChange('severity', v)}
        />
        <FilterSelect
          id="filter-confidence"
          label="Confidences"
          values={filters?.confidences}
          current={state.confidence}
          onChange={(v) => handleFilterChange('confidence', v)}
        />
        <FilterSelect
          id="filter-category"
          label="Categories"
          values={filters?.categories}
          current={state.category}
          onChange={(v) => handleFilterChange('category', v)}
        />
        <FilterSelect
          id="filter-language"
          label="Languages"
          values={filters?.languages}
          current={state.language}
          onChange={(v) => handleFilterChange('language', v)}
        />
        <FilterSelect
          id="filter-rule"
          label="Rules"
          values={filters?.rules}
          current={state.rule_id}
          onChange={(v) => handleFilterChange('rule_id', v)}
        />
        <FilterSelect
          id="filter-status"
          label="Statuses"
          values={filters?.statuses}
          current={state.status}
          onChange={(v) => handleFilterChange('status', v)}
        />
        {hasActiveFilters && (
          <button className="btn btn-sm btn-clear" onClick={resetFilters}>
            Clear All
          </button>
        )}
      </div>

      {/* Bulk action bar */}
      <BulkActionBar
        selectedCount={selected.size}
        onBulkTriage={handleBulkTriage}
        onSuppressByPattern={handleSuppressByPattern}
      />

      {/* Findings table */}
      {data.findings.length === 0 ? (
        <div className="empty-state">
          <h3>No findings</h3>
          <p>Run a scan to see results, or adjust your filters.</p>
        </div>
      ) : (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th className="col-checkbox">
                    <input
                      type="checkbox"
                      checked={allSelected}
                      onChange={(e) => toggleSelectAll(e.target.checked)}
                    />
                  </th>
                  <SortableTh
                    column="severity"
                    label="Severity"
                    currentSort={state.sort_by}
                    currentDir={state.sort_dir}
                    onSort={handleSort}
                  />
                  <SortableTh
                    column="confidence"
                    label="Confidence"
                    currentSort={state.sort_by}
                    currentDir={state.sort_dir}
                    onSort={handleSort}
                  />
                  <SortableTh
                    column="rule_id"
                    label="Rule"
                    currentSort={state.sort_by}
                    currentDir={state.sort_dir}
                    onSort={handleSort}
                  />
                  <SortableTh
                    column="category"
                    label="Category"
                    currentSort={state.sort_by}
                    currentDir={state.sort_dir}
                    onSort={handleSort}
                  />
                  <SortableTh
                    column="file"
                    label="File"
                    currentSort={state.sort_by}
                    currentDir={state.sort_dir}
                    onSort={handleSort}
                  />
                  <SortableTh
                    column="line"
                    label="Line"
                    currentSort={state.sort_by}
                    currentDir={state.sort_dir}
                    onSort={handleSort}
                  />
                  <SortableTh
                    column="language"
                    label="Language"
                    currentSort={state.sort_by}
                    currentDir={state.sort_dir}
                    onSort={handleSort}
                  />
                  <SortableTh
                    column="status"
                    label="Status"
                    currentSort={state.sort_by}
                    currentDir={state.sort_dir}
                    onSort={handleSort}
                  />
                </tr>
              </thead>
              <tbody>
                {data.findings.map((f) => (
                  <tr
                    key={f.index}
                    className={`clickable${selected.has(f.index) ? ' selected' : ''}`}
                    onClick={(e) => handleRowClick(e, f)}
                  >
                    <td className="col-checkbox">
                      <input
                        type="checkbox"
                        checked={selected.has(f.index)}
                        onChange={() => toggleRow(f.index)}
                      />
                    </td>
                    <td>
                      <span
                        className={`badge badge-${f.severity.toLowerCase()}`}
                      >
                        {f.severity}
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
                    <td title={f.message || ''}>{f.rule_id}</td>
                    <td>{f.category}</td>
                    <td className="cell-path" title={f.path}>
                      {truncPath(f.path)}
                    </td>
                    <td>{f.line}</td>
                    <td>{f.language || '-'}</td>
                    <td>
                      <span
                        className={`badge badge-triage-${f.triage_state || f.status}`}
                      >
                        {formatTriageState(f.triage_state || f.status)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <Pagination
            page={page}
            perPage={data.per_page}
            total={data.total}
            onPageChange={(p) => updateState({ page: String(p) })}
            onPerPageChange={(pp) => updateState({ per_page: String(pp) })}
          />
        </>
      )}

      {/* Suppress by pattern modal */}
      {suppressModalOpen && (
        <SuppressModal
          rules={suppressPatternRules}
          files={suppressPatternFiles}
          onSuppress={handleSuppress}
          onClose={() => setSuppressModalOpen(false)}
        />
      )}
    </>
  );
}
