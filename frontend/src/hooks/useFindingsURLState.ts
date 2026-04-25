import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';

export interface FindingsURLState {
  page: string;
  per_page: string;
  sort_by: string;
  sort_dir: string;
  severity: string;
  category: string;
  confidence: string;
  language: string;
  rule_id: string;
  status: string;
  search: string;
}

const FINDINGS_DEFAULTS: FindingsURLState = {
  page: '1',
  per_page: '50',
  sort_by: '',
  sort_dir: 'asc',
  severity: '',
  category: '',
  confidence: '',
  language: '',
  rule_id: '',
  status: '',
  search: '',
};

const FILTER_KEYS: ReadonlySet<string> = new Set([
  'severity',
  'category',
  'confidence',
  'language',
  'rule_id',
  'status',
  'search',
]);

/** Keys that do NOT trigger a page reset when changed. */
const NON_RESET_KEYS: ReadonlySet<string> = new Set([
  'page',
  'sort_by',
  'sort_dir',
  'per_page',
]);

export function useFindingsURLState() {
  const [searchParams, setSearchParams] = useSearchParams();

  const state: FindingsURLState = useMemo(() => {
    const s = {} as FindingsURLState;
    for (const key of Object.keys(
      FINDINGS_DEFAULTS,
    ) as (keyof FindingsURLState)[]) {
      s[key] = searchParams.get(key) || FINDINGS_DEFAULTS[key];
    }
    return s;
  }, [searchParams]);

  const updateState = useCallback(
    (updates: Partial<FindingsURLState>) => {
      setSearchParams((prev) => {
        const current = {} as FindingsURLState;
        for (const key of Object.keys(
          FINDINGS_DEFAULTS,
        ) as (keyof FindingsURLState)[]) {
          current[key] = prev.get(key) || FINDINGS_DEFAULTS[key];
        }

        const merged = { ...current, ...updates };

        // Reset page to 1 when any filter/non-pagination field changes
        const hasFilterChange = Object.keys(updates).some(
          (k) => !NON_RESET_KEYS.has(k),
        );
        if (hasFilterChange) {
          merged.page = '1';
        }

        // Build new search params, omitting defaults
        const next = new URLSearchParams();
        for (const [k, v] of Object.entries(merged)) {
          if (v && v !== FINDINGS_DEFAULTS[k as keyof FindingsURLState]) {
            next.set(k, v);
          }
        }
        return next;
      });
    },
    [setSearchParams],
  );

  const resetFilters = useCallback(() => {
    setSearchParams((prev) => {
      const next = new URLSearchParams();
      // Preserve per_page but reset everything else
      const perPage = prev.get('per_page');
      if (perPage && perPage !== FINDINGS_DEFAULTS.per_page) {
        next.set('per_page', perPage);
      }
      return next;
    });
  }, [setSearchParams]);

  const hasActiveFilters = useMemo(
    () =>
      Array.from(FILTER_KEYS).some(
        (k) => state[k as keyof FindingsURLState] !== '',
      ),
    [state],
  );

  return { state, updateState, resetFilters, hasActiveFilters };
}
