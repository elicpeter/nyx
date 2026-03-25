import { useQuery } from '@tanstack/react-query';
import { apiGet } from '../client';
import type {
  ScanView,
  PaginatedFindings,
  ScanLogEntry,
  ScanMetricsSnapshot,
  CompareResponse,
} from '../types';

export function useScans() {
  return useQuery({
    queryKey: ['scans'],
    queryFn: ({ signal }) => apiGet<ScanView[]>('/scans', signal),
  });
}

export function useScan(id: string) {
  return useQuery({
    queryKey: ['scans', id],
    queryFn: ({ signal }) => apiGet<ScanView>(`/scans/${id}`, signal),
    enabled: !!id,
  });
}

export interface ScanFindingsParams {
  page?: number;
  per_page?: number;
  severity?: string;
  category?: string;
  search?: string;
}

function buildQuery(
  params: Record<string, string | number | boolean | undefined | null>,
): string {
  const entries = Object.entries(params).filter(
    ([, v]) => v !== undefined && v !== null && v !== '',
  );
  if (entries.length === 0) return '';
  const qs = new URLSearchParams(
    entries.map(([k, v]) => [k, String(v)]),
  ).toString();
  return `?${qs}`;
}

export function useScanFindings(id: string, params: ScanFindingsParams = {}) {
  return useQuery({
    queryKey: ['scans', id, 'findings', params],
    queryFn: ({ signal }) =>
      apiGet<PaginatedFindings>(
        `/scans/${id}/findings${buildQuery({ ...params })}`,
        signal,
      ),
    enabled: !!id,
  });
}

export function useScanLogs(id: string, level?: string) {
  return useQuery({
    queryKey: ['scans', id, 'logs', level],
    queryFn: ({ signal }) => {
      const qs = level ? `?level=${encodeURIComponent(level)}` : '';
      return apiGet<ScanLogEntry[]>(`/scans/${id}/logs${qs}`, signal);
    },
    enabled: !!id,
  });
}

export function useScanMetrics(id: string) {
  return useQuery({
    queryKey: ['scans', id, 'metrics'],
    queryFn: ({ signal }) =>
      apiGet<ScanMetricsSnapshot>(`/scans/${id}/metrics`, signal),
    enabled: !!id,
  });
}

export function useScanCompare(left: string, right: string) {
  return useQuery({
    queryKey: ['scans', 'compare', left, right],
    queryFn: ({ signal }) =>
      apiGet<CompareResponse>(
        `/scans/compare?left=${encodeURIComponent(left)}&right=${encodeURIComponent(right)}`,
        signal,
      ),
    enabled: !!left && !!right,
  });
}
