import { useQuery } from '@tanstack/react-query';
import { apiGet } from '../client';
import type {
  PaginatedTriage,
  PaginatedAudit,
  SuppressionRule,
  SyncStatus,
} from '../types';

export interface TriageParams {
  state?: string;
  page?: number;
  per_page?: number;
}

export interface TriageAuditParams {
  fingerprint?: string;
  page?: number;
  per_page?: number;
}

function buildQuery(params: Record<string, string | number | boolean | undefined | null>): string {
  const entries = Object.entries(params).filter(
    ([, v]) => v !== undefined && v !== null && v !== '',
  );
  if (entries.length === 0) return '';
  const qs = new URLSearchParams(
    entries.map(([k, v]) => [k, String(v)]),
  ).toString();
  return `?${qs}`;
}

export function useTriage(params: TriageParams = {}) {
  return useQuery({
    queryKey: ['triage', params],
    queryFn: ({ signal }) =>
      apiGet<PaginatedTriage>(`/triage${buildQuery({ ...params })}`, signal),
  });
}

export function useTriageAudit(params: TriageAuditParams = {}) {
  return useQuery({
    queryKey: ['triage', 'audit', params],
    queryFn: ({ signal }) =>
      apiGet<PaginatedAudit>(`/triage/audit${buildQuery({ ...params })}`, signal),
  });
}

export function useSuppressions() {
  return useQuery({
    queryKey: ['triage', 'suppress'],
    queryFn: ({ signal }) =>
      apiGet<{ rules: SuppressionRule[] }>('/triage/suppress', signal),
  });
}

export function useSyncStatus() {
  return useQuery({
    queryKey: ['triage', 'sync-status'],
    queryFn: ({ signal }) =>
      apiGet<SyncStatus>('/triage/sync-status', signal),
  });
}
