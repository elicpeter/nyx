import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiPost, apiDelete } from '../client';

export interface BulkTriageBody {
  fingerprints: string[];
  state: string;
  note?: string;
}

export interface UpdateFindingTriageBody {
  state: string;
  note?: string;
}

export interface AddSuppressionBody {
  by: string;
  value: string;
  note?: string;
}

export function useBulkTriage() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: BulkTriageBody) => apiPost<void>('/triage', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings'] });
      qc.invalidateQueries({ queryKey: ['triage'] });
      qc.invalidateQueries({ queryKey: ['overview'] });
    },
  });
}

export function useUpdateFindingTriage() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      index,
      ...body
    }: UpdateFindingTriageBody & { index: number | string }) =>
      apiPost<void>(`/findings/${index}/triage`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings'] });
      qc.invalidateQueries({ queryKey: ['triage'] });
    },
  });
}

export function useAddSuppression() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AddSuppressionBody) =>
      apiPost<void>('/triage/suppress', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['triage'] });
      qc.invalidateQueries({ queryKey: ['findings'] });
      qc.invalidateQueries({ queryKey: ['triage', 'suppress'] });
    },
  });
}

export function useDeleteSuppression() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiDelete<void>(`/triage/suppress?id=${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['triage', 'suppress'] });
    },
  });
}

export function useTriageExport() {
  return useMutation({
    mutationFn: () => apiPost<unknown>('/triage/export'),
  });
}

export function useTriageImport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => apiPost<unknown>('/triage/import'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['triage'] });
      qc.invalidateQueries({ queryKey: ['findings'] });
    },
  });
}
