import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiPost, apiDelete } from '../client';
import type { ScanView } from '../types';

export function useStartScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body?: { scan_root?: string }) =>
      apiPost<ScanView>('/scans', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] });
    },
  });
}

export function useDeleteScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiDelete<void>(`/scans/${encodeURIComponent(id)}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] });
      qc.invalidateQueries({ queryKey: ['overview'] });
    },
  });
}
