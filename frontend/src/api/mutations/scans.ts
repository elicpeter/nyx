import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiPost, apiDelete } from '../client';
import type { ScanView } from '../types';

export type ScanMode = 'full' | 'ast' | 'cfg' | 'taint';
export type EngineProfile = 'fast' | 'balanced' | 'deep';

export interface StartScanBody {
  scan_root?: string;
  mode?: ScanMode;
  engine_profile?: EngineProfile;
}

export function useStartScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body?: StartScanBody) => apiPost<ScanView>('/scans', body),
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
