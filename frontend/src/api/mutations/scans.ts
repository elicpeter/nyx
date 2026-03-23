import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiPost } from '../client';
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
