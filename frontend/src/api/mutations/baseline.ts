import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiDelete, apiPost } from '../client';

export function usePinBaseline() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) =>
      apiPost<void>('/overview/baseline', { scan_id: scanId }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['overview'] });
    },
  });
}

export function useUnpinBaseline() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => apiDelete<void>('/overview/baseline'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['overview'] });
    },
  });
}
