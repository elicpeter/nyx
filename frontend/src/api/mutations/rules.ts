import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiPost } from '../client';

export function useToggleRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiPost<void>(`/rules/${encodeURIComponent(id)}/toggle`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rules'] });
    },
  });
}

export function useCloneRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { rule_id: string }) =>
      apiPost<void>('/rules/clone', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rules'] });
    },
  });
}
