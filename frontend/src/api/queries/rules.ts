import { useQuery } from '@tanstack/react-query';
import { apiGet } from '../client';
import type { RuleListItem, RuleDetailView } from '../types';

export function useRules() {
  return useQuery({
    queryKey: ['rules'],
    queryFn: ({ signal }) => apiGet<RuleListItem[]>('/rules', signal),
  });
}

export function useRuleDetail(id: string) {
  return useQuery({
    queryKey: ['rules', id],
    queryFn: ({ signal }) =>
      apiGet<RuleDetailView>(`/rules/${id}`, signal),
    enabled: !!id,
  });
}
