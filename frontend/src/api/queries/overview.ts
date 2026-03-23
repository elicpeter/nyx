import { useQuery } from '@tanstack/react-query';
import { apiGet } from '../client';
import type { OverviewResponse, TrendPoint } from '../types';

export function useOverview() {
  return useQuery({
    queryKey: ['overview'],
    queryFn: ({ signal }) => apiGet<OverviewResponse>('/overview', signal),
  });
}

export function useOverviewTrends() {
  return useQuery({
    queryKey: ['overview', 'trends'],
    queryFn: ({ signal }) => apiGet<TrendPoint[]>('/overview/trends', signal),
  });
}
