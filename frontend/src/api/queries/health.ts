import { useQuery } from '@tanstack/react-query';
import { apiGet } from '../client';
import type { HealthResponse } from '../types';

export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: ({ signal }) => apiGet<HealthResponse>('/health', signal),
    staleTime: 60_000,
  });
}
