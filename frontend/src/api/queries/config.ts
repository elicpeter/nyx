import { useQuery } from '@tanstack/react-query';
import { apiGet } from '../client';
import type { LabelEntryView, TerminatorView, ProfileView } from '../types';

export function useConfig() {
  return useQuery({
    queryKey: ['config'],
    queryFn: ({ signal }) => apiGet<unknown>('/config', signal),
  });
}

export function useSources() {
  return useQuery({
    queryKey: ['config', 'sources'],
    queryFn: ({ signal }) =>
      apiGet<LabelEntryView[]>('/config/sources', signal),
  });
}

export function useSinks() {
  return useQuery({
    queryKey: ['config', 'sinks'],
    queryFn: ({ signal }) =>
      apiGet<LabelEntryView[]>('/config/sinks', signal),
  });
}

export function useSanitizers() {
  return useQuery({
    queryKey: ['config', 'sanitizers'],
    queryFn: ({ signal }) =>
      apiGet<LabelEntryView[]>('/config/sanitizers', signal),
  });
}

export function useTerminators() {
  return useQuery({
    queryKey: ['config', 'terminators'],
    queryFn: ({ signal }) =>
      apiGet<TerminatorView[]>('/config/terminators', signal),
  });
}

export function useProfiles() {
  return useQuery({
    queryKey: ['config', 'profiles'],
    queryFn: ({ signal }) =>
      apiGet<ProfileView[]>('/config/profiles', signal),
  });
}
