import { useQuery } from '@tanstack/react-query';
import { apiGet } from '../client';
import type { TreeEntry, SymbolEntry, ExplorerFinding } from '../types';

export function useExplorerTree(path?: string) {
  return useQuery({
    queryKey: ['explorer', 'tree', path ?? ''],
    queryFn: ({ signal }) => {
      const qs = path ? `?path=${encodeURIComponent(path)}` : '';
      return apiGet<TreeEntry[]>(`/explorer/tree${qs}`, signal);
    },
  });
}

export function useExplorerSymbols(path: string | null) {
  return useQuery({
    queryKey: ['explorer', 'symbols', path],
    queryFn: ({ signal }) =>
      apiGet<SymbolEntry[]>(
        `/explorer/symbols?path=${encodeURIComponent(path!)}`,
        signal,
      ),
    enabled: !!path,
  });
}

export function useExplorerFindings(path: string | null) {
  return useQuery({
    queryKey: ['explorer', 'findings', path],
    queryFn: ({ signal }) =>
      apiGet<ExplorerFinding[]>(
        `/explorer/findings?path=${encodeURIComponent(path!)}`,
        signal,
      ),
    enabled: !!path,
  });
}
