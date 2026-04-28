import { useQuery } from '@tanstack/react-query';
import { apiGet } from '../client';
import type {
  FunctionInfo,
  CfgGraphView,
  SsaBodyView,
  TaintAnalysisView,
  AbstractInterpView,
  SymexView,
  CallGraphView,
  FuncSummaryView,
  PointerView,
  TypeFactsView,
  AuthAnalysisView,
} from '../types';

export function useDebugFunctions(file: string | null) {
  return useQuery({
    queryKey: ['debug', 'functions', file],
    queryFn: ({ signal }) =>
      apiGet<FunctionInfo[]>(
        `/debug/functions?file=${encodeURIComponent(file!)}`,
        signal,
      ),
    enabled: !!file,
  });
}

export function useDebugCfg(file: string | null, fn_name: string | null) {
  return useQuery({
    queryKey: ['debug', 'cfg', file, fn_name],
    queryFn: ({ signal }) =>
      apiGet<CfgGraphView>(
        `/debug/cfg?file=${encodeURIComponent(file!)}&function=${encodeURIComponent(fn_name!)}`,
        signal,
      ),
    enabled: !!file && !!fn_name,
  });
}

export function useDebugSsa(file: string | null, fn_name: string | null) {
  return useQuery({
    queryKey: ['debug', 'ssa', file, fn_name],
    queryFn: ({ signal }) =>
      apiGet<SsaBodyView>(
        `/debug/ssa?file=${encodeURIComponent(file!)}&function=${encodeURIComponent(fn_name!)}`,
        signal,
      ),
    enabled: !!file && !!fn_name,
  });
}

export function useDebugTaint(file: string | null, fn_name: string | null) {
  return useQuery({
    queryKey: ['debug', 'taint', file, fn_name],
    queryFn: ({ signal }) =>
      apiGet<TaintAnalysisView>(
        `/debug/taint?file=${encodeURIComponent(file!)}&function=${encodeURIComponent(fn_name!)}`,
        signal,
      ),
    enabled: !!file && !!fn_name,
  });
}

export function useDebugAbstractInterp(
  file: string | null,
  fn_name: string | null,
) {
  return useQuery({
    queryKey: ['debug', 'abstract-interp', file, fn_name],
    queryFn: ({ signal }) =>
      apiGet<AbstractInterpView>(
        `/debug/abstract-interp?file=${encodeURIComponent(file!)}&function=${encodeURIComponent(fn_name!)}`,
        signal,
      ),
    enabled: !!file && !!fn_name,
  });
}

export function useDebugSymex(file: string | null, fn_name: string | null) {
  return useQuery({
    queryKey: ['debug', 'symex', file, fn_name],
    queryFn: ({ signal }) =>
      apiGet<SymexView>(
        `/debug/symex?file=${encodeURIComponent(file!)}&function=${encodeURIComponent(fn_name!)}`,
        signal,
      ),
    enabled: !!file && !!fn_name,
  });
}

export function useDebugCallGraph(scope: string, file?: string | null) {
  const params = new URLSearchParams({ scope });
  if (file) params.set('file', file);
  return useQuery({
    queryKey: ['debug', 'call-graph', scope, file],
    queryFn: ({ signal }) =>
      apiGet<CallGraphView>(`/debug/call-graph?${params}`, signal),
  });
}

export function useDebugSummaries(
  file?: string | null,
  fn_name?: string | null,
) {
  const params = new URLSearchParams();
  if (file) params.set('file', file);
  if (fn_name) params.set('function', fn_name);
  return useQuery({
    queryKey: ['debug', 'summaries', file, fn_name],
    queryFn: ({ signal }) =>
      apiGet<FuncSummaryView[]>(`/debug/summaries?${params}`, signal),
  });
}

export function useDebugPointer(file: string | null, fn_name: string | null) {
  return useQuery({
    queryKey: ['debug', 'pointer', file, fn_name],
    queryFn: ({ signal }) =>
      apiGet<PointerView>(
        `/debug/pointer?file=${encodeURIComponent(file!)}&function=${encodeURIComponent(fn_name!)}`,
        signal,
      ),
    enabled: !!file && !!fn_name,
  });
}

export function useDebugTypeFacts(
  file: string | null,
  fn_name: string | null,
) {
  return useQuery({
    queryKey: ['debug', 'type-facts', file, fn_name],
    queryFn: ({ signal }) =>
      apiGet<TypeFactsView>(
        `/debug/type-facts?file=${encodeURIComponent(file!)}&function=${encodeURIComponent(fn_name!)}`,
        signal,
      ),
    enabled: !!file && !!fn_name,
  });
}

export function useDebugAuth(file: string | null) {
  return useQuery({
    queryKey: ['debug', 'auth', file],
    queryFn: ({ signal }) =>
      apiGet<AuthAnalysisView>(
        `/debug/auth?file=${encodeURIComponent(file!)}`,
        signal,
      ),
    enabled: !!file,
  });
}
