import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiPost, apiDelete } from '../client';
import type { LabelEntryView, TerminatorView, ProfileView } from '../types';

// --- Sources ---

export interface AddLabelBody {
  lang: string;
  matchers: string[];
  cap: string;
  case_sensitive?: boolean;
}

export function useAddSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AddLabelBody) =>
      apiPost<LabelEntryView>('/config/sources', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config', 'sources'] });
    },
  });
}

export function useDeleteSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AddLabelBody) => apiDelete<void>('/config/sources'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config', 'sources'] });
    },
  });
}

// --- Sinks ---

export function useAddSink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AddLabelBody) =>
      apiPost<LabelEntryView>('/config/sinks', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config', 'sinks'] });
    },
  });
}

export function useDeleteSink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AddLabelBody) => apiDelete<void>('/config/sinks'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config', 'sinks'] });
    },
  });
}

// --- Sanitizers ---

export function useAddSanitizer() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AddLabelBody) =>
      apiPost<LabelEntryView>('/config/sanitizers', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config', 'sanitizers'] });
    },
  });
}

export function useDeleteSanitizer() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AddLabelBody) => apiDelete<void>('/config/sanitizers'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config', 'sanitizers'] });
    },
  });
}

// --- Terminators ---

export interface AddTerminatorBody {
  lang: string;
  name: string;
}

export function useAddTerminator() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AddTerminatorBody) =>
      apiPost<TerminatorView>('/config/terminators', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config', 'terminators'] });
    },
  });
}

export function useDeleteTerminator() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AddTerminatorBody) =>
      apiDelete<void>('/config/terminators'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config', 'terminators'] });
    },
  });
}

// --- Profiles ---

export function useAddProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { name: string; settings: Record<string, unknown> }) =>
      apiPost<ProfileView>('/config/profiles', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config', 'profiles'] });
    },
  });
}

export function useDeleteProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) =>
      apiDelete<void>(`/config/profiles/${encodeURIComponent(name)}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config', 'profiles'] });
    },
  });
}

export function useActivateProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) =>
      apiPost<void>(`/config/profiles/${encodeURIComponent(name)}/activate`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config'] });
      qc.invalidateQueries({ queryKey: ['config', 'profiles'] });
    },
  });
}

// --- Triage Sync ---

export function useToggleTriageSync() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { enabled: boolean }) =>
      apiPost<void>('/config/triage-sync', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['triage', 'sync-status'] });
    },
  });
}
