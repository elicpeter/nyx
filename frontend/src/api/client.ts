const BASE = '/api';

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const url = `${BASE}${path}`;
  const headers: Record<string, string> = {
    ...(opts.headers as Record<string, string>),
  };
  if (opts.body) {
    headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(url, {
    ...opts,
    headers,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new ApiError(res.status, text);
  }

  // Handle empty responses
  const text = await res.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

export function apiGet<T>(path: string, signal?: AbortSignal): Promise<T> {
  return request<T>(path, { signal });
}

export function apiPost<T>(
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    body: body != null ? JSON.stringify(body) : undefined,
    signal,
  });
}

export function apiDelete<T>(path: string, signal?: AbortSignal): Promise<T> {
  return request<T>(path, { method: 'DELETE', signal });
}
