const BASE = '/api';
const CSRF_HEADER = 'X-Nyx-CSRF';
let csrfTokenPromise: Promise<string> | null = null;

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function getCsrfToken(): Promise<string> {
  if (!csrfTokenPromise) {
    csrfTokenPromise = fetch(`${BASE}/session`)
      .then(async (res) => {
        if (!res.ok) {
          throw new ApiError(
            res.status,
            await res.text().catch(() => res.statusText),
          );
        }

        const text = await res.text();
        const payload = text
          ? (JSON.parse(text) as { csrf_token?: unknown })
          : {};
        if (
          typeof payload.csrf_token !== 'string' ||
          payload.csrf_token.length === 0
        ) {
          throw new ApiError(500, 'Missing CSRF token');
        }

        return payload.csrf_token;
      })
      .catch((error) => {
        csrfTokenPromise = null;
        throw error;
      });
  }

  return csrfTokenPromise;
}

function isMutatingMethod(method?: string): boolean {
  const upper = (method || 'GET').toUpperCase();
  return (
    upper === 'POST' ||
    upper === 'PUT' ||
    upper === 'PATCH' ||
    upper === 'DELETE'
  );
}

async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const { headers: rawHeaders, ...rest } = opts;
  const url = `${BASE}${path}`;
  const headers: Record<string, string> = {
    ...(rawHeaders as Record<string, string>),
  };
  if (isMutatingMethod(rest.method)) {
    headers[CSRF_HEADER] = await getCsrfToken();
  }
  if (opts.body) {
    headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(url, {
    ...rest,
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
