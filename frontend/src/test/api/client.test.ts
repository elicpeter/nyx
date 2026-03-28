import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiPost } from '../../api/client';

describe('api client CSRF handling', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('fetches the session token and sends it on mutating requests', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ csrf_token: 'token-123' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ status: 'ok' }),
      });

    vi.stubGlobal('fetch', fetchMock);

    const result = await apiPost<{ status: string }>('/triage/export');

    expect(result.status).toBe('ok');
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/session');
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      '/api/triage/export',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'X-Nyx-CSRF': 'token-123',
        }),
      }),
    );
  });
});
