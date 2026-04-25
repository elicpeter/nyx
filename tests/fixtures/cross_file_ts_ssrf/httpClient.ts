import fetch from 'node-fetch';

/**
 * SINK: fetch() with a user-controlled URL.
 *
 * Called from router.ts with an unsanitised query parameter.  No allowlist
 * or URL validation is performed before making the outbound request.
 */
export async function fetchRemote(url: string): Promise<string> {
    const response = await fetch(url); // SSRF sink: url is user-controlled
    return response.text();
}
