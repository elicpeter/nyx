// Nyx CVE benchmark fixture (patched counterpart).
//
// CVE:        GHSA-4x48-cgf9-q33f (no CVE id assigned)
// Project:    Novu (novuhq/novu)
// License:    MIT  (libs/application-generic — see LICENSE-MIT)
// Advisory:   https://github.com/novuhq/novu/security/advisories/GHSA-4x48-cgf9-q33f
// Patched:    87d965eb88340ac7cd262dd52c8015acd092dc68
//             libs/application-generic/src/usecases/conditions-filter/conditions-filter.usecase.ts:241-289
//
// The fix performs the existing call-site SSRF check `validateUrlSsrf`
// (already used by the HTTP-Request workflow step) before the webhook
// POST. The branch validates protocol/host and rejects when the URL
// hits localhost/private/cloud-metadata addresses; only on success
// does control reach axios.post.
//
// Patched-fix simplification: validateUrlSsrf is sourced from
// '../../utils/ssrf-url-validation.ts' upstream — inlined here as a
// no-op signature so the fixture parses without the larger novu
// monorepo. The branch shape (early throw on truthy ssrfError) is
// verbatim from the patch.

import express, { Request, Response } from 'express';
import axios from 'axios';

interface IWebhookFilterPart {
    webhookUrl?: string;
}

declare function validateUrlSsrf(url: string): Promise<string | null>;

async function getWebhookResponse(
    child: IWebhookFilterPart,
): Promise<Record<string, unknown> | undefined> {
    if (!child.webhookUrl) return undefined;

    const payload = {};
    const config: { headers: Record<string, string> } = { headers: {} };

    const ssrfError = await validateUrlSsrf(child.webhookUrl);

    if (ssrfError) {
        throw new Error(
            JSON.stringify({
                message: ssrfError,
                data: 'Webhook URL blocked by SSRF protection.',
            })
        );
    }

    return await axios.post(child.webhookUrl, payload, config).then((response) => {
        return response.data as Record<string, unknown>;
    });
}

const app = express();
app.use(express.json());

app.post('/conditions-filter/run', async (req: Request, res: Response) => {
    const child: IWebhookFilterPart = req.body.filter;
    const result = await getWebhookResponse(child);
    res.json({ result });
});
