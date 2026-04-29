// Nyx CVE benchmark fixture.
//
// CVE:        GHSA-4x48-cgf9-q33f (no CVE id assigned)
// Project:    Novu (novuhq/novu)
// License:    MIT  (libs/application-generic — see LICENSE-MIT)
// Advisory:   https://github.com/novuhq/novu/security/advisories/GHSA-4x48-cgf9-q33f
// Vulnerable: 87d965eb88340ac7cd262dd52c8015acd092dc68^
//             libs/application-generic/src/usecases/conditions-filter/conditions-filter.usecase.ts:241-272
//
// `getWebhookResponse` POSTs to a user-configured webhook URL using raw
// `axios.post(child.webhookUrl, ...)` with no SSRF validation. The
// `child` filter part is sourced from a workflow filter config the
// caller controls, so the URL flows attacker-influenced into axios.
//
// Trims:
//   - HMAC config branch (verbatim kept; not on the flow path but
//     trivial scaffolding to keep the call shape).
//   - buildHmac, buildPayload, processFilter dispatcher, environment
//     repository lookups, decryptApiKey usage. Verbatim load-bearing
//     lines are the IWebhookFilterPart param shape and the
//     axios.post(child.webhookUrl, payload, config) call.

import express, { Request, Response } from 'express';
import axios from 'axios';

interface IWebhookFilterPart {
    webhookUrl?: string;
}

async function getWebhookResponse(
    child: IWebhookFilterPart,
): Promise<Record<string, unknown> | undefined> {
    if (!child.webhookUrl) return undefined;

    const payload = {};

    const config: { headers: Record<string, string> } = {
        headers: {},
    };

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
