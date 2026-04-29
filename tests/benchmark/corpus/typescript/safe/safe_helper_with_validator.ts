// Helper-summary all_validated propagation (precision regression
// guard).  The helper performs an indirect-validator check on
// `child.webhookUrl` and throws on failure; callers passing tainted
// `child` should NOT see the helper's `param_to_sink` summary refire
// because the validator inside the helper proved the path safe.
//
// Pinned by tests/lib::helper_with_validator_does_not_propagate_to_caller_via_summary.

import express, { Request, Response } from 'express';
import axios from 'axios';

interface IWebhookFilterPart {
    webhookUrl?: string;
}

declare function validateUrlSsrf(url: string): Promise<string | null>;

async function getWebhookResponse(child: IWebhookFilterPart) {
    const ssrfError = await validateUrlSsrf(child.webhookUrl);
    if (ssrfError) {
        throw new Error('blocked');
    }
    return await axios.post(child.webhookUrl, {});
}

const app = express();
app.use(express.json());

app.post('/run', async (req: Request, res: Response) => {
    const child: IWebhookFilterPart = req.body.filter;
    const r = await getWebhookResponse(child);
    res.json({ r });
});
