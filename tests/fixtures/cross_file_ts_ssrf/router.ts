import express from 'express';
import { fetchRemote } from './httpClient';

const router = express.Router();

/**
 * GET /proxy?url=<user-supplied>
 *
 * SOURCE: req.query.url is a taint source (user-controlled).
 * The tainted value is passed to fetchRemote() defined in httpClient.ts,
 * which makes an outbound HTTP request — a Server-Side Request Forgery sink.
 */
router.get('/proxy', async (req, res) => {
    const target = req.query.url as string; // taint source
    const data = await fetchRemote(target); // taint crosses file boundary → SSRF
    res.json({ data });
});

export default router;
