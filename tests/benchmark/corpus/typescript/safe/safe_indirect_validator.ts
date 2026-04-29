// Indirect-validator branch narrowing (precision regression guard).
// Pattern: `const err = validateXxx(input); if (err) throw …;` —
// the validator's input is treated as validated on the success
// branch, so the downstream sink does not refire.
//
// Pinned by tests/lib::indirect_validator_narrowing_marks_arg_validated.

import express, { Request, Response } from 'express';
import axios from 'axios';

declare function validateUrlSsrf(url: string): Promise<string | null>;

const app = express();

app.get('/proxy', async (req: Request, res: Response) => {
    const target = req.query.url as string;
    const ssrfError = await validateUrlSsrf(target);
    if (ssrfError) {
        throw new Error('blocked');
    }
    const response = await axios.get(target);
    res.send(response.data);
});
