import express, { Request, Response } from 'express';
import { exec } from 'child_process';

type Action =
    | { kind: 'ping'; target: string }
    | { kind: 'status' };

const app = express();

app.post('/action', (req: Request, res: Response) => {
    const a = req.body as Action;
    if (a.kind === 'ping') {
        exec(`ping -c 1 ${a.target}`);
    } else {
        res.send('ok');
    }
});
