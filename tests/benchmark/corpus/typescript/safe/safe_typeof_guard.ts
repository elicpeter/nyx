import express, { Request, Response } from 'express';

const app = express();

app.post('/eval', (req: Request, res: Response) => {
    const raw: unknown = req.body.expr;
    if (typeof raw !== 'number') {
        res.status(400).send('need number');
        return;
    }
    const n: number = raw;
    const out = eval(String(n) + ' * 2');
    res.json({ out });
});
