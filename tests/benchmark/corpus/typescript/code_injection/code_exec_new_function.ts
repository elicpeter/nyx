import express, { Request, Response } from 'express';
const app = express();

app.post('/run', (req: Request, res: Response) => {
    const body: string = req.body.code;
    const fn = new Function('ctx', body);
    res.json({ out: fn({}) });
});
