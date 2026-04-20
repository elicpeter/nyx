import express, { Request, Response } from 'express';
const app = express();

app.get('/raw', (req: Request, res: Response) => {
    const raw = req.query.html;
    const coerced = (raw as any) as string;
    document.body.innerHTML = coerced;
});
