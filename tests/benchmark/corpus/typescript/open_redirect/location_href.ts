import express, { Request, Response } from 'express';
const app = express();

app.get('/go', (req: Request, res: Response) => {
    const next = req.query.next as string;
    location.href = next;
});
