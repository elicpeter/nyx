import express, { Request, Response } from 'express';
import DOMPurify from 'dompurify';

const app = express();

app.get('/bio', (req: Request, res: Response) => {
    const raw = req.query.bio as string;
    const clean = DOMPurify.sanitize(raw);
    document.getElementById('bio')!.innerHTML = clean;
});
