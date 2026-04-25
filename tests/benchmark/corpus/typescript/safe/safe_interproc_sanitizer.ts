import express, { Request, Response } from 'express';
import DOMPurify from 'dompurify';

const app = express();

function cleanHtml(raw: string): string {
    return DOMPurify.sanitize(raw);
}

app.get('/bio', (req: Request, res: Response) => {
    const raw = req.query.bio as string;
    document.getElementById('bio')!.innerHTML = cleanHtml(raw);
});
