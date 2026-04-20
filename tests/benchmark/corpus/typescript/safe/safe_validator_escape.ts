import express, { Request, Response } from 'express';
import validator from 'validator';

const app = express();

app.get('/greet', (req: Request, res: Response) => {
    const raw = req.query.name as string;
    const safe = validator.escape(raw);
    document.getElementById('out')!.innerHTML = safe;
});
