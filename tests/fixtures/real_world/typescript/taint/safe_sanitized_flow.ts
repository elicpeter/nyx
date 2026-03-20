import express from 'express';
import DOMPurify from 'dompurify';

const app = express();

app.get('/greet', (req: express.Request, res: express.Response) => {
    const name = req.query.name as string;
    const clean = DOMPurify.sanitize(name);
    const el = document.getElementById('output');
    if (el) {
        el.innerHTML = clean;
    }
});
