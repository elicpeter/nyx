import express, { Request, Response } from 'express';
const app = express();

function identity<T>(x: T): T {
    return x;
}

app.get('/echo', (req: Request, res: Response) => {
    const raw = req.query.msg as string;
    const passthrough = identity<string>(raw);
    document.body.innerHTML = passthrough;
});
