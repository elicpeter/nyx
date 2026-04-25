import express, { Request, Response } from 'express';
const app = express();

app.get('/greet', (req: Request, res: Response) => {
    const name: string = req.query.name as string;
    document.getElementById('output')!.innerHTML = name;
});
