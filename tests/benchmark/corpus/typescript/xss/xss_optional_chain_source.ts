import express, { Request, Response } from 'express';
const app = express();

app.get('/maybe', (req: Request, res: Response) => {
    const name = req?.query?.name as string | undefined;
    if (name) {
        document.getElementById('out')!.innerHTML = name;
    }
});
