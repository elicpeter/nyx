import express, { Request, Response } from 'express';
import { exec } from 'child_process';

const app = express();

app.post('/archive', (req: Request, res: Response) => {
    const target: string = req.body.target;
    exec(`tar -czf /tmp/out.tgz ${target}`);
});
