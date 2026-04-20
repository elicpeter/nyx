import express, { Request, Response } from 'express';
import { promisify } from 'util';
import { exec as rawExec } from 'child_process';

const execAsync = promisify(rawExec);
const app = express();

app.get('/diag', async (req: Request, res: Response) => {
    const host = req.query.host as string;
    const { stdout } = await execAsync(`ping -c 1 ${host}`);
    res.send(stdout);
});
