import express, { Request, Response } from 'express';
import { exec } from 'child_process';

interface Runner {
    run(arg: string): void;
}

class ShellRunner implements Runner {
    run(arg: string): void {
        exec(arg);
    }
}

const impl: Runner = new ShellRunner();

const app = express();
app.post('/run', (req: Request, res: Response) => {
    const cmd = req.body.cmd as string;
    impl.run(cmd);
});
