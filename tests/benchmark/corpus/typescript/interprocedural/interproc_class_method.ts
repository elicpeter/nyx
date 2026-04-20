import express, { Request, Response } from 'express';
import { exec } from 'child_process';

class Runner {
    prefix: string;
    constructor(prefix: string) { this.prefix = prefix; }
    build(user: string): string {
        return `${this.prefix} ${user}`;
    }
}

const app = express();
app.get('/scan', (req: Request, res: Response) => {
    const target = req.query.target as string;
    const runner = new Runner('/usr/bin/scan');
    exec(runner.build(target));
});
