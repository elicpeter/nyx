// Interprocedural command injection: an HTTP-sourced value flows through a
// two-method static-class helper chain (entry -> helper) before reaching a
// promisify(exec) shell sink. Pins the interproc-summary + execAsync-alias
// recall path exercised by CVE-2026-27728 (OneUptime NetworkPathMonitor).
import express, { Request, Response } from 'express';
import { promisify } from 'util';
import { exec } from 'child_process';

const execAsync = promisify(exec);
const app = express();

class HostProbe {
    static async trace(destination: string): Promise<void> {
        const hostAddress: string = destination;
        await this.runTraceroute(hostAddress);
    }

    static async runTraceroute(destination: string): Promise<void> {
        const command: string = `traceroute -m 30 -w 3 ${destination}`;
        await execAsync(command);
    }
}

app.post('/trace', (req: Request, res: Response) => {
    HostProbe.trace(req.body.destination);
    res.end();
});
