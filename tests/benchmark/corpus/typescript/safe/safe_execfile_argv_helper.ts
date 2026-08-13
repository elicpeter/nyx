// Safe counterpart to cmdi_interproc_promisify_helper.ts: the same interproc
// helper chain but the shell string is replaced by execFile with a fixed
// binary and an argv array, so the tainted destination is a non-injectable
// argument (no shell). Precision guard for CVE-2026-27728's patched form.
import express, { Request, Response } from 'express';
import { promisify } from 'util';
import { execFile } from 'child_process';

const execFileAsync = promisify(execFile);
const app = express();

class HostProbe {
    static async trace(destination: string): Promise<void> {
        const hostAddress: string = destination;
        await this.runTraceroute(hostAddress);
    }

    static async runTraceroute(destination: string): Promise<void> {
        const args: string[] = ['-m', '30', '-w', '3', destination];
        await execFileAsync('traceroute', args);
    }
}

app.post('/trace', (req: Request, res: Response) => {
    HostProbe.trace(req.body.destination);
    res.end();
});
