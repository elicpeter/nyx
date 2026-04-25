import express, { Request, Response } from 'express';
import { exec } from 'child_process';

function log(_target: unknown, _key: string, desc: PropertyDescriptor): PropertyDescriptor {
    const orig = desc.value;
    desc.value = function (this: unknown, ...args: unknown[]) {
        return orig.apply(this, args);
    };
    return desc;
}

class Service {
    @log
    run(cmd: string): void {
        exec(cmd);
    }
}

const svc = new Service();
const app = express();
app.post('/x', (req: Request, res: Response) => {
    svc.run(req.body.cmd as string);
});
