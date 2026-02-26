import child_process from 'child_process';
import express from 'express';

var app = express();

function authenticate(req: any): boolean {
    return req.headers.authorization === 'Bearer secret';
}

app.get('/run', function(req: any, res: any) {
    var cmd = req.query.cmd;
    child_process.exec(cmd, function(err: any, stdout: any) {
        res.send(stdout);
    });
});

app.get('/run-authed', function(req: any, res: any) {
    if (!authenticate(req)) {
        return res.status(401).send('Unauthorized');
    }
    var cmd = req.query.cmd;
    child_process.exec(cmd, function(err: any, stdout: any) {
        res.send(stdout);
    });
});
