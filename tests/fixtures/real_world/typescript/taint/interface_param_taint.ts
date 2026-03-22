import child_process from 'child_process';
import express from 'express';
var app = express();

app.get('/run', function(req: any, res: any) {
    var cmd = req.query.cmd;
    child_process.exec(cmd, function(err: any, stdout: any) {
        res.send(stdout);
    });
});
