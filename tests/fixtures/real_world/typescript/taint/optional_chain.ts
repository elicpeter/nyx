import child_process from 'child_process';
import express from 'express';

interface Config {
    commands?: {
        deploy?: string;
    };
}

var app = express();

app.get('/deploy', function(req: any, res: any) {
    var userOverride = req.query.cmd;
    var config: Config = { commands: { deploy: 'echo noop' } };
    var cmd = userOverride ?? config.commands?.deploy ?? 'echo noop';
    child_process.exec(cmd, function(err: any, stdout: any) {
        res.send(stdout);
    });
});
