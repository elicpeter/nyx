import child_process from 'child_process';
import express from 'express';

interface QueryParams {
    host: string;
}

var app = express();

app.get('/ping', function(req: any, res: any) {
    var host = req.query.host;
    child_process.exec('ping -c 1 ' + host, function(err: any, stdout: any) {
        res.send(stdout);
    });
});

app.get('/safe-ping', function(req: any, res: any) {
    var host = req.query.host;
    var sanitized = host.replace(/[^a-zA-Z0-9.]/g, '');
    child_process.exec('ping -c 1 ' + sanitized, function(err: any, stdout: any) {
        res.send(stdout);
    });
});
