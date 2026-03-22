import express from 'express';
var app = express();

app.get('/api', function(req: any, res: any) {
    var host = req.query.host;
    fetch('http://' + host + '/data');
});
