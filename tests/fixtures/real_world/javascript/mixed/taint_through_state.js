var express = require('express');
var fs = require('fs');
var child_process = require('child_process');
var app = express();

app.post('/upload', function(req, res) {
    var filename = req.body.name;
    var content = req.body.data;
    var fd = fs.openSync('/tmp/' + filename, 'w');
    fs.writeSync(fd, content);
    // fd leaks on early return
    if (content.length > 1000000) {
        return res.status(413).send('Too large');
    }
    fs.closeSync(fd);
    res.send('OK');
});

app.get('/run', function(req, res) {
    var cmd = req.query.cmd;
    child_process.exec(cmd, function(err, stdout) {
        res.send(stdout);
    });
});
