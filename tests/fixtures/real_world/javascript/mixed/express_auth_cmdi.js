var express = require('express');
var child_process = require('child_process');
var app = express();

function isAdmin(req) {
    return req.headers['x-admin'] === 'true';
}

// Missing auth check before dangerous operation
app.get('/deploy', function(req, res) {
    var branch = req.query.branch;
    child_process.exec('git checkout ' + branch, function(err, stdout) {
        res.send(stdout);
    });
});

// Has auth check but taint still flows
app.get('/deploy-safe', function(req, res) {
    if (!isAdmin(req)) {
        return res.status(403).send('Forbidden');
    }
    var branch = req.query.branch;
    child_process.exec('git checkout ' + branch, function(err, stdout) {
        res.send(stdout);
    });
});
