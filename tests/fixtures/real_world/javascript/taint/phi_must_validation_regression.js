// B-2 regression: phi validated_must promotion must use must-analysis.
// When only one branch validates the tainted variable, the phi merge
// must NOT suppress the finding — validated_may is not enough for must.
var child_process = require('child_process');
var express = require('express');
var app = express();

app.get('/run', function(req, res) {
    var cmd = req.query.cmd;
    if (Math.random() > 0.5) {
        cmd = parseInt(cmd, 10).toString();  // validates on this path
    }
    // cmd reaches sink — only one branch validated, must still fire
    child_process.exec(cmd);
});
