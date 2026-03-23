// Context-sensitive analysis: same function called with tainted and safe args.
// With context sensitivity, only the tainted call site should produce a finding.
var child_process = require('child_process');
var express = require('express');
var app = express();

function run(cmd) {
    child_process.exec(cmd);
}

app.get('/a', function(req, res) {
    var userCmd = req.query.cmd;
    run(userCmd);          // TAINTED: req.query.cmd flows to exec via run()
    run("echo hello");     // SAFE: constant string, no real vulnerability
});
