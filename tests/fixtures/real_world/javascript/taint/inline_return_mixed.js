// C-1: mixed return paths — one tainted (param passthrough), one constant.
// Internal source must not leak; param passthrough path must still flag.
var child_process = require('child_process');
var express = require('express');
var app = express();

function maybe_taint(input, flag) {
    var internal_source = document.location();
    if (flag) {
        return input;       // tainted path — returns param
    }
    return 'safe_default';  // untainted path — returns constant
}

app.get('/test', function(req, res) {
    var result = maybe_taint(req.query.cmd, true);
    child_process.exec(result);  // SHOULD flag: input flows through tainted path
});
