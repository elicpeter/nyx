// C-1 regression guard: pure param passthrough must still propagate taint.
var child_process = require('child_process');
var express = require('express');
var app = express();

function identity(x) {
    return x;
}

app.get('/test', function(req, res) {
    var result = identity(req.query.cmd);
    child_process.exec(result);  // SHOULD flag: identity is passthrough
});
