// Callback tracking: function passed as argument should be resolved at call site.
// apply(data, dangerous_fn) — dangerous_fn is called with tainted data inside apply.
var child_process = require('child_process');
var express = require('express');
var app = express();

function apply(data, fn) {
    return fn(data);
}

app.get('/cmd', function(req, res) {
    var input = req.query.cmd;
    var result = apply(input, child_process.exec);
    res.send(result);
});
