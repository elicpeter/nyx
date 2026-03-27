// Scope shadowing: an outer variable and an inner function-local variable
// share the same name "data".  Taint on the outer "data" must NOT bleed
// into the inner scope's "data" (which is safe), and vice-versa.
var express = require('express');
var child_process = require('child_process');
var app = express();

var data = "safe_constant";                // outer: safe

app.get('/shadow', function(req, res) {
    var data = req.query.cmd;              // inner: tainted (shadows outer)
    child_process.exec(data);              // FINDING: tainted inner "data" → exec
});

app.get('/outer', function(req, res) {
    child_process.exec(data);              // SAFE: outer "data" is a constant
});
