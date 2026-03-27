// C-1 regression: inline analysis must not leak callee-internal sources
// into the return taint when the actual return value is untainted.
var child_process = require('child_process');
var express = require('express');
var app = express();

function transform(input) {
    var internal = document.location();  // internal source — not returned
    return 'constant_value';
}

app.get('/safe', function(req, res) {
    var result = transform(req.query.data);
    child_process.exec(result);  // result is constant — no finding expected
});
