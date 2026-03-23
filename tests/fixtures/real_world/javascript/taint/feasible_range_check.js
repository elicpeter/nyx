var express = require('express');
var app = express();

app.get('/calc', function(req, res) {
    var input = req.query.x;
    var n = parseInt(input, 10);
    if (n > 0) {
        if (n < 100) {
            // Feasible: 0 < n < 100 — must NOT be pruned
            eval(input);
        }
    }
});
