var express = require('express');
var app = express();

app.get('/data', function(req, res) {
    var input = req.query.value;
    var num = parseInt(input, 10);
    if (num > 100) {
        if (num < 0) {
            // Infeasible: num > 100 AND num < 0
            eval(input);
        }
    }
    eval(input);
});
