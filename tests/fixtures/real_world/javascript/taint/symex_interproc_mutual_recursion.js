var express = require('express');
var app = express();

function even(x) {
    if (x <= 0) return x;
    return odd(x - 1);
}

function odd(x) {
    if (x <= 0) return x;
    return even(x - 1);
}

app.get('/test', function(req, res) {
    var n = req.query.n;
    var result = even(n);
    res.send(result);
});
