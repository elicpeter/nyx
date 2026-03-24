var express = require('express');
var app = express();

function wrap(input, safe) {
    if (safe) {
        return "constant_value";
    }
    return input;
}

app.get('/test', function(req, res) {
    var data = req.query.x;
    var q = wrap(data, false);
    var client = require('pg').Client();
    client.query(q);
});
