var express = require('express');
var app = express();

function a(x) { return b(x); }
function b(x) { return c(x); }
function c(x) { return d(x); }
function d(x) { return e(x); }
function e(x) { return x; }

app.get('/deep', function(req, res) {
    var input = req.query.input;
    var result = a(input);
    var client = require('pg').Client();
    client.query(result);
});
