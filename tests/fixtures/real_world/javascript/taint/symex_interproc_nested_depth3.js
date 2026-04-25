var express = require('express');
var app = express();

function innerHelper(x) {
    return x;
}

function middleHelper(x) {
    return innerHelper(x);
}

function outerHelper(x) {
    return middleHelper(x);
}

app.get('/test', function(req, res) {
    var data = req.query.input;
    var result = outerHelper(data);
    var client = require('pg').Client();
    client.query(result);
});
