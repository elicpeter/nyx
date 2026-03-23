var express = require('express');
var app = express();

function copyToNew(item) {
    var fresh = [];
    fresh.push(item);
    return fresh;
}

app.get('/safe', function(req, res) {
    var original = [];
    original.push(req.query.input);
    var copy = copyToNew("safe_constant");
    res.send(copy.join(''));
});
