var express = require('express');
var app = express();

function addAndReturn(arr, item) {
    arr.push(item);
    return arr;
}

app.get('/interproc', function(req, res) {
    var items = [];
    var result = addAndReturn(items, req.query.input);
    res.send(result.join(''));
});
