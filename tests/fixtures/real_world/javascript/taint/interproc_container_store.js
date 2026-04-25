var express = require('express');
var app = express();

function storeInto(value, arr) {
    arr.push(value);
}

app.get('/store', function(req, res) {
    var items = [];
    storeInto(req.query.input, items);
    res.send(items.join(''));
});
