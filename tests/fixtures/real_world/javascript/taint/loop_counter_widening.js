var express = require('express');
var app = express();

app.get('/items', function(req, res) {
    var data = req.query.input;
    var items = [];
    for (var i = 0; i < 100; i++) {
        items.push(data);
    }
    res.send(items.join(','));
});
